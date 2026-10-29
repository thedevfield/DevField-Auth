package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.mail.VerificationMailer;
import dev.devfield.auth.session.AuthSessions;
import dev.devfield.auth.util.Secrets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EmailAccountManagement {
    private record EmailRow(UUID id, UUID userId, String hash, boolean verified, Instant latestTokenAt) {}
    private final JdbcTemplate db;
    private final AuthSessions sessions;
    private final VerificationMailer mailer;
    private final AccountChanges changes;
    private final AttemptLimiter limiter;
    private final BCryptPasswordEncoder passwords = new BCryptPasswordEncoder(12);
    private final Duration ttl;
    private final Duration cooldown;

    public EmailAccountManagement(JdbcTemplate db, AuthSessions sessions, VerificationMailer mailer, AccountChanges changes, AttemptLimiter limiter,
                                  @Value("${devfield.auth.verification-ttl}") Duration ttl,
                                  @Value("${devfield.auth.signup-cooldown}") Duration cooldown) {
        this.db = db; this.sessions = sessions; this.mailer = mailer; this.changes = changes; this.limiter = limiter;
        this.ttl = ttl; this.cooldown = cooldown;
    }
    private AuthSessions.State active(String handle) {
        var state = sessions.byHandle(handle);
        sessions.requireActive(state);
        db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, state.userId());
        state = sessions.byId(state.id(), state.userId());
        sessions.requireActive(state);
        return state;
    }
    private EmailRow email(String normalized, boolean lock) {
        String sql = "SELECT c.id,c.user_id,c.password_hash,c.verified_at IS NOT NULL," +
                "(SELECT max(created_at) FROM auth.action_token WHERE email_credential_id=c.id) " +
                "FROM auth.email_credential c WHERE c.normalized_email=?" + (lock ? " FOR UPDATE OF c" : "");
        List<EmailRow> rows = db.query(sql, (rs, i) -> new EmailRow(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getString(3), rs.getBoolean(4),
                rs.getTimestamp(5) == null ? null : rs.getTimestamp(5).toInstant()), normalized);
        return rows.isEmpty() ? null : rows.getFirst();
    }
    private static void passwordValid(String password) {
        if (password == null || password.length() < 12 || password.length() > 256)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_password");
    }
    private void sendLink(String email, String token) {
        try { mailer.sendLink(email, token); }
        catch (MailException | IllegalStateException e) { throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, "mail_unavailable"); }
    }
    @Transactional
    public void requestLink(String handle, String requested, String reauthProof) {
        var session = active(handle);
        changes.consumeProof(reauthProof, session);
        String normalized = AuthAccounts.normalize(requested);
        String limitKey = "link:" + session.userId();
        limiter.check(limitKey);
        limiter.fail(limitKey);
        Integer owned = db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL AND password_hash IS NOT NULL",
                Integer.class, session.userId());
        if (owned != null && owned > 0) throw new ApiError(HttpStatus.CONFLICT, "email_login_exists");
        Integer otherEmail = db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND normalized_email<>?", Integer.class, session.userId(), normalized);
        if (otherEmail != null && otherEmail > 0) throw new ApiError(HttpStatus.CONFLICT, "email_conflict");
        EmailRow row = email(normalized, true);
        if (row != null && !session.userId().equals(row.userId())) throw new ApiError(HttpStatus.CONFLICT, "email_conflict");
        if (row != null && row.verified()) throw new ApiError(HttpStatus.CONFLICT, "email_login_exists");
        if (row != null && row.latestTokenAt() != null && row.latestTokenAt().plus(cooldown).isAfter(Instant.now()))
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "request_cooldown");
        if (row == null) {
            UUID id = UUID.randomUUID();
            db.update("INSERT INTO auth.email_credential(id,user_id,normalized_email,password_hash,reservation_expires_at) VALUES (?,?,?,NULL,?) ON CONFLICT DO NOTHING",
                    id, session.userId(), normalized, Timestamp.from(Instant.now().plus(ttl)));
            row = email(normalized, true);
            if (row == null || !session.userId().equals(row.userId())) throw new ApiError(HttpStatus.CONFLICT, "email_conflict");
        } else {
            db.update("UPDATE auth.email_credential SET reservation_expires_at=? WHERE id=?",
                    Timestamp.from(Instant.now().plus(ttl)), row.id());
        }
        db.update("DELETE FROM auth.action_token WHERE email_credential_id=? AND purpose='VERIFY_LINK'", row.id());
        String token = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,user_id,session_id,email_credential_id,purpose,token_hash,expires_at) VALUES (?,?,?,?,'VERIFY_LINK',?,?)",
                UUID.randomUUID(), session.userId(), session.id(), row.id(), Secrets.sha256(token), Timestamp.from(Instant.now().plus(ttl)));
        sendLink(normalized, token);
    }
    @Transactional
    public void verifyLink(String handle, String token) {
        var session = active(handle);
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_token");
        var ids = db.query("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? AND purpose='VERIFY_LINK' " +
                        "AND user_id=? AND session_id=? AND consumed_at IS NULL AND expires_at>now() RETURNING email_credential_id",
                (rs, i) -> rs.getObject(1, UUID.class), Secrets.sha256(token), session.userId(), session.id());
        if (ids.isEmpty()) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        int changed = db.update("UPDATE auth.email_credential SET verified_at=now(),reservation_expires_at=NULL WHERE id=? " +
                        "AND user_id=? AND verified_at IS NULL AND reservation_expires_at>now()",
                ids.getFirst(), session.userId());
        if (changed != 1) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
    }
    @Transactional
    public void setPassword(String handle, String password) {
        var session = active(handle);
        passwordValid(password);
        int changed = db.update("UPDATE auth.email_credential SET password_hash=? WHERE user_id=? AND verified_at IS NOT NULL AND password_hash IS NULL",
                passwords.encode(password), session.userId());
        if (changed != 1) throw new ApiError(HttpStatus.CONFLICT, "email_not_ready");
        revokeOthers(session);
    }
    @Transactional
    public void changePassword(String handle, String oldPassword, String newPassword) {
        var session = active(handle);
        passwordValid(newPassword);
        String key = "password-change:" + session.userId();
        limiter.check(key);
        var hashes = db.query("SELECT password_hash FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL AND password_hash IS NOT NULL FOR UPDATE",
                (rs, i) -> rs.getString(1), session.userId());
        if (hashes.isEmpty() || oldPassword == null || !passwords.matches(oldPassword, hashes.getFirst())) {
            limiter.fail(key);
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_credentials");
        }
        limiter.clear(key);
        db.update("UPDATE auth.email_credential SET password_hash=? WHERE user_id=?", passwords.encode(newPassword), session.userId());
        revokeOthers(session);
    }
    private void revokeOthers(AuthSessions.State session) {
        db.update("UPDATE auth.auth_session SET revoked_at=now() WHERE user_id=? AND id<>? AND revoked_at IS NULL",
                session.userId(), session.id());
        db.update("UPDATE auth.action_token SET consumed_at=now() WHERE user_id=? AND purpose='ACCOUNT_REAUTH' AND consumed_at IS NULL", session.userId());
        db.update("UPDATE auth.action_token SET consumed_at=now() WHERE user_id=? AND purpose='PASSWORD_RESET' AND consumed_at IS NULL", session.userId());
    }
    @Transactional
    public void requestReset(String requested) {
        String normalized = AuthAccounts.normalize(requested);
        String key = "password-reset:" + Secrets.sha256(normalized);
        limiter.check(key);
        limiter.fail(key);
        EmailRow row = email(normalized, true);
        if (row == null || !row.verified() || row.hash() == null) return;
        Timestamp latestReset = db.queryForObject("SELECT max(created_at) FROM auth.action_token WHERE email_credential_id=? AND purpose='PASSWORD_RESET'", Timestamp.class, row.id());
        if (latestReset != null && latestReset.toInstant().plus(cooldown).isAfter(Instant.now())) return;
        db.update("DELETE FROM auth.action_token WHERE email_credential_id=? AND purpose='PASSWORD_RESET'", row.id());
        String token = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,user_id,email_credential_id,purpose,token_hash,expires_at) VALUES (?,?,?,'PASSWORD_RESET',?,?)",
                UUID.randomUUID(), row.userId(), row.id(), Secrets.sha256(token), Timestamp.from(Instant.now().plus(ttl)));
        try { mailer.sendReset(normalized, token); }
        catch (MailException | IllegalStateException e) { throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, "mail_unavailable"); }
    }
    @Transactional
    public void resetPassword(String token, String password) {
        passwordValid(password);
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_token");
        var rows = db.query("SELECT t.user_id,t.email_credential_id FROM auth.action_token t WHERE t.token_hash=? AND t.purpose='PASSWORD_RESET' " +
                "AND t.consumed_at IS NULL AND t.expires_at>now()", (rs, i) -> new UUID[]{rs.getObject(1, UUID.class), rs.getObject(2, UUID.class)}, Secrets.sha256(token));
        if (rows.isEmpty()) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        UUID userId = rows.getFirst()[0];
        String state = db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, userId);
        if (!"ACTIVE".equals(state)) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        int consumed = db.update("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? AND purpose='PASSWORD_RESET' AND consumed_at IS NULL AND expires_at>now()",
                Secrets.sha256(token));
        if (consumed != 1) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        int changed = db.update("UPDATE auth.email_credential SET password_hash=? WHERE id=? AND user_id=? AND verified_at IS NOT NULL AND password_hash IS NOT NULL",
                passwords.encode(password), rows.getFirst()[1], userId);
        if (changed != 1) throw new ApiError(HttpStatus.CONFLICT, "email_conflict");
        db.update("UPDATE auth.auth_session SET revoked_at=now() WHERE user_id=? AND revoked_at IS NULL", userId);
        db.update("UPDATE auth.action_token SET consumed_at=now() WHERE user_id=? AND purpose='ACCOUNT_REAUTH' AND consumed_at IS NULL", userId);
        db.update("UPDATE auth.action_token SET consumed_at=now() WHERE user_id=? AND purpose='PASSWORD_RESET' AND consumed_at IS NULL", userId);
    }
}
