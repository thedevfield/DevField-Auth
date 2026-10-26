package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.mail.VerificationMailer;
import dev.devfield.auth.util.Secrets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthAccounts {
    public record LoginResult(String sessionHandle, UUID userId) {}
    private record Credential(UUID id, UUID userId, String hash, Instant verifiedAt,
                              Instant reservationExpiresAt, Instant latestTokenAt, String state) {}
    private final JdbcTemplate db;
    private final VerificationMailer mailer;
    private final AttemptLimiter limiter;
    private final BCryptPasswordEncoder passwords = new BCryptPasswordEncoder(12);
    private final Duration verificationTtl;
    private final Duration signupCooldown;
    private final Duration sessionTtl;

    public AuthAccounts(JdbcTemplate db, VerificationMailer mailer, AttemptLimiter limiter,
                        @Value("${devfield.auth.verification-ttl}") Duration verificationTtl,
                        @Value("${devfield.auth.signup-cooldown}") Duration signupCooldown,
                        @Value("${devfield.auth.session-ttl}") Duration sessionTtl) {
        this.db = db; this.mailer = mailer; this.limiter = limiter;
        this.verificationTtl = verificationTtl; this.signupCooldown = signupCooldown; this.sessionTtl = sessionTtl;
        if (verificationTtl.isNegative() || verificationTtl.isZero() || signupCooldown.isNegative() ||
                sessionTtl.isNegative() || sessionTtl.isZero()) throw new IllegalArgumentException("Invalid auth lifetime");
    }

    public static String normalize(String email) {
        if (email == null) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_email");
        String value = email.strip().toLowerCase(Locale.ROOT);
        if (value.length() > 320 || !value.matches("^[^@\\s]{1,64}@[^@\\s]{1,253}\\.[^@\\s]+$"))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_email");
        return value;
    }

    @Transactional
    public void signup(String email, String password, String displayName) {
        String normalized = normalize(email);
        if (password == null || password.length() < 12 || password.length() > 256 ||
                displayName == null || displayName.isBlank() || displayName.length() > 100)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_signup");
        String limitKey = "signup:" + Secrets.sha256(normalized);
        limiter.check(limitKey);
        limiter.fail(limitKey);
        UUID proposed = UUID.randomUUID();
        db.update("INSERT INTO auth.email_credential(id,normalized_email,password_hash,pending_display_name,reservation_expires_at) " +
                "VALUES (?,?,?,?,?) ON CONFLICT (normalized_email) DO NOTHING", proposed, normalized,
                passwords.encode(password), displayName.strip(), Timestamp.from(Instant.now().plus(verificationTtl)));
        Credential row = credentialForUpdate(normalized);
        if (row.verifiedAt != null) return;
        Instant now = Instant.now();
        if (row.latestTokenAt != null && row.latestTokenAt.plus(signupCooldown).isAfter(now) &&
                row.reservationExpiresAt.isAfter(now)) return;
        if (!row.id.equals(proposed)) {
            db.update("UPDATE auth.email_credential SET password_hash=?,pending_display_name=?,reservation_expires_at=? WHERE id=?",
                    passwords.encode(password), displayName.strip(), Timestamp.from(now.plus(verificationTtl)), row.id);
        }
        db.update("DELETE FROM auth.action_token WHERE email_credential_id=?", row.id);
        String token = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,email_credential_id,purpose,token_hash,expires_at) VALUES (?,?,'VERIFY_SIGNUP',?,?)",
                UUID.randomUUID(), row.id, Secrets.sha256(token), Timestamp.from(now.plus(verificationTtl)));
        try { mailer.send(normalized, token); }
        catch (MailException | IllegalStateException e) { throw new ApiError(HttpStatus.SERVICE_UNAVAILABLE, "mail_unavailable"); }
    }

    @Transactional
    public void verify(String token) {
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}"))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_token");
        String hash = Secrets.sha256(token);
        List<UUID> ids = db.query("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? " +
                "AND purpose='VERIFY_SIGNUP' AND consumed_at IS NULL AND expires_at>now() RETURNING email_credential_id",
                (rs, i) -> rs.getObject(1, UUID.class), hash);
        if (ids.isEmpty()) throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        UUID credentialId = ids.getFirst();
        var rows = db.query("SELECT user_id,verified_at,reservation_expires_at,pending_display_name FROM auth.email_credential WHERE id=? FOR UPDATE",
                (rs, i) -> new Object[]{rs.getObject(1, UUID.class), rs.getTimestamp(2), rs.getTimestamp(3), rs.getString(4)}, credentialId);
        if (rows.isEmpty()) throw new ApiError(HttpStatus.CONFLICT, "reservation_conflict");
        Object[] row = rows.getFirst();
        if (row[0] != null || row[1] != null) throw new ApiError(HttpStatus.CONFLICT, "reservation_conflict");
        if (row[2] == null || !((Timestamp) row[2]).toInstant().isAfter(Instant.now()))
            throw new ApiError(HttpStatus.GONE, "token_expired_or_used");
        UUID userId = UUID.randomUUID();
        db.update("INSERT INTO auth.devfield_user(id,display_name) VALUES (?,?)", userId, row[3]);
        db.update("UPDATE auth.email_credential SET user_id=?,verified_at=now(),pending_display_name=NULL,reservation_expires_at=NULL WHERE id=?",
                userId, credentialId);
    }

    @Transactional
    public LoginResult login(String email, String password) {
        String normalized = normalize(email);
        if (password == null || password.isEmpty() || password.length() > 256)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        String limitKey = "login:" + Secrets.sha256(normalized);
        limiter.check(limitKey);
        Credential row = credential(normalized);
        if (row == null || !passwords.matches(password, row.hash)) {
            limiter.fail(limitKey);
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_credentials");
        }
        if (row.verifiedAt == null || !"ACTIVE".equals(row.state))
            throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");
        limiter.clear(limitKey);
        String handle = Secrets.randomToken();
        db.update("INSERT INTO auth.auth_session(id,user_id,session_handle_hash,expires_at) VALUES (?,?,?,?)",
                UUID.randomUUID(), row.userId, Secrets.sha256(handle), Timestamp.from(Instant.now().plus(sessionTtl)));
        return new LoginResult(handle, row.userId);
    }

    private Credential credentialForUpdate(String email) { return queryCredential(email, true); }
    private Credential credential(String email) { return queryCredential(email, false); }

    private Credential queryCredential(String email, boolean lock) {
        String sql = "SELECT c.id,c.user_id,c.password_hash,c.verified_at,c.reservation_expires_at," +
                "(SELECT max(t.created_at) FROM auth.action_token t WHERE t.email_credential_id=c.id),u.state " +
                "FROM auth.email_credential c LEFT JOIN auth.devfield_user u ON u.id=c.user_id WHERE c.normalized_email=?";
        if (lock) sql += " FOR UPDATE OF c";
        List<Credential> rows = db.query(sql, (rs, i) -> new Credential(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getString(3), time(rs.getTimestamp(4)), time(rs.getTimestamp(5)),
                time(rs.getTimestamp(6)), rs.getString(7)), email);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private static Instant time(Timestamp timestamp) { return timestamp == null ? null : timestamp.toInstant(); }
}
