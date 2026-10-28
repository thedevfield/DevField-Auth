package dev.devfield.auth.account;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.oauth.OAuthFlowStore;
import dev.devfield.auth.session.AuthSessions;
import dev.devfield.auth.util.Secrets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountChanges {
    private final JdbcTemplate db;
    private final AuthSessions sessions;
    private final OAuthFlowStore flows;
    private final AttemptLimiter limiter;
    private final BCryptPasswordEncoder passwords = new BCryptPasswordEncoder(12);
    public AccountChanges(JdbcTemplate db, AuthSessions sessions, OAuthFlowStore flows, AttemptLimiter limiter) {
        this.db = db; this.sessions = sessions; this.flows = flows; this.limiter = limiter;
    }
    private AuthSessions.State active(String handle) {
        var session = sessions.byHandle(handle);
        sessions.requireActive(session);
        return session;
    }
    private void lockAndCheck(AuthSessions.State session) {
        String state = db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, session.userId());
        if (!"ACTIVE".equals(state)) throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");
        sessions.requireActive(sessions.byId(session.id(), session.userId()));
    }
    @Transactional
    public String passwordProof(String handle, String password) {
        var session = active(handle);
        if (password == null || password.isEmpty() || password.length() > 256)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_request");
        lockAndCheck(session);
        String limitKey = "reauth:" + session.userId();
        limiter.check(limitKey);
        List<String> hashes = db.query("SELECT password_hash FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL",
                (rs, i) -> rs.getString(1), session.userId());
        if (hashes.isEmpty() || !passwords.matches(password, hashes.getFirst())) {
            limiter.fail(limitKey);
            throw new ApiError(HttpStatus.UNAUTHORIZED, "invalid_credentials");
        }
        limiter.clear(limitKey);
        String proof = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,user_id,session_id,purpose,token_hash,expires_at) VALUES (?,?,?,'ACCOUNT_REAUTH',?,?)",
                UUID.randomUUID(), session.userId(), session.id(), Secrets.sha256(proof), Timestamp.from(Instant.now().plusSeconds(300)));
        return proof;
    }
    @Transactional
    public String socialProofStart(String handle, String provider, String bindingHash, String flowId) {
        var session = active(handle);
        lockAndCheck(session);
        if (!OAuthFlowStore.providerAllowed(provider)) throw new ApiError(HttpStatus.BAD_REQUEST, "unsupported_provider");
        Integer owned = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=?",
                Integer.class, session.userId(), provider);
        if (owned == null || owned != 1) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
        return flows.createIntent(provider, bindingHash, flowId, "REAUTH_COMPLETE", session.userId(), session.id());
    }
    private void consumeProof(String proof, AuthSessions.State session) {
        if (!OAuthFlowStore.flowAllowed(proof)) throw new ApiError(HttpStatus.FORBIDDEN, "reauth_required");
        var rows = db.query("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? AND purpose='ACCOUNT_REAUTH' " +
                "AND user_id=? AND session_id=? AND consumed_at IS NULL AND expires_at>now() RETURNING id",
                (rs, i) -> rs.getObject(1, UUID.class), Secrets.sha256(proof), session.userId(), session.id());
        if (rows.isEmpty()) throw new ApiError(HttpStatus.FORBIDDEN, "reauth_required");
    }
    @Transactional
    public String linkStart(String handle, String provider, String proof, String bindingHash, String flowId) {
        var session = active(handle);
        lockAndCheck(session);
        if (!OAuthFlowStore.providerAllowed(provider)) throw new ApiError(HttpStatus.BAD_REQUEST, "unsupported_provider");
        consumeProof(proof, session);
        Integer existing = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=?",
                Integer.class, session.userId(), provider);
        if (existing != null && existing > 0) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
        return flows.createIntent(provider, bindingHash, flowId, "LINK_COMPLETE", session.userId(), session.id());
    }
    @Transactional
    public void unlink(String handle, String provider, String proof) {
        var session = active(handle);
        lockAndCheck(session);
        if (!OAuthFlowStore.providerAllowed(provider)) throw new ApiError(HttpStatus.BAD_REQUEST, "unsupported_provider");
        consumeProof(proof, session);
        Integer email = db.queryForObject("SELECT count(*) FROM auth.email_credential WHERE user_id=? AND verified_at IS NOT NULL", Integer.class, session.userId());
        Integer social = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=?", Integer.class, session.userId());
        Integer target = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=?", Integer.class, session.userId(), provider);
        if (target == null || target == 0) return;
        if ((email == null ? 0 : email) + (social == null ? 0 : social) <= 1)
            throw new ApiError(HttpStatus.CONFLICT, "last_login_method");
        int changed = db.update("DELETE FROM auth.social_identity WHERE user_id=? AND provider=?", session.userId(), provider);
        if (changed != 1) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
        db.update("UPDATE auth.auth_session SET revoked_at=now() WHERE user_id=? AND id<>? AND revoked_at IS NULL",
                session.userId(), session.id());
    }
}
