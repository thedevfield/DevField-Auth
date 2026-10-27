package dev.devfield.auth.oauth;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.util.Secrets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OAuthFlowStore {
    public record Intent(UUID id, String provider, String flowId, String bindingHash, String returnRoute) {}
    public record HandoffResult(String sessionHandle, UUID userId, String returnRoute) {}
    private final JdbcTemplate db;
    private final String browserOrigin;
    private final Duration intentTtl;
    private final Duration handoffTtl;
    private final Duration sessionTtl;

    public OAuthFlowStore(JdbcTemplate db,
                          @Value("${devfield.auth.oauth.browser-origin:http://127.0.0.1:18080}") String browserOrigin,
                          @Value("${devfield.auth.oauth.intent-ttl:PT5M}") Duration intentTtl,
                          @Value("${devfield.auth.oauth.handoff-ttl:PT2M}") Duration handoffTtl,
                          @Value("${devfield.auth.session-ttl}") Duration sessionTtl) {
        this.db = db; this.browserOrigin = browserOrigin; this.intentTtl = intentTtl; this.handoffTtl = handoffTtl; this.sessionTtl = sessionTtl;
        if (!browserOrigin.matches("https?://[^/]+") || intentTtl.isNegative() || intentTtl.isZero() ||
                handoffTtl.isNegative() || handoffTtl.isZero()) throw new IllegalArgumentException("Invalid OAuth configuration");
    }

    public static boolean providerAllowed(String provider) { return List.of("google", "github", "kakao").contains(provider); }
    public static boolean flowAllowed(String value) { return value != null && value.matches("[A-Za-z0-9_-]{43}"); }

    public boolean startAvailable(String proof, String provider) {
        if (!providerAllowed(provider) || !flowAllowed(proof)) return false;
        Integer count = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE token_hash=? " +
                "AND purpose='OAUTH_INTENT_LOGIN' AND provider=? AND started_at IS NULL " +
                "AND consumed_at IS NULL AND expires_at>now()", Integer.class, Secrets.sha256(proof), provider);
        return count != null && count == 1;
    }

    @Transactional
    public String createIntent(String provider, String bindingHash, String flowId, String returnRoute) {
        if (!providerAllowed(provider) || bindingHash == null || !bindingHash.matches("[0-9a-f]{64}") ||
                !flowAllowed(flowId) || !"LOGIN_COMPLETE".equals(returnRoute))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_intent");
        String intent = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,purpose,token_hash,expires_at,provider,flow_id,browser_binding_hash,return_route) " +
                        "VALUES (?, 'OAUTH_INTENT_LOGIN', ?, ?, ?, ?, ?, ?)", UUID.randomUUID(), Secrets.sha256(intent),
                Timestamp.from(Instant.now().plus(intentTtl)), provider, flowId, bindingHash, returnRoute);
        return browserOrigin + "/oauth2/authorization/" + provider + "?intent=" + intent;
    }

    @Transactional
    public Intent claimStart(String proof, String provider, String state) {
        if (!providerAllowed(provider) || !flowAllowed(proof) || state == null || state.length() < 32)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_intent");
        List<Intent> found = db.query("UPDATE auth.action_token SET started_at=now(),oauth_state_hash=? WHERE token_hash=? " +
                        "AND purpose='OAUTH_INTENT_LOGIN' AND provider=? AND started_at IS NULL AND consumed_at IS NULL AND expires_at>now() " +
                        "RETURNING id,provider,flow_id,browser_binding_hash,return_route",
                (rs, i) -> new Intent(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)),
                Secrets.sha256(state), Secrets.sha256(proof), provider);
        if (found.isEmpty()) throw new ApiError(HttpStatus.GONE, "oauth_intent_expired_or_used");
        return found.getFirst();
    }

    public Intent byState(String state) {
        if (state == null || state.length() < 32) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_state");
        var rows = db.query("SELECT id,provider,flow_id,browser_binding_hash,return_route FROM auth.action_token " +
                        "WHERE oauth_state_hash=? AND purpose='OAUTH_INTENT_LOGIN' AND started_at IS NOT NULL AND expires_at>now()",
                (rs, i) -> new Intent(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)), Secrets.sha256(state));
        if (rows.isEmpty()) throw new ApiError(HttpStatus.GONE, "oauth_intent_expired_or_used");
        return rows.getFirst();
    }

    public void saveRequest(String state, byte[] encrypted) {
        int changed = db.update("UPDATE auth.action_token SET oauth_request=? WHERE oauth_state_hash=? AND started_at IS NOT NULL " +
                        "AND consumed_at IS NULL AND expires_at>now() AND oauth_request IS NULL", encrypted, Secrets.sha256(state));
        if (changed != 1) throw new ApiError(HttpStatus.GONE, "oauth_intent_expired_or_used");
    }

    public byte[] requestBytes(String state, boolean consume) {
        String sql = consume
                ? "UPDATE auth.action_token SET consumed_at=now() WHERE oauth_state_hash=? AND purpose='OAUTH_INTENT_LOGIN' " +
                  "AND started_at IS NOT NULL AND consumed_at IS NULL AND expires_at>now() AND oauth_request IS NOT NULL RETURNING oauth_request"
                : "SELECT oauth_request FROM auth.action_token WHERE oauth_state_hash=? AND purpose='OAUTH_INTENT_LOGIN' " +
                  "AND started_at IS NOT NULL AND consumed_at IS NULL AND expires_at>now() AND oauth_request IS NOT NULL";
        List<byte[]> rows = db.query(sql, (rs, i) -> rs.getBytes(1), Secrets.sha256(state));
        return rows.isEmpty() ? null : rows.getFirst();
    }

    @Transactional
    public String createHandoff(String state, String provider, String providerId, String providerEmail) {
        Intent intent = byState(state);
        if (!intent.provider().equals(provider) || providerId == null || providerId.isBlank() || providerId.length() > 255)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_callback");
        String handoff = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,purpose,token_hash,expires_at,provider,provider_user_id,provider_email," +
                        "flow_id,browser_binding_hash,return_route,parent_intent_id) VALUES (?,'WEB_HANDOFF',?,?,?,?,?,?,?,?,?)",
                UUID.randomUUID(), Secrets.sha256(handoff), Timestamp.from(Instant.now().plus(handoffTtl)), provider,
                providerId, providerEmail, intent.flowId(), intent.bindingHash(), intent.returnRoute(), intent.id());
        return handoff;
    }

    @Transactional
    public HandoffResult exchange(String handoff, String binding, String flowId) {
        if (!flowAllowed(handoff) || !flowAllowed(binding) || !flowAllowed(flowId))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_handoff");
        String bindingHash = Secrets.sha256(binding);
        var rows = db.query("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? AND purpose='WEB_HANDOFF' " +
                        "AND flow_id=? AND browser_binding_hash=? AND consumed_at IS NULL AND expires_at>now() " +
                        "RETURNING provider,provider_user_id,return_route",
                (rs, i) -> new String[]{rs.getString(1), rs.getString(2), rs.getString(3)},
                Secrets.sha256(handoff), flowId, bindingHash);
        if (rows.isEmpty()) {
            Integer active = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE token_hash=? " +
                    "AND purpose='WEB_HANDOFF' AND consumed_at IS NULL AND expires_at>now()",
                    Integer.class, Secrets.sha256(handoff));
            if (active != null && active == 1) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_browser_binding");
            throw new ApiError(HttpStatus.GONE, "handoff_expired_or_used");
        }
        String[] row = rows.getFirst();
        db.queryForObject("SELECT pg_advisory_xact_lock(hashtext(?),hashtext(?))", Object.class, row[0], row[1]);
        List<UUID> owners = db.query("SELECT user_id FROM auth.social_identity WHERE provider=? AND provider_user_id=?",
                (rs, i) -> rs.getObject(1, UUID.class), row[0], row[1]);
        UUID userId;
        if (owners.isEmpty()) {
            userId = UUID.randomUUID();
            db.update("INSERT INTO auth.devfield_user(id) VALUES (?)", userId);
            db.update("INSERT INTO auth.social_identity(id,user_id,provider,provider_user_id) VALUES (?,?,?,?)",
                    UUID.randomUUID(), userId, row[0], row[1]);
        } else userId = owners.getFirst();
        String state = db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, userId);
        if (!"ACTIVE".equals(state)) throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");
        String handle = Secrets.randomToken();
        db.update("INSERT INTO auth.auth_session(id,user_id,session_handle_hash,expires_at) VALUES (?,?,?,?)",
                UUID.randomUUID(), userId, Secrets.sha256(handle), Timestamp.from(Instant.now().plus(sessionTtl)));
        return new HandoffResult(handle, userId, row[2]);
    }
}
