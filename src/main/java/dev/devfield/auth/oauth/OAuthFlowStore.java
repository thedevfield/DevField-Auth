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
    public record Intent(UUID id, String provider, String flowId, String bindingHash, String returnRoute, UUID userId, UUID sessionId, String purpose, boolean selectAccount) {}
    public record HandoffResult(String sessionHandle, UUID userId, String returnRoute, String reauthProof, String outcome) {}
    private final JdbcTemplate db;
    private final dev.devfield.auth.session.AuthSessions sessions;
    private final String browserOrigin;
    private final Duration intentTtl;
    private final Duration handoffTtl;
    private final Duration sessionTtl;
    private final Duration startWindow;
    private final int maxStartsPerWindow;
    private final int maxActiveIntents;

    @org.springframework.beans.factory.annotation.Autowired
    public OAuthFlowStore(JdbcTemplate db, dev.devfield.auth.session.AuthSessions sessions,
                          @Value("${devfield.auth.oauth.browser-origin:http://127.0.0.1:18080}") String browserOrigin,
                          @Value("${devfield.auth.oauth.intent-ttl:PT5M}") Duration intentTtl,
                          @Value("${devfield.auth.oauth.handoff-ttl:PT2M}") Duration handoffTtl,
                          @Value("${devfield.auth.session-ttl}") Duration sessionTtl,
                          @Value("${devfield.auth.oauth.start-window:PT1M}") Duration startWindow,
                          @Value("${devfield.auth.oauth.max-starts-per-window:120}") int maxStartsPerWindow,
                          @Value("${devfield.auth.oauth.max-active-intents:600}") int maxActiveIntents) {
        this.db = db; this.sessions = sessions; this.browserOrigin = browserOrigin; this.intentTtl = intentTtl; this.handoffTtl = handoffTtl; this.sessionTtl = sessionTtl;
        if (!browserOrigin.matches("https?://[^/]+") || intentTtl.isNegative() || intentTtl.isZero() ||
                handoffTtl.isNegative() || handoffTtl.isZero() || startWindow.isNegative() || startWindow.isZero() ||
                maxStartsPerWindow < 1 || maxActiveIntents < 1) throw new IllegalArgumentException("Invalid OAuth configuration");
        this.startWindow = startWindow;
        this.maxStartsPerWindow = maxStartsPerWindow;
        this.maxActiveIntents = maxActiveIntents;
    }

    public OAuthFlowStore(JdbcTemplate db, String browserOrigin, Duration intentTtl, Duration handoffTtl,
                          Duration sessionTtl, Duration startWindow, int maxStartsPerWindow, int maxActiveIntents) {
        this(db, new dev.devfield.auth.session.AuthSessions(db), browserOrigin, intentTtl, handoffTtl,
                sessionTtl, startWindow, maxStartsPerWindow, maxActiveIntents);
    }

    @Transactional
    public String createIntent(String provider, String bindingHash, String flowId, String returnRoute) {
        return createIntent(provider, bindingHash, flowId, returnRoute, null, null, false);
    }
    public HandoffResult exchange(String handoff, String binding, String flowId) {
        return exchange(handoff, binding, flowId, null, "LOGIN");
    }

    public static boolean providerAllowed(String provider) { return List.of("google", "github", "kakao").contains(provider); }
    public static boolean flowAllowed(String value) { return value != null && value.matches("[A-Za-z0-9_-]{43}"); }

    public boolean startAvailable(String proof, String provider) {
        if (!providerAllowed(provider) || !flowAllowed(proof)) return false;
        Integer count = db.queryForObject("SELECT count(*) FROM auth.action_token t WHERE t.token_hash=? " +
                "AND t.purpose LIKE 'OAUTH_INTENT_%' AND t.provider=? AND t.started_at IS NULL " +
                "AND t.consumed_at IS NULL AND t.expires_at>now() AND (t.user_id IS NULL OR EXISTS (" +
                "SELECT 1 FROM auth.auth_session s JOIN auth.devfield_user u ON u.id=s.user_id " +
                "WHERE s.id=t.session_id AND s.user_id=t.user_id AND s.revoked_at IS NULL " +
                "AND s.expires_at>now() AND u.state='ACTIVE'))", Integer.class, Secrets.sha256(proof), provider);
        return count != null && count == 1;
    }

    @Transactional
    public String createIntent(String provider, String bindingHash, String flowId, String returnRoute, UUID userId, UUID sessionId) {
        return createIntent(provider, bindingHash, flowId, returnRoute, userId, sessionId, false);
    }

    @Transactional
    public String createIntent(String provider, String bindingHash, String flowId, String returnRoute, UUID userId, UUID sessionId, boolean selectAccount) {
        if (!providerAllowed(provider) || bindingHash == null || !bindingHash.matches("[0-9a-f]{64}") ||
                !flowAllowed(flowId) || !List.of("LOGIN_COMPLETE", "SIGNUP_COMPLETE", "LINK_COMPLETE", "REAUTH_COMPLETE").contains(returnRoute) ||
                (List.of("LOGIN_COMPLETE", "SIGNUP_COMPLETE").contains(returnRoute) != (userId == null && sessionId == null)) ||
                (userId == null) != (sessionId == null))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_intent");
        // One database lock covers every Auth instance. Never derive a quota key from caller-controlled flow data.
        db.queryForObject("SELECT pg_advisory_xact_lock(190197822, 9)", Object.class);
        Integer recent = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' " +
                "AND created_at > ?", Integer.class, Timestamp.from(Instant.now().minus(startWindow)));
        Integer active = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE purpose LIKE 'OAUTH_INTENT_%' " +
                "AND expires_at > now()", Integer.class);
        if (recent >= maxStartsPerWindow || active >= maxActiveIntents)
            throw new ApiError(HttpStatus.TOO_MANY_REQUESTS, "oauth_start_limited");
        String purpose = "OAUTH_INTENT_" + returnRoute.substring(0, returnRoute.indexOf('_'));
        String intent = Secrets.randomToken();
        db.update("INSERT INTO auth.action_token(id,purpose,token_hash,expires_at,provider,flow_id,browser_binding_hash,return_route,user_id,session_id,select_account) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", UUID.randomUUID(), purpose, Secrets.sha256(intent),
                Timestamp.from(Instant.now().plus(intentTtl)), provider, flowId, bindingHash, returnRoute, userId, sessionId, selectAccount);
        return browserOrigin + "/oauth2/authorization/" + provider + "?intent=" + intent;
    }

    @Transactional
    public Intent claimStart(String proof, String provider, String state) {
        if (!providerAllowed(provider) || !flowAllowed(proof) || state == null || state.length() < 32)
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_intent");
        List<Intent> found = db.query("UPDATE auth.action_token SET started_at=now(),oauth_state_hash=? WHERE token_hash=? " +
                        "AND purpose LIKE 'OAUTH_INTENT_%' AND provider=? AND started_at IS NULL AND consumed_at IS NULL AND expires_at>now() " +
                        "AND (user_id IS NULL OR EXISTS (SELECT 1 FROM auth.auth_session s JOIN auth.devfield_user u ON u.id=s.user_id " +
                        "WHERE s.id=auth.action_token.session_id AND s.user_id=auth.action_token.user_id " +
                        "AND s.revoked_at IS NULL AND s.expires_at>now() AND u.state='ACTIVE')) " +
                        "RETURNING id,provider,flow_id,browser_binding_hash,return_route,user_id,session_id,purpose,select_account",
                (rs, i) -> new Intent(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getObject(6, UUID.class), rs.getObject(7, UUID.class), rs.getString(8), rs.getBoolean(9)),
                Secrets.sha256(state), Secrets.sha256(proof), provider);
        if (found.isEmpty()) throw new ApiError(HttpStatus.GONE, "oauth_intent_expired_or_used");
        return found.getFirst();
    }

    public Intent byState(String state) {
        if (state == null || state.length() < 32) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_oauth_state");
        var rows = db.query("SELECT id,provider,flow_id,browser_binding_hash,return_route,user_id,session_id,purpose,select_account FROM auth.action_token " +
                        "WHERE oauth_state_hash=? AND purpose LIKE 'OAUTH_INTENT_%' AND started_at IS NOT NULL AND expires_at>now() FOR KEY SHARE",
                (rs, i) -> new Intent(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getObject(6, UUID.class), rs.getObject(7, UUID.class), rs.getString(8), rs.getBoolean(9)), Secrets.sha256(state));
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
                ? "UPDATE auth.action_token SET consumed_at=now() WHERE oauth_state_hash=? AND purpose LIKE 'OAUTH_INTENT_%' " +
                  "AND started_at IS NOT NULL AND consumed_at IS NULL AND expires_at>now() AND oauth_request IS NOT NULL RETURNING oauth_request"
                : "SELECT oauth_request FROM auth.action_token WHERE oauth_state_hash=? AND purpose LIKE 'OAUTH_INTENT_%' " +
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
                        "flow_id,browser_binding_hash,return_route,parent_intent_id,user_id,session_id) VALUES (?,'WEB_HANDOFF',?,?,?,?,?,?,?,?,?,?,?)",
                UUID.randomUUID(), Secrets.sha256(handoff), Timestamp.from(Instant.now().plus(handoffTtl)), provider,
                providerId, providerEmail, intent.flowId(), intent.bindingHash(), intent.returnRoute(), intent.id(), intent.userId(), intent.sessionId());
        return handoff;
    }

    @Transactional
    public HandoffResult exchange(String handoff, String binding, String flowId, String handle, String expectedPurpose) {
        if (!flowAllowed(handoff) || !flowAllowed(binding) || !flowAllowed(flowId))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_handoff");
        String bindingHash = Secrets.sha256(binding);
        var rows = db.query("UPDATE auth.action_token SET consumed_at=now() WHERE token_hash=? AND purpose='WEB_HANDOFF' " +
                        "AND flow_id=? AND browser_binding_hash=? AND consumed_at IS NULL AND expires_at>now() " +
                        "RETURNING provider,provider_user_id,return_route,user_id,session_id",
                (rs, i) -> new String[]{rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)},
                Secrets.sha256(handoff), flowId, bindingHash);
        if (rows.isEmpty()) {
            Integer active = db.queryForObject("SELECT count(*) FROM auth.action_token WHERE token_hash=? " +
                    "AND purpose='WEB_HANDOFF' AND consumed_at IS NULL AND expires_at>now()",
                    Integer.class, Secrets.sha256(handoff));
            if (active != null && active == 1) throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_browser_binding");
            throw new ApiError(HttpStatus.GONE, "handoff_expired_or_used");
        }
        String[] row = rows.getFirst();
        if (!("LOGIN".equals(expectedPurpose) && "LOGIN_COMPLETE".equals(row[2])) &&
            !("SIGNUP".equals(expectedPurpose) && "SIGNUP_COMPLETE".equals(row[2])) &&
            !("ACCOUNT".equals(expectedPurpose) && ("LINK_COMPLETE".equals(row[2]) || "REAUTH_COMPLETE".equals(row[2]))))
            throw new ApiError(HttpStatus.BAD_REQUEST, "invalid_handoff_purpose");
        if ("LINK_COMPLETE".equals(row[2]))
            db.queryForObject("SELECT pg_advisory_xact_lock(hashtext(?),hashtext(?))", Object.class, row[0], row[1]);
        if (!List.of("LOGIN_COMPLETE", "SIGNUP_COMPLETE").contains(row[2])) {
            var session = sessions.byHandle(handle);
            sessions.requireActive(session);
            if (!session.userId().toString().equals(row[3]) || !session.id().toString().equals(row[4]))
                throw new ApiError(HttpStatus.FORBIDDEN, "session_unavailable");
            db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, session.userId());
            sessions.requireActive(sessions.byId(session.id(), session.userId()));
            if ("REAUTH_COMPLETE".equals(row[2])) {
                Integer match = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=? AND provider_user_id=?", Integer.class, session.userId(), row[0], row[1]);
                if (match == null || match != 1) throw new ApiError(HttpStatus.FORBIDDEN, "reauth_mismatch");
                String proof = Secrets.randomToken();
                db.update("INSERT INTO auth.action_token(id,user_id,session_id,purpose,token_hash,expires_at) VALUES (?,?,?,'ACCOUNT_REAUTH',?,?)",
                        UUID.randomUUID(), session.userId(), session.id(), Secrets.sha256(proof), Timestamp.from(Instant.now().plusSeconds(300)));
                return new HandoffResult(null, session.userId(), row[2], proof, "REAUTHENTICATED");
            }
            Integer owner = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE provider=? AND provider_user_id=?", Integer.class, row[0], row[1]);
            if (owner != null && owner > 0) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
            Integer existing = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=?", Integer.class, session.userId(), row[0]);
            if (existing != null && existing > 0) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
            db.update("INSERT INTO auth.social_identity(id,user_id,provider,provider_user_id) VALUES (?,?,?,?)", UUID.randomUUID(), session.userId(), row[0], row[1]);
            return new HandoffResult(null, session.userId(), row[2], null, "LINKED");
        }
        db.queryForObject("SELECT pg_advisory_xact_lock(hashtext(?),hashtext(?))", Object.class, row[0], row[1]);
        List<UUID> owners = db.query("SELECT user_id FROM auth.social_identity WHERE provider=? AND provider_user_id=?",
                (rs, i) -> rs.getObject(1, UUID.class), row[0], row[1]);
        boolean signup = "SIGNUP_COMPLETE".equals(row[2]);
        if (owners.isEmpty() && !signup) return new HandoffResult(null, null, row[2], null, "SIGNUP_REQUIRED");
        if (!owners.isEmpty() && signup) return new HandoffResult(null, null, row[2], null, "EXISTING_ACCOUNT");
        UUID userId;
        if (owners.isEmpty()) {
            userId = UUID.randomUUID();
            db.update("INSERT INTO auth.devfield_user(id) VALUES (?)", userId);
            db.update("INSERT INTO auth.social_identity(id,user_id,provider,provider_user_id) VALUES (?,?,?,?)",
                    UUID.randomUUID(), userId, row[0], row[1]);
        } else userId = owners.getFirst();
        String state = db.queryForObject("SELECT state FROM auth.devfield_user WHERE id=? FOR UPDATE", String.class, userId);
        if (!"ACTIVE".equals(state)) throw new ApiError(HttpStatus.FORBIDDEN, "account_unavailable");
        Integer stillOwned = db.queryForObject("SELECT count(*) FROM auth.social_identity WHERE user_id=? AND provider=? AND provider_user_id=?",
                Integer.class, userId, row[0], row[1]);
        if (stillOwned == null || stillOwned != 1) throw new ApiError(HttpStatus.CONFLICT, "social_link_conflict");
        String newHandle = Secrets.randomToken();
        db.update("INSERT INTO auth.auth_session(id,user_id,session_handle_hash,expires_at) VALUES (?,?,?,?)",
                UUID.randomUUID(), userId, Secrets.sha256(newHandle), Timestamp.from(Instant.now().plus(sessionTtl)));
        return new HandoffResult(newHandle, userId, row[2], null, signup ? "SIGNED_UP" : "LOGGED_IN");
    }

    /** At most batchSize rows of each OAuth purpose are removed per invocation. */
    @Transactional
    public int cleanupOAuth(int batchSize) {
        if (batchSize < 1 || batchSize > 1000) throw new IllegalArgumentException("Invalid OAuth cleanup batch size");
        int handoffs = db.update("WITH due AS (SELECT id FROM auth.action_token WHERE purpose='WEB_HANDOFF' " +
                "AND (expires_at<=now() OR consumed_at IS NOT NULL) ORDER BY expires_at,id LIMIT ? FOR UPDATE SKIP LOCKED) " +
                "DELETE FROM auth.action_token t USING due WHERE t.id=due.id", batchSize);
        int intents = db.update("WITH due AS (SELECT p.id FROM auth.action_token p WHERE p.purpose LIKE 'OAUTH_INTENT_%' " +
                "AND p.expires_at<=now() AND NOT EXISTS (SELECT 1 FROM auth.action_token h WHERE h.parent_intent_id=p.id) " +
                "ORDER BY p.expires_at,p.id LIMIT ? FOR UPDATE OF p SKIP LOCKED) " +
                "DELETE FROM auth.action_token t USING due WHERE t.id=due.id", batchSize);
        int proofs = db.update("WITH due AS (SELECT id FROM auth.action_token WHERE purpose='ACCOUNT_REAUTH' " +
                "AND (expires_at<=now() OR consumed_at IS NOT NULL) ORDER BY expires_at,id LIMIT ? FOR UPDATE SKIP LOCKED) " +
                "DELETE FROM auth.action_token t USING due WHERE t.id=due.id", batchSize);
        return handoffs + intents + proofs;
    }
}
