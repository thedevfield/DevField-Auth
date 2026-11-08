package dev.devfield.auth.oauth;

import dev.devfield.auth.api.ApiError;
import dev.devfield.auth.util.Secrets;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;

public final class OAuthDeletionFence {
    private OAuthDeletionFence() {}

    // Hold before taking user or token locks on anonymous OAuth paths and final deletion.
    public static void lock(JdbcTemplate db) {
        db.queryForObject("SELECT pg_advisory_xact_lock(190197822, 10)", Object.class);
    }

    public static void invalidate(JdbcTemplate db, UUID user) {
        db.update("""
                INSERT INTO auth.oauth_deletion_fence(provider_identity_hash,invalidated_at,expires_at)
                SELECT encode(sha256(convert_to(s.provider || ':' || s.provider_user_id,'UTF8')),'hex'),
                    clock_timestamp(), expires.at
                FROM auth.social_identity s
                CROSS JOIN LATERAL (
                    SELECT max(t.expires_at) AS at FROM auth.action_token t
                    WHERE t.provider=s.provider AND t.purpose IN ('OAUTH_INTENT_LOGIN','OAUTH_INTENT_SIGNUP')
                    AND t.expires_at>clock_timestamp()
                ) expires
                WHERE s.user_id=? AND expires.at IS NOT NULL
                ON CONFLICT (provider_identity_hash) DO UPDATE SET
                    invalidated_at=EXCLUDED.invalidated_at,
                    expires_at=GREATEST(auth.oauth_deletion_fence.expires_at,EXCLUDED.expires_at)
                """, user);
        db.update("""
                DELETE FROM auth.action_token t USING auth.social_identity s
                WHERE s.user_id=? AND t.purpose='WEB_HANDOFF' AND t.user_id IS NULL
                AND t.provider=s.provider AND t.provider_user_id=s.provider_user_id
                """, user);
    }

    static void rejectOldIntent(JdbcTemplate db, UUID intent, String provider, String providerId) {
        if (Boolean.TRUE.equals(db.queryForObject("""
                SELECT EXISTS(SELECT 1 FROM auth.oauth_deletion_fence f JOIN auth.action_token t ON t.id=?
                WHERE f.provider_identity_hash=? AND t.created_at<=f.invalidated_at)
                """, Boolean.class, intent, Secrets.sha256(provider + ":" + providerId))))
            throw new ApiError(HttpStatus.GONE, "oauth_intent_expired_or_used");
    }

    static void cleanup(JdbcTemplate db, int batchSize) {
        db.update("""
                WITH due AS (SELECT provider_identity_hash FROM auth.oauth_deletion_fence
                    WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT ? FOR UPDATE SKIP LOCKED)
                DELETE FROM auth.oauth_deletion_fence f USING due WHERE f.provider_identity_hash=due.provider_identity_hash
                """, batchSize);
    }
}
