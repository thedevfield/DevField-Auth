ALTER TABLE auth.action_token ADD COLUMN select_account boolean NOT NULL DEFAULT false;
-- Purpose and context are constrained together; login context remains anonymous.
ALTER TABLE auth.action_token DROP CONSTRAINT action_token_purpose_v3_check;
ALTER TABLE auth.action_token ADD CONSTRAINT action_token_purpose_v5_check CHECK (
    (purpose = 'VERIFY_SIGNUP' AND email_credential_id IS NOT NULL AND user_id IS NULL AND session_id IS NULL)
    OR (purpose = 'ACCOUNT_REAUTH' AND email_credential_id IS NULL AND user_id IS NOT NULL AND session_id IS NOT NULL
        AND provider IS NULL AND flow_id IS NULL AND browser_binding_hash IS NULL AND return_route IS NULL)
    OR (purpose = 'OAUTH_INTENT_LOGIN' AND email_credential_id IS NULL AND user_id IS NULL AND session_id IS NULL
        AND provider IN ('google','github','kakao') AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL
        AND return_route = 'LOGIN_COMPLETE' AND parent_intent_id IS NULL)
    OR (purpose IN ('OAUTH_INTENT_LINK','OAUTH_INTENT_REAUTH') AND email_credential_id IS NULL
        AND user_id IS NOT NULL AND session_id IS NOT NULL AND provider IN ('google','github','kakao')
        AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL AND parent_intent_id IS NULL
        AND return_route = CASE purpose WHEN 'OAUTH_INTENT_LINK' THEN 'LINK_COMPLETE' ELSE 'REAUTH_COMPLETE' END)
    OR (purpose = 'WEB_HANDOFF' AND email_credential_id IS NULL AND provider IN ('google','github','kakao')
        AND provider_user_id IS NOT NULL AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL
        AND parent_intent_id IS NOT NULL AND
        ((return_route = 'LOGIN_COMPLETE' AND user_id IS NULL AND session_id IS NULL)
         OR (return_route IN ('LINK_COMPLETE','REAUTH_COMPLETE') AND user_id IS NOT NULL AND session_id IS NOT NULL)))
);
CREATE INDEX action_token_account_reauth_idx ON auth.action_token(session_id, expires_at)
    WHERE purpose = 'ACCOUNT_REAUTH' AND consumed_at IS NULL;
