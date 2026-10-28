ALTER TABLE auth.action_token DROP CONSTRAINT action_token_purpose_v5_check;
ALTER TABLE auth.action_token ADD CONSTRAINT action_token_purpose_v6_check CHECK (
    (purpose = 'VERIFY_SIGNUP' AND email_credential_id IS NOT NULL AND user_id IS NULL AND session_id IS NULL)
    OR (purpose = 'ACCOUNT_REAUTH' AND email_credential_id IS NULL AND user_id IS NOT NULL AND session_id IS NOT NULL
        AND provider IS NULL AND flow_id IS NULL AND browser_binding_hash IS NULL AND return_route IS NULL)
    OR (purpose IN ('OAUTH_INTENT_LOGIN','OAUTH_INTENT_SIGNUP') AND email_credential_id IS NULL
        AND user_id IS NULL AND session_id IS NULL AND provider IN ('google','github','kakao')
        AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL AND parent_intent_id IS NULL
        AND return_route = CASE purpose WHEN 'OAUTH_INTENT_LOGIN' THEN 'LOGIN_COMPLETE' ELSE 'SIGNUP_COMPLETE' END)
    OR (purpose IN ('OAUTH_INTENT_LINK','OAUTH_INTENT_REAUTH') AND email_credential_id IS NULL
        AND user_id IS NOT NULL AND session_id IS NOT NULL AND provider IN ('google','github','kakao')
        AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL AND parent_intent_id IS NULL
        AND return_route = CASE purpose WHEN 'OAUTH_INTENT_LINK' THEN 'LINK_COMPLETE' ELSE 'REAUTH_COMPLETE' END)
    OR (purpose = 'WEB_HANDOFF' AND email_credential_id IS NULL AND provider IN ('google','github','kakao')
        AND provider_user_id IS NOT NULL AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL
        AND parent_intent_id IS NOT NULL AND
        ((return_route IN ('LOGIN_COMPLETE','SIGNUP_COMPLETE') AND user_id IS NULL AND session_id IS NULL)
         OR (return_route IN ('LINK_COMPLETE','REAUTH_COMPLETE') AND user_id IS NOT NULL AND session_id IS NOT NULL)))
);
