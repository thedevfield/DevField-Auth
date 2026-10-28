CREATE INDEX action_token_oauth_intent_created_idx
    ON auth.action_token(created_at)
    WHERE purpose = 'OAUTH_INTENT_LOGIN';

CREATE INDEX action_token_oauth_intent_expiry_idx
    ON auth.action_token(expires_at)
    WHERE purpose = 'OAUTH_INTENT_LOGIN';

CREATE INDEX action_token_oauth_handoff_expiry_idx
    ON auth.action_token(expires_at, id)
    WHERE purpose = 'WEB_HANDOFF';

CREATE INDEX action_token_oauth_handoff_consumed_idx
    ON auth.action_token(consumed_at)
    WHERE purpose = 'WEB_HANDOFF' AND consumed_at IS NOT NULL;
