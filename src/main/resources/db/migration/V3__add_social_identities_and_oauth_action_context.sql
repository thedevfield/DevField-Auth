CREATE TABLE auth.social_identity (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.devfield_user(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider IN ('google', 'github', 'kakao')),
    provider_user_id text NOT NULL CHECK (length(provider_user_id) BETWEEN 1 AND 255),
    provider_email text,
    linked_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id),
    UNIQUE (user_id, provider)
);

ALTER TABLE auth.action_token DROP CONSTRAINT action_token_purpose_check;
ALTER TABLE auth.action_token ADD COLUMN provider text;
ALTER TABLE auth.action_token ADD COLUMN provider_user_id text;
ALTER TABLE auth.action_token ADD COLUMN provider_email text;
ALTER TABLE auth.action_token ADD COLUMN return_route text;
ALTER TABLE auth.action_token ADD COLUMN flow_id text;
ALTER TABLE auth.action_token ADD COLUMN browser_binding_hash text;
ALTER TABLE auth.action_token ADD COLUMN oauth_state_hash text;
ALTER TABLE auth.action_token ADD COLUMN oauth_request bytea;
ALTER TABLE auth.action_token ADD COLUMN started_at timestamptz;
ALTER TABLE auth.action_token ADD COLUMN parent_intent_id uuid REFERENCES auth.action_token(id) ON DELETE RESTRICT;
ALTER TABLE auth.action_token ADD CONSTRAINT action_token_purpose_v3_check CHECK (
    (purpose = 'VERIFY_SIGNUP' AND email_credential_id IS NOT NULL AND user_id IS NULL AND session_id IS NULL)
    OR (purpose = 'OAUTH_INTENT_LOGIN' AND email_credential_id IS NULL AND user_id IS NULL AND session_id IS NULL
        AND provider IN ('google','github','kakao') AND flow_id IS NOT NULL AND browser_binding_hash IS NOT NULL
        AND return_route = 'LOGIN_COMPLETE')
    OR (purpose = 'WEB_HANDOFF' AND email_credential_id IS NULL AND user_id IS NULL AND session_id IS NULL
        AND provider IN ('google','github','kakao') AND provider_user_id IS NOT NULL AND flow_id IS NOT NULL
        AND browser_binding_hash IS NOT NULL AND return_route = 'LOGIN_COMPLETE' AND parent_intent_id IS NOT NULL)
);
ALTER TABLE auth.action_token ADD CONSTRAINT action_token_binding_hash_check CHECK (
    browser_binding_hash IS NULL OR browser_binding_hash ~ '^[0-9a-f]{64}$'
);
CREATE UNIQUE INDEX action_token_oauth_state_unique ON auth.action_token(oauth_state_hash) WHERE oauth_state_hash IS NOT NULL;
CREATE UNIQUE INDEX action_token_oauth_flow_purpose_unique ON auth.action_token(flow_id, purpose) WHERE flow_id IS NOT NULL;
CREATE INDEX action_token_oauth_parent_idx ON auth.action_token(parent_intent_id) WHERE parent_intent_id IS NOT NULL;
