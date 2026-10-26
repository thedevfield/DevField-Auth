CREATE TABLE auth.auth_session (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.devfield_user(id) ON DELETE RESTRICT,
    session_handle_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (length(session_handle_hash) = 64)
);

CREATE INDEX auth_session_user_state_idx
    ON auth.auth_session(user_id, revoked_at, expires_at);

CREATE TABLE auth.action_token (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES auth.devfield_user(id) ON DELETE RESTRICT,
    email_credential_id uuid REFERENCES auth.email_credential(id) ON DELETE RESTRICT,
    session_id uuid REFERENCES auth.auth_session(id) ON DELETE RESTRICT,
    purpose text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(token_hash) = 64),
    CHECK (expires_at > created_at),
    CHECK (purpose = 'VERIFY_SIGNUP'),
    CHECK (purpose <> 'VERIFY_SIGNUP' OR
        (email_credential_id IS NOT NULL AND user_id IS NULL AND session_id IS NULL))
);

CREATE INDEX action_token_credential_idx ON auth.action_token(email_credential_id);
CREATE INDEX action_token_expiry_idx ON auth.action_token(expires_at);
