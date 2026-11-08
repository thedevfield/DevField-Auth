CREATE TABLE auth.oauth_deletion_fence (
    provider_identity_hash text PRIMARY KEY CHECK (length(provider_identity_hash) = 64),
    invalidated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
