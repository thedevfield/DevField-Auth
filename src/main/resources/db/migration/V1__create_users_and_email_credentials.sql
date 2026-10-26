CREATE TABLE auth.devfield_user (
    id uuid PRIMARY KEY,
    state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DELETING', 'DELETED')),
    display_name text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (updated_at >= created_at)
);

CREATE TABLE auth.email_credential (
    id uuid PRIMARY KEY,
    user_id uuid UNIQUE REFERENCES auth.devfield_user(id) ON DELETE RESTRICT,
    normalized_email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    verified_at timestamptz,
    pending_display_name text,
    reservation_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(normalized_email) BETWEEN 3 AND 320),
    CHECK (length(password_hash) > 20),
    CHECK (verified_at IS NULL OR user_id IS NOT NULL),
    CHECK (verified_at IS NOT NULL OR reservation_expires_at IS NOT NULL),
    CHECK (verified_at IS NULL OR reservation_expires_at IS NULL)
);

CREATE INDEX email_credential_pending_expiry_idx
    ON auth.email_credential(reservation_expires_at) WHERE verified_at IS NULL;
