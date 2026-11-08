CREATE TABLE auth.account_deletion (
    user_id uuid PRIMARY KEY REFERENCES auth.devfield_user(id) ON DELETE RESTRICT,
    job_id uuid NOT NULL UNIQUE,
    project_completed_at timestamptz,
    interview_completed_at timestamptz,
    completed_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    claim_id uuid,
    CHECK (completed_at IS NULL OR (project_completed_at IS NOT NULL AND interview_completed_at IS NOT NULL))
);
CREATE INDEX account_deletion_due ON auth.account_deletion(next_attempt_at, user_id) WHERE completed_at IS NULL;
