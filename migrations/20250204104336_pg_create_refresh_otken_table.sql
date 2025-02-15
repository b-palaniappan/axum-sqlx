-- Create ENUM type
CREATE TYPE refresh_token_status AS ENUM ('ACTIVE', 'INACTIVE', 'REVOKED', 'EXPIRED');

CREATE TABLE refresh_tokens
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT REFERENCES users (id),
    token      VARCHAR(255)             NOT NULL,
    status     refresh_token_status     NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at    TIMESTAMP WITH TIME ZONE,
    is_valid   BOOLEAN                           DEFAULT TRUE
);

CREATE UNIQUE INDEX one_active_token_per_user ON refresh_tokens (user_id) WHERE is_valid = true;
