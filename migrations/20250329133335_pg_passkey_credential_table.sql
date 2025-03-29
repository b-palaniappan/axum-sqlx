CREATE TABLE passkey_credentials
(
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT REFERENCES users (id) ON DELETE CASCADE,
    credential_id   BYTEA       NOT NULL,
    public_key      BYTEA       NOT NULL,
    counter         INTEGER     NOT NULL DEFAULT 0,
    credential_type VARCHAR(32) NOT NULL,
    created_at      TIMESTAMPTZ          DEFAULT NOW(),
    UNIQUE (credential_id)
);
CREATE INDEX idx_credentials_user_id ON passkey_credentials (user_id);
