CREATE TABLE passkey_users
(
    id                    BIGSERIAL PRIMARY KEY,
    user_id               char(21)                                           NOT NULL unique,
    first_name            VARCHAR(255)                                       NOT NULL,
    last_name             VARCHAR(255)                                       NOT NULL,
    email                 VARCHAR(255)                                       NOT NULL,
    email_verified        BOOLEAN                  DEFAULT FALSE             NOT NULL,
    active                BOOLEAN                  DEFAULT FALSE             NOT NULL,
    last_login            TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER                  DEFAULT 0,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at            TIMESTAMP WITH TIME ZONE
);

CREATE TABLE passkey_credentials
(
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT REFERENCES users (id) ON DELETE CASCADE,
    credential_id   BYTEA       NOT NULL,
    public_key      BYTEA       NOT NULL,
    counter         INTEGER     NOT NULL     DEFAULT 0,
    credential_type VARCHAR(32) NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at      TIMESTAMP WITH TIME ZONE,
    UNIQUE (credential_id)
);
CREATE INDEX idx_credentials_user_id ON passkey_credentials (user_id);
