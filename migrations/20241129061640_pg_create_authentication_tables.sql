-- Create ENUM type
CREATE TYPE account_status AS ENUM ('ACTIVE', 'INACTIVE', 'PENDING', 'LOCKED', 'DELETED');
CREATE TYPE two_factor_method AS ENUM ('EMAIL', 'SMS', 'TOTP', 'PASSKEY');
CREATE TYPE event_type AS ENUM ('LOGIN', 'LOGIN_FAILED', 'PASSWORD_RESET', '2FA_ATTEMPT', 'EMAIL_VERIFICATION', '2FA_SETUP', '2FA_DISABLE', '2FA_BACKUP', '2FA_RECOVERY', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'ACCOUNT_DELETED', 'ACCOUNT_RESTORED');

CREATE TABLE users
(
    id                    BIGSERIAL PRIMARY KEY,
    key                   char(21) UNIQUE                                    NOT NULL,
    first_name            VARCHAR(255),
    last_name             VARCHAR(255)                                       NOT NULL,
    email                 VARCHAR(255) UNIQUE                                NOT NULL,
    password_hash         VARCHAR(255)                                       NOT NULL,
    password_hmac         BYTEA                                              NOT NULL,
    email_verified        BOOLEAN                  DEFAULT FALSE,
    update_password       BOOLEAN                  DEFAULT FALSE,
    two_factor_enabled    BOOLEAN                  DEFAULT FALSE,
    account_status        account_status                                     NOT NULL DEFAULT 'ACTIVE',
    last_login            TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER                  DEFAULT 0,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE INDEX idx_users_email ON users (email);

-- Password Reset Tokens Table:
CREATE TABLE password_reset_tokens
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT                   NOT NULL REFERENCES users (id),
    token      VARCHAR(255)             NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at    TIMESTAMP WITH TIME ZONE,
    is_valid   BOOLEAN                  DEFAULT TRUE,
    CONSTRAINT one_valid_reset_token_per_user UNIQUE (user_id, is_valid)
);

-- Index for token lookups
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens (token) WHERE is_valid = TRUE;

-- Two-Factor Authentication Table
CREATE TABLE user_2fa_methods
(
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT REFERENCES users (id),
    method       two_factor_method NOT NULL,
    is_preferred BOOLEAN                  DEFAULT FALSE,
    is_enabled   BOOLEAN                  DEFAULT FALSE,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, method)
);

CREATE TABLE user_2fa_email
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT REFERENCES users (id),
    email      VARCHAR(255) NOT NULL,
    verified   BOOLEAN                  DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, email)
);

CREATE TABLE user_2fa_sms
(
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT REFERENCES users (id),
    phone_number VARCHAR(20) NOT NULL,
    verified     BOOLEAN                  DEFAULT FALSE,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, phone_number)
);

CREATE TABLE user_2fa_totp
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT REFERENCES users (id),
    secret     VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id)
);

CREATE TABLE two_factor_backups
(
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users (id),
    backup_code VARCHAR(20) NOT NULL,
    used_at     TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_backup_codes UNIQUE (user_id, backup_code)
);

-- List of `remember this device` devices after 2FA.
-- Use cookies for this, and make sure the cookie is signed and encrypted.
-- The cookie value should be in the trusted device table.
CREATE TABLE two_factor_devices
(
    id                 BIGSERIAL PRIMARY KEY,
    user_id            BIGINT       NOT NULL REFERENCES users (id),
    trust_cookie_token VARCHAR(255) NOT NULL,    -- unique token stored in the cookie
    last_used_at       TIMESTAMP WITH TIME ZONE,
    trusted_until      TIMESTAMP WITH TIME ZONE, -- Trust expiration
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    trusted            BOOLEAN                  DEFAULT FALSE,
    device_type        VARCHAR(50),              -- Mobile, Desktop, etc.
    user_agent         TEXT,                     -- Browser/Device info
    ip_address         INET,                     -- Last known IP
    UNIQUE (user_id, trust_cookie_token)
);

-- Email Verification Table
CREATE TABLE email_verifications
(
    id                BIGSERIAL PRIMARY KEY,
    user_id           BIGINT                   NOT NULL REFERENCES users (id),
    email             VARCHAR(255)             NOT NULL,
    verification_code VARCHAR(64)              NOT NULL,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at       TIMESTAMP WITH TIME ZONE,
    CONSTRAINT one_active_verification_per_email UNIQUE (email, verified_at)
);

-- Enhanced Audit Log for authentication events
CREATE TABLE auth_audit_log
(
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT      NOT NULL REFERENCES users (id),
    event_type      event_type  NOT NULL,
    status          VARCHAR(50) NOT NULL,
    ip_address      INET,
    user_agent      TEXT,
    device_id       BIGINT REFERENCES two_factor_devices (id),
    timestamp       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    additional_info JSONB -- store additional info as JSON
);

-- HMAC version table for key rotation
CREATE TABLE hmac_key_versions
(
    id           SERIAL PRIMARY KEY,
    version      INTEGER      NOT NULL,
    kms_key_id   VARCHAR(255) NOT NULL, -- Store KMS reference, not the key
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP WITH TIME ZONE,
    retired_at   TIMESTAMP WITH TIME ZONE,
    status       VARCHAR(20)  NOT NULL    DEFAULT 'PENDING',
    CONSTRAINT unique_active_version UNIQUE (version, status)
);

-- Create a Fake User with password hash and HMAC.
INSERT INTO public.users (key, first_name, last_name, email, password_hash, password_hmac)
VALUES ('I6xHB0IX5DtT-SnkGEyYJ', 'Fakefname', 'Fakelname', 'fake_user@c12.io', '$argon2id$v=19$m=65536,t=4,p=5$F4mRS8vqq+4+okygQ9oYew$e5Mgx35RcnEYHqZlYKVmP88fo9wiDPtATpbZGVOn+GTzmhL7dPkLZK6whLbvYMKauWKae3Fc8BgOpCwArmqjJw', E'\\xCA8FC3E87FC2066870E79AF15BFD678754B9FC6CCF9D79EDED8BE21218AF115EB15CB5070E7C5DA769E20B2ABF03A40E3E631CC8290DF4C28D1C8EA83C3CD43B');
