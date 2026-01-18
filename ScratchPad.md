## Scratch pad

### Registration
- also called as `create_user`.
- Takes `first_name`, `last_name`, `email`, `password` as input.
- Generate Argon2id hash of password.
- Generate HMAC of the hashed password.
- Both the hash and HMAC are stored in the database.
- HMAC of the password hash is used to verify the hash is not tampered with in the database.
- Add to audit log.

### Login
- also called as `authenticate_user`.
- Takes `email`, `password` as input.
- Fetch the user record from the database using the email address and status is `active`
- Verify the password with password hash using Argon2id.
- On successful validation of password, verify the HMAC to make sure the password hash is not tampered.
- Create JWT token with claim.
  - set `jti` as random nano ID.
  - Sign the token with RSA private key.
  - Set the `kid` in the header with xxhash of RSA public key.
- Create a refresh token (which is random nano ID) and persist in the database.
- Add to audit log.

### Validate Auth
- Takes `token` as input.
- Verify the JWT token in the cache.
- If token is valid, return the user `key`.
- If the JWT token is expired, return `Unauthorized` and ask the user to login again or use refresh token.

### Refresh Token
- Takes `refresh_token` as input.
- Verify the refresh token in the database.
- If the refresh token is valid, generate a new JWT token and new `refresh_token`. Invalidate the old refresh token and persist the new refresh token in the database.
- Return the new JWT token and new `refresh_token`.
- Add to audit log.

### Forgot Password
- Takes `email` as input.
- Generate a random token and store it in the database with the user record.
- The token will be only active for few hours, let say 12 hours only.
- Send an email with the token to the user.
- The token is verified with the database and the user is allowed to reset the password.
- The token is marked as used in the database.
- Add to audit log.

### Reset Password
- Takes `email`, `token`, `refresh_token`, `password`, `new_password` and `confirm_password` as input.
- Verify the `token` and `refresh_token` in the cache and database.
- Verify the `password` with the user record in the database.
- Generate Argon2id hash of the `new_password`.
- Generate HMAC of the hashed password.
- Add to audit log.

### Logout
- `DELETE` request without any payload. JWT toke is passed in the auth header as `Bearer` token and refresh token as cookie.
- Get the user key from the JWT token.
- If the JWT token is not available, use the refresh_token from the cookie.
- Invalidate the JWT token and refresh token in the cache and database.
- Add to audit log.

## Audit Log / Table
- Create a table to store the audit log.
- Stores following auth audit events,
  - Registration
  - Login
  - Validate Auth
  - Forgot Password
  - Reset Password
  - Refresh Token
  - Logout
  - User Profile Update
  - User Profile Soft Delete

## TODO
- `Verify TOTP MFA` should return a valid JWT token if the TOTP is valid.
- `/mfa/totp/validate-backup/:userKey` should return a valid JWT token if the backup code is valid.

## For Production Ready
Here are production‑readiness improvements I’d prioritize for this app, ordered by impact/risk:

- Security & secrets: move all secrets to a proper secret manager (Vault/AWS/GCP), rotate keys, avoid .env in prod, and enforce strong JWT/refresh token policies.
- Auth hardening: add rate limiting + brute‑force protection, account lockouts, token revocation on password reset, and audit logs for auth events.
- Observability: structured logs with request IDs, tracing spans across services, metrics (latency, error rates, DB/Redis ops), and alerting dashboards.
- Resilience: graceful shutdown, request timeouts per handler, retry/backoff on DB/Redis, and circuit‑breaking for downstream calls (email/SMS).
- Data safety: DB migrations in CI/CD, backup/restore plan, indexes for hot queries, and a clear schema/versioning strategy.
- Testing & CI/CD: integration tests wired into pipeline, load tests for auth endpoints, security scans (SAST + dependency audit).
- Operational hardening: TLS termination, strict CORS policy, rate limits at gateway, and WAF rules for auth endpoints.
- Configuration: structured config validation at startup, sane defaults per environment, and a health/readiness endpoint.
- Caching discipline: explicit cache eviction on logout/token revoke, bounded TTLs, and cache key versioning.
- Monitoring MFA/Passkeys: track registration failures, replay attempts, and suspicious patterns.
