## Scratch pad

### Registration
- also called as `create_user`.
- Takes `first_name`, `last_name`, `email`, `password` as input.
- Generate Argon2id hash of password.
- Generate HMAC of the hashed password.
- Both the hash and HMAC are stored in the database.
- HMAC of the password hash is used to verify the hash is not tampered with in the database.

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

### Validate Auth
- Takes `token` and `refresh_token` as input.
- Verify the JWT token in the cache.
- Verify the refresh token in the database.
- If both are valid, return the user `key`.
- If the JWT token is expired, return `Unauthorized` and ask the user to login again or use refresh token.
- If the refresh token is expired, return `Unauthorized` and ask the user to login again.

### Refresh Token
- Takes `refresh_token` as input.
- Verify the refresh token in the database.
- If the refresh token is valid, generate a new JWT token and new `refresh_token`. Invalidate the old refresh token and persist the new refresh token in the database.
- Return the new JWT token and new `refresh_token`.

### Forgot Password
- Takes `email` as input.
- Generate a random token and store it in the database with the user record.
- The token will be only active for few hours, let say 12 hours only.
- Send an email with the token to the user.
- The token is verified with the database and the user is allowed to reset the password.
- The token is marked as used in the database.

### Reset Password
- Takes `email`, `token`, `refresh_token`, `password`, `new_password` and `confirm_password` as input.
- Verify the `token` and `refresh_token` in the cache and database.
- Verify the `password` with the user record in the database.
- Generate Argon2id hash of the `new_password`.
- Generate HMAC of the hashed password.

### Logout
- Remove the refresh token from the database.
- Remove the JWT token from the cache.

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
