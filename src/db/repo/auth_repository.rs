use crate::db::entity::auth::RefreshTokenStatus;
use crate::db::entity::user::Users;
use crate::AccountStatus;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Retrieves a user by their email address from the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `email` - A string slice that holds the email address of the user.
///
/// # Returns
///
/// * `Result<Users, sqlx::Error>` - On success, returns a `Users` struct containing the user's details.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails or if no user is found with the given email address.
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> Result<Users, sqlx::Error> {
    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus",
               last_login, failed_login_attempts, created_at, updated_at, deleted_at
        FROM users WHERE lower(email) = lower($1)
        "#,
        email
    )
        .fetch_optional(pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    Ok(user)
}

/// Retrieves an active user by their email address from the database.
///
/// This function queries the `users` table to find a user whose email matches the provided
/// email address (case-insensitive) and whose `deleted_at` field is `NULL`, indicating that
/// the user is active.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool (`PgPool`).
/// * `email` - A string slice representing the email address of the user to retrieve.
///
/// # Returns
///
/// * `Result<Option<Users>, sqlx::Error>` - On success, returns an `Option` containing a `Users` struct
///   if an active user is found, or `None` if no active user exists with the given email address.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails for any reason.
///
/// # Examples
///
/// ```rust,no_run
/// # use axum_sqlx::db::repo::auth_repository::get_active_user_by_email;
/// # use sqlx::PgPool;
/// #
/// # async fn example() -> Result<(), sqlx::Error> {
/// let pool = PgPool::connect("postgres://localhost").await?;
/// let user = get_active_user_by_email(&pool, "example@example.com").await?;
/// if let Some(user) = user {
///     println!("Found active user: {:?}", user);
/// } else {
///     println!("No active user found with the given email.");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn get_active_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<Users>, sqlx::Error> {
    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus",
               last_login, failed_login_attempts, created_at, updated_at, deleted_at
        FROM users WHERE lower(email) = lower($1) and deleted_at IS NULL
        "#,
        email
    )
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

/// Retrieves a user by their ID from the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user to retrieve.
///
/// # Returns
///
/// * `Result<Users, sqlx::Error>` - On success, returns a `Users` struct containing the user's details.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails or if no user is found with the given ID.
pub async fn get_user_by_id(pool: &PgPool, user_id: &i64) -> Result<Users, sqlx::Error> {
    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus", 
               last_login, failed_login_attempts, created_at, updated_at, deleted_at
        FROM users WHERE id = $1
        "#,
        user_id
    )
        .fetch_optional(pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
    Ok(user)
}

/// Locks a user account by setting the account status to 'LOCKED' in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose account needs to be locked.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn lock_user_account(pool: &PgPool, user_id: &i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET account_status = 'LOCKED' WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Resets the failed login attempts count for a user in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose failed login attempts count needs to be reset.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn reset_failed_login_attempts(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET failed_login_attempts = 0 WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Deactivates all active refresh tokens for a user in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose refresh tokens need to be deactivated.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn deactivate_refresh_token(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET is_valid = false, status = 'INACTIVE' WHERE user_id = $1 and status = 'ACTIVE' and is_valid = true",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke_refresh_token(pool: &PgPool, token: String) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET is_valid = false, status = 'REVOKED', used_at = CURRENT_TIMESTAMP WHERE token = $1",
        token
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Adds a new refresh token for a user in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user for whom the refresh token is being added.
/// * `token` - The refresh token to be added.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn add_refresh_token(
    pool: &PgPool,
    user_id: i64,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
        user_id,
        token,
        expires_at
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Increases the failed login attempts count for a user in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose failed login attempts count needs to be increased.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn increase_failed_login_attempts(
    pool: &PgPool,
    user_id: &i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Retrieves the active refresh token for a user from the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose active refresh token is being retrieved.
///
/// # Returns
///
/// * `Option<String>` - Returns an `Option` containing the active refresh token as a `String` if found, otherwise returns `None`.
///
/// # Errors
///
/// This function will return `None` if the query fails or if no active refresh token is found for the given user ID.
pub async fn get_active_refresh_token(pool: &PgPool, user_id: i64) -> Option<String> {
    let token = sqlx::query!(
        "SELECT token FROM refresh_tokens WHERE user_id = $1 AND is_valid = true AND status = 'ACTIVE'",
        user_id
    )
        .fetch_optional(pool)
        .await
        .ok()?
        .map(|row| row.token);
    token
}

/// Logs out a user by revoking all their active refresh tokens in the database.
///
/// This function sets the `is_valid` field to `false` and the `status` field to `REVOKED`
/// for all refresh tokens associated with the given user ID.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose refresh tokens need to be revoked.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn logout_user(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET is_valid = false, status = 'REVOKED' WHERE user_id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Updates a user's password in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose password is being updated.
/// * `password_hash` - The new hashed password.
/// * `password_hmac` - The HMAC of the password hash for integrity verification.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn update_user_password(
    pool: &PgPool,
    user_id: i64,
    password_hash: &str,
    password_hmac: &[u8],
) -> Result<(), sqlx::Error> {
    // First, mark any existing password credentials as deleted
    sqlx::query!(
        "UPDATE user_login_credentials SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1 and deleted_at IS NULL",
        user_id
    )
    .execute(pool)
    .await?;

    // Insert the new password credentials
    sqlx::query!(
        "INSERT INTO user_login_credentials (user_id, password_hash, password_hmac) VALUES ($1, $2, $3)",
        user_id,
        password_hash,
        password_hmac
    ).execute(pool)
    .await?;
    Ok(())
}

/// Retrieves a refresh token by its token value from the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `token` - The refresh token string to look up.
///
/// # Returns
///
/// * `Result<(i64, bool, RefreshTokenStatus), sqlx::Error>` - On success, returns a tuple containing:
///   - user_id: The ID of the user who owns the token
///   - is_valid: Whether the token is valid
///   - status: The current status of the token (ACTIVE, INACTIVE, REVOKED, EXPIRED)
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails or if no token is found with the given value.
pub async fn get_refresh_token_by_value(
    pool: &PgPool,
    token: &str,
) -> Result<(i64, bool, RefreshTokenStatus), sqlx::Error> {
    let result = sqlx::query!(
        r#"SELECT user_id, is_valid, status as "status: RefreshTokenStatus" FROM refresh_tokens WHERE token = $1"#,
        token
    )
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;

    let user_id = result.user_id;
    let is_valid = result.is_valid.unwrap_or(false);

    Ok((user_id, is_valid, result.status))
}

/// Creates a new password reset token for a user.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user who is resetting their password.
/// * `token` - The generated reset token.
/// * `expires_at` - When the token expires.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - Returns Ok if successful, or an error if the operation fails.
pub async fn create_password_reset_token(
    pool: &PgPool,
    user_id: i64,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    // First, invalidate any existing reset tokens for this user
    sqlx::query!(
        "UPDATE password_reset_tokens SET is_valid = false WHERE user_id = $1 AND is_valid = true",
        user_id
    )
    .execute(pool)
    .await?;

    // Create the new token
    sqlx::query!(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at, is_valid) VALUES ($1, $2, $3, true)",
        user_id,
        token,
        expires_at
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Verify a password reset token.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `token` - The reset token to verify.
///
/// # Returns
///
/// * `Result<i64, sqlx::Error>` - Returns the user ID if the token is valid,
///   or an error if the token is invalid, expired, or already used.
pub async fn verify_password_reset_token(pool: &PgPool, token: &str) -> Result<i64, sqlx::Error> {
    let now = Utc::now();

    let result = sqlx::query!(
        r#"
        SELECT user_id, expires_at, is_valid
        FROM password_reset_tokens
        WHERE token = $1
        "#,
        token
    )
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;

    let user_id = result.user_id;
    let expires_at = result.expires_at;
    let is_valid = result.is_valid.unwrap_or(false);

    // Check if token is valid and not expired
    if !is_valid {
        return Err(sqlx::Error::RowNotFound);
    }

    if expires_at < now {
        // Token is expired, mark it as invalid
        sqlx::query!(
            "UPDATE password_reset_tokens SET is_valid = false WHERE token = $1",
            token
        )
        .execute(pool)
        .await?;

        return Err(sqlx::Error::RowNotFound);
    }

    Ok(user_id)
}

/// Mark a password reset token as used.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `token` - The reset token to mark as used.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - Returns Ok if successful, or an error if the operation fails.
pub async fn mark_reset_token_as_used(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    let now = Utc::now();

    sqlx::query!(
        "UPDATE password_reset_tokens SET is_valid = false, used_at = $1 WHERE token = $2",
        now,
        token
    )
    .execute(pool)
    .await?;

    Ok(())
}
