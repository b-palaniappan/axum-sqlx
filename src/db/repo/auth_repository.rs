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
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled,
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        FROM users WHERE email = $1
        "#,
        email
    )
        .fetch_optional(pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;
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
pub async fn get_user_by_id(pool: &PgPool, user_id: i64) -> Result<Users, sqlx::Error> {
    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled,
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
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
pub async fn lock_user_account(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
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
        "UPDATE refresh_tokens SET is_valid = false, status = 'REVOKED' WHERE token = $1",
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

pub async fn increase_failed_login_attempts(
    pool: &PgPool,
    user_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

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

pub async fn logout_user(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET is_valid = false, status = 'REVOKED' WHERE user_id = $1",
        user_id
    )
    .execute(pool)
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

    let user_id = result.user_id.ok_or_else(|| sqlx::Error::RowNotFound)?;
    let is_valid = result.is_valid.unwrap_or(false);

    Ok((user_id, is_valid, result.status))
}
