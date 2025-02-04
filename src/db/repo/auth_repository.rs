use crate::db::entity::user::Users;
use crate::AccountStatus;
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

/// Updates the failed login attempts count for a user in the database.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose failed login attempts count needs to be updated.
///
/// # Returns
///
/// * `Result<(), sqlx::Error>` - On success, returns an empty `Ok(())`.
///   On failure, returns a `sqlx::Error`.
///
/// # Errors
///
/// This function will return an error if the query fails.
pub async fn update_failed_login_attempts(pool: &PgPool, user_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
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
pub async fn add_refresh_token(pool: &PgPool, user_id: i64, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO refresh_tokens (user_id, token) VALUES ($1, $2)",
        user_id,
        token
    )
    .execute(pool)
    .await?;
    Ok(())
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