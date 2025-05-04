use crate::db::entity::mfa::{TotpSecret, UserMfaTotp};
use crate::error::error_model::{AppError, ErrorType};
use sqlx::postgres::PgQueryResult;
use sqlx::types::chrono::Utc;
use sqlx::types::JsonValue;
use sqlx::{Error, PgPool};
use tracing::error;

/// Saves a TOTP secret for a user in the database.
///
/// # Arguments
///
/// * `pool` - A PostgreSQL connection pool.
/// * `user_id` - The ID of the user to associate with the TOTP secret.
/// * `totp_secret` - The TOTP secret to save.
///
/// # Returns
///
/// A `Result` containing the inserted record ID on success,
/// or an `AppError` on failure.
pub async fn save_totp_secret(
    pool: &PgPool,
    user_id: i64,
    totp_secret: &TotpSecret,
) -> Result<i64, AppError> {
    let json_secret = serde_json::to_value(totp_secret).map_err(|e| {
        error!("Failed to serialize TOTP secret: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process TOTP secret data",
        )
    })?;

    match sqlx::query_scalar!(
        r#"
        INSERT INTO user_mfa_totp (user_id, totp_secret)
        VALUES ($1, $2)
        RETURNING id
        "#,
        user_id,
        json_secret as JsonValue,
    )
    .fetch_one(pool)
    .await
    {
        Ok(id) => Ok(id),
        Err(e) => {
            error!("Failed to save TOTP secret: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to save TOTP secret",
            ))
        }
    }
}

/// Retrieves the TOTP secret for a user from the database.
///
/// # Arguments
///
/// * `pool` - A PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose TOTP secret to retrieve.
///
/// # Returns
///
/// A `Result` containing the `UseMfaTotp` record on success,
/// or an `AppError` on failure.
pub async fn get_totp_secret(pool: &PgPool, user_id: i64) -> Result<UserMfaTotp, AppError> {
    match sqlx::query_as!(
        UserMfaTotp,
        r#"
        SELECT * FROM user_mfa_totp
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        user_id
    )
    .fetch_one(pool)
    .await
    {
        Ok(record) => Ok(record),
        Err(Error::RowNotFound) => Err(AppError::new(
            ErrorType::NotFound,
            "TOTP secret not found for this user",
        )),
        Err(e) => {
            error!("Failed to get TOTP secret: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to retrieve TOTP secret",
            ))
        }
    }
}

/// Deactivates the TOTP secret for a user by setting the deleted_at timestamp.
///
/// # Arguments
///
/// * `pool` - A PostgreSQL connection pool.
/// * `user_id` - The ID of the user whose TOTP secret to deactivate.
///
/// # Returns
///
/// A `Result` containing the `PgQueryResult` on success,
/// or an `AppError` on failure.
pub async fn deactivate_totp_secret(
    pool: &PgPool,
    user_id: i64,
) -> Result<PgQueryResult, AppError> {
    let now = Utc::now(); // Generate the current timestamp in Rust
    match sqlx::query!(
        r#"
        UPDATE user_mfa_totp
        SET deleted_at = $1
        WHERE user_id = $2 AND deleted_at IS NULL
        "#,
        Some(now),
        user_id
    )
    .execute(pool)
    .await
    {
        Ok(result) => Ok(result),
        Err(e) => {
            error!("Failed to deactivate TOTP secret: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to deactivate TOTP secret",
            ))
        }
    }
}

pub async fn save_mfa_backup_code(
    pool: &PgPool,
    user_id: i64,
    backup_code_hash: String,
    backup_code_hmac: Vec<u8>,
) -> Result<i64, AppError> {
    let now = Utc::now(); // Generate the current timestamp in Rust
    match sqlx::query_scalar!(
        r#"
        INSERT INTO user_mfa_backup_codes (user_id, backup_code_hash, backup_code_hmac, created_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        user_id,
        backup_code_hash,
        backup_code_hmac,
        now
    )
    .fetch_one(pool)
    .await
    {
        Ok(id) => Ok(id),
        Err(e) => {
            error!("Failed to save Backup Code: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to save Backup code",
            ))
        }
    }
}
