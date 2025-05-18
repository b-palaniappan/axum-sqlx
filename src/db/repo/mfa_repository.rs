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

/// Saves multiple backup codes for a user.
///
/// # Arguments
///
/// * `pool` - A PostgreSQL connection pool.
/// * `user_id` - The ID of the user to associate with the backup codes.
/// * `backup_codes` - A slice of backup codes to save.
///
/// # Returns
///
/// A `Result` containing the number of codes successfully saved,
/// or an `AppError` on failure.
pub async fn save_mfa_backup_codes(
    pool: &PgPool,
    user_id: i64,
    backup_codes: &[crate::db::entity::mfa::BackupCode],
) -> Result<i64, AppError> {
    let now = Utc::now();

    // Begin transaction to ensure atomicity
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process backup codes",
        )
    })?;

    // First, delete any existing backup codes for this user
    sqlx::query!(
        r#"
        DELETE FROM user_mfa_backup_codes
        WHERE user_id = $1
        "#,
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to delete existing backup codes: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to update backup codes",
        )
    })?;

    // Insert each backup code as a separate record
    let mut inserted_count = 0;
    for code in backup_codes {
        match sqlx::query!(
            r#"
            INSERT INTO user_mfa_backup_codes (user_id, backup_code_hash, backup_code_hmac, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
            user_id,
            code.hash,
            code.hmac,
            now
        )
        .execute(&mut *tx)
        .await
        {
            Ok(_) => inserted_count += 1,
            Err(e) => {
                error!("Failed to insert backup code: {:?}", e);
                // Continue with other codes even if one fails
            }
        }
    }

    // If we couldn't insert any codes, roll back and return an error
    if inserted_count == 0 {
        let _ = tx.rollback().await;
        return Err(AppError::new(
            ErrorType::InternalServerError,
            "Failed to save any backup codes",
        ));
    }

    // Commit the transaction
    tx.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to save backup codes",
        )
    })?;

    Ok(inserted_count)
}

/// Marks a backup code as used
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `backup_code_id` - The ID of the backup code to mark as used
///
/// # Returns
///
/// A `Result` containing the query result or an `AppError` on failure
pub async fn mark_backup_code_as_used(
    pool: &PgPool,
    backup_code_id: i64,
) -> Result<sqlx::postgres::PgQueryResult, AppError> {
    let now = sqlx::types::chrono::Utc::now();
    match sqlx::query!(
        r#"
        UPDATE user_mfa_backup_codes
        SET used_at = $1
        WHERE id = $2 AND used_at IS NULL
        "#,
        now,
        backup_code_id
    )
    .execute(pool)
    .await
    {
        Ok(result) => Ok(result),
        Err(e) => {
            error!("Failed to mark backup code as used: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to mark backup code as used",
            ))
        }
    }
}

/// Retrieves all unused backup codes for a user
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
///
/// # Returns
///
/// A `Result` containing a vector of backup codes or an `AppError` on failure
pub async fn get_unused_backup_codes_by_user_id(
    pool: &PgPool,
    user_id: i64,
) -> Result<Vec<crate::db::entity::mfa::UserMfaBackupCodes>, AppError> {
    match sqlx::query_as!(
        crate::db::entity::mfa::UserMfaBackupCodes,
        r#"
        SELECT * FROM user_mfa_backup_codes
        WHERE user_id = $1 AND used_at IS NULL
        "#,
        user_id
    )
    .fetch_all(pool)
    .await
    {
        Ok(records) => Ok(records),
        Err(e) => {
            error!("Failed to get backup codes: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to retrieve backup codes",
            ))
        }
    }
}
