use crate::db::entity::mfa::{TotpSecret, UserMfaTotp};
use crate::error::error_model::{AppError, ErrorType};
use chrono::Duration;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
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
) -> Result<PgQueryResult, AppError> {
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
        WHERE user_id = $1 AND used_at IS NULL AND deleted_at IS NULL
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

/// Soft deletes all backup codes for a user by setting the deleted_at timestamp
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user whose backup codes to delete
///
/// # Returns
///
/// A `Result` containing the number of rows affected or an `AppError` on failure
pub async fn soft_delete_backup_codes(pool: &PgPool, user_id: i64) -> Result<i64, AppError> {
    let now = Utc::now();
    match sqlx::query!(
        r#"
        UPDATE user_mfa_backup_codes
        SET deleted_at = $1
        WHERE user_id = $2 AND deleted_at IS NULL
        "#,
        now,
        user_id
    )
    .execute(pool)
    .await
    {
        Ok(result) => Ok(result.rows_affected() as i64),
        Err(e) => {
            error!("Failed to soft delete backup codes: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to delete backup codes",
            ))
        }
    }
}

/// Checks if an email is already registered for MFA for the given user
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `email` - The email to check
///
/// # Returns
///
/// A `Result` containing a boolean indicating if the email is already registered
pub async fn is_email_registered_for_mfa(
    pool: &PgPool,
    user_id: i64,
    email: &str,
) -> Result<bool, AppError> {
    match sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM user_mfa_email
            WHERE user_id = $1 AND email = $2 AND verified = true
        ) as "exists!"
        "#,
        user_id,
        email
    )
    .fetch_one(pool)
    .await
    {
        Ok(exists) => Ok(exists),
        Err(e) => {
            error!("Failed to check if email is registered for MFA: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to check email MFA registration",
            ))
        }
    }
}

/// Creates or updates an email verification record for MFA
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `email` - The email to verify
/// * `verification_code` - The verification code
///
/// # Returns
///
/// A `Result` containing the ID of the created verification record
pub async fn create_email_verification(
    pool: &PgPool,
    user_id: i64,
    email: &str,
    verification_code: &str,
) -> Result<i64, AppError> {
    // Calculate the expiration time (15 minutes from now)
    let expires_at = Utc::now() + Duration::minutes(15);

    // First, insert or update the user_mfa_email record
    match sqlx::query_scalar!(
        r#"
        INSERT INTO user_mfa_email (user_id, email, verified)
        VALUES ($1, $2, false)
        ON CONFLICT (user_id, email) DO UPDATE
        SET verified = false, updated_at = CURRENT_TIMESTAMP
        RETURNING id
        "#,
        user_id,
        email
    )
    .fetch_one(pool)
    .await
    {
        Ok(mfa_email_id) => {
            // Now create the email verification record
            match sqlx::query_scalar!(
                r#"
                INSERT INTO email_verifications (user_id, email, verification_code, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
                user_id,
                email,
                verification_code,
                expires_at
            )
            .fetch_one(pool)
            .await
            {
                Ok(id) => Ok(id),
                Err(e) => {
                    error!("Failed to create email verification: {:?}", e);
                    Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Failed to create email verification",
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to create MFA email record: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to create MFA email record",
            ))
        }
    }
}

/// Verifies an email verification code for MFA
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `email` - The email to verify
/// * `verification_code` - The verification code to verify
///
/// # Returns
///
/// A `Result` containing a boolean indicating if the code was valid
pub async fn verify_email_code(
    pool: &PgPool,
    user_id: i64,
    email: &str,
    verification_code: &str,
) -> Result<bool, AppError> {
    let now = Utc::now();

    // Begin transaction
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process email verification",
        )
    })?;

    // Check if the verification code is valid
    let verification = sqlx::query!(
        r#"
        SELECT id
        FROM email_verifications
        WHERE user_id = $1 AND email = $2 AND verification_code = $3
            AND verified_at IS NULL AND expires_at > $4
        "#,
        user_id,
        email,
        verification_code,
        now
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to verify email code: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to verify email code",
        )
    })?;

    match verification {
        Some(record) => {
            // Mark the verification as used
            sqlx::query!(
                r#"
                UPDATE email_verifications
                SET verified_at = $1
                WHERE id = $2
                "#,
                now,
                record.id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update email verification: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to update email verification",
                )
            })?;

            // Mark the email as verified in the MFA table
            sqlx::query!(
                r#"
                UPDATE user_mfa_email
                SET verified = true, updated_at = $1
                WHERE user_id = $2 AND email = $3
                "#,
                now,
                user_id,
                email
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update MFA email: {:?}", e);
                AppError::new(ErrorType::InternalServerError, "Failed to update MFA email")
            })?;

            // Register/update the MFA method in user_mfa_methods
            sqlx::query!(
                r#"
                INSERT INTO user_mfa_methods (user_id, method, is_enabled)
                VALUES ($1, 'EMAIL', true)
                ON CONFLICT (user_id, method) DO UPDATE
                SET is_enabled = true, updated_at = $2
                "#,
                user_id,
                now
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update MFA method: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to update MFA method",
                )
            })?;

            // Commit transaction
            tx.commit().await.map_err(|e| {
                error!("Failed to commit transaction: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to complete email verification",
                )
            })?;

            Ok(true)
        }
        None => {
            // Code not valid or expired
            tx.rollback().await.ok(); // Ignore rollback errors
            Ok(false)
        }
    }
}

/// Checks if a phone number is already registered for MFA for the given user
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `phone_number` - The phone number to check
///
/// # Returns
///
/// A `Result` containing a boolean indicating if the phone number is already registered
pub async fn is_phone_registered_for_mfa(
    pool: &PgPool,
    user_id: i64,
    phone_number: &str,
) -> Result<bool, AppError> {
    match sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM user_mfa_sms
            WHERE user_id = $1 AND phone_number = $2 AND verified = true
        ) as "exists!"
        "#,
        user_id,
        phone_number
    )
    .fetch_one(pool)
    .await
    {
        Ok(exists) => Ok(exists),
        Err(e) => {
            error!("Failed to check if phone is registered for MFA: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to check SMS MFA registration",
            ))
        }
    }
}

/// Creates a verification record for SMS MFA
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `phone_number` - The phone number to verify
/// * `verification_code` - The verification code
///
/// # Returns
///
/// A `Result` containing the ID of the created verification record
pub async fn create_sms_verification(
    pool: &PgPool,
    user_id: i64,
    phone_number: &str,
    verification_code: &str,
) -> Result<i64, AppError> {
    // Calculate the expiration time (15 minutes from now)
    let expires_at = Utc::now() + Duration::minutes(15);

    // First, insert or update the user_mfa_sms record
    match sqlx::query_scalar!(
        r#"
        INSERT INTO user_mfa_sms (user_id, phone_number, verified)
        VALUES ($1, $2, false)
        ON CONFLICT (user_id, phone_number) DO UPDATE
        SET verified = false, updated_at = CURRENT_TIMESTAMP
        RETURNING id
        "#,
        user_id,
        phone_number
    )
    .fetch_one(pool)
    .await
    {
        Ok(mfa_sms_id) => {
            // Now create the phone verification record to store the code
            match sqlx::query_scalar!(
                r#"
                INSERT INTO phone_verifications (user_id, phone_number, verification_code, expires_at)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                "#,
                user_id,
                phone_number,
                verification_code,
                expires_at
            )
            .fetch_one(pool)
            .await
            {
                Ok(id) => Ok(id),
                Err(e) => {
                    error!("Failed to create phone verification: {:?}", e);
                    Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Failed to create phone verification",
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to create MFA SMS record: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to create MFA SMS record",
            ))
        }
    }
}

/// Verifies an SMS verification code for MFA
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool
/// * `user_id` - The ID of the user
/// * `phone_number` - The phone number to verify
/// * `verification_code` - The verification code to verify
///
/// # Returns
///
/// A `Result` containing a boolean indicating if the code was valid
pub async fn verify_sms_code(
    pool: &PgPool,
    user_id: i64,
    phone_number: &str,
    verification_code: &str,
) -> Result<bool, AppError> {
    let now = Utc::now();

    // Begin transaction
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process SMS verification",
        )
    })?;

    // Check if the verification code is valid and not expired
    let verification = sqlx::query!(
        r#"
        SELECT id
        FROM phone_verifications
        WHERE user_id = $1 AND phone_number = $2 AND verification_code = $3
            AND verified_at IS NULL AND expires_at > $4
        "#,
        user_id,
        phone_number,
        verification_code,
        now
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to verify SMS code: {:?}", e);
        AppError::new(ErrorType::InternalServerError, "Failed to verify SMS code")
    })?;

    match verification {
        Some(record) => {
            // Mark the verification as used
            sqlx::query!(
                r#"
                UPDATE phone_verifications
                SET verified_at = $1
                WHERE id = $2
                "#,
                now,
                record.id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update phone verification: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to update phone verification",
                )
            })?;

            // Mark the phone number as verified in the MFA table
            sqlx::query!(
                r#"
                UPDATE user_mfa_sms
                SET verified = true, updated_at = $1
                WHERE user_id = $2 AND phone_number = $3
                "#,
                now,
                user_id,
                phone_number
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update MFA SMS: {:?}", e);
                AppError::new(ErrorType::InternalServerError, "Failed to update MFA SMS")
            })?;

            // Register/update the MFA method in user_mfa_methods
            sqlx::query!(
                r#"
                INSERT INTO user_mfa_methods (user_id, method, is_enabled)
                VALUES ($1, 'SMS', true)
                ON CONFLICT (user_id, method) DO UPDATE
                SET is_enabled = true, updated_at = $2
                "#,
                user_id,
                now
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Failed to update MFA method: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to update MFA method",
                )
            })?;

            // Commit transaction
            tx.commit().await.map_err(|e| {
                error!("Failed to commit transaction: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to complete SMS verification",
                )
            })?;

            Ok(true)
        }
        None => {
            // Code not valid or expired
            tx.rollback().await.ok(); // Ignore rollback errors
            Ok(false)
        }
    }
}

/// Generates a random 6-digit verification code
///
/// # Returns
///
/// A string containing a 6-digit verification code
pub fn generate_verification_code() -> String {
    let mut rng = ChaCha20Rng::seed_from_u64(rand::random());

    // Generate a random 32-bit number and take modulo to get 6 digits
    let mut random_bytes = [0u8; 4];
    rng.fill_bytes(&mut random_bytes);

    // Convert bytes to u32 and get a number in range 0-999999
    let random_number = u32::from_le_bytes(random_bytes) % 1_000_000;

    // Format as 6 digits with leading zeros
    format!("{:06}", random_number)
}
