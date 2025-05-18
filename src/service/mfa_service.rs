use crate::api::model::mfa::{
    BackupCodesResponse, DeleteBackupCodesResponse, TotpResponse, ValidateBackupCodeResponse,
};
use crate::config::app_config::AppState;
use crate::db::entity::mfa::TotpSecret;
use crate::db::repo::{mfa_repository, users_repository};
use crate::error::error_model::{AppError, ErrorType};
use crate::util::crypto_helper;
use crate::util::crypto_helper::hash_password_sign_with_hmac;
use argon2::PasswordVerifier;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use futures::future::join_all;
use hmac::Mac;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use tracing::error;

/// Registers a new TOTP device for a user.
///
/// This function:
/// 1. Retrieves the user from the database
/// 2. Generates a new TOTP secret
/// 3. Encrypts and stores the secret in the database
/// 4. Generates a QR code for the user to scan
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools
/// * `user_key` - The unique identifier for the user
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the TOTP QR code on success,
/// or an `AppError` on failure.
pub async fn register_totp(
    State(state): State<Arc<AppState>>,
    user_key: &String,
) -> Result<Response, AppError> {
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key).await;
    let user = match user {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to get user: {:?}", e);
            return Err(AppError::new(ErrorType::NotFound, "User not found"));
        }
    };
    let email = user.email;

    // Generate a TOTP secret key
    let secret = generate_totp_secret().await;
    let secret_str = BASE64_URL_SAFE_NO_PAD.encode(secret);

    // Generate the QR code
    let totp = generate_totp(&secret_str, &email).await.map_err(|e| {
        error!("Failed to generate TOTP: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to generate TOTP configuration",
        )
    })?;

    // Get the application encryption key
    let encryption_key = &state.encryption_key;

    // Encrypt the TOTP secret before storing
    let (nonce, encrypted_secret) =
        crypto_helper::aes_gcm_encrypt(encryption_key, secret_str.as_bytes())
            .await
            .map_err(|e| {
                error!("Failed to encrypt TOTP secret: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to secure TOTP secret",
                )
            })?;

    // Store the encrypted secret in the database
    let totp_secret = TotpSecret {
        encrypted_secret,
        nonce,
    };

    // Save to database
    mfa_repository::save_totp_secret(&state.pg_pool, user.id, &totp_secret).await?;

    // Generate response with QR code
    let totp_url = totp.get_url();
    let qr_base64 = totp.get_qr_base64().map_err(|e| {
        error!("Failed to generate QR code: {:?}", e);
        AppError::new(ErrorType::InternalServerError, "Failed to generate QR code")
    })?;

    let response = TotpResponse {
        totp_url,
        qr_code: qr_base64,
        qr_type: "image/png".to_string(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Validates a TOTP code provided by the user.
///
/// This function:
/// 1. Retrieves the user's TOTP secret from the database
/// 2. Decrypts the secret
/// 3. Verifies if the provided code is valid
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools
/// * `user_key` - The unique identifier for the user
/// * `totp_code` - The TOTP code provided by the user
///
/// # Returns
///
/// Returns a `Result` containing a boolean indicating if the code is valid,
/// or an `AppError` on failure.
pub async fn validate_totp(
    State(state): State<Arc<AppState>>,
    user_key: &String,
    totp_code: &String,
) -> Result<bool, AppError> {
    // Get the user
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key).await;
    let user = match user {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to get user: {:?}", e);
            return Err(AppError::new(ErrorType::NotFound, "User not found"));
        }
    };

    // Get the user's TOTP secret
    let totp_record = mfa_repository::get_totp_secret(&state.pg_pool, user.id).await?;

    // Get the encrypted secret
    let totp_secret = totp_record.to_totp_secret().map_err(|e| {
        error!("Failed to parse TOTP secret: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process TOTP data",
        )
    })?;

    // Get the encryption key
    let encryption_key = &state.encryption_key;

    // Decrypt the TOTP secret
    let decrypted_secret = crypto_helper::aes_gcm_decrypt(
        encryption_key,
        &totp_secret.nonce,
        &totp_secret.encrypted_secret,
    )
    .await
    .map_err(|e| {
        error!("Failed to decrypt TOTP secret: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process TOTP authentication",
        )
    })?;

    // Convert bytes to string
    let secret_str = String::from_utf8(decrypted_secret).map_err(|e| {
        error!("Failed to convert TOTP secret to string: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process TOTP data",
        )
    })?;

    // Create TOTP instance with the decrypted secret
    let totp = generate_totp(&secret_str, &user.email).await.map_err(|e| {
        error!("Failed to generate TOTP: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process TOTP verification",
        )
    })?;

    // Verify the provided code
    let is_valid = totp.check_current(totp_code).map_err(|e| {
        error!("Failed to verify TOTP code: {:?}", e);
        AppError::new(ErrorType::InternalServerError, "Failed to verify TOTP code")
    })?;

    Ok(is_valid)
}

/// Generates backup codes for a user and saves them to the database.
///
/// This function:
/// 1. Retrieves the user from the database using their unique key.
/// 2. Generates 10 backup codes.
/// 3. Hashes the backup codes in parallel using HMAC for security.
/// 4. Saves the hashed backup codes to the database.
/// 5. Returns the plaintext backup codes in the response.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools and other shared resources.
/// * `user_key` - The unique identifier for the user.
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the plaintext backup codes on success,
/// or an `AppError` on failure.
///
/// # Errors
///
/// This function returns an `AppError` if:
/// - The user cannot be found in the database.
/// - Hashing the backup codes fails for all codes.
/// - Saving the hashed backup codes to the database fails.
pub async fn generate_backup_codes(
    State(state): State<Arc<AppState>>,
    user_key: &String,
) -> Result<Response, AppError> {
    // Retrieve the user
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key)
        .await
        .map_err(|_| AppError::new(ErrorType::NotFound, "User not found"))?;

    // Generate 10 backup codes
    let backup_codes = crypto_helper::generate_backup_codes(10, 8).await;

    // Hash the backup codes in parallel
    let hash_futures = backup_codes.iter().map(|code| {
        let state = state.clone();
        let code = code.clone();
        async move {
            match hash_password_sign_with_hmac(&state, &code).await {
                Ok((hashed_code, hmac)) => Some((
                    crate::db::entity::mfa::BackupCode {
                        hash: hashed_code,
                        hmac,
                    },
                    code,
                )),
                Err(e) => {
                    error!("Failed to hash backup code: {:?}", e);
                    None
                }
            }
        }
    });

    let results = join_all(hash_futures).await;

    let mut backup_code_records = Vec::new();
    let mut successful_codes = Vec::new();

    for result in results.into_iter().flatten() {
        let (record, code) = result;
        backup_code_records.push(record);
        successful_codes.push(code);
    }

    if backup_code_records.is_empty() {
        return Err(AppError::new(
            ErrorType::InternalServerError,
            "Failed to generate any valid backup codes",
        ));
    }

    mfa_repository::save_mfa_backup_codes(&state.pg_pool, user.id, &backup_code_records)
        .await
        .map_err(|_| {
            AppError::new(
                ErrorType::InternalServerError,
                "Failed to save backup codes",
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(BackupCodesResponse {
            backup_codes: successful_codes,
        }),
    )
        .into_response())
}

/// Creates a TOTP instance for a user with the given secret and email.
///
/// # Arguments
///
/// * `secret_key` - The TOTP secret key
/// * `email` - The user's email address
///
/// # Returns
///ss
/// Returns a `Result` containing a `TOTP` instance,
/// or an error if the TOTP creation fails.
async fn generate_totp(
    secret_key: &String,
    email: &String,
) -> Result<TOTP, Box<dyn std::error::Error>> {
    // Create a secure TOTP secret from the raw bytes
    let secret_bytes = match totp_rs::Secret::Raw(secret_key.as_bytes().to_vec()).to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Error creating TOTP secret: {}", e).into()),
    };

    let totp = TOTP::new(
        Algorithm::SHA1,
        8,  // 8-digit code
        1,  // 1 step window
        30, // 30-second code validity
        secret_bytes,
        Some("c12.io".to_string()), // Issuer
        email.to_string(),          // Account name
    )
    .map_err(|e| format!("Error creating TOTP: {}", e))?;

    Ok(totp)
}

/// Generates a 32-byte TOTP secret key using a cryptographically secure random number generator.
///
/// # Returns
///
/// A `[u8; 32]` array containing the generated secret key.
async fn generate_totp_secret() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    secret
}

/// Validates a backup code provided by the user.
///
/// This function:
/// 1. Retrieves the user from the database
/// 2. Gets the user's unused backup codes
/// 3. Attempts to verify the provided backup code against the stored hashes
/// 4. If valid, marks the backup code as used
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools
/// * `user_key` - The unique identifier for the user
/// * `backup_code` - The backup code provided by the user
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the validation result,
/// or an `AppError` on failure.
pub async fn validate_backup_code(
    State(state): State<Arc<AppState>>,
    user_key: &String,
    backup_code: &String,
) -> Result<Response, AppError> {
    // Get the user
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key)
        .await
        .map_err(|_| AppError::new(ErrorType::NotFound, "User not found"))?;

    // Get all unused backup codes for the user
    let backup_codes =
        mfa_repository::get_unused_backup_codes_by_user_id(&state.pg_pool, user.id).await?;

    if backup_codes.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(ValidateBackupCodeResponse { is_valid: false }),
        )
            .into_response());
    }

    // Try each backup code
    for code_record in backup_codes {
        // Parse the hash to check if it's a valid Argon2 hash
        if let Ok(parsed_hash) = argon2::PasswordHash::new(&code_record.backup_code_hash) {
            // Setup Argon2 with the application's pepper
            let argon2 = argon2::Argon2::new_with_secret(
                &state.argon_pepper.as_bytes(),
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::default(),
            )
            .map_err(|_| {
                error!("Failed to initialize Argon2");
                AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to process backup code verification",
                )
            })?;

            // Verify the backup code against the stored hash
            if argon2
                .verify_password(backup_code.as_bytes(), &parsed_hash)
                .is_ok()
            {
                // Verify the HMAC for tamper protection
                type HmacSha512 = hmac::Hmac<sha2::Sha512>;
                let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(&state.hmac_key.as_bytes())
                    .map_err(|_| {
                        error!("Failed to initialize HMAC");
                        AppError::new(
                            ErrorType::InternalServerError,
                            "Failed to process backup code verification",
                        )
                    })?;

                mac.update(code_record.backup_code_hash.as_bytes());
                if mac.verify_slice(&code_record.backup_code_hmac).is_ok() {
                    // Code is valid - mark it as used
                    mfa_repository::mark_backup_code_as_used(&state.pg_pool, code_record.id)
                        .await?;

                    // Return success
                    return Ok((
                        StatusCode::OK,
                        Json(ValidateBackupCodeResponse { is_valid: true }),
                    )
                        .into_response());
                }
            }
        }
    }

    // No valid backup code found
    Ok((
        StatusCode::OK,
        Json(ValidateBackupCodeResponse { is_valid: false }),
    )
        .into_response())
}

/// Deletes (soft delete) all backup codes for a user.
///
/// This function:
/// 1. Retrieves the user from the database using their unique key
/// 2. Soft deletes all backup codes for the user by setting the deleted_at timestamp
/// 3. Returns the number of backup codes that were deleted
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools
/// * `user_key` - The unique identifier for the user
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the number of deleted backup codes,
/// or an `AppError` on failure.
pub async fn delete_backup_codes(
    State(state): State<Arc<AppState>>,
    user_key: &String,
) -> Result<Response, AppError> {
    // Get the user
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key)
        .await
        .map_err(|_| AppError::new(ErrorType::NotFound, "User not found"))?;

    // Soft delete all backup codes for the user
    let deleted_count = mfa_repository::soft_delete_backup_codes(&state.pg_pool, user.id).await?;

    // Return the result
    Ok((
        StatusCode::OK,
        Json(DeleteBackupCodesResponse { deleted_count }),
    )
        .into_response())
}
