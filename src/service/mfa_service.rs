use crate::config::app_config::AppState;
use crate::db::entity::mfa::TotpSecret;
use crate::db::repo::{mfa_repository, users_repository};
use crate::error::error_model::{AppError, ErrorType};
use crate::util::crypto_helper;
use crate::util::crypto_helper::hash_password_sign_with_hmac;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use tracing::error;
use utoipa::ToSchema;

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

/// Generate backup codes for when the TOTP device is unavailable.
///
/// This function:
/// 1. Retrieves the user from the database
/// 2. Generates backup codes
/// 3. Encrypts and stores the codes in the database
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools
/// * `user_key` - The unique identifier for the user
///
/// # Returns
///
/// Returns a `Result` containing a vector of backup codes,
/// or an `AppError` on failure.
pub async fn generate_backup_codes(
    State(state): State<Arc<AppState>>,
    user_key: &String,
) -> Result<Response, AppError> {
    // Get the user
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key).await;
    let user = match user {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to get user: {:?}", e);
            return Err(AppError::new(ErrorType::NotFound, "User not found"));
        }
    };

    // Generate 10 backup codes, each 8 characters long
    let backup_codes = crypto_helper::generate_backup_codes(10, 8).await;

    // Return the plaintext backup codes to the user
    // should store these safely as they won't be retrievable in plaintext again
    Ok((
        StatusCode::CREATED,
        Json(BackupCodesResponse { backup_codes }),
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

/// Request to validate a TOTP code
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTotpRequest {
    pub totp_code: String,
}

/// Response containing TOTP information
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpResponse {
    /// URL that can be used to manually configure TOTP app
    pub totp_url: String,
    /// Base64-encoded QR code image
    pub qr_code: String,
}

/// Response after validating a TOTP code
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTotpResponse {
    /// Whether the TOTP code is valid
    pub is_valid: bool,
}

/// Response containing backup codes
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupCodesResponse {
    /// List of backup codes
    pub backup_codes: Vec<String>,
}
