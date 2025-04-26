// TOTP - Registration with QR Code.
// TOTP - Validation.
// Generate Backup Secret codes. About 10 codes which are 8 Characters alphanumeric.
// Email/SMS MFA - Generate
// Email/SMS MFA - Verify

use crate::config::app_config::AppState;
use crate::db::repo::users_repository;
use crate::error::error_model::{AppError, ErrorType};
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
use totp_rs::TOTP;
use tracing::error;
use utoipa::ToSchema;

pub async fn register_totp(
    State(state): State<Arc<AppState>>,
    user_key: &String,
) -> Result<Response, AppError> {
    // TODO: get user by user_key
    let user = users_repository::get_user_by_key(&state.pg_pool, user_key).await;
    match user {
        Ok(user) => {
            let email = user.email;
            // Generate a TOTP secret key
            let secret = generate_totp_secret().await;
            let secret_str = BASE64_URL_SAFE_NO_PAD.encode(secret);

            // Generate the QR code
            let qr_code = generate_totp(&secret_str, &email).await;
            match qr_code {
                Ok(totp) => {
                    // Return the QR code as a Base64 string
                    let totp_url = totp.get_url();
                    let qr_base64 = totp.get_qr_base64().unwrap();

                    let response = TotpResponse {
                        totp_url,
                        qr_code: qr_base64,
                    };

                    //TODO: Store the secret in the database
                    Ok((StatusCode::OK, Json(response)).into_response())
                }
                Err(e) => Err(AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                )),
            }
        }
        Err(e) => {
            error!("Error: {:?}", e);
            return Err(AppError::new(
                ErrorType::NotFound,
                "Unable to fetch the user by given user_key.",
            ));
        }
    }
}

async fn generate_totp(
    secret_key: &String,
    email: &String,
) -> Result<TOTP, Box<dyn std::error::Error>> {
    let totp = TOTP::new(
        totp_rs::Algorithm::SHA1,
        8,
        1,
        30,
        totp_rs::Secret::Raw(secret_key.as_bytes().to_vec())
            .to_bytes()
            .unwrap(),
        Some("c12.io".to_string()),
        email.to_string(),
    )
    .map_err(|_| "Error creating totp".to_string())?;
    Ok(totp)
}

/// Generates a 32-byte TOTP secret key using a cryptographically secure random number generator.
///
/// # Returns
///
/// A `[u8; 32]` array containing the generated secret key.
///
/// # Example
///
/// ```rust
/// let secret = generate_totp_secret();
/// println!("Generated TOTP secret: {:?}", secret);
/// ```
async fn generate_totp_secret() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    secret
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct TotpResponse {
    totp_url: String,
    qr_code: String,
}
