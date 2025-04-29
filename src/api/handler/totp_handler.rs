use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::mfa_service;
use crate::service::mfa_service::{
    BackupCodesResponse, TotpResponse, ValidateTotpRequest, ValidateTotpResponse,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tracing::{debug, error};

/// Creates a router for TOTP-related API endpoints.
///
/// # Returns
///
/// A router with the following endpoints:
/// - POST /register/{user_key} - Register a new TOTP device for a user
/// - POST /validate/{user_key} - Validate a TOTP code
/// - GET /backup-codes/{user_key} - Generate backup codes for a user
///
/// # Example
///
/// ```rust
/// let app = Router::new()
///     .nest("/mfa/totp", totp_routes());
/// ```
pub fn totp_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register/{user_key}", post(totp_register))
        .route("/validate/{user_key}", post(totp_validate))
        .route("/backup-codes/{user_key}", get(totp_backup_codes))
}

/// Register a new TOTP device for a user.
///
/// This endpoint generates a new TOTP secret for the user, stores it securely,
/// and returns a QR code that can be scanned by authenticator apps.
///
/// # Path parameters
///
/// * `user_key` - The unique identifier for the user
///
/// # Returns
///
/// A TOTP response containing a QR code and TOTP URL.
#[utoipa::path(
    post,
    path = "/mfa/totp/register/{user_key}",
    tag = "TOTP",
    params(
        ("user_key" = String, Path, description = "User's unique key")
    ),
    responses(
        (status = 200, description = "TOTP successfully registered", body = TotpResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn totp_register(
    State(state): State<Arc<AppState>>,
    Path(user_key): Path<String>,
) -> Result<Response, AppError> {
    debug!("Registering TOTP for user with key: {}", user_key);

    // Call the service to register the TOTP for the user
    let result = mfa_service::register_totp(State(state), &user_key).await;

    // Log errors if they occur
    if let Err(ref e) = result {
        error!("Failed to register TOTP for user {}: {:?}", user_key, e);
    }

    // Return the result
    result
}

/// Validate a TOTP code provided by a user.
///
/// This endpoint verifies if the provided TOTP code is valid for the user.
///
/// # Path parameters
///
/// * `user_key` - The unique identifier for the user
///
/// # Request body
///
/// A JSON object containing the TOTP code to validate.
///
/// # Returns
///
/// A JSON response indicating whether the code is valid.
#[utoipa::path(
    post,
    path = "/mfa/totp/validate/{user_key}",
    tag = "TOTP",
    params(
        ("user_key" = String, Path, description = "User's unique key")
    ),
    request_body = ValidateTotpRequest,
    responses(
        (status = 200, description = "TOTP validation result", body = ValidateTotpResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn totp_validate(
    State(state): State<Arc<AppState>>,
    Path(user_key): Path<String>,
    Json(request): Json<ValidateTotpRequest>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Validating TOTP code for user with key: {}", user_key);

    let is_valid =
        match mfa_service::validate_totp(State(state), &user_key, &request.totp_code).await {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to validate TOTP for user {}: {:?}", user_key, e);
                return Err(e);
            }
        };

    let response = ValidateTotpResponse { is_valid };
    Ok((StatusCode::OK, Json(response)))
}

/// Generate backup codes for a user.
///
/// This endpoint generates a set of backup codes that can be used
/// when the user's TOTP device is unavailable.
///
/// # Path parameters
///
/// * `user_key` - The unique identifier for the user
///
/// # Returns
///
/// A JSON response containing a list of backup codes.
#[utoipa::path(
    get,
    path = "/mfa/totp/backup-codes/{user_key}",
    tag = "TOTP",
    params(
        ("user_key" = String, Path, description = "User's unique key")
    ),
    responses(
        (status = 200, description = "Backup codes generated", body = BackupCodesResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn totp_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(user_key): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Generating backup codes for user with key: {}", user_key);

    let backup_codes = match mfa_service::generate_backup_codes(State(state), &user_key).await {
        Ok(codes) => codes,
        Err(e) => {
            error!(
                "Failed to generate backup codes for user {}: {:?}",
                user_key, e
            );
            return Err(e);
        }
    };

    debug!(
        "Successfully generated {} backup codes for user {}",
        backup_codes.len(),
        user_key
    );
    let response = BackupCodesResponse { backup_codes };
    Ok((StatusCode::OK, Json(response)))
}
