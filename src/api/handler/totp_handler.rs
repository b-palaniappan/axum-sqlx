use crate::api::model::mfa::{
    BackupCodesResponse, DeleteBackupCodesResponse, DeleteTotpResponse, TotpResponse,
    ValidateBackupCodeRequest, ValidateBackupCodeResponse, ValidateTotpRequest,
    ValidateTotpResponse,
};
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::mfa_service;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tracing::{debug, error};

/// Creates a router for TOTP-related API endpoints.
///
/// # Returns
///
/// A router with the following endpoints:
/// - POST /register/{key} - Register a new TOTP device for a user
/// - POST /validate/{key} - Validate a TOTP code
/// - GET /backup-codes/{key} - Generate backup codes for a user
/// - POST /validate-backup/{key} - Validate a backup code
/// - DELETE /backup-codes/{key} - Delete all backup codes for a user
///
/// # Example
///
/// ```rust,no_run
/// # use axum::Router;
/// # use axum_sqlx::api::handler::totp_handler::totp_routes;
/// # use axum_sqlx::AppState;
/// # use std::sync::Arc;
/// #
/// # fn example(state: Arc<AppState>) {
/// let app: Router = Router::new()
///     .nest("/mfa/totp", totp_routes())
///     .with_state(state);
/// # }
/// ```
pub fn totp_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register/{key}", post(totp_register))
        .route("/validate/{key}", post(totp_validate))
        .route("/{key}", delete(totp_delete))
        .route("/backup-codes/{key}", get(totp_backup_codes))
        .route("/validate-backup/{key}", post(validate_backup_code))
        .route(
            "/backup-codes/{key}",
            axum::routing::delete(delete_backup_codes),
        )
}

/// Register a new TOTP device for a user.
///
/// This endpoint generates a new TOTP secret for the user, stores it securely,
/// and returns a QR code that can be scanned by authenticator apps.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Returns
///
/// A TOTP response containing a QR code and TOTP URL.
#[utoipa::path(
    post,
    path = "/mfa/totp/register/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    responses(
        (status = 200, description = "TOTP successfully registered", body = TotpResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn totp_register(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    debug!("Registering TOTP for user with key: {}", key);

    // Call the service to register the TOTP for the user
    let result = mfa_service::register_totp(State(state), &key).await;

    // Log errors if they occur
    if let Err(ref e) = result {
        error!("Failed to register TOTP for user {}: {:?}", key, e);
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
/// * `key` - The unique identifier for the user
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
    path = "/mfa/totp/validate/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = ValidateTotpRequest,
    responses(
        (status = 200, description = "TOTP validation result", body = ValidateTotpResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn totp_validate(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<ValidateTotpRequest>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Validating TOTP code for user with key: {}", key);

    let is_valid = match mfa_service::validate_totp(State(state), &key, &request.totp_code).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to validate TOTP for user {}: {:?}", key, e);
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
/// * `key` - The unique identifier for the user
///
/// # Returns
///
/// A JSON response containing a list of backup codes.
#[utoipa::path(
    get,
    path = "/mfa/totp/backup-codes/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "Backup codes generated", body = BackupCodesResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn totp_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    match mfa_service::generate_backup_codes(State(state), &key).await {
        Ok(codes) => Ok(codes),
        Err(e) => {
            error!("Failed to generate backup codes for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Validates a backup code for a user.
///
/// This endpoint checks if the provided backup code is valid for the user
/// identified by the given key. Backup codes are used as a fallback when
/// TOTP codes are unavailable.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user.
///
/// # Request body
///
/// A JSON object containing the backup code to validate.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - A success response with validation details if the backup code is valid.
/// - An `AppError` if the user is not found or validation fails.
///
/// # Errors
///
/// This function returns an `AppError` if:
/// - The user cannot be found in the database.
/// - The provided backup code is invalid.
/// - An internal server error occurs during validation.
#[utoipa::path(
    post,
    path = "/mfa/totp/validate-backup/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = ValidateBackupCodeRequest,
    responses(
        (status = 200, description = "Backup code validation result", body = ValidateBackupCodeResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn validate_backup_code(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<ValidateBackupCodeRequest>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Validating backup code for user with key: {}", key);

    match mfa_service::validate_backup_code(State(state), &key, &request.backup_code).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to validate backup code for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Delete all backup codes for a user.
///
/// This endpoint soft deletes all backup codes for a user by setting
/// the deleted_at timestamp, making them unusable for future validation.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Returns
///
/// A JSON response containing the number of backup codes that were deleted.
#[utoipa::path(
    delete,
    path = "/mfa/totp/backup-codes/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "Backup codes deleted successfully", body = DeleteBackupCodesResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn delete_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Deleting backup codes for user with key: {}", key);

    match mfa_service::delete_backup_codes(State(state), &key).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to delete backup codes for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Delete TOTP secret for a user.
///
/// This endpoint disables TOTP authentication for a user by soft-deleting their TOTP secret.
/// It performs a soft delete by setting the deleted_at timestamp, making the TOTP secret unusable
/// for future validation.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Returns
///
/// A JSON response indicating whether the TOTP secret was successfully deleted.
#[utoipa::path(
    delete,
    path = "/mfa/totp/{key}",
    tag = "TOTP Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "TOTP secret deleted successfully", body = DeleteTotpResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn totp_delete(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    match mfa_service::delete_totp(State(state), &key).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to delete TOTP secret for user {}: {:?}", key, e);
            Err(e)
        }
    }
}
