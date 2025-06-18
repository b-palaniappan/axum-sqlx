use crate::api::model::mfa::{
    EmailMfaRegisterRequest, EmailMfaRegisterResponse, EmailMfaVerifyRequest,
    EmailMfaVerifyResponse, SmsMfaRegisterRequest, SmsMfaRegisterResponse, SmsMfaVerifyRequest,
    SmsMfaVerifyResponse,
};
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::mfa_service;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use std::sync::Arc;
use tracing::{debug, error};
use validator::Validate;

/// Creates a router for MFA-related API endpoints.
///
/// # Returns
///
/// A router with the following endpoints:
/// - POST /email/register/{key} - Register email for MFA
/// - POST /email/verify/{key} - Verify email for MFA
/// - POST /sms/register/{key} - Register SMS for MFA
/// - POST /sms/verify/{key} - Verify SMS for MFA
///
/// # Example
///
/// ```rust,no_run
/// # use axum::Router;
/// # use axum_sqlx::api::handler::mfa_handler::mfa_routes;
/// # use axum_sqlx::AppState;
/// # use std::sync::Arc;
/// #
/// # fn example(state: Arc<AppState>) {
/// let app: Router = Router::new()
///     .nest("/mfa", mfa_routes())
///     .with_state(state);
/// # }
/// ```
pub fn mfa_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/email/register/{key}", post(register_email_mfa))
        .route("/email/verify/{key}", post(verify_email_mfa))
        .route("/sms/register/{key}", post(register_sms_mfa))
        .route("/sms/verify/{key}", post(verify_sms_mfa))
}

/// Register email for MFA.
///
/// This endpoint registers an email address for Multi-Factor Authentication.
/// If the email is not already registered, a verification code is sent to it.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Request body
///
/// A JSON object containing the email to register.
///
/// # Returns
///
/// A JSON response indicating whether the email was registered and a verification code was sent.
#[utoipa::path(
    post,
    path = "/mfa/email/register/{key}",
    tag = "Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = EmailMfaRegisterRequest,
    responses(
        (status = 200, description = "Email registration initiated", body = EmailMfaRegisterResponse),
        (status = 400, description = "Invalid request", body = ApiError),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn register_email_mfa(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<EmailMfaRegisterRequest>,
) -> Result<Response, AppError> {
    // Validate the request
    if let Err(validation_errors) = request.validate() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(EmailMfaRegisterResponse {
                success: false,
                message: format!("Validation error: {}", validation_errors),
                already_registered: false,
            }),
        )
            .into_response());
    }

    debug!(
        "Registering email for MFA for user with key: {}, email: {}",
        key, request.email
    );

    // Call the service to register the email for MFA
    match mfa_service::register_email_mfa(State(state), &key, &request.email).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to register email for MFA for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Verify email for MFA.
///
/// This endpoint verifies an email address for Multi-Factor Authentication
/// using the verification code that was sent to it.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Request body
///
/// A JSON object containing the email and verification code.
///
/// # Returns
///
/// A JSON response indicating whether the email was successfully verified.
#[utoipa::path(
    post,
    path = "/mfa/email/verify/{key}",
    tag = "Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = EmailMfaVerifyRequest,
    responses(
        (status = 200, description = "Email verification successful", body = EmailMfaVerifyResponse),
        (status = 400, description = "Invalid request or verification code", body = EmailMfaVerifyResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn verify_email_mfa(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<EmailMfaVerifyRequest>,
) -> Result<Response, AppError> {
    // Validate the request
    if let Err(validation_errors) = request.validate() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(EmailMfaVerifyResponse {
                success: false,
                message: format!("Validation error: {}", validation_errors),
            }),
        )
            .into_response());
    }

    debug!(
        "Verifying email for MFA for user with key: {}, email: {}",
        key, request.email
    );

    // Call the service to verify the email for MFA
    match mfa_service::verify_email_mfa(
        State(state),
        &key,
        &request.email,
        &request.verification_code,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to verify email for MFA for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Register SMS for MFA.
///
/// This endpoint registers a phone number for Multi-Factor Authentication via SMS.
/// If the phone number is not already registered, a verification code is sent to it.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Request body
///
/// A JSON object containing the phone number to register.
///
/// # Returns
///
/// A JSON response indicating whether the phone number was registered and a verification code was sent.
#[utoipa::path(
    post,
    path = "/mfa/sms/register/{key}",
    tag = "Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = SmsMfaRegisterRequest,
    responses(
        (status = 200, description = "SMS registration initiated", body = SmsMfaRegisterResponse),
        (status = 400, description = "Invalid request", body = ApiError),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn register_sms_mfa(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<SmsMfaRegisterRequest>,
) -> Result<Response, AppError> {
    // Validate the request
    if let Err(validation_errors) = request.validate() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(SmsMfaRegisterResponse {
                success: false,
                message: format!("Validation error: {}", validation_errors),
                already_registered: false,
            }),
        )
            .into_response());
    }

    debug!(
        "Registering SMS for MFA for user with key: {}, phone: {}",
        key, request.phone_number
    );

    // Call the service to register the SMS for MFA
    match mfa_service::register_sms_mfa(State(state), &key, &request.phone_number).await {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to register SMS for MFA for user {}: {:?}", key, e);
            Err(e)
        }
    }
}

/// Verify SMS for MFA.
///
/// This endpoint verifies a phone number for Multi-Factor Authentication via SMS
/// using the verification code that was sent to it.
///
/// # Path parameters
///
/// * `key` - The unique identifier for the user
///
/// # Request body
///
/// A JSON object containing the phone number and verification code.
///
/// # Returns
///
/// A JSON response indicating whether the phone number was successfully verified.
#[utoipa::path(
    post,
    path = "/mfa/sms/verify/{key}",
    tag = "Multi-Factor Authentication",
    params(
        ("key" = String, Path, description = "User's unique key")
    ),
    request_body = SmsMfaVerifyRequest,
    responses(
        (status = 200, description = "SMS verification successful", body = SmsMfaVerifyResponse),
        (status = 400, description = "Invalid request or verification code", body = SmsMfaVerifyResponse),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
async fn verify_sms_mfa(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(request): Json<SmsMfaVerifyRequest>,
) -> Result<Response, AppError> {
    // Validate the request
    if let Err(validation_errors) = request.validate() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(SmsMfaVerifyResponse {
                success: false,
                message: format!("Validation error: {}", validation_errors),
            }),
        )
            .into_response());
    }

    debug!(
        "Verifying SMS for MFA for user with key: {}, phone: {}",
        key, request.phone_number
    );

    // Call the service to verify the SMS for MFA
    match mfa_service::verify_sms_mfa(
        State(state),
        &key,
        &request.phone_number,
        &request.verification_code,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Failed to verify SMS for MFA for user {}: {:?}", key, e);
            Err(e)
        }
    }
}
