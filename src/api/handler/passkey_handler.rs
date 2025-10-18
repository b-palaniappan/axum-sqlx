use crate::api::model::auth::{PasskeyAuthenticationRequest, PasskeyRegistrationRequest};
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::auth_service;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub fn passkey_auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register/start", post(registration_start_handler))
        .route("/register/finish", post(registration_finish_handler))
        .route("/login/start", post(login_start_handler))
        .route("/login/finish", post(login_finish_handler))
        .route("/logout", get(logout_handler))
}

/// Handles the start of the passkey registration process.
///
/// This endpoint generates a registration challenge for the client to complete
/// the WebAuthn registration process.
///
/// # Endpoint
/// `POST /api/passkeys/reg_start`
///
/// # Request Body
/// Expects a `PasskeyRegistrationRequest` object containing the necessary
/// details to initiate the registration process.
///
/// # Responses
/// - **200 OK**: Registration challenge created successfully.
/// - **400 Bad Request**: The request data is invalid.
/// - **500 Internal Server Error**: An unexpected error occurred during processing.
///
/// # Arguments
/// - `state`: The shared application state, including configuration and resources.
/// - `passkey_registration_request`: The registration request data provided by the client.
///
/// # Returns
/// A `Result` containing a `Response` on success or an `AppError` on failure.
#[utoipa::path(
    post,
    path = "/api/passkeys/reg_start",
    request_body = PasskeyRegistrationRequest,
    responses(
        (status = 200, description = "Registration challenge created successfully", body = ()),
        (status = 400, description = "Invalid request data", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    tag = "Passkey Authentication"
)]
async fn registration_start_handler(
    State(state): State<Arc<AppState>>,
    Json(passkey_registration_request): Json<PasskeyRegistrationRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::start_registration(State(state), Json(passkey_registration_request)).await
}

/// Completes the passkey registration process.
///
/// This endpoint finalizes the WebAuthn registration process by validating
/// the provided public key credential and associating it with the user.
///
/// # Endpoint
/// `POST /api/passkeys/register/finish`
///
/// # Request Headers
/// - `X-Request-ID`: A unique identifier for the request, used for tracking purposes.
///
/// # Request Body
/// Expects a `RegisterPublicKeyCredential` object containing the public key
/// credential data required to complete the registration.
///
/// # Responses
/// - **200 OK**: Registration completed successfully.
/// - **400 Bad Request**: The provided data is invalid.
/// - **500 Internal Server Error**: An unexpected error occurred during processing.
///
/// # Arguments
/// - `state`: The shared application state, including configuration and resources.
/// - `headers`: The HTTP headers of the request, used to extract the `X-Request-ID`.
/// - `public_key_credential`: The public key credential data provided by the client.
///
/// # Returns
/// A `Result` containing a `Response` on success or an `AppError` on failure.
async fn registration_finish_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(public_key_credential): Json<RegisterPublicKeyCredential>,
) -> Result<Response, AppError> {
    let request_id = headers
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // Call service method.
    auth_service::finish_registration(State(state), request_id, Json(public_key_credential)).await
}

/// Initiates the passkey login process.
///
/// This endpoint generates an authentication challenge for the client to
/// complete the WebAuthn login process.
///
/// # Endpoint
/// `POST /api/passkeys/login/start`
///
/// # Request Body
/// Expects a `PasskeyAuthenticationRequest` object containing the necessary
/// details to initiate the authentication process.
///
/// # Responses
/// - **200 OK**: Authentication challenge created successfully.
/// - **400 Bad Request**: The request data is invalid.
/// - **500 Internal Server Error**: An unexpected error occurred during processing.
///
/// # Arguments
/// - `state`: The shared application state, including configuration and resources.
/// - `passkey_authentication_request`: The authentication request data provided by the client.
///
/// # Returns
/// A `Result` containing a `Response` on success or an `AppError` on failure.
#[utoipa::path(
    post,
    path = "/api/passkeys/login/start",
    request_body = PasskeyAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication challenge created successfully", body = ()),
        (status = 400, description = "Invalid request data", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    tag = "Passkey Authentication"
)]
async fn login_start_handler(
    State(state): State<Arc<AppState>>,
    Json(passkey_authentication_request): Json<PasskeyAuthenticationRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::start_authentication(State(state), Json(passkey_authentication_request)).await
}

/// Completes the passkey login process.
///
/// This endpoint finalizes the WebAuthn login process by validating
/// the provided public key credential and authenticating the user.
///
/// # Endpoint
/// `POST /api/passkeys/login/finish`
///
/// # Request Headers
/// - `X-Request-ID`: A unique identifier for the request, used for tracking purposes.
///
/// # Request Body
/// Expects a `PublicKeyCredential` object containing the public key
/// credential data required to complete the authentication process.
///
/// # Responses
/// - **200 OK**: Authentication completed successfully.
/// - **400 Bad Request**: The provided data is invalid.
/// - **500 Internal Server Error**: An unexpected error occurred during processing.
///
/// # Arguments
/// - `state`: The shared application state, including configuration and resources.
/// - `headers`: The HTTP headers of the request, used to extract the `X-Request-ID`.
/// - `passkey_finish_auth_request`: The public key credential data provided by the client.
///
/// # Returns
/// A `Result` containing a `Response` on success or an `AppError` on failure.
async fn login_finish_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(passkey_finish_auth_request): Json<PublicKeyCredential>,
) -> Result<Response, AppError> {
    let request_id = headers
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // Call service method.
    auth_service::finish_authentication(State(state), request_id, Json(passkey_finish_auth_request))
        .await
}

async fn logout_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Call service method.
    auth_service::logout(State(state)).await
}
