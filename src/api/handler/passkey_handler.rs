use crate::api::model::auth::{PasskeyAuthenticationRequest, PasskeyRegistrationRequest};
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::auth_service;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub fn passkey_auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register/start", post(registration_start_handler))
        .route("/register/finish", post(registration_finish_handler))
        .route("/login/start", post(login_start_handler))
        .route("/login/finish", post(login_finish_handler))
    // .route("/logout", get(logout_handler))
}

/// Handler for starting the passkey registration process.
///
/// This endpoint initiates the WebAuthn registration process for a user.
/// It returns a challenge that the client needs to complete the registration.
/// TODO: fix the utoipa responses struct.
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

async fn login_start_handler(
    State(state): State<Arc<AppState>>,
    Json(passkey_authentication_request): Json<PasskeyAuthenticationRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::start_authentication(State(state), Json(passkey_authentication_request)).await
}

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

// async fn logout_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
//     // Call service method.
//     auth_service::logout(State(state)).await
// }
