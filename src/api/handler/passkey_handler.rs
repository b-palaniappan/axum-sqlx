use crate::api::model::auth::PasskeyRegistrationRequest;
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::auth_service;
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use std::sync::Arc;
use webauthn_rs::prelude::CreationChallengeResponse;

pub fn passkey_auth_routes() -> Router<Arc<AppState>> {
    Router::new().route("/reg_start", post(registration_start_handler))
    // .route("/reg_finish", post(registration_finish_handler))
    // .route("/auth_start", post(authentication_start_handler))
    // .route("/auth_finish", post(authentication_finish_handler))
    // .route("/logout", get(logout_handler))
}

/// Handler for starting the passkey registration process.
///
/// This endpoint initiates the WebAuthn registration process for a user.
/// It returns a challenge that the client needs to complete the registration.
#[utoipa::path(
    post,
    path = "/api/passkeys/reg_start",
    request_body = PasskeyRegistrationRequest,
    responses(
        (status = 200, description = "Registration challenge created successfully", body = CreationChallengeResponse),
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

// async fn registration_finish_handler(
//     State(state): State<Arc<AppState>>,
// ) -> Result<Response, AppError> {
//     // Call service method.
//     auth_service::registration_finish(State(state)).await
// }
//
// async fn authentication_start_handler(
//     State(state): State<Arc<AppState>>,
// ) -> Result<Response, AppError> {
//     // Call service method.
//     auth_service::authentication_start(State(state)).await
// }
//
// async fn authentication_finish_handler(
//     State(state): State<Arc<AppState>>,
// ) -> Result<Response, AppError> {
//     // Call service method.
//     auth_service::authentication_finish(State(state)).await
// }
//
// async fn logout_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
//     // Call service method.
//     auth_service::logout(State(state)).await
// }
