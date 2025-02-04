use crate::api::model::auth::{RefreshRequest, TokenRequest, TokenResponse};
use crate::api::model::user::UserAuthRequest;
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::auth_service;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;

/// Defines the authentication routes for the application.
///
/// This function creates a new `Router` instance and registers the `authenticate_handler`
/// function to handle POST requests to the root path ("/").
///
/// # Returns
///
/// A `Router` instance configured with the authentication routes.
pub fn auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(authenticate_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/jwks", get(jwks_handler))
        .route("/logout", delete(logout_handler))
        .route("/validate", post(validate_token_handler))
}

// Authentication handler.
/// Authenticate user
///
/// Authenticate user with email and password.
#[utoipa::path(
    post,
    path = "/auth",
    tag = "Authentication",
    request_body = UserAuthRequest,
    responses(
        (status = 200, description = "User authenticated successfully", body = TokenResponse),
        (status = 401, description = "Unauthorized error", body = ApiError),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn authenticate_handler(
    State(state): State<Arc<AppState>>,
    Json(user_auth_request): Json<UserAuthRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::authenticate_user(State(state), Json(user_auth_request)).await
}

// Validate token handler.
/// Validate token
///
/// Validate JWT token using public key.
#[utoipa::path(
    post,
    path = "/auth/validate",
    tag = "Authentication",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token validated successfully"),
        (status = 401, description = "Unauthorized error", body = ApiError),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn validate_token_handler(
    State(state): State<Arc<AppState>>,
    Json(token_request): Json<TokenRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::validate_token(State(state), Json(token_request)).await
}

// Refresh token handler.
/// Refresh auth token
///
/// Refresh auth token using refresh token.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Authentication",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Auth token refreshed successfully", body = TokenResponse),
        (status = 401, description = "Unauthorized error", body = ApiError),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn refresh_token_handler(
    State(state): State<Arc<AppState>>,
    Json(refresh_request): Json<RefreshRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::refresh_token(State(state), Json(refresh_request)).await
}

// JWKS handler.
/// JWKS
///
/// Get JSON Web Key Set (JWKS) for public key.
#[utoipa::path(
    get,
    path = "/auth/jwks",
    tag = "Authentication",
    responses(
        (status = 200, description = "JWKS retrieved successfully"),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn jwks_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Call service method.
    auth_service::get_jwks(State(state)).await
}

async fn logout_handler(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Call service method.
    auth_service::logout_user(State(state)).await
}
