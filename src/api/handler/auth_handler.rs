use crate::api::model::auth::{
    ForgotPasswordRequest, ForgotPasswordResponse, LogoutRequest, RefreshRequest,
    ResetPasswordRequest, ResetPasswordResponse, TokenRequest, TokenResponse,
};
use crate::api::model::user::UserAuthRequest;
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::auth_service;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Cookie};
use std::sync::Arc;
use tracing::info;

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
        // .route("/register", post(register_handler))
        .route("/login", post(authenticate_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/jwks", get(jwks_handler))
        .route("/logout", delete(logout_handler))
        .route("/validate", post(validate_token_handler))
        .route("/forgot-password", post(forgot_password_handler))
        .route("/reset-password", post(reset_password_handler))
}

// Authentication handler.
/// Authenticate user
///
/// Authenticate user with email and password.
#[utoipa::path(
    post,
    path = "/auth/login",
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

/// Logout user
///
/// Logout user and invalidate their tokens.
#[utoipa::path(
    delete,
    path = "/auth/logout",
    tag = "Authentication",
    request_body = LogoutRequest,
    responses(
        (status = 200, description = "Logout successful"),
        (status = 401, description = "Unauthorized error", body = ApiError),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn logout_handler(
    State(state): State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    Json(logout_request): Json<LogoutRequest>,
) -> Result<Response, AppError> {
    // Extract the token from the authorization header
    let token = bearer.token();

    // Extract cookies
    let cookies = cookie.get("refresh_token");
    info!("token: {:?} | Cookies: {:?}", token, cookies);

    // Call service method.
    auth_service::logout_user(State(state), Json(logout_request)).await
}

/// Forgot password
///
/// Request a password reset link to be sent to the user's email.
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    tag = "Authentication",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Password reset email sent", body = ForgotPasswordResponse),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn forgot_password_handler(
    State(state): State<Arc<AppState>>,
    Json(forgot_password_request): Json<ForgotPasswordRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::forgot_password(State(state), Json(forgot_password_request)).await
}

/// Reset password
///
/// Reset a user's password using a valid reset token.
#[utoipa::path(
    post,
    path = "/auth/reset-password",
    tag = "Authentication",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successful", body = ResetPasswordResponse),
        (status = 401, description = "Invalid or expired token", body = ApiError),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn reset_password_handler(
    State(state): State<Arc<AppState>>,
    Json(reset_password_request): Json<ResetPasswordRequest>,
) -> Result<Response, AppError> {
    // Call service method.
    auth_service::reset_password(State(state), Json(reset_password_request)).await
}
