use crate::service::auth_service;
use crate::{ApiError, AppError, AppState, UserAuthRequest, UserAuthResponse};
use axum::extract::State;
use axum::response::Response;
use axum::routing::post;
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
    Router::new().route("/", post(authenticate_handler))
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
        (status = 200, description = "User authenticated successfully", body = UserAuthResponse),
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
