use crate::api::model::user::{
    PaginationQuery, StoredUser, StoredUsers, UpdateUserRequest, UserRequest,
};
use crate::config::app_config::AppState;
use crate::error::error_model::{ApiError, AppError};
use crate::service::user_service;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_user_handler).get(get_users_handler))
        .route(
            "/{key}",
            get(get_user_handler)
                .patch(update_user_handler)
                .delete(delete_user_handler),
        )
}

// POST create user handler.
/// Create user
///
/// Create a new user with name, email, and password.
#[utoipa::path(
    post,
    path = "/users",
    request_body = UserRequest,
    tag = "Users",
    responses(
        (status = 201, description = "User created successfully", body = StoredUser),
        (status = 422, description = "Unprocessable request", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    Json(user_request): Json<UserRequest>,
) -> Response {
    user_service::create_user(state, user_request)
        .await
        .into_response()
}

// GET all user handler with pagination.
/// Get a list of users
///
/// Get a list of users with pagination.
#[utoipa::path(
    get,
    path = "/users",
    tag = "Users",
    params(
        PaginationQuery
    ),
    responses(
        (status = 200, description = "User created successfully", body = StoredUsers),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn get_users_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PaginationQuery>,
) -> Result<Response, AppError> {
    // The defaults will be applied automatically from the PaginationQuery struct
    user_service::get_users(state, query).await
}

// Get user by user id.
/// Get a user by user key
///
/// Get a user by unique key.
#[utoipa::path(
    get,
    path = "/users/{key}",
    tag = "Users",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "User created successfully", body = StoredUser),
        (status = 404, description = "User not found for the ID", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn get_user_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    user_service::get_user_by_key(state, key).await
}

// PATCH update user by user id.
// Only allowed to update first_name and last_name. Email address is not updatable.
/// Update user by user key
///
/// Update user by unique key. Only allowed to update first name and last name.
#[utoipa::path(
    patch,
    path = "/users/{key}",
    request_body = UpdateUserRequest,
    tag = "Users",
    params(
        ("id" = String, Path, description = "Unique user id")
    ),
    responses(
        (status = 200, description = "User created successfully", body = StoredUser),
        (status = 404, description = "User not found for the ID", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(update_user_request): Json<UpdateUserRequest>,
) -> Result<Response, AppError> {
    user_service::update_user(state, key, update_user_request).await
}

// Delete user by user id.
/// Delete user by user key
///
/// Delete user by unique key. Soft delete user by setting deleted_at timestamp.
#[utoipa::path(
    delete,
    path = "/users/{key}",
    tag = "Users",
    params(
        ("id" = String, Path, description = "Unique user id")
    ),
    responses(
        (status = 200, description = "User created successfully", body = StoredUser),
        (status = 404, description = "User not found for the ID", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    user_service::delete_user(state, key).await
}
