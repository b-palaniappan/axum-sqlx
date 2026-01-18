use crate::api::model::user::{
    PaginationQuery, StoredUser, StoredUsers, UpdateUserRequest, UserRequest,
};
use crate::config::app_config::AppState;
use crate::db::repo::{user_login_credentials_repository, users_repository};
use crate::error::error_model::{ApiError, AppError, ErrorType};
use crate::util::crypto_helper;
use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use nanoid::nanoid;
use std::sync::Arc;
use tracing::error;
use validator::Validate;

/// Create a new user.
///
/// This function creates a new user with the provided first name, last name, email, and password.
/// The password is hashed and signed with HMAC before being stored. If the request is valid and
/// the user is created successfully, it returns the created user data and sets the `Location` header
/// to the new user's resource.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools.
/// * `user_request` - The request body containing user details.
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the created user data,
/// or an `AppError` on failure.
#[tracing::instrument(
    skip(state),
    fields(
        service.name = "user_service",
        service.operation = "create_user",
        user.email = %user_request.email
    )
)]
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
pub async fn create_user(
    state: Arc<AppState>,
    user_request: UserRequest,
) -> Result<Response, AppError> {
    match user_request.validate() {
        Ok(_) => (),
        Err(e) => {
            return Err(AppError::new(
                ErrorType::RequestValidationError {
                    validation_error: e,
                    object: "UserRequest".to_string(),
                },
                "Validation error. Check the request body.",
            ));
        }
    }
    let user_key = nanoid!();

    // Hash password and sign with HMAC using helper function
    let (password_hash, password_hmac) =
        crypto_helper::hash_password_sign_with_hmac(&state, &user_request.password)
            .await
            .map_err(|_| {
                error!("Error hashing password");
                AppError::new(ErrorType::InternalServerError, "Error hashing password.")
            })?;

    let result = users_repository::create_user(
        &state.pg_pool,
        &user_key,
        user_request.first_name,
        user_request.last_name,
        &user_request.email,
    )
    .await;

    match result {
        Ok(user) => {
            user_login_credentials_repository::create_user_login_credentials(
                &state.pg_pool,
                user.id,
                &password_hash.to_string(),
                &*password_hmac,
            )
            .await
            .map_err(|e| {
                error!("Error storing user login credentials: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Error storing user login credentials",
                )
            })?;

            // Successfully created user and stored credentials
            Ok((
                StatusCode::CREATED,
                [(header::LOCATION, format!("/users/{}", user.key))],
                Json(StoredUser {
                    key: user.key,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    email: user.email,
                }),
            )
                .into_response())
        }
        Err(e) => {
            error!("Error creating user. {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Error creating user",
            ))
        }
    }
}

/// Get a list of users with pagination.
///
/// Retrieves a paginated list of users.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools.
/// * `pagination` - Pagination parameters (page and size).
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the paginated users,
/// or an `AppError` on failure.
#[utoipa::path(
    get,
    path = "/users",
    tag = "Users",
    params(
        PaginationQuery
    ),
    responses(
        (status = 200, description = "Users retrieved successfully", body = StoredUsers),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
pub async fn get_users(
    state: Arc<AppState>,
    pagination: PaginationQuery,
) -> Result<Response, AppError> {
    // Use the default values provided by the serde attributes if not specified
    let page = pagination.page;
    let limit = pagination.size;
    let users = users_repository::get_users(&state.pg_pool, limit, page).await;

    let count = users_repository::count_users(&state.pg_pool).await;
    let items_in_page = users.as_ref().unwrap().len();
    let user_count = count.unwrap_or_else(|_| 0);

    match users {
        Ok(users) => Ok((
            StatusCode::OK,
            Json(StoredUsers {
                users: users.into_iter().map(|u| StoredUser::from(u)).collect(),
                current_page: page,
                total_items: user_count,
                total_pages: (user_count as f64 / limit as f64).ceil() as i64,
                items_per_page: limit,
                items_in_page: items_in_page as i64,
            }),
        )
            .into_response()),
        Err(_) => Err(AppError::new(
            ErrorType::InternalServerError,
            "Error getting users",
        )),
    }
}

/// Get a user by user key.
///
/// Retrieves a user by their unique key.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools.
/// * `key` - The unique identifier for the user.
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the user data,
/// or an `AppError` if the user is not found or an error occurs.
#[utoipa::path(
    get,
    path = "/users/{key}",
    tag = "Users",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "User found", body = StoredUser),
        (status = 404, description = "User not found for the ID", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
pub async fn get_user_by_key(state: Arc<AppState>, key: String) -> Result<Response, AppError> {
    let user = users_repository::get_user_by_key(&state.pg_pool, &key).await;

    match user {
        Ok(user) => Ok((StatusCode::OK, Json(StoredUser::from(user))).into_response()),
        Err(e) => {
            error!("Error getting user: {}", e);
            Err(AppError::new(
                ErrorType::NotFound,
                "User not found for ID: ".to_owned() + &key,
            ))
        }
    }
}

/// Update user by user key.
///
/// Updates the user's first name and last name by their unique key.
/// The email address cannot be updated.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools.
/// * `key` - The unique identifier for the user.
/// * `update_user_request` - The request body containing the new first and last name.
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with the updated user data,
/// or an `AppError` if the user is not found or an error occurs.
#[utoipa::path(
    patch,
    path = "/users/{key}",
    request_body = UpdateUserRequest,
    tag = "Users",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 200, description = "User updated successfully", body = StoredUser),
        (status = 404, description = "User not found for the ID", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
pub async fn update_user(
    state: Arc<AppState>,
    key: String,
    update_user_request: UpdateUserRequest,
) -> Result<Response, AppError> {
    let result = users_repository::update_user(&state.pg_pool, &key, update_user_request).await;

    match result {
        Ok(user) => Ok((
            StatusCode::OK,
            Json(StoredUser {
                key: user.key,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
            }),
        )
            .into_response()),
        Err(_) => Err(AppError::new(
            ErrorType::NotFound,
            "User not found for ID: ".to_owned() + &key,
        )),
    }
}

/// Soft delete a user by user key.
///
/// This endpoint performs a soft delete of a user by setting the `deleted_at` timestamp.
/// Returns HTTP 204 No Content on success, regardless of whether the user existed.
///
/// # Arguments
///
/// * `state` - The application state containing database connection pools.
/// * `key` - The unique identifier for the user.
///
/// # Returns
///
/// Returns a `Result` containing a `Response` with HTTP 204 No Content,
/// or an `AppError` on failure.
#[utoipa::path(
    delete,
    path = "/users/{key}",
    tag = "Users",
    params(
        ("key" = String, Path, description = "Unique user key")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
pub async fn delete_user(state: Arc<AppState>, key: String) -> Result<Response, AppError> {
    let result = users_repository::delete_user(&state.pg_pool, &key).await;

    match result {
        Ok(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
        Err(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
    }
}
