use crate::api::model::user::{
    PaginationQuery, StoredUser, StoredUsers, UpdateUserRequest, UserRequest,
};
use crate::config::app_config::AppState;
use crate::db::repo::user_repository;
use crate::error::error_model::{ApiError, AppError, ErrorType};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHasher};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use nanoid::nanoid;
use sha2::Sha512;
use std::sync::Arc;
use tracing::error;
use validator::Validate;

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
    create_user(State(state), user_request)
        .await
        .into_response()
}

async fn create_user(
    State(state): State<Arc<AppState>>,
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

    // Hash password using Argon2.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password_customized(
            user_request.password.as_bytes(),
            Some(Algorithm::Argon2id.ident()),
            Some(19),
            Params::new(65536, 4, 5, Some(64)).unwrap(),
            &salt,
        )
        .unwrap();

    // create HMAC of hashed password for integrate check.
    let mut mac = match Hmac::<Sha512>::new_from_slice(state.hmac_key.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => {
            return Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid credentials. Check email and password.",
            ))
        }
    };
    mac.update(password_hash.to_string().as_bytes());
    let password_hmac = mac.finalize();

    let result = user_repository::create_user(
        &state.pg_pool,
        user_key,
        user_request.first_name,
        &user_request.last_name,
        &user_request.email,
        &password_hash.to_string(),
        &password_hmac.into_bytes().to_vec(),
    )
    .await;

    match result {
        Ok(user) => Ok((
            StatusCode::CREATED,
            [(header::LOCATION, format!("/users/{}", user.key))],
            Json(StoredUser {
                key: user.key,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
            }),
        )
            .into_response()),
        Err(e) => {
            error!("Error creating user. {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Error creating user",
            ))
        }
    }
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
    let page = query.page;
    let limit = query.size;
    let users = user_repository::get_users(&state.pg_pool, limit, page).await;

    let count = user_repository::count_users(&state.pg_pool).await;
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

// Get user by user id.
/// Get a user by user key
///
/// Get a user by unique key.
#[utoipa::path(
    get,
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
async fn get_user_handler(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let user = user_repository::get_user_by_key(&state.pg_pool, &key).await;

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
    let result = user_repository::update_user(&state.pg_pool, &key, update_user_request).await;

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
    let result = user_repository::delete_user(&state.pg_pool, &key).await;

    match result {
        Ok(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
        Err(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
    }
}
