use std::net::SocketAddr;
use std::ops::Add;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;

use crate::config::app_config::{get_server_address, initialize_app_state};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bb8_redis::bb8::Pool;
use bb8_redis::RedisConnectionManager;
use derive_more::Display;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, EncodingKey, Header};
use nanoid::nanoid;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{Error, FromRow, PgPool, Type};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info, warn};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable};
use validator::{Validate, ValidationErrors};

mod api {
    mod handler;
    mod model;
}
mod cache;
mod config;
mod db {
    mod entity;
    mod repo;
}
mod error;
mod middleware;
mod service;
mod util;

const JWT_TOKEN_SECRET: &str = "VFGiWL9ua5979rNE7GPWTXDBb5qLkCSHJqd7_S0rhh";
const JWT_TOKEN_EXPIRY: u64 = 86400;
const JWT_TOKEN_ISSUER: &str = "http://localhost:3000";
const DUMMY_HASHED_PASSWORD: &str = "$argon2id$v=19$m=65536,t=4,p=5$UNsE4Dxg3nVM4JeInGjJxw$b6uObfrK8qbCJMQr9VVDuDizRhxCZl4zXwZWbhERMaGjPvcBsHZmcbAwXsUPqtekDwkf4u3qiVKG/maAR+7BdA";

#[tokio::main]
async fn main() {
    // Logging handler using tracing.
    tracing_subscriber::fmt().init();

    // Load environment variables from .env file.
    dotenvy::dotenv().ok();
    let server_addr = get_server_address().await;

    // Initialize the application state.
    let shared_state = initialize_app_state().await;

    // OpenAPI documentation.
    #[derive(OpenApi)]
    #[openapi(
        info(title = "Users Api", contact(name = "Bala", email = "bala@c12.io"), license(name = "MIT", url = "https://opensource.org/licenses/MIT")),
        modifiers(&SecurityAddon),
        tags(
            (name = "Users", description = "User management API")
        ),
        paths(handler_create_user, get_users, get_user_by_id, update_user, handler_json, authenticate_user, delete_user),
        components(schemas(UserRequest, UpdateUserRequest, StoredUser, StoredUsers, Message, ApiError, ValidationError, UserAuthRequest, UserAuthResponse)),
    )]
    struct ApiDoc;
    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_jwt_token",
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .bearer_format("JWT")
                            .build(),
                    ),
                )
            }
        }
    }

    // CORS middleware.
    let cors = CorsLayer::new()
        // allow `GET`, `POST` and `PATCH` when accessing the resource
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        // Allow only `Content-Type` header.
        .allow_headers(vec![header::CONTENT_TYPE])
        // allow requests from any origin
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap());

    // build our application with a route
    let app = Router::new()
        .route("/", get(handler_json))
        .route("/users", post(handler_create_user).get(get_users))
        .route(
            "/users/:id",
            get(get_user_by_id).patch(update_user).delete(delete_user),
        )
        .route("/auth", post(authenticate_user))
        .merge(Scalar::with_url("/scalar", ApiDoc::openapi()))
        .fallback(page_not_found)
        .with_state(shared_state)
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .layer(cors);

    // run it
    let server_address: SocketAddr = server_addr.parse().unwrap();
    info!("Starting server at {}", server_addr);
    let listener = tokio::net::TcpListener::bind(server_address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// -- ---------------------
// -- Error Handlers
// -- ---------------------
async fn page_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            status: 404,
            time: Utc::now().to_rfc3339(),
            message: "Resource not found".to_string(),
            debug_message: None,
            sub_errors: vec![],
        }),
    )
        .into_response()
}

// -- ---------------------
// -- Handlers
// -- ---------------------
// Sample JSON handler for example.
/// Get sample JSON response
///
/// Get a sample JSON response with custom header.
#[utoipa::path(
    get,
    path = "",
    tag = "JSON",
    params(
        ("x-server-version" = String, Header, description = "Server version", example = "v0.1.0")
    ),
    responses(
        (status = 200, description = "User created successfully", body = Message),
        (status = 400, description = "Missing header 'x-server-version'"),
        (status = 500, description = "Internal server error"),
    )
)]
async fn handler_json(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Creating a Redis connection and setting a key value.
    let mut redis_con = state.redis_pool.get().await.unwrap();
    let _: () = redis_con.set("hello", "success").await.unwrap();

    // Get custom header from Request header.
    let header_value = match headers.get("x-server-version") {
        Some(header) => match header.to_str() {
            Ok(value) => value,
            Err(_) => {
                warn!("Failed to convert header value to string");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Invalid header value".into())
                    .unwrap();
            }
        },
        None => {
            warn!("Header 'x-server-version' not found");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Missing header 'x-server-version'".into())
                .unwrap();
        }
    };
    info!("Header Value -> {}", header_value);

    // Make a simple query to return the given parameter (use a question mark `?` instead of `$1` for MySQL)
    let response: Result<(String,), Error> = sqlx::query_as("SELECT 'Hello'")
        .fetch_one(&state.pg_pool)
        .await;
    match response {
        Ok(r) => info!("DB Response -> {}", r.0),
        Err(e) => info!("Error getting data {}", e),
    }

    // With custom Response Code.
    (
        StatusCode::CREATED,
        Json(Message {
            message: "Hello".to_string(),
            status: redis_con.get("hello").await.unwrap(),
        }),
    )
        .into_response()
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
async fn authenticate_user(
    State(state): State<Arc<AppState>>,
    Json(user_auth_request): Json<UserAuthRequest>,
) -> Result<Response, AppError> {
    // validate user auth request.
    if let Err(e) = user_auth_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "UserAuthRequest".to_string(),
            },
            "Validation error. Check the request body.",
        ));
    }

    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled, 
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at 
        FROM users WHERE email = $1
        "#,
        user_auth_request.email
    )
    .fetch_one(&state.pg_pool)
    .await;

    let argon2 = Argon2::default();
    match user {
        Ok(user) => {
            let password_hash = PasswordHash::new(&user.password_hash).unwrap();
            // TODO: Only do auth check if the user status is active.
            if argon2
                .verify_password(user_auth_request.password.as_bytes(), &password_hash)
                .is_err()
            {
                let status = user_authentication_failed(State(state), user.id).await;
                if status == "LOCKED" {
                    return Err(AppError::new(
                        ErrorType::UnauthorizedError,
                        "User account is locked. Contact support.",
                    ));
                }
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
            }

            let mut mac = Hmac::<Sha512>::new_from_slice(state.hmac_key.as_bytes()).unwrap();
            mac.update(&user.password_hash.as_bytes());
            if mac.verify_slice(&user.password_hmac).is_err() {
                let status = user_authentication_failed(State(state), user.id).await;
                if status == "LOCKED" {
                    return Err(AppError::new(
                        ErrorType::UnauthorizedError,
                        "User account is locked. Contact support.",
                    ));
                }
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
            }
            let now = Utc::now();
            let jti = nanoid!();
            let user_claim = Claims {
                sub: user.key,
                iss: JWT_TOKEN_ISSUER.to_string(),
                jti,
                iat: now.timestamp(),
                nbf: now.timestamp(),
                exp: now.add(Duration::from_secs(JWT_TOKEN_EXPIRY)).timestamp(),
            };
            let token = encode(
                &Header::default(),
                &user_claim,
                &EncodingKey::from_secret(JWT_TOKEN_SECRET.as_ref()),
            )
            .unwrap();
            reset_failed_login_attempts(State(state), user.id).await;
            // TODO: Store the token in Redis for revoking.
            // Generate JWT token and return.
            Ok((StatusCode::OK, Json(UserAuthResponse { token })).into_response())
        }
        Err(_) => {
            // User not found.
            // Still trigger a fake check to avoid returning immediately.
            // Which can be used by hacker to figure out user id is not valid.
            let password_hash = PasswordHash::new(DUMMY_HASHED_PASSWORD).unwrap();
            let _ = argon2.verify_password("dummy".as_bytes(), &password_hash);
            Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid credentials. Check email and password.",
            ))
        }
    }
}

// Update failed login attempts for user.
async fn user_authentication_failed(State(state): State<Arc<AppState>>, user_id: i64) -> String {
    if let Err(e) = sqlx::query!(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        user_id
    )
    .execute(&state.pg_pool)
    .await
    {
        error!("Error updating failed login attempts: {:?}", e);
        return "".to_string();
    }

    let user = match sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled,
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_one(&state.pg_pool)
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Error fetching user: {:?}", e);
            return "OK".to_string();
        }
    };

    // Lock user account if failed login attempts are more than 5.
    if user.failed_login_attempts.unwrap_or(0) >= 5 {
        if let Err(e) = sqlx::query!(
            "UPDATE users SET account_status = 'LOCKED' WHERE id = $1",
            user_id
        )
        .execute(&state.pg_pool)
        .await
        {
            error!("Error locking user account: {:?}", e);
        }
        return "LOCKED".to_string();
    }
    "OK".to_string()
}

async fn reset_failed_login_attempts(State(state): State<Arc<AppState>>, user_id: i64) {
    let result = sqlx::query!(
        "UPDATE users SET failed_login_attempts = 0 WHERE id = $1",
        user_id
    )
    .execute(&state.pg_pool)
    .await;
    match result {
        Ok(_) => (),
        Err(e) => error!("Error resetting failed login attempts: {:?}", e),
    }
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
async fn handler_create_user(
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

    let result = sqlx::query!(
        r#"
        INSERT INTO users (key, first_name, last_name, email, password_hash, password_hmac) 
        VALUES ($1, $2, $3, $4, $5, $6) 
        RETURNING id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, 
        two_factor_enabled, account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        "#,
        user_key,
        user_request.first_name,
        &user_request.last_name,
        &user_request.email,
        password_hash.to_string(),
        &password_hmac.into_bytes().to_vec(),
    )
        .fetch_one(&state.pg_pool)
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
async fn get_users(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PaginationQuery>,
) -> Result<Response, AppError> {
    let page = query.page;
    let limit = query.size;
    let users = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled, 
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2
        "#,
        limit,
        (page - 1) * limit
    )
    .fetch_all(&state.pg_pool)
    .await;

    let count = sqlx::query!("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pg_pool)
        .await
        .unwrap();
    let items_in_page = users.as_ref().unwrap().len();

    match users {
        Ok(users) => Ok((
            StatusCode::OK,
            Json(StoredUsers {
                users: users.into_iter().map(|u| StoredUser::from(u)).collect(),
                current_page: page,
                total_items: count.count.unwrap(),
                total_pages: (count.count.unwrap() as f64 / limit as f64).ceil() as i64,
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
/// Get a user by ID
///
/// Get a user by unique id.
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
async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled, 
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at 
        FROM users WHERE key = $1
        "#,
        key
    )
        .fetch_one(&state.pg_pool)
        .await;

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
/// Update user by ID
///
/// Update user by unique id. Only allowed to update first name and last name.
#[utoipa::path(
    patch,
    path = "/users/{id}",
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
async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(update_user_request): Json<UpdateUserRequest>,
) -> Result<Response, AppError> {
    let mut query = String::from("UPDATE users SET ");
    let mut params = Vec::new();
    let mut set_clauses = Vec::new();

    if let Some(first_name) = &update_user_request.first_name {
        set_clauses.push("first_name = $".to_owned() + &(params.len() + 1).to_string());
        params.push(first_name);
    }

    if let Some(last_name) = &update_user_request.last_name {
        set_clauses.push("last_name = $".to_owned() + &(params.len() + 1).to_string());
        params.push(last_name);
    }

    query += &set_clauses.join(", ");
    query += &format!(" WHERE id = ${} RETURNING *", params.len() + 1);
    params.push(&id);

    info!("Patch Query: {}", query);
    let mut query = sqlx::query_as(&query);
    for param in &params {
        query = query.bind(param);
    }
    let result: Result<Users, Error> = query.fetch_one(&state.pg_pool).await;

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
            "User not found for ID: ".to_owned() + &id,
        )),
    }
}

// Delete user by user id.
/// Delete user by ID
///
/// Delete user by unique id. Soft delete user by setting deleted_at timestamp.
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
async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    let result = sqlx::query_as!(
        Users,
        "UPDATE users SET account_status = 'DELETED' WHERE key = $1 AND account_status <> 'DELETED'",
        key
    )
    .fetch_one(&state.pg_pool)
    .await;

    match result {
        Ok(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
        Err(_) => Ok((StatusCode::NO_CONTENT,).into_response()),
    }
}

// -- ---------------------
// -- Structs for request, response and entities.
// -- ---------------------
#[derive(Clone)]
struct AppState {
    pg_pool: PgPool,
    redis_pool: Pool<RedisConnectionManager>,
    hmac_key: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
struct UserRequest {
    #[validate(length(
        min = 2,
        max = 50,
        message = "First name must be between 2 and 50 characters"
    ))]
    #[schema(example = "John")]
    first_name: Option<String>,
    #[validate(length(
        min = 2,
        max = 50,
        message = "Last name must be between 2 and 50 characters"
    ))]
    #[schema(example = "Doe")]
    last_name: String,
    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    password: String,
    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
struct UserAuthRequest {
    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    email: String,

    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct UpdateUserRequest {
    #[schema(example = "John")]
    first_name: Option<String>,
    #[schema(example = "Doe")]
    last_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct StoredUser {
    #[schema(example = "kfERHUaNceaE9i9FrbnNH")]
    key: String,
    #[schema(example = "John")]
    first_name: Option<String>,
    #[schema(example = "Doe")]
    last_name: String,
    #[schema(example = "me@example.com")]
    email: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct UserAuthResponse {
    #[schema(
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )]
    token: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct StoredUsers {
    users: Vec<StoredUser>,
    #[schema(example = 1)]
    current_page: i64,
    #[schema(example = 120)]
    total_items: i64,
    #[schema(example = 6)]
    total_pages: i64,
    #[schema(example = 20)]
    items_per_page: i64,
    #[schema(example = 20)]
    items_in_page: i64,
}

impl From<Users> for StoredUser {
    fn from(user: Users) -> Self {
        StoredUser {
            key: user.key,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
struct Message {
    #[schema(example = "Hello")]
    /// Message to display
    message: String,
    #[schema(example = "Success")]
    /// Status of the message
    status: String,
}

#[derive(Debug, Deserialize, IntoParams)]
struct PaginationQuery {
    /// current page of the pagination
    #[param(default = 1, example = 1)]
    page: i64,
    /// number of items per page
    #[param(default = 20, example = 20, required)]
    size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

// -- ---------------------
// -- Entities
// -- ---------------------
#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct Users {
    id: i64,
    key: String,
    first_name: Option<String>,
    last_name: String,
    email: String,
    password_hash: String,
    password_hmac: Vec<u8>,
    email_verified: Option<bool>,
    update_password: Option<bool>,
    two_factor_enabled: Option<bool>,
    account_status: AccountStatus,
    last_login: Option<DateTime<Utc>>,
    failed_login_attempts: Option<i32>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq, Type)]
#[sqlx(type_name = "account_status", rename_all = "lowercase")]
enum AccountStatus {
    #[sqlx(rename = "ACTIVE")]
    Active,
    #[sqlx(rename = "INACTIVE")]
    Inactive,
    #[sqlx(rename = "PENDING")]
    Pending,
    #[sqlx(rename = "LOCKED")]
    Locked,
    #[sqlx(rename = "DELETED")]
    Deleted,
}

// -- ---------------------
// -- Global error handling.
// -- ---------------------

// New error data type.
// #[derive(ToSchema)]
// TODO: Getting error for ToSchema for ValidationErrors from validator.
pub struct AppError {
    error_type: ErrorType,
    error_message: String,
}

#[derive(Debug, Display, derive_more::Error, Clone)]
pub enum ErrorType {
    #[display("Not found")]
    NotFound,
    #[display("Bad request")]
    BadRequest,
    #[display("Internal server error")]
    InternalServerError,
    #[display("Authentication error")]
    UnauthorizedError,
    #[display("Request validation error")]
    RequestValidationError {
        validation_error: ValidationErrors,
        object: String,
    },
}

impl AppError {
    // constructor.
    pub fn new(error_type: ErrorType, message: impl Into<String>) -> Self {
        Self {
            error_type,
            error_message: message.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct ApiError {
    #[schema(example = "500")]
    status: u16,
    #[schema(example = "2024-01-01T12:00:00.000Z")]
    time: String,
    #[schema(example = "Internal server error")]
    message: String,
    #[serde(rename = "debugMessage")]
    #[schema(example = "Internal server error. Try after some time")]
    debug_message: Option<String>,
    #[serde(rename = "subErrors")]
    sub_errors: Vec<ValidationError>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationError {
    #[schema(example = "Users")]
    object: String,
    #[schema(example = "email")]
    field: String,
    #[schema(example = "notAValidEmail")]
    rejected_value: String,
    #[schema(example = "Invalid email address")]
    message: String,
    #[schema(example = "email.invalid")]
    code: String,
}

// New type of error handling.
impl IntoResponse for AppError {
    // implementation for the trait.
    fn into_response(self) -> Response {
        let (status, message, debug_message, sub_errors) = match self.error_type.clone() {
            ErrorType::NotFound => (
                StatusCode::NOT_FOUND,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::BadRequest => (
                StatusCode::BAD_REQUEST,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::UnauthorizedError => (
                StatusCode::UNAUTHORIZED,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::RequestValidationError {
                validation_error,
                object,
            } => {
                let mut validation_sub_errs = Vec::new();
                for (field, field_errors) in validation_error.field_errors() {
                    for field_error in field_errors {
                        info!("Validation error on field: {:?}", field_error);
                        validation_sub_errs.push(ValidationError {
                            object: object.to_string(),
                            field: field.to_string(),
                            rejected_value: field_error
                                .params
                                .get("value")
                                .unwrap_or(&"".into())
                                .to_string(),
                            message: field_error
                                .message
                                .as_ref()
                                .unwrap_or(&"".into())
                                .to_string(),
                            code: field_error.code.to_string(),
                        })
                    }
                }
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    self.error_type.to_string(),
                    Some(self.error_message),
                    validation_sub_errs,
                )
            }
        };
        let api_error = ApiError {
            status: status.into(),
            time: Utc::now().to_rfc3339(),
            message,
            debug_message,
            sub_errors,
        };

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&api_error).unwrap_or("".to_string()),
            ))
            .unwrap_or(Response::new(axum::body::Body::empty()))
    }
}
