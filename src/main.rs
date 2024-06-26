use std::env;
use std::net::SocketAddr;
use std::ops::Add;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bb8_redis::{bb8, RedisConnectionManager};
use bb8_redis::bb8::Pool;
use derive_more::{Display, Error};
use jsonwebtoken::{encode, EncodingKey, Header};
use nid::alphabet::Base64UrlAlphabet;
use nid::Nanoid;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{Error, FromRow, PgPool};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info, warn};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable};
use validator::{Validate, ValidationErrors};

const JWT_TOKEN_SECRET: &str = "VFGiWL9ua5979rNE7GPWTXDBb5qLkCSHJqd7_S0rhh";
const JWT_TOKEN_EXPIRY: u64 = 86400;
const JWT_TOKEN_ISSUER: &str = "http://localhost:3000";
const DUMMY_HASHED_PASSWORD: &str = "$argon2id$v=19$m=65536,t=4,p=5$UNsE4Dxg3nVM4JeInGjJxw$b6uObfrK8qbCJMQr9VVDuDizRhxCZl4zXwZWbhERMaGjPvcBsHZmcbAwXsUPqtekDwkf4u3qiVKG/maAR+7BdA";

#[tokio::main]
async fn main() {
    // Logging handler using tracing.
    tracing_subscriber::fmt().init();

    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let server_host = env::var("SERVER_HOST").expect("Error getting server host");
    let server_port = env::var("SERVER_PORT").expect("Error getting server port");
    let redis_url = env::var("REDIS_URL").expect("Error getting redis host");
    let server_addr = server_host + ":" + &*server_port;

    // Setup connection pool.
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .connect(&database_url)
        .await
        .map_err(|e| {
            error!("Failed to create database connection pool: {}", e);
            panic!("Failed to create database connection pool: {}", e);
        })
        .unwrap();

    // Trigger SQLx migration.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate database");

    // Setup Redis connection.
    let manager = RedisConnectionManager::new(redis_url)
        .expect("Failed to create Redis connection manager");
    let redis_pool = bb8::Pool::builder().min_idle(5).build(manager).await.unwrap();

    let state = AppState {
        pg_pool: pool,
        redis_pool: redis_pool,
    };

    // OpenAPI documentation.
    #[derive(OpenApi)]
    #[openapi(
        info(title = "Users Api", contact(name = "Bala", email = "bala@c12.io"), license(name = "MIT", url = "https://opensource.org/licenses/MIT")),
        modifiers(&SecurityAddon),
        tags(
            (name = "Users", description = "User management API")
        ),
        paths(handler_create_user, get_users, get_user_by_id, update_user, handler_json, authenticate_user, delete_user),
        components(schemas(UserRequest, UpdateUserRequest, StoredUser, StoredUsers, Message, AppError, ApiError, ValidationError, UserAuthRequest, UserAuthResponse)),
    )]
    struct ApiDoc;
    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "api_key",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("todo_apikey"))),
                )
            }
        }
    }

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
        .with_state(state)
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
async fn handler_json(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Creating a Redis connection and setting a key value.
    let mut redis_con = state.redis_pool.get().await.unwrap();
    let _: () = redis_con.set("hello", "world").await.unwrap();

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
            status: "Success".to_string(),
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
    State(state): State<AppState>,
    Json(user_auth_request): Json<UserAuthRequest>,
) -> Result<Response, AppError> {
    // validate user auth request.
    match user_auth_request.validate() {
        Ok(_) => (),
        Err(e) => {
            return Err(AppError::new(
                ErrorType::RequestValidationError {
                    validation_error: e,
                    object: "UserAuthRequest".to_string(),
                },
                "Validation error. Check the request body.",
            ));
        }
    }

    let user = sqlx::query_as!(
        Users,
        "SELECT * FROM sqlx_users WHERE email = $1",
        user_auth_request.email
    )
    .fetch_one(&state.pg_pool)
    .await;

    let argon2 = Argon2::default();
    match user {
        Ok(user) => {
            let password_hash = PasswordHash::new(&user.password_hash).unwrap();
            if argon2
                .verify_password(user_auth_request.password.as_bytes(), &password_hash)
                .is_ok()
            {
                let now = Utc::now();
                let jti: Nanoid<32, Base64UrlAlphabet> = Nanoid::new();
                let user_claim = Claims {
                    sub: user.id,
                    iss: JWT_TOKEN_ISSUER.to_string(),
                    jti: jti.to_string(),
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
                // Generate JWT token and return.
                Ok((StatusCode::OK, Json(UserAuthResponse { token })).into_response())
            } else {
                // Invalid credentials.
                Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ))
            }
        }
        Err(_) => {
            // User not found.
            // Still trigger a dummy check to avoid returning immediately.
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
    State(state): State<AppState>,
    Json(user_request): Json<UserRequest>,
) -> Response {
    create_user(state.pg_pool, user_request).await.into_response()
}

async fn create_user(pool: PgPool, user_request: UserRequest) -> Result<Response, AppError> {
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
    let user_id: Nanoid<24, Base64UrlAlphabet> = Nanoid::new();

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

    let result = sqlx::query!(
        "INSERT INTO sqlx_users (id, first_name, last_name, email, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        user_id.to_string(),
        user_request.first_name,
        &user_request.last_name,
        &user_request.email,
        password_hash.to_string()
    )
        .fetch_one(&pool)
        .await;

    match result {
        Ok(user) => Ok((
            StatusCode::CREATED,
            [(header::LOCATION, format!("/users/{}", user.id))],
            Json(StoredUser {
                id: user.id,
                first_name: user.first_name,
                last_name: user.last_name,
                email: user.email,
            }),
        )
            .into_response()),
        Err(_) => Err(AppError::new(
            ErrorType::InternalServerError,
            "Error creating user",
        )),
    }
}

// GET all user handler with pagination.
/// Get list of users
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
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Response, AppError> {
    let page = query.page;
    let limit = query.size;
    let users = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, (page - 1) * limit)
        .fetch_all(&state.pg_pool)
        .await;

    let count = sqlx::query!("SELECT COUNT(*) FROM sqlx_users WHERE deleted_at IS NULL")
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
    path = "/users/{id}",
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
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let user = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE id = $1", id)
        .fetch_one(&state.pg_pool)
        .await;

    match user {
        Ok(user) => Ok((StatusCode::OK, Json(StoredUser::from(user))).into_response()),
        Err(e) => {
            error!("Error getting user: {}", e);
            Err(AppError::new(
                ErrorType::NotFound,
                "User not found for ID: ".to_owned() + &id,
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
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update_user_request): Json<UpdateUserRequest>,
) -> Result<Response, AppError> {
    let mut query = String::from("UPDATE sqlx_users SET ");
    // let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
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
    query += &format!(
        " WHERE id = ${} AND deleted_at is null RETURNING *",
        params.len() + 1
    );
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
                id: user.id,
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
    path = "/users/{id}",
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
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let result = sqlx::query_as!(
        Users,
        "UPDATE sqlx_users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
        id
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
    id: String,
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
    current_page: i64,
    total_items: i64,
    total_pages: i64,
    items_per_page: i64,
    items_in_page: i64,
}

impl From<Users> for StoredUser {
    fn from(user: Users) -> Self {
        StoredUser {
            id: user.id,
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
struct Users {
    id: String,
    first_name: Option<String>,
    last_name: String,
    email: String,
    password_hash: String,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
    #[allow(dead_code)]
    deleted_at: Option<DateTime<Utc>>,
}

// -- ---------------------
// -- Global error handling.
// -- ---------------------

// New error data type.
#[derive(ToSchema)]
pub struct AppError {
    error_type: ErrorType,
    error_message: String,
}

#[derive(Debug, Display, Error, Clone, ToSchema)]
pub enum ErrorType {
    #[display(fmt = "Not found")]
    NotFound,
    #[display(fmt = "Bad request")]
    BadRequest,
    #[display(fmt = "Internal server error")]
    InternalServerError,
    #[display(fmt = "Authentication error")]
    UnauthorizedError,
    #[display(fmt = "Request validation error")]
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
                            field: field.to_owned(),
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
