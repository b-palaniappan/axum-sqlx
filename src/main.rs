use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHasher};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use derive_more::{Display, Error};
use nid::alphabet::Base64UrlAlphabet;
use nid::Nanoid;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{Error, FromRow, PgPool};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info, warn};
use validator::{Validate, ValidationErrors};

#[tokio::main]
async fn main() {
    // Logging handler using tracing.
    tracing_subscriber::fmt().init();

    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let server_host = env::var("SERVER_HOST").expect("Error getting server host");
    let server_port = env::var("SERVER_PORT").expect("Error getting server port");
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
        .route("/users/:id", get(get_user_by_id).patch(update_user))
        .fallback(page_not_found)
        .with_state(pool)
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
async fn handler_json(State(pool): State<PgPool>, headers: HeaderMap) -> Response {
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
    let response: Result<(String,), Error> =
        sqlx::query_as("SELECT 'Hello'").fetch_one(&pool).await;
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

// POST create user handler.
async fn handler_create_user(
    State(pool): State<PgPool>,
    Json(user_request): Json<UserRequest>,
) -> Response {
    create_user(pool, user_request).await.into_response()
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
async fn get_users(
    State(pool): State<PgPool>,
    Query(query): Query<PaginationQuery>,
) -> Result<Response, AppError> {
    let page = query.page;
    let limit = query.size;
    let users = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, (page - 1) * limit)
        .fetch_all(&pool)
        .await;

    let count = sqlx::query!("SELECT COUNT(*) FROM sqlx_users WHERE deleted_at IS NULL")
        .fetch_one(&pool)
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
async fn get_user_by_id(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let user = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE id = $1", id)
        .fetch_one(&pool)
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
async fn update_user(
    State(pool): State<PgPool>,
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
    let result: Result<Users, Error> = query.fetch_one(&pool).await;

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

// -- ---------------------
// -- Structs for request, response and entities.
// -- ---------------------
#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UserRequest {
    #[validate(length(
        min = 2,
        max = 50,
        message = "First name must be between 2 and 50 characters"
    ))]
    first_name: Option<String>,
    #[validate(length(
        min = 2,
        max = 50,
        message = "Last name must be between 2 and 50 characters"
    ))]
    last_name: String,
    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    password: String,
    #[validate(email(message = "Invalid email address"))]
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUserRequest {
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Debug, FromRow)]
struct Users {
    id: String,
    first_name: Option<String>,
    last_name: String,
    email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredUser {
    id: String,
    first_name: Option<String>,
    last_name: String,
    email: String,
}

#[derive(Debug, Serialize)]
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

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct PaginationQuery {
    page: i64,
    size: i64,
}

// -- ---------------------
// -- Global error handling.
// -- ---------------------

// New error data type.
pub struct AppError {
    error_type: ErrorType,
    error_message: String,
}

#[derive(Debug, Display, Error, Clone)]
pub enum ErrorType {
    #[display(fmt = "Not found")]
    NotFound,
    #[display(fmt = "Bad request")]
    BadRequest,
    #[display(fmt = "Internal server error")]
    InternalServerError,
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

#[derive(Debug, Serialize)]
struct ApiError {
    status: u16,
    time: String,
    message: String,
    #[serde(rename = "debugMessage")]
    debug_message: Option<String>,
    #[serde(rename = "subErrors")]
    sub_errors: Vec<ValidationError>,
}

#[derive(Debug, Serialize)]
pub struct ValidationError {
    object: String,
    field: String,
    rejected_value: String,
    message: String,
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
