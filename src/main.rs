use std::env;
use std::net::SocketAddr;

use axum::{Json, Router};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use nid::alphabet::Base64UrlAlphabet;
use nid::Nanoid;
use serde::{Deserialize, Serialize};
use sqlx::{Error, FromRow, PgPool};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::{DateTime, Utc};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    // Logging handler using tracing.
    tracing_subscriber::fmt().init();

    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
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

    // build our application with a route
    let app = Router::new()
        .route("/", get(handler_json))
        .route("/users", post(handler_create_user).get(get_users))
        .route("/users/:id", get(get_user_by_id).patch(update_user))
        .with_state(pool);

    // run it
    let server_address: SocketAddr = server_addr.parse().unwrap();
    info!("Starting server at {}", server_addr);
    let listener = tokio::net::TcpListener::bind(server_address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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

async fn create_user(pool: PgPool, user_request: UserRequest) -> Response {
    let user_id: Nanoid<24, Base64UrlAlphabet> = Nanoid::new();
    let result = sqlx::query!(
        "INSERT INTO sqlx_users (id, first_name, last_name, email) VALUES ($1, $2, $3, $4) RETURNING *",
        user_id.to_string(),
        &user_request.first_name,
        &user_request.last_name,
        &user_request.email
    )
    .fetch_one(&pool)
    .await;

    match result {
        Ok(user) => (
            StatusCode::CREATED,
            [(header::LOCATION, format!("/users/{}", user.id))],
            Json(Message {
                message: "Success".to_string(),
                status: format!("User created with ID: {}", user.id),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "Error".to_string(),
                status: "Error creating user".to_string(),
            }),
        )
            .into_response(),
    }
}

// GET all user handler with pagination.
async fn get_users(State(pool): State<PgPool>, Query(query): Query<PaginationQuery>) -> Response {
    let page = query.page;
    let limit = query.limit;
    let users = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, (page - 1) * limit)
        .fetch_all(&pool)
        .await;

    let count = sqlx::query!("SELECT COUNT(*) FROM sqlx_users WHERE deleted_at IS NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    let items_in_page = users.as_ref().unwrap().len();

    match users {
        Ok(users) => (
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
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "Error".to_string(),
                status: "Error getting users".to_string(),
            }),
        )
            .into_response(),
    }
}

// Get user by user id.
async fn get_user_by_id(State(pool): State<PgPool>, Path(id): Path<String>) -> Response {
    let user = sqlx::query_as!(Users, "SELECT * FROM sqlx_users WHERE id = $1", id)
        .fetch_one(&pool)
        .await;

    match user {
        Ok(user) => (StatusCode::OK, Json(StoredUser::from(user))).into_response(),
        Err(e) => {
            error!("Error getting user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Message {
                    message: "Error".to_string(),
                    status: "Error getting user".to_string(),
                }),
            )
                .into_response()
        }
    }
}

// PATCH update user by user id.
// Only allowed to update first_name and last_name. Email address is not updatable.
async fn update_user(
    State(pool): State<PgPool>,
    Path(id): Path<String>,
    Json(update_user_request): Json<UpdateUserRequest>,
) -> Response {
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
        Ok(user) => (
            StatusCode::OK,
            Json(Message {
                message: "Success".to_string(),
                status: format!("User updated with ID: {}", user.id),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Message {
                message: "Error".to_string(),
                status: "Error updating user".to_string(),
            }),
        )
            .into_response(),
    }
}

// -- ---------------------
// -- Structs for request, response and entities.
// -- ---------------------
#[derive(Debug, Serialize, Deserialize)]
struct UserRequest {
    #[serde(rename = "firstName")]
    first_name: String,
    #[serde(rename = "lastName")]
    last_name: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdateUserRequest {
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, FromRow)]
struct Users {
    id: String,
    first_name: Option<String>,
    last_name: String,
    email: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredUser {
    id: String,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    limit: i64,
}
