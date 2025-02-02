use crate::api::model::user::Message;
use crate::config::app_config::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use redis::AsyncCommands;
use sqlx::Error;
use std::sync::Arc;
use tracing::{info, warn};

pub fn welcome_routes() -> Router<Arc<AppState>> {
    Router::new().route("/", get(welcome_handler))
}

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
async fn welcome_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
