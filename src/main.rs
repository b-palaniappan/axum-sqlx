use std::net::SocketAddr;
use std::string::ToString;
use std::time::Duration;

use crate::api::handler::auth_handler::auth_routes;
use crate::api::handler::user_handler::user_routes;
use crate::api::handler::welcome_handler::welcome_routes;
use crate::config::app_config::{get_server_address, initialize_app_state, AppState};
use crate::db::entity::user::{AccountStatus, Users};
use crate::error::error_model::ApiError;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use sqlx::types::chrono::Utc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::info;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable};

mod api {
    pub(crate) mod handler;
    pub(crate) mod model;
}
mod cache;
mod config;
mod db {
    pub(crate) mod entity;
    mod repo;
}
mod error;
mod middleware;
mod service;
mod util;

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
        paths(api::handler::user_handler::create_user_handler, api::handler::user_handler::get_users_handler, api::handler::user_handler::get_user_handler, api::handler::user_handler::update_user_handler, api::handler::user_handler::delete_user_handler, api::handler::welcome_handler::welcome_handler, api::handler::auth_handler::authenticate_handler),
        components(schemas(api::model::user::UserRequest, api::model::user::UpdateUserRequest, api::model::user::StoredUser, api::model::user::StoredUsers, api::model::user::Message, ApiError, error::error_model::ValidationError, api::model::user::UserAuthRequest, api::model::user::UserAuthResponse)),
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
        // allow requests from localhost only.
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap());

    // build our application with a route
    let app = Router::new()
        .nest("/welcome", welcome_routes())
        .nest("/auth", auth_routes())
        .nest("/users", user_routes())
        .merge(Scalar::with_url("/scalar", ApiDoc::openapi()))
        .fallback(page_not_found)
        .method_not_allowed_fallback(method_not_allowed)
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

async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(ApiError {
            status: 405,
            time: Utc::now().to_rfc3339(),
            message: "Method not allowed".to_string(),
            debug_message: None,
            sub_errors: vec![],
        }),
    )
        .into_response()
}
