use std::net::SocketAddr;
use std::string::ToString;
use std::time::Duration;

use crate::api::handler::auth_handler::{protected_auth_routes, public_auth_routes};
use crate::api::handler::cache_handler::cache_routes;
use crate::api::handler::mfa_handler::mfa_routes;
use crate::api::handler::passkey_handler::passkey_auth_routes;
use crate::api::handler::totp_handler::totp_routes;
use crate::api::handler::user_handler::user_routes;
use crate::api::handler::welcome_handler::welcome_routes;
use crate::config::app_config::{AppState, get_server_address, initialize_app_state};
use crate::db::entity::user::AccountStatus;
use crate::error::error_model::ApiError;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use opentelemetry::trace::TracerProvider;
use sqlx::types::chrono::Utc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
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
    pub(crate) mod repo;
}
mod error;
mod middleware;
mod observability;
mod service;
mod util;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file first.
    dotenvy::dotenv().ok();

    // Load OTEL configuration
    let otel_config = config::otel_config::load_otel_config();

    // Initialize OTEL providers
    let tracer_provider = observability::tracing::init_tracer_provider(&otel_config).ok();
    let _meter_provider = observability::metrics::init_meter_provider(&otel_config).ok();
    let logger_provider = observability::logs::init_logger_provider(&otel_config).ok();

    // Setup tracing subscriber with OTLP layers
    match (tracer_provider, logger_provider) {
        (Some(provider), Some(logger_provider)) => {
            // Both traces and logs enabled
            let tracer = provider.tracer("axum-sqlx");
            let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let logs_layer = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger_provider);

            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                .with(telemetry_layer)
                .with(logs_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();

            // Store logger provider to keep it alive
            std::mem::forget(logger_provider);
        }
        (Some(provider), None) => {
            // Only traces enabled
            let tracer = provider.tracer("axum-sqlx");
            let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                .with(telemetry_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
        (None, Some(logger_provider)) => {
            // Only logs enabled
            let logs_layer = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logger_provider);

            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                .with(logs_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();

            // Store logger provider to keep it alive
            std::mem::forget(logger_provider);
        }
        (None, None) => {
            // If OTEL is disabled, just use basic logging
            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }
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
        paths(
            api::handler::user_handler::create_user_handler,
            api::handler::user_handler::get_users_handler,
            api::handler::user_handler::get_user_handler,
            api::handler::user_handler::update_user_handler,
            api::handler::user_handler::delete_user_handler,
            api::handler::welcome_handler::welcome_handler,
            api::handler::auth_handler::authenticate_handler,
            api::handler::auth_handler::refresh_token_handler,
            api::handler::auth_handler::jwks_handler,
            api::handler::auth_handler::logout_handler,
            api::handler::auth_handler::forgot_password_handler,
            api::handler::auth_handler::reset_password_handler,
            api::handler::passkey_handler::registration_start_handler,
            api::handler::passkey_handler::login_start_handler,
            api::handler::totp_handler::totp_register,
            api::handler::totp_handler::totp_validate,
            api::handler::totp_handler::totp_backup_codes,
            api::handler::totp_handler::generate_validate_backup_code,
            api::handler::totp_handler::delete_backup_codes,
            api::handler::mfa_handler::register_email_mfa,
            api::handler::mfa_handler::verify_email_mfa,
            api::handler::mfa_handler::register_sms_mfa,
            api::handler::mfa_handler::verify_sms_mfa,
            api::handler::cache_handler::cache_set,
            api::handler::cache_handler::cache_set_ttl,
            api::handler::cache_handler::cache_get,
            api::handler::cache_handler::cache_delete,
        ),
        components(schemas(
            api::model::user::UserRequest,
            api::model::user::UpdateUserRequest,
            api::model::user::StoredUser,
            api::model::user::StoredUsers,
            api::model::user::Message,
            ApiError,
            error::error_model::ValidationError,
            api::model::user::UserAuthRequest,
            api::model::auth::TokenResponse,
            api::model::auth::LogoutResponse,
            api::model::mfa::EmailMfaRegisterRequest,
            api::model::mfa::EmailMfaRegisterResponse,
            api::model::mfa::EmailMfaVerifyRequest,
            api::model::mfa::EmailMfaVerifyResponse,
            api::model::mfa::SmsMfaRegisterRequest,
            api::model::mfa::SmsMfaRegisterResponse,
            api::model::mfa::SmsMfaVerifyRequest,
            api::model::mfa::SmsMfaVerifyResponse
        )),
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

    // Path to assets directory
    let assets_path = std::env::current_dir().unwrap().join("assets");
    info!("Serving static files from: {:?}", assets_path);

    // build our application with a route
    let app = Router::new()
        .nest("/welcome", welcome_routes())
        .nest("/auth", public_auth_routes())
        .nest(
            "/auth",
            // Protected auth routes require authentication
            protected_auth_routes().route_layer(from_fn_with_state(
                shared_state.clone(),
                middleware::auth::require_auth,
            )),
        )
        .nest("/users", user_routes())
        .nest("/cache", cache_routes())
        .nest("/passkey", passkey_auth_routes())
        .nest(
            "/mfa/totp",
            // Setup middleware to require authentication
            totp_routes().route_layer(from_fn_with_state(
                shared_state.clone(),
                middleware::auth::require_auth,
            )),
        )
        .nest(
            "/mfa",
            // Setup middleware to require authentication
            mfa_routes().route_layer(from_fn_with_state(
                shared_state.clone(),
                middleware::auth::require_auth,
            )),
        )
        .merge(Scalar::with_url("/scalar", ApiDoc::openapi()))
        // Serve static files
        .nest_service(
            "/js",
            ServeDir::new(assets_path.join("js")).precompressed_zstd(),
        )
        .route_service(
            "/",
            ServeDir::new(assets_path.clone())
                .append_index_html_on_directories(true)
                .precompressed_zstd(),
        )
        // Handle routes that are not found - apply after static files so they take precedence
        .fallback(page_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(shared_state)
        .layer(from_fn(middleware::otel_middleware::trace_layer))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(cors);

    // run it
    let server_address: SocketAddr = server_addr.parse().unwrap();
    info!("Starting server at {}", server_addr);
    let listener = tokio::net::TcpListener::bind(server_address).await.unwrap();

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    // Shutdown OTEL providers
    info!("Shutting down OpenTelemetry providers");
    // Note: In OpenTelemetry SDK 0.26+, providers should be shut down individually
    // by calling .shutdown() on each provider instance. If needed, store the providers
    // in AppState for proper shutdown handling.
}

/// Handle shutdown signal for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, starting graceful shutdown");
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
