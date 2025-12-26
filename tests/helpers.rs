use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use bb8_redis::RedisConnectionManager;
use bb8_redis::bb8::Pool;
use nanoid::nanoid;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::prelude::Url;

use axum_sqlx::AppState;
use axum_sqlx::api::handler::user_handler::user_routes;

pub async fn setup_test_app() -> Router {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Create a test-specific app state
    let app_state = setup_test_app_state().await;

    // Build test router with user routes
    Router::new()
        .nest("/users", user_routes())
        .with_state(app_state)
}

pub async fn setup_test_app_state() -> Arc<AppState> {
    // Check if TEST_DATABASE_URL is set, otherwise use DATABASE_URL
    let database_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| env::var("DATABASE_URL").expect("DATABASE_URL must be set"));
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");

    // Test-specific secrets and keys
    let test_hmac_key = env::var("HMAC_SECRET").unwrap_or_else(|_| "test_hmac_key".to_string());
    let jwt_private_key =
        env::var("JWT_PRIVATE_KEY").unwrap_or_else(|_| "test_private_key".to_string());
    let jwt_public_key =
        env::var("JWT_PUBLIC_KEY").unwrap_or_else(|_| "test_public_key".to_string());
    let jwt_expiration = env::var("JWT_TOKEN_EXPIRATION")
        .unwrap_or_else(|_| "3600".to_string())
        .parse::<u64>()
        .expect("Error parsing JWT expiration");
    let jwt_issuer = env::var("JWT_TOKEN_ISSUER").unwrap_or_else(|_| "test_issuer".to_string());
    let dummy_hashed_password = env::var("DUMMY_HASHED_PASSWORD")
        .unwrap_or_else(|_| "$argon2id$v=19$m=65536,t=4,p=1$c29tZXJhbmRvbXNhbHQ$2INNARqrDRWDs6P3h/0lNTVJQgUOjr10OjVLQ36Qz+M".to_string());

    // Encryption key (must be 32 bytes)
    let encryption_key_str = env::var("ENCRYPTION_KEY")
        .unwrap_or_else(|_| "test-encryption-key-must-be-32byte".to_string());

    // Convert to bytes and ensure it's exactly 32 bytes
    let key_bytes = encryption_key_str.as_bytes();
    if key_bytes.len() != 32 {
        panic!("ENCRYPTION_KEY must be exactly 32 bytes when encoded as UTF-8");
    }

    // Convert to fixed-size array
    let encryption_key: [u8; 32] = match key_bytes.try_into() {
        Ok(key) => key,
        Err(_) => panic!("Failed to convert encryption key to 32 byte array"),
    };

    let argon_pepper = env::var("ARGON_PEPPER").unwrap_or_else(|_| "test_argon_pepper".to_string());

    // Setup connection pool with smaller max connections for tests
    let pg_pool = PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .connect(&database_url)
        .await
        .expect("Failed to create database connection pool");

    // Setup Redis connection with smaller pool for tests
    let manager =
        RedisConnectionManager::new(redis_url).expect("Failed to create Redis connection manager");
    let redis_pool = Pool::builder()
        .min_idle(2)
        .max_size(5)
        .max_lifetime(Duration::from_secs(60 * 60))
        .idle_timeout(Duration::from_secs(60 * 10))
        .build(manager)
        .await
        .unwrap();

    // Setup Webauthn with test configuration
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:3000").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let webauthn = builder
        .rp_name("Axum SQLx Test")
        .timeout(Duration::from_secs(10 * 60))
        .build()
        .expect("Invalid configuration");

    Arc::new(AppState {
        pg_pool,
        redis_pool,
        webauthn,
        hmac_key: test_hmac_key.into(),
        jwt_private_key: jwt_private_key.into(),
        jwt_public_key: jwt_public_key.into(),
        jwt_expiration,
        jwt_issuer,
        dummy_hashed_password: dummy_hashed_password.into(),
        encryption_key,
        argon_pepper: argon_pepper.into(),
    })
}

// Helper to make API requests in tests
pub async fn make_request(
    app: Router,
    method: axum::http::Method,
    uri: &str,
    json_body: Option<String>,
) -> Response {
    let request_builder = Request::builder()
        .uri(uri)
        .method(method)
        .header("Content-Type", "application/json");

    let request = if let Some(body) = json_body {
        request_builder.body(Body::from(body)).unwrap()
    } else {
        request_builder.body(Body::empty()).unwrap()
    };

    app.oneshot(request).await.unwrap()
}

// Helper to get a unique test email
pub fn get_test_email() -> String {
    format!("test-{}@example.com", nanoid!(8))
}
