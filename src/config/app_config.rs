use bb8_redis::RedisConnectionManager;
use bb8_redis::bb8::Pool;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

/// Initializes the application state by creating and loading PostgreSQL and Redis connection pools.
///
/// # Returns
/// An `Arc<AppState>` containing the initialized PostgreSQL and Redis connection pools and HMAC key.
///
/// # Panics
/// This function will panic if the `DATABASE_URL`, `REDIS_URL`, or `HMAC_SECRET` environment variables are not set,
/// or if it fails to create the database connection pool or Redis connection manager.
pub async fn initialize_app_state() -> Arc<AppState> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").expect("Error getting redis host");
    let hmac_key = SecretString::new(
        env::var("HMAC_SECRET")
            .expect("Error getting HMAC secret")
            .into(),
    );
    let jwt_private_key = SecretString::new(
        env::var("JWT_PRIVATE_KEY")
            .expect("Error getting JWT private key")
            .into(),
    );
    let jwt_public_key = SecretString::new(
        env::var("JWT_PUBLIC_KEY")
            .expect("Error getting JWT public key")
            .into(),
    );
    let jwt_expiration = env::var("JWT_TOKEN_EXPIRATION")
        .expect("Error getting JWT expiration")
        .parse::<u64>()
        .expect("Error parsing JWT expiration");
    let jwt_issuer = env::var("JWT_TOKEN_ISSUER").expect("Error getting JWT issuer");
    let dummy_hashed_password = SecretString::new(
        env::var("DUMMY_HASHED_PASSWORD")
            .expect("Error getting dummy password")
            .into(),
    );

    // Get the encryption key for sensitive data like TOTP secrets
    let encryption_key_str = SecretString::new(
        env::var("ENCRYPTION_KEY")
            .expect("ENCRYPTION_KEY must be set")
            .into(),
    );
    let argon_pepper = SecretString::new(
        env::var("ARGON_PEPPER")
            .expect("Error getting Argon2 pepper")
            .into(),
    );

    // Convert to bytes and ensure it's exactly 32 bytes
    let key_bytes = encryption_key_str.expose_secret().as_bytes();
    if key_bytes.len() != 32 {
        panic!(
            "ENCRYPTION_KEY must be exactly 32 bytes when encoded as UTF-8. Current length: {}",
            key_bytes.len()
        );
    }

    // Convert to fixed-size array
    let encryption_key: [u8; 32] = match key_bytes.try_into() {
        Ok(key) => key,
        Err(_) => panic!("Failed to convert encryption key to 32 byte array"),
    };

    // Setup connection pool.
    info!("Initializing database connection pool");
    let pg_pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .connect(&database_url)
        .await
        .map_err(|e| {
            panic!("Failed to create database connection pool: {}", e);
        })
        .unwrap();
    info!("✅ Database connection pool initialized");

    // Setup Redis connection.
    info!("Initializing Redis connection pool");
    let manager =
        RedisConnectionManager::new(redis_url).expect("Failed to create Redis connection manager");
    let redis_pool = Pool::builder()
        .min_idle(5)
        .max_lifetime(Duration::from_secs(60 * 60))
        .idle_timeout(Duration::from_secs(60 * 10))
        .build(manager)
        .await
        .unwrap();
    info!("✅ Redis connection pool initialized");

    // Setup Webauthn.
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:3000").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let webauthn = builder
        .rp_name("Axum SQLx application")
        .timeout(Duration::from_secs(10 * 60)) // allow 10 minutes for registration
        .build()
        .expect("Invalid configuration");

    Arc::new(AppState {
        pg_pool,
        redis_pool,
        webauthn,
        hmac_key,
        jwt_private_key,
        jwt_public_key,
        jwt_expiration,
        jwt_issuer,
        dummy_hashed_password,
        encryption_key,
        argon_pepper,
    })
}

/// Retrieves the server address from the environment variables.
///
/// # Returns
/// A `String` containing the server address in the format `host:port`.
///
/// # Panics
/// This function will panic if the `SERVER_HOST` or `SERVER_PORT` environment variables are not set.
pub async fn get_server_address() -> String {
    let server_host = env::var("SERVER_HOST").expect("Error getting server host");
    let server_port = env::var("SERVER_PORT").expect("Error getting server port");
    server_host + ":" + &*server_port
}

#[derive(Clone)]
pub struct AppState {
    pub pg_pool: PgPool,
    pub redis_pool: Pool<RedisConnectionManager>,
    pub webauthn: Webauthn,
    pub hmac_key: SecretString,
    pub jwt_private_key: SecretString,
    pub jwt_public_key: SecretString,
    pub jwt_expiration: u64,
    pub jwt_issuer: String,
    pub dummy_hashed_password: SecretString,
    pub encryption_key: [u8; 32],
    pub argon_pepper: SecretString,
}
