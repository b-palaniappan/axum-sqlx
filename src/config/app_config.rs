use bb8_redis::bb8::Pool;
use bb8_redis::RedisConnectionManager;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

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
    let hmac_key = env::var("HMAC_SECRET").expect("Error getting HMAC secret");
    let jwt_private_key = env::var("JWT_PRIVATE_KEY").expect("Error getting JWT private key");
    let jwt_public_key = env::var("JWT_PUBLIC_KEY").expect("Error getting JWT public key");
    let jwt_expiration = env::var("JWT_TOKEN_EXPIRATION")
        .expect("Error getting JWT expiration")
        .parse::<u64>()
        .expect("Error parsing JWT expiration");
    let jwt_issuer = env::var("JWT_TOKEN_ISSUER").expect("Error getting JWT issuer");
    let dummy_hashed_password =
        env::var("DUMMY_HASHED_PASSWORD").expect("Error getting dummy password");

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

    Arc::new(AppState {
        pg_pool,
        redis_pool,
        hmac_key,
        jwt_private_key,
        jwt_public_key,
        jwt_expiration,
        jwt_issuer,
        dummy_hashed_password,
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
    pub hmac_key: String,
    pub jwt_private_key: String,
    pub jwt_public_key: String,
    pub jwt_expiration: u64,
    pub jwt_issuer: String,
    pub dummy_hashed_password: String,
}
