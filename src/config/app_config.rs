use crate::AppState;
use bb8_redis::bb8::Pool;
use bb8_redis::RedisConnectionManager;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;

// Create and load PostgresSQL and Redis connection pools.
pub async fn initialize_app_state() -> Arc<AppState> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").expect("Error getting redis host");
    let hmac_key = env::var("HMAC_SECRET").expect("Error getting HMAC secret");

    // Setup connection pool.
    let pg_pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .connect(&database_url)
        .await
        .map_err(|e| {
            panic!("Failed to create database connection pool: {}", e);
        })
        .unwrap();

    // Setup Redis connection.
    let manager =
        RedisConnectionManager::new(redis_url).expect("Failed to create Redis connection manager");
    let redis_pool = Pool::builder().min_idle(5).build(manager).await.unwrap();

    Arc::new(AppState {
        pg_pool,
        redis_pool,
        hmac_key,
    })
}

pub async fn get_server_address() -> String {
    let server_host = env::var("SERVER_HOST").expect("Error getting server host");
    let server_port = env::var("SERVER_PORT").expect("Error getting server port");
    server_host + ":" + &*server_port
}
