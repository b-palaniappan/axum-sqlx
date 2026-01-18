use crate::config::app_config::AppState;
use axum::extract::State;
use bb8_redis::redis;
use bb8_redis::redis::AsyncCommands;
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;
use tracing::error;

/// Sets an object in the Redis cache.
///
/// # Arguments
///
/// * `state` - The application state containing the Redis connection pool.
/// * `key` - The key under which the value will be stored in the cache.
/// * `value` - The value to be stored in the cache. It must implement the `Serialize` trait.
///
/// # Returns
///
/// * `Result<(), AppError>` - Returns `Ok(())` if the operation is successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error serializing the value to a JSON string.
/// * There is an error setting the value in the Redis cache.
#[tracing::instrument(
    skip(state, value),
    fields(
        cache.system = "redis",
        cache.operation = "SET",
        cache.key = %key
    )
)]
pub async fn set_object<T>(
    State(state): State<Arc<AppState>>,
    key: &String,
    value: &T,
) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        error!("Failed to get Redis connection: {}", e);
        e
    })?;
    let json_string = serde_json::to_string(value).map_err(|e| {
        error!("Failed to serialize value: {}", e);
        e
    })?;
    let _: redis::Value = redis_con.set(key, json_string).await.map_err(|e| {
        error!("Failed to set value in Redis: {}", e);
        e
    })?;
    Ok(())
}

/// Sets an object in the Redis cache with a time-to-live (TTL).
///
/// # Arguments
///
/// * `state` - The application state containing the Redis connection pool.
/// * `key` - The key under which the value will be stored in the cache.
/// * `value` - The value to be stored in the cache. It must implement the `Serialize` trait.
/// * `ttl` - The time-to-live for the cache entry in seconds.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns `Ok(())` if the operation is successful, otherwise returns an error.
///
/// # Errors
///
/// This function will return an error if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error serializing the value to a JSON string.
/// * There is an error setting the value in the Redis cache with the specified TTL.
#[tracing::instrument(
    skip(state, value),
    fields(
        cache.system = "redis",
        cache.operation = "SETEX",
        cache.key = %key,
        cache.ttl = ttl
    )
)]
pub async fn set_object_with_ttl<T>(
    State(state): State<Arc<AppState>>,
    key: &String,
    value: &T,
    ttl: u64,
) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        error!("Failed to get Redis connection: {}", e);
        e
    })?;
    let json_string = serde_json::to_string(value).map_err(|e| {
        error!("Failed to serialize value: {}", e);
        e
    })?;
    let _: redis::Value = redis_con.set_ex(key, json_string, ttl).await.map_err(|e| {
        error!("Failed to set value in Redis with TTL: {}", e);
        e
    })?;
    Ok(())
}

/// Retrieves an object from the Redis cache.
///
/// # Arguments
///
/// * `state` - The application state containing the Redis connection pool.
/// * `key` - The key under which the value is stored in the cache.
///
/// # Returns
///
/// * `Result<Option<T>, Box<dyn std::error::Error>>` - Returns `Ok(Some(value))` if the value is found and successfully deserialized, `Ok(None)` if the key does not exist, otherwise returns an error.
///
/// # Errors
///
/// This function will return an error if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error retrieving the value from the Redis cache.
/// * There is an error deserializing the value from a JSON string.
#[tracing::instrument(
    skip(state),
    fields(
        cache.system = "redis",
        cache.operation = "GET",
        cache.key = %key,
        cache.hit = tracing::field::Empty
    )
)]
pub async fn get_object<T>(
    State(state): State<Arc<AppState>>,
    key: &String,
) -> Result<Option<T>, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        error!("Failed to get Redis connection: {}", e);
        e
    })?;
    let json_string: Option<String> = redis_con.get(key).await.map_err(|e| {
        error!("Failed to get value from Redis: {}", e);
        e
    })?;

    let span = tracing::Span::current();
    if let Some(json_str) = json_string {
        span.record("cache.hit", true);
        let value: T = serde_json::from_str(&json_str).map_err(|e| {
            error!("Failed to deserialize value: {}", e);
            e
        })?;
        Ok(Some(value))
    } else {
        span.record("cache.hit", false);
        Ok(None)
    }
}

/// Deletes an object from the Redis cache.
///
/// # Arguments
///
/// * `state` - The application state containing the Redis connection pool.
/// * `key` - The key under which the value is stored in the cache.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns `Ok(())` if the operation is successful, otherwise returns an error.
///
/// # Errors
///
/// This function will return an error if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error deleting the value from the Redis cache.
#[tracing::instrument(
    skip(state),
    fields(
        cache.system = "redis",
        cache.operation = "DEL",
        cache.key = %key
    )
)]
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    key: &String,
) -> Result<(), Box<dyn Error>> {
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        error!("Failed to get Redis connection: {}", e);
        e
    })?;
    let _: redis::Value = redis_con.del(key).await.map_err(|e| {
        error!("Failed to delete value from Redis: {}", e);
        e
    })?;
    Ok(())
}
