use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType};
use axum::extract::State;
use redis::AsyncCommands;
use serde::Serialize;
use std::sync::Arc;

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
async fn set_object<T>(
    State(state): State<Arc<AppState>>,
    key: &str,
    value: &T,
) -> Result<(), AppError>
where
    T: Serialize,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Cache error: {}", e),
        )
    })?;
    let json_string = serde_json::to_string(value).map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Serialization error: {}", e),
        )
    })?;
    redis_con.set(key, json_string).await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Redis error: {}", e),
        )
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
/// * `ttl` - The time-to-live for the cached value, in seconds.
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
/// * There is an error setting the value in the Redis cache with the specified TTL.
async fn set_object_with_ttl<T>(
    State(state): State<Arc<AppState>>,
    key: &str,
    value: &T,
    ttl: u64,
) -> Result<(), AppError>
where
    T: Serialize,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Cache error: {}", e),
        )
    })?;
    let json_string = serde_json::to_string(value).map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Serialization error: {}", e),
        )
    })?;
    redis_con.set_ex(key, json_string, ttl).await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Redis error: {}", e),
        )
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
/// * `Result<T, AppError>` - Returns the deserialized object if the operation is successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error retrieving the value from the Redis cache.
/// * There is an error deserializing the JSON string to the specified type.
async fn get_object<T>(State(state): State<Arc<AppState>>, key: &str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Cache error: {}", e),
        )
    })?;
    let json_string: String = redis_con.get(key).await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Redis error: {}", e),
        )
    })?;
    let value: T = serde_json::from_str(&json_string).map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Deserialization error: {}", e),
        )
    })?;
    Ok(value)
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
/// * `Result<(), AppError>` - Returns `Ok(())` if the operation is successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error obtaining a Redis connection from the pool.
/// * There is an error deleting the value from the Redis cache.
async fn delete_object(State(state): State<Arc<AppState>>, key: &str) -> Result<(), AppError> {
    let mut redis_con = state.redis_pool.get().await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Cache error: {}", e),
        )
    })?;
    let _: () = redis_con.del(key).await.map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Redis error: {}", e),
        )
    })?;
    Ok(())
}
