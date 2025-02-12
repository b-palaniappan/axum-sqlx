use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType};
use axum::extract::State;
use redis::AsyncCommands;
use serde::Serialize;
use std::sync::Arc;

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
