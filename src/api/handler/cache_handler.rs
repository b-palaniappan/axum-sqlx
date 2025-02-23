use crate::cache::valkey_cache;
use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tracing::error;

pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/set", post(cache_set))
        .route("/set-ttl", post(cache_set_ttl))
        .route("/get/{key}", get(cache_get))
        .route("/delete/{key}", delete(cache_delete))
}

/// Handles the request to set a cache entry.
///
/// # Arguments
///
/// * `state` - The application state containing the cache.
/// * `request` - The data to be cached, including an ID, name, and email.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response with the cached data if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error setting the cache entry.
async fn cache_set(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CacheDataRequest>,
) -> Result<Response, AppError> {
    let response = valkey_cache::set_object(State(state), &request.id, &request).await;
    match response {
        Ok(()) => Ok((StatusCode::OK, Json(request)).into_response()),
        Err(e) => {
            error!("Error: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ))
        }
    }
}

/// Handles the request to set a cache entry with a time-to-live (TTL).
///
/// # Arguments
///
/// * `state` - The application state containing the cache.
/// * `request` - The data to be cached, including an ID, name, and email.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response with the cached data if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error setting the cache entry with TTL.
async fn cache_set_ttl(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CacheDataRequest>,
) -> Result<Response, AppError> {
    let response = valkey_cache::set_object_with_ttl(State(state), &request.id, &request, 60).await;
    match response {
        Ok(()) => Ok((StatusCode::OK, Json(request)).into_response()),
        Err(e) => {
            error!("Error: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ))
        }
    }
}

/// Handles the request to get a cache entry.
///
/// # Arguments
///
/// * `state` - The application state containing the cache.
/// * `key` - The key of the data to be retrieved from the cache.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response with the cached data if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The requested data is not found in the cache.
/// * There is an error retrieving the data from the cache.
async fn cache_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> Result<Response, AppError> {
    let response: Result<Option<CacheDataRequest>, Box<dyn Error>> =
        valkey_cache::get_object(State(state), &key).await;
    match response {
        Ok(Some(data)) => Ok((StatusCode::OK, Json(data)).into_response()),
        Ok(None) => Err(AppError::new(
            ErrorType::NotFound,
            "The requested data was not found in the cache.",
        )),
        Err(e) => {
            error!("Get cache Error: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ))
        }
    }
}

/// Handles the request to delete a cache entry.
///
/// # Arguments
///
/// * `state` - The application state containing the cache.
/// * `key` - The key of the data to be deleted from the cache.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response with no content if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error deleting the data from the cache.
async fn cache_delete(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> Result<Response, AppError> {
    let response = valkey_cache::delete_object(State(state), &key).await;
    match response {
        Ok(()) => Ok((StatusCode::NO_CONTENT, ()).into_response()),
        Err(e) => {
            error!("Error: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ))
        }
    }
}

/// Sample request to be saved to cache.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheDataRequest {
    pub id: String,
    pub name: String,
    pub email: String,
}
