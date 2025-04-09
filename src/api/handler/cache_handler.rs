use crate::cache::valkey_cache;
use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType, ApiError};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tracing::error;
use utoipa::ToSchema;
use validator::Validate;

pub fn cache_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/set", post(cache_set))
        .route("/set-ttl", post(cache_set_ttl))
        .route("/get/{key}", get(cache_get))
        .route("/delete/{key}", delete(cache_delete))
}

/// Set a cache entry.
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
#[utoipa::path(
    post,
    path = "/cache/set",
    tag = "Cache",
    request_body = CacheDataRequest,
    responses(
        (status = 200, description = "Cache entry set successfully", body = CacheDataRequest),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
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

/// Set a cache entry with a time-to-live (TTL).
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
#[utoipa::path(
    post,
    path = "/cache/set-ttl",
    tag = "Cache",
    request_body = CacheDataRequest,
    responses(
        (status = 200, description = "Cache entry set successfully", body = CacheDataRequest),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
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

/// Get a cache entry.
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
#[utoipa::path(
    get,
    path = "/cache/get/{key}",
    tag = "Cache",
    params(
        ("key" = String, Path, description = "Cache key to retrieve")
    ),
    responses(
        (status = 200, description = "Cache entry retrieved successfully", body = CacheDataRequest),
        (status = 404, description = "Cache entry not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
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

/// Delete a cache entry.
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
#[utoipa::path(
    delete,
    path = "/cache/delete/{key}",
    tag = "Cache",
    params(
        ("key" = String, Path, description = "Cache key to delete")
    ),
    responses(
        (status = 204, description = "Cache entry deleted successfully"),
        (status = 500, description = "Internal server error", body = ApiError),
    )
)]
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
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
struct CacheDataRequest {
    #[validate(length(
        min = 21,
        max = 21,
        message = "ID must be 21 characters"
    ))]
    #[schema(example = "dd48ennqEdUNsklxbXvAY")]
    pub id: String,

    #[validate(length(
        min = 2,
        max = 255,
        message = "Name must be between 2 and 255r characters"
    ))]
    #[schema(example = "John Doe")]
    pub name: String,

    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "john@example.com")]
    pub email: String,
}
