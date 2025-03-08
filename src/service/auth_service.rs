// Todo: Implement
// Registration (also called create user) - Implemented
// Login - Implemented with JWT and Refresh token.
// Passkey based login
// Forgot password - Work in progress
// Reset password - Work in progress
// Logout - Work in progress
// TOTP
// TOTP QR Code.
// JWT or Auth Token based logged in.
// Email verification
// Phone verification - using SMS
// May be use auth_token and refresh_token, both will be opaque token of size 32 characters of nano id.

use crate::api::model::auth::{RefreshRequest, TokenRequest, TokenResponse};
use crate::api::model::user::UserAuthRequest;
use crate::cache::valkey_cache;
use crate::db::repo::auth_repository;
use crate::error::error_model::{AppError, ErrorType};
use crate::AppState;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use nanoid::nanoid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sqlx::types::chrono::Utc;
use sqlx::PgPool;
use std::ops::Add;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use validator::Validate;
use xxhash_rust::xxh3::xxh3_64;

// Validate JWT token using public key
pub async fn validate_token(
    State(state): State<Arc<AppState>>,
    Json(token_request): Json<TokenRequest>,
) -> Result<Response, AppError> {
    if let Err(e) = token_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "TokenRequest".to_string(),
            },
            "Validation error. Check the token.",
        ));
    }
    let token = token_request.token;
    let public_key = state.jwt_public_key.clone();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap(),
        &Validation::new(Algorithm::RS256),
    );
    match token_data {
        Ok(token_data) => {
            if token_data.claims.exp < Utc::now().timestamp() {
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Token has expired.",
                ));
            }
            Ok((StatusCode::OK, Json(token_data.claims)).into_response())
        }
        Err(e) => {
            error!("Error decoding token: {:?}", e);
            Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid token. Check the token and try again.",
            ))
        }
    }
}

// Authentication user
pub async fn authenticate_user(
    State(state): State<Arc<AppState>>,
    Json(user_auth_request): Json<UserAuthRequest>,
) -> Result<Response, AppError> {
    // validate user auth request.
    if let Err(e) = user_auth_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "UserAuthRequest".to_string(),
            },
            "Validation error. Check the request body.",
        ));
    }
    let pg_pool = &state.pg_pool;
    let user = auth_repository::get_user_by_email(pg_pool, &user_auth_request.email).await;

    let argon2 = Argon2::default();
    match user {
        Ok(user) => {
            let password_hash = PasswordHash::new(&user.password_hash).unwrap();
            // TODO: Only do auth check if the user status is active.
            if argon2
                .verify_password(user_auth_request.password.as_bytes(), &password_hash)
                .is_err()
            {
                handle_user_authentication_failed(pg_pool, user.id)
                    .await
                    .map_err(|e| {
                        error!("Error handling user authentication failed: {:?}", e);
                        AppError::new(
                            ErrorType::InternalServerError,
                            "Something went wrong. Please try again later.",
                        )
                    })?;
            }

            let mut mac = Hmac::<Sha512>::new_from_slice(state.hmac_key.as_bytes()).unwrap();
            mac.update(&user.password_hash.as_bytes());
            if mac.verify_slice(&user.password_hmac).is_err() {
                handle_user_authentication_failed(pg_pool, user.id)
                    .await
                    .map_err(|e| {
                        error!("Error handling user authentication failed: {:?}", e);
                        AppError::new(
                            ErrorType::InternalServerError,
                            "Something went wrong. Please try again later.",
                        )
                    })?;
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
            }

            // Generate access token.
            let now = Utc::now();
            let jti = nanoid!(); // Unique jwt identifier.
            let user_key_clone = user.key.clone();
            let jti_clone = jti.clone();

            let user_claim = Claims {
                sub: user.key,
                iss: state.jwt_issuer.clone(),
                jti,
                aud: "api".to_string(),
                iat: now.timestamp(),
                nbf: now.timestamp(),
                exp: now
                    .add(Duration::from_secs(state.jwt_expiration.clone()))
                    .timestamp(),
            };
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(get_public_key_id(State(state.clone())));
            let token = encode(
                &header,
                &user_claim,
                &EncodingKey::from_rsa_pem(&state.jwt_private_key.as_bytes()).unwrap(),
            )
            .unwrap();

            let refresh_token = match generate_persist_refresh_token(&state, user.id).await {
                Ok(value) => value,
                Err(value) => return value,
            };

            reset_failed_login_attempts(pg_pool, user.id).await;
            cache_token_id(&state, &user_key_clone, &jti_clone).await?;
            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token: token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                }),
            )
                .into_response())
        }
        Err(_) => {
            // User not found.
            // Still trigger a fake check to avoid returning immediately.
            // Which can be used by hacker to figure out user id is not valid.
            let dummy_password_hash = state.dummy_hashed_password.clone();
            let password_hash = PasswordHash::new(&*dummy_password_hash).unwrap();
            let _ = argon2.verify_password("dummy".as_bytes(), &password_hash);
            Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid credentials. Check email and password.",
            ))
        }
    }
}

async fn cache_token_id(
    state: &Arc<AppState>,
    user_key: &String,
    jti_clone: &String,
) -> Result<(), AppError> {
    // Step 1. Check if there is an active JTI for the user. If yes, delete it.
    let cached_user_key: Option<JwtId> = valkey_cache::get_object(State(state.clone()), user_key)
        .await
        .map_err(|e| {
            error!("Error getting JTI from cache: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;
    if let Some(cached_user_key) = cached_user_key {
        if !cached_user_key.value.is_empty() {
            valkey_cache::delete_object(State(state.clone()), &user_key)
                .await
                .map_err(|e| {
                    error!("Error deleting JTI from cache: {:?}", e);
                    AppError::new(
                        ErrorType::InternalServerError,
                        "Something went wrong. Please try again later.",
                    )
                })?;
        }
    }

    // Step 2. Store the JTI in cache with TTL.
    valkey_cache::set_object_with_ttl(
        State(state.clone()),
        &user_key,
        &JwtId {
            value: jti_clone.clone(),
        },
        Duration::from_secs(state.jwt_expiration.clone()).as_secs(),
    )
    .await
    .map_err(|e| {
        error!("Error storing JTI to cache: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Something went wrong. Please try again later.",
        )
    })?;
    Ok(())
}

/// Generates and persists a new refresh token for a user, revoking any existing token.
///
/// # Arguments
///
/// * `state` - The application state containing the database connection pool.
/// * `user_id` - The ID of the user for whom the refresh token is being generated.
///
/// # Returns
///
/// * `Result<String, Result<Response, AppError>>` - Returns the new refresh token if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error revoking the existing refresh token.
/// * There is an error adding the new refresh token to the database.
async fn generate_persist_refresh_token(
    state: &Arc<AppState>,
    user_id: i64,
) -> Result<String, Result<Response, AppError>> {
    // Revoke existing token if present
    if let Some(token) = auth_repository::get_active_refresh_token(&state.pg_pool, user_id).await {
        auth_repository::revoke_refresh_token(&state.pg_pool, token)
            .await
            .map_err(|e| {
                error!("Error deactivating refresh token: {:?}", e);
                Err(AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to generate refresh token.",
                ))
            })?;
    }

    // Generate and persist new token
    let refresh_token = nanoid!(32);
    let refresh_token_expiry = Utc::now() + Duration::from_secs(60 * 60 * 24 * 10);

    auth_repository::add_refresh_token(
        &state.pg_pool,
        user_id,
        &refresh_token,
        refresh_token_expiry,
    )
    .await
    .map_err(|e| {
        error!("Error adding refresh token: {:?}", e);
        Err(AppError::new(
            ErrorType::InternalServerError,
            "Failed to generate refresh token.",
        ))
    })?;

    Ok(refresh_token)
}

// Update failed login attempts for user.
async fn handle_user_authentication_failed(pg_pool: &PgPool, user_id: i64) -> Result<(), AppError> {
    auth_repository::increase_failed_login_attempts(pg_pool, user_id)
        .await
        .unwrap();

    let user = auth_repository::get_user_by_id(pg_pool, user_id)
        .await
        .unwrap();

    // Lock user account if failed login attempts are more than 5.
    if user.failed_login_attempts.unwrap_or(0) >= 5 {
        auth_repository::lock_user_account(pg_pool, user_id)
            .await
            .unwrap();
        return Err(AppError::new(
            ErrorType::UnauthorizedError,
            "User account is locked. Contact support.",
        ));
    }
    Ok(())
}

async fn reset_failed_login_attempts(pg_pool: &PgPool, user_id: i64) {
    let result = auth_repository::reset_failed_login_attempts(pg_pool, user_id).await;
    match result {
        Ok(_) => (),
        Err(e) => error!("Error resetting failed login attempts: {:?}", e),
    }
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    refresh_request: Json<RefreshRequest>,
) -> Result<Response, AppError> {
    // Generate a new JWT token and refresh token if the current refresh token is valid.
    todo!()
}

/// Returns the JSON Web Key Set (JWKS) containing the public key for JWT token validation.
///
/// This function converts the stored public key from PEM format to RSA format,
/// then encodes it to Base64 URL-safe format and constructs a JWK object.
/// The JWK object is then wrapped in a JWKS and returned as a JSON response.
///
/// # Arguments
///
/// * `state` - The application state containing the public key.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns a JSON response containing the JWKS if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error converting the public key from PEM to RSA format.
/// * There is an error converting the RSA key to a PKey.
pub async fn get_jwks(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Return the public key for JWT token validation.
    let rsa = Rsa::public_key_from_pem(&state.jwt_public_key.as_bytes()).map_err(|e| {
        error!("Error converting public key to RSA: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Something went wrong. Please try again later.",
        )
    })?;
    let public_key = PKey::from_rsa(rsa).map_err(|e| {
        error!("Error converting RSA to PKey: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Something went wrong. Please try again later.",
        )
    })?;

    let n = BASE64_URL_SAFE.encode(&public_key.rsa().unwrap().n().to_vec());
    let e = BASE64_URL_SAFE.encode(&public_key.rsa().unwrap().e().to_vec());

    let jwk = Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: Some(vec![KeyOperations::Verify, KeyOperations::Sign]),
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(get_public_key_id(State(state))),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(
            jsonwebtoken::jwk::RSAKeyParameters {
                n,
                e,
                ..Default::default()
            },
        ),
    };

    let jwks = JwkSet { keys: vec![jwk] };
    Ok((StatusCode::OK, Json(jwks)).into_response())
}

pub async fn logout_user(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Invalidate the refresh token.
    // And remove the access token from redis cache.
    todo!()
}

/// Generates a unique identifier for the public key.
///
/// This function computes a hash of the public key using the xxHash3 algorithm,
/// converts the hash to a byte array, and then encodes it to a URL-safe Base64 string.
///
/// # Arguments
///
/// * `state` - The application state containing the public key.
///
/// # Returns
///
/// * `String` - A URL-safe Base64 encoded string representing the unique identifier of the public key.
fn get_public_key_id(State(state): State<Arc<AppState>>) -> String {
    let hash = xxh3_64(state.jwt_public_key.as_bytes());
    let bytes = hash.to_be_bytes();
    URL_SAFE_NO_PAD.encode(&bytes)
}

// --------------------------------
// Structs and Enums
// --------------------------------
/// Represents the claims contained in a JSON Web Token (JWT).
///
/// This struct is used to store the standard claims of a JWT, which are used for
/// authentication and authorization purposes.
///
/// # Fields
///
/// * `sub` - The subject of the token, typically the user ID.
/// * `iss` - The issuer of the token.
/// * `jti` - The unique identifier for the token.
/// * `aud` - The audience for the token, typically the intended recipient.
/// * `iat` - The issued at time, in seconds since the epoch.
/// * `nbf` - The not before time, in seconds since the epoch.
/// * `exp` - The expiration time, in seconds since the epoch.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    jti: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

/// Represents a JSON Web Token (JWT) identifier.
///
/// This struct is used to store the unique identifier (JTI) of a JWT token,
/// which can be used for various purposes such as token revocation and validation.
///
/// # Fields
///
/// * `value` - A string containing the unique identifier of the JWT token.
#[derive(Debug, Serialize, Deserialize)]
struct JwtId {
    value: String,
}
