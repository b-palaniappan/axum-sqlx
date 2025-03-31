// Todo: Implement
// Registration (also called create user) - Implemented
// Login - Implemented with JWT and Refresh token.
// Passkey based login
// Forgot password -Implemented.
// Reset password - Implemented.
// Change password.
// Logout - Work in progress
// TOTP
// TOTP QR Code.
// JWT or Auth Token based logged in.
// Email verification
// Phone verification - using SMS

use crate::api::model::auth::{
    ForgotPasswordRequest, ForgotPasswordResponse, LogoutRequest, PasskeyRegistrationStartRequest,
    RefreshRequest, ResetPasswordRequest, ResetPasswordResponse, TokenRequest, TokenResponse,
};
use crate::api::model::user::UserAuthRequest;
use crate::cache::valkey_cache;
use crate::db::entity::auth::RefreshTokenStatus;
use crate::db::repo::auth_repository;
use crate::error::error_model::{AppError, ErrorType};
use crate::service::email;
use crate::AppState;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
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
use tracing::log::info;
use uuid::Uuid;
use validator::Validate;
use xxhash_rust::xxh3::xxh3_64;

/// Validates a JWT token using the public key.
///
/// This function validates the provided JWT token by decoding it using the public key.
/// If the token is valid and not expired, it returns the claims contained in the token.
/// If the token is invalid or expired, it returns an `AppError`.
///
/// # Arguments
///
/// * `state` - The application state containing the public key.
/// * `token_request` - The request containing the JWT token to be validated.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns a JSON response containing the token claims if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The token request is invalid.
/// * The token has expired.
/// * There is an error decoding the token.
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
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["api"]);
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap(),
        &validation,
    );
    match token_data {
        Ok(token_data) => {
            // Check token expiration
            if token_data.claims.exp < Utc::now().timestamp() {
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Token has expired.",
                ));
            }

            // Verify token exists in cache
            let cached_jwt: Option<JwtId> =
                valkey_cache::get_object(State(state.clone()), &token_data.claims.sub)
                    .await
                    .map_err(|e| {
                        error!("Error getting JWT from cache: {:?}", e);
                        AppError::new(
                            ErrorType::InternalServerError,
                            "Something went wrong. Please try again later.",
                        )
                    })?;

            match cached_jwt {
                Some(jwt) if jwt.value == token_data.claims.jti => {
                    Ok((StatusCode::OK, Json(token_data.claims)).into_response())
                }
                _ => Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Token is not valid or has been revoked.",
                )),
            }
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

/// Authenticates a user based on the provided credentials.
///
/// This function validates the user authentication request, checks the user's credentials,
/// and generates an access token and a refresh token if the credentials are valid.
/// If the credentials are invalid, it handles the failed authentication attempt.
///
/// # Arguments
///
/// * `state` - The application state containing the database connection pool, HMAC key, and JWT settings.
/// * `user_auth_request` - The user authentication request containing the email and password.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns a JSON response containing the access token and refresh token if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The user authentication request is invalid.
/// * The user is not found.
/// * The password verification fails.
/// * There is an error generating the access token or refresh token.
/// * There is an error handling the failed authentication attempt.
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
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
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

            let mut response = (
                StatusCode::OK,
                Json(TokenResponse {
                    access_token: token,
                    refresh_token: refresh_token.to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: state.jwt_expiration as i64,
                }),
            )
                .into_response();

            // Also set the refresh_token in the secure cookie.
            response.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                format!(
                    "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
                    refresh_token, state.jwt_expiration
                )
                .parse()
                .unwrap(),
            );

            Ok(response)
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

/// Caches the JWT identifier (JTI) for a user, replacing any existing JTI.
///
/// This function first checks if there is an active JTI for the user in the cache.
/// If an active JTI is found, it deletes it. Then, it stores the new JTI in the cache
/// with a time-to-live (TTL) equal to the JWT expiration time.
///
/// # Arguments
///
/// * `state` - The application state containing the cache and JWT expiration settings.
/// * `user_key` - The unique key identifying the user.
/// * `jti_clone` - The new JWT identifier to be cached.
///
/// # Returns
///
/// * `Result<(), AppError>` - Returns `Ok(())` if the operation is successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error retrieving the JTI from the cache.
/// * There is an error deleting the JTI from the cache.
/// * There is an error storing the new JTI in the cache.
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
    Json(refresh_request): Json<RefreshRequest>,
) -> Result<Response, AppError> {
    // Validate the refresh token request
    if let Err(e) = refresh_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "RefreshRequest".to_string(),
            },
            "Validation error. Check the refresh token value.",
        ));
    }

    // Get the refresh token from the request
    let refresh_token = refresh_request.refresh_token;
    let pg_pool = &state.pg_pool;

    // Check if refresh token exists and is valid
    let token_info =
        match auth_repository::get_refresh_token_by_value(pg_pool, &refresh_token).await {
            Ok(token_info) => token_info,
            Err(_) => {
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid refresh token.",
                ));
            }
        };

    let (user_id, is_valid, status) = token_info;

    // Verify token is valid and active
    if !is_valid || status != RefreshTokenStatus::Active {
        return Err(AppError::new(
            ErrorType::UnauthorizedError,
            "Refresh token is no longer valid.",
        ));
    }

    // Revoke the current refresh token
    auth_repository::revoke_refresh_token(pg_pool, refresh_token)
        .await
        .map_err(|e| {
            error!("Error revoking refresh token: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;

    // Get user information
    let user = auth_repository::get_user_by_id(pg_pool, user_id)
        .await
        .map_err(|e| {
            error!("Error getting user: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;

    // Generate new JWT token
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

    // Generate and persist new refresh token
    let new_refresh_token = match generate_persist_refresh_token(&state, user_id).await {
        Ok(value) => value,
        Err(value) => return value,
    };

    // Update token in cache
    cache_token_id(&state, &user_key_clone, &jti_clone).await?;

    // Return the new tokens
    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: state.jwt_expiration as i64,
        }),
    )
        .into_response())
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

pub async fn logout_user(
    State(state): State<Arc<AppState>>,
    Json(logout_request): Json<LogoutRequest>,
) -> Result<Response, AppError> {
    // Step 1: Validate the logout request
    if let Err(e) = logout_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "LogoutRequest".to_string(),
            },
            "Validation error. Check the request body.",
        ));
    }

    let user_key = logout_request.user_key;
    let pg_pool = &state.pg_pool;

    // Step 2: Look up the user ID from the user key
    // This would typically be a DB call, but for now we assume the user key is provided
    // In a real implementation with middleware, you'd use the authenticated user context
    // Since we don't have get_user_by_key function, we'll use email instead as a workaround
    let user = match auth_repository::get_user_by_email(pg_pool, &user_key).await {
        Ok(user) => user,
        Err(_) => {
            // Even if user doesn't exist, return success to prevent user enumeration
            return Ok((StatusCode::OK, "Logout successful").into_response());
        }
    };

    // Step 3: Revoke all refresh tokens for the user
    match auth_repository::logout_user(pg_pool, user.id).await {
        Ok(_) => (),
        Err(e) => {
            error!("Error revoking refresh tokens: {:?}", e);
            // Continue with logout even if revoking tokens fails
        }
    }

    // Step 4: Remove the JWT token from cache
    if let Err(e) = valkey_cache::delete_object(State(state.clone()), &user_key).await {
        error!("Error removing JWT from cache: {:?}", e);
        // Continue with logout even if cache deletion fails
    }

    Ok((StatusCode::OK, "Logout successful").into_response())
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

/// Handles the forgot password request by generating a reset token and sending an email.
///
/// This function performs the following steps:
/// 1. Validates the email format
/// 2. Looks up the user by email
/// 3. Generates a random token
/// 4. Stores the token in the database with a 12-hour expiration
/// 5. Sends an email with the reset token to the user
///
/// # Arguments
///
/// * `state` - The application state containing database connections.
/// * `forgot_password_request` - The request containing the user's email address.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns a generic success message (even if email not found)
///   to prevent user enumeration, or an error if the request is invalid.
pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(forgot_password_request): Json<ForgotPasswordRequest>,
) -> Result<Response, AppError> {
    // Step 1: Validate the request
    if let Err(e) = forgot_password_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "ForgotPasswordRequest".to_string(),
            },
            "Validation error. Check the request body.",
        ));
    }

    let email = forgot_password_request.email;
    let pg_pool = &state.pg_pool;

    // Step 2: Look up the user by email
    // We'll continue even if the user is not found, but won't actually send an email
    // This prevents user enumeration attacks
    let user = match auth_repository::get_user_by_email(pg_pool, &email).await {
        Ok(user) => Some(user),
        Err(_) => None,
    };

    // If the user exists, generate a reset token and send an email
    if let Some(user) = user {
        // Step 3: Generate a random token (32 characters)
        let token = nanoid!(32);

        // Step 4: Store the token in the database with a 12-hour expiration
        let expires_at = Utc::now() + Duration::from_secs(60 * 60 * 12); // 12 hours

        match auth_repository::create_password_reset_token(pg_pool, user.id, &token, expires_at)
            .await
        {
            Ok(_) => {
                // Step 5: Send an email with the reset token
                if let Err(e) = email::send_password_reset_email(&email, &token).await {
                    error!("Error sending password reset email: {}", e);
                    // Continue anyway, we still want to return a generic response
                }
            }
            Err(e) => {
                error!("Error creating password reset token: {:?}", e);
                // Continue anyway, we still want to return a generic response
            }
        }
    }

    // Always return a generic success message to prevent user enumeration
    Ok((
        StatusCode::OK,
        Json(ForgotPasswordResponse {
            message: "If your email is registered, you will receive a password reset link shortly."
                .to_string(),
        }),
    )
        .into_response())
}

/// Resets a user's password using a valid reset token.
///
/// This function performs the following steps:
/// 1. Validates the reset token and new password
/// 2. Verifies the token in the database
/// 3. Hashes the new password
/// 4. Updates the user's password in the database
/// 5. Marks the token as used
/// 6. Invalidates any active refresh tokens and JWT tokens
///
/// # Arguments
///
/// * `state` - The application state containing database connections.
/// * `reset_password_request` - The request containing the reset token and new password.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns a success message if the password is reset successfully,
///   or an error if the token is invalid or the request is malformed.
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(reset_password_request): Json<ResetPasswordRequest>,
) -> Result<Response, AppError> {
    // Step 1: Validate the request
    if let Err(e) = reset_password_request.validate() {
        return Err(AppError::new(
            ErrorType::RequestValidationError {
                validation_error: e,
                object: "ResetPasswordRequest".to_string(),
            },
            "Validation error. Check the request body.",
        ));
    }

    let token = reset_password_request.token;
    let new_password = reset_password_request.new_password;
    let confirm_password = reset_password_request.confirm_password;
    let pg_pool = &state.pg_pool;

    // Validate that the new password and confirm password match
    if new_password != confirm_password {
        return Err(AppError::new(
            ErrorType::BadRequest,
            "Password and Confirm password does not match.",
        ));
    }

    // Validate password complexity (need to have at least 1 uppercase, 1 lowercase, 1 number and 1 special character)
    if !new_password.chars().any(|c| c.is_uppercase())
        || !new_password.chars().any(|c| c.is_lowercase())
        || !new_password.chars().any(|c| c.is_digit(10))
        || !new_password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;':\",.<>?/`~".contains(c))
    {
        return Err(AppError::new(
            ErrorType::BadRequest,
            "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.",
        ));
    }

    // Step 2: Verify the token in the database
    let user_id = match auth_repository::verify_password_reset_token(pg_pool, &token).await {
        Ok(user_id) => user_id,
        Err(_) => {
            return Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid or expired password reset token.",
            ));
        }
    };

    // Get the user to find their current password
    let user = match auth_repository::get_user_by_id(pg_pool, user_id).await {
        Ok(user) => user,
        Err(_) => {
            return Err(AppError::new(
                ErrorType::InternalServerError,
                "User not found.",
            ));
        }
    };

    // Step 3: Hash the new password with Argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| {
            error!("Error hashing password: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Failed to process the password.",
            )
        })?
        .to_string();

    // Generate HMAC for password hash to detect tampering
    let mut mac = Hmac::<Sha512>::new_from_slice(state.hmac_key.as_bytes()).map_err(|e| {
        error!("Error creating HMAC: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to process the password.",
        )
    })?;
    mac.update(password_hash.as_bytes());
    let password_hmac = mac.finalize().into_bytes().to_vec();

    // Step 4: Update the user's password
    auth_repository::update_user_password(pg_pool, user_id, &password_hash, &password_hmac)
        .await
        .map_err(|e| {
            error!("Error updating user password: {:?}", e);
            AppError::new(ErrorType::InternalServerError, "Failed to update password.")
        })?;

    // Step 5: Mark the token as used
    if let Err(e) = auth_repository::mark_reset_token_as_used(pg_pool, &token).await {
        error!("Error marking reset token as used: {:?}", e);
        // Continue anyway, the password has already been reset
    }

    // Step 6: Invalidate any active refresh tokens
    if let Err(e) = auth_repository::logout_user(pg_pool, user_id).await {
        error!("Error invalidating refresh tokens: {:?}", e);
        // Continue anyway, the password has already been reset
    }

    // Step 7: Remove the JWT token from cache if it exists
    if let Err(e) = valkey_cache::delete_object(State(state.clone()), &user.key).await {
        error!("Error removing JWT from cache: {:?}", e);
        // Continue anyway, the password has already been reset
    }

    Ok((
        StatusCode::OK,
        Json(ResetPasswordResponse {
            message: "Password has been reset successfully.".to_string(),
        }),
    )
        .into_response())
}

// TODO: For Registration get, First name, last name, and email.
// then store to DB with pass key UUID.
// User ID will the unique internal ID (NanoId) generated by the system.
// Display name will be the first name + last name with space in between.
pub async fn start_registration(
    State(state): State<Arc<AppState>>,
    Json(passkey_registration_start_request): Json<PasskeyRegistrationStartRequest>,
) -> Result<Response, AppError> {
    let user_id = "testuser";
    let display_name = format!("{} {}", passkey_registration_start_request.first_name, passkey_registration_start_request.last_name);
    let user_passkey_id = Uuid::new_v4();

    // TODO: Implement fetching user's existing passkeys from database
    // For now, we'll pass None as exclude_credentials since we don't have users field in AppState
    let exclude_credentials = None;

    let res = match state.webauthn.start_passkey_registration(
        user_passkey_id,
        &user_id,
        &display_name,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            valkey_cache::set_object_with_ttl(
                State(state.clone()),
                &user_passkey_id.to_string(),
                &reg_state,
                Duration::from_secs(15 * 60).as_secs(),
            )
            .await
            .map_err(|e| {
                error!("Error storing Passkey Registration to cache: {:?}", e);
                AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                )
            })?;
            info!("Registration Successful!");
            Json(ccr)
        }
        Err(e) => {
            info!("challenge_register -> {:?}", e);
            return Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ));
        }
    };
    Ok((StatusCode::OK, res).into_response())
}
