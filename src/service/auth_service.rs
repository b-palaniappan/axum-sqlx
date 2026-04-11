use crate::AppState;
use crate::api::model::auth::{
    ForgotPasswordRequest, ForgotPasswordResponse, LogoutResponse, PasskeyAuthenticationRequest,
    PasskeyRegistrationRequest, RefreshRequest, ResetPasswordRequest, ResetPasswordResponse,
    TokenRequest, TokenResponse,
};
use crate::api::model::user::UserAuthRequest;
use crate::cache::valkey_cache;
use crate::db::entity::auth::RefreshTokenStatus;
use crate::db::entity::user::{AccountStatus, Users};
use crate::db::repo::{
    auth_repository, passkey_credentials_repository, user_login_credentials_repository,
    users_repository,
};
use crate::error::error_model::{AppError, ErrorType};
use crate::service::email;
use crate::util::crypto_helper::{
    hash_password_sign_with_hmac, run_fake_password_hash_check, verify_password_hash_hmac,
};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use nanoid::nanoid;
use openssl::pkey::PKey;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::types::chrono::Utc;
use std::ops::Add;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use uuid::Uuid;
use validator::Validate;
use webauthn_rs::prelude::{
    CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};
use xxhash_rust::xxh3::xxh3_64;

// Constants for token expiration
/// Refresh token expiration time in seconds (10 days)
const REFRESH_TOKEN_EXPIRATION_SECS: u64 = 60 * 60 * 24 * 10;

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
    let public_key = state.jwt_public_key.expose_secret();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["api"]);
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_ed_pem(public_key.as_bytes()).unwrap(),
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
                Some(jwt) if jwt.jti == token_data.claims.jti => {
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

    match user {
        Ok(user) => {
            // User found, now check the password if its status is active
            if user.account_status == AccountStatus::Active {
                match user_login_credentials_repository::get_user_login_credentials_by_user_id(
                    pg_pool, &user.id,
                )
                .await
                {
                    Ok(Some(credentials)) => {
                        let credential_verification = verify_password_hash_hmac(
                            &state,
                            &user_auth_request.password,
                            &credentials.password_hash,
                            &credentials.password_hmac,
                            &user.id,
                        )
                        .await;
                        match credential_verification {
                            Ok(_) => {
                                let refresh_token =
                                    match generate_persist_refresh_token(&state, user.id).await {
                                        Ok(value) => value,
                                        Err(value) => return value,
                                    };
                                generate_access_token(&state, pg_pool, user, &refresh_token).await
                            }
                            Err(e) => {
                                error!("Password verification failed: {:?}", e);
                                return Err(AppError::new(
                                    ErrorType::UnauthorizedError,
                                    "Invalid credentials. Check email and password.",
                                ));
                            }
                        }
                    }
                    Ok(None) => {
                        error!("User login credentials not found for user ID: {}", user.id);
                        Err(AppError::new(
                            ErrorType::UnauthorizedError,
                            "Invalid credentials. Check email and password.",
                        ))
                    }
                    Err(e) => {
                        error!("Error getting user login credentials: {:?}", e);
                        Err(AppError::new(
                            ErrorType::InternalServerError,
                            "Something went wrong. Please try again later.",
                        ))
                    }
                }
            } else {
                // Trigger a fake check for inactive user.
                run_fake_password_hash_check(&state).await
            }
        }
        Err(_) => {
            // User not found.
            run_fake_password_hash_check(&state).await
        }
    }
}

/// Generates a new access token for a user and prepares the response.
///
/// This function creates a JWT access token for the given user, caches the token identifier (JTI),
/// and resets the user's failed login attempts. It also sets the refresh token in a secure cookie
/// and returns the access token and refresh token in the response.
///
/// # Arguments
///
/// * `state` - A reference to the application state containing JWT settings and the HMAC key.
/// * `pg_pool` - A reference to the PostgreSQL connection pool.
/// * `user` - The user for whom the access token is being generated.
/// * `refresh_token` - The refresh token to include in the response.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response containing the access token and refresh token
///   if successful, otherwise returns an `AppError`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error caching the token identifier (JTI).
/// * There is an error resetting the user's failed login attempts.
async fn generate_access_token(
    state: &Arc<AppState>,
    pg_pool: &PgPool,
    user: Users,
    refresh_token: &String,
) -> Result<Response, AppError> {
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
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(get_public_key_id(State(state.clone())));
    let token = encode(
        &header,
        &user_claim,
        &EncodingKey::from_ed_pem(state.jwt_private_key.expose_secret().as_bytes()).unwrap(),
    )
    .unwrap();

    reset_failed_login_attempts(pg_pool, user.id).await;
    cache_token_id(&state, &user_key_clone, &jti_clone).await?;

    let mut response = (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.jwt_expiration as i64,
        }),
    )
        .into_response();

    // Also set the refresh_token in the secure cookie.
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        format!(
            "refresh_token={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
            refresh_token, REFRESH_TOKEN_EXPIRATION_SECS
        )
        .parse()
        .unwrap(),
    );

    Ok(response)
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
        if !cached_user_key.jti.is_empty() {
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
            jti: jti_clone.clone(),
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
    let refresh_token_expiry = Utc::now() + Duration::from_secs(REFRESH_TOKEN_EXPIRATION_SECS);

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
    let user = auth_repository::get_user_by_id(pg_pool, &user_id)
        .await
        .map_err(|e| {
            error!("Error getting user: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;

    let refresh_token = match generate_persist_refresh_token(&state, user.id).await {
        Ok(value) => value,
        Err(value) => return value,
    };
    generate_access_token(&state, pg_pool, user, &refresh_token).await
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
    let public_key = PKey::public_key_from_pem(state.jwt_public_key.expose_secret().as_bytes())
        .map_err(|e| {
            error!("Error converting public key from PEM: {:?}", e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;

    // Extract the raw public key bytes for EdDSA
    let raw_public_key = public_key.raw_public_key().map_err(|e| {
        error!("Error extracting raw public key: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Something went wrong. Please try again later.",
        )
    })?;

    let x = BASE64_URL_SAFE.encode(&raw_public_key);

    let jwk = Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: Some(vec![KeyOperations::Verify, KeyOperations::Sign]),
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(get_public_key_id(State(state))),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(
            jsonwebtoken::jwk::OctetKeyPairParameters {
                key_type: jsonwebtoken::jwk::OctetKeyPairType::OctetKeyPair,
                curve: jsonwebtoken::jwk::EllipticCurve::Ed25519,
                x,
            },
        ),
    };

    let jwks = JwkSet { keys: vec![jwk] };
    Ok((StatusCode::OK, Json(jwks)).into_response())
}

/// Invalidates all authentication tokens for a user and performs cleanup.
///
/// This function performs the core logout operations for a user by revoking all their
/// refresh tokens in the database and removing their JWT token from the cache. It is
/// designed to be resilient, continuing execution even if individual cleanup operations
/// fail, to ensure the user receives a successful logout response.
///
/// # Logout Operations
///
/// 1. Looks up the user by their unique key
/// 2. Revokes all active refresh tokens in the database
/// 3. Deletes the JWT token identifier (JTI) from the cache
/// 4. Returns a successful logout response
///
/// # Arguments
///
/// * `state` - The application state containing database connections and cache configuration.
/// * `user_key` - The unique identifier for the user (typically extracted from a JWT token or refresh token).
///
/// # Returns
///
/// * `Result<Response, AppError>` - Always returns `Ok` with a logout response that includes:
///   - HTTP 200 OK status
///   - A JSON body with a success message
///   - A `Set-Cookie` header that clears the `refresh_token` cookie
///
/// # Errors
///
/// This function does not return errors. All error conditions are logged and the function
/// continues to completion, returning a successful logout response. This design ensures:
/// - Users can always log out regardless of backend state
/// - Prevents user enumeration attacks by not revealing whether a user exists
/// - Graceful handling of partial failures (e.g., database or cache unavailable)
///
/// # Security Notes
///
/// - Returns success even if the user doesn't exist (prevents user enumeration)
/// - Continues logout even if token revocation fails (ensures user gets logged out)
/// - Invalidates both refresh tokens (database) and access tokens (cache)
/// - Uses the same response format regardless of success or failure of individual operations
///
/// # Examples
///
/// This function is typically called from the `logout` route handler:
/// ```ignore
/// pub async fn logout(
///     State(state): State<Arc<AppState>>,
///     headers: HeaderMap,
/// ) -> Result<Response, AppError> {
///     if let Some(user_key) = extract_user_key_from_headers(&state, &headers).await {
///         let _ = logout_user(State(state), user_key).await;
///     }
///     Ok(logout_response())
/// }
/// ```
pub async fn logout_user(
    State(state): State<Arc<AppState>>,
    user_key: String,
) -> Result<Response, AppError> {
    let pg_pool = &state.pg_pool;

    // Step 1: Look up the user ID from the user key (authenticated by middleware)
    let user = match users_repository::get_user_by_key(pg_pool, &user_key).await {
        Ok(user) => user,
        Err(_) => {
            // Even if user doesn't exist, return success to prevent user enumeration
            return Ok(logout_response());
        }
    };

    // Step 2: Revoke all refresh tokens for the user
    match auth_repository::logout_user(pg_pool, user.id).await {
        Ok(_) => (),
        Err(e) => {
            error!("Error revoking refresh tokens: {:?}", e);
            // Continue with logout even if revoking tokens fails
        }
    }

    // Step 3: Remove the JWT token from cache (invalidates access token)
    if let Err(e) = valkey_cache::delete_object(State(state.clone()), &user_key).await {
        error!("Error removing JWT from cache: {:?}", e);
        // Continue with logout even if cache deletion fails
    }

    Ok(logout_response())
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
    let hash = xxh3_64(state.jwt_public_key.expose_secret().as_bytes());
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
/// * `nbf` - Not before time, in seconds since the epoch.
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
/// * `jti` - A string containing the unique identifier of the JWT token.
#[derive(Debug, Serialize, Deserialize)]
struct JwtId {
    jti: String,
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
/// 1. Validates the reset token and new password format
/// 2. Verifies the password and confirm password match
/// 3. Validates password complexity requirements
/// 4. Verifies the reset token in the database
/// 5. Hashes the new password with Argon2 and HMAC
/// 6. Updates the user's password in the database
/// 7. Marks the reset token as used
/// 8. Invalidates all active refresh tokens for the user
/// 9. Removes the JWT token from cache
///
/// # Arguments
///
/// * `state` - The application state containing database connections and cryptographic keys.
/// * `reset_password_request` - The request containing:
///   - `token` - The password reset token sent to the user's email
///   - `new_password` - The new password to set
///   - `confirm_password` - Confirmation of the new password (must match `new_password`)
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response:
///   - On success: HTTP 200 OK with a JSON message "Password has been reset successfully."
///   - On error: An `AppError` with appropriate error type and message
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The request validation fails (invalid format) - Returns `RequestValidationError`
/// * The new password and confirm password don't match - Returns `BadRequest`
/// * The password doesn't meet complexity requirements - Returns `BadRequest`
///   - Must contain at least 1 uppercase letter
///   - Must contain at least 1 lowercase letter
///   - Must contain at least 1 number
///   - Must contain at least 1 special character from: `!@#$%^&*()_+-=[]{}|;':",.<>?/`~`
/// * The reset token is invalid or expired - Returns `UnauthorizedError`
/// * The user cannot be found in the database - Returns `InternalServerError`
/// * There is an error hashing the password - Returns `InternalServerError`
/// * There is an error updating the password in the database - Returns `InternalServerError`
///
/// # Security Notes
///
/// - Uses Argon2 for password hashing with HMAC for additional protection
/// - Invalidates all refresh tokens to force re-authentication on all devices
/// - Clears cached JWT tokens to immediately revoke access
/// - Marks the reset token as used to prevent reuse
/// - Continues execution even if token cleanup fails to ensure password is reset
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/auth/reset-password", post(reset_password))
/// ```
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
    let user = match auth_repository::get_user_by_id(pg_pool, &user_id).await {
        Ok(user) => user,
        Err(_) => {
            return Err(AppError::new(
                ErrorType::InternalServerError,
                "User not found.",
            ));
        }
    };

    // Step 3: Hash the new password with Argon2
    let (password_hash, password_hmac) = hash_password_sign_with_hmac(&state, &new_password)
        .await
        .map_err(|_| {
            error!("Error hashing password");
            AppError::new(ErrorType::InternalServerError, "Error hashing password.")
        })?;

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

/// Initiates the passkey registration process for a new or existing user.
///
/// This function is the first step of the WebAuthn passkey registration flow. It handles both
/// new user creation and additional passkey registration for existing users. The function
/// generates a WebAuthn registration challenge, caches the registration state, and returns
/// the challenge to the client for completion.
///
/// # Registration Flow
///
/// 1. Generates a unique registration request ID with prefix "r_"
/// 2. Checks if a user with the provided email already exists
/// 3. **For existing users:**
///    - Retrieves their existing passkey credentials
///    - Adds them to the `exclude_credentials` list to prevent duplicate registration
/// 4. **For new users:**
///    - Creates a new user record in the database with the provided first name, last name, and email
/// 5. Initiates the WebAuthn passkey registration challenge using the `exclude_credentials` list
/// 6. Caches the registration state (user key and registration state) with a 15-minute TTL
/// 7. Returns the public key challenge and request ID to the client
///
/// # Arguments
///
/// * `state` - The application state containing database connections and WebAuthn configuration.
/// * `passkey_registration_request` - The registration request containing:
///   - `email` - The user's email address (used as both user ID and display name)
///   - `first_name` - The user's first name
///   - `last_name` - The user's last name
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response containing:
///   - HTTP 200 OK status
///   - A JSON body with:
///     - `publicKey` - The WebAuthn credential creation options for the client
///     - `requestId` - A unique identifier for this registration request (must be used in `finish_registration`)
///
/// The client must use the `publicKey` challenge with the browser's WebAuthn API to create
/// a credential, then submit the result to `finish_registration` along with the `requestId`.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * There is an error checking for existing user - Logs error and continues (sets `exclude_credentials` to `None`)
/// * There is an error retrieving existing passkey credentials for a user - Returns `InternalServerError`
/// * There is an error creating a new user in the database - Returns `InternalServerError`
///   with message "Failed to create user. Please try again later."
/// * The WebAuthn library fails to start passkey registration - Returns `InternalServerError`
///   with message "Something went wrong. Please try again later."
/// * There is an error caching the registration state - Returns `InternalServerError`
///
/// # Security Notes
///
/// - The registration state is cached with a 15-minute expiration to prevent replay attacks
/// - Existing credentials are excluded from re-registration to prevent duplicate passkeys
/// - A unique passkey ID (UUID) is generated for each registration attempt
/// - The user key is generated using nanoid for uniqueness and security
///
/// # Database Operations
///
/// - **For new users:** Creates a user record with status `Active` by default
/// - **For existing users:** No database writes occur in this step (only reads)
/// - The registration state is temporarily stored in Valkey cache (not the database)
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/auth/passkey/register/start", post(start_registration))
/// ```
///
/// The client flow would be:
/// 1. Call this `start_registration` endpoint with email, first name, and last name
/// 2. Receive the WebAuthn challenge and request ID
/// 3. Use the browser's `navigator.credentials.create()` with the challenge
/// 4. Call `finish_registration` with the created credential and request ID
pub async fn start_registration(
    State(state): State<Arc<AppState>>,
    Json(passkey_registration_request): Json<PasskeyRegistrationRequest>,
) -> Result<Response, AppError> {
    let registration_request_id = format!("r_{}", nanoid!(32)); // Unique ID for the registration request.
    let user_id = &passkey_registration_request.email;
    let display_name = &passkey_registration_request.email;
    let user_passkey_id = Uuid::new_v4(); // Unique passkey ID for the user.
    let user_key = nanoid!();

    let user_opt = auth_repository::get_active_user_by_email(
        &state.pg_pool,
        &passkey_registration_request.email,
    )
    .await;
    let exclude_credentials = match user_opt {
        Ok(Some(user)) => {
            info!("User already exists.");
            let passkey_credentials =
                passkey_credentials_repository::get_passkey_credentials_by_user_id(
                    &state.pg_pool,
                    &user.id,
                )
                .await;
            match passkey_credentials {
                Ok(credentials) => {
                    // Convert to Vec<CredentialID>
                    Some(
                        credentials
                            .iter()
                            .filter_map(|cred| cred.get_credential_id())
                            .collect::<Vec<CredentialID>>(),
                    )
                }
                Err(e) => {
                    error!("Error getting passkey credentials: {:?}", e);
                    return Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Something went wrong. Please try again later.",
                    ));
                }
            }
        }
        Ok(None) => {
            let saved_user = users_repository::create_user(
                &state.pg_pool,
                &user_key,
                Some(passkey_registration_request.first_name),
                Some(passkey_registration_request.last_name),
                &passkey_registration_request.email,
            )
            .await;

            if let Err(e) = saved_user {
                error!("Error creating user: {:?}", e);
                return Err(AppError::new(
                    ErrorType::InternalServerError,
                    "Failed to create user. Please try again later.",
                ));
            }
            None
        }
        Err(e) => {
            error!("Error getting user by email: {:?}", e);
            None
        }
    };

    let res = match state.webauthn.start_passkey_registration(
        user_passkey_id,
        user_id,
        display_name,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            valkey_cache::set_object_with_ttl(
                State(state.clone()),
                &registration_request_id,
                &(&user_key, &reg_state),
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
            info!("Registration START Successful!");
            Json(serde_json::json!({
                "publicKey": ccr.public_key,
                "requestId": registration_request_id,
            }))
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

/// Completes the passkey registration process and stores the credential in the database.
///
/// This function is the second step of the WebAuthn passkey registration flow. It retrieves
/// the registration state from the cache using the provided request ID, verifies the public key
/// credential submitted by the client, and upon successful verification, stores the passkey
/// credential in the database to complete the user registration.
///
/// # Registration Flow
///
/// 1. Retrieves the cached registration state (user key and passkey registration state) using the `request_id`
/// 2. Fetches the user from the database using the cached user key
/// 3. Verifies the public key credential using WebAuthn
/// 4. Stores the verified passkey credential in the database
/// 5. Cleans up the registration state from cache
/// 6. Returns a success response (HTTP 204 No Content)
///
/// # Arguments
///
/// * `state` - The application state containing database connections and WebAuthn configuration.
/// * `request_id` - A unique identifier for this registration request, used to retrieve the cached registration state.
///   This should match the `requestId` returned from the `start_registration` function.
/// * `public_key_credential` - The public key credential created by the client's authenticator during registration,
///   wrapped in a JSON extractor.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response:
///   - On success: HTTP 204 No Content (indicating successful registration completion)
///   - On error: An `AppError` with appropriate error type and message
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The registration state is not found in cache (expired or invalid `request_id`) - Returns `BadRequest`
///   with message "Passkey Registration state not found or expired."
/// * There is an error retrieving data from cache - Returns `InternalServerError`
/// * The user cannot be found in the database using the cached user key - Returns `InternalServerError`
/// * The WebAuthn library fails to verify the public key credential - Returns `InternalServerError`
///   with message "Failed to complete registration. Please try again later."
/// * There is an error storing the passkey credential in the database - Returns `InternalServerError`
///
/// # Security Notes
///
/// - The registration state is cached with a 15-minute TTL (set in `start_registration`)
/// - The cached state is deleted after successful registration to prevent reuse
/// - The WebAuthn library performs cryptographic verification of the credential before storage
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/auth/passkey/register/finish", post(finish_registration))
/// ```
///
/// The client flow would be:
/// 1. Call `start_registration` to get the challenge
/// 2. Use the browser's WebAuthn API to create a credential
/// 3. Call this `finish_registration` endpoint with the credential and request ID
pub async fn finish_registration(
    State(state): State<Arc<AppState>>,
    request_id: String,
    Json(public_key_credential): Json<RegisterPublicKeyCredential>,
) -> Result<Response, AppError> {
    let (user_key, reg_state): (String, PasskeyRegistration) =
        match valkey_cache::get_object(State(state.clone()), &request_id).await {
            Ok(Some(cached_data)) => cached_data,
            Ok(None) => {
                error!("Passkey Registration state not found in cache.");
                return Err(AppError::new(
                    ErrorType::BadRequest,
                    "Passkey Registration state not found or expired.",
                ));
            }
            Err(e) => {
                error!("Error getting Passkey Registration from cache: {:?}", e);
                return Err(AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                ));
            }
        };
    let user = users_repository::get_user_by_key(&state.pg_pool, &user_key)
        .await
        .map_err(|e| {
            error!("Error getting user by key: {:?}. Error {:?}", &user_key, e);
            AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
        })?;
    let user_id = user.id;

    match state
        .webauthn
        .finish_passkey_registration(&public_key_credential, &reg_state)
    {
        Ok(passkey) => {
            // Store the passkey in the database
            match passkey_credentials_repository::create_passkey_credential(
                &state.pg_pool,
                &user_id,
                &passkey,
            )
            .await
            {
                Ok(_) => {
                    // Clean up the registration state from cache
                    let _ = valkey_cache::delete_object(State(state.clone()), &request_id).await;
                    info!("Passkey registration successful!!");
                    Ok((StatusCode::NO_CONTENT,).into_response())
                }
                Err(e) => {
                    error!("Error storing passkey: {:?}", e);
                    Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Failed to complete registration. Please try again later.",
                    ))
                }
            }
        }
        Err(e) => {
            error!("Error finishing passkey registration: {:?}", e);
            return Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to complete registration. Please try again later.",
            ));
        }
    }
}

/// Initiates the passkey authentication process for a user.
///
/// This function is the first step of the WebAuthn passkey authentication flow. It validates
/// the user's existence, retrieves their registered passkey credentials, generates a WebAuthn
/// authentication challenge, and caches the authentication state for verification in the
/// subsequent step.
///
/// # Authentication Flow
///
/// 1. Generates a unique login request ID with prefix "l_"
/// 2. Looks up the active user by email address
/// 3. Retrieves all registered passkey credentials for the user
/// 4. Converts stored credentials to `Passkey` objects for WebAuthn
/// 5. Initiates the WebAuthn passkey authentication challenge
/// 6. Caches the authentication state (user key and auth state) with a 15-minute TTL
/// 7. Returns the public key challenge and request ID to the client
///
/// # Arguments
///
/// * `state` - The application state containing database connections and WebAuthn configuration.
/// * `passkey_authentication_request` - The request containing the user's email address.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response containing:
///   - HTTP 200 OK status
///   - A JSON body with the WebAuthn `publicKey` challenge object and a unique `requestId`
///
/// The `requestId` must be sent back to the server in the finish authentication request along
/// with the signed credential from the authenticator.
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The user is not found in the database - Returns `BadRequest` with "User not found."
/// * There is an error retrieving the user from the database - Returns `InternalServerError`
/// * There is an error fetching passkey credentials - Returns `InternalServerError`
/// * No passkeys are registered for the user - Returns `BadRequest` with "No passkeys found for the user."
/// * The WebAuthn library fails to start authentication - Returns `InternalServerError`
/// * There is an error caching the authentication state - Returns `InternalServerError`
///
/// # Security Notes
///
/// - The authentication state is cached with a 15-minute expiration to prevent replay attacks
/// - Only active users can authenticate
/// - The function validates that at least one passkey credential exists before proceeding
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/auth/passkey/start", post(start_authentication))
/// ```
pub async fn start_authentication(
    State(state): State<Arc<AppState>>,
    Json(passkey_authentication_request): Json<PasskeyAuthenticationRequest>,
) -> Result<Response, AppError> {
    let login_request_id = format!("l_{}", nanoid!(32)); // Unique ID for the login request.
    let user_id = &passkey_authentication_request.email;

    // Fetch user and passkey credentials from the database
    let user_opt = auth_repository::get_active_user_by_email(&state.pg_pool, &user_id).await;

    match user_opt {
        Ok(Some(user)) => {
            info!("User already exists.");
            let passkey_credentials =
                passkey_credentials_repository::get_passkey_credentials_by_user_id(
                    &state.pg_pool,
                    &user.id,
                )
                .await;
            let allow_passkey_credentials = match passkey_credentials {
                Ok(credentials) => {
                    // Convert to Vec<PassKey>
                    credentials
                        .iter()
                        .filter_map(|cred| cred.to_passkey().ok())
                        .collect::<Vec<Passkey>>()
                }
                Err(e) => {
                    error!("Error getting passkey credentials: {:?}", e);
                    return Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Something went wrong. Please try again later.",
                    ));
                }
            };
            if allow_passkey_credentials.is_empty() {
                return Err(AppError::new(
                    ErrorType::BadRequest,
                    "No passkeys found for the user.",
                ));
            }
            let response = match state
                .webauthn
                .start_passkey_authentication(&allow_passkey_credentials)
            {
                Ok((ccr, auth_state)) => {
                    valkey_cache::set_object_with_ttl(
                        State(state.clone()),
                        &login_request_id,
                        &(&user.key, &auth_state),
                        Duration::from_secs(15 * 60).as_secs(),
                    )
                    .await
                    .map_err(|e| {
                        error!("Error storing Passkey Login to cache: {:?}", e);
                        AppError::new(
                            ErrorType::InternalServerError,
                            "Something went wrong. Please try again later.",
                        )
                    })?;
                    info!("Login START Successful!");
                    Json(serde_json::json!({
                        "publicKey": ccr.public_key,
                        "requestId": login_request_id,
                    }))
                }
                Err(e) => {
                    info!("challenge_login -> {:?}", e);
                    return Err(AppError::new(
                        ErrorType::InternalServerError,
                        "Something went wrong. Please try again later.",
                    ));
                }
            };
            Ok((StatusCode::OK, response).into_response())
        }
        Ok(None) => Err(AppError::new(ErrorType::BadRequest, "User not found.")),
        Err(e) => {
            error!("Error getting user by email: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            ))
        }
    }
}

/// Completes the passkey authentication process and issues access and refresh tokens.
///
/// This function is the second step of the WebAuthn passkey authentication flow. It retrieves
/// the authentication state from the cache using the provided request ID, verifies the public key
/// credential submitted by the client, and upon successful verification, generates and returns
/// JWT access and refresh tokens for the authenticated user.
///
/// # Authentication Flow
///
/// 1. Retrieves the cached authentication state using the `request_id`
/// 2. Verifies the public key credential using WebAuthn
/// 3. Fetches the user from the database using the cached user key
/// 4. Cleans up the authentication state from cache
/// 5. Generates a new refresh token and revokes any existing ones
/// 6. Generates an access token (JWT) and caches its JTI
/// 7. Returns the tokens to the client
///
/// # Arguments
///
/// * `state` - The application state containing database connections and WebAuthn configuration.
/// * `request_id` - A unique identifier for this authentication request, used to retrieve the cached authentication state.
/// * `public_key_credential` - The public key credential returned by the client's authenticator, wrapped in a JSON extractor.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Returns an HTTP response containing:
///   - HTTP 200 OK status
///   - A JSON body with the access token, token type, and expiration time
///   - A `Set-Cookie` header with the refresh token (HttpOnly, Secure, SameSite=Strict)
///
/// # Errors
///
/// This function will return an `AppError` if:
/// * The authentication state is not found in cache (expired or invalid `request_id`) - Returns `BadRequest`
/// * There is an error retrieving data from cache - Returns `InternalServerError`
/// * The passkey authentication verification fails - Returns `InternalServerError`
/// * The user cannot be found in the database - Returns `InternalServerError`
/// * There is an error generating or persisting the refresh token - Returns `InternalServerError`
/// * There is an error generating the access token or caching the JTI - Returns `InternalServerError`
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/auth/passkey/finish", post(finish_authentication))
/// ```
pub async fn finish_authentication(
    State(state): State<Arc<AppState>>,
    request_id: String,
    public_key_credential: Json<PublicKeyCredential>,
) -> Result<Response, AppError> {
    // Using request_id get the auth state from cache.
    let (user_key, auth_state): (String, PasskeyAuthentication) =
        match valkey_cache::get_object(State(state.clone()), &request_id).await {
            Ok(Some(cached_data)) => cached_data,
            Ok(None) => {
                error!("Passkey Authentication state not found in cache.");
                return Err(AppError::new(
                    ErrorType::BadRequest,
                    "Passkey Authentication state not found or expired.",
                ));
            }
            Err(e) => {
                error!("Error getting Passkey Authentication from cache: {:?}", e);
                return Err(AppError::new(
                    ErrorType::InternalServerError,
                    "Something went wrong. Please try again later.",
                ));
            }
        };

    match state
        .webauthn
        .finish_passkey_authentication(&public_key_credential, &auth_state)
    {
        Ok(_auth_result) => {
            // Get the user from the database
            let user = users_repository::get_user_by_key(&state.pg_pool, &user_key)
                .await
                .map_err(|e| {
                    error!("Error getting user by key: {:?}", e);
                    AppError::new(
                        ErrorType::InternalServerError,
                        "Something went wrong. Please try again later.",
                    )
                })?;
            let user_id = user.id;

            // Cleanup the cache after successful authentication
            let _ = valkey_cache::delete_object(State(state.clone()), &request_id).await;

            // Generate and persist a new refresh token for the user
            let refresh_token = match generate_persist_refresh_token(&state, user_id).await {
                Ok(value) => value,
                Err(value) => return value,
            };

            // Generate an access token for the user
            generate_access_token(&state, &state.pg_pool, user, &refresh_token).await
        }
        Err(e) => {
            error!("Error finishing passkey authentication: {:?}", e);
            Err(AppError::new(
                ErrorType::InternalServerError,
                "Failed to complete authentication. Please try again later.",
            ))
        }
    }
}

/// Handles user logout by invalidating tokens and clearing cookies.
///
/// This function performs a graceful logout by attempting to extract the user's key from
/// the request headers (either from a Bearer token or refresh token cookie). If a user is
/// identified, it revokes all refresh tokens and invalidates the cached JWT. The function
/// always returns a successful logout response regardless of whether a user was found,
/// which helps prevent user enumeration attacks.
///
/// # Arguments
///
/// * `state` - The application state containing database connections and configuration.
/// * `headers` - The HTTP headers from the request, which may contain authentication tokens.
///
/// # Returns
///
/// * `Result<Response, AppError>` - Always returns `Ok` with a logout response that includes:
///   - HTTP 200 OK status
///   - A JSON success message
///   - A `Set-Cookie` header that clears the `refresh_token` cookie
///
/// # Examples
///
/// This function is typically used as an Axum route handler:
/// ```ignore
/// .route("/logout", post(logout))
/// ```
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(user_key) = extract_user_key_from_headers(&state, &headers).await {
        let _ = logout_user(State(state), user_key).await;
    }

    Ok(logout_response())
}

/// Constructs a logout response that clears the refresh token cookie.
///
/// This function creates an HTTP response for a successful logout operation. It includes
/// a JSON body with a success message and sets a `Set-Cookie` header to invalidate the
/// `refresh_token` cookie by setting its `Max-Age` to 0.
///
/// The cookie is cleared with the following attributes:
/// - `Path=/` - Applies to all paths
/// - `HttpOnly` - Not accessible via JavaScript
/// - `Secure` - Only transmitted over HTTPS
/// - `SameSite=Strict` - Prevents cross-site request forgery
/// - `Max-Age=0` - Immediately expires the cookie
///
/// # Returns
///
/// * `Response` - An HTTP response with status 200 OK, a JSON success message, and a
///   `Set-Cookie` header that clears the refresh token.
fn logout_response() -> Response {
    let mut response = (
        StatusCode::OK,
        Json(LogoutResponse {
            message: "Logout successful".to_string(),
        }),
    )
        .into_response();

    response.headers_mut().insert(
        header::SET_COOKIE,
        "refresh_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );

    response
}

/// Extracts the user key from HTTP headers using either a Bearer token or a refresh token cookie.
///
/// This function provides a fallback mechanism for user identification by attempting two methods:
/// 1. First, it tries to extract the user key from a JWT Bearer token in the `Authorization` header.
/// 2. If no Bearer token is present, it attempts to extract a refresh token from the `Cookie` header,
///    validates it against the database, and retrieves the associated user key.
///
/// This dual-method approach is useful for logout operations or other scenarios where authentication
/// can be provided through either an access token or a refresh token.
///
/// # Arguments
///
/// * `state` - A reference to the application state, used to access the database connection pool and JWT public key.
/// * `headers` - A reference to the `HeaderMap` containing the HTTP headers.
///
/// # Returns
///
/// * `Option<String>` - Returns `Some(String)` containing the user key if either:
///   - A valid Bearer token is found and successfully decoded, or
///   - A valid, active refresh token is found in cookies and the associated user exists in the database.
///
///   Returns `None` if:
///   - No valid Bearer token or refresh token is found, or
///   - The refresh token is invalid, expired, or not active, or
///   - There is an error retrieving the user from the database.
async fn extract_user_key_from_headers(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Option<String> {
    if let Some(user_key) = extract_user_key_from_bearer(state, headers) {
        return Some(user_key);
    }

    let refresh_token = extract_refresh_token_cookie(headers)?;
    match auth_repository::get_refresh_token_by_value(&state.pg_pool, &refresh_token).await {
        Ok((user_id, true, RefreshTokenStatus::Active)) => {
            auth_repository::get_user_by_id(&state.pg_pool, &user_id)
                .await
                .ok()
                .map(|user| user.key)
        }
        Ok(_) | Err(_) => None,
    }
}

/// Extracts the user key (subject) from a JWT Bearer token in the HTTP Authorization header.
///
/// This function attempts to retrieve the `Authorization` header from the provided HTTP headers,
/// checks if it contains a Bearer token, and then decodes the JWT using the application's public key.
/// If the token is valid and can be decoded, it returns the `sub` (subject) claim from the token,
/// which typically represents the user key.
///
/// # Arguments
///
/// * `state` - A reference to the application state, used to access the JWT public key.
/// * `headers` - A reference to the `HeaderMap` containing the HTTP headers.
///
/// # Returns
///
/// * `Option<String>` - Returns `Some(String)` containing the user key if the Bearer token is present and valid, otherwise returns `None`.
fn extract_user_key_from_bearer(state: &Arc<AppState>, headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth_header.strip_prefix("Bearer ")?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["api"]);

    decode::<Claims>(
        token,
        &DecodingKey::from_ed_pem(state.jwt_public_key.expose_secret().as_bytes()).ok()?,
        &validation,
    )
    .ok()
    .map(|token_data| token_data.claims.sub)
}

/// Extracts the value of the `refresh_token` cookie from the HTTP headers.
///
/// This function searches the `COOKIE` header for a cookie named `refresh_token` and returns its value if found.
///
/// # Arguments
///
/// * `headers` - A reference to the `HeaderMap` containing the HTTP headers.
///
/// # Returns
///
/// * `Option<String>` - Returns `Some(String)` containing the value of the `refresh_token` cookie if present, otherwise returns `None`.
fn extract_refresh_token_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    cookie_header.split(';').find_map(|cookie| {
        let (name, value) = cookie.trim().split_once('=')?;
        (name == "refresh_token").then(|| value.to_string())
    })
}
