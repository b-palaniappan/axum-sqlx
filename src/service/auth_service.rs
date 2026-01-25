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
use axum::http::StatusCode;
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
            "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
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
            return Ok((
                StatusCode::OK,
                Json(LogoutResponse {
                    message: "Logout successful".to_string(),
                }),
            )
                .into_response());
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

    Ok((
        StatusCode::OK,
        Json(LogoutResponse {
            message: "Logout successful".to_string(),
        }),
    )
        .into_response())
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

/**
*
* Registration Flow:
* 1. User provides email address, first name, last name only.
* 2. If the email exists, then return the existing user ID as `exclude_credentials` and send the response.
* 3. If the email does not exist, generate a new user ID and store it in the database.
* 4. Generate a passkey registration challenge and store it in cache with a TTL.
* 5. Return the challenge to the user for registration.
* FINISH REGISTRATION
* 6. User completes the registration by providing the public key credential.
* 7. Store the public key in the DB and complete the registration.
* 8. Request the user to complete the First Name and Last Name, Update the DB with contact info.
*/
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

// Finish Registration.
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

pub async fn logout(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // This is a generic logout endpoint that does not require a request body.
    // It simply returns a success message. If you want to clear cookies or tokens,
    // you can add logic here as needed.
    Ok((StatusCode::OK, "Logout successful").into_response())
}
