// Todo: Implement
// Registration (also called create user)
// Login - Implemented
// Passkey based login
// Forgot password
// Reset password
// TOTP
// TOTP QR Code.
// JWT or Auth Token based logged in.
// Email verification
// Phone verification - using SMS
// May be use auth_token and refresh_token, both will be opaque token of size 32 characters of nano id.

use crate::api::model::auth::{RefreshRequest, TokenRequest, TokenResponse};
use crate::api::model::user::UserAuthRequest;
use crate::error::error_model::{AppError, ErrorType};
use crate::AccountStatus;
use crate::{AppState, Users};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sqlx::types::chrono::Utc;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use validator::Validate;

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

    let user = sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled,
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        FROM users WHERE email = $1
        "#,
        user_auth_request.email
    )
        .fetch_one(&state.pg_pool)
        .await;

    let argon2 = Argon2::default();
    match user {
        Ok(user) => {
            let password_hash = PasswordHash::new(&user.password_hash).unwrap();
            // TODO: Only do auth check if the user status is active.
            if argon2
                .verify_password(user_auth_request.password.as_bytes(), &password_hash)
                .is_err()
            {
                let status = user_authentication_failed(State(state), user.id).await;
                if status == "LOCKED" {
                    return Err(AppError::new(
                        ErrorType::UnauthorizedError,
                        "User account is locked. Contact support.",
                    ));
                }
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
            }

            let mut mac = Hmac::<Sha512>::new_from_slice(state.hmac_key.as_bytes()).unwrap();
            mac.update(&user.password_hash.as_bytes());
            if mac.verify_slice(&user.password_hmac).is_err() {
                let status = user_authentication_failed(State(state), user.id).await;
                if status == "LOCKED" {
                    return Err(AppError::new(
                        ErrorType::UnauthorizedError,
                        "User account is locked. Contact support.",
                    ));
                }
                return Err(AppError::new(
                    ErrorType::UnauthorizedError,
                    "Invalid credentials. Check email and password.",
                ));
            }
            
            // Generate access token and refresh token.
            // TODO: Move this to a separate function.
            // TODO: Persist the refresh_token in PostgreSQL table and deactivate the other active refresh tokens.
            // TODO: Add the access token to the redis cache by user_key with TTL 3600 seconds.
            let now = Utc::now();
            let jti = nanoid!();
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
            let token = encode(
                &Header::new(Algorithm::RS256),
                &user_claim,
                &EncodingKey::from_rsa_pem(&state.jwt_private_key.as_bytes()).unwrap(),
            )
            .unwrap();

            let refresh_token = nanoid!(32);

            reset_failed_login_attempts(State(state), user.id).await;
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
            let password_hash = PasswordHash::new(&*state.dummy_hashed_password).unwrap();
            let _ = argon2.verify_password("dummy".as_bytes(), &password_hash);
            Err(AppError::new(
                ErrorType::UnauthorizedError,
                "Invalid credentials. Check email and password.",
            ))
        }
    }
}

// Update failed login attempts for user.
async fn user_authentication_failed(State(state): State<Arc<AppState>>, user_id: i64) -> String {
    if let Err(e) = sqlx::query!(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1",
        user_id
    )
    .execute(&state.pg_pool)
    .await
    {
        error!("Error updating failed login attempts: {:?}", e);
        return "".to_string();
    }

    let user = match sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, password_hash, password_hmac, email_verified, update_password, two_factor_enabled,
        account_status as "account_status: AccountStatus", last_login, failed_login_attempts, created_at, updated_at
        FROM users WHERE id = $1
        "#,
        user_id
    )
        .fetch_one(&state.pg_pool)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Error fetching user: {:?}", e);
            return "OK".to_string();
        }
    };

    // Lock user account if failed login attempts are more than 5.
    if user.failed_login_attempts.unwrap_or(0) >= 5 {
        if let Err(e) = sqlx::query!(
            "UPDATE users SET account_status = 'LOCKED' WHERE id = $1",
            user_id
        )
        .execute(&state.pg_pool)
        .await
        {
            error!("Error locking user account: {:?}", e);
        }
        return "LOCKED".to_string();
    }
    "OK".to_string()
}

async fn reset_failed_login_attempts(State(state): State<Arc<AppState>>, user_id: i64) {
    let result = sqlx::query!(
        "UPDATE users SET failed_login_attempts = 0 WHERE id = $1",
        user_id
    )
    .execute(&state.pg_pool)
    .await;
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

pub async fn get_jwks(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Return the public key for JWT token validation.
    // TODO: convert the public key to JWK format.
    Ok((StatusCode::OK, state.jwt_public_key.clone()).into_response())
}

pub async fn logout_user(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    // Invalidate the refresh token.
    // And remove the access token from redis cache.
    todo!()
}

// --------------------------------
// Structs and Enums
// --------------------------------
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

#[derive(Debug, Serialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize)]
struct JwkKey {
    kty: String,  // Key type
    kid: String,  // Key ID
    n: String,    // Modulus (for RSA)
    e: String,    // Exponent (for RSA)
    alg: String,  // Algorithm
    use_: String, // Use (sig for signature)
}
