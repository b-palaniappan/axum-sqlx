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

use crate::api::model::user::{UserAuthRequest, UserAuthResponse};
use crate::error::error_model::{AppError, ErrorType};
use crate::AccountStatus;
use crate::{AppState, Users};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, EncodingKey, Header};
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sqlx::types::chrono::Utc;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use validator::Validate;

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
            let now = Utc::now();
            let jti = nanoid!();
            let user_claim = Claims {
                sub: user.key,
                iss: state.jwt_issuer.clone(),
                jti,
                iat: now.timestamp(),
                nbf: now.timestamp(),
                exp: now
                    .add(Duration::from_secs(state.jwt_expiration.clone()))
                    .timestamp(),
            };
            let token = encode(
                &Header::default(),
                &user_claim,
                &EncodingKey::from_secret(state.jwt_secret.as_ref()),
            )
            .unwrap();
            reset_failed_login_attempts(State(state), user.id).await;
            // TODO: Store the token in Redis for revoking.
            // Generate JWT token and return.
            Ok((StatusCode::OK, Json(UserAuthResponse { token })).into_response())
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

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}
