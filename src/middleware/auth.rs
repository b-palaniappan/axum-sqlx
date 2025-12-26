use crate::cache::valkey_cache;
use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType};
use axum::extract::State;
use axum::http::{Request, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;
use std::sync::Arc;
use tracing::error;

/// Context inserted into request extensions after successful auth.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_key: String,
    pub jti: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    jti: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedJwtId {
    jti: String,
}

/// Middleware function that enforces Bearer JWT authentication.
///
/// # Parameters
/// - `State(state)`: Extracted application state wrapped in an `Arc`.
/// - `req`: The incoming HTTP request of type `Request<Body>`.
/// - `next`: The next middleware or handler in the chain.
///
/// # Returns
/// - A `Response` object, either an error response or the result of the next handler.
///
/// # Behavior
/// 1. Extracts the `Authorization` header from the request.
/// 2. Validates the header format and ensures it contains a Bearer token.
/// 3. Decodes and validates the JWT using RS256 signature, audience, and expiration.
/// 4. Verifies the token's JTI against a cache to ensure it hasn't been revoked.
/// 5. Inserts an `AuthContext` into the request extensions for downstream handlers.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // 1) Extract Authorization header
    let unauthorized = |msg: &str| -> Response {
        AppError::new(ErrorType::UnauthorizedError, msg).into_response()
    };

    let auth_header_val = match req.headers().get(header::AUTHORIZATION) {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return unauthorized("Invalid Authorization header"),
        },
        None => return unauthorized("Missing Authorization header"),
    };

    let token = match auth_header_val.strip_prefix("Bearer ") {
        Some(t) if !t.is_empty() => t,
        _ => return unauthorized("Authorization header must be Bearer token"),
    };

    // 2) Decode and validate JWT
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["api"]);

    let token_data = match decode::<JwtClaims>(
        token,
        &DecodingKey::from_rsa_pem(state.jwt_public_key.expose_secret().as_bytes()).unwrap_or_else(
            |e| {
                error!("Failed to parse public key: {:?}", e);
                // Use an empty key to force decode failure
                DecodingKey::from_rsa_components("", "").unwrap()
            },
        ),
        &validation,
    ) {
        Ok(td) => td,
        Err(e) => {
            error!("JWT decode failed: {:?}", e);
            return unauthorized("Invalid token");
        }
    };

    // 3) Check token expiration
    if token_data.claims.exp < Utc::now().timestamp() {
        return unauthorized("Token has expired");
    }

    // 4) Verify JTI against cache
    match valkey_cache::get_object::<CachedJwtId>(State(state.clone()), &token_data.claims.sub)
        .await
    {
        Ok(Some(cached)) if cached.jti == token_data.claims.jti => {
            // ok
        }
        Ok(_) => return unauthorized("Token is not valid or has been revoked"),
        Err(e) => {
            error!("Error reading JTI from cache: {:?}", e);
            return AppError::new(
                ErrorType::InternalServerError,
                "Something went wrong. Please try again later.",
            )
            .into_response();
        }
    }

    // 5) Insert AuthContext for downstream handlers
    req.extensions_mut().insert(AuthContext {
        user_key: token_data.claims.sub,
        jti: token_data.claims.jti,
    });

    next.run(req).await
}
