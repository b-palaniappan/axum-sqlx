use crate::config::app_config::AppState;
use crate::error::error_model::AppError;
use crate::service::mfa_service;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use nanoid::nanoid;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::info;

pub fn totp_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/generate", post(totp_generate))
        .route("/register/{user_key}", post(totp_register))
}

pub async fn totp_generate(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        8,
        1,
        30,
        Secret::Raw(nanoid!(32).as_bytes().to_vec())
            .to_bytes()
            .unwrap(),
        Some("c12.io".to_string()),
        "bala@c12.io".to_string(),
    )
    .unwrap();
    info!("Token - {}", totp.generate_current().unwrap());
    info!("Token TTL - {}", totp.ttl().unwrap());
    info!("totp url - {}", totp.get_url());
    info!("Base64 png QR code - {}", totp.get_qr_base64().unwrap());
    info!("Check current - {}", totp.check_current("123456").unwrap());
    Ok("TOTP generated")
}

pub async fn totp_register(
    State(state): State<Arc<AppState>>,
    Path(user_key): Path<String>,
) -> Result<Response, AppError> {
    mfa_service::register_totp(State(state), &user_key).await
}
