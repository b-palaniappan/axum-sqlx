use crate::db::entity::passkey::PasskeyCredential;
use crate::error::error_model::{AppError, ErrorType};
use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use tracing::{error, info};
use webauthn_rs::prelude::Passkey;

/// Retrieves all passkey credentials associated with a user ID
pub async fn get_passkey_credentials_by_user_id(
    pool: &Pool<Postgres>,
    user_id: &i64,
) -> Result<Vec<PasskeyCredential>, AppError> {
    let passkey_credentials = sqlx::query_as!(
        PasskeyCredential,
        r#"
        SELECT
            id,
            user_id,
            passkey_credential as "passkey_credential: JsonValue",
            created_at,
            updated_at,
            deleted_at
        FROM passkey_credentials
        WHERE user_id = $1 and deleted_at IS NULL
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("Error fetching passkey credentials: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to retrieve passkey credentials.",
        )
    })?;

    info!(
        "Retrieved {} passkey credentials for user {}",
        passkey_credentials.len(),
        user_id
    );
    Ok(passkey_credentials)
}

pub async fn create_passkey_credential(
    pool: &Pool<Postgres>,
    user_id: &i64,
    passkey_credential: &Passkey,
) -> Result<PasskeyCredential, AppError> {
    // Convert the passkey credential to a JSON value first
    let json_value = serde_json::to_value(passkey_credential).map_err(|e| {
        error!("Error serializing passkey credential: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to serialize passkey credential.",
        )
    })?;

    // Use sqlx::json to properly handle jsonb type in PostgreSQL
    let passkey_credential_entity = sqlx::query_as!(
        PasskeyCredential,
        r#"
        INSERT INTO passkey_credentials (user_id, passkey_credential)
        VALUES ($1, $2)
        RETURNING id, user_id, passkey_credential as "passkey_credential: JsonValue", created_at, updated_at, deleted_at
        "#,
        user_id,
        json_value,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Error creating passkey credential: {:?}", e);
        AppError::new(
            ErrorType::InternalServerError,
            "Failed to create passkey credential.",
        )
    })?;

    info!("Created new passkey credential for user {}", user_id);
    Ok(passkey_credential_entity)
}
