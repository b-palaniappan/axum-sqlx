use crate::db::entity::passkey::PasskeyCredential;
use crate::error::error_model::{AppError, ErrorType};
use sqlx::{Pool, Postgres};
use tracing::{error, info};

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
            credential_id,
            public_key,
            counter,
            credential_type,
            created_at,
            deleted_at
        FROM passkey_credentials
        WHERE user_id = $1 and deleted_at IS NULL
        "#,
        user_id
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
