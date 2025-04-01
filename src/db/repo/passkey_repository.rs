use sqlx::PgPool;
use crate::error::error_model::AppError;
use crate::error::error_model::ErrorType;

pub async fn create_passkey_user(
    pool: &PgPool,
    user_id: &str,
    first_name: &str,
    last_name: &str,
    email: &str,
) -> Result<i64, AppError> {
    let result = sqlx::query!(
        r#"
        INSERT INTO passkey_users (user_id, first_name, last_name, email)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        user_id,
        first_name,
        last_name,
        email
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Failed to create passkey user: {}", e),
        )
    })?;

    Ok(result.id)
}

pub async fn store_passkey_credential(
    pool: &PgPool,
    user_id: i64,
    credential_id: &[u8],
    public_key: &[u8],
    credential_type: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        r#"
        INSERT INTO passkey_credentials (user_id, credential_id, public_key, credential_type)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        credential_id,
        public_key,
        credential_type
    )
    .execute(pool)
    .await
    .map_err(|e| {
        AppError::new(
            ErrorType::InternalServerError,
            &format!("Failed to store passkey credential: {}", e),
        )
    })?;

    Ok(())
} 