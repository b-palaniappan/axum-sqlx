use crate::db::entity::user_login_credentials::UserLoginCredentials;
use sqlx::Error;
use sqlx::PgPool;

pub async fn create_user_login_credentials(
    pg_pool: &PgPool,
    user_id: i64,
    password_hash: &str,
    password_hmac: &[u8],
) -> Result<UserLoginCredentials, Error> {
    sqlx::query_as!(
        UserLoginCredentials,
        r#"
        INSERT INTO user_login_credentials (user_id, password_hash, password_hmac)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, password_hash, password_hmac, update_password, two_factor_enabled, created_at, deleted_at
        "#,
        user_id,
        password_hash,
        password_hmac
    )
        .fetch_one(pg_pool)
        .await
}

pub async fn get_user_login_credentials_by_user_id(
    pg_pool: &PgPool,
    user_id: &i64,
) -> Result<Option<UserLoginCredentials>, Error> {
    sqlx::query_as!(
        UserLoginCredentials,
        r#"
        SELECT id, user_id, password_hash, password_hmac, update_password, two_factor_enabled, created_at, deleted_at
        FROM user_login_credentials
        WHERE user_id = $1 AND deleted_at IS NULL
        "#,
        user_id
    )
    .fetch_optional(pg_pool)
    .await
}
