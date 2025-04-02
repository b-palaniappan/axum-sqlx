use crate::db::entity::passkey::PasskeyUsers;
use sqlx::PgPool;

pub async fn save_passkey_user(
    pg_pool: &PgPool,
    user: PasskeyUsers,
) -> Result<PasskeyUsers, sqlx::Error> {
    sqlx::query_as!(
        PasskeyUsers,
        r#"
        INSERT INTO passkey_users (user_id, first_name, last_name, email, email_verified, active, last_login, failed_login_attempts, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, user_id, first_name, last_name, email, email_verified, active, last_login, failed_login_attempts, created_at, updated_at, deleted_at
        "#,
        user.user_id,
        user.first_name,
        user.last_name,
        user.email,
        user.email_verified,
        user.active,
        user.last_login,
        user.failed_login_attempts,
        user.created_at,
        user.updated_at
    ).fetch_one(pg_pool)
        .await
}
