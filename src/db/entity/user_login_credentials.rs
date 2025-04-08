use sqlx::types::chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct UserLoginCredentials {
    pub id: i64,
    pub user_id: i64,
    pub password_hash: String,
    pub password_hmac: Vec<u8>,
    pub update_password: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
