use sqlx::types::chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct PasskeyUsers {
    pub id: i64,
    pub user_id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub email_verified: bool,
    pub active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_login_attempts: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct PasskeyCredential {
    pub id: i64,
    pub user_id: i64,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: i32,
    pub credential_type: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
