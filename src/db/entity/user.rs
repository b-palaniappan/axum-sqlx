use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{FromRow, Type};

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct Users {
    pub id: i64,
    pub key: String,
    pub first_name: Option<String>,
    pub last_name: String,
    pub email: String,
    pub password_hash: String,
    pub password_hmac: Vec<u8>,
    pub email_verified: Option<bool>,
    pub update_password: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub account_status: AccountStatus,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_login_attempts: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq, Eq, Type)]
#[sqlx(type_name = "account_status", rename_all = "lowercase")]
pub enum AccountStatus {
    #[sqlx(rename = "ACTIVE")]
    Active,
    #[sqlx(rename = "INACTIVE")]
    Inactive,
    #[sqlx(rename = "PENDING")]
    Pending,
    #[sqlx(rename = "LOCKED")]
    Locked,
    #[sqlx(rename = "DELETED")]
    Deleted,
}
