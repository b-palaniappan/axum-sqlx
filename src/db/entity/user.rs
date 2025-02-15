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
    // ACTIVE - User account is active and can be used
    #[sqlx(rename = "ACTIVE")]
    Active,
    // INACTIVE - User account is inactive and cannot be used. This status is set when the user is banned or the account is disabled.
    #[sqlx(rename = "INACTIVE")]
    Inactive,
    // PENDING - User account is pending activation and cannot be used. This status is set when the user registers but has not yet validated their email.
    #[sqlx(rename = "PENDING")]
    Pending,
    // LOCKED - User account is locked and cannot be used. This status is set when the user has too many failed login attempts.
    #[sqlx(rename = "LOCKED")]
    Locked,
    // DELETED - User account is deleted and cannot be used. This status is set when the user deletes their account.
    #[sqlx(rename = "DELETED")]
    Deleted,
}
