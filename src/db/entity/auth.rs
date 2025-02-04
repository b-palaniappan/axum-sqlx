use sqlx::types::chrono::{DateTime, Utc};
use sqlx::{FromRow, Type};

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct RefreshTokens {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub status: RefreshTokenStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: DateTime<Utc>,
    pub is_valid: bool,
}

#[derive(Debug, PartialEq, Eq, Type)]
#[sqlx(type_name = "refresh_token_status", rename_all = "lowercase")]
pub enum RefreshTokenStatus {
    #[sqlx(rename = "ACTIVE")]
    Active,
    #[sqlx(rename = "INACTIVE")]
    Inactive,
    #[sqlx(rename = "REVOKED")]
    Revoked,
    #[sqlx(rename = "EXPIRED")]
    Expired,
}
