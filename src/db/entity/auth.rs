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
    // ACTIVE - Token is valid and can be used
    #[sqlx(rename = "ACTIVE")]
    Active,
    // INACTIVE - Token is no longer valid and cannot be used. This status is set when the user logs out.
    #[sqlx(rename = "INACTIVE")]
    Inactive,
    // REVOKED - Token is no longer valid and cannot be used. This status is set when the user changes their password or the token is compromised or new token is issued.
    #[sqlx(rename = "REVOKED")]
    Revoked,
    // EXPIRED - Token is no longer valid and cannot be used. This status is set when the token expires.
    #[sqlx(rename = "EXPIRED")]
    Expired,
}
