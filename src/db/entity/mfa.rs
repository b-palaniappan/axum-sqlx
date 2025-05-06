use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::JsonValue;
use sqlx::FromRow;

/// Represents totp credentials associated with a user Multi-factor authentication (MFA).
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct UserMfaTotp {
    pub id: i64,
    pub user_id: i64,
    pub totp_secret: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Represents the TOTP secret which will be stored in the JSON format.
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSecret {
    pub encrypted_secret: String,
    pub nonce: String,
}

impl UserMfaTotp {
    /// Converts the `totp_secret` field of the `UseMfaTotp` struct
    /// into a `TotpSecret` object.
    ///
    /// # Returns
    ///
    /// * `Ok(TotpSecret)` - If the conversion from JSON to `TotpSecret` is successful.
    /// * `Err(serde_json::Error)` - If the conversion fails due to invalid JSON.
    pub fn to_totp_secret(&self) -> Result<TotpSecret, serde_json::Error> {
        serde_json::from_value(self.totp_secret.clone())
    }
}

/// Represents the Backup codes in case of MFA failure.
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct UserMfaBackupCodes {
    pub id: i64,
    pub user_id: i64,
    pub backup_code_hash: String,
    pub backup_code_hmac: Vec<u8>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Represents a single backup code with its hash and HMAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCode {
    pub hash: String,
    pub hmac: Vec<u8>,
}

/// Represents a collection of backup codes for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCodes {
    pub codes: Vec<BackupCode>,
}
