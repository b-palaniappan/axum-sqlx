use serde_json::Value as JsonValue;
use sqlx::FromRow;
use sqlx::types::chrono::{DateTime, Utc};
use webauthn_rs::prelude::{CredentialID, Passkey};

/// Represents a passkey credential associated with a user.
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct PasskeyCredential {
    pub id: i64,
    pub user_id: i64,
    pub passkey_credential: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

impl PasskeyCredential {
    /// Converts the `passkey_credential` field of the `PasskeyCredential` struct
    /// into a `Passkey` object.
    ///
    /// # Returns
    ///
    /// * `Ok(Passkey)` - If the conversion from JSON to `Passkey` is successful.
    /// * `Err(serde_json::Error)` - If the conversion fails due to invalid JSON.
    pub fn to_passkey(&self) -> Result<Passkey, serde_json::Error> {
        serde_json::from_value(self.passkey_credential.clone())
    }

    /// Retrieves the `CredentialID` from the `PasskeyCredential` struct.
    ///
    /// This method attempts to convert the `passkey_credential` field into a `Passkey`
    /// and then extracts the `CredentialID` from it.
    ///
    /// # Returns
    ///
    /// * `Some(CredentialID)` - If the conversion to `Passkey` is successful and the
    ///   `CredentialID` is available.
    /// * `None` - If the conversion fails or the `CredentialID` is not present.
    pub fn get_credential_id(&self) -> Option<CredentialID> {
        self.to_passkey().ok().map(|pk| pk.cred_id().clone())
    }
}
