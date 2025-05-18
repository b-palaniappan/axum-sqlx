use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Request to validate a TOTP code
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTotpRequest {
    #[validate(length(min = 8, max = 8, message = "TOTP code must be exactly 8 digits"))]
    #[schema(example = "48513675")]
    pub totp_code: String,
}

/// Response containing TOTP information
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpResponse {
    /// URL that can be used to manually configure TOTP app
    #[schema(
        example = "otpauth://totp/c12.io:bala4%40example.com?secret=MRZGUZ3SMFCHQUC2IJAVQV3SNRKTIYJZJNGDGU2HMJUWO2TFGBQXCRDCOZ5ES5BTIRRWG&digits=8&issuer=c12.io"
    )]
    pub totp_url: String,
    /// Base64-encoded QR code PNG image
    #[schema(example = "iVBORw0KGgoAAAANSUhEUgAAAcgAAAHICAAAAADvyiU2AAA...lFTkSuQmCC")]
    pub qr_code: String,
    /// QR Code image format
    #[schema(example = "image/png")]
    pub qr_type: String,
}

/// Response after validating a TOTP code
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTotpResponse {
    /// Whether the TOTP code is valid
    #[schema(example = "true")]
    pub is_valid: bool,
}

/// Response containing backup codes
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupCodesResponse {
    /// List of backup codes
    #[schema(example = "[\"VsZxKKAn\", \"2uNT7fJM\", \"hx5V2zaY\"]")]
    pub backup_codes: Vec<String>,
}

/// Request to validate a backup code
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateBackupCodeRequest {
    #[validate(length(max = 32, message = "backup code must be at most 32 characters"))]
    #[schema(example = "VsZxKKAn")]
    pub backup_code: String,
}

/// Response after validating a backup code
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateBackupCodeResponse {
    /// Whether the backup code is valid
    #[schema(example = "true")]
    pub is_valid: bool,
}

/// Response after deleting backup codes
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteBackupCodesResponse {
    /// The number of backup codes that were deleted
    #[schema(example = "10")]
    pub deleted_count: i64,
}

/// Response after deleting TOTP secret
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTotpResponse {
    /// Whether the TOTP secret was successfully deleted
    #[schema(example = "true")]
    pub success: bool,
    /// A message describing the result of the operation
    #[schema(example = "TOTP authentication disabled successfully")]
    pub message: String,
}
