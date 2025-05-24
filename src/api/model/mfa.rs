use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
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

/// Request to register Email MFA
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailMfaRegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Response after requesting Email MFA registration
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailMfaRegisterResponse {
    /// Whether verification code was sent successfully
    #[schema(example = "true")]
    pub success: bool,
    /// A message describing the result of the operation
    #[schema(example = "Verification code sent to email. Valid for 15 minutes.")]
    pub message: String,
    /// Whether the provided email is already registered for MFA
    #[schema(example = "false")]
    pub already_registered: bool,
}

/// Request to verify Email MFA registration
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailMfaVerifyRequest {
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,

    #[validate(length(
        min = 6,
        max = 6,
        message = "Verification code must be exactly 6 digits"
    ))]
    #[schema(example = "123456")]
    pub verification_code: String,
}

/// Response after verifying Email MFA registration
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailMfaVerifyResponse {
    /// Whether the verification was successful
    #[schema(example = "true")]
    pub success: bool,
    /// A message describing the result of the operation
    #[schema(example = "Email successfully verified and registered for MFA")]
    pub message: String,
}

/// Request to register SMS MFA
static PHONE_NUMBER_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\+?[0-9]+$").unwrap());

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SmsMfaRegisterRequest {
    #[validate(
        length(min = 10, max = 15, message = "Phone number must be between 10 and 15 digits"),
        regex(path = *PHONE_NUMBER_REGEX, message = "Phone number must contain only digits and optionally start with +")
    )]
    #[schema(example = "+14155552671")]
    pub phone_number: String,
}

/// Response after requesting SMS MFA registration
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SmsMfaRegisterResponse {
    /// Whether verification code was sent successfully
    #[schema(example = "true")]
    pub success: bool,
    /// A message describing the result of the operation
    #[schema(example = "Verification code sent via SMS. Valid for 15 minutes.")]
    pub message: String,
    /// Whether the provided phone number is already registered for MFA
    #[schema(example = "false")]
    pub already_registered: bool,
}

/// Request to verify SMS MFA registration
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SmsMfaVerifyRequest {
    #[validate(
        length(min = 10, max = 15, message = "Phone number must be between 10 and 15 digits"),
        regex(path = *PHONE_NUMBER_REGEX, message = "Phone number must contain only digits and optionally start with +")
    )]
    #[schema(example = "+14155552671")]
    pub phone_number: String,

    #[validate(length(
        min = 6,
        max = 6,
        message = "Verification code must be exactly 6 digits"
    ))]
    #[schema(example = "123456")]
    pub verification_code: String,
}

/// Response after verifying SMS MFA registration
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SmsMfaVerifyResponse {
    /// Whether the verification was successful
    #[schema(example = "true")]
    pub success: bool,
    /// A message describing the result of the operation
    #[schema(example = "Phone number successfully verified and registered for MFA")]
    pub message: String,
}

/// Request to validate MFA during login
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateMfaRequest {
    #[validate(length(min = 6, max = 8, message = "MFA code must be between 6 and 8 digits"))]
    #[schema(example = "123456")]
    pub code: String,

    #[schema(example = "EMAIL")]
    pub method: String,
}

/// Response after validating MFA during login
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateMfaResponse {
    /// Whether the MFA code is valid
    #[schema(example = "true")]
    pub is_valid: bool,
}
