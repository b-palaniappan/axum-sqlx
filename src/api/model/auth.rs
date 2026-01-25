use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    #[validate(length(
        min = 2,
        max = 50,
        message = "First name must be between 2 and 50 characters"
    ))]
    #[schema(example = "John")]
    pub first_name: Option<String>,
    #[validate(length(
        min = 2,
        max = 50,
        message = "Last name must be between 2 and 50 characters"
    ))]
    #[schema(example = "Doe")]
    pub last_name: String,
    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    pub password: String,
    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    #[validate(length(min = 1, message = "token cannot be empty"))]
    #[schema(
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )]
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    #[schema(
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )]
    pub access_token: String,
    #[schema(example = "Bearer")]
    pub token_type: String,
    #[schema(example = "3600")]
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    #[validate(length(
        min = 32,
        max = 32,
        message = "refreshToken must be 32 characters long"
    ))]
    #[schema(example = "Eyixd6RrJ2E8LF98Xv29j5AyYBYvTrof")]
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTokenResponse {
    #[schema(example = "7kGOGL3hsjTNVvJ5rMhRe")]
    pub user_key: String,
    #[schema(example = "true")]
    pub is_valid: bool,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    #[validate(length(min = 1, message = "userKey cannot be empty"))]
    #[schema(example = "xtP-MXaXpOFn168Fjz9v0")]
    pub user_key: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogoutResponse {
    #[schema(example = "Logout successful")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Must be a valid email address"))]
    #[schema(example = "user@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordResponse {
    #[schema(example = "Password reset email has been sent if the email address is registered.")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    #[validate(length(min = 32, message = "token cannot be empty"))]
    #[schema(example = "6f68e161f83b4e0a9be751950e45c8b2")]
    pub token: String,

    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    pub new_password: String,

    #[validate(length(
        min = 12,
        max = 255,
        message = "Confirm Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    pub confirm_password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordResponse {
    #[schema(example = "Password has been reset successfully.")]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationRequest {
    #[validate(length(
        min = 2,
        max = 50,
        message = "First name must be between 2 and 50 characters"
    ))]
    #[schema(example = "John")]
    pub first_name: String,

    #[validate(length(
        min = 2,
        max = 50,
        message = "Last name must be between 2 and 50 characters"
    ))]
    #[schema(example = "Doe")]
    pub last_name: String,

    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    pub email: String,

    #[serde(rename = "type")]
    #[schema(example = "passkey")]
    pub registration_type: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticationRequest {
    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    pub email: String,

    #[serde(rename = "type")]
    #[schema(example = "passkey")]
    pub login_type: String,
}
