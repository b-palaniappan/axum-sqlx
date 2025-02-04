use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

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
    #[schema(example = "Eyixd6RrJ2E8LF98Xv29j5AyYBYvTrof")]
    pub refresh_token: String,
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
