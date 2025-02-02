use crate::db::entity::user::Users;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserRequest {
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
pub struct UserAuthRequest {
    #[validate(email(message = "Invalid email address"))]
    #[schema(example = "me@example.com")]
    pub email: String,

    #[validate(length(
        min = 12,
        max = 255,
        message = "Password must be between 12 and 255 characters"
    ))]
    #[schema(example = "SecretPassword123!")]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[schema(example = "John")]
    pub first_name: Option<String>,
    #[schema(example = "Doe")]
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredUser {
    #[schema(example = "kfERHUaNceaE9i9FrbnNH")]
    pub key: String,
    #[schema(example = "John")]
    pub first_name: Option<String>,
    #[schema(example = "Doe")]
    pub last_name: String,
    #[schema(example = "me@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserAuthResponse {
    #[schema(
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )]
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredUsers {
    pub users: Vec<StoredUser>,
    #[schema(example = 1)]
    pub current_page: i64,
    #[schema(example = 120)]
    pub total_items: i64,
    #[schema(example = 6)]
    pub total_pages: i64,
    #[schema(example = 20)]
    pub items_per_page: i64,
    #[schema(example = 20)]
    pub items_in_page: i64,
}

impl From<Users> for StoredUser {
    fn from(user: Users) -> Self {
        StoredUser {
            key: user.key,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Message {
    #[schema(example = "Hello")]
    /// Message to display
    pub message: String,
    #[schema(example = "Success")]
    /// Status of the message
    pub status: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationQuery {
    /// current page of the pagination
    #[param(default = 1, example = 1)]
    pub page: i64,
    /// number of items per page
    #[param(default = 20, example = 20, required)]
    pub size: i64,
}
