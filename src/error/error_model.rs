use derive_more::Display;
use serde::Serialize;
use utoipa::ToSchema;
use validator::ValidationErrors;

// New error data type.
// #[derive(ToSchema)]
// TODO: Getting error for ToSchema for ValidationErrors from validator.
pub struct AppError {
    pub error_type: ErrorType,
    pub error_message: String,
}

#[derive(Debug, Display, derive_more::Error, Clone)]
pub enum ErrorType {
    #[display("Not found")]
    NotFound,
    #[display("Bad request")]
    BadRequest,
    #[display("Internal server error")]
    InternalServerError,
    #[display("Authentication error")]
    UnauthorizedError,
    #[display("Request validation error")]
    RequestValidationError {
        validation_error: ValidationErrors,
        object: String,
    },
}

impl AppError {
    // constructor.
    pub fn new(error_type: ErrorType, message: impl Into<String>) -> Self {
        Self {
            error_type,
            error_message: message.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    #[schema(example = "500")]
    pub status: u16,
    #[schema(example = "2024-01-01T12:00:00.000Z")]
    pub time: String,
    #[schema(example = "Internal server error")]
    pub message: String,
    #[serde(rename = "debugMessage")]
    #[schema(example = "Internal server error. Try after some time")]
    pub debug_message: Option<String>,
    #[serde(rename = "subErrors")]
    pub sub_errors: Vec<ValidationError>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationError {
    #[schema(example = "Users")]
    pub object: String,
    #[schema(example = "email")]
    pub field: String,
    #[schema(example = "notAValidEmail")]
    pub rejected_value: String,
    #[schema(example = "Invalid email address")]
    pub message: String,
    #[schema(example = "email.invalid")]
    pub code: String,
}
