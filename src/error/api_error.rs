use crate::error::error_model::{ApiError, AppError, ErrorType, ValidationError};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::types::chrono::Utc;
use tracing::info;

// New type of error handling.
impl IntoResponse for AppError {
    // implementation for the trait.
    fn into_response(self) -> Response {
        let (status, message, debug_message, sub_errors) = match self.error_type.clone() {
            ErrorType::NotFound => (
                StatusCode::NOT_FOUND,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::BadRequest => (
                StatusCode::BAD_REQUEST,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::UnauthorizedError => (
                StatusCode::UNAUTHORIZED,
                self.error_type.to_string(),
                Some(self.error_message),
                vec![],
            ),
            ErrorType::RequestValidationError {
                validation_error,
                object,
            } => {
                let mut validation_sub_errs = Vec::new();
                for (field, field_errors) in validation_error.field_errors() {
                    for field_error in field_errors {
                        info!("Validation error on field: {:?}", field_error);
                        validation_sub_errs.push(ValidationError {
                            object: object.to_string(),
                            field: field.to_string(),
                            rejected_value: field_error
                                .params
                                .get("value")
                                .unwrap_or(&"".into())
                                .to_string(),
                            message: field_error
                                .message
                                .as_ref()
                                .unwrap_or(&"".into())
                                .to_string(),
                            code: field_error.code.to_string(),
                        })
                    }
                }
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    self.error_type.to_string(),
                    Some(self.error_message),
                    validation_sub_errs,
                )
            }
        };
        let api_error = ApiError {
            status: status.into(),
            time: Utc::now().to_rfc3339(),
            message,
            debug_message,
            sub_errors,
        };

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&api_error).unwrap_or("".to_string()),
            ))
            .unwrap_or(Response::new(axum::body::Body::empty()))
    }
}
