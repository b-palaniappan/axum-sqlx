use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::api::model::user::UserRequest;
use crate::config::app_config::AppState;
use crate::error::error_model::{AppError, ErrorType};
use crate::grpc::user_v1::user_registration_service_server::UserRegistrationService;
use crate::grpc::user_v1::{RegisterUserRequest, RegisterUserResponse};
use crate::service::user_service;

pub struct UserRegistrationGrpcController {
    state: Arc<AppState>,
}

impl UserRegistrationGrpcController {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl UserRegistrationService for UserRegistrationGrpcController {
    async fn register_user(
        &self,
        request: Request<RegisterUserRequest>,
    ) -> Result<Response<RegisterUserResponse>, Status> {
        let payload = request.into_inner();
        let user_request = UserRequest {
            first_name: normalize_optional(payload.first_name),
            last_name: normalize_optional(payload.last_name),
            email: payload.email,
            password: payload.password,
        };

        let created_user = user_service::create_user_record(self.state.clone(), user_request)
            .await
            .map_err(map_app_error_to_grpc_status)?;

        Ok(Response::new(RegisterUserResponse {
            key: created_user.key,
            first_name: created_user.first_name.unwrap_or_default(),
            last_name: created_user.last_name.unwrap_or_default(),
            email: created_user.email,
        }))
    }
}

fn normalize_optional(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn map_app_error_to_grpc_status(err: AppError) -> Status {
    let message = err.error_message;
    match err.error_type {
        ErrorType::RequestValidationError { .. } | ErrorType::BadRequest => {
            Status::invalid_argument(message)
        }
        ErrorType::UnauthorizedError => Status::unauthenticated(message),
        ErrorType::NotFound => Status::not_found(message),
        ErrorType::InternalServerError => Status::internal(message),
    }
}
