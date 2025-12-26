use axum::http::{Method, StatusCode};
use axum_sqlx::api::model::user::StoredUser;
use axum_sqlx::db::repo::users_repository;
use bytes::Bytes;
use serde_json::{Value, json};

mod common {
    pub use crate::helpers::*;
}

// Helper function to convert axum response body to bytes
async fn hyper_body_to_bytes(body: axum::body::Body) -> Bytes {
    use axum::body::Body;
    use bytes::BytesMut;
    use http_body_util::BodyExt;

    let mut body = Body::from(body);
    let mut bytes = BytesMut::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
    }
    bytes.freeze()
}

#[tokio::test]
async fn test_create_user() {
    // Set up the test application
    let app = common::setup_test_app().await;

    // Get the app state for DB verification
    let app_state = common::setup_test_app_state().await;

    // Generate unique test email
    let test_email = common::get_test_email();

    // Create test user data
    let user_data = json!({
        "firstName": "Test",
        "lastName": "User",
        "email": test_email,
        "password": "SecurePassword123!"
    });

    // Make the request to create a user
    let response =
        common::make_request(app, Method::POST, "/users", Some(user_data.to_string())).await;

    // Check if the response has a 201 Created status
    assert_eq!(response.status(), StatusCode::CREATED);

    // Convert response to bytes
    let bytes = hyper_body_to_bytes(response.into_body()).await;

    // Parse the response body
    let response_json: Value = serde_json::from_slice(&bytes).unwrap();

    // Manually create a StoredUser from the response
    let response_user = StoredUser {
        key: response_json["key"].as_str().unwrap().to_string(),
        first_name: response_json["firstName"].as_str().map(|s| s.to_string()),
        last_name: response_json["lastName"].as_str().map(|s| s.to_string()),
        email: response_json["email"].as_str().unwrap().to_string(),
    };

    // Verify the user was created correctly
    assert_eq!(response_user.first_name.as_ref().unwrap(), "Test");
    assert_eq!(response_user.last_name.as_ref().unwrap(), "User");
    assert_eq!(response_user.email, test_email);

    // Verify the user exists in the database
    let db_user = users_repository::get_user_by_key(&app_state.pg_pool, &response_user.key)
        .await
        .expect("Failed to retrieve user from database");

    assert_eq!(db_user.email, test_email);
    assert_eq!(db_user.first_name.as_ref().unwrap(), "Test");
    assert_eq!(db_user.last_name.as_ref().unwrap(), "User");
}

#[tokio::test]
async fn test_create_user_validation_error() {
    // Set up the test application
    let app = common::setup_test_app().await;

    // Create invalid test user data with too short password
    let user_data = json!({
        "firstName": "Test",
        "lastName": "User",
        "email": "test@example.com",
        "password": "short"  // Password is too short according to validation rules
    });

    // Make the request to create a user
    let response =
        common::make_request(app, Method::POST, "/users", Some(user_data.to_string())).await;

    // Should return 422 Unprocessable Entity for validation error
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Convert response to bytes
    let bytes = hyper_body_to_bytes(response.into_body()).await;

    // Parse the response body
    let error_response: Value = serde_json::from_slice(&bytes).unwrap();

    // Verify we have the expected validation error message
    let message = error_response["message"].as_str().unwrap();
    assert!(message.contains("Request validation error"));

    // Verify the debug message contains information about validation
    let debug_message = error_response["debugMessage"].as_str().unwrap();
    assert!(debug_message.contains("Validation error"));

    // Verify sub-errors contain details about password length
    let sub_errors = &error_response["subErrors"];
    assert!(sub_errors.is_array());

    let sub_error = &sub_errors[0];
    assert_eq!(sub_error["field"].as_str().unwrap(), "password");
    assert!(
        sub_error["message"]
            .as_str()
            .unwrap()
            .contains("Password must be between")
    );
}
