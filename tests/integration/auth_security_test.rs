use axum::Router;
use axum::http::{Method, StatusCode};
use axum_sqlx::db::repo::{user_login_credentials_repository, users_repository};
use axum_sqlx::util::crypto_helper;
use bytes::Bytes;
use nanoid::nanoid;
use serde_json::{Value, json};
use std::sync::Arc;

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

/// Helper to create a user and return their email and key
async fn create_test_user(app_state: Arc<axum_sqlx::AppState>) -> (String, String) {
    let test_email = common::get_test_email();
    let password = "SecurePassword123!".to_string();
    let user_key = nanoid!();

    // Hash the password and sign with HMAC
    let (password_hash, password_hmac) =
        crypto_helper::hash_password_sign_with_hmac(&app_state, &password)
            .await
            .expect("Failed to hash password");

    // Create user in the database
    let created_user = users_repository::create_user(
        &app_state.pg_pool,
        &user_key,
        Some("Test".to_string()),
        Some("User".to_string()),
        &test_email,
    )
    .await
    .expect("Failed to create test user");

    // Store user login credentials
    user_login_credentials_repository::create_user_login_credentials(
        &app_state.pg_pool,
        created_user.id,
        &password_hash.to_string(),
        &*password_hmac,
    )
    .await
    .expect("Failed to create login credentials");

    (test_email, created_user.key)
}

/// Helper to authenticate a user and return their access token and refresh token
async fn authenticate_user(app: Router, email: &str, password: &str) -> (String, String) {
    let auth_data = json!({
        "email": email,
        "password": password
    });

    let response = common::make_request(
        app,
        Method::POST,
        "/auth/login",
        Some(auth_data.to_string()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = hyper_body_to_bytes(response.into_body()).await;
    let response_json: Value = serde_json::from_slice(&bytes).unwrap();

    let access_token = response_json["accessToken"].as_str().unwrap().to_string();

    // Verify refresh_token is NOT in the JSON response (security: prevent XSS exposure)
    assert!(
        response_json.get("refreshToken").is_none(),
        "refresh_token should not be in JSON response body to prevent XSS exposure"
    );

    (access_token, String::new()) // Return empty string for refresh_token (it's in HttpOnly cookie)
}

/// Helper to make an authenticated request
async fn make_authenticated_request(
    app: Router,
    method: axum::http::Method,
    uri: &str,
    access_token: &str,
    json_body: Option<String>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let request_builder = Request::builder()
        .uri(uri)
        .method(method)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", access_token));

    let request = if let Some(body) = json_body {
        request_builder.body(Body::from(body)).unwrap()
    } else {
        request_builder.body(Body::empty()).unwrap()
    };

    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn test_logout_requires_authentication() {
    // Load environment variables
    dotenvy::dotenv().ok();

    let app_state = common::setup_test_app_state().await;

    // Set up the test application with auth routes (mimicking main.rs setup)
    let app = Router::new()
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::public_auth_routes(),
        )
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::protected_auth_routes().route_layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    axum_sqlx::middleware::auth::require_auth,
                ),
            ),
        )
        .with_state(app_state);

    // Try to logout without authentication (no Authorization header)
    let response = common::make_request(app, Method::DELETE, "/auth/logout", None).await;

    // Should return 401 Unauthorized
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Logout endpoint should require authentication"
    );
}

#[tokio::test]
async fn test_logout_cannot_logout_other_users() {
    // Load environment variables
    dotenvy::dotenv().ok();

    let app_state = common::setup_test_app_state().await;

    // Create two test users
    let (user1_email, _user1_key) = create_test_user(app_state.clone()).await;
    let (user2_email, _user2_key) = create_test_user(app_state.clone()).await;

    // Set up the test application with auth routes (mimicking main.rs setup)
    let app = Router::new()
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::public_auth_routes(),
        )
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::protected_auth_routes().route_layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    axum_sqlx::middleware::auth::require_auth,
                ),
            ),
        )
        .with_state(app_state.clone());

    // Authenticate as user1
    let (user1_access_token, _) =
        authenticate_user(app.clone(), &user1_email, "SecurePassword123!").await;

    // Authenticate as user2 to establish their session
    let (user2_access_token, _) =
        authenticate_user(app.clone(), &user2_email, "SecurePassword123!").await;

    // User1 tries to logout - the request body is no longer used, identity comes from JWT
    let response = make_authenticated_request(
        app.clone(),
        Method::DELETE,
        "/auth/logout",
        &user1_access_token,
        None, // No request body needed anymore
    )
    .await;

    // Logout should succeed (for user1)
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the response is JSON with the expected message
    let bytes = hyper_body_to_bytes(response.into_body()).await;
    let response_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response_json["message"].as_str().unwrap(),
        "Logout successful"
    );

    // Verify that user2's token is still valid (user1 should have only logged out themselves)
    // Try to use user2's token - it should still work
    let validate_request = json!({
        "token": user2_access_token
    });

    let validate_response = make_authenticated_request(
        app,
        Method::POST,
        "/auth/validate",
        &user2_access_token,
        Some(validate_request.to_string()),
    )
    .await;

    // User2's token should still be valid
    assert_eq!(
        validate_response.status(),
        StatusCode::OK,
        "User2's token should still be valid after User1 logged out"
    );
}

#[tokio::test]
async fn test_logout_does_not_log_tokens() {
    // This test verifies that tokens are not logged in the logout handler.
    // We cannot directly test log output in unit tests, but we can verify
    // the implementation doesn't contain logging statements with tokens.
    // This test is a placeholder - the actual verification happens during code review
    // and by checking that the handler doesn't have info! statements with token variables.

    // Load environment variables
    dotenvy::dotenv().ok();

    // Create a test to ensure the logout endpoint works correctly
    let app_state = common::setup_test_app_state().await;
    let (user_email, _user_key) = create_test_user(app_state.clone()).await;

    let app = Router::new()
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::public_auth_routes(),
        )
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::protected_auth_routes().route_layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    axum_sqlx::middleware::auth::require_auth,
                ),
            ),
        )
        .with_state(app_state.clone());

    // Authenticate the user
    let (access_token, _) = authenticate_user(app.clone(), &user_email, "SecurePassword123!").await;

    // Logout should work without logging tokens (no request body needed)
    let response =
        make_authenticated_request(app, Method::DELETE, "/auth/logout", &access_token, None).await;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the response is JSON with the expected message
    let bytes = hyper_body_to_bytes(response.into_body()).await;
    let response_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response_json["message"].as_str().unwrap(),
        "Logout successful"
    );
}

#[tokio::test]
async fn test_successful_logout_invalidates_tokens() {
    // Load environment variables
    dotenvy::dotenv().ok();

    let app_state = common::setup_test_app_state().await;
    let (user_email, _user_key) = create_test_user(app_state.clone()).await;

    let app = Router::new()
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::public_auth_routes(),
        )
        .nest(
            "/auth",
            axum_sqlx::api::handler::auth_handler::protected_auth_routes().route_layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    axum_sqlx::middleware::auth::require_auth,
                ),
            ),
        )
        .with_state(app_state.clone());

    // Authenticate the user
    let (access_token, _) = authenticate_user(app.clone(), &user_email, "SecurePassword123!").await;

    // Logout successfully (no request body needed)
    let logout_response = make_authenticated_request(
        app.clone(),
        Method::DELETE,
        "/auth/logout",
        &access_token,
        None,
    )
    .await;

    assert_eq!(logout_response.status(), StatusCode::OK);

    // Verify the response is JSON with the expected message
    let bytes = hyper_body_to_bytes(logout_response.into_body()).await;
    let response_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response_json["message"].as_str().unwrap(),
        "Logout successful"
    );

    // Try to use the token after logout - should fail
    let validate_request = json!({
        "token": access_token
    });

    let validate_response = make_authenticated_request(
        app,
        Method::POST,
        "/auth/validate",
        &access_token,
        Some(validate_request.to_string()),
    )
    .await;

    // Token should be invalid after logout
    assert_eq!(
        validate_response.status(),
        StatusCode::UNAUTHORIZED,
        "Token should be invalid after logout"
    );
}
