use super::*;
use axum::http::Method;

#[tokio::test]
async fn test_auth_middleware_rejects_invalid_token() {
    let app = test_app().await;
    
    let (status, _) = make_request(
        app,
        Method::GET,
        "/protected",
        None,
        Some(vec![("Authorization".to_string(), "Bearer invalid-token".to_string())]),
    ).await;
    
    // Should redirect to login or return unauthorized
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FOUND);
}

#[tokio::test]
async fn test_auth_middleware_accepts_valid_token() {
    let app = test_app().await;
    
    // Create a valid token for testing
    let token = create_test_token();
    
    let (status, _) = make_request(
        app,
        Method::GET,
        "/protected",
        None,
        Some(vec![("Authorization".to_string(), format!("Bearer {}", token))]),
    ).await;
    
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_session_middleware_creates_session() {
    let app = test_app().await;
    
    let (status, headers) = make_request_with_response_headers(
        app,
        Method::GET,
        "/login",
        None,
        None,
    ).await;
    
    assert_eq!(status, StatusCode::OK);
    
    // Check that a session cookie was set
    let has_session_cookie = headers.iter()
        .any(|(name, value)| name.to_lowercase() == "set-cookie" && value.contains("session="));
    
    assert!(has_session_cookie);
}

#[tokio::test]
async fn test_error_handling_middleware_redirects_to_login() {
    let app = test_app().await;
    
    // Make a request that will trigger an unauthorized error with the specific header
    let (status, _) = make_request(
        app,
        Method::GET,
        "/protected",
        None,
        Some(vec![
            ("Authorization".to_string(), "Bearer invalid-token".to_string()),
            ("X-Introspection-Error".to_string(), "unauthorized".to_string()),
        ]),
    ).await;
    
    // Should redirect to login
    assert_eq!(status, StatusCode::FOUND);
}

#[tokio::test]
async fn test_cors_middleware() {
    let app = test_app().await;
    
    let (_, headers) = make_request_with_response_headers(
        app,
        Method::GET,
        "/public",
        None,
        Some(vec![("Origin".to_string(), "http://example.com".to_string())]),
    ).await;
    
    // Check that CORS headers were set
    let has_cors_headers = headers.iter()
        .any(|(name, _)| name.to_lowercase() == "access-control-allow-origin");
    
    assert!(has_cors_headers);
}