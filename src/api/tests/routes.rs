use super::*;
use axum::http::Method;

#[tokio::test]
async fn test_public_route_accessible() {
    let app = test_app().await;
    
    let (status, body) = make_request(
        app,
        Method::GET,
        "/public",
        None,
        None,
    ).await;
    
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "public route");
}

#[tokio::test]
async fn test_protected_route_requires_auth() {
    let app = test_app().await;
    
    let (status, _) = make_request(
        app,
        Method::GET,
        "/protected",
        None,
        None,
    ).await;
    
    // Should redirect to login or return unauthorized
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FOUND);
}

#[tokio::test]
async fn test_protected_route_with_valid_token() {
    let app = test_app().await;
    
    // Create a valid token for testing
    let token = create_test_token();
    
    let (status, body) = make_request(
        app,
        Method::GET,
        "/protected",
        None,
        Some(vec![("Authorization".to_string(), format!("Bearer {}", token))]),
    ).await;
    
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "protected route");
}

#[tokio::test]
async fn test_login_page_accessible() {
    let app = test_app().await;
    
    let (status, _) = make_request(
        app,
        Method::GET,
        "/login",
        None,
        None,
    ).await;
    
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_whoami_endpoint() {
    let app = test_app().await;
    
    // Create a valid token for testing
    let token = create_test_token();
    
    let (status, body) = make_request(
        app,
        Method::GET,
        "/api/whoami",
        None,
        Some(vec![("Authorization".to_string(), format!("Bearer {}", token))]),
    ).await;
    
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "test user");
}