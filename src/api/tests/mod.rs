use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;

// Import your API router
use crate::api::router;

// Helper function to create a test app
async fn test_app() -> Router {
    // Create a test configuration
    let config = TestConfig::default();
    
    // Create the router with test configuration
    router::create_router(config).await
}

// Helper function to make a test request
async fn make_request(
    app: Router,
    method: http::Method,
    uri: &str,
    body: Option<String>,
    headers: Option<Vec<(String, String)>>,
) -> (StatusCode, String) {
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri);
    
    // Add headers if provided
    if let Some(headers) = headers {
        for (name, value) in headers {
            req_builder = req_builder.header(name, value);
        }
    }
    
    // Add body if provided
    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };
    
    let req = req_builder.body(Body::from(body)).unwrap();
    
    // Process the request
    let response = app.oneshot(req).await.unwrap();
    
    // Extract status code
    let status = response.status();
    
    // Extract body
    let body = hyper::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    
    (status, body)
}

// Helper function to make a request and return headers
async fn make_request_with_response_headers(
    app: Router,
    method: http::Method,
    uri: &str,
    body: Option<String>,
    headers: Option<Vec<(String, String)>>,
) -> (StatusCode, Vec<(String, String)>) {
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri);
    
    // Add headers if provided
    if let Some(headers) = headers {
        for (name, value) in headers {
            req_builder = req_builder.header(name, value);
        }
    }
    
    // Add body if provided
    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };
    
    let req = req_builder.body(Body::from(body)).unwrap();
    
    // Process the request
    let response = app.oneshot(req).await.unwrap();
    
    // Extract status code
    let status = response.status();
    
    // Extract headers
    let headers = response.headers().iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();
    
    (status, headers)
}

// Helper function to create a test token
fn create_test_token() -> String {
    // In a real implementation, this would create a valid JWT token
    // For testing purposes, we can use a placeholder
    "test-token".to_string()
}

// Helper struct for test configuration
#[derive(Clone)]
struct TestConfig {
    // Add fields as needed for your tests
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            // Initialize with default values
        }
    }
}

// Export the test modules
pub mod routes;
pub mod middleware;