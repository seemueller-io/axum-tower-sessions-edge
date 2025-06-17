use crate::api::authenticated::AuthenticatedApi;
use crate::api::public::PublicApi;
use crate::axum_introspector::introspection::{IntrospectionState, IntrospectionStateBuilder};
use crate::oidc::introspection::cache::in_memory::InMemoryIntrospectionCache;
use crate::session_storage::in_memory::MemoryStore;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{any, get};
use axum::{Router, ServiceExt};
use http::HeaderName;
use std::iter::once;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_sessions::cookie::{Key, SameSite};
use tower_sessions::SessionManagerLayer;
use tower_sessions_core::Expiry;

// Test configuration struct
#[derive(Clone)]
pub struct TestConfig {
    pub auth_server_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub app_url: String,
    pub dev_mode: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            auth_server_url: "https://test-auth-server.example.com".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            app_url: "http://localhost:3000".to_string(),
            dev_mode: true,
        }
    }
}

// App state for testing
#[derive(Clone)]
pub struct TestAppState {
    pub introspection_state: IntrospectionState,
    pub session_store: MemoryStore,
}

impl From<TestAppState> for IntrospectionState {
    fn from(state: TestAppState) -> Self {
        state.introspection_state
    }
}

// Create a router for testing
pub async fn create_router(config: TestConfig) -> Router<TestAppState> {
    // Create a memory-based introspection cache for testing
    let cache = InMemoryIntrospectionCache::new();

    // Create introspection state
    let introspection_state = IntrospectionStateBuilder::new(&config.auth_server_url)
        .with_basic_auth(&config.client_id, &config.client_secret)
        .with_introspection_cache(cache)
        .build()
        .await
        .unwrap();

    // Create a memory-based session store for testing
    let session_store = MemoryStore::default();

    // Create app state
    let state = TestAppState {
        introspection_state,
        session_store: session_store.clone(),
    };

    // Generate keys for session encryption and signing
    let signing_key = Key::generate();
    let encryption_key = Key::generate();

    // Parse the app URL to get the host for cookies
    let cookie_host_uri = config.app_url.parse::<http::Uri>().unwrap();
    let mut cookie_host = cookie_host_uri.authority().unwrap().to_string();

    if cookie_host.starts_with("localhost:") {
        cookie_host = "localhost".to_string();
    }

    // Create session layer
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("session")
        .with_expiry(Expiry::OnSessionEnd)
        .with_domain(cookie_host)
        .with_same_site(SameSite::Lax)
        .with_signed(signing_key)
        .with_private(encryption_key)
        .with_path("/")
        .with_secure(!config.dev_mode)
        .with_always_save(false);

    // Error handling middleware
    async fn handle_introspection_errors(
        mut response: axum_core::response::Response,
    ) -> axum_core::response::Response {
        let x_error_header_value = response
            .headers()
            .get("x-introspection-error")
            .and_then(|header_value| header_value.to_str().ok());

        match response.status() {
            http::StatusCode::UNAUTHORIZED => {
                if let Some(x_error) = x_error_header_value {
                    if x_error == "unauthorized" {
                        return Redirect::to("/login").into_response();
                    }
                }
                response
            }
            http::StatusCode::BAD_REQUEST => {
                if let Some(x_error) = x_error_header_value {
                    if x_error == "invalid schema"
                        || x_error == "invalid header"
                        || x_error == "introspection error"
                    {
                        return Redirect::to("/login").into_response();
                    }
                }
                response
            }
            http::StatusCode::FORBIDDEN => {
                if let Some(x_error) = x_error_header_value {
                    if x_error == "user is inactive" {
                        return Redirect::to("/login").into_response();
                    }
                }
                response
            }
            http::StatusCode::NOT_FOUND => {
                if let Some(x_error) = x_error_header_value {
                    if x_error == "user was not found" {
                        return Redirect::to("/login").into_response();
                    }
                }
                response
            }
            http::StatusCode::INTERNAL_SERVER_ERROR => {
                if let Some(x_error) = x_error_header_value {
                    if x_error == "missing config" {
                        return Redirect::to("/login").into_response();
                    }
                }
                response
            }
            _ => response,
        }
    }

    // Create the router with test-specific routes
    Router::new()
        .route("/api/whoami", get(whoami))
        .route("/public", get(public_test_route))
        .route("/protected", get(protected_test_route))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static(
            "x-request-id",
        )))
        .layer(axum::middleware::map_response(handle_introspection_errors))
        .with_state(state)
        .layer(session_layer)
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::very_permissive())
        .layer(SetSensitiveRequestHeadersLayer::new(once(
            http::header::AUTHORIZATION,
        )))
}

// Test routes
async fn whoami() -> impl IntoResponse {
    "test user"
}

async fn public_test_route() -> impl IntoResponse {
    "public route"
}

async fn protected_test_route() -> impl IntoResponse {
    "protected route"
}

