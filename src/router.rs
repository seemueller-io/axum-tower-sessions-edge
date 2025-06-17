//! Routing configuration for the application.
//!
//! This module provides centralized routing functionality,
//! including router configuration and middleware setup.

use crate::api::authenticated::AuthenticatedApi;
use crate::api::public::PublicApi;
use crate::error::handle_introspection_errors;
use worker::console_log;
use axum::extract::FromRef;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::{Router, ServiceExt};
use http::HeaderName;
use serde_json::to_string;
use std::iter::once;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_sessions::SessionManagerLayer;

use crate::axum_introspector::introspection::{IntrospectedUser, IntrospectionState};
use crate::session_storage::cloudflare::CloudflareKvStore;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// State for token introspection
    pub introspection_state: IntrospectionState,
    /// Cloudflare environment
    pub env: worker::Env,
    /// Session store
    pub session_store: CloudflareKvStore,
}

impl FromRef<AppState> for IntrospectionState {
    fn from_ref(input: &AppState) -> Self {
        input.introspection_state.clone()
    }
}

impl FromRef<AppState> for CloudflareKvStore {
    fn from_ref(input: &AppState) -> Self {
        input.session_store.clone()
    }
}

/// Create a router with the given state and session layer
///
/// # Arguments
///
/// * `state` - The application state
/// * `session_layer` - The session manager layer
///
/// # Returns
///
/// A configured router
pub fn create_router(
    state: AppState,
    session_layer: SessionManagerLayer<CloudflareKvStore, tower_sessions::service::PrivateCookie>,
) -> Router {
    Router::new()
        .route("/", any(AuthenticatedApi::proxy))
        .route("/login", get(PublicApi::login_page))
        .route("/login/callback", get(PublicApi::callback))
        .route("/login/authorize", get(PublicApi::authorize))
        .route("/api/whoami", get(whoami))
        .route("/*path", any(AuthenticatedApi::proxy))
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

/// Handler for the whoami endpoint
///
/// # Arguments
///
/// * `session` - The user's session
/// * `introspected_user` - The introspected user information
///
/// # Returns
///
/// The user information as JSON
pub async fn whoami(
    session: tower_sessions::Session,
    introspected_user: IntrospectedUser,
) -> impl IntoResponse {
    console_log!("calling whoami");
    to_string(&introspected_user).unwrap()
}
