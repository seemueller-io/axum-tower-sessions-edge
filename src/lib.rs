//! # axum-tower-sessions-edge
//!
//! A Rust library that validates incoming requests for defined routes and forwards traffic 
//! to the service defined as `PROXY_TARGET`. It's designed to work with Cloudflare Workers 
//! and targets the `wasm32-unknown-unknown` platform.
//!
//! ## Features
//!
//! - OAuth 2.0 authentication flow
//! - Proof Key for Code Exchange (PKCE) for enhanced security
//! - OAuth 2.0 Token Introspection for token validation
//! - Session management with tower-sessions
//! - Cloudflare Workers integration
//!
//! See the [docs](crate::docs) module for comprehensive documentation.

mod api;
mod axum_introspector;
mod config;
mod credentials;
mod docs;
mod error;
mod oidc;
mod router;
mod session;
mod session_storage;
mod utilities;
mod zitadel_http;

use axum::handler::Handler;
use crate::axum_introspector::introspection::IntrospectionStateBuilder;
use crate::config::{Config, KV_STORAGE_BINDING};
use crate::oidc::introspection::cache::cloudflare::CloudflareIntrospectionCache;
use crate::router::{create_router, AppState};
use crate::session::{create_session_layer, SessionConfig};
use crate::session_storage::cloudflare::CloudflareKvStore;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use tower_cookies::cookie::SameSite;
use tower_service::Service;
use tower_sessions_core::Expiry;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use worker::*;

#[event(start)]
fn start() {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .without_time()
        .with_ansi(false) // Only partially supported across JavaScript runtimes
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339()); // std::time is not available in browsers
    let perf_layer = tracing_web::performance_layer();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(perf_layer)
        .init()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Callback {
    code: String,
    state: String,
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    Ok(route(req, env).await)
}

async fn route(req: HttpRequest, env: Env) -> axum::http::Response<axum::body::Body> {
    // Load configuration from environment
    let config = match Config::from_env(&env) {
        Ok(config) => config,
        Err(err) => {
            console_error!("Configuration error: {}", err);
            return axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::from("Internal Server Error: Configuration error"))
                .unwrap();
        }
    };

    // Initialize KV store
    let kv = match env.kv(KV_STORAGE_BINDING) {
        Ok(kv) => kv,
        Err(err) => {
            console_error!("KV store error: {}", err);
            return axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::from("Internal Server Error: KV store error"))
                .unwrap();
        }
    };

    // Initialize introspection cache
    let cache = CloudflareIntrospectionCache::new(kv.clone());

    // Build introspection state
    let introspection_state = match IntrospectionStateBuilder::new(&config.auth_server_url)
        .with_basic_auth(&config.client_id, &config.client_secret)
        .with_introspection_cache(cache)
        .build()
        .await
    {
        Ok(state) => state,
        Err(err) => {
            console_error!("Introspection state error: {}", err);
            return axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::from("Internal Server Error: Introspection state error"))
                .unwrap();
        }
    };

    // Initialize session store
    let session_store = CloudflareKvStore::new(kv.clone());

    // Create application state
    let state = AppState {
        introspection_state,
        session_store: session_store.clone(),
        env: env.clone(),
    };

    // Create session configuration
    let session_config = SessionConfig {
        cookie_name: "session".to_string(),
        expiry: Expiry::OnSessionEnd,
        domain: "localhost".to_string(), // Will be overridden in create_session_layer
        path: "/".to_string(),
        secure: !config.dev_mode,
        same_site: SameSite::Lax,
    };

    // Create session layer
    let session_layer = create_session_layer(
        &config,
        Some(session_config),
        session_store,
        kv,
    ).await;

    // Create router
    let router = create_router(state, session_layer);

    // Handle request
    // Convert the worker request to an axum request
    let axum_req = axum::extract::Request::try_from(req).unwrap();

    // Use the router to handle the request
    // Since we've modified create_router to return a Router with empty state,
    // we can now use the oneshot method directly
    router.oneshot(axum_req).await.unwrap()
}
