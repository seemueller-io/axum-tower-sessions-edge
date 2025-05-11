mod api;
mod axum_introspector;
mod credentials;
mod oidc;
mod session_storage;
mod utilities;
mod zitadel_http;

use crate::api::authenticated::AuthenticatedApi;
use crate::api::public::PublicApi;
use crate::axum_introspector::introspection::{
    IntrospectedUser, IntrospectionState, IntrospectionStateBuilder,
};
use crate::oidc::introspection::cache::cloudflare::CloudflareIntrospectionCache;
use crate::session_storage::cloudflare::CloudflareKvStore;
use axum::extract::FromRef;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{any, get};
use axum::{Router, ServiceExt};
use bytes::Bytes;
use http::HeaderName;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use std::fmt::Debug;
use std::iter::once;
use std::ops::Deref;
use tower::ServiceExt as TowerServiceExt;
use tower_cookies::cookie::SameSite;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_service::Service;
use tower_sessions::cookie::Key;
use tower_sessions::SessionManagerLayer;
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

const SIGNING_KEY: &str = "keystore::sig";
const ENCRYPTION_KEY: &str = "keystore::enc";

// main entrypoint

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();

    Ok(route(req, _env).await)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Callback {
    code: String,
    state: String,
}

#[derive(Clone)]
struct AppState {
    introspection_state: IntrospectionState,
    env: Env,
    session_store: CloudflareKvStore,
}
impl FromRef<AppState> for IntrospectionState {
    fn from_ref(input: &AppState) -> Self {
        input.introspection_state.clone()
    }
}

async fn route(req: HttpRequest, _env: Env) -> axum_core::response::Response {
    let kv = _env.kv("KV_STORAGE").unwrap();
    let cache = CloudflareIntrospectionCache::new(kv.clone());

    let introspection_state = IntrospectionStateBuilder::new(
        _env.secret("AUTH_SERVER_URL")
            .unwrap()
            .to_string()
            .as_str(),
    )
    .with_basic_auth(
        _env.secret("CLIENT_ID")
            .unwrap()
            .to_string()
            .as_str(),
        _env.secret("CLIENT_SECRET")
            .unwrap()
            .to_string()
            .as_str(),
    )
    .with_introspection_cache(cache)
    .build()
    .await
    .unwrap();

    let session_store = CloudflareKvStore::new(kv.clone());

    let state = AppState {
        introspection_state,
        session_store: session_store.clone(),
        env: _env.clone(),
    };

    let dev_mode = _env.var("DEV_MODE").unwrap().to_string(); // Example check

    let is_dev = dev_mode == "true";

    let keystore = _env.kv("KV_STORAGE").unwrap();

    let signing = if let Some(bytes) = keystore.get(SIGNING_KEY).bytes().await.unwrap() {
        Key::derive_from(bytes.as_slice())
    } else {
        let key = Key::generate();
        keystore
            .put_bytes(SIGNING_KEY, key.master())
            .unwrap()
            .execute()
            .await
            .unwrap();
        key
    };

    let encryption = if let Some(bytes) = keystore.get(ENCRYPTION_KEY).bytes().await.unwrap() {
        Key::derive_from(bytes.as_slice())
    } else {
        let key = Key::generate();
        keystore
            .put_bytes(ENCRYPTION_KEY, key.master())
            .unwrap()
            .execute()
            .await
            .unwrap();
        key
    };

    let host_string = _env.secret("APP_URL").unwrap().to_string().as_str().to_owned();

    let cookie_host_uri = host_string.parse::<http::Uri>().unwrap();

    let mut cookie_host = cookie_host_uri.authority().unwrap().to_string();
    
    if cookie_host.starts_with("localhost:") {
        cookie_host = "localhost".to_string();
    }

    let session_layer = SessionManagerLayer::new(state.session_store.clone())
        .with_name("session")
        .with_expiry(Expiry::OnSessionEnd)
        .with_domain(cookie_host)
        .with_same_site(SameSite::Lax)
        .with_signed(signing)
        .with_private(encryption)
        .with_path("/")
        .with_secure(!is_dev)
        .with_always_save(false);

    async fn handle_introspection_errors(
        mut response: axum_core::response::Response,
    ) -> axum_core::response::Response {
        let x_error_header_value = response
            .headers()
            .get("x-introspection-error")
            .and_then(|header_value| header_value.to_str().ok());

        // not used but is available
        let x_session_header_value = response
            .headers()
            .get("x-session")
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

    let mut router = Router::new()
        .route("/", any(AuthenticatedApi::proxy))
        .route("/login", get(PublicApi::login_page)) // Add the login page route
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
        )));

    router
        .as_service()
        .ready()
        .await
        .unwrap()
        .oneshot(req)
        .await
        .unwrap()
}

async fn whoami(
    session: tower_sessions::Session,
    introspected_user: IntrospectedUser,
) -> impl IntoResponse {
    console_log!("calling whoami");
    to_string(&introspected_user).unwrap()
}

impl FromRef<AppState> for CloudflareKvStore {
    fn from_ref(input: &AppState) -> Self {
        input.session_store.clone()
    }
}
