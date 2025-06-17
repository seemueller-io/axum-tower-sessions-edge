//! Session management for the application.
//!
//! This module provides centralized session management functionality,
//! including session configuration and key management.

use crate::config::{Config, ENCRYPTION_KEY, SIGNING_KEY};
use crate::session_storage::cloudflare::CloudflareKvStore;
use tower_cookies::cookie::SameSite;
use tower_sessions::cookie::Key;
use tower_sessions::service::PrivateCookie;
use tower_sessions::SessionManagerLayer;
use tower_sessions_core::Expiry;
use worker::kv::KvStore as Kv;

/// Session configuration options
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The name of the session cookie
    pub cookie_name: String,
    /// The expiry policy for the session
    pub expiry: Expiry,
    /// The domain for the session cookie
    pub domain: String,
    /// The path for the session cookie
    pub path: String,
    /// Whether the session cookie should be secure
    pub secure: bool,
    /// The same-site policy for the session cookie
    pub same_site: SameSite,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "session".to_string(),
            expiry: Expiry::OnSessionEnd,
            domain: "localhost".to_string(),
            path: "/".to_string(),
            secure: true,
            same_site: SameSite::Lax,
        }
    }
}

/// Create a session manager layer with the given configuration
///
/// # Arguments
///
/// * `config` - The application configuration
/// * `session_config` - The session configuration
/// * `session_store` - The session store
/// * `keystore` - The KV store for key management
///
/// # Returns
///
/// A session manager layer
pub async fn create_session_layer(
    config: &Config,
    session_config: Option<SessionConfig>,
    session_store: CloudflareKvStore,
    keystore: Kv,
) -> SessionManagerLayer<CloudflareKvStore, PrivateCookie> {
    let session_config = session_config.unwrap_or_default();

    let (signing, encryption) = get_or_create_keys(keystore).await;

    let mut domain = session_config.domain;

    // Handle localhost special case
    if let Ok(uri) = config.app_url.parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            domain = authority.to_string();
            if domain.starts_with("localhost:") {
                domain = "localhost".to_string();
            }
        }
    }

    SessionManagerLayer::new(session_store)
        .with_name(session_config.cookie_name)
        .with_expiry(session_config.expiry)
        .with_domain(domain)
        .with_same_site(session_config.same_site)
        .with_signed(signing)
        .with_private(encryption)
        .with_path(session_config.path)
        .with_secure(!config.dev_mode)
        .with_always_save(false)
}

/// Get or create signing and encryption keys
///
/// # Arguments
///
/// * `keystore` - The KV store for key management
///
/// # Returns
///
/// A tuple of (signing_key, encryption_key)
async fn get_or_create_keys(keystore: Kv) -> (Key, Key) {
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

    (signing, encryption)
}
