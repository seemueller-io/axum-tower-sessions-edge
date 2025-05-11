use std::fmt::{Debug, Formatter};
use async_trait::async_trait;
// use axum_core::response::IntoResponse;
use openidconnect::TokenIntrospectionResponse;
use crate::oidc::introspection::cache::{IntrospectionCache, Response};
// use crate::session_storage::cloudflare::CloudflareKvStore;


/// for storing introspection results.
pub struct CloudflareIntrospectionCache {
    kv: worker::kv::KvStore,
}

impl CloudflareIntrospectionCache {
    /// Creates a new instance of `CloudflareIntrospectionCache` with the given KV namespace.
    pub fn new(kv: worker::kv::KvStore) -> Self {
        Self { kv }
    }
}

impl std::fmt::Debug for CloudflareIntrospectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareKvStore")
            .finish_non_exhaustive()
        // Probably want to handle this differently
        // .field("kvstore", "KVStorePlaceholder")
    }
}


fn prefixed_key(token: &str) -> String {
    format!("introspectioncache::{}", token)
}

#[async_trait]
impl IntrospectionCache for CloudflareIntrospectionCache {
    async fn get(&self, token: &str) -> Option<Response> {
        get(self.kv.clone(), token).await
    }

    async fn set(&self, token: &str, response: Response) {
        // Check if the token is active and has an expiration time
       set(self.kv.clone(), token, response).await;
    }

    async fn clear(&self) {
        wrapped_clear(self.kv.clone()).await
    }
}

#[worker::send]
async fn set(kv: worker::kv::KvStore, token: &str, response: Response) {
    if response.active() && response.exp().is_some() {
        // Serialize the response to JSON
        if let Ok(json) = serde_json::to_string(&response) {
            // Set the expiration time
            let expiration = response.exp().unwrap();
            // Store the serialized response in the KV store with expiration
            kv.put(prefixed_key(token).as_str(), json).unwrap().expiration(expiration.timestamp().unsigned_abs()).execute().await.unwrap_or(());
        }
    }
}


#[worker::send]
async fn get(kv: worker::kv::KvStore, token: &str) -> Option<Response> {
    if let Some(data) = kv.get(prefixed_key(token).as_str()).text().await.unwrap_or(None) {
        serde_json::from_str(&data).ok()
    } else {
        None
    }
}

#[worker::send]
async fn wrapped_clear(kv: worker::kv::KvStore) {
    let keys = kv.list().execute().await.unwrap().keys;

    for key in keys.iter().filter(|key| key.name.starts_with("introspectioncache::")) {
        kv.delete(&key.name).await.unwrap_or(());
    }
}