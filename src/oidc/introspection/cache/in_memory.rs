use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use openidconnect::TokenIntrospectionResponse;
use time::Duration;

type Response = super::super::ZitadelIntrospectionResponse;

#[derive(Debug, Clone)]
pub struct InMemoryIntrospectionCache {
    cache: Arc<RwLock<HashMap<String, (Response, i64)>>>,
}

impl InMemoryIntrospectionCache {
    /// Creates a new in memory cache backed by a HashMap.
    /// No max capacity limit is enforced, but entries are cleared based on expiry.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryIntrospectionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl super::IntrospectionCache for InMemoryIntrospectionCache {
    async fn get(&self, token: &str) -> Option<Response> {
        let mut cache = self.cache.write().await;
        match cache.get(token) {
            Some((response, expires_at))
            if *expires_at < chrono::Utc::now().timestamp() => {
                cache.remove(token);
                None
            }
            Some((response, _)) => Some(response.clone()),
            None => None,
        }
    }

    async fn set(&self, token: &str, response: Response) {
        if !response.active() || response.exp().is_none() {
            return;
        }
        let expires_at = response.exp().unwrap().timestamp();
        self.cache.write().await.insert(token.to_string(), (response, expires_at));
    }

    async fn clear(&self) {
        self.cache.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use crate::oidc::introspection::cache::IntrospectionCache;
    use chrono::{TimeDelta, Utc};

    use super::*;

    #[tokio::test]
    async fn test_get_set() {
        let c = InMemoryIntrospectionCache::new();
        let t = &c as &dyn IntrospectionCache;

        let mut response = Response::new(true, Default::default());
        response.set_exp(Some(Utc::now()));

        t.set("token1", response.clone()).await;
        t.set("token2", response.clone()).await;

        assert!(t.get("token1").await.is_some());
        assert!(t.get("token2").await.is_some());
        assert!(t.get("token3").await.is_none());
    }

    #[tokio::test]
    async fn test_non_exp_response() {
        let c = InMemoryIntrospectionCache::new();
        let t = &c as &dyn IntrospectionCache;

        let response = Response::new(true, Default::default());

        t.set("token1", response.clone()).await;
        t.set("token2", response.clone()).await;

        assert!(t.get("token1").await.is_none());
        assert!(t.get("token2").await.is_none());
    }

    #[tokio::test]
    async fn test_clear() {
        let c = InMemoryIntrospectionCache::new();
        let t = &c as &dyn IntrospectionCache;

        let mut response = Response::new(true, Default::default());
        response.set_exp(Some(Utc::now()));

        t.set("token1", response.clone()).await;
        t.set("token2", response.clone()).await;

        t.clear().await;

        assert!(t.get("token1").await.is_none());
        assert!(t.get("token2").await.is_none());
    }

    #[tokio::test]
    async fn test_remove_expired_token() {
        let c = InMemoryIntrospectionCache::new();
        let t = &c as &dyn IntrospectionCache;

        let mut response = Response::new(true, Default::default());
        response.set_exp(Some(Utc::now() - TimeDelta::try_seconds(10).unwrap()));

        t.set("token1", response.clone()).await;
        t.set("token2", response.clone()).await;

        let _ = t.get("token1").await;
        let _ = t.get("token2").await;

        assert!(t.get("token1").await.is_none());
        assert!(t.get("token2").await.is_none());
    }
}