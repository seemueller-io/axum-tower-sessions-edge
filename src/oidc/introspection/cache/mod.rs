use async_trait::async_trait;
use std::fmt::Debug;
use std::ops::Deref;

pub mod in_memory;
pub mod cloudflare;

pub type Response = super::ZitadelIntrospectionResponse;


#[async_trait]
pub trait IntrospectionCache: Send + Sync + std::fmt::Debug {
    async fn get(&self, token: &str) -> Option<Response>;

    async fn set(&self, token: &str, response: Response);

    async fn clear(&self);
}

#[async_trait]
impl<T, V> IntrospectionCache for T
where
    T: Deref<Target = V> + Send + Sync + Debug,
    V: IntrospectionCache,
{
    async fn get(&self, token: &str) -> Option<Response> {
        self.deref().get(token).await
    }

    async fn set(&self, token: &str, response: Response) {
        self.deref().set(token, response).await
    }

    async fn clear(&self) {
        self.deref().clear().await
    }
}
