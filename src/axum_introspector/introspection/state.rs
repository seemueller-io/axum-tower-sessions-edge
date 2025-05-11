use openidconnect::IntrospectionUrl;
use std::sync::Arc;

use crate::oidc::introspection::cache::IntrospectionCache;
use crate::oidc::introspection::AuthorityAuthentication;

#[derive(Clone, Debug)]
pub struct IntrospectionState {
    pub(crate) config: Arc<IntrospectionConfig>,
}

#[derive(Debug)]
pub(crate) struct IntrospectionConfig {
    pub(crate) authority: String,
    pub(crate) authentication: AuthorityAuthentication,
    pub(crate) introspection_uri: IntrospectionUrl,
    pub(crate) cache: Option<Box<dyn IntrospectionCache>>,
}
