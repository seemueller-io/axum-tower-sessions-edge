use custom_error::custom_error;
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    url, AdditionalProviderMetadata, IntrospectionUrl, IssuerUrl, ProviderMetadata, RevocationUrl,
};
use serde::{Deserialize, Serialize};

custom_error! {
    pub DiscoveryError
        IssuerUrl{source: url::ParseError} = "could not parse issuer url: {source}",
        DiscoveryDocument = "could not discover OIDC document",
}

pub async fn discover(authority: &str) -> Result<ZitadelProviderMetadata, DiscoveryError> {
    let issuer = IssuerUrl::new(authority.to_string())
        .map_err(|source| DiscoveryError::IssuerUrl { source })?;
    ZitadelProviderMetadata::discover_async(issuer, async_http_client)
        .await
        .map_err(|_| DiscoveryError::DiscoveryDocument)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZitadelAdditionalMetadata {
    pub introspection_endpoint: Option<IntrospectionUrl>,
    pub revocation_endpoint: Option<RevocationUrl>,
}

impl AdditionalProviderMetadata for ZitadelAdditionalMetadata {}


pub type ZitadelProviderMetadata = ProviderMetadata<
    ZitadelAdditionalMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use super::*;

    const ZITADEL_URL: &str = "https://zitadel-libraries-l8boqa.zitadel.cloud";

    #[tokio::test]
    async fn discovery_fails_with_invalid_url() {
        let result = discover("foobar").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DiscoveryError::IssuerUrl { .. }
        ));
    }

    #[tokio::test]
    async fn discovery_fails_with_invalid_discovery() {
        let result = discover("https://smartive.ch").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DiscoveryError::DiscoveryDocument
        ));
    }

    #[tokio::test]
    async fn discovery_succeeds() {
        let result = discover(ZITADEL_URL).await.unwrap();

        assert_eq!(
            result.token_endpoint().unwrap().to_string(),
            "https://zitadel-libraries-l8boqa.zitadel.cloud/oauth/v2/token".to_string()
        );
    }
}
