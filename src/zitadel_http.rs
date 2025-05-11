#[derive(Debug, serde::Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub jwks_uri: String,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub response_modes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub subject_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub ui_locales_supported: Option<Vec<String>>,
    pub request_parameter_supported: Option<bool>,
    pub request_uri_parameter_supported: Option<bool>,
}

pub async fn fetch_oidc_metadata(issuer_url: &str) -> OidcMetadata {
    let issuer_url = issuer_url.trim_end_matches('/');
    let metadata_url = format!("{}/.well-known/openid-configuration", issuer_url);

    let response = reqwest::get(&metadata_url).await.expect("Failed to fetch metadata");

    response.json::<OidcMetadata>().await.expect("Failed to parse metadata")
}
