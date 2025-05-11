use custom_error::custom_error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use openidconnect::{
    core::{CoreProviderMetadata, CoreTokenType},
    http::HeaderMap,
    reqwest::async_http_client,
    EmptyExtraTokenFields, HttpRequest, IssuerUrl, OAuth2TokenResponse, StandardTokenResponse,
};
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Method, Url,
};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

use crate::credentials::jwt::JwtClaims;


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    user_id: String,
    key_id: String,
    key: String,
}


#[derive(Clone, Debug, Default)]
pub struct AuthenticationOptions {
    pub api_access: bool,
    
    pub scopes: Vec<String>,
    
    pub roles: Vec<String>,
    
    pub project_audiences: Vec<String>,
}

custom_error! {
    pub ServiceAccountError
        Io{source: std::io::Error} = "unable to read from file: {source}",
        Json{source: serde_json::Error} = "could not parse json: {source}",
        Key{source: jsonwebtoken::errors::Error} = "could not parse RSA key: {source}",
        AudienceUrl{source: openidconnect::url::ParseError} = "audience url could not be parsed: {source}",
        DiscoveryError{source: Box<dyn std::error::Error>} = "could not discover OIDC document: {source}",
        TokenEndpointMissing = "OIDC document does not contain token endpoint",
        HttpError{source: openidconnect::reqwest::Error<reqwest::Error>} = "http error: {source}",
        UrlEncodeError = "could not encode url params for token request",
        TokenError = "could not fetch token from endpoint",
        AccessTokenMissing = "token response does not contain access token",
}

impl ServiceAccount {
    pub fn load_from_file(file_path: &str) -> Result<Self, ServiceAccountError> {
        let data = read_to_string(file_path).map_err(|e| ServiceAccountError::Io { source: e })?;
        ServiceAccount::load_from_json(data.as_str())
    }

    pub fn load_from_json(json: &str) -> Result<Self, ServiceAccountError> {
        let sa: ServiceAccount =
            serde_json::from_str(json).map_err(|e| ServiceAccountError::Json { source: e })?;
        Ok(sa)
    }

    pub async fn authenticate(&self, audience: &str) -> Result<String, ServiceAccountError> {
        self.authenticate_with_options(audience, &Default::default())
            .await
    }

    pub async fn authenticate_with_options(
        &self,
        audience: &str,
        options: &AuthenticationOptions,
    ) -> Result<String, ServiceAccountError> {
        let issuer = IssuerUrl::new(audience.to_string())
            .map_err(|e| ServiceAccountError::AudienceUrl { source: e })?;
        let metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
            .await
            .map_err(|e| ServiceAccountError::DiscoveryError {
                source: Box::new(e),
            })?;

        let jwt = self.create_signed_jwt(audience)?;
        let url = metadata
            .token_endpoint()
            .ok_or(ServiceAccountError::TokenEndpointMissing)?;
        let mut headers = HeaderMap::new();
        headers.append(ACCEPT, "application/json".parse().unwrap());
        headers.append(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let body = serde_urlencoded::to_string([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
            ("scope", &options.create_scopes()),
        ])
        .map_err(|_| ServiceAccountError::UrlEncodeError)?;

        let url =
            Url::parse(url.as_str()).map_err(|_| ServiceAccountError::TokenEndpointMissing)?;
        let response = async_http_client(HttpRequest {
            url,
            method: Method::POST,
            headers,
            body: body.into_bytes(),
        })
        .await
        .map_err(|e| ServiceAccountError::HttpError { source: e })?;

        serde_json::from_slice(response.body.as_slice())
            .map_err(|e| ServiceAccountError::Json { source: e })
            .map(
                |response: StandardTokenResponse<EmptyExtraTokenFields, CoreTokenType>| {
                    response.access_token().secret().clone()
                },
            )
    }

    fn create_signed_jwt(&self, audience: &str) -> Result<String, ServiceAccountError> {
        let key = EncodingKey::from_rsa_pem(self.key.as_bytes())
            .map_err(|e| ServiceAccountError::Key { source: e })?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.to_string());
        let claims = JwtClaims::new(&self.user_id, audience);
        let jwt = encode(&header, &claims, &key)?;

        Ok(jwt)
    }
}

impl AuthenticationOptions {
    fn create_scopes(&self) -> String {
        let mut result = vec!["openid".to_string()];

        for role in &self.roles {
            let scope = format!("urn:zitadel:iam:org:project:role:{}", role);
            if !result.contains(&scope) {
                result.push(scope);
            }
        }

        for p_id in &self.project_audiences {
            let scope = format!("urn:zitadel:iam:org:project:id:{}:aud", p_id);
            if !result.contains(&scope) {
                result.push(scope);
            }
        }

        for scope in &self.scopes {
            if !result.contains(scope) {
                result.push(scope.clone());
            }
        }

        let api_scope = "urn:zitadel:iam:org:project:id:zitadel:aud".to_string();
        if self.api_access && !result.contains(&api_scope) {
            result.push(api_scope);
        }

        result.join(" ")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use std::fs::File;
    use std::io::Write;

    use super::*;

    const ZITADEL_URL: &str = "https://zitadel-libraries-l8boqa.zitadel.cloud";
    const SERVICE_ACCOUNT: &str = r#"
    {
        "type": "serviceaccount",
        "keyId": "181828078849229057",
        "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA9VIWALQqzx1ypi42t7MG4KSOMldD10brsEUjTcjqxhl6TJrP\nsjaNKWArnV/XH+6ZKRd55mUEFFx9VflqdwQtMVPjZKXpV4cFDiPwf1Z1h1DS6im4\nSo7eKR7OGb7TLBhwt7i2UPF4WnxBhTp/M6pG5kCJ1t8glIo5yRbrILXObRmvNWMz\nVIFAyw68NDZGYNhnR8AT43zjeJTFXG/suuEoXO/mMmMjsYY8kS0BbiQeq5t5hIrr\na/odswkDPn5Zd4P91iJHDnYlgfJuo3oRmgpOj/dDsl+vTol+vveeMO4TXPwZcl36\ngUNPok7nd6BA3gqmOS+fMImzmZB42trghARXXwIDAQABAoIBAQCbMOGQcml+ep+T\ntzqQPWYFaLQ37nKRVmE1Mpeh1o+G4Ik4utrXX6EvYpJUzVN29ObZUuufr5nEE7qK\nT+1k+zRntyzr9/VElLrC9kNnGtfg0WWMEvZt3DF4i+9P5CMNCy0LXIOhcxBzFZYR\nZS8hDQArGvrX/nFK5qKlrqTyHXFIHDFa6z59ErhXEnsTgRvx/Mo+6UkdBkHsKnlJ\nAbXqXFbfz6nDsF1DgRra5ODn1k8nZqnC/YcssE7/dlbuByz10ECkOSzqYcfufnsb\n9N1Ld4Xlj3yzsqPFzEJyHHm9eEHQXsPavaXiM64/+zpsksLscEIE/0KtIy5tngpZ\nSCqZAcj5AoGBAPb1bQFWUBmmUuSTtSymsxgXghJiJ3r+jJgdGbkv2IsRTs4En5Sz\n0SbPE1YWmMDDgTacJlB4/XiaojQ/j1EEY17inxYomE72UL6/ET7ycsEw3e9ALuD5\np0y2Sdzes2biH30bw5jD8kJ+hV18T745KtzrwSH4I0lAjnkmiH+0S67VAoGBAP5N\nTtAp/Qdxh9GjNSw1J7KRLtJrrr0pPrJ9av4GoFoWlz+Qw2X3dl8rjG3Bqz9LPV7A\ngiHMel8WTmdIM/S3F4Q3ufEfE+VzG+gncWd9SJfX5/LVhatPzTGLNsY7AYGEpSwT\n5/0anS1mHrLwsVcPrZnigekr5A5mfZl6nxtOnE9jAoGBALACqacbUkmFrmy1DZp+\nUQSptI3PoR3bEG9VxkCjZi1vr3/L8cS1CCslyT1BK6uva4d1cSVHpjfv1g1xA38V\nppE46XOMiUk16sSYPv1jJQCmCHd9givcIy3cefZOTwTTwueTAyv888wKipjfgaIs\n8my0JllEljmeJi0Ylo6V/J7lAoGBAIFqRlmZhLNtC3mcXUsKIhG14OYk9uA9RTMA\nsJpmNOSj6oTm3wndTdhRCT4x+TxUxf6aaZ9ZuEz7xRq6m/ZF1ynqUi5ramyyj9kt\neYD5OSBNODVUhJoSGpLEDjQDg1iucIBmAQHFsYeRGL5nz1hHGkneA87uDzlk3zZk\nOORktReRAoGAGUfU2UfaniAlqrZsSma3ZTlvJWs1x8cbVDyKTYMX5ShHhp+cA86H\nYjSSol6GI2wQPP+qIvZ1E8XyzD2miMJabl92/WY0tHejNNBEHwD8uBZKrtMoFWM7\nWJNl+Xneu/sT8s4pP2ng6QE7jpHXi2TUNmSlgQry9JN2AmA9TuSTW2Y=\n-----END RSA PRIVATE KEY-----\n",
        "userId": "181828061098934529"
    }"#;

    #[test]
    fn load_successfully_from_json() {
        let sa = ServiceAccount::load_from_json(SERVICE_ACCOUNT).unwrap();

        assert_eq!(sa.user_id, "181828061098934529");
        assert_eq!(sa.key_id, "181828078849229057");
    }

    #[test]
    fn load_successfully_from_file() {
        let mut file = File::create("./temp_sa").unwrap();
        file.write_all(SERVICE_ACCOUNT.as_bytes())
            .expect("Could not write temp.");

        let sa = ServiceAccount::load_from_file("./temp_sa").unwrap();

        assert_eq!(sa.user_id, "181828061098934529");
        assert_eq!(sa.key_id, "181828078849229057");
    }

    #[test]
    fn load_faulty_from_json() {
        let err = ServiceAccount::load_from_json("{1234}").unwrap_err();

        if let ServiceAccountError::Json { source: _ } = err {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn load_faulty_from_file() {
        let err = ServiceAccount::load_from_file("./foobar").unwrap_err();

        if let ServiceAccountError::Io { source: _ } = err {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn creates_a_signed_jwt() {
        let sa = ServiceAccount::load_from_json(SERVICE_ACCOUNT).unwrap();
        let claims = sa.create_signed_jwt(ZITADEL_URL).unwrap();

        assert_eq!(&claims[0..5], "eyJ0e");
    }
}
