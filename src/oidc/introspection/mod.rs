use custom_error::custom_error;
use openidconnect::http::Method;
use openidconnect::reqwest::async_http_client;
use openidconnect::url::{ParseError, Url};
use openidconnect::HttpResponse;
use openidconnect::{
    core::CoreTokenType, ExtraTokenFields, HttpRequest, StandardTokenIntrospectionResponse,
};

use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use base64::Engine;
use crate::credentials::{Application, ApplicationError};

pub mod cache;

custom_error! {
    pub IntrospectionError
        RequestFailed{source: openidconnect::reqwest::Error<reqwest::Error>} = "the introspection request did fail: {source}",
        PayloadSerialization = "could not correctly serialize introspection payload",
        JWTProfile{source: ApplicationError} = "could not create signed jwt key: {source}",
        ParseUrl{source: ParseError} = "could not parse url: {source}",
        ParseResponse{source: serde_json::Error} = "could not parse introspection response: {source}",
        DecodeResponse{source: base64::DecodeError} = "could not decode base64 metadata: {source}",
        ResponseError{source: ZitadelResponseError} = "received error response from Zitadel: {source}",
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ZitadelIntrospectionExtraTokenFields {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub locale: Option<String>,
    #[serde(rename = "urn:zitadel:iam:user:resourceowner:id")]
    pub resource_owner_id: Option<String>,
    #[serde(rename = "urn:zitadel:iam:user:resourceowner:name")]
    pub resource_owner_name: Option<String>,
    #[serde(rename = "urn:zitadel:iam:user:resourceowner:primary_domain")]
    pub resource_owner_primary_domain: Option<String>,
    #[serde(rename = "urn:zitadel:iam:org:project:roles")]
    pub project_roles: Option<HashMap<String, HashMap<String, String>>>,
    #[serde(rename = "urn:zitadel:iam:user:metadata")]
    pub metadata: Option<HashMap<String, String>>,
}

impl ExtraTokenFields for ZitadelIntrospectionExtraTokenFields {}

pub type ZitadelIntrospectionResponse =
    StandardTokenIntrospectionResponse<ZitadelIntrospectionExtraTokenFields, CoreTokenType>;

#[derive(Debug, Clone)]
pub enum AuthorityAuthentication {
    Basic {
        client_id: String,
        client_secret: String,
    },
    JWTProfile { application: Application },
}

fn headers(auth: &AuthorityAuthentication) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, "application/json".parse().unwrap());
    headers.append(
        CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );

    match auth {
        AuthorityAuthentication::Basic {
            client_id,
            client_secret,
        } => {
            headers.append(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(&format!("{}:{}", client_id, client_secret))
                )
                .parse()
                .unwrap(),
            );
            headers
        }
        AuthorityAuthentication::JWTProfile { .. } => headers,
    }
}

fn payload(
    authority: &str,
    auth: &AuthorityAuthentication,
    token: &str,
) -> Result<String, IntrospectionError> {
    match auth {
        AuthorityAuthentication::Basic { .. } => serde_urlencoded::to_string([("token", token)])
            .map_err(|_| IntrospectionError::PayloadSerialization),
        AuthorityAuthentication::JWTProfile { application } => {
            let jwt = application
                .create_signed_jwt(authority)
                .map_err(|source| IntrospectionError::JWTProfile { source })?;

            serde_urlencoded::to_string([
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &jwt),
                ("token", token),
            ])
            .map_err(|_| IntrospectionError::PayloadSerialization)
        }
    }
}

pub async fn introspect(
    introspection_uri: &str,
    authority: &str,
    authentication: &AuthorityAuthentication,
    token: &str,
) -> Result<ZitadelIntrospectionResponse, IntrospectionError> {
    let response = async_http_client(HttpRequest {
        url: Url::parse(introspection_uri)
            .map_err(|source| IntrospectionError::ParseUrl { source })?,
        method: Method::POST,
        headers: headers(authentication),
        body: payload(authority, authentication, token)?.into_bytes(),
    })
    .await
    .map_err(|source| IntrospectionError::RequestFailed { source })?;

    if !response.status_code.is_success() {
        return Err(IntrospectionError::ResponseError {
            source: ZitadelResponseError::from_response(&response),
        });
    }

    let mut response: ZitadelIntrospectionResponse =
        serde_json::from_slice(response.body.as_slice())
            .map_err(|source| IntrospectionError::ParseResponse { source })?;
    decode_metadata(&mut response)?;
    Ok(response)
}

#[derive(Debug)]
struct ZitadelResponseError {
    status_code: String,
    body: String,
}
impl ZitadelResponseError {
    fn from_response(response: &HttpResponse) -> Self {
        Self {
            status_code: response.status_code.to_string(),
            body: String::from_utf8_lossy(response.body.as_slice()).to_string(),
        }
    }
}
impl Display for ZitadelResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "status code: {}, body: {}", self.status_code, self.body)
    }
}
impl Error for ZitadelResponseError {}

// Metadata values are base64 encoded.
fn decode_metadata(response: &mut ZitadelIntrospectionResponse) -> Result<(), IntrospectionError> {

    if let Some(h) = &response.extra_fields().metadata {
        let mut extra: ZitadelIntrospectionExtraTokenFields = response.extra_fields().clone();
        let mut metadata = HashMap::new();
        for (k, v) in h {
            let decoded_v = base64::engine::general_purpose::STANDARD.decode(v)
                .map_err(|source| IntrospectionError::DecodeResponse { source })?;
            let decoded_v = String::from_utf8_lossy(&decoded_v).into_owned();
            metadata.insert(k.clone(), decoded_v);
        }
        extra.metadata.replace(metadata);
        response.set_extra_fields(extra)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use crate::oidc::discovery::discover;
    use openidconnect::TokenIntrospectionResponse;

    use super::*;

    const ZITADEL_URL: &str = "https://zitadel-libraries-l8boqa.zitadel.cloud";
    const PERSONAL_ACCESS_TOKEN: &str =
        "dEnGhIFs3VnqcQU5D2zRSeiarB1nwH6goIKY0J8MWZbsnWcTuu1C59lW9DgCq1y096GYdXA";

    #[tokio::test]
    async fn introspect_fails_with_invalid_url() {
        let result = introspect(
            "foobar",
            "foobar",
            &AuthorityAuthentication::Basic {
                client_id: "".to_string(),
                client_secret: "".to_string(),
            },
            "token",
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IntrospectionError::ParseUrl { .. }
        ));
    }

    #[tokio::test]
    async fn introspect_fails_with_invalid_endpoint() {
        let meta = discover(ZITADEL_URL).await.unwrap();
        let result = introspect(
            &meta.token_endpoint().unwrap().to_string(),
            ZITADEL_URL,
            &AuthorityAuthentication::Basic {
                client_id: "".to_string(),
                client_secret: "".to_string(),
            },
            "token",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn introspect_succeeds() {
        let meta = discover(ZITADEL_URL).await.unwrap();
        let result = introspect(
            &meta
                .additional_metadata()
                .introspection_endpoint
                .as_ref()
                .unwrap()
                .to_string(),
            ZITADEL_URL,
            &AuthorityAuthentication::Basic {
                client_id: "194339055499018497@zitadel_rust_test".to_string(),
                client_secret: "Ip56oGzxKL1rJ8JaleUVKL7qUlpZ1tqHQYRSd6JE1mTlTJ3pDkDzoObHdZsOg88B"
                    .to_string(),
            },
            PERSONAL_ACCESS_TOKEN,
        )
        .await
        .unwrap();

        assert!(result.active());
    }
}
