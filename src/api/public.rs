use crate::utilities::Utilities;
use crate::{AppState, Callback};
use axum::extract::{Query, Request, State};
use axum::response::IntoResponse;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::str::FromStr;
use std::sync::Arc;
use tower::Layer;
use tower_service::Service;
use tower_sessions_core::Session;
use worker::*;

pub struct PublicApi;

impl PublicApi {
    #[worker::send]
    pub async fn fallback() -> impl IntoResponse {
        return axum::response::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }

    #[worker::send]
    pub async fn login_page(session: Session, request: Request) -> impl IntoResponse {
        session
            .insert("last_visited", chrono::Local::now().to_string())
            .await
            .unwrap();

        session.save().await.unwrap();

        axum::response::Html(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form[action="/login/authorize"]');
            if (form) {
                form.submit();
            } else {
                console.error("Login form not found.");
            }
        });
    </script>
</head>
<body>
    <p>Redirecting to login...</p>
    <form action="/login/authorize" method="GET" style="display:none;">
        <button type="submit">Login with ZITADEL</button>
    </form>
</body>
</html>
"#,
        )
        .into_response()
    }

    #[worker::send]
    pub async fn authorize(
        session: tower_sessions::Session,
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let oauth_base_url = state.env.secret("AUTH_SERVER_URL").unwrap().to_string();
        let app_host = state.env.secret("APP_URL").unwrap().to_string();

        let redirect_uri = format!("{}{}", app_host, "/login/callback");

        let client = BasicClient::new(ClientId::new(
            state.env.secret("CLIENT_ID").unwrap().to_string(),
        ))
        .set_client_secret(ClientSecret::new(
            state.env.secret("CLIENT_SECRET").unwrap().to_string(),
        ))
        .set_auth_uri(AuthUrl::new(format!("{}{}", oauth_base_url, "/oauth/v2/authorize")).unwrap())
        .set_token_uri(TokenUrl::new(format!("{}{}", oauth_base_url, "/oauth/v2/token")).unwrap())
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let org_scope: String = if let Ok(org_id) = state.env.secret("ZITADEL_ORG_ID") {
            format!("urn:zitadel:iam:org:id:{}", org_id.to_string())
        } else {
            String::new()
        };
        let project_scope: String = if let Ok(project_id) = state.env.secret("ZITADEL_PROJECT_ID") {
            format!(
                "urn:zitadel:iam:org:project:id:{}:aud",
                project_id.to_string()
            )
        } else {
            String::new()
        };

        let mut scopes = vec![
            Scope::new("openid".to_string()),
            Scope::new("email".to_string()),
            // Scope::new("profile".to_string()),
            // Scope::new("offline_access".to_string())
        ];

        if (!org_scope.is_empty()) {
            scopes.push(Scope::new(org_scope));
        }
        if (!project_scope.is_empty()) {
            scopes.push(Scope::new(project_scope));
        }

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();

        let csrf_string = csrf_token.secret().to_string();
        let verifier_storage_key = Utilities::get_pkce_verifier_storage_key(&csrf_string); // Use a key tied to the state param

        if let Some(csrf_state) = session.get::<String>("csrf_state").await.unwrap() {
            if csrf_state != csrf_string {
                console_error!("CSRF state mismatch.");
                return axum::response::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        } else {
            session
                .insert(
                    verifier_storage_key.as_str(),
                    pkce_verifier.secret().as_str(),
                )
                .await
                .unwrap();
            session
                .insert("csrf_state", csrf_string.as_str())
                .await
                .unwrap();
            session.save().await.unwrap();
        }
        let csrf_store = state.env.kv("KV_STORAGE").unwrap();

        let session_csrf_key = Utilities::get_auth_session_key(csrf_string.as_str());

        csrf_store
            .put(session_csrf_key.as_str(), session.id().unwrap().to_string())
            .unwrap()
            .execute()
            .await
            .unwrap();

        let final_auth_url = auth_url.as_str();

        let redirect_response = http::Response::builder()
            .status(http::StatusCode::FOUND)
            .header(http::header::LOCATION, final_auth_url)
            .body(axum::body::Body::empty())
            .unwrap();

        redirect_response.into_response()
    }

    #[worker::send]
    pub async fn callback(
        State(state): State<AppState>,
        mut session: tower_sessions::Session,
        callback: Query<Callback>,
        request: Request,
    ) -> impl IntoResponse {
        let code = &callback.code;
        let state_param = &callback.state;

        if code.is_empty() {
            return axum::response::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(axum::body::Body::from("Invalid authorization code"))
                .unwrap();
        }

        let verifier_storage_key = Utilities::get_pkce_verifier_storage_key(state_param);

        let csrf_store = state.env.kv("KV_STORAGE").unwrap();

        let csrf_key = Utilities::get_auth_session_key(state_param);

        let get_auth_session_id = csrf_store
            .get(csrf_key.as_str())
            .text()
            .await
            .expect("failed to get auth session id");

        csrf_store.delete(csrf_key.as_str()).await.unwrap();

        let asi = get_auth_session_id.map(|data| data).unwrap();

        let auth_session_id = tower_sessions_core::session::Id::from_str(asi.as_str()).unwrap();

        let mut auth_session =
            Session::new(Some(auth_session_id), Arc::new(state.session_store), None);

        let verifier_string: String = match auth_session.get(verifier_storage_key.as_str()).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                console_error!(
                    "PKCE verifier not found in session for key: {:?}",
                    verifier_storage_key
                );
                return axum::response::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from("Session state mismatch or expired."))
                    .unwrap();
            }
            Err(e) => {
                console_error!("Error retrieving PKCE verifier from session: {:?}", e);
                return axum::response::Response::builder()
                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from(
                        "Internal server error retrieving session data.",
                    ))
                    .unwrap();
            }
        };

        let stored_csrf_state: String = match auth_session.get("csrf_state").await {
            Ok(Some(s)) => s,
            Ok(None) => {
                console_error!("CSRF state not found in session.");
                return axum::response::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from("CSRF state mismatch or missing."))
                    .unwrap();
            }
            Err(e) => {
                console_error!("Error retrieving CSRF state from session: {:?}", e);
                return axum::response::Response::builder()
                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from(
                        "Internal server error retrieving session data.",
                    ))
                    .unwrap();
            }
        };

        // Basic CSRF state verification
        if &stored_csrf_state != state_param {
            console_error!(
                "CSRF state mismatch. Expected: {:?}, Received: {:?}",
                stored_csrf_state,
                state_param
            );
            return axum::response::Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(axum::body::Body::empty())
                .unwrap();
        } else {
            auth_session.remove::<String>("csrf_state").await.unwrap();
        }

        let pkce_verifier = PkceCodeVerifier::new(verifier_string);
        // console_log!("callback::pkce_verifier: {:?}", pkce_verifier.secret().to_string());
        auth_session
            .remove::<String>(verifier_storage_key.as_str())
            .await
            .unwrap();

        let oauth_base_url = state.env.secret("AUTH_SERVER_URL").unwrap().to_string();
        let app_host = state.env.secret("HOST").unwrap().to_string();
        let redirect_uri = format!("{}{}", app_host, "/login/callback");

        let redirect_url = RedirectUrl::new(redirect_uri).unwrap();

        let client = BasicClient::new(ClientId::new(
            state.env.secret("CLIENT_ID").unwrap().to_string(),
        ))
        .set_client_secret(ClientSecret::new(
            state
                .env
                .secret("CLIENT_SECRET")
                .unwrap()
                .to_string(),
        ))
        .set_auth_uri(AuthUrl::new(format!("{}{}", oauth_base_url, "/oauth/v2/authorize")).unwrap())
        .set_token_uri(TokenUrl::new(format!("{}{}", oauth_base_url, "/oauth/v2/token")).unwrap())
        .set_redirect_uri(redirect_url);

        let http_client = oauth2::reqwest::ClientBuilder::new()
            .build()
            .expect("Client should build");

        match client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http_client)
            .await
        {
            Ok(token_result) => {
                session
                    .insert("token", token_result.access_token().secret().to_string())
                    .await
                    .unwrap();

                session.save().await.unwrap();

                let url = request.uri();
                let mut redirect_location = Url::parse(url.to_string().as_str()).unwrap();
                redirect_location.set_path("/");
                redirect_location.set_query(None);

                console_log!("redirecting to : {:?}", redirect_location);

                let session_response = Session::from(session).save().await.unwrap().into_response();
                let session_headers = session_response.headers();

                let mut redirect_response = axum::response::Response::builder()
                    .status(http::StatusCode::FOUND)
                    .header(http::header::LOCATION, redirect_location.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap()
                    .into_response();

                for (key, value) in session_headers.iter() {
                    redirect_response.headers_mut().insert(key, value.clone());
                }
                redirect_response.into_response()
            }
            Err(e) => {
                console_log!("Token request failed: {:?}", e);
                let error_message = match e {
                    oauth2::RequestTokenError::ServerResponse(server_error) => {
                        format!("Server error: {:?}", server_error)
                    }
                    _ => format!("Unknown error: {:?}", e),
                };
                return axum::response::Response::builder()
                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from(format!(
                        "OAuth2 Token Error: {}",
                        error_message
                    )))
                    .unwrap();
            }
        }
    }
}
