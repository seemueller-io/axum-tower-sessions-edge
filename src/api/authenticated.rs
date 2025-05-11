use crate::axum_introspector::introspection::IntrospectedUser;
use crate::AppState;
use axum::extract::{Request, State};
use axum::response::IntoResponse;
use tower::Layer;
use tower_service::Service;
use worker::*;

pub struct AuthenticatedApi;

impl AuthenticatedApi {
    #[worker::send]
    pub async fn proxy(session: tower_sessions::Session, State(state): State<AppState>, user: IntrospectedUser, mut request: Request) -> impl IntoResponse {
        let worker_request = worker::Request::try_from(request).unwrap();
        let http_request = http::Request::try_from(worker_request).unwrap();

        let proxy_target = state.env.service("PROXY_TARGET").unwrap();
        <http::Response<worker::Body> as Into<HttpResponse>>::into(proxy_target.fetch_request(http_request).await.expect("failed to proxy request"))
    }
}