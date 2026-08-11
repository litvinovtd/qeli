use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const TRANSPORT: &str = include_str!("../templates/transport.html");

pub async fn transport_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &*state.live_web.read().await) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Transport health")
        .replace("{{assetver}}", &crate::server::web::assets::asset_ver())
        .replace("{{page}}", "transport")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", TRANSPORT);

    Html(html).into_response()
}
