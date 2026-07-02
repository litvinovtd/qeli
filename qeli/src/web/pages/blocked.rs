use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const BLOCKED_PAGE: &str = include_str!("../templates/blocked.html");

/// Blocked-IPs page: lists source IPs currently locked by brute-force protection,
/// with per-IP unblock and a clear-all action.
pub async fn blocked_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &*state.live_web.read().await) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Blocked IPs")
        .replace("{{assetver}}", &crate::server::web::assets::asset_ver())
        .replace("{{page}}", "blocked")
        .replace("{{content}}", BLOCKED_PAGE)
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));

    Html(html).into_response()
}
