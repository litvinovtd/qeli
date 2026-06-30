use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const NOTIFICATIONS_PAGE: &str = include_str!("../templates/notifications.html");

pub async fn notifications(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &state.config.web) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Notifications")
        .replace("{{assetver}}", &crate::server::web::assets::asset_ver())
        .replace("{{page}}", "notifications")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", NOTIFICATIONS_PAGE);

    Html(html).into_response()
}
