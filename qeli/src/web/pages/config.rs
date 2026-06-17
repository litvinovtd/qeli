use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const CONFIG_PAGE: &str = include_str!("../templates/config.html");

pub async fn config_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed(&headers, &state.config.web).await {
        return Redirect::to("/login").into_response();
    }

    // The config page fetches its data over /api/config at runtime, so the
    // template no longer carries an inlined config snapshot.
    let html = LAYOUT
        .replace("{{title}}", "Configuration")
        .replace("{{page}}", "config")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", CONFIG_PAGE);

    Html(html).into_response()
}
