use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const LOGS_PAGE: &str = include_str!("../templates/logs.html");

pub async fn logs_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed(&headers, &state.config.web) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Logs")
        .replace("{{page}}", "logs")
        .replace("{{content}}", LOGS_PAGE)
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));

    Html(html).into_response()
}
