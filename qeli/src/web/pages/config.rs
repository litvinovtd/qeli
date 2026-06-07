use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const CONFIG_PAGE: &str = include_str!("../templates/config.html");

pub async fn config_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed(&headers, &state.config.web) {
        return Redirect::to("/login").into_response();
    }

    let config_json = serde_json::to_string_pretty(&state.config).unwrap_or_default();
    let content = CONFIG_PAGE.replace("{{config_json}}", &config_json);

    let html = LAYOUT
        .replace("{{title}}", "Configuration")
        .replace("{{page}}", "config")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", &content);

    Html(html).into_response()
}
