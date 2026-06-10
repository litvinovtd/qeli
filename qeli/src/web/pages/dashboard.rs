use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const DASHBOARD: &str = include_str!("../templates/dashboard.html");

pub async fn dashboard(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed(&headers, &state.config.web).await {
        return Redirect::to("/login").into_response();
    }

    let content = DASHBOARD.replace("{{version}}", env!("CARGO_PKG_VERSION"));

    let html = LAYOUT
        .replace("{{title}}", "Dashboard")
        .replace("{{page}}", "dashboard")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", &content);

    Html(html).into_response()
}
