use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const USERS_PAGE: &str = include_str!("../templates/users.html");

pub async fn users_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &state.config.web) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Users")
        .replace("{{page}}", "users")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", USERS_PAGE);

    Html(html).into_response()
}
