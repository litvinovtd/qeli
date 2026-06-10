use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LOGIN_PAGE: &str = include_str!("../templates/login.html");

/// Serve the login form. If the request is already authenticated, bounce to the
/// dashboard instead of showing the form.
pub async fn login_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if auth::is_authed(&headers, &state.config.web).await {
        return Redirect::to("/").into_response();
    }
    Html(LOGIN_PAGE.to_string()).into_response()
}
