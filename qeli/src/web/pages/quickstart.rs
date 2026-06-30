use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const QUICKSTART_PAGE: &str = include_str!("../templates/quickstart.html");

pub async fn quickstart(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &state.config.web) {
        return Redirect::to("/login").into_response();
    }

    let html = LAYOUT
        .replace("{{title}}", "Quick start")
        .replace("{{assetver}}", &crate::server::web::assets::asset_ver())
        .replace("{{page}}", "quickstart")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", QUICKSTART_PAGE);

    Html(html).into_response()
}
