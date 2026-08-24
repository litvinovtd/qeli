use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::sync::Arc;

const LAYOUT: &str = include_str!("../templates/layout.html");
const CONFIG_PAGE: &str = include_str!("../templates/config.html");

pub async fn config_page(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !auth::is_authed_cookie_only(&headers, &*state.live_web.read().await) {
        return Redirect::to("/login").into_response();
    }

    // The config page fetches its data over /api/config at runtime, so the
    // template no longer carries an inlined config snapshot.
    let html = LAYOUT
        .replace("{{title}}", "Configuration")
        .replace("{{assetver}}", &crate::server::web::assets::asset_ver())
        .replace("{{page}}", "config")
        .replace("{{version}}", env!("CARGO_PKG_VERSION"))
        .replace("{{content}}", CONFIG_PAGE);

    Html(html).into_response()
}

#[cfg(test)]
mod tests {
    use super::CONFIG_PAGE;

    #[test]
    fn profile_tabs_use_semantic_transport_svg_icons() {
        assert!(CONFIG_PAGE.contains(r#"data-transport-icon="tcp""#));
        assert!(CONFIG_PAGE.contains(r#"data-transport-icon="udp""#));
        assert!(CONFIG_PAGE.contains(r#"aria-label="TCP""#));
        assert!(CONFIG_PAGE.contains(r#"aria-label="UDP""#));
        assert!(!CONFIG_PAGE.contains("profileIcon("));
        assert!(!CONFIG_PAGE.contains("📡"));
        assert!(!CONFIG_PAGE.contains("🔒"));
    }
}
