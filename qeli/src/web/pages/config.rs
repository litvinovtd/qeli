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
    fn profile_navigation_wraps_and_uses_text_transport_badges() {
        assert!(CONFIG_PAGE.contains("config-profile-nav"));
        assert!(CONFIG_PAGE.contains("transport-kind-tcp"));
        assert!(CONFIG_PAGE.contains("transport-kind-udp"));
        assert!(CONFIG_PAGE.contains("? 'UDP' : 'TCP'"));
        assert!(!CONFIG_PAGE.contains("data-transport-icon"));
        assert!(!CONFIG_PAGE.contains("overflow-x-auto"));
        assert!(!CONFIG_PAGE.contains("profileIcon("));
        assert!(!CONFIG_PAGE.contains("📡"));
        assert!(!CONFIG_PAGE.contains("🔒"));
    }

    #[test]
    fn profile_form_exposes_lossless_roaming_policy() {
        assert!(CONFIG_PAGE.contains("id=\"sec-roaming\""));
        assert!(CONFIG_PAGE.contains("cfg.profiles[activeTab].roaming.enabled"));
        assert!(CONFIG_PAGE.contains("cfg.profiles[activeTab].roaming.grace_secs"));
        assert!(CONFIG_PAGE.contains("cfg.profiles[activeTab].roaming.max_orphaned"));
        assert!(CONFIG_PAGE.contains("roamingMaxMiB(cfg.profiles[activeTab])"));
        assert!(CONFIG_PAGE.contains("profile.roaming.max_orphan_bytes = mib * 1048576"));
        // Existing missing fields stay upgrade-compatible; the new-profile fallback is on.
        assert!(CONFIG_PAGE.contains("roaming: { enabled: true, grace_secs: 30, max_orphaned: 256, max_orphan_bytes: 67108864 }"));
        assert!(CONFIG_PAGE.contains("roaming: { enabled: false, grace_secs: 30, max_orphaned: 256, max_orphan_bytes: 67108864 }"));
        assert!(CONFIG_PAGE.contains("New profiles enable it by default"));
    }
}
