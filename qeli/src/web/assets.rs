//! Self-hosted static assets for the panel (CSS / Alpine.js / fonts), embedded
//! into the binary with `include_*!` and served from `/assets/*`. The panel has
//! NO runtime CDN dependency, so it works on an air-gapped server reached over
//! an SSH tunnel. Regenerate `assets/app.css` with `cd web-assets && npm run build`.

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const APP_CSS: &str = include_str!("assets/app.css");
const ALPINE_JS: &str = include_str!("assets/alpine.js");
const I18N_JS: &str = include_str!("assets/i18n.js");

/// Cache-busting token for the CSS/JS asset URLs. The asset URLs are stable
/// (`/assets/app.css`), so a stale immutable copy can survive even a hard reload;
/// appending `?v=<this>` to the links changes the URL whenever any asset's content
/// changes, forcing browsers to fetch the new version. Derived from the asset
/// sizes (changes on every rebuild that touches CSS/JS).
pub fn asset_ver() -> String {
    format!(
        "{:x}",
        APP_CSS
            .len()
            .wrapping_mul(1000003)
            .wrapping_add(ALPINE_JS.len().wrapping_mul(31))
            .wrapping_add(I18N_JS.len())
    )
}
const INTER_400: &[u8] = include_bytes!("assets/fonts/inter-400.woff2");
const INTER_500: &[u8] = include_bytes!("assets/fonts/inter-500.woff2");
const INTER_600: &[u8] = include_bytes!("assets/fonts/inter-600.woff2");
const INTER_700: &[u8] = include_bytes!("assets/fonts/inter-700.woff2");
const INTER_800: &[u8] = include_bytes!("assets/fonts/inter-800.woff2");
const JBMONO_400: &[u8] = include_bytes!("assets/fonts/jbmono-400.woff2");
const JBMONO_600: &[u8] = include_bytes!("assets/fonts/jbmono-600.woff2");

/// Serve an embedded asset by its `/assets/<path>` tail.
///
/// Caching is split by asset kind because the URLs are NOT content-addressed
/// (stable names like `/assets/app.css`): the CSS/JS change with every build, so
/// they must be served `no-cache` (revalidate each load) — otherwise an updated
/// panel stays invisible until the user hard-refreshes. Fonts never change, so
/// they keep the long immutable lifetime.
pub async fn asset(Path(path): Path<String>) -> Response {
    let (body, ctype): (&'static [u8], &'static str) = match path.as_str() {
        "app.css" => (APP_CSS.as_bytes(), "text/css; charset=utf-8"),
        "alpine.js" => (
            ALPINE_JS.as_bytes(),
            "application/javascript; charset=utf-8",
        ),
        "i18n.js" => (I18N_JS.as_bytes(), "application/javascript; charset=utf-8"),
        "inter-400.woff2" => (INTER_400, "font/woff2"),
        "inter-500.woff2" => (INTER_500, "font/woff2"),
        "inter-600.woff2" => (INTER_600, "font/woff2"),
        "inter-700.woff2" => (INTER_700, "font/woff2"),
        "inter-800.woff2" => (INTER_800, "font/woff2"),
        "jbmono-400.woff2" => (JBMONO_400, "font/woff2"),
        "jbmono-600.woff2" => (JBMONO_600, "font/woff2"),
        _ => return (StatusCode::NOT_FOUND, "asset not found").into_response(),
    };
    // Fonts are immutable; CSS/JS share a stable URL but change per build, so they
    // must revalidate or panel updates won't show without a hard refresh.
    let cache = if ctype == "font/woff2" {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(ctype)),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        body,
    )
        .into_response()
}
