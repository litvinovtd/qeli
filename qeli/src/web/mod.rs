pub mod api;
pub mod assets;
pub mod auth;
pub mod pages;
pub mod tls;

use crate::server::ServerState;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Normalize a configured origin (`host`, `host:port`, or a full
/// `https://host:port/path` URL) to the `host[:port]` form the CSRF check compares
/// against, pushing it into `out`. When the entry carries no explicit port the
/// panel's own `port` variant is added too, so a value like `panel.example.com`
/// matches both a reverse-proxied HTTPS origin (no port) and direct access on the
/// bind port.
fn push_origin_variants(out: &mut Vec<String>, raw: &str, port: u16) {
    let s = raw.trim();
    if s.is_empty() {
        return;
    }
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host_port = after_scheme.split('/').next().unwrap_or("").trim();
    if host_port.is_empty() {
        return;
    }
    // Bracketed IPv6 carries a port only after `]:`; otherwise a lone `:` is the port.
    let has_port = match host_port.strip_prefix('[') {
        Some(rest) => rest.contains("]:"),
        None => host_port.contains(':'),
    };
    out.push(host_port.to_string());
    if !has_port {
        out.push(format!("{host_port}:{port}"));
    }
}

/// Reject mutating requests whose Origin/Referer doesn't match the server's
/// own bind. Browsers send these headers automatically for fetch/XHR/form
/// submissions, so a malicious page cannot trick a logged-in admin into a
/// state-changing request.
async fn csrf_same_origin(
    State(state): State<Arc<ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    if matches!(&method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(next.run(req).await);
    }

    let web_cfg = &state.config.web;
    let port = web_cfg.port;
    // IPv6 literals must be bracketed in a Host/Origin (`[::1]:8080`), so format
    // the bind accordingly and always allow the IPv6 loopback too.
    let bind_host = if web_cfg.bind.contains(':') {
        format!("[{}]:{}", web_cfg.bind, port)
    } else {
        format!("{}:{}", web_cfg.bind, port)
    };
    let mut allowed_hosts = vec![
        bind_host,
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ];
    // A panel reached via a domain / reverse proxy has an Origin host that differs
    // from `bind`; without these it loads but every mutating request 403s. Allow the
    // configured public host plus any explicit `allowed_origins`.
    push_origin_variants(&mut allowed_hosts, &web_cfg.public_host, port);
    for o in &web_cfg.allowed_origins {
        push_origin_variants(&mut allowed_hosts, o, port);
    }

    let headers: &HeaderMap = req.headers();
    let raw = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok());

    let host_matches = |s: &str| -> bool {
        let after_scheme = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
        let host_port = after_scheme.split('/').next().unwrap_or("");
        allowed_hosts.iter().any(|h| host_port == h.as_str())
    };

    match raw {
        Some(v) if host_matches(v) => Ok(next.run(req).await),
        _ => {
            log::warn!(
                "CSRF: rejected {} {} (origin/referer={:?})",
                method,
                req.uri(),
                raw
            );
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// True if `ip` matches any entry in `list` (each a CIDR like `1.2.3.0/24` or a
/// bare IP). Used by the panel's source-IP allowlist.
fn ip_allowed(ip: IpAddr, list: &[String]) -> bool {
    list.iter().any(|e| {
        let e = e.trim();
        if let Ok(net) = e.parse::<ipnet::IpNet>() {
            net.contains(&ip)
        } else if let Ok(single) = e.parse::<IpAddr>() {
            single == ip
        } else {
            false
        }
    })
}

/// Restrict the panel to an operator-defined set of source IPs/CIDRs. When the
/// allowlist is empty the panel is open to any source (relies on TLS + auth).
/// Applies to every route (pages, assets, API) — the first line of defence for a
/// publicly-bound panel.
async fn ip_allowlist(
    State(state): State<Arc<ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let allowed = &state.config.web.allowed_ips;
    if allowed.is_empty() {
        return Ok(next.run(req).await);
    }
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    match peer {
        Some(ip) if ip_allowed(ip, allowed) => Ok(next.run(req).await),
        _ => {
            log::warn!(
                "panel: blocked request from {:?} (not in web.allowed_ips)",
                peer
            );
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Add hardening response headers to every panel response (HSTS only when the
/// panel itself serves TLS). The CSP keeps everything same-origin while allowing
/// the inline/eval Alpine.js the panel relies on.
async fn security_headers(
    State(state): State<Arc<ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let tls = state.config.web.tls;
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    if tls {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000"),
        );
    }
    resp
}

pub async fn start(state: Arc<ServerState>) {
    // Owned clone so the config outlives `state` (moved into the router below).
    let web_cfg = state.config.web.clone();
    let addr = format!("{}:{}", web_cfg.bind, web_cfg.port);

    let bind = web_cfg.bind.as_str();
    let is_loopback = matches!(bind, "127.0.0.1" | "::1" | "[::1]" | "localhost");

    // Fail closed: never serve an admin panel with NO password on a public bind.
    // (The VPN data plane is a separate worker process and is unaffected.)
    if !is_loopback && web_cfg.password_hash.is_empty() {
        log::error!(
            "Web panel NOT started: non-loopback bind {addr} with NO admin password \
             (web.password_hash empty). Set an argon2id password — refusing to serve an \
             open admin panel on a public interface."
        );
        return;
    }
    if !is_loopback && !web_cfg.tls {
        log::warn!(
            "Web panel on non-loopback {addr} WITHOUT TLS (web.tls=false) — admin \
             credentials/session transit in cleartext. Enable web.tls or front it with HTTPS."
        );
    }
    if !web_cfg.allowed_ips.is_empty() {
        log::info!(
            "Web panel source-IP allowlist active ({} entries)",
            web_cfg.allowed_ips.len()
        );
    }

    let api_router = api::routes().route_layer(middleware::from_fn_with_state(
        state.clone(),
        csrf_same_origin,
    ));

    let app = Router::new()
        .route("/", axum::routing::get(pages::dashboard::dashboard))
        .route(
            "/quickstart",
            axum::routing::get(pages::quickstart::quickstart),
        )
        // Self-hosted CSS / JS / fonts (no runtime CDN). Public (the login page
        // needs them too) and GET-only, so they sit outside the API/CSRF layer.
        .route("/assets/{file}", axum::routing::get(assets::asset))
        .route("/login", axum::routing::get(pages::login::login_page))
        .route("/users", axum::routing::get(pages::users::users_page))
        .route("/config", axum::routing::get(pages::config::config_page))
        .route("/client", axum::routing::get(pages::client::client_page))
        .route("/logs", axum::routing::get(pages::logs::logs_page))
        .route(
            "/notifications",
            axum::routing::get(pages::notifications::notifications),
        )
        .nest("/api", api_router)
        // Security headers wrap everything (outermost), so even an allowlist 403
        // carries them; the IP allowlist runs before any handler. (Layers apply
        // bottom-up: the last `.layer` added is the outermost.)
        .layer(middleware::from_fn_with_state(state.clone(), ip_allowlist))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state);

    // `into_make_service_with_connect_info` exposes the peer SocketAddr to
    // handlers/middleware (login rate-limit + IP allowlist).
    let make = app.into_make_service_with_connect_info::<SocketAddr>();

    if web_cfg.tls {
        let tls_cfg = match tls::build_server_config(&web_cfg) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Web panel TLS init failed: {e} — panel not started");
                return;
            }
        };
        let sockaddr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                log::error!("Web panel bind '{addr}' is not a socket address: {e}");
                return;
            }
        };
        log::info!("Web UI (HTTPS) listening on https://{}", addr);
        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(tls_cfg);
        axum_server::bind_rustls(sockaddr, rustls_cfg)
            .serve(make)
            .await
            .ok();
    } else {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                log::info!("Web UI listening on http://{}", addr);
                axum::serve(l, make).await.ok();
            }
            Err(e) => log::error!("Web UI failed to bind {}: {}", addr, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{routing::get, Router};

    /// Building a router with an invalid path pattern panics at *runtime* (router
    /// construction), which `cargo build`/`clippy` do NOT catch — exactly how a
    /// bad `/assets/{*path}` catch-all once crash-looped the live server. This
    /// test reproduces the router build so such a regression fails the gate.
    #[test]
    fn route_patterns_are_valid() {
        // Mirror the exact router `start()` builds: page routes + the public
        // asset route at the root, with the API nested under `/api` (so a page
        // route like `/config` doesn't clash with `/api/config`).
        let _app: Router<std::sync::Arc<crate::server::ServerState>> = Router::new()
            .route("/", get(|| async {}))
            .route("/assets/{file}", get(super::assets::asset))
            .route("/login", get(|| async {}))
            .route("/users", get(|| async {}))
            .route("/config", get(|| async {}))
            .route("/logs", get(|| async {}))
            .nest("/api", super::api::routes());
    }

    /// A built router can still *match* nothing if the param syntax is wrong for
    /// the axum/matchit version in use (brace `{file}` under axum-0.7 matches
    /// literally → real asset URLs 404, leaving the panel with no CSS/JS). Drive
    /// a real request through the asset route and assert the filename is captured
    /// and served — guards against that silent regression.
    #[tokio::test]
    async fn assets_route_captures_filename() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // oneshot

        let app: Router = Router::new().route("/assets/{file}", get(super::assets::asset));
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets/app.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK, "known asset must be served");

        let missing = app
            .oneshot(
                Request::builder()
                    .uri("/assets/does-not-exist.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            missing.status(),
            StatusCode::NOT_FOUND,
            "unknown asset 404s (route matched, handler returned 404)"
        );
    }

    #[test]
    fn origin_variants_normalize_for_reverse_proxy() {
        let mut v = Vec::new();
        // A full URL is reduced to host:port; a bare host (no port) ALSO yields the
        // panel-port variant so it matches both a reverse-proxied HTTPS origin (no
        // port in Origin) and direct access on the bind port.
        super::push_origin_variants(&mut v, "https://panel.example.com/admin", 8080);
        super::push_origin_variants(&mut v, "panel.example.com", 8080);
        super::push_origin_variants(&mut v, "1.2.3.4:9443", 8080);
        super::push_origin_variants(&mut v, "  ", 8080); // ignored
        assert!(v.contains(&"panel.example.com".to_string()));
        assert!(v.contains(&"panel.example.com:8080".to_string()));
        assert!(v.contains(&"1.2.3.4:9443".to_string()));
        // explicit port must NOT also get the panel-port variant
        assert!(!v.contains(&"1.2.3.4:9443:8080".to_string()));
        // blank entry added nothing extra
        assert_eq!(v.iter().filter(|s| s.is_empty()).count(), 0);
    }
}
