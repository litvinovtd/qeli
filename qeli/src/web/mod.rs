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

/// Normalize a base-path prefix to canonical form: "" (root) or "/qeli" (leading
/// slash, no trailing slash).
pub fn norm_prefix(s: &str) -> String {
    let t = s.trim().trim_end_matches('/');
    if t.is_empty() {
        String::new()
    } else {
        format!("/{}", t.trim_start_matches('/'))
    }
}

/// `<base href>` value for a prefix: "/" for the root, "/qeli/" otherwise.
fn base_href(prefix: &str) -> String {
    if prefix.is_empty() {
        "/".to_string()
    } else {
        format!("{prefix}/")
    }
}

/// True if a forwarded prefix is an ordinary URL path and therefore safe to
/// interpolate into `<base href="...">`.
///
/// SECURITY: the prefix comes from a request header and is substituted into an HTML
/// attribute with NO escaping (the panel renders plain HTML — there is no templating
/// engine to escape for us), while the CSP allows `'unsafe-inline'`. A value carrying
/// a `"` could therefore close the attribute and inject a `<script>`. Legitimate base
/// paths are plain path characters, so allowlist those and ignore anything else.
fn is_safe_prefix(s: &str) -> bool {
    s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~' | '%'))
}

/// Effective sub-path prefix for a request: a TRUSTED proxy's `X-Forwarded-Prefix`
/// wins, else the configured `web.base_path`; the result is normalized.
///
/// The header is only honored when the socket peer is a configured trusted reverse
/// proxy — mirroring [`effective_client_ip`] / [`forwarded_https`]. A directly-exposed
/// panel must not let any client dictate its base path. A syntactically unsafe value
/// is ignored as well, so the fallback is always the operator-controlled `base_path`.
fn req_prefix(
    headers: &HeaderMap,
    cfg_base: &str,
    peer: Option<IpAddr>,
    trusted: &[String],
) -> String {
    let from_proxy = match peer {
        Some(ip) if !trusted.is_empty() && ip_allowed(ip, trusted) => headers
            .get("x-forwarded-prefix")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter(|s| is_safe_prefix(s))
            .map(|s| s.to_string()),
        _ => None,
    };
    norm_prefix(&from_proxy.unwrap_or_else(|| cfg_base.to_string()))
}

/// Make the panel work under a reverse-proxy sub-path without touching handlers:
/// fill `{{basehref}}` in HTML pages with the request's prefix (so relative
/// asset/API/nav URLs re-root via `<base href>`), and prepend the prefix to
/// root-absolute `Location` redirects (which `<base>` cannot re-root).
async fn base_path_rewrite(
    State(state): State<Arc<ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let trusted = state.live_web.read().await.trusted_proxies.clone();
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let prefix = req_prefix(req.headers(), &state.config.web.base_path, peer, &trusted);
    let resp = next.run(req).await;
    let (mut parts, body) = resp.into_parts();

    if !prefix.is_empty() {
        if let Some(loc) = parts.headers.get(header::LOCATION) {
            if let Ok(s) = loc.to_str() {
                let already = s == prefix || s.starts_with(&format!("{prefix}/"));
                if s.starts_with('/') && !already {
                    if let Ok(v) = HeaderValue::from_str(&format!("{prefix}{s}")) {
                        parts.headers.insert(header::LOCATION, v);
                    }
                }
            }
        }
    }

    let is_html = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("text/html"))
        .unwrap_or(false);
    if !is_html {
        return Response::from_parts(parts, body);
    }
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };
    let html = String::from_utf8_lossy(&bytes).replace("{{basehref}}", &base_href(&prefix));
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(html))
}

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

    // Live web settings (public_host / allowed_origins are hot-reloadable). Cloned
    // so no read guard is held across the downstream `next.run(req).await`.
    let web_cfg = state.live_web.read().await.clone();
    // Opt-out (web.csrf=false): skip the same-origin check entirely. Only sane on a
    // loopback-only bind; a loud startup warning is logged when it is disabled.
    if !web_cfg.csrf {
        return Ok(next.run(req).await);
    }
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
        if allowed_hosts.iter().any(|h| host_port == h.as_str()) {
            return true;
        }
        // Trust any loopback Origin regardless of port. A remote page cannot forge a
        // loopback Origin (the browser sets Origin to its own page's origin), so this is
        // safe against cross-site CSRF while covering the common case of reaching the
        // panel over an SSH port-forward at localhost:<other-port> — which otherwise
        // never matches the panel's own port and 403s every mutating request.
        let host = if let Some(end) = host_port.find(']') {
            &host_port[..=end] // bracketed IPv6 literal ("[::1]:8080" -> "[::1]")
        } else {
            host_port.split(':').next().unwrap_or(host_port) // strip ":port"
        };
        matches!(host, "127.0.0.1" | "localhost" | "[::1]")
    };

    // Gate on whether this looks like a BROWSER request, not on whether a session
    // cookie is present.
    //
    // The old rule ("no cookie → can't be CSRF") had two holes. (1) In passwordless
    // mode `AuthGuard` passes with no cookie at all, so every mutating request skipped
    // the check — a page the operator visits could drive restart / identity-rotate /
    // restore against a loopback panel. (2) Browsers DO cache HTTP Basic credentials
    // per-origin and re-attach them to cross-site-initiated same-origin requests, so
    // the "Basic is never auto-attached" assumption was wrong in password mode too.
    //
    // A browser ALWAYS sends Origin on a cross-origin state-changing request (and a
    // Referer on form navigations), while a CLI/API client (curl, scripts) sends
    // neither — so "has Origin or Referer ⇒ must be same-origin" closes both holes
    // without breaking non-browser clients.
    if raw.is_none() {
        return Ok(next.run(req).await);
    }

    match raw {
        Some(v) if host_matches(v) => Ok(next.run(req).await),
        _ => {
            log::warn!(
                "CSRF: rejected {} {} (origin/referer={:?})",
                method,
                req.uri(),
                raw
            );
            // Helpful 403 (text/plain) instead of a silent forbidden: tell the admin
            // WHICH origin was rejected and how to allow it. A reverse proxy, a
            // different port, or an SSH port-forward changes the browser's Origin
            // host:port; adding it to web.allowed_origins fixes it without weakening CSRF.
            let origin = raw
                .map(|s| {
                    let after = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
                    after.split('/').next().unwrap_or(s)
                })
                .unwrap_or("(no Origin/Referer header)");
            let body = format!(
                "403 CSRF: request blocked — the browser Origin/Referer '{origin}' does \
                 not match the panel's address.\n\n\
                 If you reach the panel through a reverse proxy, a different port, or an \
                 SSH port-forward, add that origin to `allowed_origins` in the [web] \
                 config, e.g.:\n\n    [web]\n    allowed_origins = {origin}\n\n\
                 then reload the panel. (CSRF protection stops other websites from \
                 driving your logged-in panel — see docs/CONFIG.md.)\n"
            );
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            Ok(resp)
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

/// The client IP to enforce against (allowlist + brute-force limiter).
///
/// When the socket peer is a configured trusted reverse proxy, walk `X-Forwarded-For`
/// from the RIGHT and skip every hop that is itself a trusted proxy; the first address
/// that is not one is the real client. Everything further left is appended by hops we
/// do not trust, so it is attacker-controlled and must be ignored.
///
/// Taking the rightmost entry outright — which is what this did — is only correct with
/// exactly ONE proxy in front. With a chain (edge CDN → local nginx → qeli) the
/// rightmost entry is the INNER proxy's own address, so every client collapsed into one
/// bucket: the source allowlist matched on the proxy instead of the user, and the
/// brute-force limiter counted the whole world as a single IP (lock one out, lock
/// everyone out — and a distributed guesser never trips it at all).
///
/// Otherwise the socket peer is authoritative and the header is ignored, so a
/// directly-exposed panel cannot be spoofed with a forged XFF.
pub(crate) fn effective_client_ip(
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    trusted_proxies: &[String],
) -> std::net::IpAddr {
    if trusted_proxies.is_empty() || !ip_allowed(peer, trusted_proxies) {
        return peer;
    }
    let Some(chain) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer;
    };
    for hop in chain.rsplit(',') {
        let Ok(ip) = hop.trim().parse::<std::net::IpAddr>() else {
            // An unparsable entry means the chain cannot be trusted past this point —
            // stop rather than reach further left into forgeable territory.
            return peer;
        };
        if !ip_allowed(ip, trusted_proxies) {
            return ip;
        }
    }
    // Every hop was a trusted proxy (or the header was empty): nothing identifies the
    // client, so fall back to the socket peer.
    peer
}

/// True when the request reached us over HTTPS via a TRUSTED reverse proxy
/// (`X-Forwarded-Proto: https` and the socket peer is in `trusted_proxies`). Used to
/// mark the session cookie `Secure` automatically behind a TLS-terminating proxy, so
/// the operator no longer has to set `web.secure_cookie` by hand. Gated on the proxy
/// being trusted — otherwise a forged header on a plain-HTTP bind could set `Secure`
/// and lock the operator out (the browser would refuse to resend the cookie).
pub(crate) fn forwarded_https(
    headers: &HeaderMap,
    peer: std::net::IpAddr,
    trusted_proxies: &[String],
) -> bool {
    if trusted_proxies.is_empty() || !ip_allowed(peer, trusted_proxies) {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|p| p.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
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
    // Live allowlist (hot-reloadable). Cloned so no read guard is held across
    // the downstream `next.run(req).await`.
    let (allowed, trusted) = {
        let w = state.live_web.read().await;
        (w.allowed_ips.clone(), w.trusted_proxies.clone())
    };
    if allowed.is_empty() {
        return Ok(next.run(req).await);
    }
    let effective = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| effective_client_ip(req.headers(), ci.0.ip(), &trusted));
    match effective {
        Some(ip) if ip_allowed(ip, &allowed) => Ok(next.run(req).await),
        _ => {
            log::warn!(
                "panel: blocked request from {:?} (not in web.allowed_ips)",
                effective
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
        // `connect-src` also allows api.github.com: the opt-in update check runs in the
        // OPERATOR'S BROWSER by design (so the server never phones home and the admin's
        // IP is the only one GitHub sees), but `'self'` alone silently blocked it — the
        // request died at the CSP and the empty catch() swallowed it, so `update_check`
        // never worked and failed invisibly. Nothing else fetches cross-origin.
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
             connect-src 'self' https://api.github.com; frame-ancestors 'none'; \
             base-uri 'self'; form-action 'self'",
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

    // Fail closed: never serve an admin panel with NO password. Loopback used to be
    // exempt, which made "no password set yet" indistinguishable from "no password
    // wanted" — and an open panel on 127.0.0.1 is still full admin for every local
    // process, and for anything on the host that can be induced to make a request on
    // someone else's behalf (SSRF).
    if web_cfg.password_hash.is_empty() && !web_cfg.insecure_no_auth {
        log::error!(
            "Web panel NOT started: bind {addr} has NO admin password (web.password_hash \
             empty). Set one with `qeli set-web-password`, or — only if an unauthenticated \
             panel is genuinely what you want — set web.insecure_no_auth = true."
        );
        return;
    }
    if web_cfg.password_hash.is_empty() {
        log::warn!(
            "Web panel on {addr} is running WITHOUT AUTHENTICATION (web.insecure_no_auth): \
             every local process — and any SSRF on this host — has full admin access to \
             users, password hashes and the configuration."
        );
    }
    if !is_loopback && !web_cfg.tls {
        log::warn!(
            "Web panel on non-loopback {addr} WITHOUT TLS (web.tls=false) — admin \
             credentials/session transit in cleartext. Enable web.tls or front it with HTTPS."
        );
    }
    if !web_cfg.csrf {
        log::warn!(
            "Web panel CSRF protection is DISABLED (web.csrf=false){}. Any website you \
             open in the same browser can drive this logged-in panel — only acceptable on \
             a loopback-only bind reached via an SSH forward.",
            if is_loopback {
                ""
            } else {
                " on a NON-loopback bind — DANGEROUS"
            }
        );
    }
    if !web_cfg.allowed_ips.is_empty() {
        log::info!(
            "Web panel source-IP allowlist active ({} entries)",
            web_cfg.allowed_ips.len()
        );
    }
    if web_cfg
        .trusted_proxies
        .iter()
        .any(|p| p.trim().ends_with("/0"))
    {
        log::warn!(
            "web.trusted_proxies contains a /0 (all-addresses) entry — ANY peer's \
             X-Forwarded-For is then trusted, letting a client spoof its source IP past the \
             allowlist / brute-force limiter. Narrow it to your actual reverse-proxy address."
        );
    }

    let api_router = api::routes().route_layer(middleware::from_fn_with_state(
        state.clone(),
        csrf_same_origin,
    ));

    let routes = Router::new()
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
        .route("/blocked", axum::routing::get(pages::blocked::blocked_page))
        .route(
            "/notifications",
            axum::routing::get(pages::notifications::notifications),
        )
        .nest("/api", api_router);

    // Reverse-proxy sub-path: when `web.base_path` is set (e.g. "/qeli"), mount the
    // whole panel under it so upstream paths line up; `base_path_rewrite` fills
    // {{basehref}} and prefixes redirects. Empty = served at the root (unchanged).
    let base = norm_prefix(&web_cfg.base_path);
    let routes = if base.is_empty() {
        routes
    } else {
        Router::new().nest(&base, routes)
    };

    let app = routes
        // Innermost: post-processes handler responses for the sub-path.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            base_path_rewrite,
        ))
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
    use super::{effective_client_ip, HeaderMap};
    use axum::{routing::get, Router};

    /// SECURITY: `{{basehref}}` is substituted into `<base href="...">` with no HTML
    /// escaping and the CSP allows 'unsafe-inline', so an attribute breakout in the
    /// forwarded prefix would execute script. Anything but a plain URL path is refused.
    #[test]
    fn unsafe_forwarded_prefix_is_rejected() {
        assert!(super::is_safe_prefix("/qeli"));
        assert!(super::is_safe_prefix("qeli/panel"));
        assert!(super::is_safe_prefix("a-b_c.d~e%20f"));
        // The attribute-breakout payload and its ingredients.
        assert!(!super::is_safe_prefix("x\"><script>alert(1)</script>"));
        assert!(!super::is_safe_prefix("a\"b"));
        assert!(!super::is_safe_prefix("a<b"));
        assert!(!super::is_safe_prefix("a>b"));
        assert!(!super::is_safe_prefix("a b"));
        assert!(!super::is_safe_prefix(&"x".repeat(129)));
    }

    /// The header only counts from a configured trusted proxy — a directly-exposed
    /// panel must not let any caller dictate its base path (mirrors effective_client_ip).
    #[test]
    fn forwarded_prefix_ignored_from_untrusted_peer() {
        use axum::http::HeaderMap;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-prefix", "/evil".parse().unwrap());
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();

        // No trusted proxies configured -> header ignored, configured base wins.
        assert_eq!(super::req_prefix(&h, "/cfg", Some(peer), &[]), "/cfg");
        // Peer not in the trusted list -> ignored too.
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(super::req_prefix(&h, "/cfg", Some(peer), &trusted), "/cfg");
        // Peer IS the trusted proxy -> honored.
        let trusted = vec!["203.0.113.9".to_string()];
        assert_eq!(super::req_prefix(&h, "/cfg", Some(peer), &trusted), "/evil");
        // Trusted proxy but an unsafe value -> still falls back to the configured base.
        let mut bad = HeaderMap::new();
        bad.insert("x-forwarded-prefix", "x\"><script>".parse().unwrap());
        assert_eq!(
            super::req_prefix(&bad, "/cfg", Some(peer), &trusted),
            "/cfg"
        );
    }

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

    #[test]
    fn xff_strips_every_trusted_hop_not_just_the_last() {
        // edge CDN → local nginx → qeli. The header the innermost proxy hands us is
        // "client, cdn-edge"; the socket peer is nginx. Taking the rightmost entry
        // yielded the CDN edge, so every visitor shared one bucket.
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "203.0.113.9, 198.51.100.7".parse().unwrap(),
        );
        let nginx: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = vec!["10.0.0.2".to_string(), "198.51.100.0/24".to_string()];
        assert_eq!(
            effective_client_ip(&h, nginx, &trusted),
            "203.0.113.9".parse::<std::net::IpAddr>().unwrap(),
            "the first non-proxy hop from the right is the real client"
        );
    }

    #[test]
    fn xff_with_one_proxy_still_yields_the_client() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let proxy: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(
            effective_client_ip(&h, proxy, &["10.0.0.2".to_string()]),
            "203.0.113.9".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_from_an_untrusted_peer_is_ignored() {
        // A directly-exposed panel must not be spoofable by a forged header.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let attacker: std::net::IpAddr = "198.51.100.66".parse().unwrap();
        assert_eq!(
            effective_client_ip(&h, attacker, &["10.0.0.2".to_string()]),
            attacker
        );
    }

    #[test]
    fn xff_that_is_all_trusted_hops_falls_back_to_the_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.3".parse().unwrap());
        let proxy: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = vec!["10.0.0.0/24".to_string()];
        assert_eq!(effective_client_ip(&h, proxy, &trusted), proxy);
    }
}
