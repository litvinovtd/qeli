//! Outbound notifications (Tier-3): Telegram bot + generic webhook.
//!
//! Config lives in `/etc/qeli/notify.ini`, so panel edits need no main-config reload, and
//! both the supervisor (server-start / login-lockout / restore events) and the
//! worker can read it independently. Each process owns a bounded delivery queue;
//! admission never waits for network I/O and shutdown has a total drain deadline.
//! Outbound HTTPS reuses the existing rustls(ring) stack + the Mozilla root bundle (webpki-roots) so
//! certificates are properly verified — no MITM hole for the notification path.

pub use crate::config::notify::{ChannelEvents, ConditionalSave, NotifyConfig};
use crate::notify_tasks::DeliveryQueue;
#[cfg(target_os = "linux")]
use crate::server::usage;
#[cfg(all(test, not(target_os = "linux")))]
use crate::server_usage as usage;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sidecar config file (qeli-owned, beside the main config).
pub const NOTIFY_PATH: &str = "/etc/qeli/notify.ini";
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DELIVERIES: usize = 128; // Includes waiting and active requests, across both channels.
const MAX_ACTIVE: usize = 8;
const MAX_DETAIL: usize = 2048;
const MAX_SERVER_NAME: usize = 256;
const MAX_PAYLOAD: usize = 32 * 1024;
static DELIVERY: OnceLock<Mutex<Weak<DeliveryQueue>>> = OnceLock::new();

/// Scoped process owner. The global lookup is weak; drop cancels outstanding sends,
/// normal shutdown joins them, and a later generation can register a fresh service.
pub struct Runtime {
    queue: Arc<DeliveryQueue>,
}
impl Runtime {
    pub fn request_shutdown(&self) {
        self.queue.request_shutdown();
    }

    pub async fn shutdown(&self) {
        self.queue.shutdown().await;
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.queue.abort();
    }
}
pub fn start() -> anyhow::Result<Runtime> {
    let mut slot = DELIVERY
        .get_or_init(|| Mutex::new(Weak::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    anyhow::ensure!(
        slot.upgrade().is_none(),
        "notification service already owned"
    );
    let queue = Arc::new(DeliveryQueue::new(MAX_DELIVERIES, MAX_ACTIVE, SEND_TIMEOUT));
    *slot = Arc::downgrade(&queue);
    Ok(Runtime { queue })
}
fn delivery_queue() -> Option<Arc<DeliveryQueue>> {
    DELIVERY
        .get()?
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .upgrade()
}

fn bounded_text(text: &str, limit: usize) -> &str {
    &text[..text.floor_char_boundary(limit.min(text.len()))]
}

fn validate_telegram_fields(cfg: &NotifyConfig) -> Result<(), String> {
    if cfg.telegram_token.is_empty() || cfg.telegram_chat_id.is_empty() {
        return Err("set the bot token and chat id first".into());
    }
    if cfg.telegram_token.len() > 512 || cfg.telegram_chat_id.len() > 128 {
        return Err("Telegram token/chat id exceeds 512/128 bytes".into());
    }
    Ok(())
}
fn validate_webhook_fields(cfg: &NotifyConfig) -> Result<(), String> {
    if cfg.webhook_url.len() > 4096 {
        return Err("webhook URL exceeds 4096 bytes".into());
    }
    parse_url(&cfg.webhook_url)?;
    Ok(())
}

enum Delivery {
    Telegram {
        token: String,
        chat: String,
        text: String,
    },
    Webhook {
        url: String,
        body: String,
    },
}
impl Delivery {
    async fn send(self) -> Result<u16, String> {
        match self {
            Self::Telegram { token, chat, text } => send_telegram(&token, &chat, &text).await,
            Self::Webhook { url, body } => send_webhook(&url, &body).await,
        }
    }
}
fn telegram_delivery(cfg: &NotifyConfig, text: String) -> Result<Delivery, String> {
    validate_telegram_fields(cfg)?;
    Ok(Delivery::Telegram {
        token: cfg.telegram_token.clone(),
        chat: cfg.telegram_chat_id.clone(),
        text,
    })
}
fn webhook_delivery(cfg: &NotifyConfig, body: String) -> Result<Delivery, String> {
    validate_webhook_fields(cfg)?;
    if body.len() > MAX_PAYLOAD {
        return Err("notification payload exceeds 32 KiB".into());
    }
    Ok(Delivery::Webhook {
        url: cfg.webhook_url.clone(),
        body,
    })
}

fn event_deliveries(
    cfg: &NotifyConfig,
    event: Event,
    detail: &str,
) -> Vec<Result<Delivery, String>> {
    let telegram = cfg.telegram_enabled && event.enabled_in(&cfg.telegram_events);
    let webhook = cfg.webhook_enabled && event.enabled_in(&cfg.webhook_events);
    if !telegram && !webhook {
        return Vec::new();
    }
    let name = bounded_text(&cfg.server_name, MAX_SERVER_NAME);
    let detail = bounded_text(detail, MAX_DETAIL);
    let text = format!("{}{}\n{}", server_prefix(name), event.title(), detail);
    let mut deliveries = Vec::with_capacity(2);
    if telegram {
        deliveries.push(telegram_delivery(cfg, text.clone()));
    }
    if webhook {
        let body = serde_json::json!({
            "event": event.id(), "server": name, "detail": detail, "text": text, "ts": now_unix()
        })
        .to_string();
        deliveries.push(webhook_delivery(cfg, body));
    }
    deliveries
}
/// Metadata that changes on content replacement and, on Unix, chmod/chown/inode changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStampValue {
    modified_ns: u128,
    len: u64,
    #[cfg(unix)]
    changed_secs: i64,
    #[cfg(unix)]
    changed_ns: i64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}
type FileStamp = Option<FileStampValue>;
type NotifyCache = OnceLock<Mutex<Option<(FileStamp, NotifyConfig)>>>;
static NOTIFY_CACHE: NotifyCache = OnceLock::new();

#[derive(Clone, Copy)]
pub enum Event {
    ServerStart,
    QuotaBreach,
    LoginLockout,
    AuthLockout,
    Restore,
    ClientConnect,
    ClientDisconnect,
}

impl Event {
    fn id(self) -> &'static str {
        match self {
            Event::ServerStart => "server_start",
            Event::QuotaBreach => "quota_breach",
            Event::LoginLockout => "login_lockout",
            Event::AuthLockout => "auth_lockout",
            Event::Restore => "restore",
            Event::ClientConnect => "client_connect",
            Event::ClientDisconnect => "client_disconnect",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Event::ServerStart => "\u{1F7E2} qeli server started",
            Event::QuotaBreach => "\u{26D4} Quota breach",
            Event::LoginLockout => "\u{1F512} Panel login lockout",
            Event::AuthLockout => "\u{1F6AB} VPN auth IP lockout",
            Event::Restore => "\u{267B} Config restored from backup",
            Event::ClientConnect => "\u{1F517} Client connected",
            Event::ClientDisconnect => "\u{2702} Client disconnected",
        }
    }
    fn enabled_in(self, c: &ChannelEvents) -> bool {
        match self {
            Event::ServerStart => c.on_server_start,
            Event::QuotaBreach => c.on_quota_breach,
            Event::LoginLockout => c.on_login_lockout,
            Event::AuthLockout => c.on_auth_lockout,
            Event::Restore => c.on_restore,
            Event::ClientConnect => c.on_client_connect,
            Event::ClientDisconnect => c.on_client_disconnect,
        }
    }
}

/// Read the sidecar without hiding an I/O or parse failure. The panel uses this path so a
/// failed GET can never be followed by a PUT layered over empty defaults that erases secrets.
pub fn load_checked_with_raw() -> Result<(NotifyConfig, String), String> {
    crate::config::notify::load_path_with_raw(std::path::Path::new(NOTIFY_PATH))
        .map_err(|error| format!("cannot load {NOTIFY_PATH}: {error}"))
}

pub fn load_checked() -> Result<NotifyConfig, String> {
    load_checked_with_raw().map(|(config, _)| config)
}

/// Runtime reads fail closed to disabled channels, but log loudly; unlike the panel they cannot
/// return an error to an operator synchronously.
pub fn load() -> NotifyConfig {
    match load_checked() {
        Ok(config) => config,
        Err(error) => {
            log::warn!("notify: {error} — all notifications DISABLED until it is fixed");
            NotifyConfig::default()
        }
    }
}

fn file_stamp_for(path: &std::path::Path) -> FileStamp {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| {
            let modified_ns = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                FileStampValue {
                    modified_ns,
                    len: metadata.len(),
                    changed_secs: metadata.ctime(),
                    changed_ns: metadata.ctime_nsec(),
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                }
            }
            #[cfg(not(unix))]
            {
                FileStampValue {
                    modified_ns,
                    len: metadata.len(),
                }
            }
        })
}

fn file_stamp() -> FileStamp {
    file_stamp_for(std::path::Path::new(NOTIFY_PATH))
}

/// [`load`], but served from a cache refreshed whenever content or access metadata changes.
/// On Unix this includes chmod/chown and inode replacement, not only mtime/size.
///
/// The config is read on every notification-worthy event, most of which fire from the
/// session hot path. Stat-and-maybe-read is far cheaper than read-and-parse, and an
/// operator editing `notify.ini` (or the panel saving it) still takes effect within one
/// event because the metadata changes. (Audit 2026-07-27, S2.)
pub fn load_cached() -> NotifyConfig {
    let stamp = file_stamp();
    let cell = NOTIFY_CACHE.get_or_init(|| Mutex::new(None));
    let mut g = cell.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((cached_stamp, cfg)) = g.as_ref() {
        if *cached_stamp == stamp {
            return cfg.clone();
        }
    }
    let cfg = load();
    *g = Some((stamp, cfg.clone()));
    cfg
}

/// Persist atomically only while the sidecar still matches the editor snapshot.
pub fn save_if_unchanged(cfg: &NotifyConfig, checked_raw: &str) -> anyhow::Result<ConditionalSave> {
    let cell = NOTIFY_CACHE.get_or_init(|| Mutex::new(None));
    let mut cached = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let outcome = crate::config::notify::save_path_if_unchanged(
        std::path::Path::new(NOTIFY_PATH),
        cfg,
        checked_raw,
    )?;
    if matches!(outcome, ConditionalSave::Saved(_)) {
        // A manual editor may replace the published file before a pathname stat.
        // Pairing that newer stamp with cfg would cache stale settings indefinitely.
        // Reload a stable current snapshot on the next event instead.
        *cached = None;
    }
    Ok(outcome)
}

/// Reject enabled channels that cannot deliver anything. Keeping disabled channel fields is
/// allowed for the test-before-save flow; the API deliberately clears a disabled bot token.
pub fn validate_enabled(cfg: &NotifyConfig) -> Result<(), String> {
    if cfg.telegram_enabled {
        validate_telegram_fields(cfg)?;
    }
    if cfg.webhook_enabled {
        if cfg.webhook_url.is_empty() {
            return Err("Webhook is enabled but its URL is empty".into());
        }
        validate_webhook_fields(cfg)?;
    }
    Ok(())
}

fn now_unix() -> i64 {
    usage::now_unix()
}

/// Per-key cooldown so recurring conditions (a user repeatedly reconnecting over
/// quota, an IP hammering the locked panel) alert at most once per window.
fn throttle_ok(key: &str, cooldown: i64) -> bool {
    static MAP: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    let m = MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let now = now_unix();
    let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(&t) = g.get(key) {
        if now - t < cooldown {
            return false;
        }
    }
    g.insert(key.to_string(), now);
    if g.len() > 512 {
        // Age-based pruning ALONE is not a bound: keys include `authlock:<ip>`, so a
        // distributed brute force adds one entry per source and they all stay for the
        // full 24 h. Prune by age first, then hard-cap by evicting the oldest, so the map
        // can never grow without limit. (Audit 2026-07-27, S2.)
        g.retain(|_, t| now - *t < 86_400);
        const HARD_CAP: usize = 512;
        if g.len() > HARD_CAP {
            let mut by_age: Vec<(String, i64)> = g.iter().map(|(k, v)| (k.clone(), *v)).collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (k, _) in by_age.iter().take(g.len() - HARD_CAP) {
                g.remove(k);
            }
        }
    }
    true
}

/// `"[name] "` prefix identifying the server in messages, or empty when unset.
fn server_prefix(name: &str) -> String {
    let n = name.trim();
    if n.is_empty() {
        String::new()
    } else {
        format!("[{n}] ")
    }
}

/// Nonblocking admission to the process-owned queue. Disabled events spawn no tasks.
pub fn fire(event: Event, detail: &str) {
    let Some(queue) = delivery_queue() else {
        return;
    };
    for delivery in event_deliveries(&load_cached(), event, detail) {
        match delivery {
            Ok(delivery) => {
                let channel = match &delivery {
                    Delivery::Telegram { .. } => "telegram",
                    Delivery::Webhook { .. } => "webhook",
                };
                let _ = queue.try_spawn(async move {
                    match delivery.send().await {
                        Ok(code) if !(200..300).contains(&code) => {
                            log::warn!("notify {channel}: delivery rejected with HTTP {code}")
                        }
                        Err(error) => log::warn!("notify {channel}: delivery failed: {error}"),
                        _ => {}
                    }
                });
            }
            Err(error) => log::warn!("notify: invalid delivery: {error}"),
        }
    }
}

/// Like fire, but at most once per cooldown seconds for a key. Never awaits network I/O.
pub fn fire_throttled(key: &str, cooldown: i64, event: Event, detail: &str) {
    if throttle_ok(key, cooldown) {
        fire(event, detail);
    }
}

pub fn fire_connect(user: &str, profile: &str, peer: std::net::SocketAddr) {
    fire_throttled(
        &format!("connect:{user}"),
        10,
        Event::ClientConnect,
        &format!("{user} on '{profile}' from {peer}"),
    );
}
pub fn fire_disconnect(user: &str, profile: &str, peer: std::net::SocketAddr) {
    fire_throttled(
        &format!("disconnect:{user}"),
        10,
        Event::ClientDisconnect,
        &format!("{user} on '{profile}' from {peer}"),
    );
}

async fn test_delivery(delivery: Result<Delivery, String>) -> serde_json::Value {
    let result = async {
        let delivery = delivery?;
        let queue = delivery_queue().ok_or("notification service is unavailable")?;
        queue.request(delivery.send(), SEND_TIMEOUT).await
    }
    .await;
    match result {
        Ok(code) => serde_json::json!({ "ok": (200..300).contains(&code), "status": code }),
        Err(error) => serde_json::json!({ "ok": false, "error": error }),
    }
}

/// Panel probes use the same queue and return the actual delivery result.
pub async fn test_telegram(cfg: &NotifyConfig) -> serde_json::Value {
    let text = format!(
        "{}\u{2705} qeli test notification",
        server_prefix(bounded_text(&cfg.server_name, MAX_SERVER_NAME))
    );
    test_delivery(telegram_delivery(cfg, text)).await
}
pub async fn test_webhook(cfg: &NotifyConfig) -> serde_json::Value {
    let name = bounded_text(&cfg.server_name, MAX_SERVER_NAME);
    let body = serde_json::json!({
        "event": "test", "server": name,
        "text": format!("{}\u{2705} qeli test notification", server_prefix(name)),
        "ts": now_unix()
    })
    .to_string();
    test_delivery(webhook_delivery(cfg, body)).await
}

async fn send_telegram(token: &str, chat_id: &str, text: &str) -> Result<u16, String> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({ "chat_id": chat_id, "text": text }).to_string();
    http_post(&url, "application/json", body.as_bytes()).await
}

async fn send_webhook(url: &str, json_body: &str) -> Result<u16, String> {
    http_post(url, "application/json", json_body.as_bytes()).await
}

// ── minimal one-shot HTTP/1.1 POST (TLS via rustls, or plain TCP) ──────────────
// Outbound notifications only — never on the hot path. No redirects, no keep-alive.

async fn http_post(url: &str, content_type: &str, body: &[u8]) -> Result<u16, String> {
    match tokio::time::timeout(SEND_TIMEOUT, http_post_inner(url, content_type, body)).await {
        Ok(r) => r,
        Err(_) => Err("timed out".into()),
    }
}

async fn http_post_inner(url: &str, content_type: &str, body: &[u8]) -> Result<u16, String> {
    let (https, host, port, path) = parse_url(url)?;
    // SSRF guard: resolve the host and dial a validated PUBLIC address. Checking
    // the RESOLVED ip (not just the hostname) also defeats DNS rebinding to an
    // internal target (cloud metadata 169.254.169.254, localhost, LAN).
    let addr = resolve_public(&host, port).await?;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let authority = host_header(&host, port, https);
    let req = build_request(&authority, &path, content_type, body);
    if https {
        let connector = tls_connector()?;
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| format!("invalid TLS host '{host}'"))?;
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(|e| format!("tls handshake: {e}"))?;
        tls.write_all(&req)
            .await
            .map_err(|e| format!("write: {e}"))?;
        read_status(&mut tls).await
    } else {
        let mut s = stream;
        s.write_all(&req).await.map_err(|e| format!("write: {e}"))?;
        read_status(&mut s).await
    }
}

/// SSRF guard: an address we must never dial for an outbound notification —
/// loopback, private/LAN, link-local (incl. 169.254.169.254 cloud metadata),
/// CGNAT, multicast, unspecified/broadcast. Applied to the RESOLVED ip.
fn ip_is_forbidden(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0 // 0.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
                || o[0] >= 240 // reserved 240.0.0.0/4
                || (o[0] == 192 && o[1] == 0 && matches!(o[2], 0 | 2))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // deprecated relay
                || (o[0] == 198 && matches!(o[1], 18 | 19)) // benchmark networks
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return ip_is_forbidden(&IpAddr::V4(m));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
                || (s[0] & 0xe000) != 0x2000 // global-unicast allocation only
                || (s[0] == 0x2001 && s[1] < 0x0200) // special-use, including Teredo
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0] == 0x2002 // deprecated 6to4 can embed private IPv4
                || (s[0] == 0x3fff && (s[1] & 0xf000) == 0) // documentation /20
        }
    }
}

/// Resolve `host:port` and return the first PUBLIC socket address. Errors if the
/// host does not resolve or resolves only to forbidden (SSRF) addresses. The
/// error text is deliberately generic so it can't be used to probe which
/// internal host/port is reachable.
async fn resolve_public(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "cannot resolve host".to_string())?;
    let mut resolved = false;
    for a in addrs {
        resolved = true;
        if !ip_is_forbidden(&a.ip()) {
            return Ok(a);
        }
    }
    if resolved {
        Err("refused: destination resolves to a private/loopback/link-local address".into())
    } else {
        Err("host did not resolve".into())
    }
}

pub(crate) fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

fn host_header(host: &str, port: u16, https: bool) -> String {
    let rendered_host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if (https && port == 443) || (!https && port == 80) {
        rendered_host
    } else {
        format!("{rendered_host}:{port}")
    }
}

fn build_request(authority: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: qeli\r\nAccept: */*\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

/// Read just enough of the response to parse the status line.
async fn read_status<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<u16, String> {
    let mut out: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    while out.len() < 4096 {
        let remaining = tmp.len().min(4096 - out.len());
        let n = s
            .read(&mut tmp[..remaining])
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
        if out.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    // Never reflect remote bytes: an endpoint can echo the URL token or body
    // into a malformed status line, which is then shown by the panel or logged.
    let line_end = out
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| "invalid HTTP response status".to_string())?;
    let line = std::str::from_utf8(&out[..line_end])
        .map_err(|_| "invalid HTTP response status".to_string())?;
    let mut fields = line.splitn(3, ' ');
    let version = fields.next().unwrap_or("");
    let code = fields.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || code.len() != 3
        || !code.bytes().all(|c| c.is_ascii_digit())
        || fields.next().is_none()
    {
        return Err("invalid HTTP response status".into());
    }
    let code = code
        .parse::<u16>()
        .map_err(|_| "invalid HTTP response status".to_string())?;
    if !(200..600).contains(&code) {
        return Err("unsupported HTTP response status".into());
    }
    Ok(code)
}

/// Split `scheme://host[:port][/path]` → (https?, host, port, path).
pub(crate) fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
    // Reject control characters (incl. CR/LF/DEL) to prevent header injection
    // when the host/path are spliced into the raw HTTP request in build_request.
    if url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err("URL contains whitespace or control characters".into());
    }
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("URL must start with http:// or https://".into());
    };
    // Fragments are local URL metadata; queries without a slash still target '/'.
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("missing host".into());
    }
    let default_port = if https { 443 } else { 80 };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| "unterminated IPv6 host".to_string())?;
        let host = &bracketed[..close];
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "invalid IPv6 host".to_string())?;
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| "invalid authority after IPv6 host".to_string())?
                .parse::<u16>()
                .map_err(|_| "invalid port".to_string())?
        };
        (host.to_string(), port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err("IPv6 literals must be enclosed in brackets".into());
        }
        match authority.rfind(':') {
            Some(i) => (
                authority[..i].to_string(),
                authority[i + 1..]
                    .parse::<u16>()
                    .map_err(|_| "invalid port".to_string())?,
            ),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() || port == 0 {
        return Err("invalid host or port".into());
    }
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Ok((https, host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_variants() {
        assert_eq!(
            parse_url("https://api.telegram.org/bot123/sendMessage").unwrap(),
            (
                true,
                "api.telegram.org".into(),
                443,
                "/bot123/sendMessage".into()
            )
        );
        assert_eq!(
            parse_url("http://hook.local:9000/x").unwrap(),
            (false, "hook.local".into(), 9000, "/x".into())
        );
        assert_eq!(
            parse_url("https://example.com").unwrap(),
            (true, "example.com".into(), 443, "/".into())
        );
        assert_eq!(
            parse_url("https://[2001:4860:4860::8888]:9443/hook").unwrap(),
            (true, "2001:4860:4860::8888".into(), 9443, "/hook".into())
        );
        assert_eq!(
            host_header("hooks.example", 9443, true),
            "hooks.example:9443"
        );
        assert_eq!(
            host_header("2001:4860:4860::8888", 443, true),
            "[2001:4860:4860::8888]"
        );
        assert!(parse_url("ftp://nope").is_err());
        assert!(parse_url("https://2001:db8::1/hook").is_err());
    }

    #[test]
    fn parse_url_rejects_control_chars() {
        assert!(parse_url("https://host/a\r\nX-Injected: 1").is_err());
        assert!(parse_url("https://ho\nst/x").is_err());
        assert!(parse_url("https://host/\x7f").is_err());
        // A clean URL with the same shape still parses.
        assert!(parse_url("https://host/a").is_ok());
    }

    #[tokio::test]
    async fn response_status_is_complete_valid_and_never_reflects_secrets() {
        for response in [
            b"malformed echoed-bot-secret\r\n".as_slice(),
            b"anything 200 echoed-bot-secret\r\n",
            b"HTTP/1.1 200 OK",
            b"HTTP/1.1 20 OK\r\n",
            b"HTTP/1.1 999 echoed-bot-secret\r\n",
            b"HTTP/1.1 100 Continue\r\n",
            b"HTTP/1.1 200\r\n",
        ] {
            let error = read_status(&mut &response[..]).await.unwrap_err();
            assert!(!error.contains("echoed-bot-secret"), "{error}");
        }
        for (response, expected) in [
            ("HTTP/1.1 204 \r\n", 204),
            ("HTTP/1.0 503 Unavailable\r\n", 503),
            ("HTTP/1.1 302 Found\r\n", 302),
        ] {
            assert_eq!(
                read_status(&mut response.as_bytes()).await.unwrap(),
                expected
            );
        }
        let (mut tx, mut rx) = tokio::io::duplex(32);
        let writer = tokio::spawn(async move {
            for byte in b"HTTP/1.1 201 Created\r\n" {
                tx.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_status(&mut rx).await.unwrap(), 201);
        writer.await.unwrap();
    }

    #[test]
    fn url_query_fragment_and_spaces_cannot_corrupt_request_target() {
        assert_eq!(
            parse_url("https://hooks.example?token=fixture#local").unwrap(),
            (true, "hooks.example".into(), 443, "/?token=fixture".into())
        );
        assert_eq!(
            parse_url("https://hooks.example/path?q=x#local").unwrap().3,
            "/path?q=x"
        );
        for url in [
            "https://hooks.example/a b",
            "https://hooks. example/path",
            "https://hooks.example?query=bad value",
        ] {
            assert!(parse_url(url).is_err());
        }
    }

    #[test]
    fn special_use_destinations_cannot_bypass_public_address_guard() {
        for address in [
            "198.18.0.1",
            "192.88.99.2",
            "3fff::1",
            "198.19.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "fec0::1",
            "64:ff9b::a00:1",
            "2001:2::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "::ffff:198.18.0.1",
        ] {
            assert!(ip_is_forbidden(&address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn default_config_is_off_events_on() {
        let c = NotifyConfig::default();
        assert!(!c.telegram_enabled && !c.webhook_enabled);
        // Per-channel events default to all-on.
        assert!(Event::ServerStart.enabled_in(&c.telegram_events));
        assert!(Event::Restore.enabled_in(&c.webhook_events));
    }

    #[test]
    fn ssrf_guard_blocks_internal_allows_public() {
        use std::net::IpAddr;
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ] {
            assert!(
                ip_is_forbidden(&s.parse::<IpAddr>().unwrap()),
                "{s} must be blocked"
            );
        }
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "149.154.167.220", // telegram
            "2001:4860:4860::8888",
        ] {
            assert!(
                !ip_is_forbidden(&s.parse::<IpAddr>().unwrap()),
                "{s} must be allowed"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn notify_stamp_changes_when_only_permissions_change() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("qeli-notify-stamp-{}", std::process::id()));
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = file_stamp_for(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let after = file_stamp_for(&path);
        assert_ne!(before, after);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn notify_stamp_cannot_reuse_a_regular_target_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let dir =
            std::env::temp_dir().join(format!("qeli-notify-stamp-link-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("notify.ini");
        let target = dir.join("target.ini");
        std::fs::write(&path, b"[notify]\nserver_name=fixture\n").unwrap();
        assert!(file_stamp_for(&path).is_some());
        std::fs::rename(&path, &target).unwrap();
        symlink("target.ini", &path).unwrap();
        assert!(
            file_stamp_for(&path).is_none(),
            "cache stamp must inspect the entry, not follow its target"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&target, &path).unwrap();
        assert!(file_stamp_for(&path).is_some());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn disabled_events_create_no_deliveries() {
        let mut cfg = NotifyConfig::default();
        assert!(event_deliveries(&cfg, Event::ServerStart, "event").is_empty());
        cfg.telegram_enabled = true;
        cfg.webhook_enabled = true;
        // Connection notifications are opt-in on both channels.
        assert!(event_deliveries(&cfg, Event::ClientConnect, "event").is_empty());
    }

    #[test]
    fn event_payloads_bound_utf8_and_json_expansion() {
        let cfg = NotifyConfig {
            server_name: "я".repeat(500),
            telegram_enabled: true,
            telegram_token: "token".into(),
            telegram_chat_id: "123".into(),
            webhook_enabled: true,
            webhook_url: "https://hooks.example/event".into(),
            ..NotifyConfig::default()
        };
        let jobs = event_deliveries(&cfg, Event::ServerStart, &"\u{1}🙂".repeat(10_000));
        assert_eq!(jobs.len(), 2);
        for job in jobs {
            match job.unwrap() {
                Delivery::Telegram { text, .. } => assert!(text.len() < 4096),
                Delivery::Webhook { body, .. } => {
                    assert!(body.len() <= MAX_PAYLOAD);
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                    assert!(parsed["detail"].as_str().unwrap().len() <= MAX_DETAIL);
                    assert!(parsed["server"].as_str().unwrap().len() <= MAX_SERVER_NAME);
                }
            }
        }
        assert_eq!(bounded_text("a🙂z", 3), "a");
    }

    #[test]
    fn oversized_destination_fields_are_rejected_without_truncating_secrets() {
        let mut cfg = NotifyConfig {
            telegram_token: "x".repeat(513),
            telegram_chat_id: "123".into(),
            webhook_url: format!("https://hooks.example/{}", "x".repeat(4096)),
            ..NotifyConfig::default()
        };
        assert!(telegram_delivery(&cfg, "test".into()).is_err());
        assert!(webhook_delivery(&cfg, "{}".into()).is_err());
        cfg.webhook_url = "https://hooks.example/".into();
        assert!(webhook_delivery(&cfg, "x".repeat(MAX_PAYLOAD + 1)).is_err());
    }

    #[tokio::test]
    async fn process_owner_bounds_panel_probes_closes_and_can_restart() {
        let runtime = start().unwrap();
        assert!(start().is_err(), "only one process owner");
        // Fill admission with fake pending jobs. The probe must be rejected before send.
        // Even if admission regresses, the existing SSRF guard rejects this numeric
        // loopback destination, so this test cannot contact an external service.
        for _ in 0..MAX_DELIVERIES {
            runtime.queue.try_spawn(std::future::pending()).unwrap();
        }
        let cfg = NotifyConfig {
            webhook_url: "http://127.0.0.1:9/".into(),
            ..NotifyConfig::default()
        };
        let result = test_webhook(&cfg).await;
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"], "notification queue is full");
        runtime.queue.abort();
        runtime.shutdown().await;
        assert_eq!(
            test_webhook(&cfg).await["error"],
            "notification service is stopping"
        );
        drop(runtime);
        assert!(delivery_queue().is_none());
        assert_eq!(
            test_webhook(&cfg).await["error"],
            "notification service is unavailable"
        );
        let next = start().unwrap();
        next.shutdown().await;
    }
}
