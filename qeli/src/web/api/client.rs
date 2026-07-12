//! Web API for the panel's CLIENT manager: outbound tunnels this box dials to other
//! qeli servers. Profiles are stored as `/etc/qeli/clients/<name>.conf` (flat-INI),
//! brought up/down via [`crate::server::client_manager::ClientManager`].
//!
//! Safety: new profiles default to SPLIT-tunnel (gateway off). Full-tunnel reroutes
//! ALL of the box's traffic through the remote server (it can cut off this very
//! panel / SSH), so it is an explicit opt-in — the UI warns about it.

use crate::config::client::ClientConfig;
use crate::config::format::IniDoc;
use crate::config::share::ClientLink;
use crate::server::client_manager::ClientManager;
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Sanitize an arbitrary string (a link label or host) into a valid profile name.
fn sanitize_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['-', '.']).to_string();
    let n = if trimmed.is_empty() {
        "client".to_string()
    } else {
        trimmed
    };
    n.chars().take(64).collect()
}

/// Last `n` lines of a (possibly missing) log file. Reads only the tail (cap ~64
/// KiB) so a pathologically large log can't OOM the panel — we only ever show the
/// last `n` lines. (audit 3.5)
fn tail_lines(path: &str, n: usize) -> String {
    use std::io::{Read, Seek, SeekFrom};
    const CAP: u64 = 64 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(CAP);
    if start > 0 && f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if f.take(CAP).read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let buf = String::from_utf8_lossy(&bytes);
    // If we seeked into the middle of a line, drop the partial first line.
    let txt = if start > 0 {
        buf.split_once('\n').map(|(_, rest)| rest).unwrap_or(&buf)
    } else {
        &buf
    };
    let lines: Vec<&str> = txt.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Real connection state from the client's log tail. A live child process is NOT the
/// same as an up tunnel: a mis-configured client (e.g. reality-tls without a short_id)
/// loops on reconnect while the process stays alive, which showed a misleading
/// "connected" in the panel. Scan the recent log; the LAST of a success marker
/// (`… is up` / `Auth OK`) vs a failure marker (`Connection error` / `Reconnecting` /
/// ` ERROR `) decides. Returns "up" | "error" | "connecting".
fn tunnel_state(log_path: &str) -> &'static str {
    let tail = tail_lines(log_path, 40);
    let mut state = "connecting";
    for line in tail.lines() {
        if line.contains(" is up") || line.contains("Auth OK") {
            state = "up";
        } else if line.contains("Connection error")
            || line.contains("Reconnecting")
            || line.contains(" ERROR ")
        {
            state = "error";
        }
    }
    state
}

/// Extract the outbound tunnel's assigned INTERNAL IP from the client log — the key
/// diagnostic ("what tunnel address did we get") that was only buried in the log file.
/// Reads the "assigned IP: X" / "TUN <dev> is up (IP: X)" markers; last one wins.
fn tunnel_ip(log_path: &str) -> Option<String> {
    let tail = tail_lines(log_path, 40);
    let mut ip: Option<String> = None;
    for line in tail.lines() {
        if let Some(rest) = line.split("assigned IP: ").nth(1) {
            ip = Some(rest.trim().trim_end_matches(['.', ',']).to_string());
        } else if let Some(rest) = line.split("is up (IP: ").nth(1) {
            if let Some(v) = rest.split(')').next() {
                ip = Some(v.trim().to_string());
            }
        }
    }
    ip.filter(|s| !s.is_empty())
}

/// Parse a stored profile's `[qeli]` essentials for the list view (best-effort).
fn profile_summary(name: &str) -> Value {
    let path = ClientManager::profile_path(name);
    let cfg = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| IniDoc::parse(&s).ok())
        .and_then(|d| ClientConfig::from_ini(&d).ok());
    match cfg {
        Some(c) => json!({
            "name": name,
            "server": format!("{}:{}", c.server.address, c.server.port),
            "proto": c.server.protocol,
            "mode": c.obfuscation.mode,
            "user": c.auth.username,
            "gateway": c.routing.add_default_gateway,
            "dev": c.tun.name,
            "autostart": c.autostart,
        }),
        None => json!({ "name": name, "server": "?", "invalid": true }),
    }
}

pub async fn list_profiles(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let mut out = Vec::new();
    for name in ClientManager::list_profiles() {
        let mut s = profile_summary(&name);
        let running = state.client_manager.is_running(&name).await;
        // `connected` stays "is the child alive" so the UI can offer Disconnect for a
        // looping tunnel; `state` is the HONEST status (up / connecting / error / down).
        s["connected"] = json!(running);
        if running {
            let log = ClientManager::log_path(&name);
            s["state"] = json!(tunnel_state(&log));
            if let Some(ip) = tunnel_ip(&log) {
                s["tun_ip"] = json!(ip); // assigned internal tunnel IP (diagnostic)
            }
            s["log_tail"] = json!(tail_lines(&log, 8));
        } else {
            s["state"] = json!("down");
        }
        out.push(s);
    }
    Ok(Json(json!({ "ok": true, "profiles": out })))
}

/// Build the INI text for a profile from form fields (only non-empty ones).
fn ini_from_fields(b: &Value) -> String {
    // Field values are single-line; strip any control char so a value can't inject an
    // extra INI line (defense-in-depth alongside persist()'s hook rejection).
    let g = |k: &str| -> String {
        b.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|&c| !c.is_control() || c == '\t')
            .collect()
    };
    let flag = |k: &str| b.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let mut s = String::from("[qeli]\n");
    s.push_str(&format!("server = {}\n", g("server")));
    if !g("proto").is_empty() {
        s.push_str(&format!("proto = {}\n", g("proto")));
    }
    if !g("user").is_empty() {
        s.push_str(&format!("user = {}\n", g("user")));
    }
    if !g("pass").is_empty() {
        s.push_str(&format!("pass = {}\n", g("pass")));
    }
    if !g("key").is_empty() {
        s.push_str(&format!("key = {}\n", g("key")));
    }
    if !g("mode").is_empty() {
        s.push_str(&format!("mode = {}\n", g("mode")));
    }
    if !g("sni").is_empty() {
        s.push_str(&format!("sni = {}\n", g("sni")));
    }
    if !g("rsid").is_empty() {
        s.push_str(&format!("reality_sid = {}\n", g("rsid")));
    }
    if !g("obfs_key").is_empty() {
        s.push_str(&format!("obfs_key = {}\n", g("obfs_key")));
    }
    if flag("quic") {
        s.push_str("quic = true\n");
    }
    // Manual TUN interface name (optional): a legal Linux ifname (1..=15 chars,
    // [A-Za-z0-9_-]). When set it is emitted verbatim and ensure_unique_dev keeps it
    // instead of auto-assigning a free vpnN. An invalid value is ignored (falls back to
    // auto-assign) rather than writing a name the kernel would reject.
    let dev = g("dev");
    if (1..=15).contains(&dev.len())
        && dev
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        s.push_str(&format!("dev = {dev}\n"));
    }
    // Routing (file-only; not in a qeli:// link). gateway defaults OFF (split-tunnel).
    if flag("gateway") {
        s.push_str("gateway = true\n");
    }
    if flag("route_local") {
        s.push_str("route_local = true\n");
    }
    if flag("kill_switch") {
        s.push_str("kill_switch = true\n");
    }
    // Auto-connect this profile when the supervisor starts.
    if flag("autostart") {
        s.push_str("autostart = true\n");
    }
    s
}

/// Does the INI explicitly set a `dev` key in `[qeli]`?
fn ini_has_dev(ini: &str) -> bool {
    ini.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.split('=').next().map(str::trim) == Some("dev")
    })
}

/// Lowest `vpn<N>` not used as the TUN device by any OTHER stored client profile AND
/// not already a live interface on this host — so an outbound tunnel started from the
/// panel never clashes with vpn0/vpn1 already claimed by a SERVER profile on the same
/// box (or by another client, or anything else). Checking only stored client profiles
/// was the bug: on a host whose server runs on vpn1, this handed out vpn1 and the
/// client's TUN creation then failed with "device busy".
fn free_dev(exclude: &str) -> String {
    let mut used = std::collections::HashSet::new();
    for n in ClientManager::list_profiles() {
        if n == exclude {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(ClientManager::profile_path(&n)) {
            if let Ok(d) = IniDoc::parse(&s) {
                if let Ok(c) = ClientConfig::from_ini(&d) {
                    used.insert(c.tun.name);
                }
            }
        }
    }
    (0..256)
        .map(|i| format!("vpn{i}"))
        .find(|d| {
            // Skip a device that another client profile claims OR that already exists
            // on the host (a server profile's tun, or any other live interface).
            !used.contains(d) && !std::path::Path::new(&format!("/sys/class/net/{d}")).exists()
        })
        .unwrap_or_else(|| "vpn0".to_string())
}

/// Ensure the profile has a distinct TUN device. If the INI already sets `dev`,
/// keep it; if this profile already exists, reuse its device (editing doesn't move
/// it); otherwise auto-assign a free `vpnN` so multiple tunnels can coexist.
fn ensure_unique_dev(name: &str, ini: &str) -> String {
    if ini_has_dev(ini) {
        return ini.to_string();
    }
    let dev = std::fs::read_to_string(ClientManager::profile_path(name))
        .ok()
        .and_then(|s| IniDoc::parse(&s).ok())
        .and_then(|d| ClientConfig::from_ini(&d).ok())
        .map(|c| c.tun.name)
        .unwrap_or_else(|| free_dev(name));
    let mut out = String::with_capacity(ini.len() + 20);
    let mut injected = false;
    for line in ini.lines() {
        out.push_str(line);
        out.push('\n');
        if !injected && line.trim() == "[qeli]" {
            out.push_str(&format!("dev = {dev}\n"));
            injected = true;
        }
    }
    if injected {
        out
    } else {
        format!("[qeli]\ndev = {dev}\n{ini}")
    }
}

/// Validate `ini` as a client config, then persist it VERBATIM (preserving raw
/// keys/comments — so the panel can fully configure a client, not just the form
/// subset), auto-assigning a distinct TUN device when none is set. Rejects anything
/// `from_ini` won't accept.
fn persist(name: &str, ini: &str) -> anyhow::Result<()> {
    let doc = IniDoc::parse(ini).map_err(|e| anyhow::anyhow!("invalid config: {e}"))?;
    let cfg = ClientConfig::from_ini(&doc)?;
    if cfg.server.address.is_empty() {
        anyhow::bail!("server address is required");
    }
    // SECURITY: the panel/API must NEVER persist a client config that can run a shell
    // command as root — `post_up`/`post_down` (hooks.rs) and `password_command`
    // (client/mod.rs) are executed via `sh -c`, so a compromised/XSS/CSRF'd panel
    // would otherwise become root RCE on `connect`. This semantic check catches both a
    // literal `post_up = …` line AND any control-char-injected one, since `from_ini`
    // parses either into the same field. Hooks stay file-only (edit on the host).
    if !cfg.routing.post_up.is_empty() || !cfg.routing.post_down.is_empty() {
        anyhow::bail!(
            "post_up/post_down are not allowed in a panel-managed profile — set them by \
             editing the profile file directly on the host"
        );
    }
    if cfg.auth.password_command.is_some() {
        anyhow::bail!(
            "password_command is not allowed in a panel-managed profile — use `pass` or \
             `password_file`"
        );
    }
    let ini = ensure_unique_dev(name, ini);
    std::fs::create_dir_all(crate::server::client_manager::CLIENTS_DIR)?;
    crate::util::write_atomic(ClientManager::profile_path(name), ini.as_bytes())?;
    Ok(())
}

/// Create/replace a profile. Body is EITHER a full raw INI (`{name, raw}` — full
/// control over every client key) OR form fields (`{name, server, proto, ...}`).
pub async fn save_profile(
    State(_state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Json<Value> {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(sanitize_name)
        .unwrap_or_default();
    if !ClientManager::valid_name(&name) {
        return Json(super::err_json("a valid profile name is required"));
    }
    // Raw INI wins when supplied (written verbatim); otherwise build from fields.
    let raw = body
        .get("raw")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ini = match raw {
        Some(r) => r.to_string(),
        None => ini_from_fields(&body),
    };
    match persist(&name, &ini) {
        Ok(()) => Json(json!({ "ok": true, "name": name })),
        Err(e) => Json(super::err_json(e.to_string())),
    }
}

/// Import a `qeli://` link as a profile. Body: {link, name?}.
pub async fn import_link(
    State(_state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Json<Value> {
    let link = body
        .get("link")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let parsed = match ClientLink::from_uri(link) {
        Ok(l) => l,
        Err(e) => return Json(super::err_json(format!("invalid qeli:// link: {e}"))),
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(sanitize_name)
        .unwrap_or_else(|| sanitize_name(parsed.label.as_deref().unwrap_or(&parsed.host)));
    // from_link → split-tunnel by default (the link never carries gateway).
    let cfg = ClientConfig::from_link(&parsed);
    match persist(&name, &cfg.to_ini_string()) {
        Ok(()) => Json(json!({ "ok": true, "name": name })),
        Err(e) => Json(super::err_json(e.to_string())),
    }
}

/// Return a profile's stored INI (for the editor).
pub async fn get_profile(
    State(_state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
) -> Json<Value> {
    if !ClientManager::valid_name(&name) {
        return Json(super::err_json("invalid name"));
    }
    match std::fs::read_to_string(ClientManager::profile_path(&name)) {
        Ok(ini) => Json(json!({ "ok": true, "name": name, "raw": ini })),
        Err(_) => Json(super::err_json("profile not found")),
    }
}

pub async fn delete_profile(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
) -> Json<Value> {
    if !ClientManager::valid_name(&name) {
        return Json(super::err_json("invalid name"));
    }
    let _ = state.client_manager.disconnect(&name).await;
    let _ = std::fs::remove_file(ClientManager::profile_path(&name));
    let _ = std::fs::remove_file(ClientManager::log_path(&name));
    Json(super::ok_json())
}

pub async fn connect(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
) -> Json<Value> {
    match state.client_manager.connect(&name).await {
        Ok(()) => Json(json!({ "ok": true, "message": format!("connecting '{name}'") })),
        Err(e) => Json(super::err_json(e.to_string())),
    }
}

pub async fn disconnect(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
) -> Json<Value> {
    match state.client_manager.disconnect(&name).await {
        Ok(()) => Json(json!({ "ok": true, "message": format!("disconnected '{name}'") })),
        Err(e) => Json(super::err_json(e.to_string())),
    }
}
