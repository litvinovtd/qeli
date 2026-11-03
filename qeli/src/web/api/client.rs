//! Web API for the panel's CLIENT manager: outbound tunnels this box dials to other
//! qeli servers. Profiles are stored as `/etc/qeli/clients/<name>.conf` (flat-INI),
//! brought up/down via [`crate::server::client_manager::ClientManager`].
//!
//! Safety: new profiles default to SPLIT-tunnel (gateway off). Full-tunnel reroutes
//! ALL of the box's traffic through the remote server (it can cut off this very
//! panel / SSH), so it is an explicit opt-in — the UI warns about it.

use crate::config::client::ClientConfig;
use crate::config::share::ClientLink;
use crate::server::client_manager::ClientManager;
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};
use std::path::Path as FsPath;
use std::sync::Arc;

/// Read a stable snapshot with the client runtime's INI budget.
fn read_profile(path: &str) -> anyhow::Result<Option<String>> {
    match crate::config_source::load_bounded(path, crate::transport_core::MAX_CONFIG_BYTES as u64) {
        Ok(snapshot) => Ok(Some(snapshot.into_parts().0)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn profile_revision_conflict(body: &Value, current: Option<&str>) -> Option<Value> {
    let expected = body.get("expected_revision").and_then(Value::as_str);
    let revision = current.map(super::config::config_revision);
    match (current, expected) {
        (None, None) => None,
        (Some(_), Some(expected)) if Some(expected) == revision.as_deref() => None,
        (Some(_), None) => Some(json!({
            "ok": false, "kind": "config_revision_required",
            "error": "This client profile already exists. Open it for editing to load its revision.",
            "current_revision": revision,
        })),
        _ => Some(json!({
            "ok": false, "kind": "config_conflict",
            "error": "The client profile changed or was deleted. Reload and review it before saving.",
            "current_revision": revision,
        })),
    }
}

fn delete_revision_conflict(headers: &HeaderMap, current_raw: &str) -> Option<Value> {
    let expected = headers
        .get("x-qeli-revision")
        .and_then(|value| value.to_str().ok());
    profile_revision_conflict(&json!({ "expected_revision": expected }), Some(current_raw))
}

fn write_profile_if_unchanged(
    path: &str,
    ini: &str,
    checked_raw: Option<&str>,
) -> anyhow::Result<bool> {
    if read_profile(path)?.as_deref() != checked_raw {
        return Ok(false);
    }
    crate::util::write_atomic_private(path, ini.as_bytes())?;
    Ok(true)
}

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

/// Read the client's bounded machine-readable status sidecar. This is the primary panel
/// contract; the log parsers above remain only as compatibility fallback for an older client
/// process that was started before the server binary was upgraded.
fn structured_status(name: &str) -> Option<Value> {
    read_structured_status(&ClientManager::status_path(name), name)
}

fn read_structured_status(path: &str, name: &str) -> Option<Value> {
    const MAX_STATUS_BYTES: u64 = 64 * 1024;
    let raw = crate::config_source::load_bounded(path, MAX_STATUS_BYTES)
        .ok()?
        .into_parts()
        .0;
    let value: Value = serde_json::from_str(&raw).ok()?;
    if value.get("schema").and_then(Value::as_u64) != Some(1)
        || value.get("profile").and_then(Value::as_str) != Some(name)
        || !value.get("state").is_some_and(Value::is_string)
    {
        return None;
    }
    Some(value)
}

fn panel_state_from_diagnostics(status: &Value) -> &'static str {
    match status.get("state").and_then(Value::as_str).unwrap_or("") {
        "running" => "up",
        "retrying" | "failed" => "error",
        _ => "connecting",
    }
}

/// Parse a stored profile's `[qeli]` essentials for the list view (best-effort).
fn profile_summary(name: &str) -> Value {
    let path = ClientManager::profile_path(name);
    let raw = read_profile(&path).ok().flatten();
    let revision = raw.as_deref().map(super::config::config_revision);
    let cfg = raw
        .as_deref()
        .and_then(|s| crate::config::parse_client_config_strict(s).ok());
    let mut summary = match cfg {
        Some(c) => json!({
            "name": name,
            "server": crate::util::join_host_port(&c.server.address, c.server.port),
            "proto": c.server.protocol,
            "mode": c.obfuscation.mode,
            "user": c.auth.username,
            "gateway": c.routing.add_default_gateway,
            "dev": c.tun.name,
            "autostart": c.autostart,
            "ipv6": c.routing.ipv6.to_string(),
            "allow_ipv4_leak": c.routing.allow_ipv4_leak,
            "allow_ipv6_leak": c.routing.allow_ipv6_leak,
        }),
        None => json!({ "name": name, "server": "?", "invalid": true }),
    };
    if let Some(revision) = revision {
        summary["revision"] = json!(revision);
    }
    summary
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
            if let Some(diagnostics) = structured_status(&name) {
                s["state"] = json!(panel_state_from_diagnostics(&diagnostics));
                if let Some(ip) = diagnostics
                    .pointer("/plan/tunnel_address")
                    .and_then(Value::as_str)
                {
                    s["tun_ip"] = json!(ip);
                }
                s["diagnostics"] = diagnostics;
            } else {
                s["state"] = json!(tunnel_state(&log));
                if let Some(ip) = tunnel_ip(&log) {
                    s["tun_ip"] = json!(ip); // assigned internal tunnel IP (diagnostic)
                }
            }
            s["log_tail"] = json!(tail_lines(&log, 8));
        } else {
            s["state"] = json!("down");
            // Preserve the last negotiated plan/error for post-mortem inspection, but never
            // let a stale "running" value override the authoritative dead child handle.
            if let Some(diagnostics) = structured_status(&name) {
                s["diagnostics"] = diagnostics;
            }
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
        let value = b.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let value = if matches!(k, "pass" | "obfs_key") {
            value
        } else {
            value.trim()
        };
        value
            .chars()
            .filter(|&c| !c.is_control() || c == '\t')
            .collect()
    };
    let flag = |k: &str| b.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    // The AWG inputs use Alpine's `x-model.number`, so they arrive as JSON NUMBERS — `g()`
    // reads strings and would return "" for every one of them.
    let num = |k: &str| -> Option<i64> {
        b.get(k).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        })
    };
    let mut s = String::from("[qeli]\n");
    s.push_str(&format!(
        "server = {}\n",
        crate::config::format::quote_if_needed(&g("server"))
    ));
    if !g("proto").is_empty() {
        s.push_str(&format!(
            "proto = {}\n",
            crate::config::format::quote_if_needed(&g("proto"))
        ));
    }
    if !g("user").is_empty() {
        s.push_str(&format!(
            "user = {}\n",
            crate::config::format::quote_if_needed(&g("user"))
        ));
    }
    if !g("pass").is_empty() {
        s.push_str(&format!(
            "pass = {}\n",
            crate::config::format::quote_if_needed(&g("pass"))
        ));
    }
    if !g("key").is_empty() {
        s.push_str(&format!(
            "key = {}\n",
            crate::config::format::quote_if_needed(&g("key"))
        ));
    }
    if !g("mode").is_empty() {
        s.push_str(&format!(
            "mode = {}\n",
            crate::config::format::quote_if_needed(&g("mode"))
        ));
    }
    if !g("sni").is_empty() {
        s.push_str(&format!(
            "sni = {}\n",
            crate::config::format::quote_if_needed(&g("sni"))
        ));
    }
    if !g("rsid").is_empty() {
        s.push_str(&format!(
            "reality_sid = {}\n",
            crate::config::format::quote_if_needed(&g("rsid"))
        ));
    }
    if !g("obfs_key").is_empty() {
        s.push_str(&format!(
            "obfs_key = {}\n",
            crate::config::format::quote_if_needed(&g("obfs_key"))
        ));
    }
    // The form offers these; nothing read them, so an obfs profile saved from the panel lost
    // its fronting and AWG settings — the panel reported success and the client then failed to
    // handshake because the two ends disagreed about the wire. (Audit 2026-07-31, §1.)
    // `front` only when it differs from the default, mirroring the panel's own INI preview.
    if g("mode") == "obfs" && !g("front").is_empty() && g("front") != "websocket" {
        s.push_str(&format!(
            "front = {}\n",
            crate::config::format::quote_if_needed(&g("front"))
        ));
    }
    if flag("awg") {
        s.push_str("awg = true\n");
        for key in ["jc", "jmin", "jmax"] {
            if let Some(v) = num(key) {
                s.push_str(&format!("{key} = {v}\n"));
            }
        }
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
    // Inner-family policy is independent of the outer carrier. Keep the supplied value in
    // the INI so ClientConfig performs the canonical auto|required|off validation instead of
    // silently coercing a malformed API request to the default.
    let ipv6 = g("ipv6");
    if !ipv6.is_empty() {
        s.push_str(&format!("ipv6 = {ipv6}\n"));
    }
    if flag("allow_ipv4_leak") {
        s.push_str("allow_ipv4_leak = true\n");
    }
    if flag("allow_ipv6_leak") {
        s.push_str("allow_ipv6_leak = true\n");
    }
    // Routing (file-only; not in a qeli:// link). gateway defaults OFF (split-tunnel).
    if flag("gateway") {
        s.push_str("gateway = true\n");
    }
    if flag("route_local") {
        s.push_str("route_local = true\n");
    }
    for key in ["include", "exclude", "lan_subnet_ipv6"] {
        let value = g(key);
        if !value.is_empty() {
            s.push_str(&format!(
                "{key} = {}\n",
                crate::config::format::quote_if_needed(&value)
            ));
        }
    }
    if flag("kill_switch") {
        s.push_str("kill_switch = true\n");
    }
    // Auto-connect this profile when the supervisor starts.
    if flag("autostart") {
        s.push_str("autostart = true\n");
    }

    // Everything the FORM does not model, carried through verbatim.
    //
    // The frontend already collects these — unknown `[qeli]` keys into `_extraQeli`, whole
    // trailing sections into `_extraSections` — precisely so that a form save round-trips
    // losslessly. Nothing at this end read them, so saving an existing profile through the form
    // DELETED `mtu`, `mtu_probe`, `dns`, `password_file`, `dev_attach`, include/exclude routes,
    // `[logging]` — and, worst of the set, `kill_switch`. The comment upstream promised a
    // lossless save while this end silently dropped it. (Audit 2026-08-01, §1.)
    let lines = |k: &str| -> Vec<String> {
        b.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    // Same control-char strip as every scalar: a carried line must not be able
                    // to forge extra INI structure either.
                    .map(|l| {
                        l.chars()
                            .filter(|&c| !c.is_control() || c == '\t')
                            .collect()
                    })
                    .filter(|l: &String| !l.trim().is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    for l in lines("_extraQeli") {
        s.push_str(&l);
        s.push('\n');
    }
    let extra_sections = lines("_extraSections");
    if !extra_sections.is_empty() {
        s.push('\n');
        for l in extra_sections {
            s.push_str(&l);
            s.push('\n');
        }
    }
    s
}

/// Lowest `vpn<N>` not used as the TUN device by any OTHER stored client profile AND
/// not already a live interface on this host — so an outbound tunnel started from the
/// panel never clashes with vpn0/vpn1 already claimed by a SERVER profile on the same
/// box (or by another client, or anything else). Checking only stored client profiles
/// was the bug: on a host whose server runs on vpn1, this handed out vpn1 and the
/// client's TUN creation then failed with "device busy".
fn free_dev(exclude: &str) -> anyhow::Result<String> {
    let mut used = std::collections::HashSet::new();
    for n in ClientManager::list_profiles() {
        if n == exclude {
            continue;
        }
        if let Ok(Some(s)) = read_profile(&ClientManager::profile_path(&n)) {
            if let Ok(c) = crate::config::parse_client_config_strict(&s) {
                // ClientConfig zeroizes secrets in Drop, so clone the device name.
                used.insert(c.tun.name.clone());
            }
        }
    }
    select_free_dev(&used)
}

fn select_free_dev(used: &std::collections::HashSet<String>) -> anyhow::Result<String> {
    for i in 0..256 {
        let dev = format!("vpn{i}");
        if used.contains(&dev) {
            continue;
        }
        // A sysfs mount may still describe a different network namespace. Unknown
        // kernel inspection is an error, not evidence that the name is available.
        if crate::network_interface::index(&dev)?.is_none() {
            return Ok(dev);
        }
    }
    anyhow::bail!("no free client TUN device in vpn0..vpn255")
}

/// Ensure the profile has a distinct TUN device. If the INI already sets `dev`,
/// keep it; if this profile already exists, reuse its device (editing doesn't move
/// it); otherwise auto-assign a free `vpnN` so multiple tunnels can coexist.
fn ensure_unique_dev(name: &str, ini: &str) -> anyhow::Result<String> {
    if crate::config::editor::explicit_device(ini)?.is_some() {
        return Ok(ini.to_string());
    }
    let previous = read_profile(&ClientManager::profile_path(name))
        .ok()
        .flatten()
        .and_then(|s| crate::config::parse_client_config_strict(&s).ok())
        .map(|c| c.tun.name.clone());
    let dev = match previous {
        Some(dev) => dev,
        None => free_dev(name)?,
    };
    Ok(crate::config::set_section_keys(
        ini,
        "qeli",
        &[("dev", dev)],
    ))
}

/// Validate with the common client contract, then apply the panel's additional
/// command/path restrictions before any profile write or device assignment.
fn validate_panel_profile(ini: &str) -> anyhow::Result<()> {
    let cfg = crate::config::parse_client_config_strict(ini)?;
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
             a `password_file` under /etc/qeli/"
        );
    }
    // SECURITY: `password_file` is READ BY THIS SERVER — `client_manager` spawns
    // `qeli client -c <profile>` as a child of the supervisor (root / CAP_NET_ADMIN),
    // and the client uses the file's contents as the password, sending it to whatever
    // `server.address` the profile names. An unrestricted path therefore turns the
    // panel into an arbitrary-file-read-and-exfiltrate primitive (/etc/shadow, private
    // keys, .env), which is exactly the boundary `password_command` and the hook checks
    // above exist to defend. Confine it to the config directory, the same whitelist
    // used for identity_key / users_file / tls_cert. (`autostart` would otherwise
    // re-trigger the read on every server restart.)
    if let Some(ref pw_file) = cfg.auth.password_file {
        if let Err(e) =
            super::paths::validate_path_field(pw_file, super::paths::ALLOWED_CONFIG_DIRS)
        {
            anyhow::bail!("password_file: {e}");
        }
    }
    Ok(())
}

/// Persist the original INI, retaining comments and assigning a TUN device if absent.
fn persist(name: &str, ini: &str, checked_raw: Option<&str>) -> anyhow::Result<bool> {
    validate_panel_profile(ini)?;
    let ini = ensure_unique_dev(name, ini)?;
    // Validate the bytes that will be written, including the automatic device assignment.
    crate::config::parse_client_config_strict(&ini)?;
    std::fs::create_dir_all(crate::server::client_manager::CLIENTS_DIR)?;
    // The profile embeds the plaintext VPN password (`pass = …`), so it must be
    // born 0600 — `write_atomic` would fall back to 0644 for a new file, leaving
    // credentials world-readable to any local user.
    write_profile_if_unchanged(&ClientManager::profile_path(name), &ini, checked_raw)
}

/// Create/replace a profile. Body is EITHER a full raw INI (`{name, raw}` — full
/// control over every client key) OR form fields (`{name, server, proto, ...}`).
pub async fn save_profile(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Json<Value> {
    let _write_guard = state.config_write_lock.lock().await;
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
        .filter(|s| !s.trim().is_empty());
    let ini = match raw {
        Some(r) => r.to_string(),
        None => ini_from_fields(&body),
    };
    let path = ClientManager::profile_path(&name);
    if let Err(error) = std::fs::create_dir_all(crate::server::client_manager::CLIENTS_DIR) {
        return Json(super::err_json(format!(
            "cannot create client profile directory: {error}"
        )));
    }
    let _file_lock = match super::config::lock_server_config(FsPath::new(&path)).await {
        Ok(lock) => lock,
        Err(error) => return Json(super::err_json(error)),
    };
    let current = match read_profile(&path) {
        Ok(current) => current,
        Err(error) => return Json(super::err_json(error.to_string())),
    };
    if let Some(conflict) = profile_revision_conflict(&body, current.as_deref()) {
        return Json(conflict);
    }
    match persist(&name, &ini, current.as_deref()) {
        Ok(true) => {
            let requires_reconnect = state.client_manager.is_running(&name).await;
            Json(json!({ "ok": true, "name": name, "requires_reconnect": requires_reconnect }))
        }
        Ok(false) => Json(super::err_json(
            "The client profile changed on disk during this save. Reload and review it.",
        )),
        Err(e) => Json(super::err_json(e.to_string())),
    }
}

/// Import a `qeli://` link as a profile. Body: {link, name?}.
pub async fn import_link(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Json<Value> {
    let _write_guard = state.config_write_lock.lock().await;
    let link = body
        .get("link")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_matches([' ', '\t', '\r', '\n']);
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
    // Links do not carry gateway; from_link applies the shared client default.
    let cfg = ClientConfig::from_link(&parsed);
    let path = ClientManager::profile_path(&name);
    if let Err(error) = std::fs::create_dir_all(crate::server::client_manager::CLIENTS_DIR) {
        return Json(super::err_json(format!(
            "cannot create client profile directory: {error}"
        )));
    }
    let _file_lock = match super::config::lock_server_config(FsPath::new(&path)).await {
        Ok(lock) => lock,
        Err(error) => return Json(super::err_json(error)),
    };
    let current = match read_profile(&path) {
        Ok(current) => current,
        Err(error) => return Json(super::err_json(error.to_string())),
    };
    // Import is create-only, even if an API caller supplies an edit revision.
    if let Some(conflict) = profile_revision_conflict(&json!({}), current.as_deref()) {
        return Json(conflict);
    }
    match persist(&name, &cfg.to_ini_string(), current.as_deref()) {
        Ok(true) => Json(json!({ "ok": true, "name": name })),
        Ok(false) => Json(super::err_json(
            "The client profile changed on disk during this import. Reload and review it.",
        )),
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
    match read_profile(&ClientManager::profile_path(&name)) {
        Ok(Some(ini)) => {
            let revision = super::config::config_revision(&ini);
            Json(json!({ "ok": true, "name": name, "raw": ini, "revision": revision }))
        }
        Ok(None) => Json(super::err_json("profile not found")),
        Err(error) => Json(super::err_json(error.to_string())),
    }
}

pub async fn delete_profile(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    if !ClientManager::valid_name(&name) {
        return Json(super::err_json("invalid name"));
    }
    let _write_guard = state.config_write_lock.lock().await;
    let profile_path = ClientManager::profile_path(&name);
    if !FsPath::new(crate::server::client_manager::CLIENTS_DIR).is_dir() {
        return Json(super::err_json("profile not found"));
    }
    let _file_lock = match super::config::lock_server_config(FsPath::new(&profile_path)).await {
        Ok(lock) => lock,
        Err(error) => return Json(super::err_json(error)),
    };
    let checked_raw = match read_profile(&profile_path) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Json(super::err_json("profile not found")),
        Err(error) => return Json(super::err_json(error.to_string())),
    };
    if let Some(conflict) = delete_revision_conflict(&headers, &checked_raw) {
        return Json(conflict);
    }
    if let Err(error) = state.client_manager.disconnect(&name).await {
        return Json(super::err_json(format!(
            "could not stop profile '{name}': {error}"
        )));
    }
    // Detect a manual edit during graceful disconnect before unlinking the file.
    match read_profile(&profile_path) {
        Ok(Some(raw)) if raw == checked_raw => {}
        Ok(Some(raw)) => {
            return Json(json!({
                "ok": false,
                "kind": "config_conflict",
                "error": "The client profile changed during disconnect. Nothing was deleted; reload it.",
                "current_revision": super::config::config_revision(&raw),
            }))
        }
        Ok(None) => return Json(super::err_json("profile not found")),
        Err(error) => return Json(super::err_json(error.to_string())),
    }
    match std::fs::remove_file(&profile_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Json(super::err_json("profile not found"));
        }
        Err(error) => {
            return Json(super::err_json(format!(
                "could not delete {profile_path}: {error}"
            )));
        }
    }

    let mut cleanup_warnings = Vec::new();
    for path in [
        ClientManager::log_path(&name),
        ClientManager::status_path(&name),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => cleanup_warnings.push(format!("{path}: {error}")),
        }
    }
    Json(json!({
        "ok": true,
        "warning": if cleanup_warnings.is_empty() {
            None
        } else {
            Some(format!("profile deleted, but auxiliary cleanup failed: {}", cleanup_warnings.join("; ")))
        }
    }))
}

pub async fn connect(
    State(state): State<Arc<ServerState>>,
    _g: auth::AuthGuard,
    Path(name): Path<String>,
) -> Json<Value> {
    let _write_guard = state.config_write_lock.lock().await;
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

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use crate::config::format::IniDoc;

    #[test]
    fn client_status_requires_matching_profile_and_stable_size_limit() {
        let path = std::env::temp_dir().join(format!(
            "qeli-client-status-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path_str = path.to_str().unwrap();
        std::fs::write(&path, r#"{"schema":1,"profile":"alpha","state":"running"}"#).unwrap();
        assert_eq!(
            read_structured_status(path_str, "alpha").unwrap()["state"],
            "running"
        );
        assert!(read_structured_status(path_str, "beta").is_none());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(64 * 1024 + 1)
            .unwrap();
        assert!(read_structured_status(path_str, "alpha").is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn delete_revision_header_rejects_missing_and_stale_versions() {
        let original = "[qeli]\nserver = first:443\n";
        let modified = "# edited\n[qeli]\nserver = first:443\n";
        let mut headers = HeaderMap::new();
        assert_eq!(
            delete_revision_conflict(&headers, original).unwrap()["kind"],
            "config_revision_required"
        );
        headers.insert(
            "x-qeli-revision",
            super::super::config::config_revision(original)
                .parse()
                .unwrap(),
        );
        assert!(delete_revision_conflict(&headers, original).is_none());
        assert_eq!(
            delete_revision_conflict(&headers, modified).unwrap()["kind"],
            "config_conflict"
        );
    }

    #[test]
    fn client_profile_revision_rejects_stale_edit_and_name_collision() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-client-revision-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("client.conf");
        let path = file.to_str().unwrap();
        let first = "[qeli]\nserver = first:443\n";
        let edited = "# manual edit\n[qeli]\nserver = first:443\n";
        assert_eq!(read_profile(path).unwrap(), None);
        assert!(write_profile_if_unchanged(path, first, None).unwrap());
        assert!(!write_profile_if_unchanged(path, edited, None).unwrap());
        assert_eq!(
            profile_revision_conflict(&json!({}), Some(first)).unwrap()["kind"],
            "config_revision_required"
        );
        let expected = super::super::config::config_revision(first);
        assert!(
            profile_revision_conflict(&json!({"expected_revision": expected}), Some(first))
                .is_none()
        );
        std::fs::write(path, edited).unwrap();
        assert!(!write_profile_if_unchanged(path, first, Some(first)).unwrap());
        assert_eq!(
            profile_revision_conflict(&json!({"expected_revision": expected}), Some(edited))
                .unwrap()["kind"],
            "config_conflict"
        );
        assert_eq!(read_profile(path).unwrap().as_deref(), Some(edited));
        assert!(write_profile_if_unchanged(path, first, Some(edited)).unwrap());
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(crate::transport_core::MAX_CONFIG_BYTES as u64 + 1)
            .unwrap();
        assert!(read_profile(path).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn panel_validation_uses_shared_config_rules_and_retains_privilege_limits() {
        for source in [
            "[qeli]\nserver=host:443\ndns=1.1.1.1\n",
            "[qeli]\nserver=host:443\ninclude=10.0.0.0/8\ninclude=192.0.2.0/24\n",
            "\u{feff}[QELI]\nSERVER=host:443\nDEV=vpn42\n",
        ] {
            validate_panel_profile(source).unwrap();
        }
        for tail in [
            "post_up=echo bad",
            "post_down=echo bad",
            "password_command=echo bad",
            "password_file=/etc/shadow",
            "reconnect_retries=-2",
            "apps_mode=include",
        ] {
            assert!(
                validate_panel_profile(&format!("[qeli]\nserver=host:443\n{tail}\n")).is_err(),
                "{tail}"
            );
        }
    }

    #[test]
    fn backend_form_agrees_with_the_browser_ini_corpus() {
        let cases: Value = serde_json::from_str(include_str!(
            "../../../../conformance/panel-client-ini.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let ini =
                ini_from_fields(&json!({"server":"fixture.invalid:443","pass":case["password"]}));
            let parsed = crate::config::parse_client_config_strict(&ini).unwrap();
            assert_eq!(parsed.auth.password.as_deref(), case["password"].as_str());
            let expected = case["raw"].as_str().unwrap();
            assert_eq!(
                ini.lines().find(|line| line.starts_with("pass = ")),
                expected.lines().find(|line| line.starts_with("pass = "))
            );
        }
    }

    #[test]
    fn structured_states_map_to_honest_panel_states() {
        for (state, expected) in [
            ("running", "up"),
            ("retrying", "error"),
            ("failed", "error"),
            ("connecting", "connecting"),
            ("awaiting_network", "connecting"),
            ("stopped", "connecting"),
        ] {
            assert_eq!(
                panel_state_from_diagnostics(&json!({ "state": state })),
                expected
            );
        }
    }

    #[test]
    fn field_form_preserves_literal_passwords_and_obfuscation_keys() {
        for password in [
            "plain",
            "\"secret\"",
            " secret ",
            "\tsecret\t",
            "a\\b\"c",
            "#;=",
        ] {
            let ini = ini_from_fields(
                &json!({"server": "fixture.invalid:443", "pass": password, "obfs_key": password}),
            );
            let config = crate::config::parse_client_config_strict(&ini).unwrap();
            assert_eq!(config.auth.password.as_deref(), Some(password));
            assert_eq!(config.obfuscation.obfs_key, password);
        }
    }

    #[test]
    fn field_form_serializes_ipv6_policy_routes_and_fail_closed_exceptions() {
        let ini = ini_from_fields(&json!({
            "server": "vpn.example.com:443",
            "user": "alice",
            "pass": "secret",
            "ipv6": "required",
            "include": "10.20.0.0/16, 2001:db8:20::/48",
            "exclude": "192.168.50.0/24, 2001:db8:50::/48",
            "lan_subnet_ipv6": "fd42:50::/64",
            "gateway": true,
            "allow_ipv4_leak": true,
            "allow_ipv6_leak": true
        }));
        let doc = IniDoc::parse(&ini).expect("generated INI must parse");
        let config = ClientConfig::from_ini(&doc).expect("generated profile must validate");

        assert_eq!(config.routing.ipv6.to_string(), "required");
        assert!(config.routing.add_default_gateway);
        assert!(config.routing.allow_ipv4_leak);
        assert!(config.routing.allow_ipv6_leak);
        assert_eq!(
            config.routing.include,
            vec!["10.20.0.0/16".to_string(), "2001:db8:20::/48".to_string()]
        );
        assert_eq!(
            config.routing.exclude,
            vec![
                "192.168.50.0/24".to_string(),
                "2001:db8:50::/48".to_string()
            ]
        );
        assert_eq!(config.routing.lan_subnet_ipv6, "fd42:50::/64");
        assert!(ini.contains("ipv6 = required\n"));
        assert!(ini.contains("include = 10.20.0.0/16, 2001:db8:20::/48\n"));
        assert!(ini.contains("exclude = 192.168.50.0/24, 2001:db8:50::/48\n"));
        assert!(ini.contains("lan_subnet_ipv6 = fd42:50::/64\n"));
        assert!(ini.contains("allow_ipv4_leak = true\n"));
        assert!(ini.contains("allow_ipv6_leak = true\n"));
    }
}

#[cfg(test)]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated netns"]
fn native_panel_device_selection_uses_calling_namespace() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: only this new disposable thread changes namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        anyhow::ensure!(
            !std::path::Path::new("/sys/class/net/vpn0").exists(),
            "fixture requires inherited sysfs without vpn0"
        );
        let output = crate::system_command::Command::new("ip")
            .args(["link", "add", "vpn0", "type", "dummy"])
            .output()?;
        anyhow::ensure!(output.status.success());
        let used = std::collections::HashSet::from(["vpn1".to_string()]);
        anyhow::ensure!(select_free_dev(&used)? == "vpn2");
        anyhow::ensure!(!std::path::Path::new("/sys/class/net/vpn0").exists());
        Ok(())
    })
    .join()
    .expect("native panel device test panicked")
}
