use super::paths::{
    validate_in_whitelist, validate_path_field, ALLOWED_CONFIG_DIRS, ALLOWED_LOG_DIRS,
};
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn get_config(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    // Return the live on-disk config so the panel reflects Quick-Start / Apply
    // changes (the supervisor's in-memory `config` is only its startup snapshot).
    if let Some(path) = state.config_path.lock().await.clone() {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = crate::config::parse_server_config(&s) {
                return Ok(Json(json!({ "ok": true, "config": cfg })));
            }
        }
    }
    Ok(Json(json!({ "ok": true, "config": &state.config })))
}

/// Canonical defaults for the UI: a fully-defaulted profile template (every
/// serde `default_*` applied). The panel builds new
/// profiles / quick-start presets from this instead of hard-coding the schema in
/// JS — single source of truth, so the form never drifts from the Rust structs.
pub async fn get_config_defaults(_guard: auth::AuthGuard) -> Result<Json<Value>, AuthError> {
    let profile = crate::config::server::ProfileConfig::baseline();
    Ok(Json(json!({
        "ok": true,
        "profile": profile,
    })))
}

#[derive(Clone, Copy)]
struct QuickStartSpec {
    id: &'static str,
    transport: &'static str,
    port: u16,
    index: u8,
    obfuscation: &'static str,
    reality: bool,
    real_tls: bool,
    needs_short_id: bool,
    needs_obfs_key: bool,
    fronting: &'static str,
    quic: bool,
    padding: bool,
    heartbeat: bool,
    shaping: bool,
    multipath: bool,
    awg: bool,
}

const QUICKSTART_SPECS: &[QuickStartSpec] = &[
    QuickStartSpec {
        id: "reality-tls",
        transport: "tcp",
        port: 443,
        index: 0,
        obfuscation: "fake-tls",
        reality: true,
        real_tls: true,
        needs_short_id: true,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: false,
        padding: false,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "reality",
        transport: "tcp",
        port: 8443,
        index: 1,
        obfuscation: "fake-tls",
        reality: true,
        real_tls: false,
        needs_short_id: true,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: false,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "fake-tls",
        transport: "tcp",
        port: 8444,
        index: 2,
        obfuscation: "fake-tls",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: false,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "obfs-ws",
        transport: "tcp",
        port: 8445,
        index: 3,
        obfuscation: "obfs",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: true,
        fronting: "websocket",
        quic: false,
        padding: false,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "obfs-none",
        transport: "tcp",
        port: 8446,
        index: 4,
        obfuscation: "obfs",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: true,
        fronting: "none",
        quic: false,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "plain",
        transport: "tcp",
        port: 8447,
        index: 5,
        obfuscation: "plain",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: false,
        padding: false,
        heartbeat: true,
        shaping: false,
        multipath: true,
        awg: false,
    },
    QuickStartSpec {
        id: "udp-fake-tls",
        transport: "udp",
        port: 8448,
        index: 6,
        obfuscation: "fake-tls",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: false,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: false,
        awg: false,
    },
    QuickStartSpec {
        id: "udp-quic",
        transport: "udp",
        port: 8449,
        index: 7,
        obfuscation: "fake-tls",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: false,
        fronting: "websocket",
        quic: true,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: false,
        awg: false,
    },
    QuickStartSpec {
        id: "udp-obfs",
        transport: "udp",
        port: 8450,
        index: 8,
        obfuscation: "obfs",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: true,
        fronting: "websocket",
        quic: false,
        padding: false,
        heartbeat: false,
        shaping: true,
        multipath: false,
        awg: false,
    },
    QuickStartSpec {
        id: "obfs-awg",
        transport: "tcp",
        port: 8451,
        index: 9,
        obfuscation: "obfs",
        reality: false,
        real_tls: false,
        needs_short_id: false,
        needs_obfs_key: true,
        fronting: "none",
        quic: false,
        padding: true,
        heartbeat: false,
        shaping: true,
        multipath: true,
        awg: true,
    },
];

fn random_hex(bytes: usize) -> String {
    use rand::Rng;
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn build_quickstart_profile(
    mode: &str,
) -> Result<
    (
        crate::config::server::ProfileConfig,
        Option<String>,
        Option<String>,
    ),
    String,
> {
    let spec = QUICKSTART_SPECS
        .iter()
        .find(|spec| spec.id == mode)
        .ok_or_else(|| format!("unknown Quick Start mode '{mode}'"))?;
    let short_id = spec.needs_short_id.then(|| random_hex(8));
    let obfs_key = spec.needs_obfs_key.then(|| random_hex(16));
    let mut profile = crate::config::server::ProfileConfig::baseline();
    profile.name = spec.id.to_string();
    profile.enabled = true;
    profile.bind.address = "0.0.0.0".into();
    profile.bind.transport = spec.transport.into();
    profile.bind.port = spec.port;
    profile.tun.name = format!("vpn{}", spec.index);
    profile.tun.address = format!("10.9.{}.1", spec.index);
    profile.tun.mtu = 1400;
    profile.pool.cidr = format!("10.9.{}.0/24", spec.index);
    profile.dns.enabled = true;
    profile.dns.listen = profile.tun.address.clone();
    profile.routing.nat.enabled = true;
    profile.obfuscation.mode = spec.obfuscation.into();
    profile.obfuscation.obfs_key = obfs_key.clone().unwrap_or_default();
    profile.obfuscation.fronting = spec.fronting.into();
    profile.obfuscation.tls.server_name = "www.microsoft.com".into();
    profile.obfuscation.tls.reality_proxy.enabled = spec.reality;
    profile.obfuscation.tls.reality_proxy.target = "www.microsoft.com".into();
    profile.obfuscation.tls.reality_proxy.target_port = 443;
    profile.obfuscation.tls.reality_proxy.short_ids = short_id.clone().into_iter().collect();
    profile.obfuscation.tls.reality_proxy.real_tls = spec.real_tls;
    profile.obfuscation.quic.enabled = spec.quic;
    profile.obfuscation.heartbeat.enabled = spec.heartbeat;
    profile.obfuscation.traffic_shaping.enabled = spec.shaping;
    profile.obfuscation.padding.enabled = spec.padding;
    profile.obfuscation.multipath.enabled = spec.multipath;
    profile.obfuscation.multipath.adaptive = spec.multipath;
    profile.obfuscation.awg.enabled = spec.awg;
    if spec.awg {
        profile.obfuscation.awg.jc = 4;
        profile.obfuscation.awg.jmin = 40;
        profile.obfuscation.awg.jmax = 200;
    }
    Ok((profile, short_id, obfs_key))
}

/// Every RFC1918 /24, ordered so a host-wide route for one private family quickly falls
/// through to another instead of validating all 65,536 subnets in 10/8 first.
fn quickstart_private_24_candidates(preferred_third: u8) -> Vec<(u8, u8, u8)> {
    let mut candidates = Vec::with_capacity(69_888);
    candidates.push((10, 9, preferred_third));
    for third in 0u8..=u8::MAX {
        for second in 16u8..=31 {
            candidates.push((172, second, third));
        }
        candidates.push((192, 168, third));
        for second in 0u8..=u8::MAX {
            candidates.push((10, second, third));
        }
    }
    let mut seen = std::collections::HashSet::with_capacity(candidates.len());
    candidates.retain(|candidate| seen.insert(*candidate));
    candidates
}

fn place_quickstart_network(
    mut profile: crate::config::server::ProfileConfig,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
) -> Result<crate::config::server::ProfileConfig, String> {
    // Preserve the familiar 10.9.<mode>.0/24 first, then search private /24s. The complete
    // candidate config goes through both schema validation and the same host route/address
    // preflight as restart, so Quick Start chooses rather than merely hard-codes a subnet.
    let preferred = profile
        .pool
        .cidr
        .split('.')
        .nth(2)
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let initial_tun = profile.tun.address.clone();
    profile
        .pool
        .exclude
        .retain(|address| address != &initial_tun);
    for (first, second, third) in quickstart_private_24_candidates(preferred) {
        profile.tun.address = format!("{first}.{second}.{third}.1");
        profile.pool.cidr = format!("{first}.{second}.{third}.0/24");
        profile.dns.listen = profile.tun.address.clone();
        let mut candidate = current.clone();
        candidate.profiles.retain(|item| item.name != profile.name);
        candidate.profiles.push(profile.clone());
        if crate::server::validate_profiles(&candidate).is_err() {
            continue;
        }
        if host
            .is_some_and(|snapshot| crate::server::preflight::check(&candidate, snapshot).is_err())
        {
            continue;
        }
        return Ok(profile);
    }
    Err("no collision-free private /24 is available for this Quick Start profile".into())
}

/// Build a profile only on the first Quick Start launch.  Re-launching a mode is an
/// operational "make sure this profile is up" action, not an implicit credential rotation or
/// factory reset: preserve the complete existing profile and merely re-enable it.  Rotation is
/// deliberately left to the explicit config controls where the operator can see the impact on
/// already-issued clients.
fn quickstart_profile_for_current(
    mode: &str,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
) -> Result<
    (
        crate::config::server::ProfileConfig,
        Option<String>,
        Option<String>,
        bool,
    ),
    String,
> {
    let spec = QUICKSTART_SPECS
        .iter()
        .find(|spec| spec.id == mode)
        .ok_or_else(|| format!("unknown Quick Start mode '{mode}'"))?;

    if let Some(existing) = current
        .profiles
        .iter()
        .find(|profile| profile.name == spec.id)
    {
        let mut profile = existing.clone();
        profile.enabled = true;
        let short_id = spec
            .needs_short_id
            .then(|| {
                profile
                    .obfuscation
                    .tls
                    .reality_proxy
                    .short_ids
                    .first()
                    .cloned()
            })
            .flatten();
        let obfs_key = spec
            .needs_obfs_key
            .then(|| profile.obfuscation.obfs_key.clone())
            .filter(|value| !value.is_empty());
        if spec.needs_short_id && short_id.is_none() {
            return Err(format!(
                "existing Quick Start profile '{}' has no REALITY short_id; repair it in Configuration or remove it before recreating",
                spec.id
            ));
        }
        if spec.needs_obfs_key && obfs_key.is_none() {
            return Err(format!(
                "existing Quick Start profile '{}' has no obfs_key; repair it in Configuration or remove it before recreating",
                spec.id
            ));
        }
        return Ok((profile, short_id, obfs_key, true));
    }

    let (profile, short_id, obfs_key) = build_quickstart_profile(mode)?;
    let profile = place_quickstart_network(profile, current, host)?;
    Ok((profile, short_id, obfs_key, false))
}

pub async fn get_quickstart_profile(
    State(state): State<Arc<ServerState>>,
    Path(mode): Path<String>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let current = if let Some(path) = state.config_path.lock().await.clone() {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| crate::config::parse_server_config(&text).ok())
            .unwrap_or_else(|| state.config.clone())
    } else {
        state.config.clone()
    };
    let host = crate::server::preflight::gather_host_net();
    match quickstart_profile_for_current(&mode, &current, host.as_ref()) {
        Ok((profile, short_id, obfs_key, reused)) => Ok(Json(json!({
            "ok": true,
            "profile": profile,
            "sid": short_id,
            "obfs_key": obfs_key,
            "reused": reused,
        }))),
        Err(error) => Ok(Json(super::err_json(error))),
    }
}

pub async fn put_config(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let new_config_value = match body.get("config") {
        Some(v) => v.clone(),
        None => return Ok(Json(super::err_json("config field required"))),
    };

    // Deserialize-validate the structure first.
    let mut parsed: crate::config::server::ServerConfig =
        match serde_json::from_value(new_config_value.clone()) {
            Ok(c) => c,
            Err(e) => return Ok(Json(super::err_json(format!("invalid config: {}", e)))),
        };

    // SECURITY: profile/user/group names are serialized as INI section instances
    // (`[profile:<name>]`) and metadata keys as `metadata.<key>` — unlike values,
    // both are emitted BARE. A control character in one splits the line and forges
    // extra config lines on re-parse, which is enough to smuggle a
    // `routing.post_up` hook past the file-only hook restore below and get it run
    // through `/bin/sh -c` on the next start. Reject at the boundary so the
    // operator sees a clear error; `config/format.rs` also strips control chars at
    // serialize time as a fail-closed backstop.
    let name_err = |what: &str, name: &str| {
        format!(
            "{what} {name:?} is invalid — it must be non-empty, at most 128 bytes, and carry no \
             control characters or surrounding whitespace (names become INI section headers, so a \
             newline there could forge config lines)"
        )
    };
    let bad_name = parsed
        .profiles
        .iter()
        .find(|p| !crate::util::is_valid_ident(&p.name))
        .map(|p| name_err("profile name", &p.name))
        .or_else(|| {
            parsed
                .auth
                .groups
                .keys()
                .find(|g| !crate::util::is_valid_ident(g))
                .map(|g| name_err("group name", g))
        })
        .or_else(|| {
            parsed
                .auth
                .users
                .iter()
                .find(|u| !crate::util::is_valid_ident(&u.username))
                .map(|u| name_err("username", &u.username))
        })
        .or_else(|| {
            parsed
                .auth
                .users
                .iter()
                .flat_map(|u| u.metadata.keys())
                .find(|k| !crate::util::is_valid_ident(k))
                .map(|k| name_err("metadata key", k))
        });
    if let Some(e) = bad_name {
        return Ok(Json(super::err_json(e)));
    }
    // Usernames must be UNIQUE, not merely well-formed. The parser keeps the first
    // `[user:x]` block and drops the rest (first-wins, matching `find_user`), so a second
    // block saved through here would silently vanish on the next read — or worse, if the
    // duplicate is the one the admin edited, the change appears to save and has no effect.
    // (Audit 2026-07-27, C7.)
    {
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = parsed
            .auth
            .users
            .iter()
            .find(|u| !seen.insert(u.username.as_str()))
        {
            return Ok(Json(super::err_json(format!(
                "duplicate username '{}' — each user may appear only once; \
                 only the first entry would ever be used",
                dup.username
            ))));
        }
    }

    // A non-empty admin password_hash must be a REAL Argon2 PHC string. It is applied
    // verbatim, and the hash doubles as the session-signing salt — so a truncated
    // paste or a typed plaintext invalidated every session and could then never
    // verify, locking the operator out of the panel (recoverable only by editing the
    // config on the host). Empty is legal and means "keep the hash already on disk"
    // (see the restore below) — NOT "open access".
    if !parsed.web.password_hash.is_empty() {
        if let Err(e) = super::users::validate_argon2_hash(&parsed.web.password_hash) {
            return Ok(Json(super::err_json(format!(
                "web.password_hash: {e} — use the \"Set password\" button (it hashes for you); \
                 leaving the field empty keeps the current password"
            ))));
        }
    }

    // Reject configs whose logging.file would let GET /api/logs read arbitrary
    // files (e.g. /etc/shadow). Empty / None means "no file logging".
    if let Some(ref log_file) = parsed.logging.file {
        if let Err(e) = validate_path_field(log_file, ALLOWED_LOG_DIRS) {
            return Ok(Json(json!({
                "ok": false,
                "error": format!("logging.file: {}", e),
            })));
        }
    }

    // Reject users_file pointed outside config whitelist.
    if let Err(e) = validate_path_field(&parsed.auth.users_file, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("auth.users_file: {}", e),
        })));
    }

    // Reject profile identity_key / web TLS cert+key paths outside the config whitelist —
    // otherwise `/api/identity/*/rotate` (or `/api/share`, which generates a missing key)
    // would create/overwrite an arbitrary file (e.g. /etc/cron.d/x) with key bytes.
    for p in &parsed.profiles {
        if let Some(ref id_key) = p.identity_key {
            if let Err(e) = validate_path_field(id_key, ALLOWED_CONFIG_DIRS) {
                return Ok(Json(json!({
                    "ok": false,
                    "error": format!("profile '{}' identity_key: {}", p.name, e),
                })));
            }
        }
        // Reject advertised routes whose CIDR is missing/malformed, or whose
        // gateway is not a bare next hop. Without this the panel happily saves a
        // route with an EMPTY CIDR field (subnet typed into `gateway` instead):
        // it serializes to `route = " gateway=172.16.20.0/24 metric=100"`, parses
        // back with an empty cidr, and every client silently drops it — the admin
        // sees a saved route that never reaches anyone. Fail loudly at authoring time.
        for r in &p.routing.advertised_routes {
            if !crate::util::is_valid_cidr(&r.cidr) {
                return Ok(Json(json!({
                    "ok": false,
                    "error": format!(
                        "profile '{}': route CIDR is missing or invalid ({:?}). \
                         The network goes in the CIDR field, e.g. 172.16.20.0/24 — \
                         `gateway` takes a next-hop IP, not a subnet.",
                        p.name, r.cidr
                    ),
                })));
            }
            if let Some(ref gw) = r.gateway {
                if !crate::util::is_valid_gateway(gw) {
                    return Ok(Json(json!({
                        "ok": false,
                        "error": format!(
                            "profile '{}': route {} — gateway must be a bare next-hop IP \
                             (e.g. 10.0.0.1) or left empty to use the profile's tun address; got {:?}.",
                            p.name, r.cidr, gw
                        ),
                    })));
                }
            }
        }
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_cert, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(
            json!({ "ok": false, "error": format!("web.tls_cert: {}", e) }),
        ));
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_key, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(
            json!({ "ok": false, "error": format!("web.tls_key: {}", e) }),
        ));
    }

    // Resolve and validate the write target. config_path is set at startup and
    // never mutated, but we re-check on every write as defense in depth.
    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })));
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Refused config write to '{}': {}", target, e);
            return Ok(Json(json!({
                "ok": false,
                "error": format!("config path rejected: {}", e),
            })));
        }
    };

    // SECURITY: post_up/post_down run arbitrary commands as root. They are
    // FILE-ONLY — the panel/API must never set or change them, or a panel
    // compromise becomes RCE. Restore each profile's hooks from the current
    // on-disk config (discarding whatever the request sent); if the file can't be
    // read, force-clear them so the panel can never introduce a hook.
    match std::fs::read_to_string(&canon)
        .ok()
        .and_then(|s| crate::config::parse_server_config(&s).ok())
    {
        Some(cur) => {
            for p in &mut parsed.profiles {
                let (up, down) = cur
                    .profiles
                    .iter()
                    .find(|c| c.name == p.name)
                    .map(|c| (c.routing.post_up.clone(), c.routing.post_down.clone()))
                    .unwrap_or_default();
                p.routing.post_up = up;
                p.routing.post_down = down;
            }
            // Inline [user:*] password secrets are #[serde(skip_serializing)], so GET
            // stripped them and the structured editor holds no field for them. Restore
            // each inline user's hash/enc from disk (matched by username) so a structured
            // save can't silently wipe them and lock the user out.
            for u in &mut parsed.auth.users {
                if u.password_hash.is_empty() {
                    if let Some(cur_u) = cur.auth.users.iter().find(|c| c.username == u.username) {
                        u.password_hash = cur_u.password_hash.clone();
                        u.password_enc = cur_u.password_enc.clone();
                    }
                }
            }
            // The web ADMIN password_hash is #[serde(skip_serializing)] too (stripped
            // from GET so the browser never sees it), so a structured save carries an
            // empty hash. Restore it from disk — otherwise every config save wiped the
            // admin password, and on the next restart the panel refused to start
            // (non-loopback bind + empty password = fail-closed) and locked the operator
            // out. Only the explicit "set password" flow (hashAdminPw) sends a new hash.
            if parsed.web.password_hash.is_empty() {
                parsed.web.password_hash = cur.web.password_hash.clone();
            }
        }
        None => {
            // Can't read the current config to preserve secrets: if inline users exist,
            // refuse rather than overwrite them with empty hashes and lock everyone out.
            if !parsed.auth.users.is_empty() {
                return Ok(Json(super::err_json(
                    "cannot save: current config is unreadable, so inline [user:*] passwords \
                     can't be preserved — refusing to overwrite and lock users out",
                )));
            }
            for p in &mut parsed.profiles {
                p.routing.post_up.clear();
                p.routing.post_down.clear();
            }
        }
    }

    // Write flat-INI (the canonical on-disk format) so the file stays
    // consistent with hand-edited configs. Note: structured editing through the
    // UI cannot preserve hand-written comments — for comment-heavy configs, edit
    // the file directly. We serialize the validated struct so the output is a
    // faithful, lossless round-trip of the config.
    // Did the PANEL's own socket change (web.bind/port/tls/enabled)? Those are bound by the
    // supervisor at startup and NOT reapplied by the worker restart — they need a FULL restart.
    // Compare against config.web, the boot-time snapshot = what the panel is bound to now.
    let cur = &state.config.web;
    let w = &parsed.web;
    let needs_full_restart = w.bind != cur.bind
        || w.port != cur.port
        || w.enabled != cur.enabled
        || w.tls != cur.tls
        || w.tls_cert != cur.tls_cert
        || w.tls_key != cur.tls_key
        // The router is NESTED under the boot-time base_path (web/mod.rs), and the
        // base-href rewrite middleware reads the same startup snapshot — so a change
        // here does NOT take effect on a worker restart, only on a full process
        // restart. Without this the panel said "applied live" while still serving on
        // the old prefix, sending the operator on a 404 hunt behind their proxy.
        || w.base_path != cur.base_path
        // `auth.users_file` too, even though it is not a `[web]` key. Every CRUD path in
        // the panel resolves it from the BOOT-TIME snapshot (`state.config.auth.users_file`
        // in api/users.rs, share.rs and usage.rs), while the worker re-reads the config on
        // its own restart. Change the path and press the worker-restart button and the two
        // processes end up on different files: users created in the panel do not exist for
        // the VPN, users deleted there keep connecting, and nothing says so.
        // (Audit 2026-07-27, D1.)
        || parsed.auth.users_file != state.config.auth.users_file;

    let config_str = parsed.to_ini_string();
    // Fail-closed defense-in-depth: never write a config we can't read back. The
    // control-char backstops (config/format.rs) already neutralize INI injection
    // through values, names and keys; this catches any residual serialization
    // corruption before it reaches disk (mirrors set_blocked_settings).
    let reparsed = match crate::config::parse_server_config(&config_str) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Json(json!({
                "ok": false,
                "error": format!("refusing to write a config that fails re-parse: {}", e),
            })));
        }
    };
    // SECURITY: the restore loop above is the ONLY thing permitted to set
    // post_up/post_down. Re-parsing successfully is not enough — a forged section
    // or hook line would also parse. Assert the text we are about to write reads
    // back with EXACTLY the hooks we intended and no extra profile: anything else
    // means a name/key smuggled a hook past the guard, and it would run via
    // `/bin/sh -c` on the next start.
    let intended: std::collections::HashMap<&str, (&str, &str)> = parsed
        .profiles
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                (p.routing.post_up.as_str(), p.routing.post_down.as_str()),
            )
        })
        .collect();
    for p in &reparsed.profiles {
        let ok = intended
            .get(p.name.as_str())
            .is_some_and(|(up, down)| *up == p.routing.post_up && *down == p.routing.post_down);
        if !ok {
            log::error!(
                "Refused config write: profile '{}' re-parsed with unexpected lifecycle hooks \
                 (possible INI injection through a name/key)",
                crate::util::log_sanitize(&p.name)
            );
            return Ok(Json(json!({
                "ok": false,
                "error": format!(
                    "refusing to write: profile {:?} reads back with lifecycle hooks the panel \
                     did not intend — post_up/post_down are file-only and cannot be set through \
                     the API",
                    p.name
                ),
            })));
        }
    }
    // Run the SAME profile validation the worker runs at startup, against the text we
    // are about to write. Without this the panel happily saved a config the worker
    // then refused to load (duplicate profile names, `plain` over UDP, obfs with no
    // key, REALITY with no short_id, zero perf params, out-of-range heartbeat) — the
    // operator saw "saved OK" and only found out when Apply/Restart left the data
    // plane down. Validating `reparsed` (not `parsed`) checks exactly what the worker
    // will see on disk.
    if let Err(e) = crate::server::validate_profiles(&reparsed) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!(
                "refusing to write a config the server would reject at startup: {}", e
            ),
        })));
    }
    // Host-state validation must happen BEFORE the new file replaces the working config and
    // before Quick Start asks the supervisor to kill the current worker. Structural validation
    // cannot see a LAN/default-gateway/other-VPN collision; discovering it only in the new
    // worker is too late because the known-good data plane has already been stopped.
    if let Err(e) = crate::server::preflight::run(&reparsed) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("refusing to save a config that conflicts with host networking: {}", e),
        })));
    }
    if let Err(e) = crate::util::write_atomic(&canon, config_str.as_bytes()) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("write error: {}", e),
        })));
    }

    // Apply the panel's own settings (admin password/username, IP allowlist, CSRF
    // origins, public host) LIVE — the supervisor serves the panel from this copy,
    // so they take effect without a restart. Profile/bind/tun/TLS still need one.
    state.reload_web_settings().await;

    let message = if needs_full_restart {
        "config saved. This changes the PANEL socket (web.bind/port/tls/enabled/base_path) — \
         apply it with a FULL restart: the `Apply & Restart` button does one, or run \
         `systemctl restart qeli`. Other changes are picked up by the worker restart."
    } else {
        "config saved — web/panel settings applied live; restart to apply profile/bind/tun changes"
    };
    Ok(Json(json!({
        "ok": true,
        "needs_full_restart": needs_full_restart,
        "message": message,
        "path": canon.display().to_string(),
    })))
}

/// Return the on-disk config file **verbatim** (raw INI text, comments intact).
/// The structured `GET /api/config` reflects the parsed struct; this is the
/// actual file the server loads, for the raw-text editor.
pub async fn get_config_raw(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })))
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            return Ok(Json(super::err_json(format!(
                "config path rejected: {}",
                e
            ))))
        }
    };
    match std::fs::read_to_string(&canon) {
        // Secrets are masked on the way out and restored on the way back in
        // (`put_config_raw`), so the raw editor keeps working without the browser ever
        // holding the admin hash or a user's stored password. (Audit 2026-07-27, P1.)
        Ok(raw) => Ok(Json(json!({
            "ok": true,
            "raw": mask_raw_secrets(&raw),
            "path": canon.display().to_string(),
            "masked": RAW_SECRET_MASK,
        }))),
        Err(e) => Ok(Json(super::err_json(format!("read error: {}", e)))),
    }
}

/// Structural checks both config-write paths must apply. Returns the error message.
///
/// The raw editor reached disk through a MUCH thinner gate than the structured one, at
/// identical privilege: no `is_valid_ident` on names that become INI section headers, no
/// uniqueness check on usernames, and no validation of advertised routes. Anything the
/// structured path rejects with an explanation was simply accepted here — so the raw
/// editor was both the easier way to author a broken config and the one that said
/// nothing about it. (Audit 2026-07-27, C2.)
fn validate_config_structure(parsed: &crate::config::server::ServerConfig) -> Option<String> {
    let name_err = |what: &str, name: &str| {
        format!(
            "{what} {name:?} is invalid — it must be non-empty, at most 128 bytes, and carry no \
             control characters or surrounding whitespace (names become INI section headers, so a \
             newline there could forge config lines)"
        )
    };
    if let Some(p) = parsed
        .profiles
        .iter()
        .find(|p| !crate::util::is_valid_ident(&p.name))
    {
        return Some(name_err("profile name", &p.name));
    }
    if let Some(g) = parsed
        .auth
        .groups
        .keys()
        .find(|g| !crate::util::is_valid_ident(g))
    {
        return Some(name_err("group name", g));
    }
    if let Some(u) = parsed
        .auth
        .users
        .iter()
        .find(|u| !crate::util::is_valid_ident(&u.username))
    {
        return Some(name_err("username", &u.username));
    }
    if let Some(k) = parsed
        .auth
        .users
        .iter()
        .flat_map(|u| u.metadata.keys())
        .find(|k| !crate::util::is_valid_ident(k))
    {
        return Some(name_err("metadata key", k));
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(dup) = parsed
        .auth
        .users
        .iter()
        .find(|u| !seen.insert(u.username.as_str()))
    {
        return Some(format!(
            "duplicate username '{}' — each user may appear only once; \
             only the first entry would ever be used",
            dup.username
        ));
    }
    for p in &parsed.profiles {
        for r in &p.routing.advertised_routes {
            if !crate::util::is_valid_cidr(&r.cidr) {
                return Some(format!(
                    "profile '{}': route CIDR is missing or invalid ({:?}). The network goes in \
                     the CIDR field, e.g. 172.16.20.0/24 — `gateway` takes a next-hop IP, not a \
                     subnet.",
                    p.name, r.cidr
                ));
            }
            if let Some(ref gw) = r.gateway {
                if !crate::util::is_valid_gateway(gw) {
                    return Some(format!(
                        "profile '{}': route {} — gateway must be a bare next-hop IP (e.g. \
                         10.0.0.1) or left empty to use the profile's tun address; got {:?}.",
                        p.name, r.cidr, gw
                    ));
                }
            }
        }
    }
    None
}

/// Keys whose VALUE must never leave the server, in any section.
///
/// The structured `GET /api/config` marks these `#[serde(skip_serializing)]` with
/// comments stating the browser never sees them. The raw editor returned the file
/// byte-for-byte and so handed out exactly what the structured path was careful to
/// withhold: the admin's argon2 verifier (offline-crackable) and every inline user's
/// hash and reversibly-encrypted password. Any XSS — the CSP still carries
/// `'unsafe-eval'` for Alpine — or one borrowed session was enough to collect them.
/// (Audit 2026-07-27, P1.)
const RAW_SECRET_KEYS: &[&str] = &["password_hash", "password_enc", "password"];

/// Placeholder shown in place of a secret. Sent back unchanged by the editor, it means
/// "keep what is on disk"; the operator can still overwrite a value by typing a new one.
const RAW_SECRET_MASK: &str = "<unchanged>";

/// Split an INI line into `(key, value)` when it is a `key = value` assignment.
fn ini_kv(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with(';') || t.starts_with('[') {
        return None;
    }
    let (k, v) = t.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// Replace every secret VALUE with [`RAW_SECRET_MASK`], preserving the rest of the file
/// (comments, ordering, spacing) exactly.
fn mask_raw_secrets(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let eol = &line[body.len()..];
        match ini_kv(body) {
            Some((k, v)) if RAW_SECRET_KEYS.contains(&k) && !v.is_empty() => {
                let indent_len = body.len() - body.trim_start().len();
                out.push_str(&body[..indent_len]);
                out.push_str(k);
                out.push_str(" = ");
                out.push_str(RAW_SECRET_MASK);
                out.push_str(eol);
            }
            _ => out.push_str(line),
        }
    }
    out
}

/// Put the real secrets back: any masked value in `incoming` is replaced with the value
/// the same `(section, key)` holds in `on_disk`.
///
/// Keyed by section so two users' hashes can never be swapped. A masked value with no
/// counterpart on disk becomes empty, which the parser treats as "unset" — the same
/// outcome the structured path produces for a user it cannot match.
fn unmask_raw_secrets(incoming: &str, on_disk: &str) -> String {
    let mut disk: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    let mut section = String::new();
    for line in on_disk.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.to_string();
            continue;
        }
        if let Some((k, v)) = ini_kv(line) {
            if RAW_SECRET_KEYS.contains(&k) {
                disk.insert((section.clone(), k.to_string()), v.to_string());
            }
        }
    }

    let mut out = String::with_capacity(incoming.len());
    let mut section = String::new();
    for line in incoming.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let eol = &line[body.len()..];
        let t = body.trim();
        if t.starts_with('[') {
            section = t.to_string();
            out.push_str(line);
            continue;
        }
        match ini_kv(body) {
            Some((k, v)) if RAW_SECRET_KEYS.contains(&k) && v == RAW_SECRET_MASK => {
                let real = disk
                    .get(&(section.clone(), k.to_string()))
                    .cloned()
                    .unwrap_or_default();
                let indent_len = body.len() - body.trim_start().len();
                out.push_str(&body[..indent_len]);
                out.push_str(k);
                out.push_str(" = ");
                out.push_str(&real);
                out.push_str(eol);
            }
            _ => out.push_str(line),
        }
    }
    out
}

/// Write raw INI text **verbatim** (preserving hand-written comments/formatting),
/// after validating it parses into a `ServerConfig`. Same path-field guards as the
/// structured PUT, so a hostile config can't redirect log/users reads outside the
/// whitelist.
pub async fn put_config_raw(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let raw = match body.get("raw").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Ok(Json(super::err_json("raw field required"))),
    };

    // Put back any secret the editor received masked, BEFORE parsing — otherwise the
    // placeholder would be validated as an argon2 hash and the save would either fail or
    // (worse) persist the placeholder and lock the operator out. Restoration is keyed by
    // (section, key), so hashes cannot be swapped between users. (Audit 2026-07-27, P1.)
    let raw = {
        let path = state.config_path.lock().await.clone();
        let on_disk = path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();
        unmask_raw_secrets(&raw, &on_disk)
    };

    // Validate by parsing — catches INI syntax errors and invalid/missing values.
    //
    // Findings are FATAL here, unlike at server startup, and the difference is what refusing
    // costs. Aborting a start over a long-standing typo takes a working server down on
    // upgrade, so the boot path only warns. Refusing a SAVE costs nothing: the operator is
    // looking at the very text that is wrong and gets told which key, with the running config
    // untouched. Accepting it silently is how `web.tls = ture` — or a key written twice — got
    // written to disk and then read as its default. (Audit 2026-08-01, §3.)
    let (parsed, findings) = match crate::config::parse_server_config_reporting(&raw) {
        Ok(v) => v,
        Err(e) => return Ok(Json(super::err_json(format!("invalid config: {}", e)))),
    };
    if !findings.is_empty() {
        return Ok(Json(super::err_json(format!(
            "{} problem(s) whose defaults would be substituted silently: {}",
            findings.len(),
            findings.join("; ")
        ))));
    }

    if let Some(ref log_file) = parsed.logging.file {
        if let Err(e) = validate_path_field(log_file, ALLOWED_LOG_DIRS) {
            return Ok(Json(super::err_json(format!("logging.file: {}", e))));
        }
    }
    if let Err(e) = validate_path_field(&parsed.auth.users_file, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("auth.users_file: {}", e))));
    }
    // Same Argon2 check as the structured path — the raw editor is the likelier place
    // to hand-type a bad hash and lock yourself out of the panel.
    if !parsed.web.password_hash.is_empty() {
        if let Err(e) = super::users::validate_argon2_hash(&parsed.web.password_hash) {
            return Ok(Json(super::err_json(format!("web.password_hash: {e}"))));
        }
    }
    for p in &parsed.profiles {
        if let Some(ref id_key) = p.identity_key {
            if let Err(e) = validate_path_field(id_key, ALLOWED_CONFIG_DIRS) {
                return Ok(Json(super::err_json(format!(
                    "profile '{}' identity_key: {}",
                    p.name, e
                ))));
            }
        }
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_cert, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("web.tls_cert: {}", e))));
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_key, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("web.tls_key: {}", e))));
    }

    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })))
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Refused raw config write to '{}': {}", target, e);
            return Ok(Json(super::err_json(format!(
                "config path rejected: {}",
                e
            ))));
        }
    };

    // SECURITY: post_up/post_down are file-only (they execute commands as root).
    // The raw editor must not introduce or change them — reject if the submitted
    // config's hooks differ from what's currently on disk.
    let on_disk = std::fs::read_to_string(&canon)
        .ok()
        .and_then(|s| crate::config::parse_server_config(&s).ok());
    for p in &parsed.profiles {
        let (cur_up, cur_down) = on_disk
            .as_ref()
            .and_then(|c| c.profiles.iter().find(|x| x.name == p.name))
            .map(|x| (x.routing.post_up.as_str(), x.routing.post_down.as_str()))
            .unwrap_or(("", ""));
        if p.routing.post_up != cur_up || p.routing.post_down != cur_down {
            return Ok(Json(super::err_json(format!(
                "profile '{}': post_up/post_down can only be set by editing the config file directly, not via the panel",
                p.name
            ))));
        }
    }

    // Same STRUCTURAL validation as the structured path — names, unique usernames,
    // advertised routes. (Audit 2026-07-27, C2.)
    if let Some(e) = validate_config_structure(&parsed) {
        return Ok(Json(super::err_json(e)));
    }

    // Same startup validation as the structured path: the raw editor is the EASIER
    // way to produce a config the worker refuses (deleting a whole `performance`
    // object yields derived-Default zeros, not the documented defaults), so it must
    // not be the unchecked one. `parsed` here is the submitted text already parsed.
    if let Err(e) = crate::server::validate_profiles(&parsed) {
        return Ok(Json(super::err_json(format!(
            "refusing to write a config the server would reject at startup: {}",
            e
        ))));
    }

    if let Err(e) = crate::server::preflight::run(&parsed) {
        return Ok(Json(super::err_json(format!(
            "refusing to write a config that conflicts with host networking: {}",
            e
        ))));
    }

    if let Err(e) = crate::util::write_atomic(&canon, raw.as_bytes()) {
        return Ok(Json(super::err_json(format!("write error: {}", e))));
    }

    // Apply the panel's own settings live (see put_config); restart still needed
    // for profile/bind/tun/TLS.
    state.reload_web_settings().await;

    // Report whether the PANEL's own socket changed, exactly as the structured path does.
    // Without it the raw editor always claimed a worker restart would suffice, so an
    // operator who moved web.port there restarted the worker, watched the panel stay on
    // the old port, and had nothing pointing at the cause. (Audit 2026-07-27, C2.)
    let cur = &state.config.web;
    let w = &parsed.web;
    let needs_full_restart = w.bind != cur.bind
        || w.port != cur.port
        || w.enabled != cur.enabled
        || w.tls != cur.tls
        || w.tls_cert != cur.tls_cert
        || w.tls_key != cur.tls_key
        || w.base_path != cur.base_path
        || parsed.auth.users_file != state.config.auth.users_file;

    let message = if needs_full_restart {
        "raw config saved (comments preserved). This changes the PANEL socket          (web.bind/port/tls/enabled/base_path) or auth.users_file — apply it with a FULL          restart: the `Apply & Restart` button does one, or run `systemctl restart qeli`."
    } else {
        "raw config saved (comments preserved) — web/panel settings applied live; restart to apply profile/bind/tun changes"
    };

    Ok(Json(json!({
        "ok": true,
        "message": message,
        "needs_full_restart": needs_full_restart,
        "path": canon.display().to_string(),
    })))
}

#[cfg(test)]
mod raw_secret_tests {
    use super::*;

    const SAMPLE: &str = "[web]\nusername = admin\npassword_hash = $argon2id$v=19$m=19456,t=2,p=1$abc$def\n\n[user:alice]\npassword_hash = $argon2id$alice\npassword_enc = ZW5jcnlwdGVk\n\n[user:bob]\npassword_hash = $argon2id$bob\n";

    #[test]
    fn secrets_are_masked_and_nothing_else_changes() {
        let masked = mask_raw_secrets(SAMPLE);
        assert!(!masked.contains("$argon2id$v=19"), "admin hash leaked");
        assert!(!masked.contains("$argon2id$alice"), "user hash leaked");
        assert!(!masked.contains("ZW5jcnlwdGVk"), "password_enc leaked");
        // Everything that is not a secret survives verbatim.
        assert!(masked.contains("[web]"));
        assert!(masked.contains("username = admin"));
        assert!(masked.contains("[user:bob]"));
        assert_eq!(masked.matches(RAW_SECRET_MASK).count(), 4);
    }

    #[test]
    fn masked_values_round_trip_back_to_the_originals() {
        let masked = mask_raw_secrets(SAMPLE);
        let restored = unmask_raw_secrets(&masked, SAMPLE);
        assert_eq!(restored, SAMPLE, "round-trip must be byte-identical");
    }

    /// Restoration is keyed by section: alice's hash must not land on bob.
    #[test]
    fn restoration_does_not_swap_secrets_between_users() {
        let masked = mask_raw_secrets(SAMPLE);
        let restored = unmask_raw_secrets(&masked, SAMPLE);
        let alice = restored.split("[user:alice]").nth(1).unwrap();
        let alice_block = alice.split("[user:bob]").next().unwrap();
        assert!(alice_block.contains("$argon2id$alice"));
        assert!(!alice_block.contains("$argon2id$bob"));
    }

    /// An operator typing a NEW value must override, not be treated as unchanged.
    #[test]
    fn an_explicitly_edited_secret_is_kept() {
        let edited = SAMPLE.replace("$argon2id$alice", "$argon2id$NEWVALUE");
        let restored = unmask_raw_secrets(&edited, SAMPLE);
        assert!(restored.contains("$argon2id$NEWVALUE"));
    }

    #[test]
    fn every_quickstart_mode_builds_a_runtime_valid_profile() {
        let mut names = std::collections::HashSet::new();
        let mut ports = std::collections::HashSet::new();
        for spec in QUICKSTART_SPECS {
            assert!(
                names.insert(spec.id),
                "duplicate Quick Start id {}",
                spec.id
            );
            assert!(
                ports.insert((spec.transport, spec.port)),
                "duplicate Quick Start listener {}:{}",
                spec.transport,
                spec.port
            );
            let (profile, sid, obfs_key) = build_quickstart_profile(spec.id).unwrap();
            assert_eq!(sid.is_some(), spec.needs_short_id);
            assert_eq!(obfs_key.is_some(), spec.needs_obfs_key);
            assert!(
                !profile.pool.exclude.contains(&profile.tun.address),
                "Quick Start must rely on automatic tun.address reservation"
            );
            let mut config = crate::config::parse_server_config("[profile:placeholder]\n")
                .expect("baseline server config parses");
            config.profiles = vec![profile];
            crate::server::validate_profiles(&config)
                .unwrap_or_else(|error| panic!("Quick Start {} is invalid: {error}", spec.id));
        }
    }

    #[test]
    fn quickstart_page_and_backend_offer_the_same_modes() {
        let page = include_str!("../templates/quickstart.html");
        assert_eq!(
            page.matches("{ id: '").count(),
            QUICKSTART_SPECS.len(),
            "the page and canonical backend mode count drifted"
        );
        for spec in QUICKSTART_SPECS {
            assert!(
                page.contains(&format!("{{ id: '{}'", spec.id)),
                "Quick Start page omitted backend mode {}",
                spec.id
            );
        }
    }

    #[test]
    fn quickstart_selects_a_free_subnet_instead_of_hard_coding_one() {
        let (target, _, _) = build_quickstart_profile("reality-tls").unwrap();
        let mut occupied = target.clone();
        occupied.name = "occupied".into();
        occupied.bind.port = 9443;
        occupied.tun.name = "vpn200".into();
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles = vec![occupied];
        let host = crate::server::preflight::HostNet {
            routes: vec![("eth0".into(), "10.9.1.0/24".parse().unwrap())],
            ..Default::default()
        };

        let placed = place_quickstart_network(target, &current, Some(&host)).unwrap();
        assert_ne!(placed.pool.cidr, "10.9.0.0/24");
        assert_ne!(placed.pool.cidr, "10.9.1.0/24");
        current.profiles.push(placed);
        crate::server::validate_profiles(&current).unwrap();
        crate::server::preflight::check(&current, &host).unwrap();
    }

    #[test]
    fn quickstart_searches_all_three_private_address_families() {
        let candidates = quickstart_private_24_candidates(7);
        assert_eq!(candidates.len(), 69_888);
        assert_eq!(candidates[0], (10, 9, 7));
        assert!(candidates.contains(&(10, 255, 255)));
        assert!(candidates.contains(&(172, 31, 255)));
        assert!(candidates.contains(&(192, 168, 255)));

        let (target, _, _) = build_quickstart_profile("reality-tls").unwrap();
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = crate::server::preflight::HostNet {
            routes: vec![("eth0".into(), "10.0.0.0/8".parse().unwrap())],
            ..Default::default()
        };
        let placed = place_quickstart_network(target, &current, Some(&host)).unwrap();
        assert_eq!(placed.pool.cidr, "172.16.0.0/24");
        current.profiles.push(placed);
        crate::server::preflight::check(&current, &host).unwrap();
    }

    #[test]
    fn repeated_quickstart_preserves_credentials_and_manual_settings() {
        let (mut profile, original_sid, _) = build_quickstart_profile("reality-tls").unwrap();
        profile.enabled = false;
        profile.bind.port = 9443;
        profile.tun.mtu = 1337;
        profile.obfuscation.tls.reality_proxy.short_ids =
            vec![original_sid.clone().unwrap(), "0011223344556677".into()];
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles = vec![profile.clone()];

        let (reused, sid, obfs_key, was_reused) =
            quickstart_profile_for_current("reality-tls", &current, None).unwrap();

        assert!(was_reused);
        assert!(reused.enabled, "Launch must re-enable an existing profile");
        assert_eq!(reused.bind.port, 9443, "manual listener change was reset");
        assert_eq!(reused.tun.mtu, 1337, "manual MTU was reset");
        assert_eq!(
            reused.obfuscation.tls.reality_proxy.short_ids,
            profile.obfuscation.tls.reality_proxy.short_ids,
            "relaunch rotated or discarded existing REALITY credentials"
        );
        assert_eq!(sid, original_sid);
        assert!(obfs_key.is_none());
    }

    #[test]
    fn repeated_obfs_quickstart_preserves_the_existing_key() {
        let (mut profile, _, _) = build_quickstart_profile("udp-obfs").unwrap();
        profile.obfuscation.obfs_key = "operator-kept-key".into();
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles = vec![profile];

        let (_, sid, obfs_key, reused) =
            quickstart_profile_for_current("udp-obfs", &current, None).unwrap();
        assert!(reused);
        assert!(sid.is_none());
        assert_eq!(obfs_key.as_deref(), Some("operator-kept-key"));
    }
}
