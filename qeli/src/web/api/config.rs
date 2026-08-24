use super::paths::{
    validate_in_whitelist, validate_path_field, ALLOWED_CONFIG_DIRS, ALLOWED_LOG_DIRS,
};
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

const CONFIG_HISTORY_DIR: &str = ".config-history";
const CONFIG_HISTORY_KEEP: usize = 10;

/// Revision of the exact file bytes, comments included. Structured and raw editors therefore
/// share one optimistic-concurrency token and a hand edit is detected just like a panel edit.
pub(super) fn config_revision(raw: &str) -> String {
    Sha256::digest(raw.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn revision_conflict(body: &Value, current_raw: &str) -> Option<Value> {
    let expected = body
        .get("expected_revision")
        .and_then(Value::as_str)
        .filter(|revision| !revision.is_empty())?;
    let current = config_revision(current_raw);
    (expected != current).then(|| {
        json!({
            "ok": false,
            "kind": "config_conflict",
            "error": "The server configuration changed after this page was loaded. Reload and review the newer version before saving.",
            "expected_revision": expected,
            "current_revision": current,
        })
    })
}

/// Detect a hand edit made after validation but before the final rename. The process lock
/// serializes panel writers; this second disk read extends the same protection to an operator
/// editing the INI over SSH while a panel request is validating it.
fn external_write_conflict(
    config_path: &FsPath,
    checked_raw: &str,
) -> Result<Option<Value>, String> {
    let actual_raw = std::fs::read_to_string(config_path)
        .map_err(|error| format!("re-read config {}: {error}", config_path.display()))?;
    let checked_revision = config_revision(checked_raw);
    let current_revision = config_revision(&actual_raw);
    Ok((checked_revision != current_revision).then(|| {
        json!({
            "ok": false,
            "kind": "config_conflict",
            "error": "The server configuration changed on disk while this save was being prepared. Nothing was written; reload and review the newer version.",
            "expected_revision": checked_revision,
            "current_revision": current_revision,
        })
    }))
}

fn config_history_dir(config_path: &FsPath) -> Result<PathBuf, String> {
    let parent = config_path
        .parent()
        .ok_or_else(|| "config path has no parent directory".to_string())?;
    Ok(parent.join(CONFIG_HISTORY_DIR))
}

/// Store the exact previous file before replacing it. Snapshots contain password hashes and
/// encrypted user credentials, so the directory and files are private and the history is
/// bounded. A failed snapshot aborts the save: rollback must not be best-effort.
fn snapshot_config(config_path: &FsPath, current_raw: &str) -> Result<Option<String>, String> {
    if current_raw.is_empty() {
        return Ok(None);
    }
    let dir = config_history_dir(config_path)?;
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("create config history {}: {error}", dir.display()))?;
    let dir_meta = std::fs::symlink_metadata(&dir)
        .map_err(|error| format!("inspect config history {}: {error}", dir.display()))?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
        return Err(format!(
            "config history {} is not a real directory",
            dir.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect config history {}: {error}", dir.display()))?;
    }
    let revision = config_revision(current_raw);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let id = format!("{timestamp}-{}.conf", &revision[..12]);
    let snapshot = dir.join(&id);
    if snapshot.exists() {
        let metadata = std::fs::symlink_metadata(&snapshot)
            .map_err(|error| format!("inspect config snapshot {}: {error}", snapshot.display()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || std::fs::read_to_string(&snapshot).ok().as_deref() != Some(current_raw)
        {
            return Err(format!(
                "existing config snapshot {} is not the expected regular file",
                snapshot.display()
            ));
        }
    } else {
        crate::util::write_atomic_private(&snapshot, current_raw.as_bytes())
            .map_err(|error| format!("write config snapshot {}: {error}", snapshot.display()))?;
    }

    let mut entries = std::fs::read_dir(&dir)
        .map_err(|error| format!("read config history {}: {error}", dir.display()))?
        .flatten()
        .filter(|entry| {
            entry.path().extension().and_then(|x| x.to_str()) == Some("conf")
                && entry
                    .file_type()
                    .map(|kind| kind.is_file() && !kind.is_symlink())
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    let remove_count = entries.len().saturating_sub(CONFIG_HISTORY_KEEP);
    for entry in entries.into_iter().take(remove_count) {
        let _ = std::fs::remove_file(entry.path());
    }
    Ok(Some(id))
}

pub(super) fn snapshot_before_changed_write(
    config_path: &FsPath,
    current_raw: &str,
    next_raw: &str,
) -> Result<Option<String>, String> {
    if config_revision(current_raw) == config_revision(next_raw) {
        Ok(None)
    } else {
        snapshot_config(config_path, current_raw)
    }
}

pub async fn get_config(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    // Return the live on-disk config so the panel reflects Quick-Start / Apply
    // changes (the supervisor's in-memory `config` is only its startup snapshot).
    if let Some(path) = state.config_path.lock().await.clone() {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) => {
                return Ok(Json(super::err_json(format!(
                    "cannot read current server config '{}': {error}",
                    path
                ))))
            }
        };
        let (config, findings) = match crate::config::parse_server_config_reporting(&raw) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Ok(Json(super::err_json(format!(
                    "cannot parse current server config '{}': {error}",
                    path
                ))))
            }
        };
        if !findings.is_empty() {
            return Ok(Json(super::err_json(format!(
                "current server config '{}' has {} unreadable or ambiguous value(s): {}",
                path,
                findings.len(),
                findings.join("; ")
            ))));
        }
        return Ok(Json(json!({
            "ok": true,
            "config": config,
            "revision": config_revision(&raw),
        })));
    }
    let raw = state.config.to_ini_string();
    Ok(Json(json!({
        "ok": true,
        "config": &state.config,
        "revision": config_revision(&raw),
    })))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuickStartIpMode {
    Auto,
    Ipv4,
    Dual,
    Ipv6,
}

impl QuickStartIpMode {
    fn parse_body(body: &Value) -> Result<Option<Self>, String> {
        let Some(value) = body.get("ip_mode") else {
            return Ok(None); // compatibility with panel/API clients predating IPv6
        };
        let value = value
            .as_str()
            .ok_or_else(|| "Quick Start ip_mode must be a string".to_string())?;
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Some(Self::Auto)),
            "ipv4" => Ok(Some(Self::Ipv4)),
            "dual" => Ok(Some(Self::Dual)),
            "ipv6" => Ok(Some(Self::Ipv6)),
            _ => Err(format!(
                "unknown Quick Start ip_mode '{value}'; expected auto, ipv4, dual or ipv6"
            )),
        }
    }

    fn concrete(self) -> Option<crate::config::server::IpMode> {
        use crate::config::server::IpMode;
        match self {
            Self::Auto => None,
            Self::Ipv4 => Some(IpMode::Ipv4),
            Self::Dual => Some(IpMode::Dual),
            Self::Ipv6 => Some(IpMode::Ipv6),
        }
    }
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
    // The host-aware Quick Start wrapper adds an outer IPv6 listener only when the
    // snapshot proves that an IPv6 interface exists. Keeping the pure baseline IPv4-only
    // avoids creating a profile that cannot bind at all on an IPv6-disabled kernel.
    profile.bind.listen.clear();
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

/// Every RFC1918 /24, generated lazily and ordered so a host-wide route for one private
/// family quickly falls through to another instead of allocating all 69,888 candidates.
fn quickstart_private_24_candidates(preferred_third: u8) -> impl Iterator<Item = (u8, u8, u8)> {
    let preferred = (10, 9, preferred_third);
    std::iter::once(preferred).chain(
        (0u8..=u8::MAX)
            .flat_map(|third| {
                (16u8..=31)
                    .map(move |second| (172, second, third))
                    .chain(std::iter::once((192, 168, third)))
                    .chain((0u8..=u8::MAX).map(move |second| (10, second, third)))
            })
            .filter(move |candidate| *candidate != preferred),
    )
}

fn ipv4_nets_overlap(a: &ipnet::Ipv4Net, b: &ipnet::Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Cheap subnet-only predicate used during the RFC1918 search. Full schema/preflight
/// validation is intentionally run once, after selection: cloning and validating the whole
/// ServerConfig for every rejected /24 made the authenticated panel handler monopolize an
/// async worker when all private families were routed on the host.
fn quickstart_pool_is_free(
    pool: &ipnet::Ipv4Net,
    occupied_pools: &[ipnet::Ipv4Net],
    own_interfaces: &std::collections::HashSet<&str>,
    host: Option<&crate::server::preflight::HostNet>,
) -> bool {
    if occupied_pools
        .iter()
        .any(|occupied| ipv4_nets_overlap(pool, occupied))
    {
        return false;
    }
    let Some(host) = host else { return true };
    if host.gateways.iter().any(|gateway| pool.contains(gateway)) {
        return false;
    }
    if host.addrs.iter().any(|(interface, address)| {
        !own_interfaces.contains(interface.as_str()) && pool.contains(address)
    }) {
        return false;
    }
    !host.routes.iter().any(|(interface, route)| {
        !own_interfaces.contains(interface.as_str()) && ipv4_nets_overlap(pool, route)
    })
}

fn existing_quickstart_ipv4_plan_is_usable(
    profile: &crate::config::server::ProfileConfig,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
) -> bool {
    // Validate the complete post-transition profile, not only its CIDR. IPv6-only mode leaves
    // every legacy IPv4 field dormant, so a stale tun address, DNS listener, exclusion,
    // reservation or DHCP range can all become invalid at the same instant as the pool.
    let mut candidate = current.clone();
    candidate.profiles.retain(|item| item.name != profile.name);
    candidate.profiles.push(profile.clone());
    if crate::server::validate_profiles(&candidate).is_err() {
        return false;
    }
    match host {
        Some(snapshot) => crate::server::preflight::check(&candidate, snapshot).is_ok(),
        None => true,
    }
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
    let occupied_pools: Vec<ipnet::Ipv4Net> = current
        .profiles
        .iter()
        .filter(|item| item.enabled && item.name != profile.name)
        // IPv6-only profiles do not install or allocate their dormant IPv4 pool.
        .filter(|item| item.tun.ip_mode != crate::config::server::IpMode::Ipv6)
        .filter_map(|item| item.pool.cidr.trim().parse().ok())
        .collect();
    let mut own_interfaces: std::collections::HashSet<&str> = current
        .profiles
        .iter()
        .map(|item| item.tun.name.as_str())
        .collect();
    own_interfaces.insert(profile.tun.name.as_str());

    let selected =
        quickstart_private_24_candidates(preferred).find_map(|(first, second, third)| {
            let network = std::net::Ipv4Addr::new(first, second, third, 0);
            let pool = ipnet::Ipv4Net::new(network, 24).ok()?;
            quickstart_pool_is_free(&pool, &occupied_pools, &own_interfaces, host)
                .then_some((first, second, third))
        });
    let Some((first, second, third)) = selected else {
        return Err(
            "no collision-free private /24 is available for this Quick Start profile".into(),
        );
    };

    profile.tun.address = format!("{first}.{second}.{third}.1");
    profile.pool.cidr = format!("{first}.{second}.{third}.0/24");
    profile.dns.listen = profile.tun.address.clone();
    // These values are addresses inside the old subnet; preserving them after re-homing would
    // either make the generated config fail startup or hand clients unreachable addresses.
    // There is no safe one-to-one translation for arbitrary reservations, so reset only the
    // dependent IPv4 allocation state. Credentials, routes and all non-address settings stay.
    profile.pool.exclude.clear();
    profile.pool.static_reservations.clear();
    profile.dhcp.listen.clear();
    profile.dhcp.pool_start = None;
    profile.dhcp.pool_end = None;
    let mut candidate = current.clone();
    candidate.profiles.retain(|item| item.name != profile.name);
    candidate.profiles.push(profile.clone());
    crate::server::validate_profiles(&candidate).map_err(|error| error.to_string())?;
    if let Some(snapshot) = host {
        crate::server::preflight::check(&candidate, snapshot).map_err(|error| error.to_string())?;
    }
    Ok(profile)
}

fn is_public_native_ipv6_address(address: &std::net::Ipv6Addr) -> bool {
    if (address.segments()[0] & 0xe000) != 0x2000 {
        return false;
    }
    // These ranges are inside 2000::/3 but are not evidence of native public egress.
    const NON_NATIVE_OR_NON_ROUTABLE: &[&str] = &[
        "2001::/32",     // Teredo
        "2001:2::/48",   // benchmarking
        "2001:10::/28",  // ORCHID (deprecated)
        "2001:20::/28",  // ORCHIDv2
        "2001:db8::/32", // documentation
        "2002::/16",     // 6to4 (deprecated)
        "3fff::/20",     // documentation
    ];
    !NON_NATIVE_OR_NON_ROUTABLE.iter().any(|prefix| {
        prefix
            .parse::<ipnet::Ipv6Net>()
            .expect("static IPv6 exclusion prefix must parse")
            .contains(address)
    })
}

fn host_has_native_ipv6_egress(host: Option<&crate::server::preflight::HostNet>) -> bool {
    let Some(host) = host else { return false };
    host.ipv6_egress_addrs.iter().any(|(interface, address)| {
        // Internet-assigned global unicast space. ULA or link-local plus a default route
        // is not evidence that NAT66 can reach the public IPv6 Internet.
        is_public_native_ipv6_address(address) && host.ipv6_default_interfaces.contains(interface)
    })
}

fn host_has_ipv6_listener(host: Option<&crate::server::preflight::HostNet>) -> bool {
    host.is_some_and(|snapshot| {
        !snapshot.ipv6_addrs.is_empty() || !snapshot.ipv6_default_interfaces.is_empty()
    })
}

fn ipv6_nets_overlap(a: &ipnet::Ipv6Net, b: &ipnet::Ipv6Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn quickstart_ipv6_pool_is_free(
    pool: &ipnet::Ipv6Net,
    target_name: &str,
    target_interface: &str,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
) -> bool {
    if current
        .profiles
        .iter()
        .filter(|profile| profile.enabled && profile.name != target_name)
        .filter_map(|profile| profile.pool.ipv6.cidr.trim().parse::<ipnet::Ipv6Net>().ok())
        .any(|occupied| ipv6_nets_overlap(pool, &occupied))
    {
        return false;
    }
    let Some(host) = host else { return true };
    let mut own_interfaces: std::collections::HashSet<&str> = current
        .profiles
        .iter()
        .map(|profile| profile.tun.name.as_str())
        .collect();
    own_interfaces.insert(target_interface);
    if host
        .ipv6_gateways
        .iter()
        .any(|gateway| pool.contains(gateway))
    {
        return false;
    }
    if host.ipv6_addrs.iter().any(|(interface, address)| {
        !own_interfaces.contains(interface.as_str()) && pool.contains(address)
    }) {
        return false;
    }
    !host.ipv6_routes.iter().any(|(interface, route)| {
        !own_interfaces.contains(interface.as_str()) && ipv6_nets_overlap(pool, route)
    })
}

fn quickstart_subnet_from_site_prefix(site_prefix: u128, index: u8) -> ipnet::Ipv6Net {
    // RFC4193 site prefix is /48. Give each canonical Quick Start mode a stable,
    // non-zero /64 subnet ID inside it.
    let address = std::net::Ipv6Addr::from(
        (site_prefix & (u128::MAX << 80)) | ((u128::from(index) + 1) << 64),
    );
    ipnet::Ipv6Net::new(address, 64).expect("a /64 is always valid")
}

fn existing_quickstart_site_prefix(current: &crate::config::server::ServerConfig) -> Option<u128> {
    current
        .profiles
        .iter()
        .filter(|profile| QUICKSTART_SPECS.iter().any(|spec| spec.id == profile.name))
        .filter_map(|profile| profile.pool.ipv6.cidr.trim().parse::<ipnet::Ipv6Net>().ok())
        .map(|network| u128::from(network.network()) & (u128::MAX << 80))
        .find(|prefix| (*prefix >> 120) as u8 == 0xfd)
}

fn select_quickstart_ipv6_pool(
    target_name: &str,
    target_interface: &str,
    index: u8,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
) -> Result<ipnet::Ipv6Net, String> {
    if let Some(site_prefix) = existing_quickstart_site_prefix(current) {
        let candidate = quickstart_subnet_from_site_prefix(site_prefix, index);
        if quickstart_ipv6_pool_is_free(&candidate, target_name, target_interface, current, host) {
            return Ok(candidate);
        }
    }

    use rand::Rng;
    for _ in 0..128 {
        let mut global_id = [0u8; 5];
        rand::rng().fill_bytes(&mut global_id);
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1..6].copy_from_slice(&global_id);
        let site_prefix = u128::from_be_bytes(bytes);
        let candidate = quickstart_subnet_from_site_prefix(site_prefix, index);
        if quickstart_ipv6_pool_is_free(&candidate, target_name, target_interface, current, host) {
            return Ok(candidate);
        }
    }
    Err("could not generate a collision-free RFC4193 /64 for Quick Start".into())
}

fn configure_quickstart_ip_mode(
    profile: &mut crate::config::server::ProfileConfig,
    desired: crate::config::server::IpMode,
    index: u8,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
    ipv6_firewall_available: bool,
) -> Result<(), String> {
    use crate::config::server::{IpMode, Ipv6RoutingMode};

    profile.tun.ip_mode = desired;
    if desired == IpMode::Ipv4 {
        // Quick Start IPv4 always promises ordinary Internet egress. Restore NAT44 when
        // an existing IPv6-only profile (where NAT44 is deliberately disabled) is
        // switched back to IPv4.
        profile.routing.nat.enabled = true;
        profile.routing.forward_private = true;
        profile.tun.ipv6_address = None;
        profile.pool.ipv6 = Default::default();
        profile.routing.ipv6.mode = Ipv6RoutingMode::Off;
        profile.routing.ipv6.interface.clear();
        profile.dns.listen_ipv6 = None;
        profile
            .dns
            .push_servers
            .retain(|value| value.trim().parse::<std::net::Ipv4Addr>().is_ok());
        return Ok(());
    }

    if profile.tun.mtu < 1280 {
        return Err(format!(
            "profile '{}': IPv6 requires tun.mtu >= 1280 (current value is {}); change the MTU in Configuration first",
            profile.name, profile.tun.mtu
        ));
    }
    if !host_has_native_ipv6_egress(host) {
        return Err(
            "this host has no observed global IPv6 address on an IPv6 default-route interface; Quick Start cannot promise Internet IPv6 (use IPv4, or configure routed/off IPv6 manually)"
                .into(),
        );
    }
    if !ipv6_firewall_available {
        return Err(
            "Quick Start IPv6 requires ip6tables to enforce and verify the IPv6 forwarding policy; install ip6tables or configure the profile manually after fixing the host firewall"
                .into(),
        );
    }

    let existing_addressing = profile
        .tun
        .ipv6_address
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && !profile.pool.ipv6.cidr.trim().is_empty();
    if !existing_addressing {
        let pool =
            select_quickstart_ipv6_pool(&profile.name, &profile.tun.name, index, current, host)?;
        let gateway = std::net::Ipv6Addr::from(u128::from(pool.network()) + 1);
        profile.tun.ipv6_address = Some(gateway.to_string());
        profile.pool.ipv6.cidr = pool.to_string();
        profile.pool.ipv6.exclude.clear();
        profile.pool.ipv6.static_reservations.clear();
    }
    // Selecting IPv6/dual in Quick Start is an explicit request for working Internet IPv6,
    // not merely for an address. Existing profiles can legally retain dormant IPv6 address
    // fields while ip_mode=ipv4 and mode=off; normalize those too instead of silently
    // reusing addressing with no egress (or failing later because DNS has no IPv6 listener).
    profile.routing.ipv6.mode = Ipv6RoutingMode::Nat66;
    profile.dns.listen_ipv6 = profile.tun.ipv6_address.clone();

    if desired == IpMode::Ipv6 {
        // An IPv6-only profile has no IPv4 lease or TUN address to forward. Leaving the
        // Quick Start NAT44 switch on would install irrelevant IPv4 sysctl/firewall state.
        profile.routing.nat.enabled = false;
        profile.routing.forward_private = false;
        profile
            .dns
            .push_servers
            .retain(|value| value.trim().parse::<std::net::Ipv6Addr>().is_ok());
    } else {
        // Quick Start dual-stack promises Internet egress for both families. Restore NAT44
        // when an existing IPv6-only Quick Start profile is deliberately changed to dual.
        profile.routing.nat.enabled = true;
        profile.routing.forward_private = true;
    }
    Ok(())
}

fn resolve_new_quickstart_ip_mode(
    requested: Option<QuickStartIpMode>,
    host: Option<&crate::server::preflight::HostNet>,
    ipv6_firewall_available: bool,
) -> crate::config::server::IpMode {
    use crate::config::server::IpMode;
    match requested {
        Some(QuickStartIpMode::Auto) => {
            // Auto promises a profile that can be launched immediately. Native IPv6 is not
            // sufficient when the host lacks the firewall backend required to enforce and
            // verify forwarding; fall back to the fully usable IPv4 profile. Explicit dual/
            // IPv6 selections remain fail-closed with the actionable ip6tables error.
            if host_has_native_ipv6_egress(host) && ipv6_firewall_available {
                IpMode::Dual
            } else {
                IpMode::Ipv4
            }
        }
        Some(mode) => mode.concrete().unwrap_or(IpMode::Ipv4),
        None => IpMode::Ipv4,
    }
}

/// Build a profile only on the first Quick Start launch. Re-launching without an explicit
/// address-family choice merely re-enables the complete existing profile; an explicit choice
/// reconciles only the requested IPv4/IPv6 network plan. Credentials are never rotated here —
/// rotation stays in the config controls where the operator can see the impact on issued links.
fn quickstart_profile_for_current(
    mode: &str,
    current: &crate::config::server::ServerConfig,
    host: Option<&crate::server::preflight::HostNet>,
    ipv6_firewall_available: bool,
    requested_ip_mode: Option<QuickStartIpMode>,
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
        // Missing/auto on an existing profile is deliberately non-mutating. `auto` is
        // resolved only at creation time, so a temporary IPv6 uplink outage on a later
        // Launch cannot silently downgrade a stored dual-stack profile.
        if let Some(desired) = requested_ip_mode.and_then(QuickStartIpMode::concrete) {
            // The explicit selection describes the complete Quick Start egress contract,
            // not only the `tun.ip_mode` enum. Re-apply it even when the enum is already
            // equal: a manually edited dual profile may still have IPv6 mode=off or no DNS
            // listener, and Launch must repair that dormant state instead of returning a
            // profile that cannot deliver the Internet mode the panel just promised.
            let activates_ipv4 = existing.tun.ip_mode == crate::config::server::IpMode::Ipv6
                && desired != crate::config::server::IpMode::Ipv6;
            configure_quickstart_ip_mode(
                &mut profile,
                desired,
                spec.index,
                current,
                host,
                ipv6_firewall_available,
            )?;
            // An IPv6-only profile may safely retain dormant IPv4 fields even when every
            // RFC1918 route is occupied. Once an explicit switch activates IPv4 those fields
            // become operational. Preserve a valid, collision-free manual subnet exactly;
            // otherwise run the same selector used at creation instead of failing later on
            // the stale baseline pool.
            if activates_ipv4 && !existing_quickstart_ipv4_plan_is_usable(&profile, current, host) {
                profile = place_quickstart_network(profile, current, host)?;
            }
        }
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
    let desired = resolve_new_quickstart_ip_mode(requested_ip_mode, host, ipv6_firewall_available);
    // IPv6-only profiles do not lease, assign or route the dormant IPv4 fields. Requiring a
    // collision-free RFC1918 /24 here made an otherwise valid IPv6-only Quick Start fail on
    // corporate hosts that route all private IPv4 space. Dual/IPv4 profiles still use the
    // full host-aware selector because their IPv4 pool is active.
    let mut profile = if desired == crate::config::server::IpMode::Ipv6 {
        profile
    } else {
        place_quickstart_network(profile, current, host)?
    };
    // Outer carrier reachability is independent from inner `tun.ip_mode`. Add the V6ONLY
    // wildcard socket only when the host snapshot contains an IPv6 interface/default;
    // otherwise `[::]` can make an otherwise valid IPv4 Quick Start profile fail startup.
    if host_has_ipv6_listener(host) {
        profile.bind.listen = vec![format!("[::]:{}", spec.port)];
    }
    configure_quickstart_ip_mode(
        &mut profile,
        desired,
        spec.index,
        current,
        host,
        ipv6_firewall_available,
    )?;
    Ok((profile, short_id, obfs_key, false))
}

pub async fn get_quickstart_profile(
    State(state): State<Arc<ServerState>>,
    Path(mode): Path<String>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let current = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let host = crate::server::preflight::gather_host_net();
    match quickstart_profile_for_current(
        &mode,
        &current,
        host.as_ref(),
        crate::server::nat::ip6tables_path().is_some(),
        None,
    ) {
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

/// Build, validate and persist one Quick Start profile as a single serialized operation.
/// The former browser flow assembled a profile with one request and later PUT the complete
/// config with another, leaving an unavoidable last-writer-wins gap. This endpoint owns the
/// whole read-modify-write and returns the exact profile/credentials that reached disk.
pub async fn apply_quickstart_profile(
    State(state): State<Arc<ServerState>>,
    Path(mode): Path<String>,
    _guard: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let _config_write_guard = state.config_write_lock.lock().await;
    let Some(target) = state.config_path.lock().await.clone() else {
        return Ok(Json(super::err_json(
            "config_path not set — running from in-memory config",
        )));
    };
    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(path) => path,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let current_raw = match std::fs::read_to_string(&canon) {
        Ok(raw) => raw,
        Err(error) => return Ok(Json(super::err_json(format!("read config: {error}")))),
    };
    if let Some(conflict) = revision_conflict(&body, &current_raw) {
        return Ok(Json(conflict));
    }
    let requested_ip_mode = match QuickStartIpMode::parse_body(&body) {
        Ok(mode) => mode,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let mut current = match crate::config::parse_server_config(&current_raw) {
        Ok(config) => config,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "current config is invalid: {error}"
            ))))
        }
    };
    let host = crate::server::preflight::gather_host_net();
    let (profile, short_id, obfs_key, reused) = match quickstart_profile_for_current(
        &mode,
        &current,
        host.as_ref(),
        crate::server::nat::ip6tables_path().is_some(),
        requested_ip_mode,
    ) {
        Ok(result) => result,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    current.profiles.retain(|item| item.name != profile.name);
    current.profiles.push(profile.clone());
    if let Some(error) = validate_config_structure(&current) {
        return Ok(Json(super::err_json(error)));
    }
    let next_raw = current.to_ini_string();
    let reparsed = match crate::config::parse_server_config(&next_raw) {
        Ok(config) => config,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "Quick Start generated an unreadable config: {error}"
            ))))
        }
    };
    if let Err(error) = crate::server::validate_profiles(&reparsed) {
        return Ok(Json(super::err_json(format!(
            "Quick Start config would be rejected at startup: {error}"
        ))));
    }
    if let Err(error) = super::effective_users(&reparsed) {
        return Ok(Json(super::err_json(format!(
            "Quick Start conflicts with existing static user addresses: {error}"
        ))));
    }
    if let Some(host) = host.as_ref() {
        if let Err(error) = crate::server::preflight::check(&reparsed, host) {
            return Ok(Json(super::err_json(format!(
                "Quick Start conflicts with host networking: {error}"
            ))));
        }
    }
    match external_write_conflict(&canon, &current_raw) {
        Ok(Some(conflict)) => return Ok(Json(conflict)),
        Ok(None) => {}
        Err(error) => return Ok(Json(super::err_json(error))),
    }
    let snapshot = match snapshot_before_changed_write(&canon, &current_raw, &next_raw) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "refusing Quick Start without a rollback snapshot: {error}"
            ))))
        }
    };
    if let Err(error) = crate::util::write_atomic(&canon, next_raw.as_bytes()) {
        return Ok(Json(super::err_json(format!(
            "Quick Start write failed: {error}"
        ))));
    }
    state.reload_web_settings().await;
    Ok(Json(json!({
        "ok": true,
        "profile": profile,
        "sid": short_id,
        "obfs_key": obfs_key,
        "reused": reused,
        "revision": config_revision(&next_raw),
        "snapshot": snapshot,
        "message": if reused {
            "Existing profile enabled; credentials preserved and requested IP mode applied."
        } else {
            "Quick Start profile created."
        },
    })))
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

    // Serialize the entire read-modify-write sequence, not just the final atomic rename.
    // The expected revision is checked while this guard is held, closing the last-writer-wins
    // window between two panel tabs or Configuration and Quick Start.
    let _config_write_guard = state.config_write_lock.lock().await;
    let revision_path = state.config_path.lock().await.clone();
    let current_raw_for_revision = revision_path
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_else(|| state.config.to_ini_string());
    if let Some(conflict) = revision_conflict(&body, &current_raw_for_revision) {
        return Ok(Json(conflict));
    }

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
        || w.base_path != cur.base_path;

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
    if let Err(error) = super::effective_users(&reparsed) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!(
                "refusing to write profile reservations that conflict with existing users: {error}"
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
    match external_write_conflict(&canon, &current_raw_for_revision) {
        Ok(Some(conflict)) => return Ok(Json(conflict)),
        Ok(None) => {}
        Err(error) => return Ok(Json(super::err_json(error))),
    }
    let snapshot =
        match snapshot_before_changed_write(&canon, &current_raw_for_revision, &config_str) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(Json(super::err_json(format!(
                    "refusing to save without a rollback snapshot: {error}"
                ))))
            }
        };
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
        "revision": config_revision(&config_str),
        "snapshot": snapshot,
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
            "revision": config_revision(&raw),
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

    let _config_write_guard = state.config_write_lock.lock().await;
    let revision_path = state.config_path.lock().await.clone();
    let current_raw_for_revision = revision_path
        .as_deref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_else(|| state.config.to_ini_string());
    if let Some(conflict) = revision_conflict(&body, &current_raw_for_revision) {
        return Ok(Json(conflict));
    }

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
    if let Err(error) = super::effective_users(&parsed) {
        return Ok(Json(super::err_json(format!(
            "refusing raw config with profile reservations that conflict with existing users: {error}"
        ))));
    }

    if let Err(e) = crate::server::preflight::run(&parsed) {
        return Ok(Json(super::err_json(format!(
            "refusing to write a config that conflicts with host networking: {}",
            e
        ))));
    }

    match external_write_conflict(&canon, &current_raw_for_revision) {
        Ok(Some(conflict)) => return Ok(Json(conflict)),
        Ok(None) => {}
        Err(error) => return Ok(Json(super::err_json(error))),
    }
    let snapshot = match snapshot_before_changed_write(&canon, &current_raw_for_revision, &raw) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "refusing to save without a rollback snapshot: {error}"
            ))))
        }
    };
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
        || w.base_path != cur.base_path;

    let message = if needs_full_restart {
        "raw config saved (comments preserved). This changes the PANEL socket (web.bind/port/tls/enabled/base_path); apply it with a FULL restart: the `Apply & Restart` button does one, or run `systemctl restart qeli`."
    } else {
        "raw config saved (comments preserved) — web/panel settings applied live; restart to apply profile/bind/tun changes"
    };

    Ok(Json(json!({
        "ok": true,
        "message": message,
        "needs_full_restart": needs_full_restart,
        "path": canon.display().to_string(),
        "revision": config_revision(&raw),
        "snapshot": snapshot,
    })))
}

fn valid_history_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id.ends_with(".conf")
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && id != ".conf"
}

pub async fn list_config_history(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let Some(target) = state.config_path.lock().await.clone() else {
        return Ok(Json(super::err_json(
            "config_path not set — running from in-memory config",
        )));
    };
    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(path) => path,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let dir = match config_history_dir(&canon) {
        Ok(dir) => dir,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let mut entries = Vec::new();
    if let Ok(metadata) = std::fs::symlink_metadata(&dir) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(Json(super::err_json(
                "config history path is not a real directory",
            )));
        }
    }
    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let id = entry.file_name().to_string_lossy().to_string();
            if !valid_history_id(&id)
                || !entry
                    .file_type()
                    .map(|kind| kind.is_file() && !kind.is_symlink())
                    .unwrap_or(false)
            {
                continue;
            }
            let raw = match std::fs::read_to_string(entry.path()) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let created = id
                .split('-')
                .next()
                .and_then(|part| part.parse::<u64>().ok())
                .unwrap_or(0);
            entries.push(json!({
                "id": id,
                "created": created,
                "bytes": raw.len(),
                "revision": config_revision(&raw),
            }));
        }
    }
    entries.sort_by(|a, b| b["created"].as_u64().cmp(&a["created"].as_u64()));
    Ok(Json(json!({ "ok": true, "entries": entries })))
}

pub async fn restore_config_history(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    _guard: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    if !valid_history_id(&id) {
        return Ok(Json(super::err_json("invalid config history id")));
    }
    let _config_write_guard = state.config_write_lock.lock().await;
    let Some(target) = state.config_path.lock().await.clone() else {
        return Ok(Json(super::err_json(
            "config_path not set — running from in-memory config",
        )));
    };
    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(path) => path,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let current_raw = match std::fs::read_to_string(&canon) {
        Ok(raw) => raw,
        Err(error) => return Ok(Json(super::err_json(format!("read config: {error}")))),
    };
    if let Some(conflict) = revision_conflict(&body, &current_raw) {
        return Ok(Json(conflict));
    }
    let history_dir = match config_history_dir(&canon) {
        Ok(dir) => dir,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    match std::fs::symlink_metadata(&history_dir) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Ok(Json(super::err_json(
                "config history path is not a real directory",
            )))
        }
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "inspect config history: {error}"
            ))))
        }
    }
    let snapshot_path = history_dir.join(&id);
    let snapshot_meta = match std::fs::symlink_metadata(&snapshot_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            return Ok(Json(super::err_json(
                "config snapshot is not a regular file",
            )))
        }
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "inspect config snapshot {id}: {error}"
            ))))
        }
    };
    if snapshot_meta.len() > 16 * 1024 * 1024 {
        return Ok(Json(super::err_json(
            "config snapshot is unexpectedly large",
        )));
    }
    let raw = match std::fs::read_to_string(&snapshot_path) {
        Ok(raw) => raw,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "read config snapshot {id}: {error}"
            ))))
        }
    };
    let (parsed, findings) = match crate::config::parse_server_config_reporting(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "snapshot is no longer parseable: {error}"
            ))))
        }
    };
    if !findings.is_empty() {
        return Ok(Json(super::err_json(format!(
            "snapshot has {} invalid setting(s): {}",
            findings.len(),
            findings.join("; ")
        ))));
    }
    if let Some(error) = validate_config_structure(&parsed) {
        return Ok(Json(super::err_json(error)));
    }
    if let Err(error) = crate::server::validate_profiles(&parsed) {
        return Ok(Json(super::err_json(format!(
            "snapshot would be rejected at startup: {error}"
        ))));
    }
    if let Err(error) = super::effective_users(&parsed) {
        return Ok(Json(super::err_json(format!(
            "snapshot conflicts with existing static user addresses: {error}"
        ))));
    }
    if let Err(error) = crate::server::preflight::run(&parsed) {
        return Ok(Json(super::err_json(format!(
            "snapshot conflicts with current host networking: {error}"
        ))));
    }
    match external_write_conflict(&canon, &current_raw) {
        Ok(Some(conflict)) => return Ok(Json(conflict)),
        Ok(None) => {}
        Err(error) => return Ok(Json(super::err_json(error))),
    }
    let rollback_snapshot = match snapshot_before_changed_write(&canon, &current_raw, &raw) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(Json(super::err_json(format!(
                "refusing rollback without preserving the current config: {error}"
            ))))
        }
    };
    if let Err(error) = crate::util::write_atomic(&canon, raw.as_bytes()) {
        return Ok(Json(super::err_json(format!(
            "rollback write failed: {error}"
        ))));
    }
    state.reload_web_settings().await;
    let cur = &state.config.web;
    let web = &parsed.web;
    let needs_full_restart = web.bind != cur.bind
        || web.port != cur.port
        || web.enabled != cur.enabled
        || web.tls != cur.tls
        || web.tls_cert != cur.tls_cert
        || web.tls_key != cur.tls_key
        || web.base_path != cur.base_path;
    Ok(Json(json!({
        "ok": true,
        "message": "Configuration snapshot restored — restart to apply it.",
        "revision": config_revision(&raw),
        "restored": id,
        "rollback_snapshot": rollback_snapshot,
        "needs_full_restart": needs_full_restart,
    })))
}

#[cfg(test)]
mod raw_secret_tests {
    use super::*;

    const SAMPLE: &str = "[web]\nusername = admin\npassword_hash = $argon2id$v=19$m=19456,t=2,p=1$abc$def\n\n[user:alice]\npassword_hash = $argon2id$alice\npassword_enc = ZW5jcnlwdGVk\n\n[user:bob]\npassword_hash = $argon2id$bob\n";

    #[test]
    fn config_revision_covers_exact_file_bytes() {
        let a = config_revision("[web]\nport = 8080\n");
        assert_eq!(a.len(), 64);
        assert_eq!(a, config_revision("[web]\nport = 8080\n"));
        assert_ne!(a, config_revision("# comment\n[web]\nport = 8080\n"));
    }

    #[test]
    fn expected_revision_detects_a_stale_editor() {
        let current = "[web]\nport = 8080\n";
        let matching = json!({ "expected_revision": config_revision(current) });
        assert!(revision_conflict(&matching, current).is_none());
        let stale = json!({ "expected_revision": config_revision("old") });
        let conflict = revision_conflict(&stale, current).unwrap();
        assert_eq!(conflict["kind"], "config_conflict");
        assert_eq!(conflict["current_revision"], config_revision(current));
        // API compatibility for older automation: no token still takes the serialized lock.
        assert!(revision_conflict(&json!({}), current).is_none());
    }

    #[test]
    fn config_history_ids_are_single_safe_path_segments() {
        assert!(valid_history_id("1780000000-aabbccddeeff.conf"));
        for invalid in ["../server.conf", "x/y.conf", ".conf", "x.tgz", "x conf"] {
            assert!(!valid_history_id(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn second_disk_read_detects_a_hand_edit_during_validation() {
        let unique = format!(
            "qeli-config-revision-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.conf");
        let checked = "[web]\nport = 8080\n";
        std::fs::write(&path, checked).unwrap();
        assert!(external_write_conflict(&path, checked).unwrap().is_none());
        std::fs::write(&path, "[web]\nport = 8081\n").unwrap();
        let conflict = external_write_conflict(&path, checked).unwrap().unwrap();
        assert_eq!(conflict["kind"], "config_conflict");
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
                profile.bind.listen.is_empty(),
                "the host-independent baseline must not assume an IPv6 socket"
            );
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
    fn quickstart_page_checks_the_bind_that_relaunch_will_preserve() {
        let page = include_str!("../templates/quickstart.html");
        assert!(
            page.contains("const effectivePort = existingProfile?.bind?.port ?? m.port"),
            "relaunch collision check drifted back to the card's default port"
        );
        assert!(
            page.contains(
                "const effectiveTransport = existingProfile?.bind?.transport || m.transport"
            ),
            "relaunch collision check drifted back to the card's default transport"
        );
        assert!(page.contains("Number(p.bind?.port) === Number(effectivePort)"));
        assert!(page.contains("(p.bind?.transport || 'tcp') === effectiveTransport"));
    }

    #[test]
    fn quickstart_selects_a_free_subnet_instead_of_hard_coding_one() {
        let (target, _, _) = build_quickstart_profile("reality-tls").unwrap();
        let mut occupied = target.clone();
        occupied.name = "occupied".into();
        occupied.bind.port = 9443;
        occupied.bind.listen.clear();
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
        let candidates: Vec<_> = quickstart_private_24_candidates(7).collect();
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
    fn quickstart_rejects_fully_routed_rfc1918_without_per_candidate_validation() {
        let (target, _, _) = build_quickstart_profile("reality-tls").unwrap();
        let current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        let host = crate::server::preflight::HostNet {
            routes: vec![
                ("corp0".into(), "10.0.0.0/8".parse().unwrap()),
                ("corp0".into(), "172.16.0.0/12".parse().unwrap()),
                ("corp0".into(), "192.168.0.0/16".parse().unwrap()),
            ],
            ..Default::default()
        };
        let error = place_quickstart_network(target, &current, Some(&host)).unwrap_err();
        assert!(error.contains("no collision-free private /24"));
    }

    #[test]
    fn ipv6_only_quickstart_does_not_require_unused_rfc1918_space() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let mut host = native_ipv6_host();
        host.routes = vec![
            ("corp0".into(), "10.0.0.0/8".parse().unwrap()),
            ("corp0".into(), "172.16.0.0/12".parse().unwrap()),
            ("corp0".into(), "192.168.0.0/16".parse().unwrap()),
        ];

        let (profile, _, _, reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap();
        assert!(!reused);
        assert_eq!(profile.tun.ip_mode, crate::config::server::IpMode::Ipv6);
        current.profiles.push(profile);
        crate::server::validate_profiles(&current).unwrap();
        crate::server::preflight::check(&current, &host).unwrap();
    }

    #[test]
    fn ipv6_only_to_dual_rehomes_the_complete_stale_ipv4_plan() {
        use crate::config::server::{IpMode, Ipv6RoutingMode};

        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (mut target, _, _, _) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap();
        let old_pool = target.pool.cidr.clone();
        let old_tun = target.tun.address.clone();

        // This second active profile legitimately owns the same IPv4 subnet while the target
        // is IPv6-only. Its IPv4 shadow becomes a collision only when dual mode activates it.
        let mut occupied = target.clone();
        occupied.name = "occupied-ipv4".into();
        occupied.bind.port = 9443;
        occupied.bind.listen.clear();
        occupied.tun.name = "vpn200".into();
        occupied.tun.ip_mode = IpMode::Ipv4;
        occupied.tun.ipv6_address = None;
        occupied.pool.ipv6 = Default::default();
        occupied.routing.ipv6.mode = Ipv6RoutingMode::Off;
        occupied.dns.listen_ipv6 = None;
        occupied.routing.nat.enabled = true;
        occupied.routing.forward_private = true;

        // All of these fields are dormant in IPv6-only mode and tied to the old subnet.
        target.pool.exclude = vec!["10.9.0.200".into()];
        target
            .pool
            .static_reservations
            .insert("legacy".into(), "10.9.0.201".into());
        target.dhcp.listen = old_tun.clone();
        target.dhcp.pool_start = Some("10.9.0.20".into());
        target.dhcp.pool_end = Some("10.9.0.30".into());
        current.profiles = vec![occupied, target];
        crate::server::validate_profiles(&current).unwrap();

        let (reused, _, _, was_reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Dual),
        )
        .unwrap();

        assert!(was_reused);
        assert_eq!(reused.tun.ip_mode, IpMode::Dual);
        assert_ne!(reused.pool.cidr, old_pool);
        assert_ne!(reused.tun.address, old_tun);
        assert_eq!(reused.dns.listen, reused.tun.address);
        assert!(reused.pool.exclude.is_empty());
        assert!(reused.pool.static_reservations.is_empty());
        assert!(reused.dhcp.listen.is_empty());
        assert!(reused.dhcp.pool_start.is_none());
        assert!(reused.dhcp.pool_end.is_none());

        current
            .profiles
            .retain(|profile| profile.name != reused.name);
        current.profiles.push(reused);
        crate::server::validate_profiles(&current).unwrap();
        crate::server::preflight::check(&current, &host).unwrap();
    }

    #[test]
    fn ipv6_only_to_dual_preserves_a_valid_manual_ipv4_plan() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (mut profile, _, _, _) = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap();
        profile.pool.cidr = "10.77.12.0/25".into();
        profile.tun.address = "10.77.12.7".into();
        profile.dns.listen = "10.77.12.7".into();
        profile.pool.exclude = vec!["10.77.12.9".into()];
        profile
            .pool
            .static_reservations
            .insert("kept".into(), "10.77.12.10".into());
        current.profiles.push(profile);

        let (reused, _, _, was_reused) = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Dual),
        )
        .unwrap();

        assert!(was_reused);
        assert_eq!(reused.pool.cidr, "10.77.12.0/25");
        assert_eq!(reused.tun.address, "10.77.12.7");
        assert_eq!(reused.dns.listen, "10.77.12.7");
        assert_eq!(reused.pool.exclude, vec!["10.77.12.9"]);
        assert_eq!(
            reused
                .pool
                .static_reservations
                .get("kept")
                .map(String::as_str),
            Some("10.77.12.10")
        );

        current.profiles.clear();
        current.profiles.push(reused);
        crate::server::validate_profiles(&current).unwrap();
        crate::server::preflight::check(&current, &host).unwrap();
    }

    fn native_ipv6_host() -> crate::server::preflight::HostNet {
        let address = "2606:4700:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap();
        crate::server::preflight::HostNet {
            ipv6_addrs: vec![("eth0".into(), address)],
            ipv6_egress_addrs: vec![("eth0".into(), address)],
            ipv6_gateways: vec!["fe80::1".parse().unwrap()],
            ipv6_default_interfaces: vec!["eth0".into()],
            ..Default::default()
        }
    }

    #[test]
    fn native_ipv6_detection_requires_ready_routable_address_on_the_default_interface() {
        let public = "2606:4700:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap();
        let documentation = "2001:db8::10".parse().unwrap();

        let host = crate::server::preflight::HostNet {
            ipv6_addrs: vec![("eth0".into(), public)],
            ipv6_default_interfaces: vec!["eth0".into()],
            ..Default::default()
        };
        assert!(!host_has_native_ipv6_egress(Some(&host)));

        let host = crate::server::preflight::HostNet {
            ipv6_addrs: vec![("eth0".into(), documentation)],
            ipv6_egress_addrs: vec![("eth0".into(), documentation)],
            ipv6_default_interfaces: vec!["eth0".into()],
            ..Default::default()
        };
        assert!(!host_has_native_ipv6_egress(Some(&host)));

        let host = crate::server::preflight::HostNet {
            ipv6_addrs: vec![("eth0".into(), public)],
            ipv6_egress_addrs: vec![("eth0".into(), public)],
            ipv6_default_interfaces: vec!["eth1".into()],
            ..Default::default()
        };
        assert!(!host_has_native_ipv6_egress(Some(&host)));
        assert!(host_has_native_ipv6_egress(Some(&native_ipv6_host())));
    }

    #[test]
    fn quickstart_auto_is_resolved_once_to_a_concrete_dual_stack_profile() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (profile, _, _, reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Auto),
        )
        .unwrap();

        assert!(!reused);
        assert_eq!(profile.tun.ip_mode, crate::config::server::IpMode::Dual);
        assert!(profile.pool.ipv6.cidr.starts_with("fd"));
        assert!(profile.pool.ipv6.cidr.ends_with("/64"));
        assert_eq!(
            profile.routing.ipv6.mode,
            crate::config::server::Ipv6RoutingMode::Nat66
        );
        assert_eq!(profile.dns.listen_ipv6, profile.tun.ipv6_address);
        assert!(profile.routing.nat.enabled);
        assert_eq!(profile.bind.listen, vec!["[::]:443".to_string()]);
    }

    #[test]
    fn quickstart_auto_falls_back_to_ipv4_without_ipv6_firewall_support() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (profile, _, _, reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            false,
            Some(QuickStartIpMode::Auto),
        )
        .unwrap();

        assert!(!reused);
        assert_eq!(profile.tun.ip_mode, crate::config::server::IpMode::Ipv4);
        assert!(profile.tun.ipv6_address.is_none());
        assert!(profile.pool.ipv6.cidr.is_empty());
        assert_eq!(
            profile.routing.ipv6.mode,
            crate::config::server::Ipv6RoutingMode::Off
        );
        assert!(profile.routing.nat.enabled);
    }

    #[test]
    fn quickstart_auto_relaunch_does_not_downgrade_on_uplink_outage() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (profile, _, _, _) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Auto),
        )
        .unwrap();
        let ipv6_cidr = profile.pool.ipv6.cidr.clone();
        current.profiles.push(profile);

        let (reused, _, _, was_reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&crate::server::preflight::HostNet::default()),
            true,
            Some(QuickStartIpMode::Auto),
        )
        .unwrap();
        assert!(was_reused);
        assert_eq!(reused.tun.ip_mode, crate::config::server::IpMode::Dual);
        assert_eq!(reused.pool.ipv6.cidr, ipv6_cidr);
        assert_eq!(reused.bind.listen, vec!["[::]:443".to_string()]);
    }

    #[test]
    fn quickstart_omits_outer_ipv6_listener_when_the_host_cannot_bind_it() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let (profile, _, _, reused) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&crate::server::preflight::HostNet::default()),
            false,
            Some(QuickStartIpMode::Ipv4),
        )
        .unwrap();
        assert!(!reused);
        assert!(profile.bind.listen.is_empty());
        assert_eq!(profile.bind.address, "0.0.0.0");
    }

    #[test]
    fn quickstart_modes_share_a_site_ula_but_get_distinct_subnets() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let (first, _, _, _) = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Dual),
        )
        .unwrap();
        current.profiles.push(first.clone());
        let (second, _, _, _) = quickstart_profile_for_current(
            "udp-obfs",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Dual),
        )
        .unwrap();
        let first_net = first.pool.ipv6.cidr.parse::<ipnet::Ipv6Net>().unwrap();
        let second_net = second.pool.ipv6.cidr.parse::<ipnet::Ipv6Net>().unwrap();
        assert_eq!(
            u128::from(first_net.network()) >> 80,
            u128::from(second_net.network()) >> 80
        );
        assert_ne!(first_net, second_net);
    }

    #[test]
    fn explicit_quickstart_ipv6_refuses_to_promise_egress_without_native_ipv6() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let error = quickstart_profile_for_current(
            "reality-tls",
            &current,
            Some(&crate::server::preflight::HostNet::default()),
            true,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap_err();
        assert!(
            error.contains("cannot promise Internet IPv6"),
            "got: {error}"
        );
    }

    #[test]
    fn quickstart_ipv6_requires_firewall_support_and_does_not_install_nat44() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let host = native_ipv6_host();
        let error = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&host),
            false,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap_err();
        assert!(error.contains("ip6tables"), "got: {error}");

        let (profile, _, _, _) = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&host),
            true,
            Some(QuickStartIpMode::Ipv6),
        )
        .unwrap();
        assert_eq!(profile.tun.ip_mode, crate::config::server::IpMode::Ipv6);
        assert!(!profile.routing.nat.enabled);
        assert!(!profile.routing.forward_private);
        assert_eq!(
            profile.routing.ipv6.mode,
            crate::config::server::Ipv6RoutingMode::Nat66
        );

        current.profiles.push(profile);
        let (profile, _, _, reused) = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&host),
            false,
            Some(QuickStartIpMode::Ipv4),
        )
        .unwrap();
        assert!(reused);
        assert_eq!(profile.tun.ip_mode, crate::config::server::IpMode::Ipv4);
        assert!(profile.routing.nat.enabled);
        assert!(profile.routing.forward_private);
        assert!(profile.tun.ipv6_address.is_none());
        assert!(profile.pool.ipv6.cidr.is_empty());
        assert_eq!(
            profile.routing.ipv6.mode,
            crate::config::server::Ipv6RoutingMode::Off
        );
    }

    #[test]
    fn quickstart_dual_normalizes_dormant_existing_ipv6_addressing() {
        let mut current = crate::config::parse_server_config("[profile:placeholder]\n").unwrap();
        current.profiles.clear();
        let (mut profile, _, _) = build_quickstart_profile("fake-tls").unwrap();
        // The enum already says dual, but its egress policy is dormant. This is the
        // important regression: comparing only `desired != ip_mode` skipped normalization.
        profile.tun.ip_mode = crate::config::server::IpMode::Dual;
        profile.tun.ipv6_address = Some("fd71:e1:42::1".into());
        profile.pool.ipv6.cidr = "fd71:e1:42::/64".into();
        profile.routing.ipv6.mode = crate::config::server::Ipv6RoutingMode::Off;
        profile.dns.listen_ipv6 = None;
        current.profiles.push(profile);

        let (normalized, _, _, reused) = quickstart_profile_for_current(
            "fake-tls",
            &current,
            Some(&native_ipv6_host()),
            true,
            Some(QuickStartIpMode::Dual),
        )
        .unwrap();

        assert!(reused);
        assert_eq!(normalized.tun.ip_mode, crate::config::server::IpMode::Dual);
        assert_eq!(normalized.pool.ipv6.cidr, "fd71:e1:42::/64");
        assert_eq!(
            normalized.routing.ipv6.mode,
            crate::config::server::Ipv6RoutingMode::Nat66
        );
        assert_eq!(normalized.dns.listen_ipv6, normalized.tun.ipv6_address);
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
            quickstart_profile_for_current("reality-tls", &current, None, false, None).unwrap();

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
            quickstart_profile_for_current("udp-obfs", &current, None, false, None).unwrap();
        assert!(reused);
        assert!(sid.is_none());
        assert_eq!(obfs_key.as_deref(), Some("operator-kept-key"));
    }
}
