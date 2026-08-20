//! Server-side NAT / masquerade for full-tunnel egress, programmed via the
//! **`iptables` CLI only** (never `nft` or `ufw`). When a profile sets
//! `routing.nat.enabled = true`, [`setup`] enables IPv4 forwarding and installs the
//! MASQUERADE + FORWARD + MSS-clamp rules so the client pool can reach the internet
//! through the server's WAN interface.
//!
//! Every rule carries a per-profile iptables comment (`qeli-nat:<profile>`), so
//! [`cleanup`] can find and delete EXACTLY our rules — even after an unclean exit.
//! `run_profile` calls [`cleanup`] on every start (clearing rules left behind, or a
//! now-disabled profile's rules) before [`setup`], and the worker tears them down
//! again on graceful shutdown.
//!
//! Rules are split into ESSENTIAL (MASQUERADE + MSS clamp — full-tunnel egress can't
//! work without them) and CONDITIONAL (the explicit `FORWARD … ACCEPT` rules, redundant
//! only when the host's built-in chain is empty with policy ACCEPT). Because the modern `iptables-nft`
//! wrapper can return success while silently no-op'ing on a chain backed by a legacy
//! table, we VERIFY each rule with `iptables -C` rather than trusting the exit code:
//! an essential rule that won't apply fails the setup; a conditional rule may be absent
//! only when the built-in FORWARD chain is verified as empty with policy ACCEPT. DROP,
//! any explicit rule/jump, or an unreadable chain fails closed instead of starting a
//! profile that black-holes client traffic.

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// iptables comment tag for the rules belonging to `profile`.
fn tag(profile: &str) -> String {
    format!("qeli-nat:{profile}")
}

/// Locate the `iptables` binary. `None` = not installed — the caller surfaces that
/// as an error + log + panel warning. Checks the usual sbin locations first (cheap,
/// no exec) then falls back to a PATH probe.
pub fn iptables_path() -> Option<String> {
    for p in [
        "/usr/sbin/iptables",
        "/sbin/iptables",
        "/usr/bin/iptables",
        "/bin/iptables",
    ] {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    if Command::new("iptables")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("iptables".to_string());
    }
    None
}

pub fn ip6tables_path() -> Option<String> {
    for path in [
        "/usr/sbin/ip6tables",
        "/sbin/ip6tables",
        "/usr/bin/ip6tables",
        "/bin/ip6tables",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    Command::new("ip6tables")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|_| "ip6tables".to_string())
}

/// Whether `iptables` is available on this host (used by the panel to warn).
pub fn available() -> bool {
    iptables_path().is_some()
}

fn ipt(path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(path).args(args).output()
}

/// Auto-detect the default-route (WAN) interface via `ip route get 1.1.1.1`.
fn detect_wan() -> Option<String> {
    let out = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // "1.1.1.1 via 10.0.0.1 dev eth0 src ..." — the token after "dev".
    let s = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = s.split_whitespace().collect();
    toks.iter()
        .position(|&t| t == "dev")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.to_string())
}

/// Best-effort `net.ipv4.ip_forward = 1` (needs CAP_NET_ADMIN, which the worker has).
/// Left enabled on teardown — forwarding is a global host knob and flipping it off
/// could break other services on the box.
fn enable_ip_forward() -> bool {
    let path = "/proc/sys/net/ipv4/ip_forward";
    if matches!(std::fs::read_to_string(path), Ok(ref v) if v.trim() == "1") {
        return true; // already on
    }
    match std::fs::write(path, "1\n") {
        Ok(()) => {
            log::info!("NAT: enabled net.ipv4.ip_forward (left enabled on teardown)");
            true
        }
        Err(e) => {
            log::error!(
                "NAT: could not enable net.ipv4.ip_forward ({e}) — the kernel will not forward \
                 anything between the tunnel and the WAN"
            );
            false
        }
    }
}

const IPV6_FORWARDING_SYSCTL: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

#[derive(Debug)]
struct ManagedIpv6Sysctl {
    original: String,
    owners: HashSet<String>,
}

/// Process-local ownership of the global IPv6 router sysctls changed by active profiles.
///
/// Profiles start and stop independently. Restoring `forwarding` or an uplink's `accept_ra`
/// from a per-profile teardown would therefore break every sibling still using the setting.
/// The first owner records the host value, every later owner shares it, and the last one
/// restores it. A value changed by the operator while qeli is running is never overwritten.
#[derive(Debug, Default)]
struct Ipv6SysctlState {
    forwarding: Option<ManagedIpv6Sysctl>,
    accept_ra: HashMap<String, ManagedIpv6Sysctl>,
    profile_wan: HashMap<String, String>,
}

fn ipv6_sysctl_state() -> &'static Mutex<Ipv6SysctlState> {
    static STATE: OnceLock<Mutex<Ipv6SysctlState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Ipv6SysctlState::default()))
}

fn accept_ra_sysctl(wan: &str) -> anyhow::Result<String> {
    // Interface names originate in a trusted config or `ip route`, but they are still used as
    // one filesystem component below. Reject separators/dot components here so a malformed
    // command response or config can never turn this into an arbitrary /proc write.
    if wan.is_empty()
        || wan.len() > 15
        || wan == "."
        || wan == ".."
        || wan.contains('/')
        || wan.contains('\\')
        || wan.contains('\0')
    {
        anyhow::bail!("invalid IPv6 uplink interface name '{wan}'");
    }
    Ok(format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"))
}

fn read_sysctl(path: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .map_err(|error| anyhow::anyhow!("cannot read {path}: {error}"))
}

fn set_sysctl(path: &str, value: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{value}\n"))
        .map_err(|error| anyhow::anyhow!("cannot write {path}={value}: {error}"))?;
    let actual = read_sysctl(path)?;
    if actual != value {
        anyhow::bail!("{path} remained {actual} after writing {value}");
    }
    Ok(())
}

fn restore_sysctl_if_owned(path: &str, managed_value: &str, original: &str) {
    let current = match read_sysctl(path) {
        Ok(value) => value,
        Err(error) => {
            log::warn!("IPv6 routing: cannot inspect {path} during cleanup: {error}");
            return;
        }
    };
    if current != managed_value {
        log::warn!(
            "IPv6 routing: not restoring {path} to {original}: it was changed externally to {current} while qeli was running"
        );
        return;
    }
    if current != original {
        match set_sysctl(path, original) {
            Ok(()) => log::info!("IPv6 routing: restored {path}={original}"),
            Err(error) => log::warn!("IPv6 routing: could not restore {path}: {error}"),
        }
    }
}

/// Acquire the host IPv6-router settings for one profile.
///
/// `accept_ra=2` is applied before global forwarding is enabled. Linux otherwise stops
/// accepting Router Advertisements when it becomes a router, which can silently remove the
/// WAN's SLAAC address/default route. The ordering also keeps auto-detection usable.
fn acquire_ipv6_sysctls(profile: &str, wan: &str) -> anyhow::Result<()> {
    let ra_path = accept_ra_sysctl(wan)?;
    let mut state = ipv6_sysctl_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if let Some(existing) = state.profile_wan.get(profile) {
        if existing == wan {
            return Ok(());
        }
        anyhow::bail!(
            "profile '{profile}' already owns IPv6 router settings for interface '{existing}'"
        );
    }

    let mut created_ra = false;
    if let Some(entry) = state.accept_ra.get_mut(wan) {
        entry.owners.insert(profile.to_string());
    } else {
        let original = read_sysctl(&ra_path)?;
        if original != "2" {
            set_sysctl(&ra_path, "2")?;
            log::info!("IPv6 routing: set {ra_path}=2 while the uplink is used by qeli");
        }
        state.accept_ra.insert(
            wan.to_string(),
            ManagedIpv6Sysctl {
                original,
                owners: HashSet::from([profile.to_string()]),
            },
        );
        created_ra = true;
    }

    let forwarding_result = if let Some(entry) = state.forwarding.as_mut() {
        entry.owners.insert(profile.to_string());
        Ok(())
    } else {
        read_sysctl(IPV6_FORWARDING_SYSCTL).and_then(|original| {
            if original != "1" {
                set_sysctl(IPV6_FORWARDING_SYSCTL, "1")?;
                log::info!(
                    "IPv6 routing: enabled {IPV6_FORWARDING_SYSCTL} while IPv6 profiles are active"
                );
            }
            state.forwarding = Some(ManagedIpv6Sysctl {
                original,
                owners: HashSet::from([profile.to_string()]),
            });
            Ok(())
        })
    };
    if let Err(error) = forwarding_result {
        // Roll back the RA ownership added above. When this was the first owner, also restore
        // the value we changed before attempting the global forwarding write.
        if let Some(entry) = state.accept_ra.get_mut(wan) {
            entry.owners.remove(profile);
        }
        let remove_ra = state
            .accept_ra
            .get(wan)
            .is_some_and(|entry| entry.owners.is_empty());
        if remove_ra {
            if let Some(entry) = state.accept_ra.remove(wan) {
                if created_ra {
                    restore_sysctl_if_owned(&ra_path, "2", &entry.original);
                }
            }
        }
        return Err(error);
    }

    state
        .profile_wan
        .insert(profile.to_string(), wan.to_string());
    Ok(())
}

fn release_ipv6_sysctls(profile: &str) {
    let mut state = ipv6_sysctl_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(wan) = state.profile_wan.remove(profile) else {
        return;
    };

    if let Some(entry) = state.accept_ra.get_mut(&wan) {
        entry.owners.remove(profile);
    }
    if state
        .accept_ra
        .get(&wan)
        .is_some_and(|entry| entry.owners.is_empty())
    {
        if let Some(entry) = state.accept_ra.remove(&wan) {
            if let Ok(path) = accept_ra_sysctl(&wan) {
                restore_sysctl_if_owned(&path, "2", &entry.original);
            }
        }
    }

    if let Some(entry) = state.forwarding.as_mut() {
        entry.owners.remove(profile);
    }
    if state
        .forwarding
        .as_ref()
        .is_some_and(|entry| entry.owners.is_empty())
    {
        if let Some(entry) = state.forwarding.take() {
            restore_sysctl_if_owned(IPV6_FORWARDING_SYSCTL, "1", &entry.original);
        }
    }
}

fn detect_wan_ipv6() -> Option<String> {
    let output = Command::new("ip")
        .args(["-6", "route", "get", "2606:4700:4700::1111"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].to_string())
}

/// Resolve the IPv4 egress using the historical compatibility rule: the old default value
/// `eth0` was a placeholder for auto-detection, so only a different non-empty value is explicit.
pub(crate) fn resolve_wan_ipv4(configured_iface: &str) -> Option<String> {
    let configured = configured_iface.trim();
    if !configured.is_empty() && configured != "eth0" {
        Some(configured.to_string())
    } else {
        detect_wan()
    }
}

/// Resolve the IPv6 egress. Unlike the legacy IPv4 key, this setting has always documented an
/// empty string as auto; an explicit `eth0` therefore means exactly eth0.
pub(crate) fn resolve_wan_ipv6(configured_iface: &str) -> Option<String> {
    let configured = configured_iface.trim();
    if configured.is_empty() {
        detect_wan_ipv6()
    } else {
        Some(configured.to_string())
    }
}

/// One iptables rule we manage. `essential = false` rules (FORWARD ACCEPT) may be
/// omitted only when the built-in FORWARD chain is verified as empty with policy ACCEPT.
struct Rule {
    table: &'static str,
    chain: &'static str,
    args: Vec<String>,
    essential: bool,
}

/// The iptables rules we install for one profile.
fn rules(profile: &str, wan: &str, tun: &str, pool_cidr: &str, mss: i32) -> Vec<Rule> {
    let mss = mss.to_string();
    let comment = tag(profile);
    let cm = |mut r: Vec<String>| -> Vec<String> {
        r.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
        ]);
        r
    };
    vec![
        // ESSENTIAL — MASQUERADE the client pool out the WAN interface.
        Rule {
            table: "nat",
            chain: "POSTROUTING",
            args: cm(vec!["-s".into(), pool_cidr.into(), "-o".into(), wan.into()])
                .into_iter()
                .chain(["-j".into(), "MASQUERADE".into()])
                .collect(),
            essential: true,
        },
        // ESSENTIAL — clamp forwarded-TCP MSS to the tunnel MTU (both directions);
        // avoids the PMTU black hole that hangs downloads on TCP transports.
        Rule {
            table: "mangle",
            chain: "FORWARD",
            args: cm(vec![
                "-p".into(),
                "tcp".into(),
                "--tcp-flags".into(),
                "SYN,RST".into(),
                "SYN".into(),
                "-o".into(),
                tun.into(),
            ])
            .into_iter()
            .chain([
                "-j".into(),
                "TCPMSS".into(),
                "--set-mss".into(),
                mss.clone(),
            ])
            .collect(),
            essential: true,
        },
        Rule {
            table: "mangle",
            chain: "FORWARD",
            args: cm(vec![
                "-p".into(),
                "tcp".into(),
                "--tcp-flags".into(),
                "SYN,RST".into(),
                "SYN".into(),
                "-i".into(),
                tun.into(),
            ])
            .into_iter()
            .chain(["-j".into(), "TCPMSS".into(), "--set-mss".into(), mss])
            .collect(),
            essential: true,
        },
        // CONDITIONAL — explicitly permit forwarding tun <-> wan (redundant only for an
        // otherwise empty FORWARD chain whose built-in policy is ACCEPT).
        Rule {
            table: "filter",
            chain: "FORWARD",
            args: cm(vec!["-i".into(), tun.into(), "-o".into(), wan.into()])
                .into_iter()
                .chain(["-j".into(), "ACCEPT".into()])
                .collect(),
            essential: false,
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            args: cm(vec![
                "-i".into(),
                wan.into(),
                "-o".into(),
                tun.into(),
                "-m".into(),
                "state".into(),
                "--state".into(),
                "RELATED,ESTABLISHED".into(),
            ])
            .into_iter()
            .chain(["-j".into(), "ACCEPT".into()])
            .collect(),
            essential: false,
        },
    ]
}

/// Is this exact rule currently present? Verified with `iptables -C` (the only
/// reliable check across the legacy/nft backends — the exit code of `-A` lies on a
/// chain the nft wrapper considers incompatible).
fn rule_present(path: &str, table: &str, chain: &str, rule: &[String]) -> bool {
    let mut a: Vec<String> = vec!["-t".into(), table.into(), "-C".into(), chain.into()];
    a.extend_from_slice(rule);
    let argv: Vec<&str> = a.iter().map(String::as_str).collect();
    ipt(path, &argv)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install NAT for `profile`. Returns the chosen WAN interface on success.
pub fn setup(
    profile: &str,
    configured_iface: &str,
    pool_cidr: &str,
    tun: &str,
    mtu: i32,
) -> anyhow::Result<String> {
    let path = iptables_path().ok_or_else(|| {
        anyhow::anyhow!(
            "`iptables` is not installed (apt install iptables) — required for routing.nat.enabled"
        )
    })?;
    // WAN: an explicit, non-default interface wins; otherwise auto-detect. The config
    // default "eth0" is treated as "auto" (it's just a placeholder).
    let wan = resolve_wan_ipv4(configured_iface).ok_or_else(|| {
        anyhow::anyhow!(
            "could not auto-detect the WAN interface; set routing.nat.interface explicitly"
        )
    })?;

    // `routing.nat.enabled = true` is a PROMISE that clients reach the internet, and without
    // `ip_forward` the kernel drops every transit packet no matter how correct the iptables
    // rules are. This used to be best-effort — a warning, then `Ok(wan)` — so the profile came
    // up, clients connected, got an address, and had no connectivity at all, with the cause a
    // single WARN line above a screen of INFO. Making it fatal is what turns "NAT is enabled"
    // into something that was actually checked. (Audit 2026-08-01, §6.)
    if !enable_ip_forward() {
        anyhow::bail!(
            "routing.nat.enabled = true but net.ipv4.ip_forward could not be enabled — the \
             kernel would not forward client traffic, so every client would connect and then \
             reach nothing. Enable it on the host (`sysctl -w net.ipv4.ip_forward=1`), or set \
             routing.nat.enabled = false"
        );
    }
    // Clear any stale copies first so a re-apply can't stack duplicates.
    cleanup_with(&path, profile);

    let mss = (mtu - 40).max(536);
    let mut forward_unapplied = false;
    for r in rules(profile, &wan, tun, pool_cidr, mss) {
        let insert = r.table == "filter" && r.chain == "FORWARD";
        let mut args: Vec<String> = vec![
            "-t".into(),
            r.table.into(),
            if insert { "-I".into() } else { "-A".into() },
            r.chain.into(),
        ];
        if insert {
            args.push("1".into());
        }
        args.extend(r.args.clone());
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = ipt(&path, &argv); // exit code is unreliable on nft-incompatible chains
        if !rule_present(&path, r.table, r.chain, &r.args) {
            if r.essential {
                cleanup_with(&path, profile); // roll back the partial set
                anyhow::bail!(
                    "iptables could not apply the {}/{} rule — check the host firewall backend \
                     (e.g. legacy/nft mix)",
                    r.table,
                    r.chain
                );
            }
            forward_unapplied = true;
        }
    }
    if forward_unapplied {
        // Whether this is survivable depends on the host's FORWARD POLICY, so ask instead of
        // guessing. With a policy of ACCEPT the missing rules change nothing and a warning is
        // the right response — that is why they are not `essential`. With DROP the chain
        // discards exactly the transit traffic those rules existed to permit, so the profile
        // would serve clients that can reach nothing; the old code warned in both cases and
        // returned Ok. (Audit 2026-08-01, §6.)
        match forward_policy(&path) {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': FORWARD ACCEPT rules could not be applied (host has a \
                 mixed legacy/nft filter table). The empty built-in chain has policy ACCEPT, so egress \
                 still works — but if you tighten it later, permit forwarding {pool_cidr} \
                 <-> {wan} yourself."
            ),
            status => {
                cleanup_with(&path, profile); // roll back the partial set
                anyhow::bail!(
                    "the FORWARD ACCEPT rules could not be applied and the observed chain state is {} — client traffic between {pool_cidr} and {wan} may be dropped. Permit that forwarding yourself, fix the iptables backend, or set routing.nat.enabled = false",
                    status.as_ref().map_or("unknown", |value| value.summary())
                );
            }
        }
    }
    Ok(wan)
}

fn ipv6_rules(
    profile: &str,
    wan: &str,
    tun: &str,
    pool_cidr: &str,
    mss: i32,
    mode: crate::config::server::Ipv6RoutingMode,
) -> Vec<Rule> {
    let comment = tag(profile);
    let annotate = |mut rule: Vec<String>| {
        rule.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
        ]);
        rule
    };
    let mut rules = Vec::new();
    if mode == crate::config::server::Ipv6RoutingMode::Nat66 {
        rules.push(Rule {
            table: "nat",
            chain: "POSTROUTING",
            args: annotate(vec![
                "-s".into(),
                pool_cidr.into(),
                "-o".into(),
                wan.into(),
                "-j".into(),
                "MASQUERADE".into(),
            ]),
            essential: true,
        });
    }
    for direction in ["-o", "-i"] {
        rules.push(Rule {
            table: "mangle",
            chain: "FORWARD",
            args: annotate(vec![
                "-p".into(),
                "tcp".into(),
                "--tcp-flags".into(),
                "SYN,RST".into(),
                "SYN".into(),
                direction.into(),
                tun.into(),
                "-j".into(),
                "TCPMSS".into(),
                "--set-mss".into(),
                mss.to_string(),
            ]),
            essential: true,
        });
    }
    rules.push(Rule {
        table: "filter",
        chain: "FORWARD",
        args: annotate(vec![
            "-i".into(),
            tun.into(),
            "-o".into(),
            wan.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]),
        essential: false,
    });
    let inbound = if mode == crate::config::server::Ipv6RoutingMode::Route {
        // A delegated/routed GUA prefix is bidirectional by definition. Limit the permit
        // to this profile's pool so it cannot open another TUN or a server-local address.
        vec![
            "-i".into(),
            wan.into(),
            "-o".into(),
            tun.into(),
            "-d".into(),
            pool_cidr.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    } else {
        // NAT66 exposes no independently routed client prefix. Only reply traffic may
        // cross from WAN to TUN; a fresh unsolicited connection remains closed.
        vec![
            "-i".into(),
            wan.into(),
            "-o".into(),
            tun.into(),
            "-m".into(),
            "state".into(),
            "--state".into(),
            "RELATED,ESTABLISHED".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    };
    rules.push(Rule {
        table: "filter",
        chain: "FORWARD",
        args: annotate(inbound),
        essential: false,
    });
    rules
}

/// `off` still carries IPv6 inside the profile, but must never inherit host-wide forwarding
/// from a sibling route/NAT66 profile or from the administrator. Client-to-client and
/// client-side routed-LAN traffic uses qeli's authenticated direct forwarder, so no broad
/// kernel ACCEPT is needed here; fail closed for every packet leaving through another
/// interface while leaving local INPUT and same-TUN handling untouched.
fn ipv6_off_rules(profile: &str, tun: &str) -> Vec<Rule> {
    let comment = tag(profile);
    let annotate = |mut rule: Vec<String>| {
        rule.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
        ]);
        rule
    };
    vec![Rule {
        table: "filter",
        chain: "FORWARD",
        args: annotate(vec![
            "-i".into(),
            tun.into(),
            "!".into(),
            "-o".into(),
            tun.into(),
            "-j".into(),
            "DROP".into(),
        ]),
        essential: true,
    }]
}

/// Configure native IPv6 forwarding for one profile. `route` preserves client source
/// addresses; `nat66` additionally applies MASQUERADE on the selected IPv6 uplink.
pub fn setup_ipv6(
    profile: &str,
    mode: crate::config::server::Ipv6RoutingMode,
    configured_iface: &str,
    pool_cidr: &str,
    tun: &str,
    mtu: i32,
) -> anyhow::Result<Option<String>> {
    let path = ip6tables_path().ok_or_else(|| {
        anyhow::anyhow!(
            "an IPv6 profile with routing.ipv6.mode = {mode} requires ip6tables so its egress boundary can be enforced"
        )
    })?;
    cleanup_with(&path, profile);
    if mode == crate::config::server::Ipv6RoutingMode::Off {
        // Be correct even when a caller changes this profile from route/NAT66 to off
        // without first going through the outer cleanup wrapper: off owns no router
        // sysctls and must release its previous forwarding/accept_ra lease.
        release_ipv6_sysctls(profile);
        // Verification is mandatory: falling back to a permissive FORWARD policy would be
        // the exact cross-profile leak this mode exists to prevent.
        for rule in ipv6_off_rules(profile, tun) {
            let mut args = vec![
                "-t".to_string(),
                rule.table.to_string(),
                "-I".to_string(),
                rule.chain.to_string(),
                "1".to_string(),
            ];
            args.extend(rule.args.clone());
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = ipt(&path, &refs);
            if !rule_present(&path, rule.table, rule.chain, &rule.args) {
                cleanup_with(&path, profile);
                anyhow::bail!(
                    "ip6tables could not enforce routing.ipv6.mode = off for profile '{profile}'; refusing an IPv6 plan that could inherit Internet forwarding"
                );
            }
        }
        return Ok(None);
    }
    let wan = resolve_wan_ipv6(configured_iface).ok_or_else(|| {
        anyhow::anyhow!("could not detect an IPv6 uplink; set routing.ipv6.interface explicitly")
    })?;
    acquire_ipv6_sysctls(profile, &wan).map_err(|error| {
        anyhow::anyhow!(
            "routing.ipv6.mode = {mode} could not enable safe IPv6 forwarding on '{wan}': {error}"
        )
    })?;
    // Auto-detection depends on the RA/default route that existed before forwarding was
    // enabled. Verify it survived the transition: otherwise rules below would be installed
    // for a stale uplink and the profile would ACK IPv6 while public traffic has no route.
    if configured_iface.trim().is_empty() {
        match detect_wan_ipv6() {
            Some(active_wan) if active_wan == wan => {}
            active_wan => {
                release_ipv6_sysctls(profile);
                anyhow::bail!(
                    "the auto-detected IPv6 uplink changed from '{wan}' to '{}' after enabling forwarding; check accept_ra=2 and the host IPv6 default route",
                    active_wan.as_deref().unwrap_or("none")
                );
            }
        }
    }
    let mut forward_unapplied = false;
    for rule in ipv6_rules(profile, &wan, tun, pool_cidr, (mtu - 60).max(1220), mode) {
        let insert = rule.table == "filter" && rule.chain == "FORWARD";
        let mut args = vec![
            "-t".to_string(),
            rule.table.to_string(),
            if insert { "-I" } else { "-A" }.to_string(),
            rule.chain.to_string(),
        ];
        if insert {
            args.push("1".to_string());
        }
        args.extend(rule.args.clone());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = ipt(&path, &refs);
        if !rule_present(&path, rule.table, rule.chain, &rule.args) {
            if rule.essential {
                cleanup_with(&path, profile);
                release_ipv6_sysctls(profile);
                anyhow::bail!(
                    "ip6tables could not apply the {}/{} rule for IPv6 {}",
                    rule.table,
                    rule.chain,
                    mode
                );
            }
            forward_unapplied = true;
        }
    }
    if forward_unapplied {
        match forward_policy(&path) {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': IPv6 FORWARD permit rules could not be verified; \
                 the empty built-in chain has policy ACCEPT. Ensure {pool_cidr} can forward between \
                 {tun} and {wan}."
            ),
            status => {
                cleanup_with(&path, profile);
                release_ipv6_sysctls(profile);
                anyhow::bail!(
                    "qeli could not install IPv6 FORWARD permit rules and the observed chain state is {}; refusing a profile that may black-hole forwarded traffic",
                    status.as_ref().map_or("unknown", |value| value.summary())
                );
            }
        }
    }
    Ok(Some(wan))
}

/// The `filter/FORWARD` chain's default policy plus whether it contains explicit rules, or
/// `None` when it cannot be read. `iptables -S FORWARD` opens with `-P FORWARD DROP`.
fn forward_policy(path: &str) -> Option<ChainPolicy> {
    let out = ipt(path, &["-t", "filter", "-S", "FORWARD"]).ok()?;
    if !out.status.success() {
        return None;
    }
    chain_policy_from_output(&out.stdout, "FORWARD")
}

/// The `filter/INPUT` chain's default policy. DNS traffic terminates on the server rather
/// than traversing FORWARD, so a host with `INPUT DROP` needs an explicit per-profile rule.
fn input_policy(path: &str) -> Option<ChainPolicy> {
    let out = ipt(path, &["-t", "filter", "-S", "INPUT"]).ok()?;
    if !out.status.success() {
        return None;
    }
    chain_policy_from_output(&out.stdout, "INPUT")
}

#[derive(Debug, PartialEq, Eq)]
struct ChainPolicy {
    policy: String,
    unconditionally_accepts: bool,
}

impl ChainPolicy {
    fn summary(&self) -> &str {
        if self.unconditionally_accepts {
            "empty/ACCEPT"
        } else if self.policy.eq_ignore_ascii_case("ACCEPT") {
            "ACCEPT with explicit rules"
        } else {
            self.policy.as_str()
        }
    }
}

/// Parse an exact built-in-chain policy and record whether any explicit rule can intercept
/// packets before it. Default ACCEPT is a safe fallback only for a genuinely empty chain.
fn chain_policy_from_output(output: &[u8], chain: &str) -> Option<ChainPolicy> {
    let prefix = format!("-P {chain} ");
    let mut policy = None;
    let mut has_explicit_rules = false;
    for line in String::from_utf8_lossy(output)
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        if let Some(value) = line.strip_prefix(&prefix) {
            let mut fields = value.split_whitespace();
            let value = fields.next()?;
            if fields.next().is_some() || policy.replace(value.to_string()).is_some() {
                return None;
            }
        } else {
            has_explicit_rules = true;
        }
    }
    let policy = policy?;
    Some(ChainPolicy {
        unconditionally_accepts: policy.eq_ignore_ascii_case("ACCEPT") && !has_explicit_rules,
        policy,
    })
}

fn dns_input_rule(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
    proto: &str,
) -> Vec<String> {
    vec![
        "-i".into(),
        tun.into(),
        "-s".into(),
        pool_cidr.into(),
        "-p".into(),
        proto.into(),
        "-d".into(),
        listen.into(),
        "--dport".into(),
        port.to_string(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        tag(profile),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

/// Permit only this profile's clients to reach its in-process DNS proxy.
///
/// Full-tunnel traffic normally crosses `FORWARD`, but the pushed resolver is the server's
/// own TUN address and therefore crosses `INPUT`. Keep the exception narrow: exact interface,
/// client pool, resolver address and port, for both DNS transports.
pub fn enable_dns_input(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
) -> anyhow::Result<()> {
    let ipv6 = listen
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_ipv6());
    let tool = if ipv6 { "ip6tables" } else { "iptables" };
    let path = if ipv6 {
        ip6tables_path()
    } else {
        iptables_path()
    };
    let path = path.ok_or_else(|| {
        anyhow::anyhow!("{tool} is required to verify INPUT access to DNS {listen}:{port} on {tun}")
    })?;
    let mut unapplied = Vec::new();
    for proto in ["udp", "tcp"] {
        let args = dns_input_rule(profile, tun, pool_cidr, listen, port, proto);
        // Insert before operator catch-all DROP rules. The match is restricted to the exact
        // qeli TUN/pool/destination, so it cannot make a public listener reachable.
        let mut argv = vec![
            "-t".to_string(),
            "filter".to_string(),
            "-I".to_string(),
            "INPUT".to_string(),
            "1".to_string(),
        ];
        argv.extend(args.clone());
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = ipt(&path, &refs);
        if !rule_present(&path, "filter", "INPUT", &args) {
            unapplied.push(proto);
        }
    }
    if !unapplied.is_empty() {
        match input_policy(&path) {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': DNS INPUT rule(s) for {} could not be verified, but the \
                 empty built-in chain has policy ACCEPT. If you tighten it later, permit {listen}:{port} \
                 from {pool_cidr} on {tun} yourself.",
                unapplied.join("+")
            ),
            status => anyhow::bail!(
                "could not install DNS INPUT rule(s) for {} on {} and the observed INPUT \
                 chain state is {} - clients would receive {} as their resolver but queries may \
                 be firewalled",
                unapplied.join("+"),
                tun,
                status.as_ref().map_or("unknown", |value| value.summary()),
                listen
            ),
        }
    }
    log::info!(
        "Profile '{profile}': DNS INPUT permit {pool_cidr} via {tun} -> {listen}:{port}, udp+tcp"
    );
    Ok(())
}

/// Pure L3 routing WITHOUT NAT (`routing.forward_private`): enable `net.ipv4.ip_forward`
/// and permit forwarding to/from the tunnel, so the server routes TRANSIT traffic between
/// the tunnel and its own networks with the real source IPs preserved (site-to-site) —
/// unlike [`setup`], which MASQUERADEs for internet egress. For a packet the server itself
/// originates to a client's `client_subnet` (#13) neither of these is needed (a route is
/// enough); this is only for third-party transit. `iptables` is required so the path can
/// be verified; failure to install explicit permits is accepted only when the built-in
/// FORWARD chain is empty and its policy is exactly ACCEPT. Rules carry the same
/// `qeli-nat:<profile>` tag, so
/// [`cleanup`]/[`cleanup_all`] remove them too.
pub fn enable_routing(profile: &str, tun: &str, mtu: i32) -> anyhow::Result<()> {
    // Same invariant as `setup`, for the same reason: `forward_private` promises the server
    // ROUTES transit traffic, and without `ip_forward` the kernel drops every transit packet
    // whatever the rules say. This used to be ignored entirely — the function returned `()`
    // and logged success unconditionally — so a profile came up "routing" while nothing was
    // forwarded. (Audit 2026-08-01, §5.)
    if !enable_ip_forward() {
        anyhow::bail!(
            "routing.forward_private = true but net.ipv4.ip_forward could not be enabled — the \
             kernel would not route anything between the tunnel and your networks. Enable it on \
             the host (`sysctl -w net.ipv4.ip_forward=1`), or unset routing.forward_private"
        );
    }
    let path = iptables_path().ok_or_else(|| {
        anyhow::anyhow!(
            "routing.forward_private = true requires iptables so qeli can verify the FORWARD path"
        )
    })?;
    let mss = (mtu - 40).max(536).to_string();
    let comment = tag(profile);
    let cm = |mut r: Vec<String>| -> Vec<String> {
        r.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
        ]);
        r
    };
    let mss_rule = |dir: &str| -> (&'static str, &'static str, Vec<String>) {
        (
            "mangle",
            "FORWARD",
            cm(vec![
                "-p".into(),
                "tcp".into(),
                "--tcp-flags".into(),
                "SYN,RST".into(),
                "SYN".into(),
                dir.into(),
                tun.into(),
            ])
            .into_iter()
            .chain([
                "-j".into(),
                "TCPMSS".into(),
                "--set-mss".into(),
                mss.clone(),
            ])
            .collect(),
        )
    };
    let accept = |dir: &str| -> (&'static str, &'static str, Vec<String>) {
        (
            "filter",
            "FORWARD",
            cm(vec![dir.into(), tun.into()])
                .into_iter()
                .chain(["-j".into(), "ACCEPT".into()])
                .collect(),
        )
    };
    // MSS-clamp forwarded TCP (PMTU black-hole guard), then permit tun<->anywhere routing.
    let mut forward_unapplied = false;
    let mut mss_unapplied = false;
    for (table, chain, args) in [mss_rule("-o"), mss_rule("-i"), accept("-i"), accept("-o")] {
        let insert = table == "filter" && chain == "FORWARD";
        let mut argv = vec![
            "-t".to_string(),
            table.to_string(),
            if insert { "-I" } else { "-A" }.to_string(),
            chain.to_string(),
        ];
        if insert {
            argv.push("1".to_string());
        }
        argv.extend(args.clone());
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = ipt(&path, &refs); // exit code is unreliable on nft-incompatible chains
                                   // VERIFY instead of assuming. The whole set was applied with `let _ =` and then
                                   // reported as success, so a host that refused every rule still logged "FORWARD ACCEPT
                                   // for tun0" — the operator had no way to tell routing from silence.
        if !rule_present(&path, table, chain, &args) {
            if insert {
                forward_unapplied = true;
            } else {
                mss_unapplied = true;
            }
        }
    }
    if forward_unapplied {
        // Survivable only for a genuinely empty chain whose policy is ACCEPT. A default
        // ACCEPT behind an explicit DROP/jump proves nothing about this transit path.
        match forward_policy(&path) {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': forward_private — explicit FORWARD permits could not be \
                 applied, but the empty built-in chain has policy ACCEPT. If you tighten it later, permit \
                 {tun} yourself."
            ),
            status => {
                cleanup_with(&path, profile); // roll back the partial set
                anyhow::bail!(
                    "routing.forward_private = true, but FORWARD permits could not be applied and the observed chain state is {} — transit through {tun} may be dropped. Permit it yourself, fix the iptables backend, or unset routing.forward_private",
                    status.as_ref().map_or("unknown", |value| value.summary())
                );
            }
        }
    }
    if mss_unapplied {
        log::warn!(
            "Profile '{profile}': forward_private — TCP MSS clamp could not be verified; \
             correct Path-MTU Discovery is required for forwarded TCP through {tun}."
        );
    }
    log::info!(
        "Profile '{profile}': forward_private — ip_forward + FORWARD ACCEPT for {tun} (routing, no NAT)"
    );
    Ok(())
}

/// Redirect in-tunnel DNS from the standard port 53 to where the proxy actually listens.
///
/// `dns.port` exists so the proxy can dodge a host service already holding 53 (dnsmasq,
/// Pi-hole and friends bind `0.0.0.0:53`, which covers the TUN address too). But the port was
/// then PUSHED to clients — and no client platform can use it: `VpnService.Builder` and
/// `NEDNSSettings` take an address and nothing else, Windows and macOS configure resolvers by
/// IP, and even the Rust client only manages it through `resolvectl`'s `IP#port` syntax, which
/// cannot be represented by every platform. So a non-default `dns.port`
/// silently black-holed DNS for every client but one.
///
/// Splitting the two settings fixes it properly: the proxy keeps its odd port, clients are
/// told the only port they can express — 53 — and the kernel bridges the gap here. A no-op
/// when the proxy already listens on 53.
///
/// Tagged with the same per-profile comment as every other rule, so [`cleanup`] removes it
/// with the rest when the profile stops.
pub fn enable_dns_redirect(profile: &str, tun: &str, listen: &str, port: u16) -> bool {
    if port == 53 {
        return true; // nothing to bridge
    }
    let ipv6 = listen
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_ipv6());
    let tool = if ipv6 { "ip6tables" } else { "iptables" };
    let path = match if ipv6 {
        ip6tables_path()
    } else {
        iptables_path()
    } {
        Some(p) => p,
        None => {
            log::error!(
                "Profile '{profile}': dns.port = {port} needs a {tool} REDIRECT so clients \
                 can keep using port 53, but {tool} is absent. Clients would be handed a \
                 resolver they cannot reach. Set dns.port = 53, or install {tool}."
            );
            return false;
        }
    };
    let comment = tag(profile);
    // BOTH protocols. This was UDP-only, and correctly so at the time: the proxy bound a UDP
    // socket and nothing listened on TCP, so a TCP rule would have redirected clients to a
    // closed port — worse than leaving 53/tcp unserved. Now that the resolver serves TCP
    // (RFC 7766, and the retry path for a truncated answer), the rule has to cover it, or a
    // client told to retry over TCP would reach port 53 with nothing behind it — precisely the
    // black hole the redirect exists to prevent. (Audit 2026-08-01, §10.)
    for proto in ["udp", "tcp"] {
        let args: Vec<String> = vec![
            "-i".into(),
            tun.into(),
            "-p".into(),
            proto.into(),
            "-d".into(),
            listen.into(),
            "--dport".into(),
            "53".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.clone(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            port.to_string(),
        ];
        let mut argv = vec![
            "-t".to_string(),
            "nat".to_string(),
            "-A".to_string(),
            "PREROUTING".to_string(),
        ];
        argv.extend(args.clone());
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = ipt(&path, &refs);

        // VERIFY rather than trust the exit code — `iptables-nft` can report success for a rule
        // it did not install, which is why every other rule here is checked the same way.
        if !rule_present(&path, "nat", "PREROUTING", &args) {
            log::error!(
                "Profile '{profile}': FAILED to install the DNS redirect {listen}:53/{proto} -> \
                 :{port} on {tun}. Clients would be handed a resolver they cannot reach — set \
                 dns.port = 53, or fix iptables."
            );
            return false;
        }
    }
    log::info!(
        "Profile '{profile}': DNS redirect {listen}:53 -> :{port} on {tun}, udp+tcp \
         (clients are told 53; the proxy listens on {port})"
    );
    true
}

/// Remove every NAT rule tagged for `profile` (idempotent; a no-op if none exist or
/// iptables is absent).
pub fn cleanup(profile: &str) {
    if let Some(path) = iptables_path() {
        cleanup_with(&path, profile);
    }
    if let Some(path) = ip6tables_path() {
        cleanup_with(&path, profile);
    }
    release_ipv6_sysctls(profile);
}

/// Remove EVERY qeli-managed NAT rule (`qeli-nat:*`, any profile). Called once at
/// worker startup so rules left behind by a profile that has since been REMOVED
/// from the config — whose own [`cleanup`] is never called again — don't leak
/// forever. Active profiles re-install their rules immediately afterwards.
pub fn cleanup_all() {
    if let Some(path) = iptables_path() {
        cleanup_matching(&path, "qeli-nat:", false);
    }
    if let Some(path) = ip6tables_path() {
        cleanup_matching(&path, "qeli-nat:", false);
    }
}

fn cleanup_with(path: &str, profile: &str) {
    // EXACT tag match: the per-profile teardown must delete only THIS profile's rules.
    // A substring match (the old behaviour) made `qeli-nat:web` match `qeli-nat:web2`, so
    // starting/stopping profile `web` silently wiped profile `web2`'s MASQUERADE/FORWARD/
    // MSS rules and broke its egress until it restarted. Both names are valid idents. (M1)
    cleanup_matching(path, &tag(profile), true);
}

/// The iptables comment on a rule (the token right after `--comment`, dequoted). `None`
/// when the rule carries no comment.
fn rule_comment(line: &str) -> Option<String> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.windows(2)
        .find(|w| w[0] == "--comment")
        .map(|w| w[1].trim_matches('"').to_string())
}

/// Delete every managed rule whose iptables comment matches `needle`. With `exact`, the
/// comment must equal `needle` (a specific `qeli-nat:<profile>` tag); without it, the
/// comment must START WITH `needle` (the bare `qeli-nat:` prefix used by `cleanup_all`).
/// The comment is our own tag — no wire input — but we still match the parsed token, not a
/// raw substring, so one profile name can never be a prefix of another's rules. (M1)
fn cleanup_matching(path: &str, needle: &str, exact: bool) {
    for (table, chain) in [
        ("nat", "POSTROUTING"),
        // `nat/PREROUTING` holds the `dns.port` REDIRECT installed by `enable_dns_redirect`,
        // and it was missing from this list — so that rule was never removed by ANYTHING:
        // not a profile stop, not `cleanup_all()` at worker startup, not shutdown. Every
        // restart appended another copy, and a profile that changed `dns.port` (or turned DNS
        // off) left a rule still redirecting :53 to a port nothing listens on any more.
        // (Audit 2026-08-01, follow-up to §5.)
        ("nat", "PREROUTING"),
        // DNS proxy traffic terminates on the host rather than traversing FORWARD.
        // `enable_dns_input` tags its narrow per-profile permits exactly like NAT rules,
        // so profile teardown and startup recovery must remove those from INPUT too.
        ("filter", "INPUT"),
        ("filter", "FORWARD"),
        ("mangle", "FORWARD"),
    ] {
        // List the chain, find a tagged rule, delete it by replaying its own spec
        // with -D, and re-list (positions shift). Capped to avoid spinning.
        for _ in 0..64 {
            let out = match ipt(path, &["-t", table, "-S", chain]) {
                Ok(o) if o.status.success() => o,
                _ => break,
            };
            let listing = String::from_utf8_lossy(&out.stdout);
            let Some(line) = listing.lines().find(|l| {
                l.starts_with("-A ")
                    && rule_comment(l).is_some_and(|c| {
                        if exact {
                            c == needle
                        } else {
                            c.starts_with(needle)
                        }
                    })
            }) else {
                break;
            };
            // "-A CHAIN <spec...>" -> "iptables -t table -D CHAIN <spec...>".
            // Strip the quotes iptables-save puts around the comment value.
            let spec: Vec<String> = line
                .split_whitespace()
                .skip(2)
                .map(|t| t.trim_matches('"').to_string())
                .collect();
            let mut args: Vec<String> = vec!["-t".into(), table.into(), "-D".into(), chain.into()];
            args.extend(spec);
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            if ipt(path, &argv)
                .map(|o| !o.status.success())
                .unwrap_or(true)
            {
                break; // delete failed — don't loop forever
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        chain_policy_from_output, dns_input_rule, ipv6_off_rules, ipv6_rules, resolve_wan_ipv6,
        rule_comment, tag,
    };
    use crate::config::server::Ipv6RoutingMode;

    fn has_sequence(args: &[String], expected: &[&str]) -> bool {
        args.windows(expected.len()).any(|window| {
            window
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        })
    }

    #[test]
    fn ipv6_off_is_an_essential_non_tun_egress_drop() {
        let rules = ipv6_off_rules("isolated", "qeli6");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert!(rule.essential);
        assert_eq!(rule.table, "filter");
        assert_eq!(rule.chain, "FORWARD");
        assert!(has_sequence(
            &rule.args,
            &["-i", "qeli6", "!", "-o", "qeli6"]
        ));
        // The boundary is the authenticated profile TUN, not only its address pool.
        // A client may legitimately source traffic from an operator-approved
        // `client_subnet`; mode=off must keep that routed prefix from inheriting host-wide
        // forwarding just as strictly as a pool address.
        assert!(!rule.args.iter().any(|value| value == "-s"));
        assert!(has_sequence(&rule.args, &["-j", "DROP"]));
        assert!(!rule.args.iter().any(|value| value == "ACCEPT"));
    }

    #[test]
    fn routed_ipv6_opens_only_the_profiles_delegated_prefix_inbound() {
        let rules = ipv6_rules(
            "routed",
            "wan6",
            "qeli6",
            "2001:db8:42::/64",
            1340,
            Ipv6RoutingMode::Route,
        );
        assert!(!rules.iter().any(|rule| rule.table == "nat"));
        let inbound = rules
            .iter()
            .find(|rule| has_sequence(&rule.args, &["-i", "wan6", "-o", "qeli6"]))
            .expect("route mode needs an inbound WAN permit");
        assert!(has_sequence(&inbound.args, &["-d", "2001:db8:42::/64"]));
        assert!(has_sequence(&inbound.args, &["-j", "ACCEPT"]));
        assert!(!inbound.args.iter().any(|value| value == "--state"));
    }

    #[test]
    fn nat66_keeps_unsolicited_inbound_closed() {
        let rules = ipv6_rules(
            "nat66",
            "wan6",
            "qeli6",
            "fd71:e1:42::/64",
            1340,
            Ipv6RoutingMode::Nat66,
        );
        assert!(rules.iter().any(|rule| {
            rule.table == "nat" && has_sequence(&rule.args, &["-j", "MASQUERADE"])
        }));
        let inbound = rules
            .iter()
            .find(|rule| has_sequence(&rule.args, &["-i", "wan6", "-o", "qeli6"]))
            .expect("NAT66 needs a return-traffic permit");
        assert!(has_sequence(
            &inbound.args,
            &["--state", "RELATED,ESTABLISHED"]
        ));
        assert!(!inbound.args.iter().any(|value| value == "-d"));
    }

    #[test]
    fn firewall_policy_parser_accepts_only_the_exact_requested_chain_line() {
        let listing = b"-P INPUT DROP\n-P FORWARD ACCEPT\n-A FORWARD -j DROP\n";
        let forward = chain_policy_from_output(listing, "FORWARD").unwrap();
        assert_eq!(forward.policy, "ACCEPT");
        assert!(!forward.unconditionally_accepts);
        let input = chain_policy_from_output(listing, "INPUT").unwrap();
        assert_eq!(input.policy, "DROP");
        assert!(!input.unconditionally_accepts);
        assert!(
            chain_policy_from_output(b"-P FORWARD ACCEPT\n", "FORWARD")
                .unwrap()
                .unconditionally_accepts
        );
        assert_eq!(
            chain_policy_from_output(b"-P OUTPUT ACCEPT\n", "INPUT"),
            None
        );
        assert_eq!(
            chain_policy_from_output(b"-P FORWARD ACCEPT unexpected\n", "FORWARD"),
            None
        );
    }

    #[test]
    fn explicit_eth0_is_not_reinterpreted_as_ipv6_auto_detection() {
        assert_eq!(resolve_wan_ipv6("eth0").as_deref(), Some("eth0"));
        assert_eq!(resolve_wan_ipv6("  eth0  ").as_deref(), Some("eth0"));
    }

    /// Reproduce the substring bug: `web`'s exact tag must NOT match `web2`'s rule, or
    /// tearing down `web` wipes `web2`'s NAT and breaks its egress. (M1)
    #[test]
    fn exact_tag_does_not_match_a_sibling_prefix() {
        let web = tag("web"); // "qeli-nat:web"
        let web2 = tag("web2"); // "qeli-nat:web2"
        let line_web2 =
            format!("-A POSTROUTING -o qeli0 -m comment --comment {web2} -j MASQUERADE");
        let c = rule_comment(&line_web2).unwrap();
        assert_eq!(c, web2);
        assert_ne!(c, web, "exact match must distinguish web from web2");
        assert!(
            c.starts_with(&web),
            "the substring bug: web2 DOES start with web"
        );
        // The prefix form (cleanup_all) intentionally matches both.
        assert!(c.starts_with("qeli-nat:"));
    }

    #[test]
    fn rule_comment_handles_quoted_and_bare() {
        let bare = "-A FORWARD -o t -m comment --comment qeli-nat:us -j ACCEPT";
        assert_eq!(rule_comment(bare).as_deref(), Some("qeli-nat:us"));
        let quoted = "-A FORWARD -o t -m comment --comment \"qeli-nat:us\" -j ACCEPT";
        assert_eq!(rule_comment(quoted).as_deref(), Some("qeli-nat:us"));
        let none = "-A FORWARD -o t -j ACCEPT";
        assert_eq!(rule_comment(none), None);
    }

    #[test]
    fn dns_input_rule_is_scoped_to_one_profile_resolver() {
        assert_eq!(
            dns_input_rule("udp-obfs", "vpn8", "10.9.8.0/24", "10.9.8.1", 53, "udp"),
            [
                "-i",
                "vpn8",
                "-s",
                "10.9.8.0/24",
                "-p",
                "udp",
                "-d",
                "10.9.8.1",
                "--dport",
                "53",
                "-m",
                "comment",
                "--comment",
                "qeli-nat:udp-obfs",
                "-j",
                "ACCEPT",
            ]
        );
    }
}
