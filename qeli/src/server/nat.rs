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
//! work without them) and BEST-EFFORT (the explicit `FORWARD … ACCEPT` rules, only
//! needed when the host's FORWARD policy is DROP). Because the modern `iptables-nft`
//! wrapper can return success while silently no-op'ing on a chain backed by a legacy
//! table, we VERIFY each rule with `iptables -C` rather than trusting the exit code:
//! an essential rule that won't apply fails the setup; a best-effort one only logs a
//! warning (MASQUERADE alone still routes when the FORWARD policy is ACCEPT).

use std::process::Command;

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
fn enable_ip_forward() {
    let path = "/proc/sys/net/ipv4/ip_forward";
    if matches!(std::fs::read_to_string(path), Ok(ref v) if v.trim() == "1") {
        return; // already on
    }
    match std::fs::write(path, "1\n") {
        Ok(()) => log::info!("NAT: enabled net.ipv4.ip_forward (left enabled on teardown)"),
        Err(e) => log::warn!(
            "NAT: could not enable net.ipv4.ip_forward ({e}); full-tunnel egress may not route"
        ),
    }
}

/// One iptables rule we manage. `essential = false` rules (FORWARD ACCEPT) are
/// best-effort: a host where they can't be applied still routes if its FORWARD
/// policy is ACCEPT.
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
        // BEST-EFFORT — explicitly permit forwarding tun <-> wan (needed only when the
        // FORWARD policy is DROP).
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
    let iface = configured_iface.trim();
    let wan = if !iface.is_empty() && iface != "eth0" {
        iface.to_string()
    } else {
        detect_wan().ok_or_else(|| {
            anyhow::anyhow!(
                "could not auto-detect the WAN interface; set routing.nat.interface explicitly"
            )
        })?
    };

    enable_ip_forward();
    // Clear any stale copies first so a re-apply can't stack duplicates.
    cleanup_with(&path, profile);

    let mss = (mtu - 40).max(536);
    let mut forward_unapplied = false;
    for r in rules(profile, &wan, tun, pool_cidr, mss) {
        let mut args: Vec<String> = vec!["-t".into(), r.table.into(), "-A".into(), r.chain.into()];
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
        log::warn!(
            "Profile '{profile}': FORWARD ACCEPT rules could not be applied (host has a mixed \
             legacy/nft filter table). NAT egress still works when the FORWARD policy is ACCEPT; \
             if it is DROP, permit forwarding {pool_cidr} <-> {wan} yourself."
        );
    }
    Ok(wan)
}

/// Remove every NAT rule tagged for `profile` (idempotent; a no-op if none exist or
/// iptables is absent).
pub fn cleanup(profile: &str) {
    if let Some(path) = iptables_path() {
        cleanup_with(&path, profile);
    }
}

/// Remove EVERY qeli-managed NAT rule (`qeli-nat:*`, any profile). Called once at
/// worker startup so rules left behind by a profile that has since been REMOVED
/// from the config — whose own [`cleanup`] is never called again — don't leak
/// forever. Active profiles re-install their rules immediately afterwards.
pub fn cleanup_all() {
    if let Some(path) = iptables_path() {
        cleanup_matching(&path, "qeli-nat:");
    }
}

fn cleanup_with(path: &str, profile: &str) {
    cleanup_matching(path, &tag(profile));
}

/// Delete every managed rule whose iptables comment CONTAINS `needle` — either a
/// specific `qeli-nat:<profile>` tag or the bare `qeli-nat:` prefix (all profiles).
fn cleanup_matching(path: &str, needle: &str) {
    for (table, chain) in [
        ("nat", "POSTROUTING"),
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
            let Some(line) = listing
                .lines()
                .find(|l| l.starts_with("-A ") && l.contains(needle))
            else {
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
