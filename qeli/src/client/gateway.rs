//! Gateway / router NAT (Linux / **`iptables` CLI only**, same backend as
//! `server/nat.rs` and the kill-switch).
//!
//! When `routing.gateway_nat = true`, a client acting as a router programs the
//! firewall so a LAN *behind* it reaches the internet through the tunnel, without
//! any manual `iptables`:
//!   * `net.ipv4.ip_forward = 1` (+ relaxed `rp_filter` for the asymmetric
//!     LAN↔tun path);
//!   * `MASQUERADE` everything (or just `lan_subnet`) out the tun device — so the
//!     LAN's private source becomes the tunnel IP the server's own NAT understands;
//!   * a `FORWARD` accept both ways and a TCP **MSS-clamp** (without it the pings
//!     pass but TCP/HTTPS stalls — the tunnel MTU is below 1500).
//!
//! All rules carry a `qeli-gw-nat` comment, are verified with `iptables -C`
//! (the `iptables-nft` wrapper lies via exit codes — same lesson as the
//! kill-switch and `server/nat.rs`), and are idempotent.
//!
//! LIFECYCLE: [`engage`] runs once before the connect loop and stays up across
//! reconnects (the rules are by interface name, so a recreated `tun` keeps them);
//! [`disengage`] removes them on a clean stop. A crash leaves them in place
//! (fail-safe) — clear manually with the commands logged on engage.

use super::killswitch::{ipt, ipt_path, present, present_checked, valid_ifname};

/// Comment tag on every rule we own, so teardown removes exactly ours.
const TAG: &str = "qeli-gw-nat";

/// Best-effort write to a `/proc/sys` knob. Returns whether the write succeeded
/// (a missing/read-only path in a restricted container yields `false`). Not fatal
/// on its own, but the caller warns for a knob that actually matters (ip_forward),
/// so a silently-unforwarded LAN doesn't look like a working gateway.
fn write_sysctl_raw(path: &str, val: &str) -> bool {
    std::fs::write(path, val).is_ok()
}

fn set_sysctl(path: &str, val: &str) -> bool {
    // A read-only container may already have the required value. In that case
    // no write (and no later restoration) is necessary.
    if std::fs::read_to_string(path).is_ok_and(|current| current.trim() == val) {
        return true;
    }
    // Record the host's PRIOR value before overwriting it. Doing this inside the writer
    // makes the ordering structural: the previous code snapshotted separately, after the
    // writes had already happened, so it captured our own values and `disengage` then
    // "restored" ip_forward=1 / rp_filter=0 — permanently turning a workstation into a
    // router with anti-spoofing disabled. With the snapshot bound to the write, that
    // mistake is no longer expressible.
    remember_prior(path);
    std::fs::write(path, val).is_ok()
}

/// First-write-wins snapshot of one knob. Called only from [`set_sysctl`]; a reconnect
/// re-enters `engage` and must NOT overwrite the pristine value with our own.
fn remember_prior(path: &str) {
    let Ok(current) = std::fs::read_to_string(path) else {
        return; // knob absent (container / older kernel) — nothing to restore later
    };
    let mut g = PRIOR_SYSCTLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let prior = g.get_or_insert_with(Vec::new);
    if !prior.iter().any(|(p, _)| p == path) {
        prior.push((path.to_string(), current.trim().to_string()));
    }
}

/// Should the gateway firewall run for this config? True for NAT (`gateway_nat`) OR
/// pure L3 forwarding (`forward`, #13). [`engage`]'s `masquerade` arg picks which.
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.gateway_nat || routing.forward
}

// ── exit-node (this client is an internet EXIT for other tunnel clients) ──────
//
// The MIRROR of `gateway_nat`. gateway_nat masquerades a LAN *behind* this client OUT
// THE TUN (into the tunnel); exit_node masquerades traffic that arrived FROM the tunnel
// OUT THE PHYSICAL WAN (into this host's own internet). Chain:
//   consumer client --tunnel--> server --(client_to_client)--> THIS client --WAN--> net
// so remote clients reach the internet under THIS host's public IP (e.g. a grey/NAT'd
// residential line). The server side of the chain is `client_to_client` on the profile
// plus the exit user's `client_subnet` (0.0.0.0/0) — see the server config; this module
// is only the last hop's forward+NAT.
//
// Scoping is by PACKET MARK, not by source subnet: the pool CIDR is not known until
// after auth, but exit rules install before the connect loop (like gateway_nat). We mark
// packets forwarded tun->wan in mangle/FORWARD and MASQUERADE only those in
// nat/POSTROUTING — so locally-generated traffic (OUTPUT->POSTROUTING, never marked) is
// left alone, and no pool knowledge is needed. The nfmark persists FORWARD->POSTROUTING
// on the same skb. Masked (`0x51/0x51`) so it coexists with any other fwmark user.
const EXIT_TAG: &str = "qeli-exit-node";
const EXIT_MARK: &str = "0x51/0x51";

/// WAN interface used at [`engage_exit`], so [`disengage_exit`] removes exactly the rule
/// it added even if the default route changed meanwhile (a re-detect could differ).
static EXIT_WAN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Extract the token following `dev` in an `ip route` line.
fn dev_token(s: &str) -> Option<String> {
    let toks: Vec<&str> = s.split_whitespace().collect();
    toks.iter()
        .position(|&t| t == "dev")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.to_string())
}

/// Detect the WAN (default-route) interface. `None` if there is no default route — an
/// exit node with no internet path has nothing to share.
///
/// Asks the ROUTING TABLE for the default route first, and only falls back to probing a
/// well-known address. The probe alone was wrong on any host that routes that specific
/// address differently — a Pi-hole or corporate resolver at 1.1.1.1 reached over a
/// management interface, or a blackhole entry for it. `MASQUERADE` and the `MARK` rule
/// were then installed on the WRONG interface: tunnel traffic left with a private source
/// address, the return path was a black hole, and the log still said "Exit-node engaged".
/// (Audit 2026-07-27, R4.)
fn detect_wan() -> Option<String> {
    // 1. The default route itself. `ip route show default` prints e.g.
    //    "default via 10.0.0.1 dev eth0 proto dhcp metric 100"; with several defaults the
    //    first line is the lowest-metric one, which is what the kernel would pick.
    if let Ok(out) = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(dev) = s.lines().find_map(dev_token) {
                return Some(dev);
            }
        }
    }
    // 2. Fallback: ask the kernel which interface it would use for a public address.
    //    Kept because it also resolves policy-routing setups that `show default` misses.
    let out = std::process::Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // "1.1.1.1 via 10.0.0.1 dev eth0 src ..." — the token after "dev".
    dev_token(&String::from_utf8_lossy(&out.stdout))
}

fn exit_mark_rule<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        tun_if,
        "-o",
        wan_if,
        "-j",
        "MARK",
        "--set-xmark",
        EXIT_MARK,
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_masq_rule(wan_if: &str) -> Vec<&str> {
    vec![
        "-o",
        wan_if,
        "-m",
        "mark",
        "--mark",
        EXIT_MARK,
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_fwd_out<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        tun_if,
        "-o",
        wan_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_fwd_in<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        wan_if,
        "-o",
        tun_if,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

/// MSS-clamp SYNs entering the small-MTU tunnel (the SYN-ACK returning to the consumer).
/// The consumer's own forward SYN already carries a small MSS from its own tun clamp, so
/// this side covers the return leg — without it TCP/HTTPS through the exit stalls.
fn exit_mss(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

/// Program this host as an internet exit for other tunnel clients: `ip_forward`, a
/// MASQUERADE of tun-forwarded traffic out the WAN, a FORWARD accept both ways, and an
/// MSS-clamp. Idempotent; installs by interface name so it survives reconnects (rules
/// stay while the tun is recreated), and is removed on a clean stop by [`disengage_exit`].
/// Relax `rp_filter` on the tunnel interface, once it EXISTS.
///
/// `engage` / `engage_exit` run before the connect loop, i.e. before `setup_tunnel` has
/// created the TUN — so their per-interface write to
/// `/proc/sys/net/ipv4/conf/<tun>/rp_filter` hit a path that did not exist yet,
/// `remember_prior` bailed on the read, the write failed and `set_sysctl` returned false
/// into a discarded result. The knob was therefore NEVER applied, and neither function is
/// replayed (they are documented as staying up across reconnects).
///
/// That matters because the kernel evaluates reverse-path filtering as
/// `max(conf/all, conf/<incoming-iface>)`: setting `conf/all` to 0 does not help while
/// the tun inherits `conf/default` = 1, which is the norm on many distributions. Strict
/// RPF on the tun then drops exactly the asymmetric paths gateway-NAT and exit-node
/// exist to carry, while the log cheerfully reported the feature engaged.
///
/// Called from `setup_tunnel` after the interface is up, on every connect.
/// (Audit 2026-07-27, R1.)
pub fn apply_tun_rp_filter(tun_if: &str) {
    if !set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0") {
        log::warn!(
            "could not relax rp_filter on {tun_if} — asymmetric paths (gateway-NAT /              exit-node) may be dropped by reverse-path filtering"
        );
    }
}

pub fn engage_exit(tun_if: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node: invalid TUN interface name {tun_if:?}");
    }
    let wan = detect_wan().ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node: no default route found — cannot determine the WAN interface to NAT \
             out of. An exit node needs its own working internet path to share."
        )
    })?;
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node: detected WAN interface name {wan:?} is invalid");
    }
    // Publish the exact interface before the first fallible/mutating step. If a
    // later rule or sysctl fails, the caller's rollback must not depend on the
    // default route still being detectable at teardown time.
    *EXIT_WAN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(wan.clone());
    let path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("exit-node: `iptables` is not installed (apt install iptables)")
    })?;

    // ip_forward is load-bearing (same as gateway_nat); rp_filter relaxed for the
    // asymmetric tun<->wan path. Each snapshots its prior value (remember_prior) so
    // disengage restores it — these are HOST-wide knobs, not ours to leave changed.
    if !set_sysctl("/proc/sys/net/ipv4/ip_forward", "1") {
        anyhow::bail!(
            "exit-node: cannot enable net.ipv4.ip_forward; refusing to report an exit node \
             that cannot forward traffic (enable it on the host first)"
        );
    }
    set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{wan}/rp_filter"), "0");

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        let mut c: Vec<&str> = vec!["-t", table, "-C", chain];
        c.extend_from_slice(rule);
        if !present(&path, &c) {
            let mut a: Vec<&str> = vec!["-t", table, "-A", chain];
            a.extend_from_slice(rule);
            let _ = ipt(&path, &a);
        }
        present(&path, &c)
    };

    // MARK + MASQUERADE are both essential — without either, tunnel traffic reaches the
    // WAN with a private source and the return path is black-holed.
    if !ensure("mangle", "FORWARD", &exit_mark_rule(tun_if, &wan)) {
        anyhow::bail!("exit-node: could not install the tun->wan MARK rule (mangle FORWARD)");
    }
    if !ensure("nat", "POSTROUTING", &exit_masq_rule(&wan)) {
        anyhow::bail!("exit-node: could not install MASQUERADE out {wan} (nat POSTROUTING)");
    }
    // FORWARD accepts are best-effort — when the FORWARD policy is already ACCEPT they are
    // redundant, and on iptables-nft hosts the legacy filter chain can be incompatible.
    let fwd_ok = ensure("filter", "FORWARD", &exit_fwd_out(tun_if, &wan))
        & ensure("filter", "FORWARD", &exit_fwd_in(tun_if, &wan));
    ensure("mangle", "FORWARD", &exit_mss(tun_if));

    if !fwd_ok {
        log::warn!(
            "exit-node: FORWARD accept rules not installed (legacy/nft filter conflict?) — \
             relying on the FORWARD policy being ACCEPT. If forwarding fails, permit \
             {tun_if}<->{wan} yourself."
        );
    }
    log::warn!(
        "Exit-node engaged: MASQUERADE tunnel traffic out {wan} (+forward +mss-clamp, \
         ip_forward=1). Remote clients now reach the internet under THIS host's IP. The \
         server must set client_to_client + this user's client_subnet = 0.0.0.0/0. Stays up \
         across reconnects, removed on a clean stop; a crash leaves it — clear rules tagged \
         `{EXIT_TAG}`."
    );
    Ok(())
}

fn remove_rule(path: &str, table: &str, chain: &str, rule: &[&str]) -> anyhow::Result<()> {
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    for _ in 0..8 {
        if !present_checked(path, &check)? {
            return Ok(());
        }
        let mut delete: Vec<&str> = vec!["-t", table, "-D", chain];
        delete.extend_from_slice(rule);
        ipt(path, &delete).map_err(|error| {
            anyhow::anyhow!(
                "cannot run {} {} while removing qeli firewall state: {}",
                path,
                delete.join(" "),
                error
            )
        })?;
    }
    if present_checked(path, &check)? {
        anyhow::bail!(
            "{} rule remains after 8 deletion attempts: {}",
            table,
            rule.join(" ")
        );
    }
    Ok(())
}

/// Remove every `qeli-exit-node` rule. A missing rule is an idempotent success;
/// failures are returned so the caller cannot report a clean host restoration.
pub fn disengage_exit(tun_if: &str) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    let wan = EXIT_WAN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .or_else(detect_wan);
    let Some(path) = ipt_path("iptables") else {
        if let Err(error) = restore_sysctls() {
            errors.push(error.to_string());
        }
        anyhow::bail!(
            "exit-node cleanup: `iptables` is unavailable; rules tagged `{EXIT_TAG}` may remain{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!("; {}", errors.join("; "))
            }
        );
    };
    let Some(wan) = wan else {
        if let Err(error) = restore_sysctls() {
            errors.push(error.to_string());
        }
        anyhow::bail!(
            "exit-node: WAN interface unknown at teardown — rules tagged `{EXIT_TAG}` may remain{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!("; {}", errors.join("; "))
            }
        );
    };
    for result in [
        remove_rule(&path, "mangle", "FORWARD", &exit_mark_rule(tun_if, &wan)),
        remove_rule(&path, "nat", "POSTROUTING", &exit_masq_rule(&wan)),
        remove_rule(&path, "filter", "FORWARD", &exit_fwd_out(tun_if, &wan)),
        remove_rule(&path, "filter", "FORWARD", &exit_fwd_in(tun_if, &wan)),
        remove_rule(&path, "mangle", "FORWARD", &exit_mss(tun_if)),
    ] {
        if let Err(error) = result {
            errors.push(error.to_string());
        }
    }
    if let Err(error) = restore_sysctls() {
        errors.push(error.to_string());
    }
    if !errors.is_empty() {
        anyhow::bail!("exit-node cleanup failed: {}", errors.join("; "))
    }
    *EXIT_WAN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    log::info!("Exit-node disengaged (WAN {wan})");
    Ok(())
}

/// The MASQUERADE rule body (optionally restricted to a source subnet), tagged.
fn masq_rule<'a>(tun_if: &'a str, lan_subnet: &'a str) -> Vec<&'a str> {
    let mut r: Vec<&str> = Vec::new();
    if !lan_subnet.is_empty() {
        r.extend_from_slice(&["-s", lan_subnet]);
    }
    r.extend_from_slice(&[
        "-o",
        tun_if,
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]);
    r
}

fn fwd_out(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

fn fwd_in(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

/// Unrestricted inbound FORWARD accept (routing mode, #13): unlike [`fwd_in`], NEW
/// connections from the far side INTO the LAN are permitted — site-to-site is bidirectional,
/// there is no NAT state to gate on.
fn fwd_in_open(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

fn mss(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

/// Program `ip_forward` + a FORWARD accept + MSS-clamp so a LAN behind the client is
/// reachable through `tun_if`. With `masquerade = true` (`gateway_nat`) it also MASQUERADEs
/// the LAN out the tun (internet egress); with `masquerade = false` (`forward`, #13) there is
/// NO NAT — real source IPs are preserved (site-to-site routing) and the inbound accept is
/// unrestricted so the far side can initiate to the LAN. Idempotent. Empty `lan_subnet`
/// masquerades everything leaving the tun.
pub fn engage(tun_if: &str, lan_subnet: &str, masquerade: bool) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway-nat: invalid TUN interface name {tun_if:?}");
    }
    let path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("gateway-nat: `iptables` is not installed (apt install iptables)")
    })?;

    // Forwarding + relaxed reverse-path filter (the LAN↔tun path is asymmetric).
    // ip_forward is load-bearing: without it the LAN is silently un-forwarded even
    // though the iptables rules land, so setup must fail instead of reporting success.
    if !set_sysctl("/proc/sys/net/ipv4/ip_forward", "1") {
        anyhow::bail!(
            "gateway-nat: cannot enable net.ipv4.ip_forward; refusing to report a gateway \
             that cannot forward traffic (enable it on the host first)"
        );
    }
    // rp_filter stays best-effort (relaxing it only avoids drops on the asymmetric path).
    set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0");
    // (Each set_sysctl snapshots the prior value itself — see remember_prior. These are
    // HOST-wide knobs: leaving ip_forward on turns a workstation into a router after the
    // VPN stops, and a relaxed rp_filter keeps an anti-spoofing check disabled — neither
    // is ours to change permanently.)

    // Append a rule iff absent, then confirm it actually landed.
    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        let mut c: Vec<&str> = vec!["-t", table, "-C", chain];
        c.extend_from_slice(rule);
        if !present(&path, &c) {
            let mut a: Vec<&str> = vec!["-t", table, "-A", chain];
            a.extend_from_slice(rule);
            let _ = ipt(&path, &a); // exit code unreliable — verify below
        }
        present(&path, &c)
    };

    // MASQUERADE only in NAT mode (essential there — the LAN can't reach the internet
    // without it). Routing mode (#13) preserves real source IPs, so no MASQUERADE.
    if masquerade && !ensure("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet)) {
        anyhow::bail!("gateway-nat: could not install MASQUERADE on {tun_if}");
    }
    // FORWARD accept is best-effort: on `iptables-nft` hosts the legacy `filter` FORWARD
    // chain can be incompatible (same as `server/nat.rs`); when the FORWARD policy is
    // already ACCEPT, forwarding works regardless. Inbound is ESTABLISHED-only under NAT
    // (return traffic) but UNRESTRICTED for routing (the far side may initiate to the LAN).
    let fwd_ok = ensure("filter", "FORWARD", &fwd_out(tun_if))
        & if masquerade {
            ensure("filter", "FORWARD", &fwd_in(tun_if))
        } else {
            ensure("filter", "FORWARD", &fwd_in_open(tun_if))
        };
    ensure("mangle", "FORWARD", &mss(tun_if));

    if !fwd_ok {
        log::warn!(
            "gateway: FORWARD accept rules not installed (legacy/nft filter conflict?) — \
             relying on the FORWARD policy being ACCEPT. If forwarding fails, permit \
             {tun_if}<->LAN yourself."
        );
    }
    if masquerade {
        log::warn!(
            "Gateway-NAT engaged: MASQUERADE {} out {tun_if} (+forward +mss-clamp, ip_forward=1). \
             Stays up across reconnects, removed on a clean stop; a crash leaves it — clear \
             rules tagged `{TAG}`.",
            if lan_subnet.is_empty() {
                "all".to_string()
            } else {
                format!("-s {lan_subnet}")
            }
        );
    } else {
        log::warn!(
            "Gateway forwarding engaged: routing tun<->LAN through {tun_if} WITHOUT NAT \
             (+mss-clamp, ip_forward=1). The far side needs a route back to this LAN (the \
             server's client_subnets for this user). Removed on a clean stop; a crash leaves \
             it — clear rules tagged `{TAG}`."
        );
    }
    Ok(())
}

/// Remove every `qeli-gw-nat` rule for `tun_if`/`lan_subnet`. A missing rule is an
/// idempotent success; failures are returned so clean shutdown remains truthful.
pub fn disengage(tun_if: &str, lan_subnet: &str) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    if let Some(path) = ipt_path("iptables") {
        for result in [
            remove_rule(&path, "nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet)),
            remove_rule(&path, "filter", "FORWARD", &fwd_out(tun_if)),
            remove_rule(&path, "filter", "FORWARD", &fwd_in(tun_if)),
            remove_rule(&path, "filter", "FORWARD", &fwd_in_open(tun_if)),
            remove_rule(&path, "mangle", "FORWARD", &mss(tun_if)),
        ] {
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
    } else {
        errors
            .push("gateway cleanup: `iptables` is unavailable; qeli rules may remain".to_string());
    }
    if let Err(error) = restore_sysctls() {
        errors.push(error.to_string());
    }
    if !errors.is_empty() {
        anyhow::bail!("gateway cleanup failed: {}", errors.join("; "))
    }
    log::info!("Gateway-NAT disengaged on {tun_if}");
    Ok(())
}

/// Host sysctl values as they were before `engage` touched them, so `disengage` can put
/// them back. Recorded per path by [`remember_prior`] on the first write (a reconnect
/// re-enters `engage` and must not overwrite the pristine values with our own); a knob we
/// could not read is simply not recorded, since there is nothing to restore.
static PRIOR_SYSCTLS: std::sync::Mutex<Option<Vec<(String, String)>>> = std::sync::Mutex::new(None);

fn restore_sysctls() -> anyhow::Result<()> {
    let mut g = PRIOR_SYSCTLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(prior) = g.take() else {
        return Ok(());
    };
    let mut failed = Vec::new();
    for (path, value) in prior {
        // RAW write: going through set_sysctl would re-record the value we are about to
        // replace (i.e. our own), so the next engage would treat it as the pristine one.
        if !write_sysctl_raw(&path, &value) {
            failed.push((path, value));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        let detail = failed
            .iter()
            .map(|(path, value)| format!("{path}={value:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        // Keep the failed entries so another in-process cleanup attempt can retry them.
        *g = Some(failed);
        anyhow::bail!("could not restore host sysctl value(s): {detail}")
    }
}
