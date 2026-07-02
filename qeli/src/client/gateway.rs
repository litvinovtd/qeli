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

use super::killswitch::{ipt, ipt_path, present, valid_ifname};

/// Comment tag on every rule we own, so teardown removes exactly ours.
const TAG: &str = "qeli-gw-nat";

/// Best-effort write to a `/proc/sys` knob. Returns whether the write succeeded
/// (a missing/read-only path in a restricted container yields `false`). Not fatal
/// on its own, but the caller warns for a knob that actually matters (ip_forward),
/// so a silently-unforwarded LAN doesn't look like a working gateway.
fn set_sysctl(path: &str, val: &str) -> bool {
    std::fs::write(path, val).is_ok()
}

/// Should gateway NAT run for this config?
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.gateway_nat
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

/// Program `ip_forward` + MASQUERADE (+ FORWARD + MSS-clamp) so a LAN behind the
/// client reaches the internet through `tun_if`. Idempotent. Empty `lan_subnet`
/// masquerades everything leaving the tun.
pub fn engage(tun_if: &str, lan_subnet: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway-nat: invalid TUN interface name {tun_if:?}");
    }
    let path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("gateway-nat: `iptables` is not installed (apt install iptables)")
    })?;

    // Forwarding + relaxed reverse-path filter (the LAN↔tun path is asymmetric).
    // ip_forward is load-bearing: without it the LAN is silently un-forwarded even
    // though the iptables rules land — warn loudly instead of pretending success.
    if !set_sysctl("/proc/sys/net/ipv4/ip_forward", "1") {
        log::warn!(
            "gateway-nat: could NOT enable net.ipv4.ip_forward (read-only /proc or a \
             restricted container?) — LAN traffic will NOT be forwarded through the tunnel. \
             Enable it on the host: `sysctl -w net.ipv4.ip_forward=1`."
        );
    }
    // rp_filter stays best-effort (relaxing it only avoids drops on the asymmetric path).
    set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0");

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

    // MASQUERADE is ESSENTIAL (the LAN can't reach the internet without it).
    let ok = ensure("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet));
    // FORWARD accept is best-effort: on `iptables-nft` hosts the legacy `filter`
    // FORWARD chain can be incompatible (same as `server/nat.rs`). When the FORWARD
    // policy is already ACCEPT, forwarding works regardless.
    let fwd_ok = ensure("filter", "FORWARD", &fwd_out(tun_if))
        & ensure("filter", "FORWARD", &fwd_in(tun_if));
    ensure("mangle", "FORWARD", &mss(tun_if));

    if !ok {
        anyhow::bail!("gateway-nat: could not install MASQUERADE on {tun_if}");
    }
    if !fwd_ok {
        log::warn!(
            "gateway-nat: FORWARD accept rules not installed (legacy/nft filter conflict?) — \
             relying on the FORWARD policy being ACCEPT. If the LAN can't reach the internet, \
             permit forwarding {tun_if}<->LAN yourself."
        );
    }
    log::warn!(
        "Gateway-NAT engaged: MASQUERADE {} out {tun_if} (+forward +mss-clamp, ip_forward=1). \
         Stays up across reconnects, removed on a clean stop; a crash leaves it — clear with \
         `iptables -t nat -D POSTROUTING …MASQUERADE` (rules tagged `{TAG}`).",
        if lan_subnet.is_empty() {
            "all".to_string()
        } else {
            format!("-s {lan_subnet}")
        }
    );
    Ok(())
}

/// Remove every `qeli-gw-nat` rule for `tun_if`/`lan_subnet`. Best-effort; a
/// missing rule is not an error. Called only on a clean stop.
pub fn disengage(tun_if: &str, lan_subnet: &str) {
    let Some(path) = ipt_path("iptables") else {
        return;
    };
    let drop = |table: &str, chain: &str, rule: &[&str]| {
        let mut c: Vec<&str> = vec!["-t", table, "-C", chain];
        c.extend_from_slice(rule);
        for _ in 0..8 {
            if present(&path, &c) {
                let mut d: Vec<&str> = vec!["-t", table, "-D", chain];
                d.extend_from_slice(rule);
                let _ = ipt(&path, &d);
            } else {
                break;
            }
        }
    };
    drop("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet));
    drop("filter", "FORWARD", &fwd_out(tun_if));
    drop("filter", "FORWARD", &fwd_in(tun_if));
    drop("mangle", "FORWARD", &mss(tun_if));
    log::info!("Gateway-NAT disengaged on {tun_if}");
}
