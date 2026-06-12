//! Firewall kill-switch (Linux / nftables).
//!
//! While engaged, ALL egress is dropped except: loopback, traffic out the VPN tun
//! device, DHCP (physical-link renew), DNS (so a hostname server can be resolved —
//! see the trade-off below), and traffic to the VPN server's resolved IP(s). So
//! when the tunnel drops, nothing of substance leaks onto the physical interface
//! during the reconnect window — closing the classic "real IP exposed between
//! reconnects" hole.
//!
//! DNS TRADE-OFF: port 53 is allowed so the client can resolve a *hostname* server
//! address (otherwise the very first connect — which re-resolves the name with the
//! drop policy active — would fail). The residual leak is only DNS metadata on the
//! physical link while the tunnel is down; the actual data plane (your traffic and
//! real IP to arbitrary sites) stays fully blocked. Use an IP server address to
//! avoid even that.
//!
//! FAIL-SAFE LIFECYCLE — this is the whole point, read carefully:
//!   * [`engage`] installs an `inet qeli_ks` table and is idempotent (it replaces
//!     any existing one atomically). It is installed ONCE, before the connect loop,
//!     and deliberately stays up across every reconnect.
//!   * [`disengage`] removes the table and is called only on a CLEAN stop
//!     (user disconnect / SIGINT / SIGTERM / loop exit).
//!   * A crashed run (SIGKILL / panic / power loss) leaves the table in place — the
//!     machine stays locked (no leak) until qeli runs again, which `engage`
//!     replaces it. To unlock without reconnecting: `sudo nft delete table inet
//!     qeli_ks`.
//!
//! Only meaningful in full-tunnel mode (in split-tunnel the dropped "everything
//! else" is exactly the traffic that is supposed to go direct), so the caller
//! gates on that.

use std::io::Write;
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};

const TABLE: &str = "qeli_ks";

/// Resolve `server_addr:port` to the set of IPs the kill-switch must allow through
/// (so the tunnel can (re)connect). Returns string IPs (v4 and v6).
fn resolve_ips(server_addr: &str, server_port: u16) -> Vec<String> {
    // A bare IP resolves to itself; a hostname resolves via the system resolver
    // (which still works here — we resolve BEFORE engaging the drop policy).
    match (server_addr, server_port).to_socket_addrs() {
        Ok(addrs) => {
            let mut ips: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Err(_) => Vec::new(),
    }
}

/// Feed an nft script to `nft -f -` (one atomic transaction). Returns an error
/// with stderr if nft is missing or the ruleset is rejected.
fn run_nft(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!("kill-switch: cannot run nft ({e}); is nftables installed?")
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("kill-switch: no nft stdin"))?
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "kill-switch: nft rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// True for a syntactically valid Linux interface name (≤ IFNAMSIZ-1 = 15,
/// `[A-Za-z0-9_-]`). `tun_if` is interpolated into the nft ruleset, so reject
/// anything that could inject nft syntax — defence-in-depth, the name is from
/// trusted config (H-3).
fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Engage the kill-switch: allow only loopback, `tun_if`, DHCP, and the server
/// IP(s). Idempotent — replaces any existing `qeli_ks` table atomically.
pub fn engage(server_addr: &str, server_port: u16, tun_if: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("kill-switch: invalid TUN interface name {tun_if:?}");
    }
    let ips = resolve_ips(server_addr, server_port);
    if ips.is_empty() {
        anyhow::bail!(
            "kill-switch NOT engaged: cannot resolve server '{}' to an IP to allow through \
             (refusing to lock the host out with no path to the server)",
            server_addr
        );
    }

    let mut script = String::new();
    // `add; delete; add` gives a clean slate whether or not the table pre-existed
    // (a leftover from a crashed run, or a live one from this run).
    script.push_str(&format!("add table inet {TABLE}\n"));
    script.push_str(&format!("delete table inet {TABLE}\n"));
    script.push_str(&format!("add table inet {TABLE}\n"));
    script.push_str(&format!(
        "add chain inet {TABLE} output {{ type filter hook output priority 0; policy drop; }}\n"
    ));
    script.push_str(&format!(
        "add rule inet {TABLE} output oifname \"lo\" accept\n"
    ));
    script.push_str(&format!(
        "add rule inet {TABLE} output oifname \"{tun_if}\" accept\n"
    ));
    // DHCP client → server, so the physical lease can renew while locked.
    script.push_str(&format!(
        "add rule inet {TABLE} output udp dport 67 accept\n"
    ));
    // DNS, so a hostname server can be (re)resolved during a reconnect (the data
    // plane stays blocked; only DNS metadata can transit — see the module docs).
    script.push_str(&format!(
        "add rule inet {TABLE} output udp dport 53 accept\n"
    ));
    script.push_str(&format!(
        "add rule inet {TABLE} output tcp dport 53 accept\n"
    ));
    for ip in &ips {
        // Reformat from a parsed IpAddr so only a canonical address literal can
        // reach the nft script, even if resolution ever yields an odd string (H-3).
        match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(a)) => {
                script.push_str(&format!(
                    "add rule inet {TABLE} output ip6 daddr {a} accept\n"
                ));
            }
            Ok(std::net::IpAddr::V4(a)) => {
                script.push_str(&format!(
                    "add rule inet {TABLE} output ip daddr {a} accept\n"
                ));
            }
            Err(_) => continue,
        }
    }
    run_nft(&script)?;
    log::warn!(
        "Kill-switch ENGAGED (nft table inet {TABLE}): egress restricted to lo, {tun_if}, DHCP, \
         and {}. It stays up across reconnects and is removed only on a clean stop; a crash \
         leaves it (no leak) — clear manually with `sudo nft delete table inet {TABLE}`.",
        ips.join(", ")
    );
    Ok(())
}

/// Remove the kill-switch table. Called only on a CLEAN stop. Best-effort: a
/// missing table (never engaged / already cleared) is not an error.
pub fn disengage() {
    // `delete table` errors if absent; swallow that so a clean stop with the
    // kill-switch off is a no-op.
    let _ = run_nft(&format!("delete table inet {TABLE}\n"));
    log::info!("Kill-switch disengaged (nft table inet {TABLE} removed if present)");
}

/// True when the kill-switch should run for this config: explicitly enabled AND
/// full-tunnel (in split-tunnel, dropping all other egress would break the traffic
/// that is meant to go direct).
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.kill_switch
        && (routing.add_default_gateway || routing.mode == "full-tunnel" || routing.mode == "all")
}
