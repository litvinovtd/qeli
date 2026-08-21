//! Client DNS management with lifecycle-safe per-link configuration.
//!
//! The hard requirement: *never* leave the system pointing at the tunnel
//! resolver after the tunnel is gone. New connections therefore only install
//! DNS through systemd-resolved's per-link API: deleting the tunnel link also
//! deletes its DNS state after SIGKILL, power loss, or uninstall.
//!
//! The snapshot/restore code below remains deliberately supported to recover
//! systems changed by older qeli versions. New sessions never create such a
//! snapshot or write `/etc/resolv.conf` directly.

use crate::config::client::ClientDnsConfig;
use crate::transport_core::NetworkDns;
use serde::{Deserialize, Serialize};
use std::path::Path;

const RESOLV_PATH: &str = "/etc/resolv.conf";
const STATE_DIR: &str = "/var/lib/qeli";
const BACKUP_PATH: &str = "/var/lib/qeli/dns-backup.json";
/// Records the interface a `resolvectl` config was applied to, so it can be
/// reverted even on a later run.
///
/// PER-INTERFACE. A single shared path meant two clients (`vpn0` and `vpn1`) overwrote
/// each other's marker, and the first one to disconnect then reverted the OTHER's link —
/// or logged "Reverted resolvectl config on …" naming an interface it never touched. The
/// kill-switch chain and the route journal are already keyed per instance
/// (`chain_for(tun_if)`); this was the one piece of teardown state that was not.
/// (Audit 2026-07-27, R7.)
fn resolvectl_mark_path(ifname: &str) -> String {
    // `ifname` comes from config and is used in `ip`/`resolvectl` argv already; keep the
    // filename conservative regardless.
    let safe: String = ifname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(32)
        .collect();
    format!("/var/lib/qeli/dns-resolvectl-{safe}")
}
#[cfg(test)]
const MARKER: &str = "# Managed by qeli VPN — original saved in /var/lib/qeli/dns-backup.json";

/// Legacy holder set written by releases that took over `/etc/resolv.conf` directly. New
/// connections use per-link systemd-resolved state and never create this file, but recovery
/// must still honour it while an older client process may be alive.
const REFCOUNT_PATH: &str = "/var/lib/qeli/dns-holders";

/// Snapshot of `/etc/resolv.conf` before qeli touched it.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct DnsBackup {
    /// "symlink" | "file" | "absent" | "managed-no-original"
    kind: String,
    /// Link target for `kind == "symlink"`.
    target: Option<String>,
    /// File content for `kind == "file"`.
    content: Option<String>,
    /// Unix permission bits for `kind == "file"`.
    mode: Option<u32>,
}

/// Resolve the DNS part of a core `NetworkPlan` without changing host state.
/// `None` means the platform must leave the system resolver untouched: DNS is disabled,
/// or an untrusted server push was rejected by the split-tunnel reachability policy.
/// Test-only compatibility seam: production resolves the complete dual-stack list in
/// `transport_core::network` and applies it through `setup_network_plan_dns` below.
#[cfg(test)]
pub fn planned_dns_server(
    config: &ClientDnsConfig,
    pushed_server: &str,
    pushed_port: &str,
    tun_net: Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
    full_tunnel: bool,
) -> anyhow::Result<Option<NetworkDns>> {
    crate::transport_core::network::planned_dns_servers(
        config,
        pushed_server,
        pushed_port,
        tun_net,
        full_tunnel,
        &[],
    )
    .map(|servers| servers.into_iter().next())
}

/// Historical singular/IPv4 seam retained only in test builds. Production must consume the
/// authenticated dual-stack NetworkPlan instead of silently discarding an IPv6 resolver.
#[cfg(test)]
pub fn setup_dns_for_interface(
    config: &ClientDnsConfig,
    dns_server: &str,
    dns_port: &str,
    ifname: &str,
    // Tunnel address + netmask, used to check that a SERVER-PUSHED resolver is actually
    // reachable through the tunnel rather than over the physical link.
    tun_net: Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
    // Full-tunnel routes everything, so any resolver address is reachable there.
    full_tunnel: bool,
) -> anyhow::Result<()> {
    if config.mode != "tunnel" {
        return Ok(());
    }

    // Resolver precedence: the client's OWN `dns_servers` first, then whatever the server
    // pushed, then the built-in fallback.
    //
    // The client's list used to be consulted only when the push was EMPTY, which inverted
    // the rule the product works by and every other port already implements (see the C#
    // `EffectiveDns`, which logs "server push: DNS … IGNORED — this client's own dns …
    // overrides it"): a resolver the user typed into their own config is a deliberate
    // choice and outranks the server's suggestion. With the old order, setting
    // `dns_servers` on a profile whose server pushes anything at all did nothing at all,
    // silently — the operator's resolver won and the user never learned their setting was
    // ignored. `dns = off` / `system` still short-circuit above this, so "leave my resolver
    // alone" continues to beat both. (Audit 2026-08-03, D1.)
    // Track WHERE the chosen resolver came from. A resolver the user configured is their
    // decision and is applied as-is; one the SERVER pushed is only as trustworthy as the
    // server, and gets the reachability check below. (Audit 2026-08-04.)
    let mut from_server_push = false;
    let chosen;
    let fallback;
    let dns_server = if let Some(own) = config.servers.first() {
        chosen = own.clone();
        if !dns_server.is_empty() && dns_server != chosen {
            log::info!(
                "server pushed DNS {dns_server}, but this client's own dns_servers = {} \
                 overrides it (clear dns_servers to use the pushed resolver)",
                config.servers.join(", ")
            );
        }
        chosen.as_str()
    } else if dns_server.is_empty() {
        match config.fallback_servers.first() {
            Some(s) => {
                fallback = s.clone();
                log::info!("server pushed no DNS — using client resolver {}", fallback);
                fallback.as_str()
            }
            None => {
                // Refuse to silently hand the user's DNS to a third party.
                //
                // This used to default to 1.1.1.1. Someone who configured NO resolver had
                // every query sent to Cloudflare without being told — for a
                // censorship-circumvention tool that is a privacy decision the user did
                // not make, and `dns.mode = tunnel` with nothing to point at is a
                // misconfiguration worth surfacing. Failing here leaves the host's
                // existing resolver untouched. (Audit 2026-07-27, R5.)
                anyhow::bail!(
                    "dns = tunnel but the server pushed no DNS address and this client has no \
                     resolver configured — set `dns_servers = <ip>[, <ip>…]` in the client \
                     flat-INI config, or `dns = off` to keep the host's \
                     resolver. Until then the host's own resolvers stay in place, so in a \
                     full-tunnel profile DNS may go to the physical network."
                );
            }
        }
    } else {
        from_server_push = true;
        dns_server
    };

    // The DNS address is server-pushed (auth-OK JSON) and is written verbatim
    // into resolv.conf / handed to `resolvectl`. A malicious server could push
    // a bogus or option-looking value, so require a bare IP address before use;
    // on reject, leave the existing resolver untouched (safe no-op).
    if dns_server.starts_with('-') || dns_server.parse::<std::net::IpAddr>().is_err() {
        log::warn!("Ignoring invalid pushed DNS server: {}", dns_server);
        return Ok(());
    }

    // A server-pushed resolver must be REACHABLE THROUGH THE TUNNEL.
    //
    // "It parses as an IP" was the only check. In the default configuration —
    // `dns.mode = tunnel` and split-tunnel routing, both shipped defaults — the server
    // therefore chose an address that this client wrote into the host resolver, and nothing
    // routed it through the tunnel: `setup_routes` adds no route for an arbitrary external
    // address in split-tunnel mode. Every DNS query on the machine then left in cleartext
    // over the PHYSICAL interface to an address of the operator's choosing, while the log
    // said "server push: DNS <ip> APPLIED". The existing leak warning only covers the
    // opposite case (full-tunnel + dns=off), so this one was invisible.
    //
    // In full-tunnel everything goes through the tunnel, so any address is fine there.
    // Otherwise require the resolver to sit inside the tunnel subnet. A resolver the USER
    // configured is untouched by this — see `from_server_push`.
    if from_server_push && !full_tunnel {
        let reachable = tun_net
            .and_then(|(addr, mask)| {
                dns_server.parse::<std::net::Ipv4Addr>().ok().map(|d| {
                    (u32::from(d) & u32::from(mask)) == (u32::from(addr) & u32::from(mask))
                })
            })
            .unwrap_or(false);
        if !reachable {
            log::warn!(
                "REFUSING the server-pushed resolver {dns_server}: this is a split-tunnel                  profile and that address is not inside the tunnel subnet, so every DNS query                  would leave over the PHYSICAL interface in cleartext. Set `dns_servers = …`                  to choose a resolver yourself, `mode = full-tunnel` to route everything, or                  `dns = off` to keep the host's resolver."
            );
            return Ok(());
        }
    }

    let dns_addr = if dns_port == "53" {
        dns_server.to_string()
    } else {
        format!("{}#{}", dns_server, dns_port)
    };

    // Safe path: systemd-resolved — but ONLY when it is actually the system
    // resolver (resolv.conf → stub). Otherwise `resolvectl dns` "succeeds" yet has
    // no effect (glibc reads real nameservers straight from resolv.conf). Per-link
    // config is auto-dropped when the tun is deleted, so it cannot strand the host
    // on a dead resolver after an unclean exit; we still record the interface so
    // `restore` can revert explicitly on a clean stop.
    if resolved_is_active() {
        // Persist ownership BEFORE changing the link. In attach mode the interface belongs
        // to another process and survives our exit, so relying on link deletion as the only
        // rollback can strand the host on the tunnel resolver. Writing first also makes the
        // crash window safe: a marker with no applied DNS merely causes an idempotent revert.
        // The atomic/private writer fsyncs the contents and never exposes a partial marker.
        ensure_state_dir()?;
        let marker = resolvectl_mark_path(ifname);
        crate::util::write_atomic_private(&marker, ifname.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "cannot persist resolvectl ownership marker {}: {} — DNS was not changed",
                marker,
                error
            )
        })?;
        if try_resolvectl(config, ifname, &dns_addr) {
            log::info!("DNS set via resolvectl on {}: {}", ifname, dns_addr);
            return Ok(());
        }
        // Keep the marker even when try_resolvectl's immediate revert appeared to work.
        // The caller's generation cleanup retries the revert and removes the marker only
        // after a confirmed zero exit status.
        anyhow::bail!(
            "systemd-resolved is the active resolver, but per-link DNS could not be fully \
             applied to {ifname}; the partial change was reverted and qeli refused a persistent \
             {RESOLV_PATH} takeover. Check the preceding resolvectl error, or set `dns = off`"
        );
    }

    anyhow::bail!(
        "refusing to replace {RESOLV_PATH} with tunnel DNS: systemd-resolved is not the active \
         system resolver, so an unclean exit or uninstall could strand the host on a dead \
         resolver. Enable systemd-resolved and point {RESOLV_PATH} at its stub, or set \
         `dns = off` when NetworkManager/dnsmasq/the platform manages DNS"
    )
}

/// Apply exactly the resolver set already validated into the shared NetworkPlan.
/// Unlike the legacy singular seam, this preserves both IPv4 and IPv6 resolvers.
pub fn setup_network_plan_dns(
    config: &ClientDnsConfig,
    servers: &[NetworkDns],
    ifname: &str,
) -> anyhow::Result<()> {
    if config.mode != "tunnel" || servers.is_empty() {
        return Ok(());
    }
    let mut resolver_args = Vec::with_capacity(servers.len());
    for server in servers {
        let address: std::net::IpAddr = server.address.parse().map_err(|_| {
            anyhow::anyhow!("invalid network-plan DNS address '{}'", server.address)
        })?;
        if server.port == 0 {
            anyhow::bail!("invalid network-plan DNS port 0 for {address}");
        }
        resolver_args.push(if server.port == 53 {
            address.to_string()
        } else {
            format!("{address}#{}", server.port)
        });
    }

    if !resolved_is_active() {
        anyhow::bail!(
            "refusing to replace {RESOLV_PATH} with tunnel DNS: systemd-resolved is not the active \
             system resolver, so an unclean exit or uninstall could strand the host on a dead \
             resolver. Enable systemd-resolved and point {RESOLV_PATH} at its stub, or set \
             `dns = off` when NetworkManager/dnsmasq/the platform manages DNS"
        );
    }

    // Persist ownership before changing the link. This is essential for attach mode, where
    // deleting qeli does not delete the externally owned interface and therefore does not
    // automatically discard its per-link resolver state.
    ensure_state_dir()?;
    let marker = resolvectl_mark_path(ifname);
    crate::util::write_atomic_private(&marker, ifname.as_bytes()).map_err(|error| {
        anyhow::anyhow!(
            "cannot persist resolvectl ownership marker {}: {} — DNS was not changed",
            marker,
            error
        )
    })?;
    if try_resolvectl_many(config, ifname, &resolver_args) {
        log::info!(
            "DNS set via resolvectl on {}: {}",
            ifname,
            resolver_args.join(", ")
        );
        return Ok(());
    }
    // Keep the marker after the immediate revert attempt. Generation cleanup will retry the
    // revert and only remove the marker after a confirmed successful command.
    anyhow::bail!(
        "systemd-resolved is the active resolver, but per-link DNS could not be fully applied \
         to {ifname}; the partial change was reverted and qeli refused a persistent \
         {RESOLV_PATH} takeover. Check the preceding resolvectl error, or set `dns = off`"
    )
}

/// Revert the `resolvectl` per-link config recorded for one interface, if any.
fn revert_resolvectl_marker(path: &std::path::Path) -> anyhow::Result<()> {
    let ifname = match std::fs::read_to_string(path) {
        Ok(ifname) => ifname,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => anyhow::bail!(
            "cannot read DNS ownership marker {}: {error}",
            path.display()
        ),
    };
    let ifname = ifname.trim();
    if ifname.is_empty() {
        std::fs::remove_file(path).map_err(|error| {
            anyhow::anyhow!("cannot remove empty DNS marker {}: {error}", path.display())
        })?;
        return Ok(());
    }
    let output = resolvectl_cmd()
        .args(["revert", ifname])
        .output()
        .map_err(|error| anyhow::anyhow!("cannot run resolvectl revert {ifname}: {error}"))?;
    if !output.status.success() {
        // Keep the marker: dropping it discarded the only record that this link
        // still carries our DNS config, so nothing would ever retry — matching
        // how a failed resolv.conf restore keeps its backup.
        anyhow::bail!(
            "resolvectl revert {} failed with {}: {} — marker kept at {} for a later retry",
            ifname,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            path.display()
        );
    }
    log::info!("Reverted resolvectl config on {}", ifname);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => anyhow::bail!(
            "DNS was reverted on {ifname}, but marker {} could not be removed: {error}",
            path.display()
        ),
    }
}

/// Does a network interface with this name currently exist?
fn link_exists(ifname: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{ifname}")).exists()
}

/// Restore DNS to its pre-tunnel state. Safe to call repeatedly and even when
/// nothing was changed (it becomes a no-op).
///
/// Prefer [`restore_dns_for`] when the caller knows its own interface: without a name
/// this can only guess which marker belongs to it. (Audit 2026-07-27, R7.)
pub fn restore_dns() -> anyhow::Result<()> {
    restore_dns_inner(None)
}

/// Restore DNS, reverting the `resolvectl` config for THIS instance's `ifname` only.
pub fn restore_dns_for(ifname: &str) -> anyhow::Result<()> {
    restore_dns_inner(Some(ifname))
}

fn restore_dns_inner(ifname: Option<&str>) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // 1. Revert resolvectl per-link config.
    //
    // Markers are per-interface (see `resolvectl_mark_path`). With an explicit `ifname`
    // only that instance's marker is touched. Without one, revert only markers whose
    // interface is GONE — those are certainly stale. A live foreign link is left alone:
    // reverting it would strip a RUNNING sibling client's DNS, which is precisely what the
    // old single shared marker did.
    match ifname {
        Some(name) => {
            let p = resolvectl_mark_path(name);
            let p = std::path::Path::new(&p);
            if p.exists() {
                if let Err(error) = revert_resolvectl_marker(p) {
                    errors.push(error.to_string());
                }
            }
        }
        None => {
            let mut markers: Vec<std::path::PathBuf> = Vec::new();
            match std::fs::read_dir(STATE_DIR) {
                Ok(rd) => {
                    for e in rd.flatten() {
                        let name = e.file_name();
                        let name = name.to_string_lossy();
                        if let Some(iface) = name.strip_prefix("dns-resolvectl-") {
                            if !iface.is_empty() {
                                markers.push(e.path());
                            }
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => errors.push(format!("cannot inspect {STATE_DIR}: {error}")),
            }
            // Revert a marker only when its interface is GONE (or unnamed).
            //
            // There used to be an `only_one` short-circuit: a single marker was reverted
            // without checking anything. But markers are REMOVED on a clean stop, so "exactly
            // one marker" does not mean "leftover junk from a crash" — in practice it means
            // "one client is running right now". Starting a second client (another profile,
            // another server) therefore ran `resolvectl revert` on the FIRST one's live link:
            // its tunnel resolver was stripped, every lookup fell back through the
            // systemd-resolved stub to the physical network's resolvers in cleartext, and the
            // first client — whose marker was also deleted — could no longer restore or even
            // roll back its own DNS. It kept reporting a healthy tunnel throughout; only the
            // second client's log mentioned the revert.
            //
            // That is exactly the behaviour the comment above says must not happen ("a live
            // foreign link is left alone"), cancelled by the `||` in front of it.
            // (Audit 2026-08-04.)
            for p in markers {
                let owner = std::fs::read_to_string(&p).unwrap_or_default();
                let owner = owner.trim().to_string();
                if owner.is_empty() || !link_exists(&owner) {
                    if let Err(error) = revert_resolvectl_marker(&p) {
                        errors.push(error.to_string());
                    }
                }
            }
        }
    }

    // 2. Restore /etc/resolv.conf from a legacy persistent backup, but only when no older
    // client process still holds it. If the holder state cannot be locked or parsed, preserve
    // the backup and leave the host untouched rather than guessing that this process is last.
    let backup = Path::new(BACKUP_PATH);
    if backup.exists() {
        match release_dns_holder() {
            Ok(false) => {
                log::info!(
                    "DNS restore deferred: another qeli client still holds the host DNS — \
                     /etc/resolv.conf left in place"
                );
                if errors.is_empty() {
                    return Ok(());
                }
                anyhow::bail!("DNS cleanup failed: {}", errors.join("; "));
            }
            Ok(true) => {}
            Err(error) => {
                errors.push(format!(
                    "DNS restore deferred because legacy holder state is unsafe ({error}); backup kept at {BACKUP_PATH}"
                ));
                return Err(anyhow::anyhow!("DNS cleanup failed: {}", errors.join("; ")));
            }
        }
    }
    if backup.exists() {
        match restore_resolv(Path::new(RESOLV_PATH), backup) {
            Ok(()) => {
                log::info!("Restored /etc/resolv.conf to its original state");
                if let Err(error) = std::fs::remove_file(backup) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        errors.push(format!(
                            "restored {RESOLV_PATH}, but could not remove backup {BACKUP_PATH}: {error}"
                        ));
                    }
                }
            }
            Err(e) => {
                // Keep the backup so a later restore (or recover_stale) can retry.
                errors.push(format!(
                    "failed to restore {RESOLV_PATH}: {e} (backup kept at {BACKUP_PATH})"
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("DNS cleanup failed: {}", errors.join("; "))
    }
}

/// Repair leftover state from a previous run that died without restoring
/// (SIGKILL, power loss, panic). Call once at client startup. If a backup or
/// resolvectl marker exists, the previous run did not clean up — restore now.
pub fn recover_stale() -> anyhow::Result<()> {
    let has_backup = Path::new(BACKUP_PATH).exists();
    let has_mark = match std::fs::read_dir(STATE_DIR) {
        Ok(rd) => rd.flatten().any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("dns-resolvectl-")
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => anyhow::bail!("cannot inspect stale DNS state in {STATE_DIR}: {error}"),
    };
    if has_backup || has_mark {
        log::warn!("Found stale DNS state from a previous run — restoring before connecting");
        restore_dns()?;
    }
    Ok(())
}

// ── resolvectl ────────────────────────────────────────────────────────────

/// Is systemd-resolved actually the system resolver? Its per-link DNS only takes
/// effect if the box resolves THROUGH it — i.e. `/etc/resolv.conf` points at the
/// stub (`127.0.0.53`) or systemd's run dir. On a box where systemd-resolved is
/// merely installed (so `resolvectl` exists and returns success) but resolv.conf
/// lists real nameservers or is managed by something else, `resolvectl dns` is a
/// silent no-op and the tunnel's pushed DNS is ignored (a leak). When this returns
/// false the client refuses a persistent resolv.conf takeover.
fn resolved_is_active() -> bool {
    if let Ok(target) = std::fs::read_link(RESOLV_PATH) {
        let t = target.to_string_lossy();
        if t.contains("systemd/resolve") || t.contains("stub-resolv.conf") {
            return true;
        }
    }
    std::fs::read_to_string(RESOLV_PATH)
        .map(|c| c.contains("127.0.0.53"))
        .unwrap_or(false)
}

/// Path to the `resolvectl` binary, if it is installed at all.
///
/// The decision to use the per-link path is made by [`resolved_is_active`], which asks a
/// different and more important question. Looked up by absolute path rather than via
/// `PATH`: the client runs from a
/// systemd unit whose environment may not carry a useful `PATH`.
fn which_resolvectl() -> Option<String> {
    // An explicit override wins. It exists because the absolute-path lookup below is, by
    // design, immune to `PATH` — which also makes it immune to being pointed at a stand-in.
    // The fault-injection tests substitute a script and can only do so through the
    // environment; without this they passed on a host with no systemd-resolved (lookup
    // fails, the bare-name fallback finds the stand-in on `PATH`) and failed on one that
    // has it, where the REAL resolvectl ran and refused to configure a link named `qtest`.
    // A test that only passes where the tool is absent is worse than no test. It is also
    // the escape hatch for a distribution that keeps the binary somewhere unusual.
    if let Ok(p) = std::env::var("QELI_RESOLVECTL") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    [
        "/usr/bin/resolvectl",
        "/bin/resolvectl",
        "/usr/sbin/resolvectl",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(str::to_string)
}

/// `resolvectl` as a runnable command, resolved to an ABSOLUTE path.
///
/// Every call site used `Command::new("resolvectl")`, which searches `PATH` — defeating the
/// whole reason [`which_resolvectl`] looks the binary up by absolute path in the first place
/// (its own doc says so: the client runs from a systemd unit whose environment may carry no
/// useful `PATH`). Where that bit, the symptom was silent: `resolvectl dns` simply failed to
/// spawn, the caller read that as "resolvectl did not work". Falls back to the bare name
/// when the binary is somewhere unusual, so
/// a working `PATH` still succeeds. (Audit 2026-07-30.)
fn resolvectl_cmd() -> std::process::Command {
    std::process::Command::new(which_resolvectl().unwrap_or_else(|| "resolvectl".to_string()))
}

/// The `resolvectl domain` list for the tunnel link.
///
/// Shared with [`try_resolvectl_many`] so the decision can be tested without spawning anything —
/// it is the difference between "all DNS goes through the tunnel" and a silent split.
fn routing_domains(config: &ClientDnsConfig) -> Vec<String> {
    let mut domains: Vec<String> = config.search_domains.clone();
    if config.redirect_all || config.mode.eq_ignore_ascii_case("tunnel") {
        domains.push("~.".to_string());
    }
    domains
}

#[cfg(test)]
fn try_resolvectl(config: &ClientDnsConfig, ifname: &str, dns_addr: &str) -> bool {
    try_resolvectl_many(config, ifname, &[dns_addr.to_string()])
}

fn try_resolvectl_many(config: &ClientDnsConfig, ifname: &str, dns_addrs: &[String]) -> bool {
    let result = resolvectl_cmd()
        .args(["dns", ifname])
        .args(dns_addrs)
        .output();
    let applied = result
        .as_ref()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !applied {
        let detail = result
            .as_ref()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "command unavailable or returned failure".to_string());
        log::warn!(
            "resolvectl refused DNS [{}] on {} ({}) — reverting the link state",
            dns_addrs.join(", "),
            ifname,
            detail
        );
        let _ = resolvectl_cmd().args(["revert", ifname]).output();
        return false;
    }

    // Routing domains decide which queries go to this link. `~.` is the
    // catch-all that sends *all* DNS through the tunnel (full-tunnel mode).
    //
    // `~.` used to be gated on `config.redirect_all`, and NOTHING could set that field: the
    // only client config format is the flat INI, and `ClientConfig::from_ini` populates just
    // `dns.mode` and `dns.servers` — `redirect_all` and `search_domains` have no INI key at
    // all (grep finds the field declaration and unit tests, nothing else). So the catch-all
    // was never emitted, `domains` was always empty, and this whole block was skipped.
    //
    // The consequence was a silent leak on the most common desktop Linux there is. On a host
    // with systemd-resolved this path is PREFERRED and /etc/resolv.conf is left alone, so the
    // tunnel link got a DNS server but no routing domain — and resolved then splits queries
    // between the tunnel resolver and the physical link's. A user running full-tunnel with
    // `dns = tunnel` saw "DNS set via resolvectl" in the log while the Wi-Fi operator saw
    // every domain they visited. For a censorship-circumvention tool that is precisely the
    // metadata the tunnel exists to hide.
    //
    // So: whenever we are taking DNS over (`dns.mode = tunnel`, which is the default), claim
    // the catch-all. Anything less is not "DNS through the VPN". (Audit 2026-08-04, H-01.)
    let domains = routing_domains(config);
    if !domains.is_empty() {
        // The routing domains decide WHICH queries take this link — with `~.` they are
        // the difference between "all DNS goes through the tunnel" and "almost none does".
        // The result used to be discarded and the caller told the whole thing succeeded,
        // so a failure here meant queries kept going to the physical resolver while the
        // log said DNS was set: a silent leak in exactly the mode that exists to prevent
        // one. Report it, so the caller reverts the partial state and refuses takeover.
        let ok = resolvectl_cmd()
            .args(["domain", ifname])
            .args(&domains)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            log::warn!(
                "resolvectl set the DNS server on {} but REFUSED the routing domains ({}) —                  queries would keep using the physical resolver; reverting and refusing the                  DNS takeover",
                ifname,
                domains.join(" ")
            );
            let _ = resolvectl_cmd().args(["revert", ifname]).output();
            return false;
        }
    }
    true
}

// ── /etc/resolv.conf capture & restore (pure file logic, path-injectable) ───

fn ensure_state_dir() -> anyhow::Result<()> {
    std::fs::create_dir_all(STATE_DIR)
        .map_err(|e| anyhow::anyhow!("cannot create state dir {}: {}", STATE_DIR, e))
}

/// Live-holder set for the host DNS takeover: one line per still-running client pid.
/// Read under a lock, filtered to pids that are actually alive (so a SIGKILLed instance
/// does not pin the takeover forever), and returned.
fn read_live_holders() -> anyhow::Result<Vec<u32>> {
    let text = match std::fs::read_to_string(REFCOUNT_PATH) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => anyhow::bail!("cannot read {REFCOUNT_PATH}: {error}"),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim().parse::<u32>().map_err(|error| {
                anyhow::anyhow!("invalid PID in {REFCOUNT_PATH} ({line:?}): {error}")
            })
        })
        .filter_map(|pid| match pid {
            Ok(pid) if pid_alive(pid) => Some(Ok(pid)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn write_holders(pids: &[u32]) -> anyhow::Result<()> {
    let body: String = pids.iter().map(|p| format!("{p}\n")).collect();
    crate::util::write_atomic_private(REFCOUNT_PATH, body.as_bytes())
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    // kill(pid, 0): 0 or EPERM => the process exists; ESRCH => it does not.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn pid_alive(_pid: u32) -> bool {
    true
}

/// Release: returns (remaining, last).
fn compute_release(holders: Vec<u32>, me: u32) -> (Vec<u32>, bool) {
    let remaining: Vec<u32> = holders.into_iter().filter(|&p| p != me).collect();
    let last = remaining.is_empty();
    (remaining, last)
}

/// Drop this process from the holder set. Returns true when it was the LAST holder — the
/// only case in which the caller should restore the original and delete the backup.
fn release_dns_holder() -> anyhow::Result<bool> {
    ensure_state_dir()?;
    let _lock = crate::util::FileLock::acquire(REFCOUNT_PATH)?;
    let (remaining, last) = compute_release(read_live_holders()?, std::process::id());
    if last {
        match std::fs::remove_file(REFCOUNT_PATH) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!("cannot remove {REFCOUNT_PATH}: {error}"),
        }
    } else {
        write_holders(&remaining)?;
    }
    Ok(last)
}

/// Capture the current resolv.conf state into `backup`, exactly once.
///
/// Idempotent: if `backup` already exists we keep the previously-saved
/// original. If the current file is already ours (contains `marker`) but no
/// backup exists, we record `managed-no-original` so restore falls back to a
/// working public resolver rather than leaving a dangling tunnel address.
#[cfg(test)]
fn capture_original(resolv: &Path, backup: &Path, marker: &str) -> anyhow::Result<()> {
    if backup.exists() {
        return Ok(());
    }

    let snapshot = match std::fs::symlink_metadata(resolv) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = std::fs::read_link(resolv)
                .map_err(|e| anyhow::anyhow!("read_link {}: {}", resolv.display(), e))?;
            DnsBackup {
                kind: "symlink".into(),
                target: Some(target.to_string_lossy().into_owned()),
                content: None,
                mode: None,
            }
        }
        Ok(_meta) => {
            let content = std::fs::read_to_string(resolv).unwrap_or_default();
            if content.contains(marker) {
                // Our own file with no saved original — corrupted prior state.
                DnsBackup {
                    kind: "managed-no-original".into(),
                    target: None,
                    content: None,
                    mode: None,
                }
            } else {
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(resolv)
                        .ok()
                        .map(|m| m.permissions().mode())
                };
                #[cfg(not(unix))]
                let mode = None;
                DnsBackup {
                    kind: "file".into(),
                    target: None,
                    content: Some(content),
                    mode,
                }
            }
        }
        Err(_) => DnsBackup {
            kind: "absent".into(),
            target: None,
            content: None,
            mode: None,
        },
    };

    let json = serde_json::to_string(&snapshot)?;
    write_atomic(backup, json.as_bytes())?;
    Ok(())
}

/// Rebuild `/etc/resolv.conf` exactly as captured in `backup`.
fn restore_resolv(resolv: &Path, backup: &Path) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(backup)?;
    let snap: DnsBackup = serde_json::from_str(&json)?;

    match snap.kind.as_str() {
        "symlink" => {
            let target = snap
                .target
                .ok_or_else(|| anyhow::anyhow!("symlink backup without target"))?;
            // Remove whatever is there now (our regular file) then recreate the link.
            let _ = std::fs::remove_file(resolv);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, resolv)
                .map_err(|e| anyhow::anyhow!("recreate symlink -> {}: {}", target, e))?;
            Ok(())
        }
        "file" => {
            let content = snap.content.unwrap_or_default();
            write_atomic(resolv, content.as_bytes())?;
            #[cfg(unix)]
            if let Some(mode) = snap.mode {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(resolv, std::fs::Permissions::from_mode(mode));
            }
            Ok(())
        }
        "absent" => {
            // There was no resolv.conf before us; remove ours if still present.
            if resolv.exists() {
                let _ = std::fs::remove_file(resolv);
            }
            Ok(())
        }
        "managed-no-original" => {
            // We never knew the original. Leave a working public resolver
            // rather than a dead tunnel address.
            let content =
                "# Restored by qeli (original unknown)\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
            write_atomic(resolv, content.as_bytes())?;
            Ok(())
        }
        other => Err(anyhow::anyhow!("unknown backup kind: {}", other)),
    }
}

#[cfg(test)]
fn write_managed_resolv(
    resolv: &Path,
    dns_server: &str,
    search: &[String],
    marker: &str,
) -> anyhow::Result<()> {
    write_managed_resolv_many(resolv, &[dns_server.to_string()], search, marker)
}

#[cfg(test)]
fn write_managed_resolv_many(
    resolv: &Path,
    dns_servers: &[String],
    search: &[String],
    marker: &str,
) -> anyhow::Result<()> {
    let mut content = String::new();
    content.push_str(marker);
    content.push('\n');
    for dns_server in dns_servers {
        content.push_str(&format!("nameserver {}\n", dns_server));
    }
    if !search.is_empty() {
        content.push_str(&format!("search {}\n", search.join(" ")));
    }
    write_atomic(resolv, content.as_bytes())
}

/// Write a file atomically (tmp in the same dir, then rename). Thin wrapper over
/// [`crate::util::write_atomic`] — the single shared implementation (also used by
/// the server's config/users/key writes), which on Unix uses `O_EXCL` +
/// `O_NOFOLLOW` against symlink pre-planting (H-5) and preserves the target's
/// mode. Replacing a symlink with the renamed regular file is intentional —
/// `restore_resolv` recreates the link from the backup.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    crate::util::write_atomic(path, bytes)
}

#[cfg(test)]
mod tests {

    #[test]
    fn network_plan_contains_only_a_reachable_server_pushed_resolver() {
        let dns: crate::config::client::ClientDnsConfig =
            serde_json::from_str("{}").expect("empty document uses serde defaults");
        let tun_net = Some((
            "10.8.0.2".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        ));
        assert!(
            super::planned_dns_server(&dns, "", "53", tun_net, false)
                .unwrap()
                .is_none(),
            "no configured resolver means an explicit no-op DNS plan"
        );

        let reachable = super::planned_dns_server(&dns, "10.8.0.1", "5353", tun_net, false)
            .unwrap()
            .unwrap();
        assert_eq!(reachable.address, "10.8.0.1");
        assert_eq!(reachable.port, 5353);
        assert!(
            super::planned_dns_server(&dns, "203.0.113.53", "53", tun_net, false)
                .unwrap()
                .is_none(),
            "a split-tunnel plan must omit an unreachable server resolver"
        );
        assert!(
            super::planned_dns_server(&dns, "203.0.113.53", "53", tun_net, true)
                .unwrap()
                .is_some(),
            "a full tunnel can reach an external resolver through its default route"
        );
    }

    /// A default client (`dns.mode = tunnel`) MUST claim the `~.` catch-all routing domain.
    ///
    /// It used to be gated on `redirect_all`, which no INI key can set, so the catch-all was
    /// never emitted: systemd-resolved kept splitting queries between the tunnel resolver and
    /// the physical link's, and the log still said DNS was set. Deserialized from an EMPTY
    /// document on purpose — `#[derive(Default)]` ignores `#[serde(default = "…")]`, so
    /// testing `::default()` would not exercise the real default. (Audit 2026-08-04, H-01.)
    #[test]
    fn tunnel_dns_mode_claims_the_catch_all_routing_domain() {
        let dns: crate::config::client::ClientDnsConfig =
            serde_json::from_str("{}").expect("empty document uses the serde defaults");
        assert_eq!(dns.mode, "tunnel", "the shipped default");
        assert!(
            !dns.redirect_all,
            "no INI key sets this; it must not be required"
        );
        assert!(
            super::routing_domains(&dns).contains(&"~.".to_string()),
            "dns.mode = tunnel must send ALL queries through the tunnel link"
        );

        // `dns = off` / `system` means the user keeps their own resolver — do not hijack it.
        let mut off = dns.clone();
        off.mode = "off".to_string();
        assert!(
            !super::routing_domains(&off).contains(&"~.".to_string()),
            "dns = off must leave the host resolver alone"
        );

        // Search domains still ride along, and `redirect_all` alone still works.
        let mut with_search = off.clone();
        with_search.search_domains = vec!["corp.example".to_string()];
        assert_eq!(super::routing_domains(&with_search), vec!["corp.example"]);
        with_search.redirect_all = true;
        assert_eq!(
            super::routing_domains(&with_search),
            vec!["corp.example", "~."]
        );
    }

    /// An unconfigured client must NOT silently send its DNS to a third party.
    ///
    /// The refusal in `setup_dns_for_interface` consults `servers` then `fallback_servers`, so
    /// a non-empty DEFAULT for either one makes it unreachable — which is exactly how a
    /// `["1.1.1.1", "8.8.8.8"]` default cancelled the R5 fix and sent every query of every
    /// default-configured client to Cloudflare. Deserialized from an EMPTY document on purpose:
    /// `#[derive(Default)]` ignores `#[serde(default = "…")]`, so testing `::default()` would
    /// pass no matter what the serde default said. (Audit 2026-07-30, #8.)
    #[test]
    fn an_unconfigured_client_has_no_third_party_resolver() {
        let dns: crate::config::client::ClientDnsConfig =
            serde_json::from_str("{}").expect("empty config deserializes");
        assert_eq!(
            dns.mode, "tunnel",
            "guard: this test assumes tunnel is the default mode"
        );
        assert!(
            dns.servers.is_empty(),
            "dns.servers must not default to anything"
        );
        assert!(
            dns.fallback_servers.is_empty(),
            "dns.fallback_servers must not default to a third-party resolver — that silently              overrides the user's choice and makes the 'no resolver configured' refusal dead code"
        );
    }

    /// Legacy recovery must remove only this process and defer restoration while another
    /// live holder remains.
    #[test]
    fn legacy_holder_release_restores_only_for_the_last_process() {
        let (holders, last) = super::compute_release(vec![100, 200], 100);
        assert!(
            !last,
            "the first to leave must NOT restore while another holds DNS"
        );
        assert_eq!(holders, vec![200]);

        let (holders, last) = super::compute_release(holders, 200);
        assert!(last, "the last holder out restores the original");
        assert!(holders.is_empty());
    }

    use super::*;
    use std::path::PathBuf;

    /// Unique temp workspace per test.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "qeli-dns-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn capture_and_restore_regular_file() {
        let t = Tmp::new("file");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        std::fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        assert!(read(&resolv).contains("10.0.0.1"));
        assert!(read(&resolv).contains(MARKER));

        restore_resolv(&resolv, &backup).unwrap();
        assert_eq!(read(&resolv), "nameserver 192.168.1.1\n");
    }

    #[test]
    fn capture_is_idempotent_across_reconnects() {
        // The core bug: a second setup must NOT overwrite the saved original
        // with our generated file.
        let t = Tmp::new("reconnect");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        std::fs::write(&resolv, "nameserver 9.9.9.9\n").unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        // Reconnect: setup runs again while resolv.conf is already ours.
        capture_original(&resolv, &backup, MARKER).unwrap();

        restore_resolv(&resolv, &backup).unwrap();
        assert_eq!(
            read(&resolv),
            "nameserver 9.9.9.9\n",
            "original must survive reconnect"
        );
    }

    #[test]
    #[cfg(unix)]
    fn capture_and_restore_symlink() {
        let t = Tmp::new("symlink");
        let resolv = t.path("resolv.conf");
        let real = t.path("stub-resolv.conf");
        std::fs::write(&real, "nameserver 127.0.0.53\n").unwrap();
        std::os::unix::fs::symlink(&real, &resolv).unwrap();

        capture_original(&resolv, &t.path("backup.json"), MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        // Our write replaced the symlink with a regular file.
        assert!(!std::fs::symlink_metadata(&resolv)
            .unwrap()
            .file_type()
            .is_symlink());

        restore_resolv(&resolv, &t.path("backup.json")).unwrap();
        let meta = std::fs::symlink_metadata(&resolv).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must be recreated");
        assert_eq!(std::fs::read_link(&resolv).unwrap(), real);
    }

    #[test]
    fn absent_original_is_removed_on_restore() {
        let t = Tmp::new("absent");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        // No resolv.conf exists yet.
        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        assert!(resolv.exists());

        restore_resolv(&resolv, &backup).unwrap();
        assert!(
            !resolv.exists(),
            "file we created must be removed when there was no original"
        );
    }

    #[test]
    fn managed_file_without_backup_restores_to_public_resolver() {
        // Simulates a crashed prior run: resolv.conf is ours, backup is gone.
        let t = Tmp::new("orphan");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        let snap: DnsBackup = serde_json::from_str(&read(&backup)).unwrap();
        assert_eq!(snap.kind, "managed-no-original");

        restore_resolv(&resolv, &backup).unwrap();
        let restored = read(&resolv);
        assert!(
            restored.contains("1.1.1.1"),
            "must leave a working resolver, not the dead tunnel IP"
        );
        assert!(!restored.contains("10.0.0.1"));
    }
}

// ── fault injection: a PARTIAL resolvectl failure must not read as success ───
//
// `resolvectl dns` and `resolvectl domain` are two calls, and only the pair does what
// the mode promises: the server address decides WHERE queries go, the routing domains
// decide WHICH queries take that link. With `~.` the domains are the difference between
// "all DNS goes through the tunnel" and "almost none does" — so a failure of the second
// call while the first succeeded is a silent DNS leak, reported as a working tunnel.
//
// Only reproducible by making the command fail on demand, hence the stub behind QELI_RESOLVECTL.
#[cfg(all(test, target_os = "linux"))]
mod fault_injection {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};

    static SERIAL: Mutex<()> = Mutex::new(());

    struct Resolvectl {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        old_path: String,
    }

    impl Resolvectl {
        fn new(tag: &str, fail_on: &[&str]) -> Resolvectl {
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-rslv-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("case \"$*\" in\n");
            for cond in fail_on {
                script.push_str(&format!("  *\"{cond}\"*) exit 1;;\n"));
            }
            script.push_str("esac\nexit 0\n");

            let bin = dir.join("resolvectl");
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            // Point the code at the stand-in explicitly. Prepending to PATH is not enough:
            // the lookup is deliberately immune to PATH, so on a host that HAS a real
            // resolvectl the tests used to drive the real one against a link named `qtest`.
            let old_path = std::env::var("QELI_RESOLVECTL").unwrap_or_default();
            std::env::set_var("QELI_RESOLVECTL", bin.as_os_str());
            Resolvectl {
                dir,
                _guard: guard,
                old_path,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Resolvectl {
        fn drop(&mut self) {
            if self.old_path.is_empty() {
                std::env::remove_var("QELI_RESOLVECTL");
            } else {
                std::env::set_var("QELI_RESOLVECTL", &self.old_path);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Full-tunnel DNS: the `~.` catch-all is what makes every query take the link.
    fn redirect_all() -> ClientDnsConfig {
        ClientDnsConfig {
            redirect_all: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_refused_routing_domain_is_not_reported_as_success() {
        // `dns` lands, `domain` does not. The old code discarded the second result and
        // returned true, so the caller logged "DNS set" and never fell back — while every
        // query kept going to the physical resolver.
        let rc = Resolvectl::new("domain", &["domain qtest"]);
        assert!(
            !try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"),
            "a failed routing-domain call must report failure so the caller refuses takeover"
        );
        assert!(
            rc.calls().contains("revert qtest"),
            "the half-applied link config must be reverted, not left behind:\n{}",
            rc.calls()
        );
    }

    #[test]
    fn a_working_resolvectl_reports_success_and_sets_both() {
        let rc = Resolvectl::new("ok", &[]);
        assert!(try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"));
        let calls = rc.calls();
        assert!(
            calls.contains("dns qtest 10.0.0.1") && calls.contains("domain qtest"),
            "both halves must be applied:\n{calls}"
        );
        assert!(
            !calls.contains("revert"),
            "nothing to revert on the success path:\n{calls}"
        );
    }

    #[test]
    fn a_refused_dns_call_fails_before_touching_domains() {
        // The first call failing must also revert any partial per-link state and make the
        // caller refuse a persistent resolv.conf takeover.
        let rc = Resolvectl::new("dns", &["dns qtest"]);
        assert!(!try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"));
        assert!(
            !rc.calls().contains("domain qtest"),
            "no point setting routing domains on a link whose server was refused:\n{}",
            rc.calls()
        );
        assert!(
            rc.calls().contains("revert qtest"),
            "a refused DNS call must leave no partial link state:\n{}",
            rc.calls()
        );
    }
}
