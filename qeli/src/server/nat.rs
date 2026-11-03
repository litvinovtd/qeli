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

#[cfg(test)]
use crate::nat_cleanup::exact_delete_args;
use crate::nat_cleanup::{cleanup_exact_rules_with, cleanup_matching_with, rule_comment};
#[cfg(test)]
use crate::nat_dns_input::DnsInputId;
use crate::nat_dns_input::{dns_input_rule, DnsInputOwner, DnsInputRegistry, DnsInputRules};
use crate::network_default_route::{preferred_default_device, DefaultDevice};
use crate::system_command::Command;
use std::sync::{Mutex, OnceLock};

mod cleanup_budget;
mod discovery;
mod journal;
use cleanup_budget::Budget;
#[cfg(test)]
pub(crate) use discovery::with_probe;

const XTABLES_LOCK_WAIT_SECS: &str = "5";

/// iptables comment tag for the rules belonging to `profile`.
fn tag(profile: &str) -> String {
    format!("qeli-nat:{profile}")
}

/// Locate the `iptables` binary. `None` = not installed — the caller surfaces that
/// as an error + log + panel warning. Checks the usual sbin locations first (cheap,
/// no exec) then falls back to a PATH probe.
pub fn iptables_path() -> Option<String> {
    if let Some(path) = discovery::installed(discovery::Tool::Ipv4) {
        return Some(path);
    }
    if Command::new("iptables")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some("iptables".to_string());
    }
    None
}

pub fn ip6tables_path() -> Option<String> {
    discovery::installed(discovery::Tool::Ipv6).or_else(|| {
        Command::new("ip6tables")
            .args(["--version"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|_| "ip6tables".to_string())
    })
}

pub async fn iptables_path_async(until: tokio::time::Instant) -> std::io::Result<Option<String>> {
    discovery::find_async(discovery::Tool::Ipv4, until).await
}

pub async fn ip6tables_path_async(until: tokio::time::Instant) -> Option<String> {
    // Quick Start enables IPv6 management only when availability was established.
    discovery::find_async(discovery::Tool::Ipv6, until)
        .await
        .ok()
        .flatten()
}

/// Whether `iptables` is available on this host (used by the panel to warn).
pub fn available() -> bool {
    iptables_path().is_some()
}

#[cfg(test)]
fn ipt(path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    // Keep the 5s xtables-lock wait inside the shared runner's 15s command deadline.
    // The lock wait alone cannot bound a stalled backend or inherited output pipe.
    // A timeout can follow an applied mutation: callers must still verify/retain ownership.
    Command::new(path)
        .args(["--wait", XTABLES_LOCK_WAIT_SECS])
        .args(args)
        .output()
}

/// Resolve a route in the same operation deadline as its subsequent firewall rules.
fn detect_wan_until(
    ipv6: bool,
    require_default: bool,
    budget: Budget,
) -> anyhow::Result<Option<String>> {
    // route-get reflects just one destination's ECMP hash bucket. First inspect
    // all best-metric default candidates; an ambiguous best route must fail
    // closed rather than authorize rules for only one of its physical uplinks.
    let mut show = Command::new("ip");
    if ipv6 {
        show.args(["-6"]);
    }
    show.args(["route", "show", "default"]);
    let listing = budget.output(&mut show);
    budget.check()?;
    match listing {
        Ok(output) if output.status.success() => {
            match preferred_default_device(&String::from_utf8_lossy(&output.stdout)) {
                DefaultDevice::Selected(wan) => return Ok(Some(wan)),
                DefaultDevice::Ambiguous => {
                    anyhow::bail!(
                        "ambiguous default WAN: multiple equally preferred uplinks or ECMP nexthops"
                    );
                }
                DefaultDevice::Missing => {}
            }
        }
        Ok(output) if require_default => {
            anyhow::bail!(
                "cannot verify a unique default WAN: ip route show default exited with {}; set the WAN interface explicitly only if its routing is administrator-controlled",
                output.status
            );
        }
        Err(error) if require_default => {
            anyhow::bail!(
                "cannot verify a unique default WAN: ip route show default failed: {error}; set the WAN interface explicitly only if its routing is administrator-controlled"
            );
        }
        _ => {}
    }
    if require_default {
        anyhow::bail!(
            "cannot verify a unique default WAN: no usable default route was listed; set the WAN interface explicitly only if its routing is administrator-controlled"
        );
    }

    // Route mode and manual NDP may have policy routing or no default route.
    // Preserve their legacy one-destination fallback; NAT auto-WAN cannot use
    // it because a route-get result is only one ECMP hash bucket.
    let mut command = Command::new("ip");
    if ipv6 {
        command.args(["-6"]);
    }
    command.args([
        "route",
        "get",
        if ipv6 {
            "2606:4700:4700::1111"
        } else {
            "1.1.1.1"
        },
    ]);
    let output = budget.output(&mut command);
    budget.check()?;
    Ok(output.ok().filter(|o| o.status.success()).and_then(|o| {
        let text = String::from_utf8_lossy(&o.stdout);
        let fields: Vec<_> = text.split_whitespace().collect();
        fields
            .windows(2)
            .find(|pair| pair[0] == "dev")
            .map(|pair| pair[1].to_string())
    }))
}

/// Acquire `net.ipv4.ip_forward = 1` for the server worker through the common host journal.
/// The lease lasts until final worker cleanup; stopping one profile must not flip a
/// host-global knob off beneath its siblings. A panel-managed client
/// can therefore stop without restoring `0` underneath an active NAT44/routed server profile.
fn enable_ip_forward() -> bool {
    let path = "/proc/sys/net/ipv4/ip_forward";
    if crate::sysctl::acquire(path, "1", "server-ipv4") {
        log::info!("NAT: net.ipv4.ip_forward is owned for the server worker lifetime");
        true
    } else {
        log::error!(
            "NAT: could not enable net.ipv4.ip_forward — the kernel will not forward \
             anything between the tunnel and the WAN"
        );
        false
    }
}

fn ipv6_sysctl_leases() -> &'static Mutex<crate::nat_ipv6_sysctl::Registry> {
    static LEASES: OnceLock<Mutex<crate::nat_ipv6_sysctl::Registry>> = OnceLock::new();
    LEASES.get_or_init(Default::default)
}

fn firewall_program_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Acquire router settings with a retryable scope registered before either sysctl write.
fn acquire_ipv6_sysctls(
    profile: &str,
    wan: Option<&str>,
    tun: &str,
    budget: Budget,
) -> anyhow::Result<()> {
    budget.lock(ipv6_sysctl_leases())?.acquire(
        profile,
        wan,
        tun,
        |path, value, scope| budget.checked(|| crate::sysctl::acquire_checked(path, value, scope)),
        // An expired setup must not renew its time here. The outer operation owns
        // one fresh rollback budget after this registry guard has been released.
        |scope| budget.checked(|| crate::sysctl::release_scope(scope)),
    )
}

/// Resolve the IPv6 egress. Unlike the legacy IPv4 key, this setting has always documented an
/// empty string as auto; an explicit `eth0` therefore means exactly eth0.
pub(crate) fn resolve_wan_ipv6(configured_iface: &str) -> Option<String> {
    let configured = configured_iface.trim();
    if configured.is_empty() {
        detect_wan_until(true, false, Budget::for_operation("WAN discovery"))
            .ok()
            .flatten()
    } else {
        Some(configured.to_string())
    }
}

fn resolve_wan_until(
    configured: &str,
    ipv6: bool,
    require_default: bool,
    budget: Budget,
) -> anyhow::Result<Option<String>> {
    budget.check()?;
    let configured = configured.trim();
    let selected = if configured.is_empty() || (!ipv6 && configured == "eth0") {
        detect_wan_until(ipv6, require_default, budget)
    } else {
        Ok(Some(configured.to_string()))
    }?;
    if let Some(wan) = selected.as_deref() {
        // iptables -o accepts a name that does not exist yet. Such a rule would
        // silently become active if an unrelated link later acquired that name.
        // Query the calling NET namespace before changing forwarding or adding
        // rules; a vanished auto-detected link is an error as well.
        budget.checked(|| match crate::network_interface::index(wan)? {
            Some(_) => Ok(()),
            None => anyhow::bail!(
                "selected WAN interface '{wan}' is absent in the server network namespace"
            ),
        })?;
    }
    Ok(selected)
}

/// Select NDP's link independently from firewall setup. A dedicated interface wins,
/// then the effective/configured routing uplink, then read-only route discovery.
pub(crate) fn resolve_ndp_interface(
    dedicated: &str,
    effective_wan: &str,
    configured_wan: &str,
) -> Option<String> {
    if !dedicated.trim().is_empty() {
        Some(dedicated.trim().to_string())
    } else if !effective_wan.trim().is_empty() {
        Some(effective_wan.trim().to_string())
    } else {
        resolve_wan_ipv6(configured_wan)
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

fn cross_profile_drop_rules(profile: &str, tun: &str, peers: &[String]) -> Vec<Rule> {
    let comment = tag(profile);
    let mut unique = std::collections::HashSet::new();
    let mut rules = Vec::new();
    for peer in peers
        .iter()
        .map(|value| value.trim())
        .filter(|peer| !peer.is_empty() && *peer != tun && unique.insert((*peer).to_string()))
    {
        for (input, output) in [(tun, peer), (peer, tun)] {
            rules.push(Rule {
                table: "filter",
                chain: "FORWARD",
                args: vec![
                    "-i".into(),
                    input.into(),
                    "-o".into(),
                    output.into(),
                    "-j".into(),
                    "DROP".into(),
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    comment.clone(),
                ],
                essential: true,
            });
        }
    }
    rules
}

/// The iptables rules we install for one profile.
fn rules(
    profile: &str,
    wan: &str,
    tun: &str,
    pool_cidr: &str,
    peer_tuns: &[String],
    mss: i32,
) -> Vec<Rule> {
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
    let mut managed = cross_profile_drop_rules(profile, tun, peer_tuns);
    // A permissive host FORWARD chain must not leak unmasqueraded Internet
    // traffic through another uplink. Preserve access to RFC1918 networks
    // behind the server; unlike NAT66, NAT44 commonly shares those routes.
    // Match the tunnel rather than only pool_cidr so client_subnet traffic is
    // subject to the same public-destination boundary.
    managed.push(Rule {
        table: "filter",
        chain: "FORWARD",
        args: cm(vec![
            "-i".into(),
            tun.into(),
            "!".into(),
            "-o".into(),
            wan.into(),
            "-m".into(),
            "iprange".into(),
            "!".into(),
            "--dst-range".into(),
            "10.0.0.0-10.255.255.255".into(),
            "-m".into(),
            "iprange".into(),
            "!".into(),
            "--dst-range".into(),
            "172.16.0.0-172.31.255.255".into(),
            "-m".into(),
            "iprange".into(),
            "!".into(),
            "--dst-range".into(),
            "192.168.0.0-192.168.255.255".into(),
            "-j".into(),
            "DROP".into(),
        ]),
        essential: true,
    });
    managed.extend([
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
    ]);
    managed
}

/// Is this exact rule currently present? Verified with `iptables -C` (the only
/// reliable check across the legacy/nft backends — the exit code of `-A` lies on a
/// chain the nft wrapper considers incompatible).
#[cfg(test)]
fn rule_present(path: &str, table: &str, chain: &str, rule: &[String]) -> bool {
    let mut a: Vec<String> = vec!["-t".into(), table.into(), "-C".into(), chain.into()];
    a.extend_from_slice(rule);
    let argv: Vec<&str> = a.iter().map(String::as_str).collect();
    ipt(path, &argv)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn rule_jumps_to(args: &[String], target: &str) -> bool {
    args.windows(2)
        .any(|pair| pair[0] == "-j" && pair[1].eq_ignore_ascii_case(target))
}

/// Return the first position below every qeli-managed isolation DROP. Broad routing permits
/// are inserted there, never at rule 1, so a later profile restart cannot move an ACCEPT above
/// another profile's boundary.
fn forward_permit_position_from_listing(listing: &str) -> usize {
    let mut position = 0usize;
    let mut last_managed_drop = 0usize;
    for line in listing
        .lines()
        .filter(|line| line.starts_with("-A FORWARD "))
    {
        position += 1;
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let drops = tokens
            .windows(2)
            .any(|pair| pair[0] == "-j" && pair[1].eq_ignore_ascii_case("DROP"));
        if drops && rule_comment(line).is_some_and(|comment| comment.starts_with("qeli-nat:")) {
            last_managed_drop = position;
        }
    }
    last_managed_drop + 1
}

fn forward_permit_position(path: &str, budget: Budget) -> anyhow::Result<Option<usize>> {
    let output = budget.ipt(path, &["-t", "filter", "-S", "FORWARD"]);
    budget.check()?;
    Ok(output
        .ok()
        .filter(|o| o.status.success())
        .map(|o| forward_permit_position_from_listing(&String::from_utf8_lossy(&o.stdout))))
}

fn owned_rules() -> &'static Mutex<crate::nat_owned_rules::Registry> {
    static REGISTRY: OnceLock<Mutex<crate::nat_owned_rules::Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Caller holds firewall_program_lock, including while recording/retrying ownership.
fn retry_owned_rules(profile: Option<&str>, budget: Budget) -> anyhow::Result<()> {
    budget.lock(owned_rules())?.cleanup(profile, |rule| {
        journal::remove(rule, budget, || remove_exact(rule, budget))
    })
}

fn remove_exact(rule: &crate::nat_owned_rules::Rule, budget: Budget) -> anyhow::Result<()> {
    let path = budget
        .find(rule.ipv6)?
        .ok_or_else(|| anyhow::anyhow!("firewall tool unavailable; exact ownership retained"))?;
    cleanup_exact_rules_with(
        &rule.table,
        &rule.chain,
        [("managed rule", rule.args.as_slice())],
        |args| budget.ipt(&path, args),
    )
}

/// Caller holds the firewall lock. Failed admission never reaches a mutation.
fn install_rule(
    profile: &str,
    ipv6: bool,
    path: &str,
    rule: &Rule,
    budget: Budget,
) -> anyhow::Result<bool> {
    budget.check()?;
    let insert = rule.table == "filter" && rule.chain == "FORWARD";
    let mut args = vec![
        "-t".to_string(),
        rule.table.to_string(),
        if insert { "-I" } else { "-A" }.to_string(),
        rule.chain.to_string(),
    ];
    if insert {
        let position = if rule_jumps_to(&rule.args, "DROP") {
            1
        } else {
            match forward_permit_position(path, budget)? {
                Some(position) => position,
                None => return Ok(false),
            }
        };
        args.push(position.to_string());
    }
    args.extend(rule.args.clone());
    let owned = crate::nat_owned_rules::Rule {
        ipv6,
        table: rule.table.into(),
        chain: rule.chain.into(),
        args: rule.args.clone(),
    };
    budget.lock(owned_rules())?.retain(profile, owned.clone())?;
    journal::apply(&owned, path, budget, || {
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        let _ = budget.ipt(path, &refs);
        budget.check()?;
        let mut check = vec!["-t", rule.table, "-C", rule.chain];
        check.extend(rule.args.iter().map(String::as_str));
        let present = budget
            .ipt(path, &check)
            .is_ok_and(|output| output.status.success());
        budget.check()?;
        Ok(present)
    })
}

/// Each setup is a profile startup boundary. On error the profile cannot continue;
/// release all its retained NAT rules, including earlier families, before returning.
/// Keep the firewall guard through rollback so a new setup cannot overtake retirement.
fn setup_operation<T>(
    profile: &str,
    budget: Budget,
    run: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = budget.lock(firewall_program_lock())?;
    let result = budget.checked(run);
    match result {
        Ok(value) => Ok(value),
        Err(error) => match rollback_setup_until(profile, Budget::for_operation("NAT rollback")) {
            Ok(()) => Err(error),
            Err(rollback) => Err(anyhow::anyhow!(
                "{error:#}; NAT rollback incomplete: {rollback:#}"
            )),
        },
    }
}

/// Caller holds firewall_program_lock. Every rollback command shares this budget.
fn rollback_setup_until(profile: &str, budget: Budget) -> anyhow::Result<()> {
    let mut errors = crate::nat_cleanup::Errors::default();
    errors.record("exact rules", retry_owned_rules(Some(profile), budget));
    errors.record("IPv6 sysctls", release_ipv6_sysctls_until(profile, budget));
    errors.record("deadline", budget.check().map_err(Into::into));
    errors.finish()
}

/// Install NAT for `profile`. Returns the chosen WAN interface on success.
pub fn setup(
    profile: &str,
    configured_iface: &str,
    pool_cidr: &str,
    tun: &str,
    peer_tuns: &[String],
    mtu: i32,
) -> anyhow::Result<String> {
    let budget = Budget::for_operation("NAT setup");
    setup_operation(profile, budget, || {
        let path = budget.find(false)?.ok_or_else(|| {
            anyhow::anyhow!(
            "`iptables` is not installed (apt install iptables) — required for routing.nat.enabled"
        )
        })?;
        // WAN: an explicit, non-default interface wins; otherwise auto-detect. The config
        // default "eth0" is treated as "auto" (it's just a placeholder).
        let wan = resolve_wan_until(configured_iface, false, true, budget)?.ok_or_else(|| {
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
        if !budget.checked(|| Ok(enable_ip_forward()))? {
            anyhow::bail!(
                "routing.nat.enabled = true but net.ipv4.ip_forward could not be enabled — the \
             kernel would not forward client traffic, so every client would connect and then \
             reach nothing. Enable it on the host (`sysctl -w net.ipv4.ip_forward=1`), or set \
             routing.nat.enabled = false"
            );
        }
        // Clear any stale copies first so a re-apply can't stack duplicates.
        cleanup_matching_until(&path, &tag(profile), true, budget);
        budget.check()?;

        let mss = (mtu - 40).max(536);
        let mut forward_unapplied = false;
        for r in rules(profile, &wan, tun, pool_cidr, peer_tuns, mss) {
            if !install_rule(profile, false, &path, &r, budget)? {
                if r.essential {
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
            match forward_policy(&path, budget)? {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': FORWARD ACCEPT rules could not be applied (host has a \
                 mixed legacy/nft filter table). The empty built-in chain has policy ACCEPT, so egress \
                 still works — but if you tighten it later, permit forwarding {pool_cidr} \
                 <-> {wan} yourself."
            ),
            status => {

                anyhow::bail!(
                    "the FORWARD ACCEPT rules could not be applied and the observed chain state is {} — client traffic between {pool_cidr} and {wan} may be dropped. Permit that forwarding yourself, fix the iptables backend, or set routing.nat.enabled = false",
                    status.as_ref().map_or("unknown", |value| value.summary())
                );
            }
        }
        }
        Ok(wan)
    })
}

fn ipv6_rules(
    profile: &str,
    wan: &str,
    tun: &str,
    pool_cidr: &str,
    peer_tuns: &[String],
    mss: i32,
    mode: crate::config::server::Ipv6RoutingMode,
) -> Vec<Rule> {
    if mode == crate::config::server::Ipv6RoutingMode::Manual {
        return Vec::new();
    }
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
    let mut rules = cross_profile_drop_rules(profile, tun, peer_tuns);
    if mode == crate::config::server::Ipv6RoutingMode::Nat66 {
        // A permissive host FORWARD chain (or a sibling route profile) must not
        // forward this profile's unmasqueraded packets through another uplink.
        // Match the TUN, not only pool_cidr: authenticated client_subnet traffic
        // must have the same NAT66 egress boundary. Route/manual have separate
        // routing contracts and intentionally receive no such guard.
        rules.push(Rule {
            table: "filter",
            chain: "FORWARD",
            args: annotate(vec![
                "-i".into(),
                tun.into(),
                "!".into(),
                "-o".into(),
                wan.into(),
                "-j".into(),
                "DROP".into(),
            ]),
            essential: true,
        });
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
    let outbound = if mode == crate::config::server::Ipv6RoutingMode::Route {
        // Route mode is the no-NAT site-to-site mode. The kernel route, not one selected
        // Internet uplink, decides whether a packet goes to the server LAN, WAN or another
        // operator-routed network. Same-TUN traffic stays in qeli's authenticated direct
        // forwarder and is deliberately not opened here.
        vec![
            "-i".into(),
            tun.into(),
            "!".into(),
            "-o".into(),
            tun.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    } else {
        vec![
            "-i".into(),
            tun.into(),
            "-o".into(),
            wan.into(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    };
    rules.push(Rule {
        table: "filter",
        chain: "FORWARD",
        args: annotate(outbound),
        essential: false,
    });
    let inbound = if mode == crate::config::server::Ipv6RoutingMode::Route {
        // The output interface is selected only by routes owned by this profile: its
        // connected pool plus authenticated dynamic client_subnet routes. Do not pin the
        // input to the WAN; that silently breaks a server-side LAN initiating to a client
        // LAN. Same-TUN traffic remains under the user-space client-to-client policy.
        vec![
            "!".into(),
            "-i".into(),
            tun.into(),
            "-o".into(),
            tun.into(),
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
/// kernel ACCEPT is needed here; fail closed in both transit directions while leaving local
/// INPUT/OUTPUT and same-TUN handling untouched.
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
    [
        vec![
            "-i".into(),
            tun.into(),
            "!".into(),
            "-o".into(),
            tun.into(),
            "-j".into(),
            "DROP".into(),
        ],
        vec![
            "!".into(),
            "-i".into(),
            tun.into(),
            "-o".into(),
            tun.into(),
            "-j".into(),
            "DROP".into(),
        ],
    ]
    .into_iter()
    .map(|args| Rule {
        table: "filter",
        chain: "FORWARD",
        args: annotate(args),
        essential: true,
    })
    .collect()
}

/// Configure native IPv6 forwarding for one profile. `route` preserves client source
/// addresses; `nat66` additionally applies MASQUERADE on the selected IPv6 uplink.
pub fn setup_ipv6(
    profile: &str,
    mode: crate::config::server::Ipv6RoutingMode,
    configured_iface: &str,
    pool_cidr: &str,
    tun: &str,
    peer_tuns: &[String],
    mtu: i32,
) -> anyhow::Result<Option<String>> {
    // run_profile has already removed this profile's old rules/sysctl leases through
    // cleanup(), including route/NAT66 -> manual transitions. Do not require a firewall
    // binary, install even DROP rules, or acquire router sysctls for an unmanaged profile.
    if mode == crate::config::server::Ipv6RoutingMode::Manual {
        return Ok(resolve_wan_ipv6(configured_iface));
    }
    let budget = Budget::for_operation("IPv6 routing setup");
    setup_operation(profile, budget, || {
        let path = budget.find(true)?.ok_or_else(|| {
        anyhow::anyhow!(
            "an IPv6 profile with routing.ipv6.mode = {mode} requires ip6tables so its egress boundary can be enforced"
        )
    })?;
        cleanup_matching_until(&path, &tag(profile), true, budget);
        budget.check()?;
        if mode == crate::config::server::Ipv6RoutingMode::Off {
            // Be correct even when a caller changes this profile from route/NAT66 to off
            // without first going through the outer cleanup wrapper: off owns no router
            // sysctls and must release its previous forwarding/accept_ra lease.
            release_ipv6_sysctls_until(profile, budget)?;
            // Verification is mandatory: falling back to a permissive FORWARD policy would be
            // the exact cross-profile leak this mode exists to prevent.
            for rule in ipv6_off_rules(profile, tun) {
                if !install_rule(profile, true, &path, &rule, budget)? {
                    anyhow::bail!(
                    "ip6tables could not enforce routing.ipv6.mode = off for profile '{profile}'; refusing an IPv6 plan that could inherit Internet forwarding"
                );
                }
            }
            return Ok(None);
        }
        let wan = resolve_wan_until(
            configured_iface,
            true,
            mode == crate::config::server::Ipv6RoutingMode::Nat66,
            budget,
        )?;
        if mode == crate::config::server::Ipv6RoutingMode::Nat66 && wan.is_none() {
            anyhow::bail!(
                "could not detect an IPv6 uplink for NAT66; set routing.ipv6.interface explicitly"
            );
        }
        let uplink_label = wan.as_deref().unwrap_or("<kernel routes>");
        acquire_ipv6_sysctls(profile, wan.as_deref(), tun, budget).map_err(|error| {
        anyhow::anyhow!(
            "routing.ipv6.mode = {mode} could not enable safe IPv6 forwarding via '{uplink_label}': {error}"
        )
    })?;
        // Auto-detection depends on the RA/default route that existed before forwarding was
        // enabled. Verify it survived the transition: otherwise rules below would be installed
        // for a stale uplink and the profile would ACK IPv6 while public traffic has no route.
        if configured_iface.trim().is_empty() {
            if let Some(expected_wan) = wan.as_deref() {
                match detect_wan_until(
                    true,
                    mode == crate::config::server::Ipv6RoutingMode::Nat66,
                    budget,
                )? {
                    Some(active_wan) if active_wan == expected_wan => {}
                    active_wan => {
                        anyhow::bail!(
                        "the auto-detected IPv6 uplink changed from '{expected_wan}' to '{}' after enabling forwarding; check accept_ra=2 and the host IPv6 default route",
                        active_wan.as_deref().unwrap_or("none")
                    );
                    }
                }
            }
        }
        let wan_for_rules = wan.as_deref().unwrap_or("");
        let mut forward_unapplied = false;
        for rule in ipv6_rules(
            profile,
            wan_for_rules,
            tun,
            pool_cidr,
            peer_tuns,
            (mtu - 60).max(1220),
            mode,
        ) {
            if !install_rule(profile, true, &path, &rule, budget)? {
                if rule.essential {
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
            match forward_policy(&path, budget)? {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': IPv6 FORWARD permit rules could not be verified; \
                 the empty built-in chain has policy ACCEPT. Ensure {pool_cidr} can forward between \
                 {tun} and {uplink_label}."
            ),
            status => {

                anyhow::bail!(
                    "qeli could not install IPv6 FORWARD permit rules and the observed chain state is {}; refusing a profile that may black-hole forwarded traffic",
                    status.as_ref().map_or("unknown", |value| value.summary())
                );
            }
        }
        }
        Ok(Some(wan.unwrap_or_default()))
    })
}

/// The `filter/FORWARD` chain's default policy plus whether it contains explicit rules, or
/// `None` when it cannot be read. `iptables -S FORWARD` opens with `-P FORWARD DROP`.
fn forward_policy(path: &str, budget: Budget) -> anyhow::Result<Option<ChainPolicy>> {
    let output = budget.ipt(path, &["-t", "filter", "-S", "FORWARD"]);
    budget.check()?;
    Ok(output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| chain_policy_from_output(&o.stdout, "FORWARD")))
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

fn dns_input_registry() -> &'static Mutex<DnsInputRegistry> {
    static REGISTRY: OnceLock<Mutex<DnsInputRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(DnsInputRegistry::default()))
}

/// Caller holds firewall_program_lock; this function must not re-enter the registry.
fn cleanup_dns_rules_until(owned: &DnsInputRules, budget: Budget) -> anyhow::Result<()> {
    let mut errors = crate::nat_cleanup::Errors::default();
    for args in &owned.rules {
        let rule = crate::nat_owned_rules::Rule {
            ipv6: owned.ipv6,
            table: "filter".into(),
            chain: "INPUT".into(),
            args: args.clone(),
        };
        errors.record(
            "DNS INPUT",
            journal::remove(&rule, budget, || remove_exact(&rule, budget)),
        );
    }
    errors.finish()
}

/// Caller holds firewall_program_lock. Failed records stay in the registry for retry.
fn retry_dns_input(profile: Option<&str>, budget: Budget) -> anyhow::Result<()> {
    budget
        .lock(dns_input_registry())?
        .retry(profile, |owned| cleanup_dns_rules_until(owned, budget))
}

fn release_ipv6_sysctls_until(profile: &str, budget: Budget) -> anyhow::Result<()> {
    budget
        .lock(ipv6_sysctl_leases())?
        .release(profile, |scope| {
            budget.checked(|| crate::sysctl::release_scope(scope))
        })
}

/// A generation token for its exact DNS INPUT rules. The worker registry owns the
/// specifications, so destroying this lease cannot discard failed cleanup evidence.
/// Every kernel mutation also reserves its exact specification in the durable worker journal.
#[derive(Debug)]
pub(crate) struct DnsInputLease {
    owner: Option<DnsInputOwner>,
    profile: String,
}

impl DnsInputLease {
    fn cleanup(&mut self) -> anyhow::Result<()> {
        self.cleanup_until(Budget::for_operation("DNS INPUT cleanup"))
    }
    fn cleanup_until(&mut self, budget: Budget) -> anyhow::Result<()> {
        let Some(owner) = self.owner.as_ref() else {
            return Ok(());
        };
        // Publish before ANY fallible lock admission. Dropping the token also retires it,
        // so timeout/unwind never strands an active record without a living lease.
        owner.retire();
        let _firewall_guard = budget.lock(firewall_program_lock())?;
        budget
            .lock(dns_input_registry())?
            .finish(owner.id(), |owned| cleanup_dns_rules_until(owned, budget))?;
        self.owner = None;
        budget.check()?;
        Ok(())
    }
}

impl Drop for DnsInputLease {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            log::error!("Profile '{}': {error}; exact DNS INPUT ownership retained for retry in this worker", self.profile);
        }
    }
}

/// Permit only this profile's clients to reach its in-process DNS proxy.
///
/// Full-tunnel traffic normally crosses `FORWARD`, but the pushed resolver is the server's
/// own TUN address and therefore crosses `INPUT`. Keep the exception narrow: exact interface,
/// client pool, resolver address and port, for both DNS transports.
#[cfg(test)]
pub(crate) fn enable_dns_input(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
) -> anyhow::Result<DnsInputLease> {
    enable_dns_input_until(
        profile,
        tun,
        pool_cidr,
        listen,
        port,
        Budget::for_operation("DNS INPUT setup"),
    )
}

fn enable_dns_input_until(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
    budget: Budget,
) -> anyhow::Result<DnsInputLease> {
    budget.check()?;
    // Outer ownership outlives the inner lock scope: a setup error drops the lock
    // before the lease retries exact cleanup, avoiding recursive mutex acquisition.
    let lease;
    {
        let _firewall_guard = budget.lock(firewall_program_lock())?;
        let owned = DnsInputRules::new(profile, tun, pool_cidr, listen, port)?;
        let tool = if owned.ipv6 { "ip6tables" } else { "iptables" };
        let path = budget.find(owned.ipv6)?.ok_or_else(|| {
            anyhow::anyhow!(
                "{tool} is required to verify INPUT access to DNS {listen}:{port} on {tun}"
            )
        })?;
        let owner = budget
            .lock(dns_input_registry())?
            .begin_owned(owned, |pending| cleanup_dns_rules_until(pending, budget))?;
        lease = DnsInputLease {
            owner: Some(owner),
            profile: profile.to_string(),
        };
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
            let saved = crate::nat_owned_rules::Rule {
                ipv6: listen.parse::<std::net::IpAddr>()?.is_ipv6(),
                table: "filter".into(),
                chain: "INPUT".into(),
                args: args.clone(),
            };
            let applied = journal::apply(&saved, &path, budget, || {
                let _ = budget.ipt(&path, &refs);
                budget.check()?;
                let mut check = vec!["-t", "filter", "-C", "INPUT"];
                check.extend(args.iter().map(String::as_str));
                let present = budget
                    .ipt(&path, &check)
                    .is_ok_and(|output| output.status.success());
                budget.check()?;
                Ok(present)
            })?;
            if !applied {
                unapplied.push(proto);
            }
        }
        if !unapplied.is_empty() {
            let status = budget
                .ipt(&path, &["-t", "filter", "-S", "INPUT"])
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| chain_policy_from_output(&output.stdout, "INPUT"));
            budget.check()?;
            if status
                .as_ref()
                .is_some_and(|value| value.unconditionally_accepts)
            {
                log::warn!(
                "Profile '{profile}': DNS INPUT rule(s) for {} could not be verified, but the \
                 empty built-in chain has policy ACCEPT. If you tighten it later, permit {listen}:{port} \
                 from {pool_cidr} on {tun} yourself.",
                unapplied.join("+")
            );
            } else {
                // The already-armed lease rolls back after the firewall lock is released.
                anyhow::bail!(
                    "could not install DNS INPUT rule(s) for {} on {} and the observed INPUT \
                 chain state is {} - clients would receive {} as their resolver but queries may \
                 be firewalled",
                    unapplied.join("+"),
                    tun,
                    status.as_ref().map_or("unknown", |value| value.summary()),
                    listen
                );
            }
        }
        budget.check()?;
        log::info!(
        "Profile '{profile}': DNS INPUT permit {pool_cidr} via {tun} -> {listen}:{port}, udp+tcp"
    );
    }
    Ok(lease)
}

/// DNS follows the same IPv6 firewall ownership as transit. In manual mode the
/// administrator permits INPUT and, for a nonstandard dns.port, redirects port 53.
/// IPv4 DNS keeps its existing independently configured behavior in dual-stack profiles.
pub(crate) fn setup_dns_firewall(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
    ipv6_mode: crate::config::server::Ipv6RoutingMode,
) -> anyhow::Result<Option<DnsInputLease>> {
    let ipv6 = listen.parse::<std::net::IpAddr>()?.is_ipv6();
    if ipv6 && ipv6_mode == crate::config::server::Ipv6RoutingMode::Manual {
        log::info!("Profile '{profile}': IPv6 DNS {listen}:{port} uses administrator-managed INPUT and port-53 delivery");
        return Ok(None);
    }
    let budget = Budget::for_operation("DNS firewall setup");
    let lease = enable_dns_input_until(profile, tun, pool_cidr, listen, port, budget)?;
    enable_dns_redirect_until(profile, tun, listen, port, budget)?;
    Ok(Some(lease))
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
pub fn enable_routing(
    profile: &str,
    tun: &str,
    peer_tuns: &[String],
    mtu: i32,
) -> anyhow::Result<()> {
    let budget = Budget::for_operation("IPv4 routing setup");
    setup_operation(profile, budget, || {
        // Same invariant as `setup`, for the same reason: `forward_private` promises the server
        // ROUTES transit traffic, and without `ip_forward` the kernel drops every transit packet
        // whatever the rules say. This used to be ignored entirely — the function returned `()`
        // and logged success unconditionally — so a profile came up "routing" while nothing was
        // forwarded. (Audit 2026-08-01, §5.)
        if !budget.checked(|| Ok(enable_ip_forward()))? {
            anyhow::bail!(
            "routing.forward_private = true but net.ipv4.ip_forward could not be enabled — the \
             kernel would not route anything between the tunnel and your networks. Enable it on \
             the host (`sysctl -w net.ipv4.ip_forward=1`), or unset routing.forward_private"
        );
        }
        let path = budget.find(false)?.ok_or_else(|| {
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
        for rule in cross_profile_drop_rules(profile, tun, peer_tuns) {
            if !install_rule(profile, false, &path, &rule, budget)? {
                anyhow::bail!("could not enforce cross-profile isolation for {tun}");
            }
        }
        // MSS-clamp forwarded TCP (PMTU black-hole guard), then permit tun<->anywhere routing.
        let mut forward_unapplied = false;
        let mut mss_unapplied = false;
        for (table, chain, args) in [mss_rule("-o"), mss_rule("-i"), accept("-i"), accept("-o")] {
            let insert = table == "filter" && chain == "FORWARD";
            let rule = Rule {
                table,
                chain,
                args: args.clone(),
                essential: false,
            };
            // VERIFY instead of assuming. The whole set was applied with `let _ =` and then
            // reported as success, so a host that refused every rule still logged "FORWARD ACCEPT
            // for tun0" — the operator had no way to tell routing from silence.
            if !install_rule(profile, false, &path, &rule, budget)? {
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
            match forward_policy(&path, budget)? {
            Some(status) if status.unconditionally_accepts => log::warn!(
                "Profile '{profile}': forward_private — explicit FORWARD permits could not be \
                 applied, but the empty built-in chain has policy ACCEPT. If you tighten it later, permit \
                 {tun} yourself."
            ),
            status => {

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
    })
}

/// Redirect in-tunnel DNS from the standard port 53 to where the proxy actually listens.
///
/// `dns.port` exists so the proxy can dodge a host service already holding 53 (dnsmasq,
/// Pi-hole and friends bind `0.0.0.0:53`, which covers the TUN address too). But the port was
/// then pushed to clients whose platform resolver APIs accept only an IP address.
/// Linux can apply custom ports through SetLinkDNSEx, but that capability does not
/// change the portable server-pushed contract: clients use 53 on the tunnel address.
///
/// Splitting the two settings fixes it properly: the proxy keeps its odd port, clients are
/// told the only port they can express — 53 — and the kernel bridges the gap here. A no-op
/// when the proxy already listens on 53.
///
/// Tagged with the same per-profile comment as every other rule, so [`cleanup`] removes it
/// with the rest when the profile stops.
fn enable_dns_redirect_until(
    profile: &str,
    tun: &str,
    listen: &str,
    port: u16,
    budget: Budget,
) -> anyhow::Result<()> {
    budget.check()?;
    if port == 53 {
        return Ok(()); // nothing to bridge
    }
    setup_operation(profile, budget, || {
        let ipv6 = listen.parse::<std::net::IpAddr>()?.is_ipv6();
        let tool = if ipv6 { "ip6tables" } else { "iptables" };
        let path = budget.find(ipv6)?.ok_or_else(|| {
            anyhow::anyhow!("Profile '{profile}': dns.port = {port} requires {tool} REDIRECT")
        })?;
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
            let rule = Rule {
                table: "nat",
                chain: "PREROUTING",
                args,
                essential: true,
            };
            if !install_rule(profile, ipv6, &path, &rule, budget)? {
                anyhow::bail!(
                "Profile '{profile}': FAILED to install the DNS redirect {listen}:53/{proto} -> \
                 :{port} on {tun}. Clients would be handed a resolver they cannot reach — set \
                 dns.port = 53, or fix iptables."
            );
            }
        }
        log::info!(
            "Profile '{profile}': DNS redirect {listen}:53 -> :{port} on {tun}, udp+tcp \
         (clients are told 53; the proxy listens on {port})"
        );
        Ok(())
    })
}

/// Sweep historical tags, then verify every exact specification retained by this worker.
/// Missing tools are an error when rules remain owned; an unmanaged profile is a no-op.
pub fn cleanup(profile: &str) -> anyhow::Result<()> {
    cleanup_until(profile, Budget::new())
}

fn cleanup_until(profile: &str, budget: Budget) -> anyhow::Result<()> {
    let _firewall_guard = budget.lock(firewall_program_lock())?;
    let mut errors = crate::nat_cleanup::Errors::default();
    errors.record("DNS INPUT", retry_dns_input(Some(profile), budget));
    for ipv6 in [false, true] {
        errors.record(
            "tag sweep admission",
            (|| {
                if let Some(path) = budget.find(ipv6)? {
                    cleanup_matching_until(&path, &tag(profile), true, budget);
                }
                budget.check().map_err(Into::into)
            })(),
        );
    }
    errors.record(
        "exact NAT/routing rules",
        retry_owned_rules(Some(profile), budget),
    );
    errors.record("IPv6 sysctls", release_ipv6_sysctls_until(profile, budget));
    errors.record("deadline", budget.check().map_err(Into::into));
    errors.finish()
}

/// Final verification of resources whose exact ownership is retained by this worker.
/// Call only AFTER all profile supervisors have stopped and the generic tag sweeps ran.
/// Includes NAT/routing/DNS redirects; historical rules without a saved spec need the tag sweep.
pub(crate) fn finish_owned_cleanup() -> anyhow::Result<()> {
    finish_owned_cleanup_until(Budget::new(), || {
        crate::sysctl::release_scope("server-ipv4")
    })
}

fn finish_owned_cleanup_until(
    budget: Budget,
    release_ipv4: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let _firewall_guard = budget.lock(firewall_program_lock())?;
    let profiles = budget.lock(ipv6_sysctl_leases())?.profiles();
    let mut errors = crate::nat_cleanup::Errors::default();
    errors.record("exact NAT/routing rules", retry_owned_rules(None, budget));
    errors.record(
        "DNS and IPv6 sysctls",
        crate::nat_cleanup::finish_owned_cleanup_with(
            || {
                budget
                    .lock(dns_input_registry())?
                    .finish_shutdown(|owned| cleanup_dns_rules_until(owned, budget))
            },
            &profiles,
            |profile| release_ipv6_sysctls_until(profile, budget),
        ),
    );
    errors.record("IPv4 forwarding", budget.checked(release_ipv4));
    errors.record("deadline", budget.check().map_err(Into::into));
    errors.finish()
}

/// Restore a killed worker's host-wide IPv6 sysctls, then remove EVERY qeli-managed NAT rule
/// (`qeli-nat:*`, any profile). Called once at worker startup so rules left behind by a profile
/// that has since been REMOVED from the config do not leak forever. Active profiles
/// reinstall their rules afterwards. Non-deadline historical sweep failures remain warnings.
pub fn cleanup_all() -> anyhow::Result<()> {
    let budget = Budget::new();
    {
        let _guard = budget.lock(firewall_program_lock())?;
        // Before sysctl recovery, tag sweeps or any new profiles. A failure retains
        // exact state and aborts startup; it is never downgraded to a sweep warning.
        journal::initialize(budget, |rule| remove_exact(rule, budget))?;
    }
    cleanup_all_until(budget, crate::sysctl::recover)
}

fn cleanup_all_until(
    budget: Budget,
    recover: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let _firewall_guard = budget.lock(firewall_program_lock())?;
    if let Err(error) = retry_dns_input(None, budget) {
        log::error!("DNS INPUT retry incomplete: {error}");
    }
    budget.checked(recover)?;
    for ipv6 in [false, true] {
        if let Some(path) = budget.find(ipv6)? {
            cleanup_matching_until(&path, "qeli-nat:", false, budget);
        }
    }
    budget.check()?;
    Ok(())
}

fn cleanup_matching_until(path: &str, needle: &str, exact: bool, budget: Budget) {
    // Historical tag sweeps remain best effort for mixed nft compatibility. The caller
    // checks the shared deadline separately and cannot report a timed-out attempt as success.
    if let Err(error) = cleanup_matching_with(needle, exact, |args| budget.ipt(path, args)) {
        log::warn!("NAT cleanup via {path} for '{needle}' incomplete: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        chain_policy_from_output, cross_profile_drop_rules, dns_input_rule, exact_delete_args,
        forward_permit_position_from_listing, ipv6_off_rules, ipv6_rules, resolve_wan_ipv6,
        rule_comment, rules, tag,
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
    fn switching_to_manual_removes_only_the_previous_profiles_rules() {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;
        for previous in [
            Ipv6RoutingMode::Off,
            Ipv6RoutingMode::Route,
            Ipv6RoutingMode::Nat66,
        ] {
            let mut rules = if previous == Ipv6RoutingMode::Off {
                ipv6_off_rules("edge", "vpn0")
            } else {
                ipv6_rules(
                    "edge",
                    "ens3",
                    "vpn0",
                    "2001:db8:42::/64",
                    &[],
                    1340,
                    previous,
                )
            };
            // Include old DNS state, another profile with a prefix-sharing name, and an
            // administrator rule. Only exact ownership may be removed during the switch.
            rules.push(super::Rule {
                table: "filter",
                chain: "INPUT",
                args: dns_input_rule(
                    "edge",
                    "vpn0",
                    "2001:db8:42::/64",
                    "2001:db8:42::1",
                    53,
                    "udp",
                ),
                essential: true,
            });
            rules.push(super::Rule {
                table: "filter",
                chain: "FORWARD",
                args: vec![
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    "qeli-nat:edge2".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ],
                essential: true,
            });
            rules.push(super::Rule {
                table: "filter",
                chain: "FORWARD",
                args: vec![
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    "administrator".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ],
                essential: true,
            });
            super::cleanup_matching_with(&tag("edge"), true, |args| {
                let mut stdout = String::new();
                match args[2] {
                    "-S" => {
                        for rule in rules
                            .iter()
                            .filter(|rule| rule.table == args[1] && rule.chain == args[3])
                        {
                            stdout.push_str(&format!(
                                "-A {} {}\n",
                                rule.chain,
                                rule.args.join(" ")
                            ));
                        }
                    }
                    "-D" => {
                        let index = rules
                            .iter()
                            .position(|rule| {
                                rule.table == args[1]
                                    && rule.chain == args[3]
                                    && rule
                                        .args
                                        .iter()
                                        .map(String::as_str)
                                        .eq(args[4..].iter().copied())
                            })
                            .unwrap();
                        rules.remove(index);
                    }
                    _ => panic!("cleanup must never install a rule"),
                }
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: stdout.into_bytes(),
                    stderr: Vec::new(),
                })
            })
            .unwrap();
            assert_eq!(rules.len(), 2, "{previous}");
            assert!(rules[0].args.iter().any(|arg| arg == "qeli-nat:edge2"));
            assert!(rules[1].args.iter().any(|arg| arg == "administrator"));
        }
    }

    #[test]
    fn manual_ipv6_and_dns_do_not_require_host_firewall_or_sysctls() {
        // The explicit link needs no command or host interface. A managed mode would
        // attempt ip6tables/sysctl before returning and fail on an unprivileged runner.
        assert_eq!(
            super::setup_ipv6(
                "manual-test",
                Ipv6RoutingMode::Manual,
                "fixture-uplink",
                "2001:db8:42::/64",
                "fixture-tun",
                &[],
                1400
            )
            .unwrap()
            .as_deref(),
            Some("fixture-uplink")
        );
        for port in [53, 5353] {
            assert!(super::setup_dns_firewall(
                "manual-test",
                "fixture-tun",
                "2001:db8:42::/64",
                "2001:db8:42::1",
                port,
                Ipv6RoutingMode::Manual
            )
            .unwrap()
            .is_none());
        }
        assert!(ipv6_rules(
            "manual-test",
            "fixture-uplink",
            "fixture-tun",
            "2001:db8:42::/64",
            &["sibling-tun".into()],
            1340,
            Ipv6RoutingMode::Manual
        )
        .is_empty());
    }

    #[test]
    fn ndp_interface_selection_is_independent_from_managed_egress() {
        assert_eq!(
            super::resolve_ndp_interface(" ens3 ", "ens4", "eth0").as_deref(),
            Some("ens3")
        );
        assert_eq!(
            super::resolve_ndp_interface("", "ens4", "eth0").as_deref(),
            Some("ens4")
        );
        assert_eq!(
            super::resolve_ndp_interface("", "", " eth0 ").as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn ipv6_off_is_an_essential_bidirectional_transit_drop() {
        let rules = ipv6_off_rules("isolated", "qeli6");
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| rule.essential));
        assert!(rules
            .iter()
            .all(|rule| rule.table == "filter" && rule.chain == "FORWARD"));
        assert!(rules
            .iter()
            .any(|rule| has_sequence(&rule.args, &["-i", "qeli6", "!", "-o", "qeli6"])));
        assert!(rules
            .iter()
            .any(|rule| has_sequence(&rule.args, &["!", "-i", "qeli6", "-o", "qeli6"])));
        // The boundary is the authenticated profile TUN, not only its address pool.
        // A client may legitimately source traffic from an operator-approved
        // `client_subnet`; mode=off must keep that routed prefix from inheriting host-wide
        // forwarding just as strictly as a pool address.
        assert!(rules
            .iter()
            .all(|rule| !rule.args.iter().any(|value| value == "-s")));
        assert!(rules
            .iter()
            .all(|rule| has_sequence(&rule.args, &["-j", "DROP"])));
        assert!(rules
            .iter()
            .all(|rule| !rule.args.iter().any(|value| value == "ACCEPT")));
    }

    #[test]
    fn routed_ipv6_uses_the_profiles_kernel_routes_bidirectionally() {
        let rules = ipv6_rules(
            "routed",
            "",
            "qeli6",
            "2001:db8:42::/64",
            &[],
            1340,
            Ipv6RoutingMode::Route,
        );
        assert!(!rules.iter().any(|rule| rule.table == "nat"));
        assert!(rules
            .iter()
            .all(|rule| !rule.args.iter().any(String::is_empty)));
        let outbound = rules
            .iter()
            .find(|rule| has_sequence(&rule.args, &["-i", "qeli6", "!", "-o", "qeli6"]))
            .expect("route mode needs an outbound routed permit");
        assert!(has_sequence(&outbound.args, &["-j", "ACCEPT"]));
        let inbound = rules
            .iter()
            .find(|rule| has_sequence(&rule.args, &["!", "-i", "qeli6", "-o", "qeli6"]))
            .expect("route mode needs an inbound routed permit");
        assert!(has_sequence(&inbound.args, &["-j", "ACCEPT"]));
        assert!(!inbound.args.iter().any(|value| value == "--state"));
        assert!(!inbound.args.iter().any(|value| value == "-d"));
    }

    #[test]
    fn cross_profile_isolation_is_bidirectional_and_deduplicated() {
        let rules = cross_profile_drop_rules(
            "edge",
            "qeli0",
            &[
                "qeli1".to_string(),
                " qeli1 ".to_string(),
                "qeli0".to_string(),
                String::new(),
            ],
        );
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| rule.essential));
        assert!(rules
            .iter()
            .any(|rule| has_sequence(&rule.args, &["-i", "qeli0", "-o", "qeli1", "-j", "DROP"])));
        assert!(rules
            .iter()
            .any(|rule| has_sequence(&rule.args, &["-i", "qeli1", "-o", "qeli0", "-j", "DROP"])));
    }

    #[test]
    fn broad_permits_are_placed_below_every_managed_drop() {
        let listing = "\
-P FORWARD ACCEPT
-A FORWARD -i lan0 -j ACCEPT
-A FORWARD -i qeli0 -o qeli1 -j DROP -m comment --comment qeli-nat:a
-A FORWARD -i hostile0 -j DROP
-A FORWARD -i qeli2 -o qeli3 -m comment --comment qeli-nat:b -j DROP
-A FORWARD -i lan1 -j ACCEPT
";
        assert_eq!(forward_permit_position_from_listing(listing), 5);
    }

    #[test]
    fn nat44_drops_public_off_uplink_transit_but_spares_private_lan() {
        let rules = rules("nat44", "wan0", "qeli4", "10.73.0.0/24", &[], 1340);
        let guard = rules
            .iter()
            .find(|rule| has_sequence(&rule.args, &["-i", "qeli4", "!", "-o", "wan0"]))
            .expect("NAT44 must guard public off-uplink transit");
        assert_eq!((guard.table, guard.chain), ("filter", "FORWARD"));
        assert!(guard.essential);
        assert!(has_sequence(&guard.args, &["-j", "DROP"]));
        assert!(!guard.args.iter().any(|value| value == "-s"));
        for range in [
            "10.0.0.0-10.255.255.255",
            "172.16.0.0-172.31.255.255",
            "192.168.0.0-192.168.255.255",
        ] {
            assert!(has_sequence(&guard.args, &["!", "--dst-range", range]));
        }
        assert!(guard.args.iter().any(|value| value == "qeli-nat:nat44"));
    }

    #[test]
    fn nat66_drops_off_uplink_transit_before_host_permits() {
        let rules = ipv6_rules(
            "nat66",
            "wan6",
            "qeli6",
            "fd71:e1:42::/64",
            &[],
            1340,
            Ipv6RoutingMode::Nat66,
        );
        let guard = rules
            .iter()
            .find(|rule| {
                has_sequence(
                    &rule.args,
                    &["-i", "qeli6", "!", "-o", "wan6", "-j", "DROP"],
                )
            })
            .expect("NAT66 must prevent unmasqueraded off-uplink transit");
        assert!(guard.essential);
        assert_eq!((guard.table, guard.chain), ("filter", "FORWARD"));
        assert!(!guard.args.iter().any(|value| value == "-s"));
        assert!(guard.args.iter().any(|value| value == "qeli-nat:nat66"));
        assert!(!ipv6_rules(
            "route",
            "wan6",
            "qeli6",
            "2001:db8:42::/64",
            &[],
            1340,
            Ipv6RoutingMode::Route,
        )
        .iter()
        .any(|rule| has_sequence(&rule.args, &["!", "-o", "wan6", "-j", "DROP"])));
    }

    #[test]
    fn nat66_keeps_unsolicited_inbound_closed() {
        let rules = ipv6_rules(
            "nat66",
            "wan6",
            "qeli6",
            "fd71:e1:42::/64",
            &[],
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

    #[test]
    fn managed_nat_auto_wan_never_uses_one_destination_after_incomplete_listing() {
        use crate::system_command::test_support::{with_commands, Action};
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;
        use std::process::{ExitStatus, Output};

        for ipv6 in [false, true] {
            for listing in ["", "default via 192.0.2.1 metric broken\n"] {
                let listing = listing.as_bytes().to_vec();
                let result = with_commands(
                    move |command| {
                        let args = crate::system_command::test_support::arguments(command);
                        assert!(args.ends_with(&["route".into(), "show".into(), "default".into()]));
                        Action::Reply(Ok(Output {
                            status: ExitStatus::from_raw(0),
                            stdout: listing.clone(),
                            stderr: Vec::new(),
                        }))
                    },
                    || {
                        super::resolve_wan_until(
                            "",
                            ipv6,
                            true,
                            super::Budget::for_operation("managed auto-WAN test"),
                        )
                    },
                );
                let error = result.unwrap_err();
                assert!(error
                    .to_string()
                    .contains("cannot verify a unique default WAN"));
            }
            let result = with_commands(
                |command| {
                    let args = crate::system_command::test_support::arguments(command);
                    assert!(args.ends_with(&["route".into(), "show".into(), "default".into()]));
                    Action::Reply(Err(std::io::ErrorKind::NotFound.into()))
                },
                || {
                    super::resolve_wan_until(
                        "",
                        ipv6,
                        true,
                        super::Budget::for_operation("managed auto-WAN test"),
                    )
                },
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("ip route show default failed"));
        }
    }

    #[test]
    fn routed_ipv6_keeps_policy_route_get_fallback() {
        use crate::system_command::test_support::{with_commands, Action};
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(windows)]
        use std::os::windows::process::ExitStatusExt;
        use std::process::{ExitStatus, Output};

        let selected = with_commands(
            |command| {
                let args = crate::system_command::test_support::arguments(command);
                let stdout = if args.ends_with(&["route".into(), "show".into(), "default".into()]) {
                    String::new()
                } else {
                    assert!(args.iter().any(|arg| arg == "get"));
                    "2606:4700:4700::1111 via fe80::1 dev lo src ::1\n".into()
                };
                Action::Reply(Ok(Output {
                    status: ExitStatus::from_raw(0),
                    stdout: stdout.into_bytes(),
                    stderr: Vec::new(),
                }))
            },
            || {
                super::resolve_wan_until(
                    "",
                    true,
                    false,
                    super::Budget::for_operation("route-mode fallback test"),
                )
            },
        )
        .unwrap();
        assert_eq!(selected.as_deref(), Some("lo"));
    }

    #[test]
    fn managed_wan_must_exist_in_the_calling_namespace() {
        let missing = "qeli-miss0";
        assert_eq!(crate::network_interface::index(missing).unwrap(), None);
        for ipv6 in [false, true] {
            let error = super::resolve_wan_until(
                missing,
                ipv6,
                false,
                super::Budget::for_operation("WAN presence test"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("absent"), "{error}");
            assert_eq!(
                super::resolve_wan_until(
                    "lo",
                    ipv6,
                    false,
                    super::Budget::for_operation("WAN presence test"),
                )
                .unwrap()
                .as_deref(),
                Some("lo")
            );
        }
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
        let spaced = "-A FORWARD -o t -m comment --comment \"qeli-nat:branch office\" -j ACCEPT";
        assert_eq!(
            rule_comment(spaced).as_deref(),
            Some("qeli-nat:branch office")
        );
        let escaped = "-A FORWARD -m comment --comment \"qeli-nat:branch \\\"office\\\"\" -j DROP";
        assert_eq!(
            rule_comment(escaped).as_deref(),
            Some("qeli-nat:branch \"office\"")
        );
        assert_eq!(rule_comment("--comment \"unterminated"), None);
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

    #[test]
    fn exact_dns_cleanup_replays_the_owned_rule_without_listing_the_chain() {
        let rule = dns_input_rule("udp-obfs", "vpn8", "10.9.8.0/24", "10.9.8.1", 53, "udp");
        assert_eq!(
            exact_delete_args("filter", "INPUT", &rule),
            [
                "-t",
                "filter",
                "-D",
                "INPUT",
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

#[cfg(test)]
#[path = "nat/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "nat/cleanup_budget_tests.rs"]
mod cleanup_budget_tests;

#[cfg(test)]
#[path = "nat/dns_input_budget_tests.rs"]
mod dns_input_budget_tests;
#[cfg(test)]
#[path = "nat/test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "nat/setup_budget_tests.rs"]
mod setup_budget_tests;
