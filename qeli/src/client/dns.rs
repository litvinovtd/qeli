//! Client DNS management with lifecycle-safe per-link configuration.
//!
//! The hard requirement: *never* leave the system pointing at the tunnel
//! resolver after the tunnel is gone. New connections therefore only install
//! DNS through systemd-resolved's per-link API: deleting the tunnel link also
//! deletes its DNS state after SIGKILL, power loss, or uninstall.
//!
//! Old resolver snapshots lack namespace and current-file ownership. Preserve them
//! for administrator recovery; neither startup nor new sessions write resolv.conf.

use crate::config::client::ClientDnsConfig;
use crate::transport_core::NetworkDns;
use std::path::Path;

const RESOLV_PATH: &str = "/etc/resolv.conf";
const DNS_SETUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);
#[path = "dns/resolver_context.rs"]
mod resolver_context;
pub(crate) struct DnsLease {
    lease: crate::dns_lease::Lease,
    resolver: resolver_context::Context,
}

fn current_scope() -> anyhow::Result<crate::dns_lease::Scope> {
    use std::os::unix::fs::MetadataExt;
    let net = std::fs::metadata("/proc/thread-self/ns/net")?;
    Ok(crate::dns_lease::Scope {
        boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_string(),
        device: net.dev(),
        inode: net.ino(),
        network_cookie: crate::network_namespace::cookie()?.ok_or_else(|| {
            anyhow::anyhow!(
                "DNS ownership requires SO_NETNS_COOKIE; refusing unscoped DNS mutation"
            )
        })?,
    })
}

fn target(
    link: &crate::dns_lease::Link,
    tun: &crate::tun::iface::TunInterface,
) -> anyhow::Result<Option<String>> {
    let scope = current_scope()?;
    let attached = tun.attached_link()?.map(|(_, index)| index);
    Ok(crate::dns_lease::command_target(link, &scope, attached)?.map(|index| index.to_string()))
}

impl DnsLease {
    pub(crate) fn restore(&mut self, tun: &crate::tun::iface::TunInterface) -> anyhow::Result<()> {
        let until = crate::operation_budget::limit(std::time::Instant::now() + DNS_SETUP_BUDGET);
        self.lease.cleanup(|link| {
            if let Some(index) = target(link, tun)? {
                revert_link_with(&index, Some(&self.resolver), until)?;
            }
            Ok(())
        })
    }
}

/// Apply exactly the resolver set already validated into the shared NetworkPlan.
/// Resolver selection and reachability routes belong to the core, for both IP families.
pub(crate) fn setup_network_plan_dns(
    config: &ClientDnsConfig,
    servers: &[NetworkDns],
    tun: &crate::tun::iface::TunInterface,
    owned: &mut Option<DnsLease>,
) -> anyhow::Result<()> {
    let until = crate::operation_budget::limit(std::time::Instant::now() + DNS_SETUP_BUDGET);
    if owned.is_some() {
        anyhow::bail!("DNS plan already owns a lease");
    }
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

    let resolver = resolver_context::Context::capture(until)?;
    let (name, index) = tun
        .attached_link()?
        .ok_or_else(|| anyhow::anyhow!("TUN disappeared before DNS setup"))?;
    let link = crate::dns_lease::Link {
        scope: current_scope()?,
        index,
        name,
    };
    let directory = crate::state_storage::default_state_dir();
    let lease = crate::dns_lease::Lease::acquire(&directory, link)
        .map_err(|e| anyhow::anyhow!("DNS ownership in {}: {e}", directory.display()))?;
    // Transfer ownership BEFORE the first resolver mutation, including partial failures.
    *owned = Some(DnsLease { lease, resolver });
    let lease = owned.as_ref().expect("lease just installed");
    apply_link_dns(
        config,
        || {
            target(lease.lease.link(), tun)?
                .ok_or_else(|| anyhow::anyhow!("TUN disappeared during DNS setup"))
        },
        &resolver_args,
        until,
        Some(&lease.resolver),
    )?;
    log::info!(
        "DNS set via systemd-resolved on ifindex {}: {}",
        index,
        resolver_args.join(", ")
    );
    Ok(())
}

#[cfg(test)]
fn revert_resolvectl_link(ifname: &str) -> anyhow::Result<()> {
    revert_link_with(ifname, None, std::time::Instant::now() + DNS_SETUP_BUDGET)
}
fn revert_link_with(
    ifname: &str,
    context: Option<&resolver_context::Context>,
    until: std::time::Instant,
) -> anyhow::Result<()> {
    if let Some(context) = context {
        context.verify(until)?;
    }
    execute_link_command(context, "revert", ifname, &[], until)?;
    if let Some(context) = context {
        context.verify(until)?;
    }
    Ok(())
}

/// Startup never reverts a live link from a durable marker alone. Only the generation
/// holding the original TUN descriptor and DNS lease may issue a resolver mutation.
pub fn recover_stale() -> anyhow::Result<()> {
    let root = crate::state_storage::default_state_dir();
    let directory = crate::dns_lease::Directory::existing(&root)?;
    let namespace = crate::network_namespace::Namespace::capture()?;
    let mut errors = Vec::new();
    let mut scope = None;
    if let Some(directory) = directory {
        // A PID-only holder list and an unscoped snapshot cannot authorize global DNS
        // recovery, even if every listed PID appears absent in this caller's namespace.
        directory.refuse_legacy_global()?;
        for entry in directory.entries()? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(error.to_string());
                    continue;
                }
            };
            let name = entry.file_name();
            let visible = root.join(&name);
            let name = name.to_string_lossy();
            if crate::dns_lease::is_legacy_marker(&name) {
                log::warn!("Legacy DNS v1 marker {} lacks namespace generation; retained for administrator recovery", visible.display());
                continue;
            }
            if crate::dns_lease::is_marker(&name) {
                if scope.is_none() {
                    scope = Some(current_scope()?);
                }
                match crate::dns_lease::recover_in(&directory, &entry.file_name(), scope.as_ref().expect("scope initialized"), |index| {
                    namespace.verify()?;
                    let present = index_exists(index)?;
                    namespace.verify()?;
                    Ok(present)
                }) {
                    Ok(crate::dns_lease::Recovery::Legacy) => log::warn!("Legacy DNS v1 marker {} lacks namespace generation; retained for administrator recovery", visible.display()),
                    Ok(crate::dns_lease::Recovery::Live) => log::warn!("DNS marker {} still names a live index; automatic revert cannot prove device ownership",visible.display()),
                    Ok(_) => {},
                    Err(error) => errors.push(format!("DNS marker {} retained: {error}",visible.display())),
                }
            } else if name.starts_with("dns-resolvectl-") {
                log::warn!("Legacy DNS marker {} retained for administrator recovery; a saved name is not ownership",visible.display());
            }
        }
    }
    if !errors.is_empty() {
        anyhow::bail!("DNS recovery failed: {}", errors.join("; "));
    }
    Ok(())
}

fn index_exists(index: u32) -> anyhow::Result<bool> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: libc writes at most IF_NAMESIZE bytes to this initialized buffer.
    if !unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENXIO) {
        return Ok(false);
    }
    Err(error.into())
}

// ── resolvectl ────────────────────────────────────────────────────────────

#[path = "dns/resolver_config.rs"]
mod resolver_config;

// The file proves the configured stub path; resolver_context separately verifies
// the bus, calling namespace and possible service receivers before mutation.
fn resolved_is_active() -> bool {
    resolver_config::uses_stub(Path::new(RESOLV_PATH))
}

/// Path to the `resolvectl` binary, if it is installed at all.
///
/// The decision to use the per-link path is made by [`resolved_is_active`], which asks a
/// different and more important question. Looked up by absolute path rather than via
/// `PATH`: the client runs from a
/// systemd unit whose environment may not carry a useful `PATH`.
#[cfg(test)]
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

#[cfg(test)]
fn resolver_command(context: Option<&resolver_context::Context>) -> crate::system_command::Command {
    let mut command =
        std::process::Command::new(which_resolvectl().unwrap_or_else(|| "resolvectl".into()));
    if let Some(context) = context {
        command.env("DBUS_SYSTEM_BUS_ADDRESS", context.address());
    }
    command.into()
}
fn execute_link_command(
    context: Option<&resolver_context::Context>,
    operation: &str,
    index: &str,
    values: &[String],
    until: std::time::Instant,
) -> anyhow::Result<()> {
    if let Some(context) = context {
        return context.apply(operation, index, values, until);
    }
    #[cfg(test)]
    {
        let output = resolver_command(None)
            .args([operation, index])
            .args(values)
            .output_until(until)?;
        anyhow::ensure!(
            output.status.success(),
            "resolvectl {operation} on {index} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
    #[cfg(not(test))]
    anyhow::bail!("verified resolver context is required for per-link DNS");
}

/// The `resolvectl domain` list for the tunnel link.
///
/// Shared with [`apply_link_dns`] so the decision can be tested without spawning anything —
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
    try_resolvectl_many(
        config,
        || Ok(ifname.to_string()),
        &[dns_addr.to_string()],
        std::time::Instant::now() + DNS_SETUP_BUDGET,
    )
    .is_ok()
}

#[cfg(test)]
fn try_resolvectl_many(
    config: &ClientDnsConfig,
    current_target: impl FnMut() -> anyhow::Result<String>,
    dns_addrs: &[String],
    until: std::time::Instant,
) -> anyhow::Result<()> {
    apply_link_dns(config, current_target, dns_addrs, until, None)
}

fn apply_link_dns(
    config: &ClientDnsConfig,
    mut current_target: impl FnMut() -> anyhow::Result<String>,
    dns_addrs: &[String],
    until: std::time::Instant,
    context: Option<&resolver_context::Context>,
) -> anyhow::Result<()> {
    let domains = routing_domains(config);
    for (operation, values) in [("dns", dns_addrs), ("domain", domains.as_slice())] {
        if values.is_empty() {
            continue;
        }
        if std::time::Instant::now() >= until {
            anyhow::bail!(
                "DNS setup command budget exhausted; generation rollback retains its DNS lease"
            );
        }
        // Recheck the original descriptor before each mutation; use its captured numeric
        // index so a rename does not redirect a later operation to a same-name replacement.
        if let Some(context) = context {
            context.verify(until)?;
        }
        let index = current_target()?;
        execute_link_command(context, operation, &index, values, until)?;
        if let Some(context) = context {
            context.verify(until)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

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
    /// Core DNS selection consults `servers` then the push and `fallback_servers`, so
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

    use std::path::PathBuf;

    /// Unique temp workspace per test.
    pub(super) struct Tmp(PathBuf);
    impl Tmp {
        pub(super) fn new(tag: &str) -> Self {
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
        pub(super) fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
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
            !rc.calls().contains("revert qtest"),
            "only the owning generation guard may revert partial state:\n{}",
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
            !rc.calls().contains("revert qtest"),
            "command failure must leave rollback to the generation guard:\n{}",
            rc.calls()
        );
    }
    #[test]
    fn identity_change_between_dns_and_domain_stops_further_commands() {
        let rc = Resolvectl::new("identity", &[]);
        let mut calls = 0;
        let result = try_resolvectl_many(
            &redirect_all(),
            || {
                calls += 1;
                if calls == 2 {
                    anyhow::bail!("original TUN disappeared");
                }
                Ok("42".to_string())
            },
            &["10.0.0.1".to_string()],
            std::time::Instant::now() + DNS_SETUP_BUDGET,
        );
        assert!(result.is_err());
        assert_eq!(rc.calls().trim(), "dns 42 10.0.0.1");
    }

    #[test]
    fn dns_and_domain_share_deadline_and_partial_lease_survives() {
        let rc = Resolvectl::new("shared-budget", &[]);
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in\n dns) sleep 0.15;;\n domain) sleep 0.70;;\nesac\nexit 0\n",
            rc.dir.join("calls.log").display()
        );
        std::fs::write(rc.dir.join("resolvectl"), script).unwrap();
        let mut lease = crate::dns_lease::Lease::acquire(
            &rc.dir,
            crate::dns_lease::Link {
                scope: crate::dns_lease::Scope {
                    boot: "00000000-0000-0000-0000-000000000001".into(),
                    device: 4,
                    inode: 42,
                    network_cookie: 123,
                },
                index: 42,
                name: "qtest".into(),
            },
        )
        .unwrap();
        let marker = std::fs::read_dir(&rc.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| crate::dns_lease::is_marker(p.file_name().unwrap().to_str().unwrap()))
            .unwrap();
        let original = std::fs::read(&marker).unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_millis(600);
        let result = try_resolvectl_many(
            &redirect_all(),
            || Ok("42".into()),
            &["10.0.0.1".into()],
            until,
        );
        assert!(
            result.is_err(),
            "two commands must not receive independent budgets"
        );
        assert!(rc.calls().contains("dns 42 10.0.0.1"));
        assert!(rc.calls().contains("domain 42 ~."));
        assert!(!rc.calls().contains("revert"));
        assert_eq!(std::fs::read(&marker).unwrap(), original);
        // Rollback is a separate owned operation with its own command deadline.
        lease.cleanup(|_| revert_resolvectl_link("42")).unwrap();
        assert!(rc.calls().contains("revert 42"));
        assert!(!marker.exists());
    }

    #[test]
    fn expired_dns_budget_starts_no_target_probe_or_command() {
        let rc = Resolvectl::new("expired-budget", &[]);
        let result = try_resolvectl_many(
            &redirect_all(),
            || panic!("expired operation must not probe the target"),
            &["10.0.0.1".into()],
            std::time::Instant::now(),
        );
        assert!(result.unwrap_err().to_string().contains("budget exhausted"));
        assert!(rc.calls().is_empty());
    }

    #[test]
    fn slow_target_probe_cannot_start_domain_after_shared_deadline() {
        let rc = Resolvectl::new("target-budget", &[]);
        let until = std::time::Instant::now() + std::time::Duration::from_millis(250);
        let mut probes = 0;
        let result = try_resolvectl_many(
            &redirect_all(),
            || {
                probes += 1;
                if probes == 2 {
                    std::thread::sleep(
                        until.saturating_duration_since(std::time::Instant::now())
                            + std::time::Duration::from_millis(10),
                    );
                }
                Ok("42".into())
            },
            &["10.0.0.1".into()],
            until,
        );
        assert!(result.is_err());
        assert_eq!(probes, 2);
        assert_eq!(rc.calls().trim(), "dns 42 10.0.0.1");
    }
}
