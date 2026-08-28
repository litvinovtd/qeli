use crate::config::client::ClientRoutingConfig;
#[cfg(feature = "experimental-roaming")]
use crate::transport_core::path::PreparedPathCandidate;
use crate::transport_core::{NetworkAddressFamily, NetworkPlan, NetworkRoute};
use std::net::IpAddr;

/// Routes this process actually CREATED on the physical interface, so cleanup removes
/// only those.
///
/// Cleanup used to `ip route del` the server address, every `exclude` subnet and the IPv6
/// blackholes unconditionally — but setup treats an existing route as a benign no-op
/// ("File exists"), so those are exactly the cases where the route was someone else's:
/// an operator's static bypass, a route another VPN put there, a blackhole the host had.
/// Disconnecting then deleted it and left the host worse than it found it, with nothing
/// said. Record on successful creation, delete only what is recorded.
static CREATED_ROUTES: std::sync::Mutex<Vec<Vec<String>>> = std::sync::Mutex::new(Vec::new());

// The two /1 routes capture the default IPv6 route without replacing ::/0, but they do not
// beat physical aggregate routes commonly present on hosts (notably 2000::/3 and fc00::/7).
// Install the same more-specific guards as the Windows and macOS adapters. Connected LAN
// routes remain more specific by design; route_local/exclude policy decides their treatment.
const IPV6_CAPTURE_PREFIXES: &[&str] = &["::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7"];
const FULL_TUNNEL_ROUTE_METRIC: u32 = 1;

fn full_tunnel_prefixes(family: NetworkAddressFamily) -> &'static [&'static str] {
    match family {
        NetworkAddressFamily::Ipv4 => &["0.0.0.0/1", "128.0.0.0/1"],
        NetworkAddressFamily::Ipv6 => IPV6_CAPTURE_PREFIXES,
    }
}

fn note_created(args: &[&str]) {
    CREATED_ROUTES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(args.iter().map(|s| s.to_string()).collect());
}

fn note_created_owned(args: Vec<String>) {
    if let Ok(mut journal) = CREATED_ROUTES.lock() {
        journal.push(args);
    }
}

#[cfg(feature = "experimental-roaming")]
fn created_by_us_owned(args: &[String]) -> bool {
    CREATED_ROUTES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .any(|entry| entry == args)
}

#[cfg(feature = "experimental-roaming")]
fn forget_created_owned(args: &[String]) {
    CREATED_ROUTES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|entry| entry != args);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalPath {
    gateway: Option<String>,
    device: String,
}

fn family_flag(ipv6: bool) -> Option<&'static str> {
    ipv6.then_some("-6")
}

fn physical_path_query(
    destination: IpAddr,
    tunnel_if: &str,
    source: Option<IpAddr>,
    output_interface: Option<&str>,
) -> Option<PhysicalPath> {
    let mut command = std::process::Command::new("ip");
    if let Some(flag) = family_flag(destination.is_ipv6()) {
        command.arg(flag);
    }
    command.args(["route", "get", &destination.to_string()]);
    if let Some(source) = source {
        if source.is_ipv4() != destination.is_ipv4() {
            return None;
        }
        command.args(["from", &source.to_string()]);
    }
    if let Some(interface) = output_interface {
        command.args(["oif", interface]);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.lines().next()?.split_whitespace().collect();
    let gateway = fields
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].to_string());
    let device = fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].to_string())?;
    (device != tunnel_if).then_some(PhysicalPath { gateway, device })
}

fn physical_path_for(
    destination: IpAddr,
    tunnel_if: &str,
    source: Option<IpAddr>,
) -> Option<PhysicalPath> {
    physical_path_query(destination, tunnel_if, source, None)
}

#[cfg(feature = "experimental-roaming")]
fn physical_path_for_interface(
    destination: IpAddr,
    tunnel_if: &str,
    source: IpAddr,
    output_interface: &str,
) -> Option<PhysicalPath> {
    let path = physical_path_query(destination, tunnel_if, Some(source), Some(output_interface))?;
    (path.device == output_interface).then_some(path)
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxCandidateRoute {
    pub remote: IpAddr,
    pub source: IpAddr,
    pub gateway: Option<String>,
    pub interface: String,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxPreparedPathRoutes {
    pub generation: u64,
    pub candidate_id: u64,
    pub routes: Vec<LinuxCandidateRoute>,
    tunnel_interface: String,
}

/// Resolve every candidate carrier through the exact interface/source pair reported by the
/// platform. PREPARE is deliberately read-only: the bound candidate socket can prove the new
/// path before COMMIT replaces any qeli-owned host route.
#[cfg(feature = "experimental-roaming")]
pub(crate) fn prepare_candidate_path_routes(
    candidate: &PreparedPathCandidate,
    tunnel_if: &str,
) -> anyhow::Result<LinuxPreparedPathRoutes> {
    let interface_index = candidate
        .update
        .interface_index
        .ok_or_else(|| anyhow::anyhow!("Linux candidate path requires an interface index"))?;
    let interface = crate::transport_core::carrier::linux_interface_name(interface_index)?
        .into_string()
        .map_err(|_| anyhow::anyhow!("candidate interface name is not valid UTF-8"))?;
    prepare_candidate_path_routes_on(candidate, tunnel_if, &interface)
}

#[cfg(feature = "experimental-roaming")]
fn prepare_candidate_path_routes_on(
    candidate: &PreparedPathCandidate,
    tunnel_if: &str,
    interface: &str,
) -> anyhow::Result<LinuxPreparedPathRoutes> {
    if interface.is_empty() || interface == tunnel_if {
        anyhow::bail!("candidate interface must be a non-tunnel interface");
    }
    let local_addresses = candidate
        .update
        .local_addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid validated candidate source '{value}'"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut routes = Vec::new();
    for remote in candidate.update.compatible_resolved_addresses() {
        let source = local_addresses
            .iter()
            .copied()
            .find(|source| source.is_ipv4() == remote.is_ipv4())
            .ok_or_else(|| {
                anyhow::anyhow!("candidate path has no source address for carrier {remote}")
            })?;
        let path =
            physical_path_for_interface(remote, tunnel_if, source, interface).ok_or_else(|| {
                anyhow::anyhow!(
                    "candidate carrier {remote} has no route from {source} through {interface}"
                )
            })?;
        routes.push(LinuxCandidateRoute {
            remote,
            source,
            gateway: path.gateway,
            interface: path.device,
        });
    }
    if routes.is_empty() {
        anyhow::bail!("candidate path has no compatible carrier route");
    }
    Ok(LinuxPreparedPathRoutes {
        generation: candidate.update.generation,
        candidate_id: candidate.candidate_id,
        routes,
        tunnel_interface: tunnel_if.to_string(),
    })
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
enum CandidateRouteMutation {
    None,
    Add {
        undo: Vec<String>,
        journal_was_present: bool,
    },
    Replace {
        ipv6: bool,
        previous: Vec<String>,
    },
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
struct CandidateRouteStep {
    route: LinuxCandidateRoute,
    mutation: CandidateRouteMutation,
}

#[cfg(feature = "experimental-roaming")]
fn carrier_route_undo(remote: IpAddr) -> Vec<String> {
    let mut args = Vec::new();
    if remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "del".to_string(), remote.to_string()]);
    args
}

#[cfg(feature = "experimental-roaming")]
fn candidate_route_command(action: &str, route: &LinuxCandidateRoute) -> Vec<String> {
    let mut args = Vec::new();
    if route.remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        action.to_string(),
        route.remote.to_string(),
    ]);
    if let Some(gateway) = &route.gateway {
        args.extend([
            "via".to_string(),
            gateway.clone(),
            "dev".to_string(),
            route.interface.clone(),
        ]);
    } else {
        args.extend([
            "dev".to_string(),
            route.interface.clone(),
            "scope".to_string(),
            "link".to_string(),
        ]);
    }
    args.extend(["src".to_string(), route.source.to_string()]);
    args
}

#[cfg(feature = "experimental-roaming")]
fn exact_route_tokens(remote: IpAddr) -> anyhow::Result<Option<Vec<String>>> {
    let mut args = Vec::<String>::new();
    if remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "show".to_string(), remote.to_string()]);
    let output = std::process::Command::new("ip").args(args).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "could not inspect existing carrier route {remote}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().map(str::to_string).collect()))
}

#[cfg(feature = "experimental-roaming")]
fn candidate_route_expected_tokens(route: &LinuxCandidateRoute) -> Vec<String> {
    let mut expected = vec![format!("dev {}", route.interface)];
    if let Some(gateway) = &route.gateway {
        expected.push(format!("via {gateway}"));
    }
    expected
}

#[cfg(feature = "experimental-roaming")]
fn run_ip_owned(args: &[String], description: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{description}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(feature = "experimental-roaming")]
fn rollback_candidate_route_steps(applied: &[CandidateRouteStep]) -> Vec<String> {
    let mut errors = Vec::new();
    for step in applied.iter().rev() {
        match &step.mutation {
            CandidateRouteMutation::None => {}
            CandidateRouteMutation::Add {
                undo,
                journal_was_present,
            } => match std::process::Command::new("ip").args(undo).output() {
                Ok(output) if output.status.success() => {
                    if !journal_was_present {
                        forget_created_owned(undo);
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if route_is_already_absent(&stderr) {
                        if !journal_was_present {
                            forget_created_owned(undo);
                        }
                    } else {
                        errors.push(format!("ip {}: {}", undo.join(" "), stderr.trim()));
                    }
                }
                Err(error) => errors.push(format!("ip {}: {error}", undo.join(" "))),
            },
            CandidateRouteMutation::Replace { ipv6, previous } => {
                let mut restore = Vec::new();
                if *ipv6 {
                    restore.push("-6".to_string());
                }
                restore.extend(["route".to_string(), "replace".to_string()]);
                restore.extend(previous.iter().cloned());
                if let Err(error) = run_ip_owned(&restore, "could not restore carrier route") {
                    errors.push(error.to_string());
                }
            }
        }
    }
    errors
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
struct RetiredCarrierRoute {
    undo: Vec<String>,
    ipv6: bool,
    previous: Vec<String>,
}

#[cfg(feature = "experimental-roaming")]
fn restore_retired_carrier_routes(retired: &[RetiredCarrierRoute]) -> Vec<String> {
    let mut errors = Vec::new();
    for route in retired.iter().rev() {
        let mut restore = Vec::new();
        if route.ipv6 {
            restore.push("-6".to_string());
        }
        restore.extend(["route".to_string(), "replace".to_string()]);
        restore.extend(route.previous.iter().cloned());
        match run_ip_owned(&restore, "could not restore retired carrier route") {
            Ok(()) => note_created_owned(route.undo.clone()),
            Err(error) => errors.push(error.to_string()),
        }
    }
    errors
}

#[cfg(feature = "experimental-roaming")]
impl LinuxPreparedPathRoutes {
    /// Atomically from qeli's ownership perspective: all conflicts are rejected before mutation,
    /// every applied route is verified through the ordinary (unforced) FIB, and any later failure
    /// restores earlier qeli routes in reverse order. After the candidate is usable, qeli-owned
    /// host routes for the previous carrier are retired so another-family handover leaves exactly
    /// the authenticated active bypass; operator-owned routes are never removed.
    pub(crate) fn commit(&self, previous_carriers: &[IpAddr]) -> anyhow::Result<()> {
        let desired = self
            .routes
            .iter()
            .map(|route| route.remote)
            .collect::<Vec<_>>();
        let mut retire = Vec::new();
        for remote in previous_carriers.iter().copied() {
            if desired.contains(&remote) {
                continue;
            }
            let undo = carrier_route_undo(remote);
            if !created_by_us_owned(&undo) {
                continue;
            }
            match exact_route_tokens(remote)? {
                Some(previous) => retire.push(RetiredCarrierRoute {
                    undo,
                    ipv6: remote.is_ipv6(),
                    previous,
                }),
                None => forget_created_owned(&undo),
            }
        }
        let mut steps = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            let undo = carrier_route_undo(route.remote);
            let owned = created_by_us_owned(&undo);
            let existing = exact_route_tokens(route.remote)?;
            let expected = candidate_route_expected_tokens(route);
            let mutation = match existing {
                Some(previous) if owned => CandidateRouteMutation::Replace {
                    ipv6: route.remote.is_ipv6(),
                    previous,
                },
                Some(previous)
                    if route_output_satisfies_all(
                        &previous.join(" "),
                        &expected.iter().map(String::as_str).collect::<Vec<_>>(),
                    ) =>
                {
                    CandidateRouteMutation::None
                }
                Some(_) => {
                    anyhow::bail!(
                        "candidate carrier {} conflicts with an operator-owned route",
                        route.remote
                    )
                }
                None => CandidateRouteMutation::Add {
                    undo,
                    journal_was_present: owned,
                },
            };
            steps.push(CandidateRouteStep {
                route: route.clone(),
                mutation,
            });
        }

        let mut applied = Vec::with_capacity(steps.len());
        for step in steps {
            let result = match &step.mutation {
                CandidateRouteMutation::None => Ok(()),
                CandidateRouteMutation::Add {
                    undo,
                    journal_was_present,
                } => {
                    let args = candidate_route_command("add", &step.route);
                    run_ip_owned(&args, "could not add candidate carrier route").map(|()| {
                        if !journal_was_present {
                            note_created_owned(undo.clone());
                        }
                    })
                }
                CandidateRouteMutation::Replace { .. } => {
                    let args = candidate_route_command("replace", &step.route);
                    run_ip_owned(&args, "could not replace qeli-owned carrier route")
                }
            };
            if let Err(error) = result {
                let rollback_errors = rollback_candidate_route_steps(&applied);
                if rollback_errors.is_empty() {
                    return Err(error);
                }
                anyhow::bail!(
                    "{error}; candidate route rollback failed: {}",
                    rollback_errors.join("; ")
                );
            }
            applied.push(step);

            let route = &applied.last().expect("applied step is present").route;
            let expected = PhysicalPath {
                gateway: route.gateway.clone(),
                device: route.interface.clone(),
            };
            let actual =
                physical_path_for(route.remote, &self.tunnel_interface, Some(route.source));
            if actual.as_ref() != Some(&expected) {
                let rollback_errors = rollback_candidate_route_steps(&applied);
                let mut message = format!(
                    "candidate carrier {} failed post-commit FIB verification",
                    route.remote
                );
                if !rollback_errors.is_empty() {
                    message.push_str("; candidate route rollback failed: ");
                    message.push_str(&rollback_errors.join("; "));
                }
                anyhow::bail!(message);
            }
        }

        let mut retired = Vec::with_capacity(retire.len());
        for route in retire {
            let output = std::process::Command::new("ip").args(&route.undo).output();
            match output {
                Ok(output) if output.status.success() => {
                    forget_created_owned(&route.undo);
                    retired.push(route);
                }
                Ok(output) if route_is_already_absent(&String::from_utf8_lossy(&output.stderr)) => {
                    forget_created_owned(&route.undo);
                }
                Ok(output) => {
                    let mut rollback_errors = restore_retired_carrier_routes(&retired);
                    rollback_errors.extend(rollback_candidate_route_steps(&applied));
                    let error = format!(
                        "could not retire previous carrier route: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                    if rollback_errors.is_empty() {
                        anyhow::bail!(error);
                    }
                    anyhow::bail!(
                        "{error}; route rollback failed: {}",
                        rollback_errors.join("; ")
                    );
                }
                Err(error) => {
                    let mut rollback_errors = restore_retired_carrier_routes(&retired);
                    rollback_errors.extend(rollback_candidate_route_steps(&applied));
                    if rollback_errors.is_empty() {
                        anyhow::bail!("could not retire previous carrier route: {error}");
                    }
                    anyhow::bail!(
                        "could not retire previous carrier route: {error}; route rollback failed: {}",
                        rollback_errors.join("; ")
                    );
                }
            }
        }
        Ok(())
    }
}

fn add_tunnel_route(
    cidr: &str,
    gateway: &str,
    ifname: &str,
    metric: u32,
    is_tap: bool,
) -> anyhow::Result<()> {
    let destination = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid network-plan route '{cidr}'"))?;
    let gateway_ip = gateway
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid network-plan gateway '{gateway}'"))?;
    if destination.is_ipv4() != gateway_ip.is_ipv4() {
        anyhow::bail!("route {cidr} and gateway {gateway} use different families");
    }
    let ipv6 = destination.is_ipv6();
    let direct_interface_route = !is_tap;
    // An L3 TUN is point-to-point for BOTH families. NetworkPlan v2 deliberately assigns
    // host prefixes (/32 and /128), so `via <gateway>` would require ARP/NDP reachability
    // that does not exist and Linux rejects the IPv4 next hop as invalid. A direct device
    // route sends the inner packet to qeli without neighbour discovery. TAP is real L2 and
    // retains the gateway route.
    let args = tunnel_route_args(ipv6, cidr, gateway, ifname, metric, is_tap);
    let output = std::process::Command::new("ip").args(&args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") {
        let dev = format!("dev {ifname}");
        let route_matches = if direct_interface_route {
            existing_route_satisfies_all(ipv6, cidr, &[&dev])
        } else {
            let via = format!("via {gateway}");
            existing_route_satisfies_all(ipv6, cidr, &[&via, &dev])
        };
        if route_matches == Some(true) {
            return Ok(());
        }
    }
    let route_description = if direct_interface_route {
        format!("{cidr} dev {ifname}")
    } else {
        format!("{cidr} via {gateway} dev {ifname}")
    };
    anyhow::bail!(
        "network-plan route {route_description} was not applied: {}",
        stderr.trim()
    )
}

fn tunnel_route_args(
    ipv6: bool,
    cidr: &str,
    gateway: &str,
    ifname: &str,
    metric: u32,
    is_tap: bool,
) -> Vec<String> {
    let mut args = Vec::with_capacity(10);
    if let Some(flag) = family_flag(ipv6) {
        args.push(flag.to_string());
    }
    args.extend(["route".into(), "add".into(), cidr.into()]);
    if is_tap {
        args.extend(["via".into(), gateway.into()]);
    }
    args.extend([
        "dev".into(),
        ifname.into(),
        "metric".into(),
        metric.to_string(),
    ]);
    args
}

fn connected_tunnel_cidr(address: IpAddr, prefix: u8) -> anyhow::Result<String> {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv4Addr::from(u32::from(address) & mask),
                prefix
            ))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv6Addr::from(u128::from(address) & mask),
                prefix
            ))
        }
        _ => anyhow::bail!("invalid on-link prefix {prefix} for tunnel address {address}"),
    }
}

fn add_blackhole_half(cidr: &str) -> anyhow::Result<()> {
    let ipv6 = cidr.contains(':');
    let mut args: Vec<String> = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend([
        "route".into(),
        "add".into(),
        "blackhole".into(),
        cidr.into(),
    ]);
    let output = std::process::Command::new("ip").args(&args).output()?;
    if output.status.success() {
        let mut undo = args;
        let action = if ipv6 { 2 } else { 1 };
        undo[action] = "del".into();
        note_created_owned(undo);
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists")
        && existing_route_satisfies(ipv6, cidr, "blackhole") == Some(true)
    {
        return Ok(());
    }
    anyhow::bail!("could not install blackhole {cidr}: {}", stderr.trim())
}

fn pin_carrier_route(carrier: IpAddr, path: &PhysicalPath) -> anyhow::Result<()> {
    let ipv6 = carrier.is_ipv6();
    let destination = carrier.to_string();
    let mut args: Vec<String> = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend(["route".into(), "add".into(), destination.clone()]);
    if let Some(gateway) = &path.gateway {
        // Keep the route on the exact interface returned by `ip route get`. The same
        // gateway address can legitimately exist on two links of a multi-homed host.
        args.extend([
            "via".into(),
            gateway.clone(),
            "dev".into(),
            path.device.clone(),
        ]);
    } else {
        args.extend([
            "dev".into(),
            path.device.clone(),
            "scope".into(),
            "link".into(),
        ]);
    }

    let output = std::process::Command::new("ip").args(&args).output()?;
    if output.status.success() {
        let mut undo = Vec::new();
        if ipv6 {
            undo.push("-6".into());
        }
        undo.extend(["route".into(), "del".into(), destination]);
        note_created_owned(undo);
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") {
        let dev = format!("dev {}", path.device);
        let via = path
            .gateway
            .as_ref()
            .map(|gateway| format!("via {gateway}"));
        let mut expected = vec![dev.as_str()];
        if let Some(via) = via.as_deref() {
            expected.push(via);
        }
        if existing_route_satisfies_all(ipv6, &carrier.to_string(), &expected) == Some(true) {
            // It belongs to another owner but is already the exact safe physical path.
            return Ok(());
        }
        anyhow::bail!(
            "full tunnel found a conflicting existing carrier route for {carrier}; expected {}{}",
            path.device,
            path.gateway
                .as_deref()
                .map(|gateway| format!(" via {gateway}"))
                .unwrap_or_default()
        );
    }
    anyhow::bail!(
        "full tunnel could not pin carrier {carrier}: {}",
        stderr.trim()
    )
}

/// Apply the already validated, generation-scoped dual-family network plan on Linux.
/// Every requested family is handled symmetrically; an inactive family is blocked only for
/// full-tunnel mode and only when its explicit leak escape hatch is disabled.
pub fn setup_network_plan_routes(
    config: &ClientRoutingConfig,
    plan: &NetworkPlan,
    ifname: &str,
    carrier_addresses: &[IpAddr],
    carrier_local_address: Option<IpAddr>,
    is_tap: bool,
) -> anyhow::Result<()> {
    if carrier_addresses.is_empty() {
        anyhow::bail!("network plan has no resolved carrier address to preserve");
    }
    let mut seen_carriers = std::collections::HashSet::new();
    let carrier_paths: Vec<(IpAddr, Option<PhysicalPath>)> = carrier_addresses
        .iter()
        .copied()
        .filter(|address| seen_carriers.insert(*address))
        .map(|address| {
            (
                address,
                physical_path_for(address, ifname, carrier_local_address),
            )
        })
        .collect();

    let exclude_paths: Vec<(String, IpAddr, Option<PhysicalPath>)> = config
        .exclude
        .iter()
        .filter_map(|cidr| {
            let address = cidr
                .split_once('/')
                .map(|(address, _)| address)
                .unwrap_or(cidr)
                .parse::<IpAddr>()
                .ok()?;
            Some((
                cidr.clone(),
                address,
                physical_path_for(address, ifname, None),
            ))
        })
        .collect();

    // NetworkPlan v2 assigns host prefixes to an L3 TUN to prevent ARP/NDP. Install the
    // negotiated pool prefix explicitly so the server gateway, tunnel DNS and peer/client
    // addresses remain reachable in split-tunnel mode. Android already did this in its
    // Builder; without the equivalent Linux route only full-tunnel defaults happened to
    // cover the pool.
    for assigned in &plan.addresses {
        if assigned.on_link_prefix_len >= assigned.prefix_len {
            continue;
        }
        let address = assigned.address.parse::<IpAddr>().map_err(|_| {
            anyhow::anyhow!("invalid network-plan tunnel address '{}'", assigned.address)
        })?;
        let cidr = connected_tunnel_cidr(address, assigned.on_link_prefix_len)?;
        let gateway = assigned.gateway.as_deref().unwrap_or(&assigned.address);
        add_tunnel_route(&cidr, gateway, ifname, 0, is_tap)?;
    }

    if plan.full_tunnel {
        for (carrier, path) in &carrier_paths {
            let path = path.as_ref().ok_or_else(|| {
                anyhow::anyhow!("full tunnel cannot determine a physical path to carrier {carrier}")
            })?;
            pin_carrier_route(*carrier, path)?;
        }

        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for address in &plan.addresses {
            match address.family {
                NetworkAddressFamily::Ipv4 => has_ipv4 = true,
                NetworkAddressFamily::Ipv6 => has_ipv6 = true,
            }
            let gateway = address.gateway.as_deref().ok_or_else(|| {
                anyhow::anyhow!("full tunnel address '{}' has no gateway", address.address)
            })?;
            for &prefix in full_tunnel_prefixes(address.family) {
                add_tunnel_route(prefix, gateway, ifname, FULL_TUNNEL_ROUTE_METRIC, is_tap)?;
            }
        }
        if !has_ipv4 && !config.allow_ipv4_leak {
            add_blackhole_half("0.0.0.0/1")?;
            add_blackhole_half("128.0.0.0/1")?;
        }
        if !has_ipv6 && !config.allow_ipv6_leak {
            for &prefix in IPV6_CAPTURE_PREFIXES {
                add_blackhole_half(prefix)?;
            }
        }
    }

    for route in &plan.routes {
        add_tunnel_route(&route.cidr, &route.gateway, ifname, route.metric, is_tap)?;
    }

    if config.kill_switch && !config.exclude.is_empty() {
        log::warn!("exclude + kill_switch: excluded networks are fail-closed by the firewall");
    }
    for (cidr, address, path) in exclude_paths {
        let Some(path) = path else {
            anyhow::bail!("exclude {cidr}: no physical route is known");
        };
        let ipv6 = address.is_ipv6();
        let PhysicalPath { gateway, device } = path;
        let mut args: Vec<String> = Vec::new();
        if ipv6 {
            args.push("-6".into());
        }
        args.extend(["route".into(), "add".into(), cidr.clone()]);
        if let Some(gateway) = &gateway {
            // Pin the interface as well as the next hop. The same gateway (especially an
            // IPv6 link-local one) may exist on several uplinks of a multi-homed host.
            args.extend(["via".into(), gateway.clone(), "dev".into(), device.clone()]);
        } else {
            args.extend(["dev".into(), device.clone(), "scope".into(), "link".into()]);
        }
        let output = std::process::Command::new("ip").args(&args).output()?;
        if output.status.success() {
            let mut undo = Vec::new();
            if ipv6 {
                undo.push("-6".into());
            }
            undo.extend(["route".into(), "del".into(), cidr]);
            note_created_owned(undo);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                let dev = format!("dev {device}");
                let via = gateway.as_ref().map(|value| format!("via {value}"));
                let mut expected = vec![dev.as_str()];
                if let Some(via) = via.as_deref() {
                    expected.push(via);
                }
                if existing_route_satisfies_all(ipv6, &cidr, &expected) == Some(true) {
                    // Exact operator-owned bypass; leave it in place and do not journal it.
                    continue;
                }
                anyhow::bail!(
                    "exclude {cidr}: a conflicting route already exists; expected {}{}",
                    device,
                    gateway
                        .as_deref()
                        .map(|value| format!(" via {value}"))
                        .unwrap_or_else(|| " on-link".to_string())
                );
            }
            anyhow::bail!("exclude route was not applied: {}", stderr.trim());
        }
    }
    if plan.full_tunnel {
        // `ip route add` success is not the final truth when source-policy rules or several
        // tables are present. Ask the FIB again after the /1 capture routes exist and require
        // every carrier to retain the exact physical path resolved before capture.
        for (carrier, expected) in carrier_paths {
            let expected = expected.ok_or_else(|| {
                anyhow::anyhow!("full tunnel has no pre-capture physical path to {carrier}")
            })?;
            let actual = physical_path_for(carrier, ifname, carrier_local_address)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "full tunnel carrier {carrier} resolves through {ifname} or has no route after capture"
                    )
                })?;
            if actual != expected {
                anyhow::bail!(
                    "full tunnel carrier {carrier} changed physical path after capture: expected {:?}, got {:?}",
                    expected,
                    actual
                );
            }
        }
    }
    Ok(())
}

/// Did WE install the route this undo-command would remove?
///
/// The journal records the undo command for everything qeli adds, so asking whether an
/// undo is already queued answers "is this route ours". Used before any delete that is
/// not paired with an add of our own. (Audit 2026-07-27, R6.)
fn created_by_us(args: &[&str]) -> bool {
    CREATED_ROUTES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .any(|e| e.iter().eq(args.iter().copied()))
}

/// Take the journal, leaving it empty (cleanup runs once per connection).
fn take_created() -> Vec<Vec<String>> {
    CREATED_ROUTES
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_else(|poisoned| {
            let mut journal = poisoned.into_inner();
            std::mem::take(&mut *journal)
        })
}

/// Legacy IPv4 route applicator retained for its fault-injection regression suite.
/// Production connections use [`setup_network_plan_routes`], which is dual-family.
pub fn setup_routes(
    config: &ClientRoutingConfig,
    gateway: &str,
    ifname: &str,
    server_addr: &str,
) -> anyhow::Result<()> {
    // Install a default route via the tunnel only when explicitly requested.
    // (Previously this also fired when `include` was empty, which silently
    // hijacked the host's default route — and could black-hole SSH.)
    // Physical default gateway toward the server. Used both to pin the server-bypass
    // /32 (full-tunnel) and to route EXCLUDED subnets around the tunnel below.
    let physical_gw = default_gateway(server_addr);

    if config.add_default_gateway || config.mode == "full-tunnel" || config.mode == "all" {
        if let Some(gw) = &physical_gw {
            let output = std::process::Command::new("ip")
                .args(["route", "add", server_addr, "via", gw])
                .output()?;
            if output.status.success() {
                note_created(&["route", "del", server_addr]);
                log::info!("Added bypass route: {} via {}", server_addr, gw);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    // Fatal in full tunnel: without the bypass the encrypted path to the
                    // server would itself be routed into the tunnel we are building.
                    anyhow::bail!(
                        "full tunnel: could not pin the server bypass route for {} via {}: {}",
                        server_addr,
                        gw,
                        stderr.trim()
                    );
                }
            }
        } else if let Some(dev) = physical_dev_for(server_addr).filter(|d| d != ifname) {
            // ON-LINK server (no gateway — same subnet, reached directly). The old code
            // pinned the bypass ONLY when a gateway existed, so here it did nothing, and the
            // `0.0.0.0/1`+`128.0.0.0/1` halves below then captured the encrypted carrier to
            // the server INTO the tunnel it carries — an immediate deadlock. Pin a scoped
            // `/32` on the physical dev instead: more specific than the halves, so the
            // carrier stays off the tunnel. (on-link bypass)
            let output = std::process::Command::new("ip")
                .args(["route", "add", server_addr, "dev", &dev, "scope", "link"])
                .output()?;
            if output.status.success() {
                note_created(&["route", "del", server_addr]);
                log::info!("Added on-link bypass route: {} dev {}", server_addr, dev);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "full tunnel: could not pin the on-link server bypass route for {} \
                         dev {}: {} — without it the encrypted path to the server loops into \
                         the tunnel",
                        server_addr,
                        dev,
                        stderr.trim()
                    );
                }
            }
        } else {
            // Neither a gateway nor a usable physical dev: we cannot keep the carrier off
            // the tunnel, so a full tunnel would deadlock. Fail loudly rather than build a
            // tunnel that cannot pass its own carrier traffic.
            anyhow::bail!(
                "full tunnel: could not determine how to reach the server {} on the physical \
                 network (no gateway and no usable interface) — refusing to build a tunnel \
                 whose own encrypted path would loop back into it",
                server_addr
            );
        }

        // Override the host default via the tunnel with the two-halves trick
        // (`0.0.0.0/1` + `128.0.0.0/1`): each is MORE SPECIFIC than any `/0`
        // default, so the tunnel wins regardless of the physical default's metric,
        // without deleting it (the server-bypass `/32` above keeps the encrypted
        // path to the server on the physical gateway, and the connected `/24` keeps
        // tunnel-internal traffic local). A single `default … metric 100` would lose
        // to the common metric-0 physical default and silently fail to tunnel.
        //
        // Both halves are load-bearing and failure here is FATAL. Logging and carrying on
        // meant losing one half silently exposed half of the IPv4 space — and losing both
        // exposed everything — while the UI still said "connected, full tunnel". A refused
        // connection is the honest outcome; the caller tears down and retries.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let output = std::process::Command::new("ip")
                .args(["route", "add", half, "via", gateway, "dev", ifname])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "full tunnel: could not install route {} via {} dev {}: {} — refusing \
                         to run with a partial default route (traffic would leak)",
                        half,
                        gateway,
                        ifname,
                        stderr.trim()
                    );
                }
            }
        }
        // Verify against the FIB rather than trusting the exit status. The kill-switch
        // already re-checks every rule it installs because the iptables-nft wrapper can
        // report success while silently doing nothing; `ip route` deserves the same
        // distrust, and here a false success is a full-traffic leak.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let shown = std::process::Command::new("ip")
                .args(["route", "show", half])
                .output()?;
            let text = String::from_utf8_lossy(&shown.stdout);
            if !text.contains(ifname) {
                anyhow::bail!(
                    "full tunnel: route {} is not in the routing table on {} after being added \
                     (saw {:?}) — refusing to run with a partial default route",
                    half,
                    ifname,
                    text.trim()
                );
            }
        }

        // This legacy applicator has only an IPv4 gateway, so it cannot tunnel IPv6.
        // Block rather than leak, matching the current NetworkPlan path's fail-closed
        // contract, and let `allow_ipv6_leak` remain the explicit opt-out.
        if !config.allow_ipv6_leak {
            let mut blocked = 0;
            for &half in IPV6_CAPTURE_PREFIXES {
                let out = std::process::Command::new("ip")
                    .args(["-6", "route", "add", "blackhole", half])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        note_created(&["-6", "route", "del", "blackhole", half]);
                        blocked += 1;
                    }
                    Ok(o) => {
                        let e = String::from_utf8_lossy(&o.stderr);
                        if e.contains("File exists") {
                            // Pre-existing — but a route to ::/1 is not necessarily a
                            // BLACKHOLE. Verify before counting it as blocked, or a plain
                            // pre-existing route makes us report IPv6 as blocked while it
                            // leaks out the physical interface.
                            match existing_route_satisfies(true, half, "blackhole") {
                                Some(true) => blocked += 1, // genuinely blocked, not ours to remove
                                Some(false) => log::warn!(
                                    "full tunnel: {} already has a NON-blackhole route — IPv6                                      traffic to it will BYPASS the tunnel",
                                    half
                                ),
                                None => log::warn!(
                                    "full tunnel: {} exists but could not be verified as a                                      blackhole — assuming IPv6 is NOT blocked",
                                    half
                                ),
                            }
                        } else {
                            log::warn!(
                                "full tunnel: could not blackhole IPv6 {}: {}",
                                half,
                                e.trim()
                            );
                        }
                    }
                    Err(e) => log::warn!("full tunnel: `ip -6 route` unavailable ({}) ", e),
                }
            }
            if blocked == IPV6_CAPTURE_PREFIXES.len() {
                log::info!(
                    "legacy IPv4 route plan: IPv6 blackholed (set \
                     allow_ipv6_leak = true to let IPv6 use the physical interface instead)"
                );
            } else {
                log::warn!(
                    "full tunnel: IPv6 is NOT fully blocked — traffic to IPv6 destinations may \
                     bypass the tunnel. Enable the kill-switch, or disable IPv6 on this host."
                );
            }
        }
    }

    // `include` is the split-tunnel counterpart of the halves above: the operator named
    // exactly which subnets must go through the tunnel, so a route that failed to install
    // is that subnet leaking in the clear. Fatal for the same reason.
    for subnet in &config.include {
        let output = std::process::Command::new("ip")
            .args(["route", "add", subnet, "via", gateway, "dev", ifname])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                anyhow::bail!(
                    "could not route included subnet {} through the tunnel ({} dev {}): {} — \
                     refusing to run, as that subnet would leave unencrypted",
                    subnet,
                    gateway,
                    ifname,
                    stderr.trim()
                );
            }
            // `File exists` was accepted as success — but this branch exists precisely
            // because an un-tunnelled `include` subnet leaves in the clear, and a
            // pre-existing route to it may point anywhere (a LAN gateway, another VPN).
            // Swallowing it defeated the very check whose comment calls it fatal. Verify
            // the existing route uses OUR interface; bail with the same reasoning if not.
            let dev = format!("dev {ifname}");
            match existing_route_satisfies(false, subnet, &dev) {
                Some(true) => {}
                Some(false) => anyhow::bail!(
                    "included subnet {} already has a route that does NOT use {} — it would \
                     leave unencrypted. Remove the conflicting route (`ip route show {}`) or \
                     drop it from `include`.",
                    subnet,
                    ifname,
                    subnet
                ),
                None => anyhow::bail!(
                    "included subnet {} already has a route, but it could not be verified as \
                     going through {} — refusing to run rather than assume it is tunnelled.",
                    subnet,
                    ifname
                ),
            }
        }
    }

    // Exclude: carve specific subnets OUT of the tunnel. Adding a more-specific route
    // via the PHYSICAL gateway beats the `0.0.0.0/1`+`128.0.0.0/1` full-tunnel halves,
    // so exclusion works even in full-tunnel (a plain `route del ... dev tun` is a no-op
    // there — the subnet has no dedicated tun route to remove). Falls back to the delete
    // when the physical gateway is unknown (split-tunnel, where the subnet only exists on
    // tun if `include` added it). Removed on disconnect by cleanup_routes.
    // A kill-switch + exclude combination is fail-closed but silently non-functional: the
    // kill-switch's terminal DROP blocks everything not going out `tun` or to the server, so
    // an excluded subnet is BLACKHOLED rather than routed direct. That is safe (no leak) but
    // confusing — the user set exclude and sees the destination unreachable with no reason.
    // Say so once. (L4)
    if config.kill_switch && !config.exclude.is_empty() {
        log::warn!(
            "exclude + kill_switch: {} excluded subnet(s) will be BLACKHOLED, not sent direct — \
             the kill-switch blocks all non-tunnel egress. Disable the kill-switch if you need \
             these to reach the physical network.",
            config.exclude.len()
        );
    }
    for subnet in &config.exclude {
        if !is_valid_cidr(subnet) {
            log::warn!("skipping invalid exclude subnet: {}", subnet);
            continue;
        }
        if let Some(gw) = &physical_gw {
            let output = std::process::Command::new("ip")
                .args(["route", "add", subnet, "via", gw])
                .output();
            if let Ok(o) = output {
                if o.status.success() {
                    note_created(&["route", "del", subnet]);
                } else {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("File exists") {
                        log::warn!("Failed to add exclude bypass {}: {}", subnet, stderr);
                    }
                }
            }
        } else {
            // No physical gateway to route around the tunnel, so the best we can do is
            // stop sending this subnet INTO the tunnel — but only if the route through
            // the tunnel is ours.
            //
            // This used to delete unconditionally and journal nothing, which breaks the
            // rule the whole module is built on ("delete only what we created", see the
            // header): with `dev_attach`, the tun is owned by an external manager that may
            // have installed this very route, and `cleanup_routes` restores only what is
            // in the journal — so the route was gone for good once qeli exited. Deleting
            // only routes we added keeps the invariant; anything else is left alone and
            // reported, because silently not-excluding is worse than saying so.
            // (Audit 2026-07-27, R6.)
            if created_by_us(&["route", "del", subnet]) {
                let _ = std::process::Command::new("ip")
                    .args(["route", "del", subnet, "dev", ifname])
                    .output();
            } else {
                log::warn!(
                    "exclude {}: no physical gateway is known and the tunnel route for it \
                     was not installed by qeli — leaving it untouched (deleting a route we \
                     did not create could not be undone on disconnect). Traffic to this \
                     subnet keeps using the tunnel.",
                    subnet
                );
            }
        }
    }

    Ok(())
}

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PushedRoute {
    cidr: String,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
}

/// Convert the server push into the exact route records exported by the shared core.
/// Invalid and policy-forbidden entries are absent from the plan and therefore are never
/// acknowledged as applied. `apply_pushed_routes` repeats the same checks immediately
/// before invoking `ip`, keeping the platform boundary defensive against a hostile peer.
pub fn planned_pushed_routes(
    routes_json: &str,
    default_gateway: &str,
) -> anyhow::Result<Vec<NetworkRoute>> {
    crate::transport_core::network::planned_pushed_routes(routes_json, default_gateway)
}

/// Apply the subnets the server advertised, plus — only when
/// `routing.route_local_networks` is on — the broad RFC1918 ranges.
///
/// The two are deliberately NOT gated together. A server-pushed route is a
/// *specific* CIDR an admin explicitly configured (`route = …` on the profile,
/// or a per-user route), so it is always honoured — exactly like OpenVPN's
/// `push "route …"`. Every pushed value is validated in `apply_pushed_routes`
/// before it reaches `ip`, so a hostile server still cannot smuggle anything.
/// `route_local_networks` gates only the *blanket* 10/8 + 172.16/12 +
/// 192.168/16 pull, which stays off by default because it would hijack the
/// client's OWN LAN (printers, NAS, local router).
///
/// Until 0.7.12 the pushed routes sat behind the same flag, so a correctly
/// configured `route =` was silently dropped on every default client.
pub fn apply_local_networks(
    routing: &ClientRoutingConfig,
    routes_json: &str,
    ifname: &str,
    gateway: &str,
) -> anyhow::Result<()> {
    // Specific subnets the server advertised — always honoured.
    apply_pushed_routes(routes_json, ifname, gateway)?;
    if !routing.route_local_networks {
        return Ok(());
    }
    // Broad RFC1918 ranges so any private destination also tunnels.
    for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
        let output = std::process::Command::new("ip")
            .args([
                "route", "add", cidr, "via", gateway, "dev", ifname, "metric", "100",
            ])
            .output();
        match output {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "could not route requested local network {} through {}: {}",
                        cidr,
                        ifname,
                        stderr.trim()
                    );
                } else {
                    // A route already exists — but pointing where? A pre-existing
                    // `10.0.0.0/8 via <LAN gw>` is the normal case on a router, and
                    // swallowing it made the "routing local networks through the tunnel"
                    // line below a lie for that range.
                    let dev = format!("dev {ifname}");
                    match existing_route_satisfies(false, cidr, &dev) {
                        Some(true) => {}
                        Some(false) => anyhow::bail!(
                            "requested local network {} already has a route that does not use {}",
                            cidr,
                            ifname
                        ),
                        None => anyhow::bail!(
                            "requested local network {} already has a route that could not be verified",
                            cidr
                        ),
                    }
                }
            }
            Err(e) => anyhow::bail!("could not add local network route {cidr}: {e}"),
        }
    }
    log::info!("Routing local networks (RFC1918 blanket) through the tunnel");
    Ok(())
}

/// Does the route the kernel ALREADY has for `cidr` satisfy what we wanted?
///
/// `ip route add` answers `File exists` for any pre-existing route to that prefix — it says
/// nothing about where that route points. Treating it as success (which every call site
/// did) meant a stale `10.0.0.0/8 via 192.168.1.1` counted as "routed through the tunnel",
/// and a plain `::/1` counted as "IPv6 blackholed". Both then logged success while the
/// traffic went straight out the physical interface. So: ask what is actually installed and
/// check it contains `want` (`dev <tun>` for a tunnelled prefix, `blackhole` for a blocked
/// one).
///
/// `None` = could not tell (no `ip`, unparsable output); the caller warns rather than
/// silently assuming either way.
fn existing_route_satisfies(v6: bool, cidr: &str, want: &str) -> Option<bool> {
    existing_route_satisfies_all(v6, cidr, &[want])
}

fn existing_route_satisfies_all(v6: bool, cidr: &str, wants: &[&str]) -> Option<bool> {
    let mut args: Vec<&str> = Vec::new();
    if v6 {
        args.push("-6");
    }
    args.extend_from_slice(&["route", "show", cidr]);
    let out = std::process::Command::new("ip").args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return None;
    }
    Some(route_output_satisfies_all(&text, wants))
}

/// Require every expected token sequence on one concrete route. Substring matching made
/// `dev eth0` accept `dev eth01`, and searching the complete multi-line output could combine
/// a gateway from one route with an interface from another.
fn route_output_satisfies_all(output: &str, wants: &[&str]) -> bool {
    output.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        wants.iter().all(|want| {
            let expected: Vec<&str> = want.split_whitespace().collect();
            !expected.is_empty()
                && fields
                    .windows(expected.len())
                    .any(|window| window == expected.as_slice())
        })
    })
}

pub fn apply_pushed_routes(
    routes_json: &str,
    ifname: &str,
    default_gateway: &str,
) -> anyhow::Result<()> {
    let trimmed = routes_json.trim();
    if trimmed == "[]" || trimmed.is_empty() {
        return Ok(());
    }

    let routes: Vec<PushedRoute> = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            anyhow::bail!("failed to parse pushed routes: {e}");
        }
    };

    for route in &routes {
        let gateway = route.gateway.as_deref().unwrap_or(default_gateway);
        let metric = route.metric.unwrap_or(100);

        // Report the route EXACTLY as it arrived, BEFORE we touch it, so the log answers
        // "what did the server actually send?" on its own. NB: the server resolves the
        // defaults itself (`gateway` falls back to the profile's tun address and `metric`
        // to 100 in build_auth_ok), so every pushed route carries both fields — we cannot
        // tell an admin-set gateway from a server-defaulted one, and must not pretend to.
        log::info!(
            "pushed route received: {} gateway={} metric={}",
            if route.cidr.is_empty() {
                "<empty>"
            } else {
                &route.cidr
            },
            gateway,
            metric,
        );

        // A malicious server could push a bogus/hostile CIDR or gateway that
        // ends up as an argument to `ip route add`. Validate both as real IP
        // values (and reject any option-looking string) before use; skip+log
        // anything that does not parse.
        if !is_valid_cidr(&route.cidr) {
            log::warn!("Ignoring pushed route with invalid CIDR: {}", route.cidr);
            continue;
        }
        if !is_valid_gateway(gateway) {
            log::warn!(
                "Ignoring pushed route {} with invalid gateway: {}",
                route.cidr,
                gateway
            );
            continue;
        }
        // The SERVER must not get to decide that this client is full-tunnel.
        //
        // `is_valid_cidr` accepts any legal family prefix, and `apply_pushed_routes` runs
        // unconditionally — before the `routing.route_local_networks` check and on both the
        // TCP and UDP paths — so a split-tunnel client (the default: `gateway = false`)
        // applied whatever the server sent. Pushing `0.0.0.0/1` + `128.0.0.0/1` captures all
        // traffic while being MORE SPECIFIC than any physical default route, so it wins
        // regardless of metric; `0.0.0.0/0 metric 0` beats a NetworkManager default at 100.
        // Either way the user asked for split-tunnel and silently got everything routed to
        // the server, with no bypass /32 for the server address (setup_routes only adds that
        // in full-tunnel mode).
        //
        // IPv4 /8 and IPv6 /3 are the broadest legitimate site-to-site/global aggregates
        // accepted by the shared planner. A wider route is a policy decision that belongs
        // to the user, not to the peer.
        // (Audit 2026-08-04.)
        let route_address = route
            .cidr
            .split_once('/')
            .and_then(|(address, _)| address.parse::<IpAddr>().ok())
            .expect("CIDR was validated above");
        let gateway_address = gateway
            .parse::<IpAddr>()
            .expect("gateway was validated above");
        if route_address.is_ipv4() != gateway_address.is_ipv4() {
            log::warn!(
                "Ignoring pushed route {} with cross-family gateway {}",
                route.cidr,
                gateway
            );
            continue;
        }
        let prefix = route
            .cidr
            .rsplit_once('/')
            .and_then(|(_, p)| p.parse::<u8>().ok())
            .unwrap_or(if route_address.is_ipv4() { 32 } else { 128 });
        if !crate::transport_core::network::pushed_route_prefix_is_allowed(route_address, prefix) {
            log::warn!(
                "REFUSING pushed route {}: a /{} covers the whole default route, and a server                  may not turn a split-tunnel client into a full-tunnel one. Set                  'routing.mode = full-tunnel' locally if that is what you want.",
                route.cidr,
                prefix
            );
            continue;
        }

        let mut args: Vec<String> = Vec::new();
        if route_address.is_ipv6() {
            args.push("-6".into());
        }
        args.extend([
            "route".into(),
            "add".into(),
            route.cidr.clone(),
            "via".into(),
            gateway.into(),
            "dev".into(),
            ifname.into(),
            "metric".into(),
            metric.to_string(),
        ]);
        let output = std::process::Command::new("ip").args(&args).output();

        match output {
            Ok(o) if o.status.success() => {
                log::info!(
                    "Pushed route applied: {} via {} dev {} metric {}",
                    route.cidr,
                    gateway,
                    ifname,
                    metric
                );
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if stderr.contains("File exists") {
                    let via = format!("via {gateway}");
                    let dev = format!("dev {ifname}");
                    let metric = format!("metric {metric}");
                    if existing_route_satisfies_all(
                        route_address.is_ipv6(),
                        &route.cidr,
                        &[&via, &dev, &metric],
                    ) == Some(true)
                    {
                        continue;
                    }
                }
                anyhow::bail!(
                    "pushed route {} via {} was not applied: {} — refusing to acknowledge a partial network plan",
                    route.cidr,
                    gateway,
                    stderr.trim()
                );
            }
            Err(e) => anyhow::bail!("pushed route {} error: {}", route.cidr, e),
        }
    }
    Ok(())
}

/// Validate a server-pushed CIDR — shared with the config parser and the panel
/// API so the same rule rejects a bad route wherever it is authored.
fn is_valid_cidr(s: &str) -> bool {
    crate::util::is_valid_cidr(s)
}

/// Validate a server-pushed gateway: a bare `IpAddr`, never a subnet.
fn is_valid_gateway(s: &str) -> bool {
    crate::util::is_valid_gateway(s)
}

/// The physical default gateway used to reach `server_addr` (parsed from
/// `ip route get`). `None` if it can't be determined (e.g. an on-link server).
fn default_gateway(server_addr: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", server_addr])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut saw_via = false;
    for part in s.split_whitespace() {
        if part == "via" {
            saw_via = true;
        } else if saw_via {
            return Some(part.to_string());
        }
    }
    None
}

/// The physical interface `server_addr` is reached on, parsed from the `dev` field of
/// `ip route get`. This is what a gateway-less (ON-LINK) server has instead of a `via`:
/// same subnet as the client, reached directly. (on-link bypass)
fn physical_dev_for(server_addr: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", server_addr])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut saw_dev = false;
    for part in s.split_whitespace() {
        if part == "dev" {
            saw_dev = true;
        } else if saw_dev {
            // Never our own tunnel device — if `ip route get` already resolves the server
            // through the tun (a stale route from a previous run), pinning it there is the
            // exact loop we are trying to prevent.
            return Some(part.to_string());
        }
    }
    None
}

pub fn cleanup_routes(ifname: &str, _server_addr: &str, _exclude: &[String]) -> anyhow::Result<()> {
    // Only the routes this process put on the PHYSICAL interface (server bypass, exclude
    // bypasses, IPv6 blackholes) — see CREATED_ROUTES. Anything that was already there
    // when we started stays; it was not ours to remove.
    let mut failed = Vec::new();
    let mut errors = Vec::new();
    for args in take_created() {
        match std::process::Command::new("ip").args(&args).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !route_is_already_absent(&stderr) {
                    errors.push(format!("ip {}: {}", args.join(" "), stderr.trim()));
                    failed.push(args);
                }
            }
            Err(error) => {
                errors.push(format!("ip {}: {error}", args.join(" ")));
                failed.push(args);
            }
        }
    }

    // A failed deletion is still ours. Keep it in the journal so TunGuard's retry (or a
    // later explicit cleanup) can try again instead of permanently forgetting ownership.
    if !failed.is_empty() {
        CREATED_ROUTES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(failed);
    }

    // The tun device's own routes go with the device, so flushing by interface can only
    // ever touch ours.
    match std::process::Command::new("ip")
        .args(["route", "flush", "dev", ifname])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !route_is_already_absent(&stderr) {
                errors.push(format!("ip route flush dev {ifname}: {}", stderr.trim()));
            }
        }
        Err(error) => errors.push(format!("ip route flush dev {ifname}: {error}")),
    }
    match std::process::Command::new("ip")
        .args(["-6", "route", "flush", "dev", ifname])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !route_is_already_absent(&stderr) {
                errors.push(format!("ip -6 route flush dev {ifname}: {}", stderr.trim()));
            }
        }
        Err(error) => errors.push(format!("ip -6 route flush dev {ifname}: {error}")),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("route cleanup failed: {}", errors.join("; "))
    }
}

fn route_is_already_absent(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    [
        "no such process",
        "no such device",
        "cannot find device",
        "does not exist",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        connected_tunnel_cidr, full_tunnel_prefixes, is_valid_cidr, is_valid_gateway,
        planned_pushed_routes, route_output_satisfies_all, tunnel_route_args,
        IPV6_CAPTURE_PREFIXES,
    };
    use std::net::IpAddr;

    #[test]
    fn network_plan_tun_routes_are_direct_for_both_families() {
        assert_eq!(
            tunnel_route_args(false, "0.0.0.0/1", "10.9.0.1", "qeli0", 100, false),
            ["route", "add", "0.0.0.0/1", "dev", "qeli0", "metric", "100"]
        );
        assert_eq!(
            tunnel_route_args(true, "2001:db8::/32", "fd71:e1::1", "qeli0", 7, false),
            [
                "-6",
                "route",
                "add",
                "2001:db8::/32",
                "dev",
                "qeli0",
                "metric",
                "7"
            ]
        );
        assert_eq!(
            tunnel_route_args(false, "10.20.0.0/16", "10.9.0.1", "tap0", 9, true),
            [
                "route",
                "add",
                "10.20.0.0/16",
                "via",
                "10.9.0.1",
                "dev",
                "tap0",
                "metric",
                "9"
            ]
        );
    }

    #[test]
    fn ipv6_capture_routes_override_global_and_ula_physical_aggregates() {
        assert_eq!(
            full_tunnel_prefixes(super::NetworkAddressFamily::Ipv6),
            IPV6_CAPTURE_PREFIXES
        );
        assert_eq!(
            IPV6_CAPTURE_PREFIXES,
            &["::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7"]
        );
    }

    #[test]
    fn connected_tunnel_prefix_is_canonical_for_ipv4_and_ipv6() {
        assert_eq!(
            connected_tunnel_cidr("10.9.0.27".parse::<IpAddr>().unwrap(), 24).unwrap(),
            "10.9.0.0/24"
        );
        assert_eq!(
            connected_tunnel_cidr("fd71:e1:20::beef".parse::<IpAddr>().unwrap(), 64).unwrap(),
            "fd71:e1:20::/64"
        );
        assert!(connected_tunnel_cidr("10.9.0.27".parse().unwrap(), 64).is_err());
    }

    #[test]
    fn existing_route_match_is_token_exact_and_stays_on_one_route() {
        assert!(route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth0 metric 5\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
        assert!(!route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth01 metric 5\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
        assert!(!route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth1\n192.0.2.10 via 10.0.0.2 dev eth0\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
    }

    #[test]
    fn pushed_route_plan_preserves_gateway_and_metric_after_policy_filtering() {
        let json = r#"[
            {"cidr":"192.0.2.0/24","gateway":"10.0.0.9","metric":7},
            {"cidr":"0.0.0.0/1","gateway":"10.0.0.1","metric":1},
            {"cidr":"not-a-route","gateway":"10.0.0.1"}
        ]"#;
        let routes = planned_pushed_routes(json, "10.0.0.1").unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cidr, "192.0.2.0/24");
        assert_eq!(routes[0].gateway, "10.0.0.9");
        assert_eq!(routes[0].metric, 7);
    }

    #[test]
    fn pushed_cidr_validation() {
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("fd00::/64"));
        assert!(is_valid_cidr("2001:db8::/32"));

        assert!(!is_valid_cidr("10.0.0.0")); // no prefix
        assert!(!is_valid_cidr("10.0.0.0/33")); // v4 prefix too large
        assert!(!is_valid_cidr("fd00::/129")); // v6 prefix too large
        assert!(!is_valid_cidr("not-an-ip/24"));
        assert!(!is_valid_cidr("-10.0.0.0/8")); // option-looking
        assert!(!is_valid_cidr("10.0.0.0/8 dev eth0")); // injected args
    }

    #[test]
    fn pushed_gateway_validation() {
        assert!(is_valid_gateway("10.0.0.1"));
        assert!(is_valid_gateway("fe80::1"));

        assert!(!is_valid_gateway("-1.2.3.4"));
        assert!(!is_valid_gateway("10.0.0.1/24"));
        assert!(!is_valid_gateway("gateway"));
        assert!(!is_valid_gateway("10.0.0.1 metric 0"));
    }
}

// ── fault injection: does the routing layer actually fail CLOSED? ────────────
//
// Everything below drives `setup_routes` / `cleanup_routes` with a FAKE `ip` on PATH.
// That is the point: the interesting behaviour here is "we ran a command and interpreted
// its result", and the failures that matter are the ones where the command did NOT work —
// which a healthy machine will not produce on demand. With a shim these tests need no
// root, no TUN and no network, because nothing real is ever configured.
//
// The shim records every invocation, so a test can assert not just the outcome but
// exactly WHICH commands ran. That is how "cleanup removes only what it created" is
// checked — something no amount of end-to-end testing on a healthy box would reveal.
#[cfg(all(test, target_os = "linux"))]
mod fault_injection {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};

    /// `PATH` is process-global, so shimmed tests must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Shim {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        old_path: String,
    }

    impl Shim {
        /// `fail_on` — argument-line substrings that make the fake `ip` exit non-zero
        /// with `stderr_text`. Everything else succeeds.
        fn new(tag: &str, fail_on: &[&str], stderr_text: &str) -> Shim {
            Self::new_with_route_show(tag, fail_on, stderr_text, Some("shown dev qtest"))
        }

        #[cfg(feature = "experimental-roaming")]
        fn new_with_route_show_cases(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show_cases: &[(&str, Option<&str>)],
            route_show: Option<&str>,
        ) -> Shim {
            Self::build(tag, fail_on, stderr_text, route_show_cases, route_show)
        }

        fn new_with_route_show(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show: Option<&str>,
        ) -> Shim {
            Self::build(tag, fail_on, stderr_text, &[], route_show)
        }

        fn build(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show_cases: &[(&str, Option<&str>)],
            route_show: Option<&str>,
        ) -> Shim {
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-shim-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("case \"$*\" in\n");
            for cond in fail_on {
                script.push_str(&format!(
                    "  *\"{cond}\"*) echo '{stderr_text}' >&2; exit 2;;\n"
                ));
            }
            // `route get` must answer with a gateway and `route show` with a device, or
            // setup_routes cannot get as far as the behaviour under test.
            script.push_str(
                "  *\"route get\"*) echo '1.2.3.4 via 10.0.0.254 dev eth0 src 10.0.0.5'; exit 0;;\n",
            );
            for (pattern, result) in route_show_cases {
                if let Some(result) = result {
                    script.push_str(&format!("  *\"{pattern}\"*) echo '{result}'; exit 0;;\n"));
                } else {
                    script.push_str(&format!("  *\"{pattern}\"*) exit 0;;\n"));
                }
            }
            if let Some(route_show) = route_show {
                script.push_str(&format!(
                    "  *\"route show\"*) echo '{route_show}'; exit 0;;\n"
                ));
            } else {
                script.push_str("  *\"route show\"*) exit 0;;\n");
            }
            script.push_str("esac\nexit 0\n");

            let bin = dir.join("ip");
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            // The ownership journal is process-global and deliberately SURVIVES a failed
            // setup (those routes were created and still need removing later). Across
            // tests that means one scenario inherits another's entries, so start clean.
            let _ = take_created();

            let old_path = std::env::var("PATH").unwrap_or_default();
            std::env::set_var("PATH", format!("{}:{}", dir.display(), old_path));
            Shim {
                dir,
                _guard: guard,
                old_path,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Shim {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.old_path);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn full_tunnel() -> ClientRoutingConfig {
        ClientRoutingConfig {
            add_default_gateway: true,
            // The IPv6 leg has its own behaviour; keep these focused on IPv4 routing.
            allow_ipv6_leak: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_failed_full_tunnel_half_refuses_the_connection() {
        // The regression this exists for: losing one /1 half used to be a warn the client
        // carried on from, so half of IPv4 left in the clear while the UI said "full
        // tunnel".
        let _shim = Shim::new(
            "half",
            &["route add 128.0.0.0/1"],
            "RTNETLINK answers: permission denied",
        );
        let err = setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("128.0.0.0/1") && msg.contains("refusing"),
            "a half-installed default route must refuse, got: {msg}"
        );
    }

    #[test]
    fn a_route_that_lies_about_success_is_caught_by_the_fib_check() {
        // iptables-nft taught us a zero exit code is not proof; `ip route add` gets the
        // same distrust. Here every add "succeeds" but the table shows a different device.
        let _shim = Shim::new("fib", &[], "");
        let err = setup_routes(&full_tunnel(), "10.0.0.1", "other0", "1.2.3.4").unwrap_err();
        assert!(
            err.to_string().contains("not in the routing table"),
            "expected the FIB verification to fire, got: {err}"
        );
    }

    #[test]
    fn a_failed_include_subnet_refuses_rather_than_leaking_it() {
        let cfg = ClientRoutingConfig {
            include: vec!["192.0.2.0/24".to_string()],
            ..Default::default()
        };
        let _shim = Shim::new(
            "incl",
            &["route add 192.0.2.0/24"],
            "RTNETLINK answers: network unreachable",
        );
        let err = setup_routes(&cfg, "10.0.0.1", "qtest", "1.2.3.4").unwrap_err();
        assert!(
            err.to_string().contains("192.0.2.0/24"),
            "an include route that did not install must refuse, got: {err}"
        );
    }

    #[test]
    fn a_failed_exclude_is_only_a_warning() {
        // Deliberately NOT fatal: a failed exclude leaves that subnet INSIDE the tunnel,
        // which is fail-closed. This test exists so nobody "tightens" it later.
        let cfg = ClientRoutingConfig {
            exclude: vec!["198.51.100.0/24".to_string()],
            ..Default::default()
        };
        let _shim = Shim::new(
            "excl",
            &["route add 198.51.100.0/24"],
            "RTNETLINK answers: no such device",
        );
        assert!(
            setup_routes(&cfg, "10.0.0.1", "qtest", "1.2.3.4").is_ok(),
            "a failed exclude bypass must not break the connection"
        );
    }

    #[test]
    fn cleanup_removes_the_bypass_route_we_created() {
        let shim = Shim::new("own", &[], "");
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();
        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();
        let calls = shim.calls();
        assert!(
            calls.contains("route del 1.2.3.4"),
            "a bypass route WE added must be removed on cleanup:\n{calls}"
        );
    }

    #[test]
    fn cleanup_leaves_a_pre_existing_route_alone() {
        // Setup treats an existing route as a benign no-op, so "File exists" means the
        // route was someone ELSE's — an operator's static bypass, another VPN's. Cleanup
        // used to delete it anyway, leaving the host worse than it found it.
        let shim = Shim::new(
            "preexist",
            &["route add 1.2.3.4"],
            "RTNETLINK answers: File exists",
        );
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();
        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();
        let calls = shim.calls();
        assert!(
            !calls.contains("route del 1.2.3.4"),
            "a route that already existed is not ours to delete:\n{calls}"
        );
    }

    #[test]
    fn cleanup_surfaces_failure_and_retains_ownership_for_retry() {
        let shim = Shim::new(
            "cleanup-fail",
            &["route del 1.2.3.4"],
            "RTNETLINK answers: Operation not permitted",
        );
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();

        let first = cleanup_routes("qtest", "1.2.3.4", &[]).unwrap_err();
        assert!(first.to_string().contains("Operation not permitted"));
        assert!(cleanup_routes("qtest", "1.2.3.4", &[]).is_err());

        let calls = shim.calls();
        assert_eq!(
            calls.matches("route del 1.2.3.4").count(),
            2,
            "a failed owned-route deletion must be retried:\n{calls}"
        );
    }

    #[test]
    fn cleanup_treats_an_already_absent_owned_route_as_success() {
        let shim = Shim::new(
            "cleanup-absent",
            &["route del 1.2.3.4"],
            "RTNETLINK answers: No such process",
        );
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();

        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();
        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();

        let calls = shim.calls();
        assert_eq!(
            calls.matches("route del 1.2.3.4").count(),
            1,
            "an already absent route must leave the ownership journal:\n{calls}"
        );
    }

    #[test]
    fn cleanup_surfaces_a_failed_tun_route_flush() {
        let _shim = Shim::new(
            "cleanup-flush",
            &["route flush dev qtest"],
            "RTNETLINK answers: Operation not permitted",
        );

        let err = cleanup_routes("qtest", "1.2.3.4", &[]).unwrap_err();
        assert!(err.to_string().contains("route flush dev qtest"));
        assert!(err.to_string().contains("Operation not permitted"));
    }

    #[cfg(feature = "experimental-roaming")]
    fn prepared_candidate() -> PreparedPathCandidate {
        PreparedPathCandidate {
            candidate_id: 41,
            update: crate::transport_core::path::PathUpdate {
                generation: 7,
                update_id: 3,
                platform_path_id: "linux:eth0".to_string(),
                reason: crate::transport_core::path::PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: Some(2),
                local_addresses: vec!["192.0.2.10".to_string(), "2001:db8::10".to_string()],
                resolved_addresses: vec![
                    crate::transport_core::path::PathResolution {
                        address: "198.51.100.20".to_string(),
                        ttl_secs: 30,
                    },
                    crate::transport_core::path::PathResolution {
                        address: "2001:db8::20".to_string(),
                        ttl_secs: 30,
                    },
                ],
                flags: crate::transport_core::path::PathUpdateFlags::default(),
            },
        }
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_prepare_is_read_only_and_queries_exact_source_and_interface() {
        let shim = Shim::new("candidate-prepare", &[], "");
        let candidate = prepared_candidate();
        let prepared = prepare_candidate_path_routes_on(&candidate, "qtest", "eth0").unwrap();

        assert_eq!(prepared.generation, 7);
        assert_eq!(prepared.candidate_id, 41);
        assert_eq!(prepared.routes.len(), 2);
        assert_eq!(
            prepared.routes[0].remote,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prepared.routes[0].source,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(prepared.routes[0].interface, "eth0");
        assert_eq!(prepared.routes[0].gateway.as_deref(), Some("10.0.0.254"));
        assert_eq!(
            prepared.routes[1].remote,
            "2001:db8::20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prepared.routes[1].source,
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );

        let calls = shim.calls();
        assert!(calls.contains("route get 198.51.100.20 from 192.0.2.10 oif eth0"));
        assert!(calls.contains("-6 route get 2001:db8::20 from 2001:db8::10 oif eth0"));
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_prepare_rejects_tunnel_or_mismatched_fib_interface() {
        let _shim = Shim::new("candidate-wrong-interface", &[], "");
        let candidate = prepared_candidate();
        assert!(prepare_candidate_path_routes_on(&candidate, "eth0", "eth0").is_err());
        let error = prepare_candidate_path_routes_on(&candidate, "qtest", "wlan0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("through wlan0"));
    }

    #[cfg(feature = "experimental-roaming")]
    fn ipv4_candidate() -> PreparedPathCandidate {
        let mut candidate = prepared_candidate();
        candidate.update.local_addresses.truncate(1);
        candidate.update.resolved_addresses.truncate(1);
        candidate
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_adds_only_missing_routes_and_journals_ownership() {
        let shim = Shim::new_with_route_show("candidate-add", &[], "", None);
        let prepared =
            prepare_candidate_path_routes_on(&prepared_candidate(), "qtest", "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("route add 198.51.100.20 via 10.0.0.254 dev eth0 src 192.0.2.10"));
        assert!(
            calls.contains("-6 route add 2001:db8::20 via 10.0.0.254 dev eth0 src 2001:db8::10")
        );
        assert!(created_by_us_owned(&carrier_route_undo(
            "198.51.100.20".parse::<IpAddr>().unwrap()
        )));
        assert!(created_by_us_owned(&carrier_route_undo(
            "2001:db8::20".parse::<IpAddr>().unwrap()
        )));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_rejects_operator_conflict_before_mutation() {
        let shim = Shim::new("candidate-conflict", &[], "");
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), "qtest", "eth0").unwrap();
        let error = prepared.commit(&[]).unwrap_err().to_string();
        assert!(error.contains("operator-owned"));

        let calls = shim.calls();
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_preserves_matching_operator_route_without_claiming_it() {
        let shim = Shim::new_with_route_show(
            "candidate-operator-match",
            &[],
            "",
            Some("198.51.100.20 via 10.0.0.254 dev eth0"),
        );
        let remote = "198.51.100.20".parse::<IpAddr>().unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), "qtest", "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        let calls = shim.calls();
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
        assert!(!created_by_us_owned(&carrier_route_undo(remote)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_replaces_only_a_qeli_owned_route() {
        let shim = Shim::new_with_route_show(
            "candidate-replace",
            &[],
            "",
            Some("198.51.100.20 via 192.0.2.1 dev old0"),
        );
        let remote = "198.51.100.20".parse::<IpAddr>().unwrap();
        note_created_owned(carrier_route_undo(remote));
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), "qtest", "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        assert!(shim
            .calls()
            .contains("route replace 198.51.100.20 via 10.0.0.254 dev eth0 src 192.0.2.10"));
        assert!(created_by_us_owned(&carrier_route_undo(remote)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_rolls_back_prior_add_when_a_later_family_fails() {
        let shim = Shim::new_with_route_show(
            "candidate-rollback",
            &["-6 route add 2001:db8::20"],
            "RTNETLINK answers: network unreachable",
            None,
        );
        let first = "198.51.100.20".parse::<IpAddr>().unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&prepared_candidate(), "qtest", "eth0").unwrap();
        let error = prepared.commit(&[]).unwrap_err().to_string();
        assert!(error.contains("network unreachable"));

        let calls = shim.calls();
        assert!(calls.contains("route del 198.51.100.20"));
        assert!(!created_by_us_owned(&carrier_route_undo(first)));
    }

    #[cfg(feature = "experimental-roaming")]
    fn ipv6_candidate() -> PreparedPathCandidate {
        let mut candidate = prepared_candidate();
        candidate.update.local_addresses.remove(0);
        candidate.update.resolved_addresses.remove(0);
        candidate
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn family_commit_retires_the_previous_qeli_owned_carrier() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-retire-family",
            &[],
            "",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev old0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        note_created_owned(carrier_route_undo(old));
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), "qtest", "eth0").unwrap();
        prepared.commit(&[old]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("-6 route add 2001:db8::20"));
        assert!(calls.contains("route del 198.51.100.20"));
        assert!(!created_by_us_owned(&carrier_route_undo(old)));
        assert!(created_by_us_owned(&carrier_route_undo(new)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn family_commit_does_not_retire_an_operator_owned_previous_carrier() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-keep-operator-family",
            &[],
            "",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev operator0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), "qtest", "eth0").unwrap();
        prepared.commit(&[old]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("-6 route add 2001:db8::20"));
        assert!(
            !calls.contains("route del 198.51.100.20"),
            "an operator-owned previous route must not be retired:\n{calls}"
        );
        assert!(!created_by_us_owned(&carrier_route_undo(old)));
        assert!(created_by_us_owned(&carrier_route_undo(new)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn failed_old_carrier_retirement_rolls_back_the_new_family() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-retire-rollback",
            &["route del 198.51.100.20"],
            "RTNETLINK answers: operation not permitted",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev old0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        note_created_owned(carrier_route_undo(old));
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), "qtest", "eth0").unwrap();
        let error = prepared.commit(&[old]).unwrap_err().to_string();

        assert!(error.contains("could not retire previous carrier route"));
        assert!(shim.calls().contains("-6 route del 2001:db8::20"));
        assert!(created_by_us_owned(&carrier_route_undo(old)));
        assert!(!created_by_us_owned(&carrier_route_undo(new)));
    }
}
