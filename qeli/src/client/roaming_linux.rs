//! Linux physical-path observation for the feature-gated roaming adapter.
//!
//! The active tunnel deliberately uses two `/1` capture routes, so the kernel's remaining
//! `default` routes describe physical candidates. We reuse already authenticated/pinned server
//! addresses instead of asking a resolver which may itself be routed through a failed tunnel.

use super::{carrier_candidate_ips, LinuxPathController};
use crate::transport_core::path::{PathResolution, PathUpdate, PathUpdateFlags, PathUpdateReason};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const WAKE_GAP: Duration = Duration::from_secs(5);
const STABLE_SAMPLES: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalPath {
    interface_index: u32,
    interface_name: String,
    local_addresses: Vec<String>,
    route_fingerprint: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn ip_flag(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl From<IpAddr> for AddressFamily {
    fn from(value: IpAddr) -> Self {
        if value.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

#[derive(Debug, Deserialize)]
struct RouteRecord {
    dev: Option<String>,
    gateway: Option<String>,
    metric: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    family: AddressFamily,
    interface_name: String,
    gateway: Option<String>,
    metric: u64,
}

#[derive(Debug, Deserialize)]
struct AddressRecord {
    ifindex: u32,
    #[serde(default)]
    addr_info: Vec<AddressInfo>,
}

#[derive(Debug, Deserialize)]
struct AddressInfo {
    family: String,
    local: String,
    scope: String,
    #[serde(default)]
    flags: Vec<String>,
}

fn ip_json(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let output = Command::new("ip").args(args).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn parse_default_route(
    bytes: &[u8],
    family: AddressFamily,
    tunnel_interface: &str,
) -> anyhow::Result<Option<DefaultRoute>> {
    let records: Vec<RouteRecord> = serde_json::from_slice(bytes)?;
    Ok(records
        .into_iter()
        .filter_map(|record| {
            let interface_name = record.dev?;
            (interface_name != tunnel_interface).then_some(DefaultRoute {
                family,
                interface_name,
                gateway: record.gateway,
                metric: record.metric.unwrap_or(0),
            })
        })
        .min_by_key(|route| route.metric))
}

fn default_route(
    family: AddressFamily,
    tunnel_interface: &str,
) -> anyhow::Result<Option<DefaultRoute>> {
    let bytes = ip_json(&[family.ip_flag(), "-j", "route", "show", "default"])?;
    parse_default_route(&bytes, family, tunnel_interface)
}

fn parse_interface_addresses(
    bytes: &[u8],
    allowed_families: &HashSet<AddressFamily>,
) -> anyhow::Result<(u32, Vec<String>)> {
    let mut records: Vec<AddressRecord> = serde_json::from_slice(bytes)?;
    let record = records
        .pop()
        .ok_or_else(|| anyhow::anyhow!("candidate interface disappeared"))?;
    let mut seen = HashSet::new();
    let addresses = record
        .addr_info
        .into_iter()
        .filter(|address| address.scope == "global")
        .filter(|address| {
            !address
                .flags
                .iter()
                .any(|flag| matches!(flag.as_str(), "tentative" | "dadfailed" | "deprecated"))
        })
        .filter_map(|address| {
            let family = match address.family.as_str() {
                "inet" => AddressFamily::Ipv4,
                "inet6" => AddressFamily::Ipv6,
                _ => return None,
            };
            (allowed_families.contains(&family) && seen.insert(address.local.clone()))
                .then_some(address.local)
        })
        .collect();
    Ok((record.ifindex, addresses))
}

fn observe_physical_path(
    tunnel_interface: &str,
    remote_addresses: &[IpAddr],
) -> anyhow::Result<Option<PhysicalPath>> {
    let ipv4 = default_route(AddressFamily::Ipv4, tunnel_interface)?;
    let ipv6 = default_route(AddressFamily::Ipv6, tunnel_interface)?;
    let route_for = |family| match family {
        AddressFamily::Ipv4 => ipv4.as_ref(),
        AddressFamily::Ipv6 => ipv6.as_ref(),
    };
    let selected = remote_addresses
        .iter()
        .find_map(|address| route_for((*address).into()))
        .cloned();
    let Some(selected) = selected else {
        return Ok(None);
    };

    let matching_routes = [ipv4.as_ref(), ipv6.as_ref()]
        .into_iter()
        .flatten()
        .filter(|route| route.interface_name == selected.interface_name)
        .collect::<Vec<_>>();
    let allowed_families = matching_routes
        .iter()
        .map(|route| route.family)
        .collect::<HashSet<_>>();
    let bytes = ip_json(&["-j", "address", "show", "dev", &selected.interface_name])?;
    let (interface_index, local_addresses) = parse_interface_addresses(&bytes, &allowed_families)?;
    if local_addresses.is_empty() {
        return Ok(None);
    }
    let route_fingerprint = matching_routes
        .into_iter()
        .map(|route| {
            format!(
                "{}:{}:{}",
                route.family.label(),
                route.gateway.as_deref().unwrap_or("on-link"),
                route.metric
            )
        })
        .collect();
    Ok(Some(PhysicalPath {
        interface_index,
        interface_name: selected.interface_name,
        local_addresses,
        route_fingerprint,
    }))
}

fn path_update_json(
    path: &PhysicalPath,
    generation: u64,
    update_id: u64,
    reason: PathUpdateReason,
    remote_addresses: &[IpAddr],
) -> anyhow::Result<String> {
    let mut seen = HashSet::new();
    let resolved_addresses = remote_addresses
        .iter()
        .copied()
        .filter(|address| seen.insert(*address))
        .map(|address| PathResolution {
            address: address.to_string(),
            // The monitor does not perform DNS. These are already pinned, authenticated carrier
            // addresses and are intentionally not advertised as a reusable DNS cache entry.
            ttl_secs: 0,
        })
        .collect();
    let flags = PathUpdateFlags {
        default_route_changed: reason == PathUpdateReason::DefaultRouteChanged,
        wake: reason == PathUpdateReason::Wake,
        same_network_nat_failure: reason == PathUpdateReason::SameNetworkNatFailure,
    };
    Ok(serde_json::to_string(&PathUpdate {
        generation,
        update_id,
        platform_path_id: format!("linux-if{}", path.interface_index),
        reason,
        network_token: Some(format!("linux-ifindex-{}", path.interface_index)),
        interface_index: Some(path.interface_index),
        local_addresses: path.local_addresses.clone(),
        resolved_addresses,
        flags,
    })?)
}

/// Start the Linux physical-path sampler and register its bounded transport-proven NAT-failure
/// trigger with the shared path controller. The sampler remains the single owner of observation
/// and update IDs, so liveness recovery cannot race route/wake detection or invent platform facts
/// in the actor.
pub(super) fn spawn(
    controller: Arc<LinuxPathController>,
    tunnel_interface: String,
    generation: u64,
) -> tokio::task::JoinHandle<()> {
    let (same_network_nat_failure_tx, mut same_network_nat_failure_rx) =
        tokio::sync::mpsc::channel(1);
    controller.install_same_network_nat_failure_trigger(same_network_nat_failure_tx);
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_tick = tokio::time::Instant::now();
        let mut baseline: Option<PhysicalPath> = None;
        let mut pending: Option<(PhysicalPath, u8)> = None;
        let mut update_id = 0u64;

        loop {
            let same_network_nat_failure = tokio::select! {
                _ = interval.tick() => false,
                request = same_network_nat_failure_rx.recv(),
                    if !same_network_nat_failure_rx.is_closed() => request.is_some(),
            };
            let now = tokio::time::Instant::now();
            let woke = if same_network_nat_failure {
                false
            } else {
                let woke = now.duration_since(last_tick) >= WAKE_GAP;
                last_tick = now;
                woke
            };
            let remotes = carrier_candidate_ips();
            if remotes.is_empty() {
                continue;
            }
            let tun = tunnel_interface.clone();
            let observed_remotes = remotes.clone();
            let observed = match tokio::task::spawn_blocking(move || {
                observe_physical_path(&tun, &observed_remotes)
            })
            .await
            {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => continue,
                Ok(Err(error)) => {
                    log::debug!("Linux roaming path sample failed: {error}");
                    continue;
                }
                Err(error) => {
                    log::warn!("Linux roaming path sampler stopped unexpectedly: {error}");
                    continue;
                }
            };
            if baseline.is_none() {
                log::debug!(
                    "Linux roaming baseline: {} (ifindex {})",
                    observed.interface_name,
                    observed.interface_index
                );
                baseline = Some(observed.clone());
                if !same_network_nat_failure {
                    continue;
                }
            }
            let changed = baseline
                .as_ref()
                .is_some_and(|current| current != &observed);
            if !changed && !woke && !same_network_nat_failure {
                pending = None;
                continue;
            }
            if changed {
                match pending.as_mut() {
                    Some((candidate, samples)) if candidate == &observed => {
                        *samples = samples.saturating_add(1);
                        if *samples < STABLE_SAMPLES {
                            continue;
                        }
                    }
                    _ => {
                        pending = Some((observed, 1));
                        continue;
                    }
                }
            }
            let candidate = pending.take().map(|(path, _)| path).unwrap_or(observed);
            update_id = update_id.saturating_add(1);
            let reason = if same_network_nat_failure && !changed {
                PathUpdateReason::SameNetworkNatFailure
            } else if woke && !changed {
                PathUpdateReason::Wake
            } else {
                PathUpdateReason::DefaultRouteChanged
            };
            let update = match path_update_json(&candidate, generation, update_id, reason, &remotes)
            {
                Ok(update) => update,
                Err(error) => {
                    log::warn!("Linux roaming PathUpdate encoding failed: {error}");
                    baseline = Some(candidate);
                    continue;
                }
            };
            let path_id = candidate.interface_name.clone();
            let submitter = controller.clone();
            match tokio::task::spawn_blocking(move || submitter.submit_path_update(&update)).await {
                Ok(Ok(candidate_id)) => log::info!(
                    "Linux roaming prepared candidate {} on {} ({reason:?})",
                    candidate_id,
                    path_id
                ),
                Ok(Err(error)) => log::warn!(
                    "Linux roaming rejected path observation on {}: {}",
                    path_id,
                    error
                ),
                Err(error) => log::warn!(
                    "Linux roaming PathUpdate worker stopped unexpectedly on {}: {}",
                    path_id,
                    error
                ),
            }
            // Avoid a hot loop on a stable but unusable path. Carrier liveness still triggers the
            // ordinary reconnect fallback; another route/address change or wake creates a new update.
            baseline = Some(candidate);
        }
    });
    task
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_parser_ignores_tunnel_and_uses_lowest_metric() {
        let json = br#"[
            {"dst":"default","dev":"qeli0","metric":1},
            {"dst":"default","gateway":"192.0.2.1","dev":"eth1","metric":200},
            {"dst":"default","gateway":"198.51.100.1","dev":"eth0","metric":100}
        ]"#;
        let route = parse_default_route(json, AddressFamily::Ipv4, "qeli0")
            .unwrap()
            .unwrap();
        assert_eq!(route.interface_name, "eth0");
        assert_eq!(route.gateway.as_deref(), Some("198.51.100.1"));
    }

    #[test]
    fn address_parser_keeps_only_ready_global_addresses_on_routed_families() {
        let json = br#"[{
            "ifindex":7,
            "addr_info":[
                {"family":"inet","local":"192.0.2.10","scope":"global"},
                {"family":"inet6","local":"2001:db8::10","scope":"global","flags":["tentative"]},
                {"family":"inet6","local":"fe80::1","scope":"link"}
            ]
        }]"#;
        let families = HashSet::from([AddressFamily::Ipv4, AddressFamily::Ipv6]);
        let (index, addresses) = parse_interface_addresses(json, &families).unwrap();
        assert_eq!(index, 7);
        assert_eq!(addresses, vec!["192.0.2.10"]);
    }

    #[test]
    fn same_network_nat_failure_uses_a_fresh_update_on_the_same_path() {
        let path = PhysicalPath {
            interface_index: 7,
            interface_name: "eth0".into(),
            local_addresses: vec!["192.0.2.10".into()],
            route_fingerprint: vec!["ipv4:192.0.2.1:100".into()],
        };
        let json = path_update_json(
            &path,
            9,
            4,
            PathUpdateReason::SameNetworkNatFailure,
            &["198.51.100.20".parse().unwrap()],
        )
        .unwrap();
        let update: PathUpdate = serde_json::from_str(&json).unwrap();
        update.validate().unwrap();
        assert_eq!(update.generation, 9);
        assert_eq!(update.update_id, 4);
        assert_eq!(update.interface_index, Some(7));
        assert_eq!(update.reason, PathUpdateReason::SameNetworkNatFailure);
        assert!(update.flags.same_network_nat_failure);
        assert!(!update.flags.default_route_changed);
        assert!(!update.flags.wake);
    }

    #[test]
    #[ignore = "requires the Linux ip tool and a live global default route"]
    fn live_observation_finds_a_source_complete_physical_path() {
        let path = observe_physical_path(
            "qeli-test-tunnel-that-does-not-exist",
            &["1.1.1.1".parse().unwrap()],
        )
        .unwrap()
        .expect("physical IPv4 default route");
        assert!(path.interface_index > 0);
        assert!(!path.interface_name.is_empty());
        assert!(!path.local_addresses.is_empty());
    }
}
