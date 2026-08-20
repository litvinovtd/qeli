//! Sanitized transport-health projection for the panel.
//!
//! This endpoint joins the on-disk intended configuration with the worker's live sessions.
//! It intentionally selects fields one by one: serializing a whole profile would expose the
//! obfs pre-shared key and other deployment credentials to a page that only needs diagnostics.

use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn health(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let live = super::status::control(json!({"cmd": "list-clients"})).await;
    let worker_ok = live
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let clients = super::status::client_array(&live);
    let Some(config) = super::status::current_config(&state).await else {
        return Ok(Json(super::err_json(
            "cannot read the current server configuration",
        )));
    };

    let nat_available = crate::server::nat::available();
    let mut profiles = Vec::with_capacity(config.profiles.len());
    let mut total_sent = 0u64;
    let mut total_recv = 0u64;
    let mut total_dropped = 0u64;
    let mut active_profiles = 0usize;

    for profile in &config.profiles {
        let sessions = clients
            .iter()
            .filter(|client| client.get("profile").and_then(Value::as_str) == Some(&profile.name))
            .collect::<Vec<_>>();
        let sent = sessions.iter().fold(0u64, |sum, client| {
            sum.saturating_add(
                client
                    .get("bytes_sent")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        });
        let recv = sessions.iter().fold(0u64, |sum, client| {
            sum.saturating_add(
                client
                    .get("bytes_recv")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        });
        let dropped = sessions.iter().fold(0u64, |sum, client| {
            sum.saturating_add(client.get("dropped").and_then(Value::as_u64).unwrap_or(0))
        });
        let streams = sessions.iter().fold(0u64, |sum, client| {
            sum.saturating_add(client.get("streams").and_then(Value::as_u64).unwrap_or(1))
        });

        total_sent = total_sent.saturating_add(sent);
        total_recv = total_recv.saturating_add(recv);
        total_dropped = total_dropped.saturating_add(dropped);
        if !sessions.is_empty() {
            active_profiles += 1;
        }

        let mut alerts = Vec::new();
        if profile.enabled && !worker_ok {
            alerts.push(json!({
                "severity": "critical",
                "message": "The data-plane worker is unavailable; this profile cannot accept tunnels.",
            }));
        }
        if dropped > 0 {
            alerts.push(json!({
                "severity": "warning",
                "message": format!("{dropped} outbound packet(s) were dropped by server backpressure."),
            }));
        }
        if profile.routing.nat.enabled && !nat_available {
            alerts.push(json!({
                "severity": "critical",
                "message": "NAT is enabled but iptables is unavailable; full-tunnel internet egress will fail.",
            }));
        }
        if profile.bind.transport == "udp"
            && profile.performance.udp.recv_buffer_auto
            && profile.performance.udp.recv_buffer_size == 0
        {
            alerts.push(json!({
                "severity": "warning",
                "message": "UDP receive buffering is automatic but starts from the OS default; verify kernel buffer ceilings under load.",
            }));
        }
        if !profile.obfuscation.heartbeat.enabled
            && !profile.obfuscation.traffic_shaping.enabled
            && profile.performance.connection.idle_timeout_secs == 0
        {
            alerts.push(json!({
                "severity": "warning",
                "message": "Heartbeat, shaping and idle timeout are all disabled; a dead peer may remain allocated indefinitely.",
            }));
        }

        let status = if !profile.enabled {
            "disabled"
        } else if !worker_ok {
            "unavailable"
        } else if sessions.is_empty() {
            "ready"
        } else {
            "active"
        };

        profiles.push(json!({
            "name": profile.name,
            "status": status,
            "sessions": sessions.len(),
            "streams": streams,
            "bytes_sent": sent,
            "bytes_recv": recv,
            "dropped": dropped,
            "alerts": alerts,
            "endpoint": {
                "transport": profile.bind.transport,
                "address": profile.bind.address,
                "port": profile.bind.port,
                "additional_listeners": profile.bind.listen,
            },
            "tunnel": {
                "device": profile.tun.name,
                "ip_mode": profile.tun.ip_mode,
                "address": profile.tun.address,
                "pool": profile.pool.cidr,
                "ipv4_address": profile.tun.address,
                "ipv6_address": profile.tun.ipv6_address,
                "ipv4_pool": profile.pool.cidr,
                "ipv6_pool": profile.pool.ipv6.cidr,
                "mtu": profile.tun.mtu,
                "queues": profile.tun.queues,
                "tx_queue_len": profile.tun.tx_queue_len,
            },
            "routing": {
                "nat": profile.routing.nat.enabled,
                "nat_interface": profile.routing.nat.interface,
                "ipv6_mode": profile.routing.ipv6.mode,
                "ipv6_interface": profile.routing.ipv6.interface,
                "client_to_client": profile.routing.client_to_client,
                "advertised_routes": profile.routing.advertised_routes.len(),
            },
            "dns": {
                "enabled": profile.dns.enabled,
                "listen": profile.dns.listen,
                "listen_ipv6": profile.dns.listen_ipv6,
                "port": profile.dns.port,
                "upstream_protocol": profile.dns.upstream_protocol,
                "upstreams": profile.dns.upstream,
                "push_servers": profile.dns.push_servers,
            },
            "wire": {
                "mode": profile.obfuscation.mode,
                "fronting": profile.obfuscation.fronting,
                "padding": profile.obfuscation.padding.enabled,
                "fragmentation": profile.obfuscation.fragmentation.enabled,
                "heartbeat": profile.obfuscation.heartbeat.enabled,
                "heartbeat_interval_ms": profile.obfuscation.heartbeat.interval_ms,
                "shaping": profile.obfuscation.traffic_shaping.enabled,
                "stealth": profile.obfuscation.traffic_shaping.stealth,
                "quic": profile.obfuscation.quic.enabled,
                "multipath": profile.obfuscation.multipath.enabled,
                "multipath_adaptive": profile.obfuscation.multipath.adaptive,
                "max_streams": profile.obfuscation.multipath.max_streams,
            },
            "buffers": {
                "tcp_send": profile.performance.tcp.send_buffer_size,
                "tcp_recv": profile.performance.tcp.recv_buffer_size,
                "udp_send": profile.performance.udp.send_buffer_size,
                "udp_recv": profile.performance.udp.recv_buffer_size,
                "udp_recv_auto": profile.performance.udp.recv_buffer_auto,
                "tun_read": profile.performance.tun.read_buffer_size,
            },
            "limits": {
                "max_clients": profile.performance.connection.max_clients,
                "handshake_timeout_secs": profile.performance.connection.handshake_timeout_secs,
                "idle_timeout_secs": profile.performance.connection.idle_timeout_secs,
            },
        }));
    }

    let alert_count = profiles
        .iter()
        .map(|profile| {
            profile
                .get("alerts")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum::<usize>();
    Ok(Json(json!({
        "ok": true,
        "worker_ok": worker_ok,
        "generated_at_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0),
        "summary": {
            "profiles": profiles.len(),
            "active_profiles": active_profiles,
            "sessions": clients.len(),
            "alerts": alert_count,
            "bytes_sent": total_sent,
            "bytes_recv": total_recv,
            "dropped": total_dropped,
        },
        "profiles": profiles,
    })))
}
