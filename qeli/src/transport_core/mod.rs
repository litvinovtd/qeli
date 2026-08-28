//! Cross-platform lifecycle boundary for the shared qeli client core.
//!
//! The core owns strict configuration, lifecycle, carriers, handshakes and packet pumps.
//! Platform adapters remain responsible for system APIs and must positively acknowledge a
//! [`NetworkPlan`] before the core enters [`ClientState::Running`]. Android executes the full
//! data plane through ABI 1.6, iOS uses the ABI 1.7 packet seam, macOS adopts its utun fd,
//! and the same common sessions run behind the in-process Linux adapter. ABI 1.8 exposes the
//! shared UDP first-flight diagnostic; ABI 1.9 moves the Windows Wintun session/rings into Rust;
//! ABI 1.10 appends observable UDP receive-buffer/drop counters to the stats structure; ABI 1.11
//! adds the dual-family NetworkPlan representation while retaining the legacy IPv4 projection;
//! ABI 1.12 adds the experimental generation-scoped path transaction contract and telemetry.

use self::path::{
    PathCandidate, PathCandidatePhase, PathCommand, PathCommandAction, PathUpdate,
    PreparedPathCandidate, QueuedPathCandidate,
};
use crate::config::{client::ClientConfig, parse_client_config_strict, share::ClientLink};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroize;

#[cfg(any(feature = "client", feature = "server", feature = "transport-core-ffi"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod buffer_pool;

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) mod carrier;

#[cfg(any(test, feature = "transport-core-ffi"))]
pub(crate) mod diagnostic;

#[cfg(all(feature = "transport-core-ffi", target_pointer_width = "64"))]
pub mod ffi;

// Android consumes the same generation-checked control-plane ABI through JNI. Keep the
// adapter behind the opt-in whole-client feature so a compatibility-only realtls build
// cannot accidentally ship Kotlin declarations without their native implementation.
#[cfg(all(
    target_os = "android",
    feature = "transport-core-ffi",
    target_pointer_width = "64"
))]
pub mod jni;

// Unix fd-based clients share one TUN backend. Android supplies the descriptor through
// VpnService, macOS supplies its utun control socket, and Linux opens the device locally.
#[cfg(all(unix, any(feature = "client", feature = "transport-core-ffi")))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod linux_tun;

// Wintun and iOS packetFlow cannot hand Rust a portable descriptor. Their small platform
// wrappers exchange bounded packet batches with the same common transport loops.
#[cfg(any(feature = "client", feature = "transport-core-ffi"))]
#[cfg_attr(not(any(target_os = "windows", target_os = "ios")), allow(dead_code))]
pub(crate) mod packet_tun;

// The Windows whole-client core opens a second handle to the platform-created adapter and owns
// the Wintun session, read event and both packet rings for one acknowledged generation.
#[cfg(all(
    target_os = "windows",
    any(feature = "client", feature = "transport-core-ffi")
))]
pub(crate) mod wintun;

// The first live external data plane is a synchronous FFI runner: it releases the handle
// mutex while waiting for protect/trust/network ACKs and owns every payload byte afterward.
#[cfg(all(
    any(
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios"
    ),
    feature = "transport-core-ffi"
))]
pub(crate) mod runtime;
pub(crate) mod udp_buffer;
pub(crate) mod udp_client_framing;
pub(crate) mod udp_receive;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod network;

pub mod path;

#[cfg(feature = "experimental-roaming")]
pub mod tcp_roaming;

#[cfg(feature = "experimental-roaming")]
pub mod udp_roaming;

#[cfg(feature = "experimental-roaming")]
pub mod udp_roaming_client;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod session;

#[cfg(all(feature = "transport-core-ffi", not(target_pointer_width = "64")))]
compile_error!(
    "transport-core-ffi currently supports only 64-bit targets; shipped GUI clients are \
     64-bit, while 32-bit router builds must leave this feature disabled"
);

pub const ABI_VERSION_MAJOR: u16 = 1;
pub const ABI_VERSION_MINOR: u16 = 12;
pub const ABI_VERSION: u32 = ((ABI_VERSION_MAJOR as u32) << 16) | ABI_VERSION_MINOR as u32;

pub const DEFAULT_EVENT_CAPACITY: usize = 64;
pub const MIN_EVENT_CAPACITY: usize = 2;
pub const MAX_EVENT_CAPACITY: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub(crate) const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 8;
const MAX_PLAN_STRING_BYTES: usize = 128;
const MAX_CONNECTION_LOG_LINES: usize = MAX_ROUTES + 24;
const MAX_CONNECTION_LOG_LINE_BYTES: usize = 1_024;
const MAX_PLATFORM_ERROR_CHARS: usize = 512;
const MAX_HANDSHAKE_NETWORK_BYTES: usize = 256 * 1024;

/// Capabilities implemented by this revision of the shared core ABI.
pub mod core_capability {
    pub const STRICT_CONFIG: u64 = 1 << 0;
    pub const LIFECYCLE_EVENTS: u64 = 1 << 1;
    pub const NETWORK_PLAN_ACK: u64 = 1 << 2;
    pub const TUN_FD_OWNERSHIP: u64 = 1 << 3;
    pub const SOCKET_PROTECT_ACK: u64 = 1 << 4;
    pub const DEVICE_ID_INPUT: u64 = 1 << 5;
    pub const SERVER_IDENTITY_ACK: u64 = 1 << 6;
    pub const HANDSHAKE_NETWORK_INPUT: u64 = 1 << 7;
    pub const NATIVE_DATA_PLANE: u64 = 1 << 8;
    pub const TUN_PACKET_IO: u64 = 1 << 9;
    pub const UDP_DIAGNOSTIC: u64 = 1 << 10;
    pub const WINTUN_IO: u64 = 1 << 11;
    pub const NETWORK_PLAN_V2: u64 = 1 << 12;
    pub const PATH_TRANSACTIONS: u64 = 1 << 13;
    #[cfg(feature = "experimental-roaming")]
    const EXPERIMENTAL: u64 = PATH_TRANSACTIONS;
    #[cfg(not(feature = "experimental-roaming"))]
    const EXPERIMENTAL: u64 = 0;
    pub const BASE: u64 = STRICT_CONFIG | LIFECYCLE_EVENTS | NETWORK_PLAN_ACK | NETWORK_PLAN_V2;
    #[cfg(target_os = "android")]
    pub const ALL: u64 = BASE
        | TUN_FD_OWNERSHIP
        | SOCKET_PROTECT_ACK
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | UDP_DIAGNOSTIC
        | EXPERIMENTAL;
    #[cfg(target_os = "windows")]
    pub const ALL: u64 = BASE
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | TUN_PACKET_IO
        | UDP_DIAGNOSTIC
        | WINTUN_IO
        | EXPERIMENTAL;
    #[cfg(target_os = "macos")]
    pub const ALL: u64 = BASE
        | TUN_FD_OWNERSHIP
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | TUN_PACKET_IO
        | UDP_DIAGNOSTIC
        | EXPERIMENTAL;
    #[cfg(target_os = "ios")]
    pub const ALL: u64 = BASE
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | TUN_PACKET_IO
        | UDP_DIAGNOSTIC
        | EXPERIMENTAL;
    #[cfg(not(any(
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios"
    )))]
    pub const ALL: u64 = BASE
        | SOCKET_PROTECT_ACK
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | UDP_DIAGNOSTIC
        | EXPERIMENTAL;
}

/// System operations a platform adapter is able to perform.
pub mod platform_capability {
    pub const ROUTES: u64 = 1 << 0;
    pub const DNS: u64 = 1 << 1;
    pub const KILL_SWITCH: u64 = 1 << 2;
    pub const TUN_FD: u64 = 1 << 3;
    pub const TUN_PACKET_BATCH: u64 = 1 << 4;
    pub const SOCKET_PROTECT: u64 = 1 << 5;
    pub const SERVER_IDENTITY: u64 = 1 << 6;
    pub const TUN_WINTUN: u64 = 1 << 7;
    /// The adapter can configure an IPv6 address on its TUN/packet tunnel.
    pub const IPV6_TUN: u64 = 1 << 8;
    /// The adapter can atomically install and roll back IPv6 routes.
    pub const IPV6_ROUTES: u64 = 1 << 9;
    /// The adapter can apply IPv6 resolvers without bypassing the tunnel.
    pub const IPV6_DNS: u64 = 1 << 10;
    /// The adapter can enforce the IPv6 side of a kill switch.
    pub const IPV6_KILL_SWITCH: u64 = 1 << 11;
    /// The adapter can atomically prepare, commit and roll back candidate path rules.
    pub const PATH_TRANSACTIONS: u64 = 1 << 12;
    /// The adapter can bind/protect a core-owned socket to the exact candidate path.
    pub const PATH_SOCKET_BINDING: u64 = 1 << 13;
    pub const ROAMING_PATH: u64 = PATH_TRANSACTIONS | PATH_SOCKET_BINDING;
    pub const SYSTEM_PLAN: u64 = ROUTES | DNS | KILL_SWITCH;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClientState {
    Created = 0,
    Connecting = 1,
    AwaitingNetwork = 2,
    Running = 3,
    Stopping = 4,
    Stopped = 5,
    Failed = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventKind {
    StateChanged = 1,
    NetworkPlan = 2,
    Error = 3,
    SocketProtect = 4,
    ServerIdentity = 5,
    PathCommand = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    InvalidArgument = -1,
    InvalidConfig = -2,
    InvalidState = -3,
    StalePlan = -4,
    EventQueueFull = -5,
    BufferTooSmall = -6,
    InvalidHandle = -7,
    Panic = -8,
    Unsupported = -9,
    PlatformRejected = -10,
    StaleRequest = -11,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid client configuration: {0}")]
    InvalidConfig(String),
    #[error("operation is not valid in state {state:?}: {operation}")]
    InvalidState {
        state: ClientState,
        operation: &'static str,
    },
    #[error("network plan generation {got} is stale; expected {expected}")]
    StalePlan { expected: u64, got: u64 },
    #[error("platform request {got} is stale or already acknowledged")]
    StaleRequest { got: u64 },
    #[error("event queue is full; poll pending events before retrying")]
    EventQueueFull,
    #[error("platform is missing required capabilities 0x{missing:x}")]
    MissingCapability { missing: u64 },
    #[error("operation is unsupported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("platform operation failed: {0}")]
    Platform(String),
}

impl CoreError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::InvalidConfig(_) => ErrorCode::InvalidConfig,
            Self::InvalidState { .. } => ErrorCode::InvalidState,
            Self::StalePlan { .. } => ErrorCode::StalePlan,
            Self::StaleRequest { .. } => ErrorCode::StaleRequest,
            Self::EventQueueFull => ErrorCode::EventQueueFull,
            Self::MissingCapability { .. } => ErrorCode::Unsupported,
            Self::Unsupported(_) => ErrorCode::Unsupported,
            Self::Platform(_) => ErrorCode::PlatformRejected,
        }
    }
}

#[cfg(unix)]
struct AttachedTun {
    generation: u64,
    // Kept opaque until the platform packet pump is connected. Ownership is already real:
    // replacing the attachment, stopping or freeing the core closes this descriptor.
    _fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
struct AttachedWintun {
    generation: u64,
    // The platform retains its creator handle for interface lifetime and route cleanup.
    // Rust opens a separate adapter handle and owns the session/rings after the plan ACK.
    adapter_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRoute {
    pub cidr: String,
    pub gateway: String,
    pub metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDns {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFamilyMode {
    Ipv4,
    Dual,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAddress {
    pub family: NetworkAddressFamily,
    pub address: String,
    /// Prefix applied to the assigned address. L3 IPv6 TUN plans normally use `/128`.
    pub prefix_len: u8,
    /// Pool/on-link prefix, kept distinct from the assigned host prefix.
    pub on_link_prefix_len: u8,
    /// Point-to-point routes may deliberately omit a next hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// Effective post-authentication data-plane facts exposed to platform status UIs.
///
/// They are descriptive only: Rust already owns and applies these settings. Keeping them in
/// the authenticated NetworkPlan prevents platform adapters from parsing AuthOK or inferring
/// negotiated values from their local profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct NetworkDataPlaneFacts {
    pub padding_enabled: bool,
    pub padding_min: u16,
    pub padding_max: u16,
    /// Largest authenticated traffic-normalization target, zero when disabled/empty.
    pub normalization_max: u16,
    pub heartbeat_enabled: bool,
    pub heartbeat_interval_ms: u64,
    pub shaping_enabled: bool,
}

impl NetworkDataPlaneFacts {
    pub(crate) fn from_obfuscation(
        config: &crate::config::client::ClientObfuscationConfig,
    ) -> Self {
        Self {
            padding_enabled: config.padding.enabled,
            padding_min: config.padding.min_bytes,
            padding_max: config.padding.max_bytes,
            normalization_max: if config.traffic_normalization.enabled {
                config
                    .traffic_normalization
                    .round_sizes
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(0)
            } else {
                0
            },
            heartbeat_enabled: config.heartbeat.enabled,
            heartbeat_interval_ms: config.heartbeat.interval_ms,
            shaping_enabled: config.traffic_shaping.enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPlan {
    pub generation: u64,
    pub family_mode: NetworkFamilyMode,
    pub addresses: Vec<NetworkAddress>,
    /// ABI 1.10 IPv4 projection. In IPv6-only mode this mirrors the sole IPv6 address, but
    /// such a plan is emitted only to an adapter that advertised the IPv6 capability set.
    pub tunnel_address: String,
    pub prefix_len: u8,
    pub mtu: u16,
    pub tunnel_gateway: String,
    /// Actual outer peer selected by DNS/connect. Desktop adapters pin this literal before
    /// installing full-tunnel routes, avoiding a second round-robin DNS lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier_address: Option<String>,
    pub routes: Vec<NetworkRoute>,
    /// Validated server-pushed route CIDRs, before client include/local/custom routes are added.
    pub pushed_routes: Vec<String>,
    pub dns_servers: Vec<NetworkDns>,
    pub full_tunnel: bool,
    pub kill_switch: bool,
    /// In a full tunnel whose negotiated plan has no IPv4 address, permit native IPv4
    /// egress instead of failing closed. Platform adapters must apply this symmetrically
    /// with `allow_ipv6_leak`; keeping the decision in the authenticated plan prevents
    /// mobile/desktop adapters from re-parsing transport configuration differently.
    pub allow_ipv4_leak: bool,
    /// In a full tunnel whose negotiated plan has no IPv6 address, permit native IPv6
    /// egress instead of capturing/blocking that family.
    pub allow_ipv6_leak: bool,
    pub max_streams: u32,
    pub adaptive: bool,
    /// Effective negotiated data-plane values, for platform UI only.
    pub data_plane: NetworkDataPlaneFacts,
    /// Sanitized connection diagnostics produced by the shared owner. Platform adapters
    /// display these verbatim so server-push decisions cannot drift between clients again.
    /// Passwords, keys and the bonded-stream session token are deliberately never included.
    pub connection_log: Vec<String>,
}

/// Authenticated network values supplied by a platform adapter after its legacy handshake.
///
/// This is a temporary migration seam: Rust re-parses the complete `OK:` response and owns
/// plan construction, while the adapter may explicitly preserve a platform DNS fallback.
/// Once the shared handshake is the sole live path, it produces the same values internally.
#[derive(Debug, Deserialize)]
struct HandshakeNetworkInput {
    auth_ok: String,
    effective_mtu: u16,
    #[serde(default)]
    fallback_dns_servers: Vec<String>,
}

impl NetworkPlan {
    pub fn required_capabilities(&self) -> u64 {
        let mut required = 0;
        if self.full_tunnel || !self.routes.is_empty() {
            required |= platform_capability::ROUTES;
        }
        if !self.dns_servers.is_empty() {
            required |= platform_capability::DNS;
        }
        if self.kill_switch {
            required |= platform_capability::KILL_SWITCH;
        }
        let has_ipv6_address = self
            .addresses
            .iter()
            .any(|address| address.family == NetworkAddressFamily::Ipv6);
        let has_ipv6_route = self.routes.iter().any(|route| {
            route
                .cidr
                .split_once('/')
                .and_then(|(address, _)| address.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_ipv6())
        });
        let has_ipv6_dns = self.dns_servers.iter().any(|dns| {
            dns.address
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_ipv6())
        });
        // IPv4-only full tunnel is not an IPv6-free plan: unless the explicit leak
        // escape hatch is enabled, every adapter must still capture/blackhole native
        // IPv6. Requiring IPv6 operations only when an IPv6 tunnel address existed let
        // an adapter advertise IPv4-only routing, accept the plan, and then have no
        // declared ability to enforce its fail-closed IPv6 half.
        let controls_ipv6_family = has_ipv6_address || (self.full_tunnel && !self.allow_ipv6_leak);
        if has_ipv6_address {
            required |= platform_capability::IPV6_TUN;
        }
        if has_ipv6_route || (self.full_tunnel && controls_ipv6_family) {
            required |= platform_capability::IPV6_ROUTES;
        }
        if has_ipv6_dns {
            required |= platform_capability::IPV6_DNS;
        }
        if self.kill_switch && controls_ipv6_family {
            required |= platform_capability::IPV6_KILL_SWITCH;
        }
        required
    }

    fn validate(&self) -> Result<(), CoreError> {
        if self.generation == 0 {
            return Err(CoreError::InvalidArgument(
                "network plan generation must be non-zero".into(),
            ));
        }
        if self.addresses.is_empty() || self.addresses.len() > 2 {
            return Err(CoreError::InvalidArgument(
                "network plan must contain one address per active IP family".into(),
            ));
        }
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for assigned in &self.addresses {
            if assigned.address.len() > MAX_PLAN_STRING_BYTES {
                return Err(CoreError::InvalidArgument(
                    "network plan address is too long".into(),
                ));
            }
            let parsed: IpAddr = assigned.address.parse().map_err(|_| {
                CoreError::InvalidArgument(format!(
                    "invalid network plan address '{}'",
                    assigned.address
                ))
            })?;
            let (expected_family, max_prefix) = if parsed.is_ipv4() {
                if has_ipv4 {
                    return Err(CoreError::InvalidArgument(
                        "network plan contains duplicate IPv4 addresses".into(),
                    ));
                }
                has_ipv4 = true;
                (NetworkAddressFamily::Ipv4, 32)
            } else {
                if has_ipv6 {
                    return Err(CoreError::InvalidArgument(
                        "network plan contains duplicate IPv6 addresses".into(),
                    ));
                }
                has_ipv6 = true;
                (NetworkAddressFamily::Ipv6, 128)
            };
            if let IpAddr::V6(address) = parsed {
                crate::config::server::validate_tunnel_ipv6_address(
                    "network plan address",
                    address,
                )
                .map_err(CoreError::InvalidArgument)?;
            }
            if assigned.family != expected_family
                || assigned.prefix_len == 0
                || assigned.prefix_len > max_prefix
                || assigned.on_link_prefix_len == 0
                || assigned.on_link_prefix_len > max_prefix
                || assigned.on_link_prefix_len > assigned.prefix_len
            {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid {:?} address metadata for '{}'",
                    assigned.family, assigned.address
                )));
            }
            if let Some(gateway) = &assigned.gateway {
                let gateway: IpAddr = gateway.parse().map_err(|_| {
                    CoreError::InvalidArgument(format!("invalid tunnel gateway '{gateway}'"))
                })?;
                if gateway.is_ipv4() != parsed.is_ipv4() {
                    return Err(CoreError::InvalidArgument(format!(
                        "address '{}' and gateway '{}' use different families",
                        assigned.address, gateway
                    )));
                }
                if let IpAddr::V6(gateway) = gateway {
                    crate::config::server::validate_tunnel_ipv6_address(
                        "network plan tunnel gateway",
                        gateway,
                    )
                    .map_err(CoreError::InvalidArgument)?;
                }
            }
        }
        let expected_mode = match (has_ipv4, has_ipv6) {
            (true, false) => NetworkFamilyMode::Ipv4,
            (true, true) => NetworkFamilyMode::Dual,
            (false, true) => NetworkFamilyMode::Ipv6,
            (false, false) => unreachable!("empty address list rejected above"),
        };
        if self.family_mode != expected_mode {
            return Err(CoreError::InvalidArgument(format!(
                "network plan family mode {:?} does not match its addresses",
                self.family_mode
            )));
        }
        if self.tunnel_address.len() > MAX_PLAN_STRING_BYTES {
            return Err(CoreError::InvalidArgument(
                "tunnel address is too long".into(),
            ));
        }
        let address: IpAddr = self.tunnel_address.parse().map_err(|_| {
            CoreError::InvalidArgument(format!("invalid tunnel address '{}'", self.tunnel_address))
        })?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len == 0 || self.prefix_len > max_prefix {
            return Err(CoreError::InvalidArgument(format!(
                "prefix {} is invalid for {}",
                self.prefix_len, self.tunnel_address
            )));
        }
        if !crate::config::server::mtu_in_range(i64::from(self.mtu)) {
            return Err(CoreError::InvalidArgument(format!(
                "mtu {} is outside {}..={}",
                self.mtu,
                crate::config::server::MTU_MIN,
                crate::config::server::MTU_MAX
            )));
        }
        if has_ipv6 && self.mtu < 1280 {
            return Err(CoreError::InvalidArgument(format!(
                "IPv6 network plan MTU {} is below the IPv6 minimum 1280",
                self.mtu
            )));
        }
        if self.tunnel_gateway.len() > MAX_PLAN_STRING_BYTES
            || self.tunnel_gateway.parse::<IpAddr>().is_err()
        {
            return Err(CoreError::InvalidArgument(format!(
                "invalid tunnel gateway '{}'",
                self.tunnel_gateway
            )));
        }
        let projection_matches = self.addresses.iter().any(|assigned| {
            assigned.address == self.tunnel_address
                && assigned.on_link_prefix_len == self.prefix_len
                && assigned.gateway.as_deref() == Some(self.tunnel_gateway.as_str())
        });
        if !projection_matches {
            return Err(CoreError::InvalidArgument(
                "legacy network-plan projection disagrees with typed addresses".into(),
            ));
        }
        if let Some(carrier) = &self.carrier_address {
            if carrier.len() > MAX_PLAN_STRING_BYTES || carrier.parse::<IpAddr>().is_err() {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid carrier address '{carrier}'"
                )));
            }
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(CoreError::InvalidArgument(format!(
                "network plan contains {} routes; maximum is {MAX_ROUTES}",
                self.routes.len()
            )));
        }
        if self.pushed_routes.len() > MAX_ROUTES
            || self
                .pushed_routes
                .iter()
                .any(|route| validate_cidr(route).is_err())
        {
            return Err(CoreError::InvalidArgument(
                "network plan contains invalid pushed routes".into(),
            ));
        }
        for route in &self.routes {
            validate_cidr(&route.cidr)?;
            if route.gateway.len() > MAX_PLAN_STRING_BYTES
                || route.gateway.parse::<IpAddr>().is_err()
            {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid gateway '{}' for route '{}'",
                    route.gateway, route.cidr
                )));
            }
            let route_family = route
                .cidr
                .split_once('/')
                .and_then(|(address, _)| address.parse::<IpAddr>().ok())
                .expect("CIDR validated above");
            let gateway_family = route
                .gateway
                .parse::<IpAddr>()
                .expect("gateway validated above");
            if route_family.is_ipv4() != gateway_family.is_ipv4() {
                return Err(CoreError::InvalidArgument(format!(
                    "route '{}' and gateway '{}' use different families",
                    route.cidr, route.gateway
                )));
            }
            if let IpAddr::V6(gateway) = gateway_family {
                crate::config::server::validate_tunnel_ipv6_address(
                    "network plan route gateway",
                    gateway,
                )
                .map_err(CoreError::InvalidArgument)?;
            }
            if (route_family.is_ipv4() && !has_ipv4) || (route_family.is_ipv6() && !has_ipv6) {
                return Err(CoreError::InvalidArgument(format!(
                    "route '{}' uses a family absent from the tunnel",
                    route.cidr
                )));
            }
        }
        if self.dns_servers.len() > MAX_DNS_SERVERS {
            return Err(CoreError::InvalidArgument(format!(
                "network plan contains {} DNS servers; maximum is {MAX_DNS_SERVERS}",
                self.dns_servers.len()
            )));
        }
        for dns in &self.dns_servers {
            let parsed = dns.address.parse::<IpAddr>();
            if dns.address.len() > MAX_PLAN_STRING_BYTES || parsed.is_err() || dns.port == 0 {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid DNS server '{}:{}'",
                    dns.address, dns.port
                )));
            }
            let parsed = parsed.expect("DNS address validated above");
            if (parsed.is_ipv4() && !has_ipv4) || (parsed.is_ipv6() && !has_ipv6) {
                return Err(CoreError::InvalidArgument(format!(
                    "DNS server '{}' uses a family absent from the tunnel",
                    dns.address
                )));
            }
        }
        if self.connection_log.len() > MAX_CONNECTION_LOG_LINES {
            return Err(CoreError::InvalidArgument(format!(
                "network plan contains {} connection log lines; maximum is {MAX_CONNECTION_LOG_LINES}",
                self.connection_log.len()
            )));
        }
        for line in &self.connection_log {
            if line.len() > MAX_CONNECTION_LOG_LINE_BYTES
                || line.chars().any(|character| character.is_control())
            {
                return Err(CoreError::InvalidArgument(
                    "network plan contains an invalid connection log line".into(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_cidr(route: &str) -> Result<(), CoreError> {
    if route.len() > MAX_PLAN_STRING_BYTES || !crate::util::is_valid_cidr(route) {
        return Err(CoreError::InvalidArgument(format!(
            "invalid route '{route}'"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreFault {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketProtectRequest {
    pub fd: i32,
}

/// A cryptographically proven server key awaiting platform trust policy.
///
/// The handshake emits this only after proving that the peer owns `public_key`. Android may
/// therefore persist a first-use key without letting an unauthenticated packet poison TOFU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerIdentityRequest {
    pub server_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEvent {
    pub sequence: u64,
    pub kind: EventKind,
    pub state: ClientState,
    pub plan: Option<NetworkPlan>,
    pub socket_protect: Option<SocketProtectRequest>,
    pub server_identity: Option<ServerIdentityRequest>,
    pub path_command: Option<PathCommand>,
    pub fault: Option<CoreFault>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreStats {
    pub state: ClientState,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub reconnects: u64,
    pub uptime_ms: u64,
    pub udp_kernel_drops: u64,
    pub udp_internal_drops: u64,
    pub udp_buffer_grows: u64,
    pub udp_recv_buffer_bytes: u64,
    pub roam_attempts: u64,
    pub roam_successes: u64,
    pub roam_failures: u64,
    pub roam_reconnect_fallbacks: u64,
    pub roam_candidates: u64,
    pub last_roam_latency_ms: u64,
}

/// Lock-free counters shared with a running native packet pump.
///
/// The ABI stats path reads these without taking a lock on every packet. A fresh generation
/// receives a fresh owner, so a cancelled predecessor cannot write into its successor's totals.
#[derive(Default)]
pub(crate) struct RuntimeCounters {
    pub tx_packets: portable_atomic::AtomicU64,
    pub tx_bytes: portable_atomic::AtomicU64,
    pub rx_packets: portable_atomic::AtomicU64,
    pub rx_bytes: portable_atomic::AtomicU64,
    pub udp: Arc<udp_buffer::UdpBufferCounters>,
}

#[derive(Debug, Clone, Copy)]
pub struct CoreOptions {
    pub platform_capabilities: u64,
    pub event_capacity: usize,
}

impl Default for CoreOptions {
    fn default() -> Self {
        Self {
            platform_capabilities: platform_capability::SYSTEM_PLAN,
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

/// State owned by one future transport/data-plane instance.
///
/// Deliberately does not implement `Debug`: it owns the parsed client config, including
/// credentials, and accidental diagnostics must not print it.
pub struct ClientCore {
    config: ClientConfig,
    device_id: Option<[u8; crate::protocol::DEVICE_ID_LEN]>,
    platform_capabilities: u64,
    state: ClientState,
    events: VecDeque<ClientEvent>,
    event_capacity: usize,
    next_sequence: u64,
    pending_plan: Option<u64>,
    pending_socket_protect: BTreeMap<u64, tokio::sync::oneshot::Sender<Result<(), String>>>,
    pending_server_identity: BTreeMap<u64, tokio::sync::oneshot::Sender<Result<(), String>>>,
    pending_path_command: BTreeMap<u64, tokio::sync::oneshot::Sender<Result<(), String>>>,
    last_plan_generation: u64,
    path_candidate: Option<PathCandidate>,
    queued_path_candidate: Option<QueuedPathCandidate>,
    next_path_candidate_id: u64,
    last_path_update_generation: u64,
    last_path_update_id: u64,
    last_path_candidate_id: u64,
    roam_attempts: u64,
    roam_successes: u64,
    roam_failures: u64,
    roam_reconnect_fallbacks: u64,
    last_roam_latency_ms: u64,
    /// Largest inbound wire record this session can produce, computed when the plan is built
    /// (see `publish_network_plan`) and used to size the packet bridge's buffers instead of
    /// reserving the protocol maximum per slot. Zero until the first plan; the bridge clamps.
    last_downlink_record_bytes: usize,
    #[cfg(unix)]
    attached_tun: Option<AttachedTun>,
    #[cfg(target_os = "windows")]
    attached_wintun: Option<AttachedWintun>,
    #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
    packet_tun_bridge: Option<packet_tun::PacketTunBridge>,
    #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
    packet_tun_pump: Option<(u64, packet_tun::PacketTunPump)>,
    runtime_cancel: Arc<AtomicBool>,
    runtime_active: bool,
    runtime_counters: Option<Arc<RuntimeCounters>>,
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    udp_kernel_drops: u64,
    udp_internal_drops: u64,
    udp_buffer_grows: u64,
    udp_recv_buffer_bytes: u64,
    reconnects: u64,
    created_at: Instant,
}

impl Drop for ClientCore {
    fn drop(&mut self) {
        self.runtime_cancel.store(true, Ordering::Release);
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        if let Some(bridge) = &self.packet_tun_bridge {
            bridge.stop();
        }
        self.config.auth.password.zeroize();
        self.config.auth.password_command.zeroize();
        self.config.obfuscation.obfs_key.zeroize();
        self.device_id.zeroize();
    }
}

impl ClientCore {
    pub fn new(config_text: &str, options: CoreOptions) -> Result<Self, CoreError> {
        if config_text.len() > MAX_CONFIG_BYTES {
            return Err(CoreError::InvalidConfig(format!(
                "configuration is {} bytes; maximum is {MAX_CONFIG_BYTES}",
                config_text.len()
            )));
        }
        if options.event_capacity < MIN_EVENT_CAPACITY
            || options.event_capacity > MAX_EVENT_CAPACITY
        {
            return Err(CoreError::InvalidArgument(format!(
                "event capacity must be {MIN_EVENT_CAPACITY}..={MAX_EVENT_CAPACITY}"
            )));
        }
        let config = parse_config(config_text)?;
        let mut core = Self {
            config,
            device_id: None,
            platform_capabilities: options.platform_capabilities,
            state: ClientState::Created,
            events: VecDeque::with_capacity(options.event_capacity),
            event_capacity: options.event_capacity,
            next_sequence: 1,
            pending_plan: None,
            pending_socket_protect: BTreeMap::new(),
            pending_server_identity: BTreeMap::new(),
            pending_path_command: BTreeMap::new(),
            last_plan_generation: 0,
            path_candidate: None,
            queued_path_candidate: None,
            next_path_candidate_id: 1,
            last_path_update_generation: 0,
            last_path_update_id: 0,
            last_path_candidate_id: 0,
            roam_attempts: 0,
            roam_successes: 0,
            roam_failures: 0,
            roam_reconnect_fallbacks: 0,
            last_roam_latency_ms: 0,
            last_downlink_record_bytes: 0,
            #[cfg(unix)]
            attached_tun: None,
            #[cfg(target_os = "windows")]
            attached_wintun: None,
            #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
            packet_tun_bridge: None,
            #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
            packet_tun_pump: None,
            runtime_cancel: Arc::new(AtomicBool::new(false)),
            runtime_active: false,
            runtime_counters: None,
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            udp_kernel_drops: 0,
            udp_internal_drops: 0,
            udp_buffer_grows: 0,
            udp_recv_buffer_bytes: 0,
            reconnects: 0,
            created_at: Instant::now(),
        };
        core.push_event(EventKind::StateChanged, None, None, None, None);
        Ok(core)
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn platform_capabilities(&self) -> u64 {
        self.platform_capabilities
    }

    /// Copy the stable platform device identity into the core before connecting.
    ///
    /// The identifier is explicit so Android, Apple and Windows keep their existing
    /// persistence semantics and the shared handshake never invents a second identity.
    pub fn set_device_id(&mut self, device_id: &[u8]) -> Result<(), CoreError> {
        if !matches!(self.state, ClientState::Created | ClientState::Stopped) {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "set_device_id",
            });
        }
        if device_id.len() != crate::protocol::DEVICE_ID_LEN
            || device_id.iter().all(|byte| *byte == 0)
        {
            return Err(CoreError::InvalidArgument(format!(
                "device id must be {} non-zero bytes",
                crate::protocol::DEVICE_ID_LEN
            )));
        }
        let mut owned = [0u8; crate::protocol::DEVICE_ID_LEN];
        owned.copy_from_slice(device_id);
        self.device_id.zeroize();
        self.device_id = Some(owned);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn device_id(&self) -> Option<&[u8; crate::protocol::DEVICE_ID_LEN]> {
        self.device_id.as_ref()
    }

    pub fn start(&mut self) -> Result<(), CoreError> {
        match self.state {
            ClientState::Created | ClientState::Stopped => {}
            state => {
                return Err(CoreError::InvalidState {
                    state,
                    operation: "start",
                })
            }
        }
        self.discard_queued_path_events();
        self.require_event_slots(1)?;

        self.pending_plan = None;
        self.pending_socket_protect.clear();
        self.pending_server_identity.clear();
        self.pending_path_command.clear();
        self.path_candidate = None;
        self.queued_path_candidate = None;
        #[cfg(unix)]
        {
            self.attached_tun = None;
        }
        #[cfg(target_os = "windows")]
        {
            self.attached_wintun = None;
        }
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        {
            if let Some(bridge) = &self.packet_tun_bridge {
                bridge.stop();
            }
            self.packet_tun_bridge = None;
            self.packet_tun_pump = None;
        }
        // Do not reset an in-flight generation's flag in place: a cancelled native call may
        // still be unwinding on another thread. Give this start a distinct token instead.
        self.runtime_cancel = Arc::new(AtomicBool::new(false));
        self.runtime_active = false;
        self.runtime_counters = None;
        self.state = ClientState::Connecting;
        self.push_event(EventKind::StateChanged, None, None, None, None);

        Ok(())
    }

    fn network_plan_record_budget(plan: &NetworkPlan) -> usize {
        usize::from(plan.mtu)
            .max(usize::from(plan.data_plane.normalization_max))
            .saturating_add(usize::from(plan.data_plane.padding_max))
            .saturating_add(crate::protocol::packet::TLS_RECORD_HEADER)
            // Nonce, tag, counter, padding length and headroom for future record fields.
            .saturating_add(128)
            .min(
                crate::protocol::packet::TLS_RECORD_HEADER
                    + crate::protocol::packet::MAX_RECORD_SIZE,
            )
    }

    /// Publish the system configuration learned during the handshake.
    ///
    /// The data plane calls this after authentication. The core remains paused in
    /// `AwaitingNetwork` until [`ack_network_plan`](Self::ack_network_plan) confirms that
    /// the platform installed the plan. No tunnel payload may flow before that ACK.
    pub fn publish_network_plan(&mut self, plan: NetworkPlan) -> Result<(), CoreError> {
        plan.validate()?;
        if !matches!(self.state, ClientState::Connecting | ClientState::Running) {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "publish_network_plan",
            });
        }
        if self.path_candidate.is_some() || self.queued_path_candidate.is_some() {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "publish_network_plan while a path transaction is active",
            });
        }
        if self.pending_plan.is_some() {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "publish a second network plan before acknowledging the first",
            });
        }
        if plan.generation <= self.last_plan_generation {
            return Err(CoreError::StalePlan {
                expected: self.last_plan_generation.saturating_add(1),
                got: plan.generation,
            });
        }
        let missing = plan.required_capabilities() & !self.platform_capabilities;
        if missing != 0 {
            return Err(CoreError::MissingCapability { missing });
        }
        self.require_event_slots(2)?;
        // Every publication path, including direct native/iOS plans, must size the packet
        // bridge from the final authenticated plan rather than a stale zero/default slot.
        self.last_downlink_record_bytes = Self::network_plan_record_budget(&plan);
        self.pending_plan = Some(plan.generation);
        self.state = ClientState::AwaitingNetwork;
        self.push_event(EventKind::StateChanged, None, None, None, None);
        self.push_event(EventKind::NetworkPlan, Some(plan), None, None, None);
        Ok(())
    }

    /// Re-parse an authenticated platform handshake and publish its canonical network plan.
    ///
    /// The JSON envelope is additive and bounded. `auth_ok` must be the complete `OK:{...}`
    /// plaintext produced by the authenticated channel; untrusted routes/DNS are therefore
    /// validated by the same Rust code as the native client before crossing the ABI.
    pub fn publish_handshake_network(&mut self, input_json: &str) -> Result<u64, CoreError> {
        if input_json.len() > MAX_HANDSHAKE_NETWORK_BYTES {
            return Err(CoreError::InvalidArgument(format!(
                "handshake network input is {} bytes; maximum is {MAX_HANDSHAKE_NETWORK_BYTES}",
                input_json.len()
            )));
        }
        let input: HandshakeNetworkInput = serde_json::from_str(input_json).map_err(|error| {
            CoreError::InvalidArgument(format!("invalid handshake network input: {error}"))
        })?;
        if !crate::config::server::mtu_in_range(i64::from(input.effective_mtu)) {
            return Err(CoreError::InvalidArgument(format!(
                "effective MTU {} is outside {}..={}",
                input.effective_mtu,
                crate::config::server::MTU_MIN,
                crate::config::server::MTU_MAX
            )));
        }
        if input.fallback_dns_servers.len() > MAX_DNS_SERVERS {
            return Err(CoreError::InvalidArgument(format!(
                "handshake input contains {} fallback DNS servers; maximum is {MAX_DNS_SERVERS}",
                input.fallback_dns_servers.len()
            )));
        }
        for address in &input.fallback_dns_servers {
            if address.len() > MAX_PLAN_STRING_BYTES || address.parse::<IpAddr>().is_err() {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid platform fallback DNS server '{address}'"
                )));
            }
        }

        let auth = session::parse_auth_ok(&input.auth_ok)
            .map_err(|error| CoreError::InvalidArgument(error.to_string()))?;
        let generation =
            self.last_plan_generation
                .checked_add(1)
                .ok_or(CoreError::InvalidState {
                    state: self.state,
                    operation: "publish_handshake_network after generation exhaustion",
                })?;
        let network = network::HandshakeNetwork {
            family_mode: auth.family_mode,
            addresses: &auth.addresses,
            client_ip: &auth.client_ip,
            prefix: auth.prefix,
            tunnel_gateway: &auth.server_ip,
            dns_ip: &auth.dns_ip,
            dns_port: &auth.dns_port,
            dns_servers: &auth.dns_servers,
            routes_json: &auth.routes_json,
            mtu: i32::from(input.effective_mtu),
            fallback_dns_servers: &input.fallback_dns_servers,
        };
        let mut plan = network::build_network_plan(&self.config, generation, &network)
            .map_err(|error| CoreError::InvalidArgument(error.to_string()))?;
        plan.max_streams = auth.max_streams;
        plan.adaptive = auth.adaptive;
        let mut effective_obfuscation = self.config.obfuscation.clone();
        if let Some(pushed) = auth.pushed_obf.as_ref() {
            effective_obfuscation.padding = pushed.padding.clone();
            effective_obfuscation.heartbeat = pushed.heartbeat.clone();
            effective_obfuscation.traffic_normalization = pushed.traffic_normalization.clone();
            effective_obfuscation.traffic_shaping = pushed.traffic_shaping.clone();
        }
        plan.data_plane = NetworkDataPlaneFacts::from_obfuscation(&effective_obfuscation);
        plan.connection_log = network::server_push_log_lines(
            &self.config,
            &plan,
            auth.mtu,
            &auth.dns_ip,
            &auth.dns_port,
            &auth.routes_json,
            auth.pushed_obf.as_ref(),
        );
        self.publish_network_plan(plan)?;
        Ok(generation)
    }

    pub fn ack_network_plan(
        &mut self,
        generation: u64,
        applied: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
        if self.state != ClientState::AwaitingNetwork {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "ack_network_plan outside AwaitingNetwork",
            });
        }
        let expected = self.pending_plan.ok_or(CoreError::InvalidState {
            state: self.state,
            operation: "ack_network_plan with no pending plan",
        })?;
        if generation != expected {
            return Err(CoreError::StalePlan {
                expected,
                got: generation,
            });
        }
        if applied && self.platform_capabilities & platform_capability::TUN_FD != 0 {
            #[cfg(unix)]
            if self.attached_tun.as_ref().map(|tun| tun.generation) != Some(generation) {
                return Err(CoreError::InvalidState {
                    state: self.state,
                    operation: "ack_network_plan before attaching the generation TUN fd",
                });
            }
            #[cfg(not(unix))]
            return Err(CoreError::Unsupported(
                "TUN file-descriptor ownership requires a Unix target",
            ));
        }
        if applied && self.platform_capabilities & platform_capability::TUN_WINTUN != 0 {
            #[cfg(target_os = "windows")]
            if self.attached_wintun.as_ref().map(|tun| tun.generation) != Some(generation) {
                return Err(CoreError::InvalidState {
                    state: self.state,
                    operation: "ack_network_plan before attaching the generation Wintun adapter",
                });
            }
            #[cfg(not(target_os = "windows"))]
            return Err(CoreError::Unsupported(
                "Wintun ownership requires a Windows target",
            ));
        }
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        let packet_tun =
            if applied && self.platform_capabilities & platform_capability::TUN_PACKET_BATCH != 0 {
                Some(
                    packet_tun::PacketTunPump::new(generation, self.last_downlink_record_bytes)
                        .map_err(|error| CoreError::Platform(error.to_string()))?,
                )
            } else {
                None
            };
        self.require_event_slots(if applied { 1 } else { 2 })?;
        self.pending_plan = None;
        self.last_plan_generation = generation;
        if applied {
            #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
            if let Some((bridge, pump)) = packet_tun {
                self.packet_tun_bridge = Some(bridge);
                self.packet_tun_pump = Some((generation, pump));
            }
            self.state = ClientState::Running;
            self.push_event(EventKind::StateChanged, None, None, None, None);
        } else {
            #[cfg(unix)]
            if self
                .attached_tun
                .as_ref()
                .is_some_and(|tun| tun.generation == generation)
            {
                self.attached_tun = None;
            }
            #[cfg(target_os = "windows")]
            if self
                .attached_wintun
                .as_ref()
                .is_some_and(|tun| tun.generation == generation)
            {
                self.attached_wintun = None;
            }
            self.state = ClientState::Failed;
            let message: String = reason
                .unwrap_or("platform rejected the network plan")
                .chars()
                .take(MAX_PLATFORM_ERROR_CHARS)
                .collect();
            self.push_event(
                EventKind::Error,
                None,
                None,
                None,
                Some(CoreFault {
                    code: ErrorCode::PlatformRejected,
                    message,
                }),
            );
            self.push_event(EventKind::StateChanged, None, None, None, None);
        }
        Ok(())
    }

    /// Duplicate and adopt the platform TUN descriptor for one pending network-plan
    /// generation. The caller retains ownership of `fd`; the core owns only an atomic
    /// close-on-exec duplicate and closes it on replacement, stop or free.
    pub fn attach_tun_fd(&mut self, generation: u64, fd: i32) -> Result<(), CoreError> {
        if self.platform_capabilities & platform_capability::TUN_FD == 0 {
            return Err(CoreError::MissingCapability {
                missing: platform_capability::TUN_FD,
            });
        }
        let expected = self.pending_plan.ok_or(CoreError::InvalidState {
            state: self.state,
            operation: "attach_tun_fd with no pending network plan",
        })?;
        if generation != expected {
            return Err(CoreError::StalePlan {
                expected,
                got: generation,
            });
        }
        if self.state != ClientState::AwaitingNetwork {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "attach_tun_fd",
            });
        }
        if fd < 0 {
            return Err(CoreError::InvalidArgument(
                "TUN file descriptor must be non-negative".into(),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::fd::BorrowedFd;

            // SAFETY: the FFI contract requires `fd` to remain open for this call only.
            // `try_clone_to_owned` performs an atomic CLOEXEC duplication, so the stored
            // descriptor is independent before control returns to the platform.
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            let owned = borrowed.try_clone_to_owned().map_err(|error| {
                CoreError::InvalidArgument(format!("could not duplicate TUN fd: {error}"))
            })?;
            self.attached_tun = Some(AttachedTun {
                generation,
                _fd: owned,
            });
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = generation;
            Err(CoreError::Unsupported(
                "TUN file-descriptor ownership requires a Unix target",
            ))
        }
    }

    /// Attach the platform-created Wintun adapter name for one pending plan generation.
    ///
    /// The platform retains only its creator handle and network setup responsibilities.
    /// After a positive ACK the Windows backend opens an independent adapter handle and owns
    /// the session, read event and both rings until the generation stops.
    pub fn attach_wintun_adapter(
        &mut self,
        generation: u64,
        adapter_name: &str,
    ) -> Result<(), CoreError> {
        if self.platform_capabilities & platform_capability::TUN_WINTUN == 0 {
            return Err(CoreError::MissingCapability {
                missing: platform_capability::TUN_WINTUN,
            });
        }
        let expected = self.pending_plan.ok_or(CoreError::InvalidState {
            state: self.state,
            operation: "attach_wintun_adapter with no pending network plan",
        })?;
        if generation != expected {
            return Err(CoreError::StalePlan {
                expected,
                got: generation,
            });
        }
        if self.state != ClientState::AwaitingNetwork {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "attach_wintun_adapter",
            });
        }
        let adapter_name = adapter_name.trim();
        if adapter_name.is_empty()
            || adapter_name.len() > MAX_PLAN_STRING_BYTES
            || adapter_name.contains('\0')
        {
            return Err(CoreError::InvalidArgument(
                "Wintun adapter name must be 1..=128 UTF-8 bytes without NUL".into(),
            ));
        }

        #[cfg(target_os = "windows")]
        {
            self.attached_wintun = Some(AttachedWintun {
                generation,
                adapter_name: adapter_name.to_owned(),
            });
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = adapter_name;
            Err(CoreError::Unsupported(
                "Wintun ownership requires a Windows target",
            ))
        }
    }

    /// Move the acknowledged generation's TUN descriptor into packet workers.
    ///
    /// A second owned descriptor is created so blocking read and write can be stopped and
    /// joined independently. Neither descriptor escapes to platform code, and the transfer
    /// is one-shot for the generation.
    #[cfg(unix)]
    #[allow(dead_code)]
    pub(crate) fn take_attached_tun_fds(
        &mut self,
        generation: u64,
    ) -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), CoreError> {
        if self.state != ClientState::Running {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "take_attached_tun_fds before positive network-plan ACK",
            });
        }
        let attached = self.attached_tun.as_ref().ok_or(CoreError::InvalidState {
            state: self.state,
            operation: "take_attached_tun_fds with no attached descriptor",
        })?;
        if attached.generation != generation {
            return Err(CoreError::StalePlan {
                expected: attached.generation,
                got: generation,
            });
        }
        let reader = attached._fd.try_clone().map_err(|error| {
            CoreError::Platform(format!("could not duplicate TUN reader fd: {error}"))
        })?;
        let writer = self
            .attached_tun
            .take()
            .ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "take_attached_tun_fds lost the validated descriptor",
            })?
            ._fd;
        Ok((reader, writer))
    }

    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    pub(crate) fn take_attached_wintun(&mut self, generation: u64) -> Result<String, CoreError> {
        if self.state != ClientState::Running {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "take_attached_wintun before positive network-plan ACK",
            });
        }
        let attached = self
            .attached_wintun
            .as_ref()
            .ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "take_attached_wintun with no attached adapter",
            })?;
        if attached.generation != generation {
            return Err(CoreError::StalePlan {
                expected: attached.generation,
                got: generation,
            });
        }
        Ok(self
            .attached_wintun
            .take()
            .expect("validated Wintun attachment is present")
            .adapter_name)
    }

    #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
    #[allow(dead_code)]
    pub(crate) fn take_packet_tun_pump(
        &mut self,
        generation: u64,
    ) -> Result<packet_tun::PacketTunPump, CoreError> {
        if self.state != ClientState::Running {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "take_packet_tun_pump before positive network-plan ACK",
            });
        }
        let (expected, _) = self
            .packet_tun_pump
            .as_ref()
            .ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "take_packet_tun_pump with no packet bridge",
            })?;
        if *expected != generation {
            return Err(CoreError::StalePlan {
                expected: *expected,
                got: generation,
            });
        }
        Ok(self
            .packet_tun_pump
            .take()
            .expect("validated packet pump is present")
            .1)
    }

    #[cfg(feature = "transport-core-ffi")]
    pub(crate) fn packet_tun_bridge(
        &self,
        generation: u64,
    ) -> Result<packet_tun::PacketTunBridge, CoreError> {
        let bridge = self
            .packet_tun_bridge
            .as_ref()
            .ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "packet IO before positive network-plan ACK",
            })?;
        if bridge.generation() != generation {
            return Err(CoreError::StalePlan {
                expected: bridge.generation(),
                got: generation,
            });
        }
        Ok(bridge.clone())
    }

    /// Ask the platform to exclude one core-owned carrier socket from its VPN routing.
    ///
    /// The caller retains ownership of `fd` and must keep it open until the returned receiver
    /// resolves or is cancelled by stop/free. The event sequence is the one-shot request ID;
    /// a platform must acknowledge exactly that value after its synchronous `protect(fd)` call.
    // The native socket-opening handshake will consume this seam in the next migration slice.
    // Until then only contract tests exercise the producer side; Android already binds the ACK.
    #[allow(dead_code)]
    pub(crate) fn request_socket_protect(
        &mut self,
        fd: i32,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<Result<(), String>>), CoreError> {
        if self.platform_capabilities & platform_capability::SOCKET_PROTECT == 0 {
            return Err(CoreError::MissingCapability {
                missing: platform_capability::SOCKET_PROTECT,
            });
        }
        if !matches!(self.state, ClientState::Connecting | ClientState::Running) {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "request_socket_protect",
            });
        }
        if fd < 0 {
            return Err(CoreError::InvalidArgument(
                "socket file descriptor must be non-negative".into(),
            ));
        }
        self.require_event_slots(1)?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sequence = self.push_event(
            EventKind::SocketProtect,
            None,
            Some(SocketProtectRequest { fd }),
            None,
            None,
        );
        let replaced = self.pending_socket_protect.insert(sequence, sender);
        debug_assert!(replaced.is_none());
        Ok((sequence, receiver))
    }

    pub fn ack_socket_protect(
        &mut self,
        request_sequence: u64,
        protected: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
        let sender = self
            .pending_socket_protect
            .remove(&request_sequence)
            .ok_or(CoreError::StaleRequest {
                got: request_sequence,
            })?;
        let result = if protected {
            Ok(())
        } else {
            Err(reason
                .unwrap_or("platform rejected socket protection")
                .chars()
                .take(MAX_PLATFORM_ERROR_CHARS)
                .collect())
        };
        sender.send(result).map_err(|_| CoreError::StaleRequest {
            got: request_sequence,
        })?;
        Ok(())
    }

    /// Ask the platform trust store to accept a server identity that already passed the
    /// cryptographic proof in `session::verify_server_identity`.
    ///
    /// The event sequence is a one-shot request ID. A platform may compare an existing pin
    /// or persist this proven key on first use, then must acknowledge the exact sequence.
    #[allow(dead_code)]
    pub(crate) fn request_server_identity(
        &mut self,
        public_key: [u8; 32],
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<Result<(), String>>), CoreError> {
        if self.platform_capabilities & platform_capability::SERVER_IDENTITY == 0 {
            return Err(CoreError::MissingCapability {
                missing: platform_capability::SERVER_IDENTITY,
            });
        }
        if !matches!(self.state, ClientState::Connecting | ClientState::Running) {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "request_server_identity",
            });
        }
        self.require_event_slots(1)?;
        let request = ServerIdentityRequest {
            server_id: format!("{}:{}", self.config.server.address, self.config.server.port),
            public_key: public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sequence = self.push_event(EventKind::ServerIdentity, None, None, Some(request), None);
        let replaced = self.pending_server_identity.insert(sequence, sender);
        debug_assert!(replaced.is_none());
        Ok((sequence, receiver))
    }

    pub fn ack_server_identity(
        &mut self,
        request_sequence: u64,
        trusted: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
        if !trusted {
            self.require_event_slots(2)?;
        }
        let sender = self
            .pending_server_identity
            .remove(&request_sequence)
            .ok_or(CoreError::StaleRequest {
                got: request_sequence,
            })?;
        let result = if trusted {
            Ok(())
        } else {
            Err(reason
                .unwrap_or("platform rejected the server identity")
                .chars()
                .take(MAX_PLATFORM_ERROR_CHARS)
                .collect())
        };
        sender
            .send(result.clone())
            .map_err(|_| CoreError::StaleRequest {
                got: request_sequence,
            })?;
        if let Err(message) = result {
            self.state = ClientState::Failed;
            self.push_event(
                EventKind::Error,
                None,
                None,
                None,
                Some(CoreFault {
                    code: ErrorCode::PlatformRejected,
                    message,
                }),
            );
            self.push_event(EventKind::StateChanged, None, None, None, None);
        }
        Ok(())
    }

    fn ensure_path_transactions_enabled(&self) -> Result<(), CoreError> {
        if !cfg!(feature = "experimental-roaming") {
            return Err(CoreError::Unsupported(
                "path transactions require the experimental-roaming build feature",
            ));
        }
        let missing = platform_capability::ROAMING_PATH & !self.platform_capabilities;
        if missing != 0 {
            return Err(CoreError::MissingCapability { missing });
        }
        Ok(())
    }

    fn validate_active_path_generation(&self, generation: u64) -> Result<(), CoreError> {
        if self.state != ClientState::Running {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "path transaction outside Running",
            });
        }
        if generation != self.last_plan_generation {
            return Err(CoreError::StalePlan {
                expected: self.last_plan_generation,
                got: generation,
            });
        }
        Ok(())
    }

    fn allocate_path_candidate_id(&mut self) -> Result<u64, CoreError> {
        let candidate_id = self.next_path_candidate_id;
        if candidate_id > i64::MAX as u64 {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "allocate path candidate after signed ABI id exhaustion",
            });
        }
        self.next_path_candidate_id =
            candidate_id.checked_add(1).ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "allocate path candidate after id exhaustion",
            })?;
        Ok(candidate_id)
    }

    fn push_path_event(&mut self, command: PathCommand) -> u64 {
        debug_assert!(self.events.len() < self.event_capacity);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push_back(ClientEvent {
            sequence,
            kind: EventKind::PathCommand,
            state: self.state,
            plan: None,
            socket_protect: None,
            server_identity: None,
            path_command: Some(command),
            fault: None,
        });
        sequence
    }

    fn start_path_candidate(&mut self, queued: QueuedPathCandidate) {
        let mut candidate = PathCandidate {
            candidate_id: queued.candidate_id,
            update: queued.update,
            phase: PathCandidatePhase::Preparing,
            pending_sequence: None,
            started_at: Instant::now(),
            failure_recorded: false,
        };
        let command = candidate.command(PathCommandAction::PreparePath, None, None);
        let sequence = self.push_path_event(command);
        candidate.pending_sequence = Some(sequence);
        self.roam_attempts = self.roam_attempts.saturating_add(1);
        self.path_candidate = Some(candidate);
    }

    fn record_path_failure(&mut self) {
        let should_record = self
            .path_candidate
            .as_ref()
            .is_some_and(|candidate| !candidate.failure_recorded);
        if should_record {
            self.roam_failures = self.roam_failures.saturating_add(1);
            if let Some(candidate) = self.path_candidate.as_mut() {
                candidate.failure_recorded = true;
            }
        }
    }

    fn begin_path_abort(&mut self, reason: String) {
        if let Some(sequence) = self
            .path_candidate
            .as_ref()
            .and_then(|candidate| candidate.pending_sequence)
        {
            self.pending_path_command.remove(&sequence);
        }
        self.record_path_failure();
        let command = self
            .path_candidate
            .as_ref()
            .expect("active candidate is present")
            .command(PathCommandAction::AbortPath, None, Some(reason));
        let sequence = self.push_path_event(command);
        let candidate = self
            .path_candidate
            .as_mut()
            .expect("active candidate is present");
        candidate.phase = PathCandidatePhase::Aborting;
        candidate.pending_sequence = Some(sequence);
    }

    fn remove_queued_path_event(&mut self, sequence: u64) -> bool {
        let Some(position) = self
            .events
            .iter()
            .position(|event| event.kind == EventKind::PathCommand && event.sequence == sequence)
        else {
            return false;
        };
        self.events.remove(position);
        self.pending_path_command.remove(&sequence);
        true
    }

    fn discard_queued_path_events(&mut self) {
        self.events
            .retain(|event| event.kind != EventKind::PathCommand);
        self.pending_path_command.clear();
    }

    /// Return the only candidate which has crossed PREPARE_PATH successfully and is not
    /// already owned by a socket transaction. Polling is idempotent until BIND_SOCKET starts.
    #[allow(dead_code)]
    pub(crate) fn prepared_path_candidate(&self) -> Option<PreparedPathCandidate> {
        self.path_candidate.as_ref().and_then(|candidate| {
            (candidate.phase == PathCandidatePhase::Prepared
                && candidate.pending_sequence.is_none())
            .then(|| PreparedPathCandidate {
                candidate_id: candidate.candidate_id,
                update: candidate.update.clone(),
            })
        })
    }

    /// Accept one bounded, generation-scoped path observation from a platform adapter.
    ///
    /// Repeating the same `update_id` is idempotent. A newer observation cancels an older
    /// candidate; if PREPARE already crossed the ABI, explicit ABORT is required before the
    /// queued replacement can begin. The active transport and NetworkPlan are never changed.
    pub fn submit_path_update(&mut self, input_json: &str) -> Result<u64, CoreError> {
        self.ensure_path_transactions_enabled()?;
        let update = PathUpdate::parse(input_json)?;
        self.validate_active_path_generation(update.generation)?;

        if self.last_path_update_generation == update.generation {
            if update.update_id < self.last_path_update_id {
                return Err(CoreError::StaleRequest {
                    got: update.update_id,
                });
            }
            if update.update_id == self.last_path_update_id {
                return Ok(self.last_path_candidate_id);
            }
        }

        let candidate_id = self.allocate_path_candidate_id()?;
        let pending_event_is_queued = self
            .path_candidate
            .as_ref()
            .and_then(|candidate| candidate.pending_sequence)
            .is_some_and(|sequence| {
                self.events
                    .iter()
                    .any(|event| event.kind == EventKind::PathCommand && event.sequence == sequence)
            });
        let active_phase = self
            .path_candidate
            .as_ref()
            .map(|candidate| candidate.phase);
        let required_events = match active_phase {
            None => 1,
            Some(PathCandidatePhase::Aborting) => 0,
            Some(_) if pending_event_is_queued => 0,
            Some(_) => 1,
        };
        self.require_event_slots(required_events)?;

        self.last_path_update_generation = update.generation;
        self.last_path_update_id = update.update_id;
        self.last_path_candidate_id = candidate_id;
        let queued = QueuedPathCandidate {
            candidate_id,
            update,
        };

        match active_phase {
            None => self.start_path_candidate(queued),
            Some(PathCandidatePhase::Aborting) => {
                self.queued_path_candidate = Some(queued);
            }
            Some(_) => {
                let pending_sequence = self
                    .path_candidate
                    .as_ref()
                    .and_then(|candidate| candidate.pending_sequence);
                if pending_sequence.is_some_and(|sequence| self.remove_queued_path_event(sequence))
                {
                    // The platform never observed the pending command, so no temporary rule can
                    // exist and an ABORT round trip would be both noisy and misleading.
                    self.record_path_failure();
                    self.path_candidate = None;
                    self.start_path_candidate(queued);
                } else {
                    self.queued_path_candidate = Some(queued);
                    self.begin_path_abort("superseded by a newer path update".into());
                }
            }
        }
        Ok(candidate_id)
    }

    /// Ask the platform to bind/protect a core-owned candidate socket to the prepared path.
    /// The descriptor remains owned by the transport and is only borrowed for the platform
    /// call represented by the emitted event.
    #[allow(dead_code)]
    pub(crate) fn request_candidate_socket_binding(
        &mut self,
        generation: u64,
        candidate_id: u64,
        fd: i32,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<Result<(), String>>), CoreError> {
        self.ensure_path_transactions_enabled()?;
        self.validate_active_path_generation(generation)?;
        if fd < 0 {
            return Err(CoreError::InvalidArgument(
                "candidate socket descriptor must be non-negative".into(),
            ));
        }
        let candidate = self
            .path_candidate
            .as_ref()
            .ok_or(CoreError::StaleRequest { got: candidate_id })?;
        if candidate.candidate_id != candidate_id || candidate.update.generation != generation {
            return Err(CoreError::StaleRequest { got: candidate_id });
        }
        if candidate.phase != PathCandidatePhase::Prepared || candidate.pending_sequence.is_some() {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "bind candidate socket before PREPARE_PATH acknowledgement",
            });
        }
        self.require_event_slots(1)?;
        let command = candidate.command(PathCommandAction::BindSocket, Some(fd), None);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sequence = self.push_path_event(command);
        let candidate = self
            .path_candidate
            .as_mut()
            .expect("validated candidate is present");
        candidate.phase = PathCandidatePhase::Binding;
        candidate.pending_sequence = Some(sequence);
        let replaced = self.pending_path_command.insert(sequence, sender);
        debug_assert!(replaced.is_none());
        Ok((sequence, receiver))
    }

    /// Publish transport proof for a bound candidate. Stage 1 exposes the COMMIT contract,
    /// but deliberately does not switch a live socket; TCP/UDP proof producers land later.
    #[allow(dead_code)]
    pub(crate) fn candidate_path_validated(
        &mut self,
        generation: u64,
        candidate_id: u64,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<Result<(), String>>), CoreError> {
        self.ensure_path_transactions_enabled()?;
        self.validate_active_path_generation(generation)?;
        let candidate = self
            .path_candidate
            .as_ref()
            .ok_or(CoreError::StaleRequest { got: candidate_id })?;
        if candidate.candidate_id != candidate_id || candidate.update.generation != generation {
            return Err(CoreError::StaleRequest { got: candidate_id });
        }
        if candidate.phase != PathCandidatePhase::Bound || candidate.pending_sequence.is_some() {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "commit candidate path before binding and transport validation",
            });
        }
        self.require_event_slots(1)?;
        let command = candidate.command(PathCommandAction::CommitPath, None, None);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sequence = self.push_path_event(command);
        let candidate = self
            .path_candidate
            .as_mut()
            .expect("validated candidate is present");
        candidate.phase = PathCandidatePhase::Committing;
        candidate.pending_sequence = Some(sequence);
        let replaced = self.pending_path_command.insert(sequence, sender);
        debug_assert!(replaced.is_none());
        Ok((sequence, receiver))
    }

    #[allow(dead_code)]
    pub(crate) fn abort_candidate_path(
        &mut self,
        generation: u64,
        candidate_id: u64,
        reason: &str,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<Result<(), String>>), CoreError> {
        self.ensure_path_transactions_enabled()?;
        self.validate_active_path_generation(generation)?;
        let candidate = self
            .path_candidate
            .as_ref()
            .ok_or(CoreError::StaleRequest { got: candidate_id })?;
        if candidate.candidate_id != candidate_id || candidate.update.generation != generation {
            return Err(CoreError::StaleRequest { got: candidate_id });
        }
        if candidate.phase == PathCandidatePhase::Aborting {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "abort candidate path while rollback is already pending",
            });
        }
        self.require_event_slots(1)?;
        let reason: String = reason.chars().take(MAX_PLATFORM_ERROR_CHARS).collect();
        self.begin_path_abort(if reason.is_empty() {
            "candidate path aborted by transport".into()
        } else {
            reason
        });
        let sequence = self
            .path_candidate
            .as_ref()
            .and_then(|candidate| candidate.pending_sequence)
            .expect("ABORT_PATH event has a sequence");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let replaced = self.pending_path_command.insert(sequence, sender);
        debug_assert!(replaced.is_none());
        Ok((sequence, receiver))
    }

    /// Acknowledge exactly one PREPARE/BIND/COMMIT/ABORT event.
    ///
    /// Rejections before ABORT schedule a mandatory rollback. A rejected rollback records a
    /// reconnect fallback and returns `PlatformRejected`; the queued candidate is discarded.
    pub fn ack_path_command(
        &mut self,
        generation: u64,
        candidate_id: u64,
        request_sequence: u64,
        accepted: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
        self.ensure_path_transactions_enabled()?;
        self.validate_active_path_generation(generation)?;
        let candidate = self
            .path_candidate
            .as_ref()
            .ok_or(CoreError::StaleRequest {
                got: request_sequence,
            })?;
        if candidate.candidate_id != candidate_id
            || candidate.update.generation != generation
            || candidate.pending_sequence != Some(request_sequence)
        {
            return Err(CoreError::StaleRequest {
                got: request_sequence,
            });
        }
        let phase = candidate.phase;
        let starts_queued = matches!(
            phase,
            PathCandidatePhase::Committing | PathCandidatePhase::Aborting
        ) && accepted
            && self.queued_path_candidate.is_some();
        let schedules_abort = !accepted && phase != PathCandidatePhase::Aborting;
        self.require_event_slots(usize::from(starts_queued || schedules_abort))?;

        let pending_result = self.pending_path_command.remove(&request_sequence);

        if accepted {
            match phase {
                PathCandidatePhase::Preparing => {
                    let candidate = self.path_candidate.as_mut().expect("candidate is present");
                    candidate.phase = PathCandidatePhase::Prepared;
                    candidate.pending_sequence = None;
                }
                PathCandidatePhase::Binding => {
                    let candidate = self.path_candidate.as_mut().expect("candidate is present");
                    candidate.phase = PathCandidatePhase::Bound;
                    candidate.pending_sequence = None;
                }
                PathCandidatePhase::Committing => {
                    let candidate = self.path_candidate.take().expect("candidate is present");
                    self.roam_successes = self.roam_successes.saturating_add(1);
                    self.last_roam_latency_ms = candidate
                        .started_at
                        .elapsed()
                        .as_millis()
                        .min(u128::from(u64::MAX))
                        as u64;
                    if let Some(queued) = self.queued_path_candidate.take() {
                        self.start_path_candidate(queued);
                    }
                }
                PathCandidatePhase::Aborting => {
                    self.path_candidate = None;
                    if let Some(queued) = self.queued_path_candidate.take() {
                        self.start_path_candidate(queued);
                    }
                }
                PathCandidatePhase::Prepared | PathCandidatePhase::Bound => {
                    return Err(CoreError::StaleRequest {
                        got: request_sequence,
                    });
                }
            }
            if let Some(sender) = pending_result {
                let _ = sender.send(Ok(()));
            }
            return Ok(());
        }

        let reason: String = reason
            .unwrap_or("platform rejected path command")
            .chars()
            .take(MAX_PLATFORM_ERROR_CHARS)
            .collect();
        if let Some(sender) = pending_result {
            let _ = sender.send(Err(reason.clone()));
        }
        if phase == PathCandidatePhase::Aborting {
            self.record_path_failure();
            self.roam_reconnect_fallbacks = self.roam_reconnect_fallbacks.saturating_add(1);
            self.path_candidate = None;
            self.queued_path_candidate = None;
            return Err(CoreError::Platform(format!(
                "candidate path rollback failed: {reason}"
            )));
        }

        let failed_action = match phase {
            PathCandidatePhase::Preparing => "PREPARE_PATH",
            PathCandidatePhase::Binding => "BIND_SOCKET",
            PathCandidatePhase::Committing => "COMMIT_PATH",
            PathCandidatePhase::Prepared
            | PathCandidatePhase::Bound
            | PathCandidatePhase::Aborting => {
                unreachable!("only pending command phases can be acknowledged")
            }
        };
        self.begin_path_abort(format!("{failed_action} rejected: {reason}"));
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), CoreError> {
        if self.state == ClientState::Stopped {
            return Ok(());
        }
        // Cancellation is not an event and must never be held hostage by a full event queue:
        // a blocking native runner owns socket/TUN descriptors that teardown must release.
        self.runtime_cancel.store(true, Ordering::Release);
        self.discard_queued_path_events();
        self.require_event_slots(2)?;
        self.runtime_active = false;
        self.pending_plan = None;
        self.pending_socket_protect.clear();
        self.pending_server_identity.clear();
        self.pending_path_command.clear();
        if self.path_candidate.is_some() {
            self.record_path_failure();
        }
        self.path_candidate = None;
        self.queued_path_candidate = None;
        #[cfg(unix)]
        {
            self.attached_tun = None;
        }
        #[cfg(target_os = "windows")]
        {
            self.attached_wintun = None;
        }
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        {
            if let Some(bridge) = &self.packet_tun_bridge {
                bridge.stop();
            }
            self.packet_tun_bridge = None;
            self.packet_tun_pump = None;
        }
        self.state = ClientState::Stopping;
        self.push_event(EventKind::StateChanged, None, None, None, None);
        self.state = ClientState::Stopped;
        self.push_event(EventKind::StateChanged, None, None, None, None);
        Ok(())
    }

    /// Remove the oldest PathCommand without disturbing lifecycle or diagnostic events which
    /// the platform adapter still has to observe. Native FFI pollers continue to use `poll_event`.
    #[cfg(any(test, all(feature = "experimental-roaming", target_os = "linux")))]
    #[cfg_attr(not(feature = "experimental-roaming"), allow(dead_code))]
    pub(crate) fn poll_path_event(&mut self) -> Option<ClientEvent> {
        let position = self
            .events
            .iter()
            .position(|event| event.kind == EventKind::PathCommand)?;
        self.events.remove(position)
    }

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    /// Publish the terminal state of a native runtime generation.
    ///
    /// Unlike request-driven transitions, a background runner cannot return
    /// `EventQueueFull` and ask the platform to retry the mutation. Terminal failure therefore
    /// preempts the oldest queued events while staying within the configured bound.
    #[cfg(any(
        test,
        all(
            feature = "transport-core-ffi",
            any(
                target_os = "android",
                target_os = "windows",
                target_os = "macos",
                target_os = "ios"
            )
        )
    ))]
    pub(crate) fn publish_runtime_failure(&mut self, message: String) {
        let required = 2;
        self.discard_queued_path_events();
        while self.events.len().saturating_add(required) > self.event_capacity {
            self.events.pop_front();
        }
        self.pending_plan = None;
        self.pending_socket_protect.clear();
        self.pending_server_identity.clear();
        self.pending_path_command.clear();
        if self.path_candidate.is_some() {
            self.record_path_failure();
        }
        self.path_candidate = None;
        self.queued_path_candidate = None;
        #[cfg(unix)]
        {
            self.attached_tun = None;
        }
        #[cfg(target_os = "windows")]
        {
            self.attached_wintun = None;
        }
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        {
            if let Some(bridge) = &self.packet_tun_bridge {
                bridge.stop();
            }
            self.packet_tun_bridge = None;
            self.packet_tun_pump = None;
        }
        self.state = ClientState::Failed;
        self.push_event(
            EventKind::Error,
            None,
            None,
            None,
            Some(CoreFault {
                code: ErrorCode::PlatformRejected,
                message,
            }),
        );
        self.push_event(EventKind::StateChanged, None, None, None, None);
    }

    pub fn stats(&self) -> CoreStats {
        let runtime = self.runtime_counters.as_ref();
        let udp = runtime.map(|c| c.udp.snapshot());
        CoreStats {
            state: self.state,
            tx_packets: self.tx_packets.saturating_add(
                runtime.map_or(0, |c| c.tx_packets.load(portable_atomic::Ordering::Relaxed)),
            ),
            tx_bytes: self.tx_bytes.saturating_add(
                runtime.map_or(0, |c| c.tx_bytes.load(portable_atomic::Ordering::Relaxed)),
            ),
            rx_packets: self.rx_packets.saturating_add(
                runtime.map_or(0, |c| c.rx_packets.load(portable_atomic::Ordering::Relaxed)),
            ),
            rx_bytes: self.rx_bytes.saturating_add(
                runtime.map_or(0, |c| c.rx_bytes.load(portable_atomic::Ordering::Relaxed)),
            ),
            reconnects: self.reconnects,
            uptime_ms: self
                .created_at
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
            udp_kernel_drops: self
                .udp_kernel_drops
                .saturating_add(udp.map_or(0, |s| s.kernel_drops)),
            udp_internal_drops: self
                .udp_internal_drops
                .saturating_add(udp.map_or(0, |s| s.internal_drops)),
            udp_buffer_grows: self
                .udp_buffer_grows
                .saturating_add(udp.map_or(0, |s| s.grow_events)),
            udp_recv_buffer_bytes: udp.map_or(self.udp_recv_buffer_bytes, |s| s.granted_recv_bytes),
            roam_attempts: self.roam_attempts,
            roam_successes: self.roam_successes,
            roam_failures: self.roam_failures,
            roam_reconnect_fallbacks: self.roam_reconnect_fallbacks,
            roam_candidates: u64::from(self.path_candidate.is_some())
                .saturating_add(u64::from(self.queued_path_candidate.is_some())),
            last_roam_latency_ms: self.last_roam_latency_ms,
        }
    }

    // The Linux transport migration will consume the parsed config through this crate-only
    // accessor. Keep credentials away from the public API while the data plane is still
    // being moved behind this state machine.
    #[allow(dead_code)]
    pub(crate) fn config(&self) -> &ClientConfig {
        &self.config
    }

    #[cfg(feature = "transport-core-ffi")]
    pub(crate) fn peek_event(&self) -> Option<&ClientEvent> {
        self.events.front()
    }

    /// Account for one packet accepted from the platform TUN boundary.
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_packets = self.tx_packets.saturating_add(1);
        self.tx_bytes = self.tx_bytes.saturating_add(bytes as u64);
    }

    /// Account for one packet delivered to the platform TUN boundary.
    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.rx_bytes = self.rx_bytes.saturating_add(bytes as u64);
    }

    /// Account for a transport reconnect attempt.
    pub fn record_reconnect(&mut self) {
        self.reconnects = self.reconnects.saturating_add(1);
    }

    #[cfg(all(test, unix))]
    fn attached_tun_raw_fd(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        self.attached_tun.as_ref().map(|tun| tun._fd.as_raw_fd())
    }

    fn require_event_slots(&self, count: usize) -> Result<(), CoreError> {
        if self.events.len().saturating_add(count) > self.event_capacity {
            Err(CoreError::EventQueueFull)
        } else {
            Ok(())
        }
    }

    fn push_event(
        &mut self,
        kind: EventKind,
        plan: Option<NetworkPlan>,
        socket_protect: Option<SocketProtectRequest>,
        server_identity: Option<ServerIdentityRequest>,
        fault: Option<CoreFault>,
    ) -> u64 {
        debug_assert!(self.events.len() < self.event_capacity);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push_back(ClientEvent {
            sequence,
            kind,
            state: self.state,
            plan,
            socket_protect,
            server_identity,
            path_command: None,
            fault,
        });
        sequence
    }
}

pub(crate) fn parse_config(config_text: &str) -> Result<ClientConfig, CoreError> {
    let text = config_text.trim();
    if text.is_empty() {
        return Err(CoreError::InvalidConfig("configuration is empty".into()));
    }
    let config = if text.starts_with("qeli://") {
        let mut link = ClientLink::from_uri(text)
            .map_err(|error| CoreError::InvalidConfig(error.to_string()))?;
        let config = ClientConfig::from_link(&link);
        // `from_link` currently clones its input. Wipe the short-lived duplicate so the
        // new shared core does not extend the lifetime of credentials merely by accepting
        // the mobile import format. The caller still owns and must clear the source buffer.
        link.pass.zeroize();
        link.obfs_key.zeroize();
        config
    } else {
        parse_client_config_strict(text)
            .map_err(|error| CoreError::InvalidConfig(error.to_string()))?
    };
    config
        .validate()
        .map_err(|error| CoreError::InvalidConfig(error.to_string()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn ini() -> String {
        format!(
            "[qeli]\nserver = 127.0.0.1:443\nproto = tcp\nuser = test\npass = secret\nkey = {KEY}\nmode = fake-tls\n"
        )
    }

    fn plan(generation: u64) -> NetworkPlan {
        NetworkPlan {
            generation,
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: vec![NetworkAddress {
                family: NetworkAddressFamily::Ipv4,
                address: "10.10.0.2".into(),
                prefix_len: 24,
                on_link_prefix_len: 24,
                gateway: Some("10.10.0.1".into()),
            }],
            tunnel_address: "10.10.0.2".into(),
            prefix_len: 24,
            mtu: 1400,
            tunnel_gateway: "10.10.0.1".into(),
            carrier_address: None,
            routes: vec![NetworkRoute {
                cidr: "0.0.0.0/0".into(),
                gateway: "10.10.0.1".into(),
                metric: 100,
            }],
            pushed_routes: Vec::new(),
            dns_servers: vec![NetworkDns {
                address: "1.1.1.1".into(),
                port: 53,
            }],
            full_tunnel: true,
            kill_switch: true,
            allow_ipv4_leak: false,
            allow_ipv6_leak: false,
            max_streams: 1,
            adaptive: false,
            data_plane: Default::default(),
            connection_log: Vec::new(),
        }
    }

    const TEST_SYSTEM_PLAN_CAPABILITIES: u64 = platform_capability::SYSTEM_PLAN
        | platform_capability::IPV6_ROUTES
        | platform_capability::IPV6_KILL_SWITCH;

    fn started_core(capacity: usize) -> ClientCore {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES,
                event_capacity: capacity,
            },
        )
        .unwrap();
        assert_eq!(core.poll_event().unwrap().state, ClientState::Created);
        core.start().unwrap();
        assert_eq!(core.poll_event().unwrap().state, ClientState::Connecting);
        core
    }

    #[test]
    fn accepts_ini_and_share_link_through_one_parser() {
        let ini_core = ClientCore::new(&ini(), CoreOptions::default()).unwrap();
        assert_eq!(ini_core.config.server.address, "127.0.0.1");

        let uri = format!("qeli://test:secret@127.0.0.1:443?proto=tcp&mode=fake-tls&key={KEY}");
        let uri_core = ClientCore::new(&uri, CoreOptions::default()).unwrap();
        assert_eq!(uri_core.config.auth.username, "test");
        assert!(ClientCore::new("[qeli]\nserver = broken", CoreOptions::default()).is_err());
    }

    #[test]
    fn running_requires_positive_network_plan_ack() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        let mut network_plan = plan(1);
        network_plan.data_plane.normalization_max = 1600;
        network_plan.data_plane.padding_max = 200;
        core.publish_network_plan(network_plan).unwrap();
        assert_eq!(
            core.last_downlink_record_bytes,
            1600 + 200 + crate::protocol::packet::TLS_RECORD_HEADER + 128,
            "direct plans must size the packet bridge from authenticated data-plane facts",
        );
        assert_eq!(core.state(), ClientState::AwaitingNetwork);
        assert_eq!(core.poll_event().unwrap().kind, EventKind::StateChanged);
        let event = core.poll_event().unwrap();
        assert_eq!(event.kind, EventKind::NetworkPlan);
        assert_eq!(event.plan.unwrap().generation, 1);

        core.ack_network_plan(1, true, None).unwrap();
        assert_eq!(core.state(), ClientState::Running);
        assert_eq!(core.poll_event().unwrap().state, ClientState::Running);
    }

    #[test]
    fn authenticated_platform_input_publishes_a_canonical_generation() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        let auth_ok = serde_json::json!({
            "client_ip": "10.8.0.2",
            "server_ip": "10.8.0.1",
            "prefix": 24,
            "mtu": 1300,
            "dns": "10.8.0.1",
            "dns_port": 5353,
            "routes": [{"cidr": "10.20.0.0/16", "metric": 42}]
        });
        let input = serde_json::json!({
            "auth_ok": format!("OK:{auth_ok}"),
            "effective_mtu": 1400,
            "fallback_dns_servers": ["1.1.1.1", "8.8.8.8"]
        })
        .to_string();

        assert_eq!(core.publish_handshake_network(&input).unwrap(), 1);
        assert_eq!(
            core.poll_event().unwrap().state,
            ClientState::AwaitingNetwork
        );
        let plan = core.poll_event().unwrap().plan.unwrap();
        assert_eq!(plan.generation, 1);
        assert_eq!(plan.mtu, 1400);
        assert_eq!(plan.routes[0].cidr, "10.20.0.0/16");
        assert_eq!(plan.dns_servers.len(), 1, "server push wins over fallback");
        assert_eq!(plan.dns_servers[0].port, 5353);
        core.ack_network_plan(1, true, None).unwrap();
        core.poll_event();

        let no_dns = serde_json::json!({
            "client_ip": "10.8.0.2",
            "server_ip": "10.8.0.1",
            "prefix": 24,
            "mtu": 1400,
            "dns": "",
            "dns_port": 53,
            "routes": []
        });
        let fallback_input = serde_json::json!({
            "auth_ok": format!("OK:{no_dns}"),
            "effective_mtu": 1400,
            "fallback_dns_servers": ["1.1.1.1", "8.8.8.8"]
        })
        .to_string();
        assert_eq!(core.publish_handshake_network(&fallback_input).unwrap(), 2);
        core.poll_event();
        let fallback_plan = core.poll_event().unwrap().plan.unwrap();
        assert_eq!(fallback_plan.dns_servers.len(), 2);
        assert_eq!(fallback_plan.dns_servers[1].address, "8.8.8.8");
    }

    #[test]
    fn malformed_handshake_network_input_does_not_change_lifecycle() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        assert!(matches!(
            core.publish_handshake_network("{not-json"),
            Err(CoreError::InvalidArgument(_))
        ));
        assert_eq!(core.state(), ClientState::Connecting);
        assert!(core.poll_event().is_none());

        let invalid_dns = serde_json::json!({
            "auth_ok": "OK:{}",
            "effective_mtu": 1400,
            "fallback_dns_servers": ["not-an-ip"]
        })
        .to_string();
        assert!(matches!(
            core.publish_handshake_network(&invalid_dns),
            Err(CoreError::InvalidArgument(_))
        ));
        assert_eq!(core.state(), ClientState::Connecting);
    }

    #[test]
    fn stale_ack_does_not_advance_state() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        core.publish_network_plan(plan(7)).unwrap();
        let error = core.ack_network_plan(6, true, None).unwrap_err();
        assert!(matches!(
            error,
            CoreError::StalePlan {
                expected: 7,
                got: 6
            }
        ));
        assert_eq!(core.state(), ClientState::AwaitingNetwork);
    }

    #[test]
    fn rejected_plan_fails_closed_and_reports_reason() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        core.publish_network_plan(plan(1)).unwrap();
        core.poll_event();
        core.poll_event();
        core.ack_network_plan(1, false, Some("route install failed"))
            .unwrap();
        assert_eq!(core.state(), ClientState::Failed);
        let error = core.poll_event().unwrap();
        assert_eq!(error.kind, EventKind::Error);
        assert_eq!(error.fault.unwrap().code, ErrorCode::PlatformRejected);
        assert_eq!(core.poll_event().unwrap().state, ClientState::Failed);
    }

    #[test]
    fn bounded_queue_applies_backpressure_without_partial_transition() {
        let mut core = started_core(2);
        core.publish_network_plan(plan(1)).unwrap();
        let error = core.ack_network_plan(1, true, None).unwrap_err();
        assert!(matches!(error, CoreError::EventQueueFull));
        assert_eq!(core.state(), ClientState::AwaitingNetwork);
        core.poll_event();
        core.ack_network_plan(1, true, None).unwrap();
        assert_eq!(core.state(), ClientState::Running);
    }

    #[test]
    fn terminal_runtime_failure_preempts_a_full_queue() {
        let mut core = started_core(2);
        core.push_event(EventKind::StateChanged, None, None, None, None);
        core.push_event(EventKind::StateChanged, None, None, None, None);

        core.publish_runtime_failure("carrier failed".to_string());

        assert_eq!(core.state(), ClientState::Failed);
        let error = core
            .poll_event()
            .expect("terminal Error must be observable");
        assert_eq!(error.kind, EventKind::Error);
        assert_eq!(error.state, ClientState::Failed);
        assert_eq!(error.fault.unwrap().message, "carrier failed");
        let changed = core
            .poll_event()
            .expect("terminal StateChanged must be observable");
        assert_eq!(changed.kind, EventKind::StateChanged);
        assert_eq!(changed.state, ClientState::Failed);
        assert!(core.poll_event().is_none());
    }

    #[test]
    fn one_slot_queue_is_rejected_before_it_creates_an_unusable_core() {
        let error = match ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN,
                event_capacity: 1,
            },
        ) {
            Err(error) => error,
            Ok(_) => {
                panic!("a one-slot queue cannot atomically publish lifecycle plus plan events")
            }
        };
        assert!(matches!(error, CoreError::InvalidArgument(_)));
    }

    #[test]
    fn late_network_plan_ack_cannot_revive_a_failed_runtime() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        core.publish_network_plan(plan(7)).unwrap();
        core.publish_runtime_failure("platform ACK timed out".to_string());

        assert_eq!(core.state(), ClientState::Failed);
        assert!(matches!(
            core.ack_network_plan(7, true, None),
            Err(CoreError::InvalidState { .. })
        ));
        assert_eq!(core.state(), ClientState::Failed);
    }

    #[test]
    fn missing_platform_capability_is_detected_before_emitting_plan() {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::ROUTES,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        let error = core.publish_network_plan(plan(1)).unwrap_err();
        assert!(matches!(error, CoreError::MissingCapability { .. }));
        assert_eq!(core.state(), ClientState::Connecting);
        assert!(core.poll_event().is_none());
    }

    #[test]
    fn ipv4_only_full_tunnel_requires_ipv6_fail_closed_capabilities() {
        let mut fail_closed = plan(1);
        let required = fail_closed.required_capabilities();
        assert_ne!(required & platform_capability::IPV6_ROUTES, 0);
        assert_ne!(required & platform_capability::IPV6_KILL_SWITCH, 0);

        fail_closed.kill_switch = false;
        let without_kill_switch = fail_closed.required_capabilities();
        assert_ne!(without_kill_switch & platform_capability::IPV6_ROUTES, 0);
        assert_eq!(
            without_kill_switch & platform_capability::IPV6_KILL_SWITCH,
            0
        );

        fail_closed.allow_ipv6_leak = true;
        let explicit_leak = fail_closed.required_capabilities();
        assert_eq!(explicit_leak & platform_capability::IPV6_ROUTES, 0);
        assert_eq!(explicit_leak & platform_capability::IPV6_KILL_SWITCH, 0);
    }

    #[test]
    fn invalid_plan_is_rejected_without_changing_state() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        let mut invalid = plan(1);
        invalid.routes = vec![NetworkRoute {
            cidr: "not-a-cidr".into(),
            gateway: "10.10.0.1".into(),
            metric: 100,
        }];
        assert!(matches!(
            core.publish_network_plan(invalid),
            Err(CoreError::InvalidArgument(_))
        ));
        assert_eq!(core.state(), ClientState::Connecting);
    }

    #[test]
    fn ipv6_plan_rejects_unusable_next_hops_before_platform_dispatch() {
        let mut invalid = plan(1);
        invalid.family_mode = NetworkFamilyMode::Ipv6;
        invalid.addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("::".into()),
        }];
        invalid.tunnel_address = "fd71:e1::2".into();
        invalid.prefix_len = 64;
        invalid.tunnel_gateway = "::".into();
        invalid.routes = vec![NetworkRoute {
            cidr: "2001:db8::/32".into(),
            gateway: "::".into(),
            metric: 100,
        }];
        invalid.dns_servers.clear();
        assert!(matches!(
            invalid.validate(),
            Err(CoreError::InvalidArgument(message))
                if message.contains("gateway") && message.contains("unspecified")
        ));

        invalid.addresses[0].gateway = Some("fd71:e1::1".into());
        invalid.tunnel_gateway = "fd71:e1::1".into();
        assert!(matches!(
            invalid.validate(),
            Err(CoreError::InvalidArgument(message))
                if message.contains("route gateway") && message.contains("unspecified")
        ));
    }

    #[test]
    fn stats_are_saturating_and_do_not_expose_config() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        core.record_tx(100);
        core.record_rx(200);
        core.record_reconnect();
        let runtime = Arc::new(RuntimeCounters::default());
        runtime
            .udp
            .kernel_drops
            .store(3, portable_atomic::Ordering::Relaxed);
        runtime
            .udp
            .internal_drops
            .store(5, portable_atomic::Ordering::Relaxed);
        runtime
            .udp
            .grow_events
            .store(2, portable_atomic::Ordering::Relaxed);
        runtime
            .udp
            .granted_recv_bytes
            .store(8 * 1024 * 1024, portable_atomic::Ordering::Relaxed);
        core.runtime_counters = Some(runtime);
        let stats = core.stats();
        assert_eq!((stats.tx_packets, stats.tx_bytes), (1, 100));
        assert_eq!((stats.rx_packets, stats.rx_bytes), (1, 200));
        assert_eq!(stats.reconnects, 1);
        assert_eq!(stats.udp_kernel_drops, 3);
        assert_eq!(stats.udp_internal_drops, 5);
        assert_eq!(stats.udp_buffer_grows, 2);
        assert_eq!(stats.udp_recv_buffer_bytes, 8 * 1024 * 1024);
    }

    #[test]
    #[cfg(unix)]
    fn socket_protect_request_is_correlated_and_acknowledged_once() {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::SOCKET_PROTECT,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();

        let (sequence, mut result) = core.request_socket_protect(42).unwrap();
        let event = core.poll_event().unwrap();
        assert_eq!(event.kind, EventKind::SocketProtect);
        assert_eq!(event.sequence, sequence);
        assert_eq!(event.socket_protect.unwrap().fd, 42);
        assert!(matches!(
            result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        core.ack_socket_protect(sequence, true, None).unwrap();
        assert_eq!(result.try_recv().unwrap(), Ok(()));
        assert!(matches!(
            core.ack_socket_protect(sequence, true, None),
            Err(CoreError::StaleRequest { got }) if got == sequence
        ));
    }

    #[test]
    #[cfg(unix)]
    fn socket_protect_fails_closed_without_capability_or_after_rejection() {
        let mut without_capability = started_core(DEFAULT_EVENT_CAPACITY);
        assert!(matches!(
            without_capability.request_socket_protect(7),
            Err(CoreError::MissingCapability { missing })
                if missing == platform_capability::SOCKET_PROTECT
        ));
        assert!(without_capability.poll_event().is_none());

        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES
                    | platform_capability::SOCKET_PROTECT,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        let (sequence, mut result) = core.request_socket_protect(7).unwrap();
        core.poll_event();
        let reason = "x".repeat(MAX_PLATFORM_ERROR_CHARS + 20);
        core.ack_socket_protect(sequence, false, Some(&reason))
            .unwrap();
        assert_eq!(
            result.try_recv().unwrap().unwrap_err().len(),
            MAX_PLATFORM_ERROR_CHARS
        );

        assert!(matches!(
            core.request_socket_protect(-1),
            Err(CoreError::InvalidArgument(_))
        ));

        let (_sequence, mut cancelled) = core.request_socket_protect(8).unwrap();
        core.poll_event();
        core.stop().unwrap();
        assert!(matches!(
            cancelled.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn server_identity_request_is_correlated_and_fails_closed() {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::SERVER_IDENTITY,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();

        let key = [0xabu8; 32];
        let (sequence, mut result) = core.request_server_identity(key).unwrap();
        let event = core.poll_event().unwrap();
        assert_eq!(event.kind, EventKind::ServerIdentity);
        assert_eq!(event.sequence, sequence);
        assert_eq!(
            event.server_identity.unwrap(),
            ServerIdentityRequest {
                server_id: "127.0.0.1:443".into(),
                public_key: "ab".repeat(32),
            }
        );
        core.ack_server_identity(sequence, true, None).unwrap();
        assert_eq!(result.try_recv().unwrap(), Ok(()));
        assert!(matches!(
            core.ack_server_identity(sequence, true, None),
            Err(CoreError::StaleRequest { got }) if got == sequence
        ));

        let (sequence, mut rejected) = core.request_server_identity(key).unwrap();
        core.poll_event();
        core.ack_server_identity(sequence, false, Some("known-host mismatch"))
            .unwrap();
        assert_eq!(
            rejected.try_recv().unwrap(),
            Err("known-host mismatch".into())
        );
        assert_eq!(core.state(), ClientState::Failed);
        assert_eq!(core.poll_event().unwrap().kind, EventKind::Error);
        assert_eq!(core.poll_event().unwrap().state, ClientState::Failed);
    }

    #[test]
    fn server_identity_request_requires_capability_and_is_cancelled_by_stop() {
        let mut without_capability = started_core(DEFAULT_EVENT_CAPACITY);
        assert!(matches!(
            without_capability.request_server_identity([7; 32]),
            Err(CoreError::MissingCapability { missing })
                if missing == platform_capability::SERVER_IDENTITY
        ));

        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::SERVER_IDENTITY,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        let (_sequence, mut cancelled) = core.request_server_identity([7; 32]).unwrap();
        core.poll_event();
        core.stop().unwrap();
        assert!(matches!(
            cancelled.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn start_defers_socket_creation_until_runtime_knows_the_candidate_family() {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::SOCKET_PROTECT,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        assert_eq!(core.poll_event().unwrap().state, ClientState::Connecting);
        assert!(core.poll_event().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn tun_attachment_requires_capability_and_is_released_on_plan_rejection() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (original, _peer) = UnixStream::pair().unwrap();
        let mut without_capability = started_core(DEFAULT_EVENT_CAPACITY);
        without_capability.publish_network_plan(plan(1)).unwrap();
        assert!(matches!(
            without_capability.attach_tun_fd(1, original.as_raw_fd()),
            Err(CoreError::MissingCapability { missing })
                if missing == platform_capability::TUN_FD
        ));

        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES | platform_capability::TUN_FD,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        core.publish_network_plan(plan(7)).unwrap();
        core.attach_tun_fd(7, original.as_raw_fd()).unwrap();
        let duplicate = core.attached_tun_raw_fd().unwrap();
        assert!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) } >= 0);

        core.ack_network_plan(7, false, Some("route setup failed"))
            .unwrap();
        assert_eq!(core.state(), ClientState::Failed);
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wintun_attachment_is_generation_scoped_and_gates_positive_ack() {
        let mut without_capability = started_core(DEFAULT_EVENT_CAPACITY);
        without_capability.publish_network_plan(plan(1)).unwrap();
        assert!(matches!(
            without_capability.attach_wintun_adapter(1, "Qeli-test"),
            Err(CoreError::MissingCapability { missing })
                if missing == platform_capability::TUN_WINTUN
        ));

        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES
                    | platform_capability::TUN_WINTUN,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        core.publish_network_plan(plan(7)).unwrap();
        assert!(matches!(
            core.ack_network_plan(7, true, None),
            Err(CoreError::InvalidState { .. })
        ));
        assert!(matches!(
            core.attach_wintun_adapter(6, "Qeli-test"),
            Err(CoreError::StalePlan {
                expected: 7,
                got: 6
            })
        ));
        core.attach_wintun_adapter(7, "Qeli-test").unwrap();
        core.ack_network_plan(7, true, None).unwrap();
        assert_eq!(core.take_attached_wintun(7).unwrap(), "Qeli-test");
        assert!(matches!(
            core.take_attached_wintun(7),
            Err(CoreError::InvalidState { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn acknowledged_tun_transfers_two_owned_descriptors_to_packet_workers() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (original, _peer) = UnixStream::pair().unwrap();
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES | platform_capability::TUN_FD,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        core.publish_network_plan(plan(7)).unwrap();
        core.attach_tun_fd(7, original.as_raw_fd()).unwrap();
        core.ack_network_plan(7, true, None).unwrap();

        let (reader, writer) = core.take_attached_tun_fds(7).unwrap();
        assert_ne!(reader.as_raw_fd(), writer.as_raw_fd());
        assert!(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(core.attached_tun_raw_fd().is_none());
        assert!(matches!(
            core.take_attached_tun_fds(7),
            Err(CoreError::InvalidState { .. })
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    fn running_path_core(generation: u64) -> ClientCore {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: TEST_SYSTEM_PLAN_CAPABILITIES
                    | platform_capability::ROAMING_PATH,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        core.publish_network_plan(plan(generation)).unwrap();
        assert_eq!(core.poll_event().unwrap().kind, EventKind::StateChanged);
        assert_eq!(core.poll_event().unwrap().kind, EventKind::NetworkPlan);
        core.ack_network_plan(generation, true, None).unwrap();
        assert_eq!(core.poll_event().unwrap().state, ClientState::Running);
        core
    }

    #[cfg(feature = "experimental-roaming")]
    fn path_update(generation: u64, update_id: u64, path_id: &str) -> String {
        serde_json::json!({
            "generation": generation,
            "update_id": update_id,
            "platform_path_id": path_id,
            "reason": "network_changed",
            "network_token": format!("network-{path_id}"),
            "interface_index": 7,
            "local_addresses": ["192.0.2.10", "2001:db8::10"],
            "resolved_addresses": [
                {"address": "198.51.100.20", "ttl_secs": 60},
                {"address": "2001:db8::20", "ttl_secs": 30}
            ],
            "flags": {
                "default_route_changed": true,
                "wake": false,
                "same_network_nat_failure": false
            }
        })
        .to_string()
    }

    #[cfg(feature = "experimental-roaming")]
    fn path_command(core: &mut ClientCore, action: PathCommandAction) -> ClientEvent {
        let event = core.poll_event().expect("path command event");
        assert_eq!(event.kind, EventKind::PathCommand);
        assert_eq!(
            event.path_command.as_ref().map(|command| command.action),
            Some(action)
        );
        event
    }

    #[cfg(feature = "experimental-roaming")]
    fn acknowledge_path_event(
        core: &mut ClientCore,
        event: &ClientEvent,
        accepted: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
        let command = event.path_command.as_ref().expect("path command payload");
        core.ack_path_command(
            command.generation,
            command.candidate_id,
            event.sequence,
            accepted,
            reason,
        )
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn path_event_poll_preserves_unrelated_queued_events() {
        let mut core = running_path_core(7);
        core.push_event(EventKind::StateChanged, None, None, None, None);
        core.submit_path_update(&path_update(7, 1, "wifi-a"))
            .unwrap();

        let path = core.poll_path_event().expect("path command event");
        assert_eq!(path.kind, EventKind::PathCommand);
        assert_eq!(
            path.path_command.as_ref().map(|command| command.action),
            Some(PathCommandAction::PreparePath)
        );
        assert_eq!(core.poll_event().unwrap().kind, EventKind::StateChanged);
        assert!(core.poll_event().is_none());
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn path_update_is_generation_scoped_bounded_and_idempotent() {
        let mut core = running_path_core(7);
        assert!(matches!(
            core.submit_path_update(&path_update(6, 1, "stale")),
            Err(CoreError::StalePlan {
                expected: 7,
                got: 6
            })
        ));
        assert!(matches!(
            core.submit_path_update("{}"),
            Err(CoreError::InvalidArgument(_))
        ));
        let mut loopback: serde_json::Value =
            serde_json::from_str(&path_update(7, 1, "loopback")).unwrap();
        loopback["local_addresses"][0] = serde_json::Value::String("127.0.0.1".into());
        assert!(matches!(
            core.submit_path_update(&loopback.to_string()),
            Err(CoreError::InvalidArgument(_))
        ));
        let mut inconsistent: serde_json::Value =
            serde_json::from_str(&path_update(7, 1, "wake")).unwrap();
        inconsistent["reason"] = serde_json::Value::String("wake".into());
        assert!(matches!(
            core.submit_path_update(&inconsistent.to_string()),
            Err(CoreError::InvalidArgument(_))
        ));
        let mut incompatible: serde_json::Value =
            serde_json::from_str(&path_update(7, 1, "incompatible")).unwrap();
        incompatible["local_addresses"] = serde_json::json!(["192.0.2.10"]);
        incompatible["resolved_addresses"] =
            serde_json::json!([{"address": "2001:db8::20", "ttl_secs": 30}]);
        assert!(matches!(
            core.submit_path_update(&incompatible.to_string()),
            Err(CoreError::InvalidArgument(_))
        ));

        let candidate = core.submit_path_update(&path_update(7, 1, "wifi")).unwrap();
        assert_eq!(
            core.submit_path_update(&path_update(7, 1, "wifi")).unwrap(),
            candidate
        );
        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        let payload = prepare.path_command.as_ref().unwrap();
        assert_eq!(payload.generation, 7);
        assert_eq!(payload.candidate_id, candidate);
        assert_eq!(payload.path.platform_path_id, "wifi");
        assert_eq!(payload.path.resolved_addresses.len(), 2);
        assert_eq!(
            payload.path.compatible_resolved_addresses(),
            vec![
                "198.51.100.20".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::20".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
        assert!(
            core.poll_event().is_none(),
            "duplicate must not enqueue work"
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn path_candidate_addresses_keep_dns_order_but_skip_unusable_families() {
        let mut update: serde_json::Value =
            serde_json::from_str(&path_update(9, 1, "ipv4-only")).unwrap();
        update["local_addresses"] = serde_json::json!(["192.0.2.10"]);
        update["resolved_addresses"] = serde_json::json!([
            {"address": "2001:db8::20", "ttl_secs": 30},
            {"address": "198.51.100.21", "ttl_secs": 60},
            {"address": "198.51.100.22", "ttl_secs": 60}
        ]);
        let mut core = running_path_core(9);
        core.submit_path_update(&update.to_string()).unwrap();
        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        assert_eq!(
            prepare
                .path_command
                .unwrap()
                .path
                .compatible_resolved_addresses(),
            vec![
                "198.51.100.21".parse::<std::net::IpAddr>().unwrap(),
                "198.51.100.22".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn path_transaction_commits_without_replacing_running_data_plane() {
        let mut core = running_path_core(11);
        let candidate = core
            .submit_path_update(&path_update(11, 1, "cellular"))
            .unwrap();

        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        acknowledge_path_event(&mut core, &prepare, true, None).unwrap();
        assert!(matches!(
            core.candidate_path_validated(11, candidate),
            Err(CoreError::InvalidState { .. })
        ));

        let (_, mut bind_result) = core
            .request_candidate_socket_binding(11, candidate, 42)
            .unwrap();
        let bind = path_command(&mut core, PathCommandAction::BindSocket);
        assert_eq!(bind.path_command.as_ref().unwrap().socket_fd, Some(42));
        assert_eq!(
            bind_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        acknowledge_path_event(&mut core, &bind, true, None).unwrap();
        assert_eq!(bind_result.try_recv(), Ok(Ok(())));

        let (_, mut commit_result) = core.candidate_path_validated(11, candidate).unwrap();
        let commit = path_command(&mut core, PathCommandAction::CommitPath);
        acknowledge_path_event(&mut core, &commit, true, None).unwrap();
        assert_eq!(commit_result.try_recv(), Ok(Ok(())));

        let stats = core.stats();
        assert_eq!(core.state(), ClientState::Running);
        assert_eq!(core.last_plan_generation, 11);
        assert_eq!(stats.roam_attempts, 1);
        assert_eq!(stats.roam_successes, 1);
        assert_eq!(stats.roam_failures, 0);
        assert_eq!(stats.reconnects, 0);
        assert_eq!(stats.roam_candidates, 0);
        assert!(core.poll_event().is_none());
        assert!(matches!(
            acknowledge_path_event(&mut core, &commit, true, None),
            Err(CoreError::StaleRequest { .. })
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn prepared_candidate_is_single_owner_and_supersede_cancels_bind_waiter() {
        let mut core = running_path_core(13);
        let first = core
            .submit_path_update(&path_update(13, 1, "wifi-a"))
            .unwrap();
        assert!(core.prepared_path_candidate().is_none());
        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        acknowledge_path_event(&mut core, &prepare, true, None).unwrap();

        let prepared = core
            .prepared_path_candidate()
            .expect("prepared transport snapshot");
        assert_eq!(prepared.candidate_id, first);
        assert_eq!(prepared.update.platform_path_id, "wifi-a");
        let (_, mut bind_result) = core
            .request_candidate_socket_binding(13, first, 17)
            .unwrap();
        assert!(core.prepared_path_candidate().is_none());

        let second = core
            .submit_path_update(&path_update(13, 2, "wifi-b"))
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            bind_result.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
        let replacement = path_command(&mut core, PathCommandAction::PreparePath);
        assert_eq!(
            replacement
                .path_command
                .as_ref()
                .map(|command| command.candidate_id),
            Some(second)
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn path_ack_waiters_report_rejection_and_explicit_abort_completion() {
        let mut rejected = running_path_core(15);
        let candidate = rejected
            .submit_path_update(&path_update(15, 1, "wifi-rejected"))
            .unwrap();
        let prepare = path_command(&mut rejected, PathCommandAction::PreparePath);
        acknowledge_path_event(&mut rejected, &prepare, true, None).unwrap();
        let (_, mut binding) = rejected
            .request_candidate_socket_binding(15, candidate, 19)
            .unwrap();
        let bind = path_command(&mut rejected, PathCommandAction::BindSocket);
        acknowledge_path_event(&mut rejected, &bind, false, Some("network vanished")).unwrap();
        assert_eq!(binding.try_recv(), Ok(Err("network vanished".into())));
        let rollback = path_command(&mut rejected, PathCommandAction::AbortPath);
        acknowledge_path_event(&mut rejected, &rollback, true, None).unwrap();

        let mut aborted = running_path_core(16);
        let candidate = aborted
            .submit_path_update(&path_update(16, 1, "wifi-abort"))
            .unwrap();
        let prepare = path_command(&mut aborted, PathCommandAction::PreparePath);
        acknowledge_path_event(&mut aborted, &prepare, true, None).unwrap();
        let _binding = aborted
            .request_candidate_socket_binding(16, candidate, 23)
            .unwrap();
        let bind = path_command(&mut aborted, PathCommandAction::BindSocket);
        acknowledge_path_event(&mut aborted, &bind, true, None).unwrap();
        let (_, mut abort_result) = aborted
            .abort_candidate_path(16, candidate, "candidate connect failed")
            .unwrap();
        let abort = path_command(&mut aborted, PathCommandAction::AbortPath);
        assert_eq!(
            abort
                .path_command
                .as_ref()
                .and_then(|command| command.reason.as_deref()),
            Some("candidate connect failed")
        );
        acknowledge_path_event(&mut aborted, &abort, true, None).unwrap();
        assert_eq!(abort_result.try_recv(), Ok(Ok(())));
    }

    #[cfg(feature = "experimental-roaming")]
    struct FaultInjectingPathAdapter {
        fail_at: PathCommandAction,
    }

    #[cfg(feature = "experimental-roaming")]
    impl FaultInjectingPathAdapter {
        fn apply(&self, core: &mut ClientCore, event: &ClientEvent) {
            let action = event.path_command.as_ref().unwrap().action;
            acknowledge_path_event(
                core,
                event,
                action != self.fail_at,
                (action == self.fail_at).then_some("injected platform fault"),
            )
            .unwrap();
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn run_path_fault(fail_at: PathCommandAction) -> CoreStats {
        let adapter = FaultInjectingPathAdapter { fail_at };
        let mut core = running_path_core(17);
        let candidate = core
            .submit_path_update(&path_update(17, 1, "fault-path"))
            .unwrap();

        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        adapter.apply(&mut core, &prepare);
        if fail_at != PathCommandAction::PreparePath {
            let _binding = core
                .request_candidate_socket_binding(17, candidate, 9)
                .unwrap();
            let bind = path_command(&mut core, PathCommandAction::BindSocket);
            adapter.apply(&mut core, &bind);
            if fail_at != PathCommandAction::BindSocket {
                let _commit = core.candidate_path_validated(17, candidate).unwrap();
                let commit = path_command(&mut core, PathCommandAction::CommitPath);
                adapter.apply(&mut core, &commit);
            }
        }

        let abort = path_command(&mut core, PathCommandAction::AbortPath);
        acknowledge_path_event(&mut core, &abort, true, None).unwrap();
        assert_eq!(core.state(), ClientState::Running);
        core.stats()
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn mock_adapter_rolls_back_prepare_bind_and_commit_faults() {
        for action in [
            PathCommandAction::PreparePath,
            PathCommandAction::BindSocket,
            PathCommandAction::CommitPath,
        ] {
            let stats = run_path_fault(action);
            assert_eq!(stats.roam_attempts, 1, "{action:?}");
            assert_eq!(stats.roam_successes, 0, "{action:?}");
            assert_eq!(stats.roam_failures, 1, "{action:?}");
            assert_eq!(stats.roam_reconnect_fallbacks, 0, "{action:?}");
            assert_eq!(stats.roam_candidates, 0, "{action:?}");
        }
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn failed_abort_is_a_reconnect_fallback_and_discards_queued_candidate() {
        let mut core = running_path_core(21);
        core.submit_path_update(&path_update(21, 1, "bad-path"))
            .unwrap();
        let prepare = path_command(&mut core, PathCommandAction::PreparePath);
        acknowledge_path_event(&mut core, &prepare, false, Some("route failed")).unwrap();
        let abort = path_command(&mut core, PathCommandAction::AbortPath);
        assert!(matches!(
            acknowledge_path_event(&mut core, &abort, false, Some("rollback failed")),
            Err(CoreError::Platform(_))
        ));
        let stats = core.stats();
        assert_eq!(stats.roam_failures, 1);
        assert_eq!(stats.roam_reconnect_fallbacks, 1);
        assert_eq!(stats.roam_candidates, 0);
        assert_eq!(core.state(), ClientState::Running);
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn newer_update_cancels_an_unobserved_prepare_without_stale_platform_work() {
        let mut core = running_path_core(31);
        let first = core
            .submit_path_update(&path_update(31, 1, "wifi-a"))
            .unwrap();
        while core.events.len() < core.event_capacity {
            core.push_event(EventKind::StateChanged, None, None, None, None);
        }
        let second = core
            .submit_path_update(&path_update(31, 2, "wifi-b"))
            .unwrap();
        assert_eq!(core.events.len(), core.event_capacity);
        core.events
            .retain(|event| event.kind == EventKind::PathCommand);
        assert_ne!(first, second);
        let event = path_command(&mut core, PathCommandAction::PreparePath);
        assert_eq!(event.path_command.as_ref().unwrap().candidate_id, second);
        assert_eq!(
            event.path_command.as_ref().unwrap().path.platform_path_id,
            "wifi-b"
        );
        assert!(core.poll_event().is_none());
        let stats = core.stats();
        assert_eq!(stats.roam_attempts, 2);
        assert_eq!(stats.roam_failures, 1);
        assert_eq!(stats.roam_candidates, 1);
        assert!(matches!(
            core.submit_path_update(&path_update(31, 1, "wifi-a")),
            Err(CoreError::StaleRequest { got: 1 })
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn stop_discards_unobserved_path_commands() {
        let mut core = running_path_core(37);
        core.submit_path_update(&path_update(37, 1, "wifi"))
            .unwrap();

        core.stop().unwrap();

        let events: Vec<_> = std::iter::from_fn(|| core.poll_event()).collect();
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|event| event.kind == EventKind::StateChanged));
        assert_eq!(
            events.last().map(|event| event.state),
            Some(ClientState::Stopped)
        );
        assert_eq!(core.stats().roam_failures, 1);
        assert_eq!(core.stats().roam_candidates, 0);
    }
}
