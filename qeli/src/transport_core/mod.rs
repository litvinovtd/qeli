//! Cross-platform lifecycle boundary for the shared qeli client core.
//!
//! The core owns strict configuration, lifecycle, carriers, handshakes and packet pumps.
//! Platform adapters remain responsible for system APIs and must positively acknowledge a
//! [`NetworkPlan`] before the core enters [`ClientState::Running`]. Android executes the full
//! data plane through ABI 1.6, Windows/macOS/iOS use the ABI 1.7 packet seam, and the same
//! common sessions run behind the in-process Linux adapter. ABI 1.8 also exposes the shared
//! UDP first-flight diagnostic to every native adapter.

use crate::config::{client::ClientConfig, parse_client_config_strict, share::ClientLink};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::fd::AsRawFd;

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

// Unix fd-based clients share one raw TUN backend. Android supplies the descriptor through
// VpnService, while Linux opens it locally; both then use the same blocking packet workers.
#[cfg(all(unix, any(feature = "client", feature = "transport-core-ffi")))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod linux_tun;

// Wintun and the managed utun adapter cannot hand Rust a portable descriptor. Their small
// platform wrappers exchange bounded packet batches with the same common transport loops.
#[cfg(any(feature = "client", feature = "transport-core-ffi"))]
#[cfg_attr(
    not(any(target_os = "windows", target_os = "macos", target_os = "ios")),
    allow(dead_code)
)]
pub(crate) mod packet_tun;

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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod network;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod session;

#[cfg(all(feature = "transport-core-ffi", not(target_pointer_width = "64")))]
compile_error!(
    "transport-core-ffi currently supports only 64-bit targets; shipped GUI clients are \
     64-bit, while 32-bit router builds must leave this feature disabled"
);

pub const ABI_VERSION_MAJOR: u16 = 1;
pub const ABI_VERSION_MINOR: u16 = 8;
pub const ABI_VERSION: u32 = ((ABI_VERSION_MAJOR as u32) << 16) | ABI_VERSION_MINOR as u32;

pub const DEFAULT_EVENT_CAPACITY: usize = 64;
pub const MAX_EVENT_CAPACITY: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 8;
const MAX_PLAN_STRING_BYTES: usize = 128;
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
    pub const BASE: u64 = STRICT_CONFIG | LIFECYCLE_EVENTS | NETWORK_PLAN_ACK;
    #[cfg(target_os = "android")]
    pub const ALL: u64 = BASE
        | TUN_FD_OWNERSHIP
        | SOCKET_PROTECT_ACK
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | UDP_DIAGNOSTIC;
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "ios"))]
    pub const ALL: u64 = BASE
        | DEVICE_ID_INPUT
        | SERVER_IDENTITY_ACK
        | HANDSHAKE_NETWORK_INPUT
        | NATIVE_DATA_PLANE
        | TUN_PACKET_IO
        | UDP_DIAGNOSTIC;
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
        | UDP_DIAGNOSTIC;
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

/// A carrier socket created by Rust before Android routes the VPN through its TUN.
///
/// `pending` keeps the descriptor alive while `VpnService.protect(fd)` is in flight.
/// Only a positive ACK moves it to `protected`; rejection, stop and free close it.
#[cfg(unix)]
struct PendingWireSocket {
    sequence: u64,
    socket: socket2::Socket,
    result: tokio::sync::oneshot::Receiver<Result<(), String>>,
}

#[cfg(unix)]
struct ProtectedWireSocket {
    _socket: socket2::Socket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkRoute {
    pub cidr: String,
    pub gateway: String,
    pub metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkDns {
    pub address: String,
    pub port: u16,
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
            heartbeat_enabled: config.heartbeat.enabled,
            heartbeat_interval_ms: config.heartbeat.interval_ms,
            shaping_enabled: config.traffic_shaping.enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPlan {
    pub generation: u64,
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
    pub max_streams: u32,
    pub adaptive: bool,
    /// Effective negotiated data-plane values, for platform UI only.
    pub data_plane: NetworkDataPlaneFacts,
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
        required
    }

    fn validate(&self) -> Result<(), CoreError> {
        if self.generation == 0 {
            return Err(CoreError::InvalidArgument(
                "network plan generation must be non-zero".into(),
            ));
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
        if self.prefix_len > max_prefix {
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
        if self.tunnel_gateway.len() > MAX_PLAN_STRING_BYTES
            || self.tunnel_gateway.parse::<IpAddr>().is_err()
        {
            return Err(CoreError::InvalidArgument(format!(
                "invalid tunnel gateway '{}'",
                self.tunnel_gateway
            )));
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
        }
        if self.dns_servers.len() > MAX_DNS_SERVERS {
            return Err(CoreError::InvalidArgument(format!(
                "network plan contains {} DNS servers; maximum is {MAX_DNS_SERVERS}",
                self.dns_servers.len()
            )));
        }
        for dns in &self.dns_servers {
            if dns.address.len() > MAX_PLAN_STRING_BYTES
                || dns.address.parse::<IpAddr>().is_err()
                || dns.port == 0
            {
                return Err(CoreError::InvalidArgument(format!(
                    "invalid DNS server '{}:{}'",
                    dns.address, dns.port
                )));
            }
        }
        Ok(())
    }
}

fn validate_cidr(route: &str) -> Result<(), CoreError> {
    if route.len() > MAX_PLAN_STRING_BYTES {
        return Err(CoreError::InvalidArgument("route is too long".into()));
    }
    let (address, prefix) = route
        .split_once('/')
        .ok_or_else(|| CoreError::InvalidArgument(format!("invalid route '{route}'")))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| CoreError::InvalidArgument(format!("invalid route '{route}'")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| CoreError::InvalidArgument(format!("invalid route '{route}'")))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
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
    #[cfg(unix)]
    pending_wire_socket: Option<PendingWireSocket>,
    #[cfg(unix)]
    protected_wire_socket: Option<ProtectedWireSocket>,
    last_plan_generation: u64,
    #[cfg(unix)]
    attached_tun: Option<AttachedTun>,
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
        if options.event_capacity == 0 || options.event_capacity > MAX_EVENT_CAPACITY {
            return Err(CoreError::InvalidArgument(format!(
                "event capacity must be 1..={MAX_EVENT_CAPACITY}"
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
            #[cfg(unix)]
            pending_wire_socket: None,
            #[cfg(unix)]
            protected_wire_socket: None,
            last_plan_generation: 0,
            #[cfg(unix)]
            attached_tun: None,
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
        let needs_socket_protect =
            self.platform_capabilities & platform_capability::SOCKET_PROTECT != 0;
        self.require_event_slots(if needs_socket_protect { 2 } else { 1 })?;

        #[cfg(unix)]
        let wire_socket = if needs_socket_protect {
            Some(open_wire_socket(&self.config)?)
        } else {
            None
        };
        #[cfg(not(unix))]
        if needs_socket_protect {
            return Err(CoreError::Unsupported(
                "socket-protect ownership requires a Unix descriptor",
            ));
        }

        self.pending_plan = None;
        self.pending_socket_protect.clear();
        self.pending_server_identity.clear();
        #[cfg(unix)]
        {
            self.attached_tun = None;
            self.pending_wire_socket = None;
            self.protected_wire_socket = None;
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

        #[cfg(unix)]
        if let Some(socket) = wire_socket {
            let fd = socket.as_raw_fd();
            let (sequence, result) = self.request_socket_protect(fd)?;
            self.pending_wire_socket = Some(PendingWireSocket {
                sequence,
                socket,
                result,
            });
        }
        Ok(())
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
            client_ip: &auth.client_ip,
            prefix: auth.prefix,
            tunnel_gateway: &auth.server_ip,
            dns_ip: &auth.dns_ip,
            dns_port: &auth.dns_port,
            routes_json: &auth.routes_json,
            mtu: i32::from(input.effective_mtu),
            fallback_dns_servers: &input.fallback_dns_servers,
        };
        let plan = network::build_network_plan(&self.config, generation, &network)
            .map_err(|error| CoreError::InvalidArgument(error.to_string()))?;
        self.publish_network_plan(plan)?;
        Ok(generation)
    }

    pub fn ack_network_plan(
        &mut self,
        generation: u64,
        applied: bool,
        reason: Option<&str>,
    ) -> Result<(), CoreError> {
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
        #[cfg(any(feature = "client", feature = "transport-core-ffi"))]
        let packet_tun =
            if applied && self.platform_capabilities & platform_capability::TUN_PACKET_BATCH != 0 {
                Some(
                    packet_tun::PacketTunPump::new(generation)
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
        #[cfg(unix)]
        let owns_wire_socket = self
            .pending_wire_socket
            .as_ref()
            .is_some_and(|pending| pending.sequence == request_sequence);
        #[cfg(not(unix))]
        let owns_wire_socket = false;

        // A rejected core-owned socket produces Error + Failed atomically. Do not consume
        // the one-shot request when the bounded event queue cannot report that failure.
        if owns_wire_socket && !protected {
            self.require_event_slots(2)?;
        }
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

        #[cfg(unix)]
        if owns_wire_socket {
            let mut pending = self
                .pending_wire_socket
                .take()
                .ok_or(CoreError::StaleRequest {
                    got: request_sequence,
                })?;
            let delivered = pending
                .result
                .try_recv()
                .map_err(|_| CoreError::StaleRequest {
                    got: request_sequence,
                })?;
            match delivered {
                Ok(()) => {
                    self.protected_wire_socket = Some(ProtectedWireSocket {
                        _socket: pending.socket,
                    });
                }
                Err(message) => {
                    self.protected_wire_socket = None;
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
            }
        }
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

    pub fn stop(&mut self) -> Result<(), CoreError> {
        if self.state == ClientState::Stopped {
            return Ok(());
        }
        // Cancellation is not an event and must never be held hostage by a full event queue:
        // a blocking native runner owns socket/TUN descriptors that teardown must release.
        self.runtime_cancel.store(true, Ordering::Release);
        self.require_event_slots(2)?;
        self.runtime_active = false;
        self.pending_plan = None;
        self.pending_socket_protect.clear();
        self.pending_server_identity.clear();
        #[cfg(unix)]
        {
            self.attached_tun = None;
            self.pending_wire_socket = None;
            self.protected_wire_socket = None;
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

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    pub fn stats(&self) -> CoreStats {
        let runtime = self.runtime_counters.as_ref();
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
        }
    }

    // The Linux transport migration will consume the parsed config through this crate-only
    // accessor. Keep credentials away from the public API while the data plane is still
    // being moved behind this state machine.
    #[allow(dead_code)]
    pub(crate) fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Transfer the protected, still-unconnected carrier into the async handshake owner.
    /// The descriptor cannot be taken before the matching platform ACK and can be taken once.
    #[cfg(unix)]
    #[allow(dead_code)]
    pub(crate) fn take_protected_wire_socket(&mut self) -> Result<socket2::Socket, CoreError> {
        if self.state != ClientState::Connecting {
            return Err(CoreError::InvalidState {
                state: self.state,
                operation: "take_protected_wire_socket",
            });
        }
        self.protected_wire_socket
            .take()
            .map(|protected| protected._socket)
            .ok_or(CoreError::InvalidState {
                state: self.state,
                operation: "take_protected_wire_socket before platform ACK",
            })
    }

    /// Consume the protected carrier and connect it under the configured shared deadline.
    /// `start()` only publishes lifecycle/platform requests; the external runner consumes and
    /// connects the carrier after the protect ACK.
    #[cfg(unix)]
    #[allow(dead_code)]
    pub(crate) async fn connect_protected_carrier(
        &mut self,
    ) -> Result<carrier::ConnectedCarrier, CoreError> {
        let socket = self.take_protected_wire_socket()?;
        carrier::connect(socket, &self.config)
            .await
            .map_err(|error| CoreError::Platform(format!("carrier connect failed: {error}")))
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

    #[cfg(all(test, unix))]
    fn pending_wire_socket_raw_fd(&self) -> Option<i32> {
        self.pending_wire_socket
            .as_ref()
            .map(|pending| pending.socket.as_raw_fd())
    }

    #[cfg(all(test, unix))]
    fn protected_wire_socket_raw_fd(&self) -> Option<i32> {
        self.protected_wire_socket
            .as_ref()
            .map(|protected| protected._socket.as_raw_fd())
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
            fault,
        });
        sequence
    }
}

#[cfg(unix)]
fn open_wire_socket(config: &ClientConfig) -> Result<socket2::Socket, CoreError> {
    carrier::open(config)
        .map_err(|error| CoreError::Platform(format!("could not create wire socket: {error}")))
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
            max_streams: 1,
            adaptive: false,
            data_plane: Default::default(),
        }
    }

    fn started_core(capacity: usize) -> ClientCore {
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                event_capacity: capacity,
                ..CoreOptions::default()
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
        core.publish_network_plan(plan(1)).unwrap();
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
    fn stats_are_saturating_and_do_not_expose_config() {
        let mut core = started_core(DEFAULT_EVENT_CAPACITY);
        core.record_tx(100);
        core.record_rx(200);
        core.record_reconnect();
        let stats = core.stats();
        assert_eq!((stats.tx_packets, stats.tx_bytes), (1, 100));
        assert_eq!((stats.rx_packets, stats.rx_bytes), (1, 200));
        assert_eq!(stats.reconnects, 1);
    }

    #[test]
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

        let initial = core.poll_event().unwrap();
        assert_eq!(initial.kind, EventKind::SocketProtect);
        core.ack_socket_protect(initial.sequence, true, None)
            .unwrap();
        assert!(core.protected_wire_socket_raw_fd().is_some());

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
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::SOCKET_PROTECT,
                event_capacity: DEFAULT_EVENT_CAPACITY,
            },
        )
        .unwrap();
        core.poll_event();
        core.start().unwrap();
        core.poll_event();
        let initial = core.poll_event().unwrap();
        core.ack_socket_protect(initial.sequence, true, None)
            .unwrap();
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
    fn start_owns_wire_socket_until_platform_ack_and_fails_closed_on_rejection() {
        use std::os::fd::BorrowedFd;

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
        let request = core.poll_event().unwrap();
        assert_eq!(request.kind, EventKind::SocketProtect);
        let fd = request.socket_protect.unwrap().fd;
        assert_eq!(core.pending_wire_socket_raw_fd(), Some(fd));
        // SAFETY: the core owns the descriptor and keeps it open until this ACK.
        assert!(unsafe { BorrowedFd::borrow_raw(fd) }
            .try_clone_to_owned()
            .is_ok());

        core.ack_socket_protect(request.sequence, false, Some("protect denied"))
            .unwrap();
        assert_eq!(core.state(), ClientState::Failed);
        assert!(core.pending_wire_socket_raw_fd().is_none());
        assert!(core.protected_wire_socket_raw_fd().is_none());
        let error = core.poll_event().unwrap();
        assert_eq!(error.kind, EventKind::Error);
        assert_eq!(error.fault.unwrap().message, "protect denied");
        assert_eq!(core.poll_event().unwrap().state, ClientState::Failed);
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
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::TUN_FD,
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

    #[cfg(unix)]
    #[test]
    fn acknowledged_tun_transfers_two_owned_descriptors_to_packet_workers() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (original, _peer) = UnixStream::pair().unwrap();
        let mut core = ClientCore::new(
            &ini(),
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN
                    | platform_capability::TUN_FD,
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
}
