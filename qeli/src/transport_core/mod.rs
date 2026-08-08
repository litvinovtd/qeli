//! Cross-platform lifecycle boundary for the shared qeli client core.
//!
//! The transport data plane is still being extracted from `client`; this module is the
//! first non-breaking slice: one strict configuration parser, one explicit state machine,
//! a bounded event queue, and an acknowledge-before-running contract for routes/DNS and
//! the kill switch. Platform code remains responsible for system APIs and must positively
//! acknowledge a [`NetworkPlan`] before the core enters [`ClientState::Running`].

use crate::config::{client::ClientConfig, parse_client_config_strict, share::ClientLink};
use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Instant;
use zeroize::Zeroize;

#[cfg(all(feature = "transport-core-ffi", target_pointer_width = "64"))]
pub mod ffi;

#[cfg(all(feature = "transport-core-ffi", not(target_pointer_width = "64")))]
compile_error!(
    "transport-core-ffi currently supports only 64-bit targets; shipped GUI clients are \
     64-bit, while 32-bit router builds must leave this feature disabled"
);

pub const ABI_VERSION_MAJOR: u16 = 1;
pub const ABI_VERSION_MINOR: u16 = 0;
pub const ABI_VERSION: u32 = ((ABI_VERSION_MAJOR as u32) << 16) | ABI_VERSION_MINOR as u32;

pub const DEFAULT_EVENT_CAPACITY: usize = 64;
pub const MAX_EVENT_CAPACITY: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_ROUTES: usize = 256;
const MAX_DNS_SERVERS: usize = 8;
const MAX_PLAN_STRING_BYTES: usize = 128;
const MAX_PLATFORM_ERROR_CHARS: usize = 512;

/// Capabilities implemented by this revision of the shared core ABI.
pub mod core_capability {
    pub const STRICT_CONFIG: u64 = 1 << 0;
    pub const LIFECYCLE_EVENTS: u64 = 1 << 1;
    pub const NETWORK_PLAN_ACK: u64 = 1 << 2;
    pub const ALL: u64 = STRICT_CONFIG | LIFECYCLE_EVENTS | NETWORK_PLAN_ACK;
}

/// System operations a platform adapter is able to perform.
pub mod platform_capability {
    pub const ROUTES: u64 = 1 << 0;
    pub const DNS: u64 = 1 << 1;
    pub const KILL_SWITCH: u64 = 1 << 2;
    pub const TUN_FD: u64 = 1 << 3;
    pub const TUN_PACKET_BATCH: u64 = 1 << 4;
    pub const SOCKET_PROTECT: u64 = 1 << 5;
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
    #[error("event queue is full; poll pending events before retrying")]
    EventQueueFull,
    #[error("platform is missing required capabilities 0x{missing:x}")]
    MissingCapability { missing: u64 },
}

impl CoreError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::InvalidConfig(_) => ErrorCode::InvalidConfig,
            Self::InvalidState { .. } => ErrorCode::InvalidState,
            Self::StalePlan { .. } => ErrorCode::StalePlan,
            Self::EventQueueFull => ErrorCode::EventQueueFull,
            Self::MissingCapability { .. } => ErrorCode::Unsupported,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkPlan {
    pub generation: u64,
    pub tunnel_address: String,
    pub prefix_len: u8,
    pub mtu: u16,
    pub tunnel_gateway: String,
    pub routes: Vec<NetworkRoute>,
    pub dns_servers: Vec<NetworkDns>,
    pub full_tunnel: bool,
    pub kill_switch: bool,
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
        if self.routes.len() > MAX_ROUTES {
            return Err(CoreError::InvalidArgument(format!(
                "network plan contains {} routes; maximum is {MAX_ROUTES}",
                self.routes.len()
            )));
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEvent {
    pub sequence: u64,
    pub kind: EventKind,
    pub state: ClientState,
    pub plan: Option<NetworkPlan>,
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
    platform_capabilities: u64,
    state: ClientState,
    events: VecDeque<ClientEvent>,
    event_capacity: usize,
    next_sequence: u64,
    pending_plan: Option<u64>,
    last_plan_generation: u64,
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    reconnects: u64,
    created_at: Instant,
}

impl Drop for ClientCore {
    fn drop(&mut self) {
        self.config.auth.password.zeroize();
        self.config.auth.password_command.zeroize();
        self.config.obfuscation.obfs_key.zeroize();
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
            platform_capabilities: options.platform_capabilities,
            state: ClientState::Created,
            events: VecDeque::with_capacity(options.event_capacity),
            event_capacity: options.event_capacity,
            next_sequence: 1,
            pending_plan: None,
            last_plan_generation: 0,
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            reconnects: 0,
            created_at: Instant::now(),
        };
        core.push_event(EventKind::StateChanged, None, None);
        Ok(core)
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn platform_capabilities(&self) -> u64 {
        self.platform_capabilities
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
        self.require_event_slots(1)?;
        self.pending_plan = None;
        self.state = ClientState::Connecting;
        self.push_event(EventKind::StateChanged, None, None);
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
        self.push_event(EventKind::StateChanged, None, None);
        self.push_event(EventKind::NetworkPlan, Some(plan), None);
        Ok(())
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
        self.require_event_slots(if applied { 1 } else { 2 })?;
        self.pending_plan = None;
        self.last_plan_generation = generation;
        if applied {
            self.state = ClientState::Running;
            self.push_event(EventKind::StateChanged, None, None);
        } else {
            self.state = ClientState::Failed;
            let message: String = reason
                .unwrap_or("platform rejected the network plan")
                .chars()
                .take(MAX_PLATFORM_ERROR_CHARS)
                .collect();
            self.push_event(
                EventKind::Error,
                None,
                Some(CoreFault {
                    code: ErrorCode::PlatformRejected,
                    message,
                }),
            );
            self.push_event(EventKind::StateChanged, None, None);
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), CoreError> {
        if self.state == ClientState::Stopped {
            return Ok(());
        }
        self.require_event_slots(2)?;
        self.pending_plan = None;
        self.state = ClientState::Stopping;
        self.push_event(EventKind::StateChanged, None, None);
        self.state = ClientState::Stopped;
        self.push_event(EventKind::StateChanged, None, None);
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    pub fn stats(&self) -> CoreStats {
        CoreStats {
            state: self.state,
            tx_packets: self.tx_packets,
            tx_bytes: self.tx_bytes,
            rx_packets: self.rx_packets,
            rx_bytes: self.rx_bytes,
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

    fn require_event_slots(&self, count: usize) -> Result<(), CoreError> {
        if self.events.len().saturating_add(count) > self.event_capacity {
            Err(CoreError::EventQueueFull)
        } else {
            Ok(())
        }
    }

    fn push_event(&mut self, kind: EventKind, plan: Option<NetworkPlan>, fault: Option<CoreFault>) {
        debug_assert!(self.events.len() < self.event_capacity);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.events.push_back(ClientEvent {
            sequence,
            kind,
            state: self.state,
            plan,
            fault,
        });
    }
}

fn parse_config(config_text: &str) -> Result<ClientConfig, CoreError> {
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
            routes: vec![NetworkRoute {
                cidr: "0.0.0.0/0".into(),
                gateway: "10.10.0.1".into(),
                metric: 100,
            }],
            dns_servers: vec![NetworkDns {
                address: "1.1.1.1".into(),
                port: 53,
            }],
            full_tunnel: true,
            kill_switch: true,
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
}
