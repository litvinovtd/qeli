//! Blocking external-client entry point for the shared Rust transport.
//!
//! Android JNI and the desktop C ABI call this on an IO worker; the core mutex is held only
//! for short lifecycle transitions. The platform concurrently drains protect/trust/NetworkPlan
//! events, while this owner performs every handshake and moves every payload byte.

#![cfg(all(
    any(
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios"
    ),
    feature = "transport-core-ffi"
))]

use super::carrier::{self, ConnectedCarrier};
use super::{
    ClientCore, ClientState, CoreFault, ErrorCode, EventKind, NetworkDns, NetworkPlan,
    RuntimeCounters,
};
use crate::client::{
    run_tcp_tunnel, run_udp_tunnel, ClientPlatform, IdentityVerifier, StreamConnector, TunnelSetup,
};
use crate::config::client::ClientConfig;
use crate::protocol::obfs::{AwgParams, ObfsStream};
use crate::transport_core::network::HandshakeNetwork;
use serde::Deserialize;
use socket2::Socket;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};

const PLATFORM_ACK_POLL: Duration = Duration::from_millis(20);
const NETWORK_ACK_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeInput {
    #[serde(default)]
    fallback_dns_servers: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct NativeCoreAdapter {
    core: Arc<Mutex<ClientCore>>,
    cancel: Arc<AtomicBool>,
    counters: Arc<RuntimeCounters>,
    fallback_dns_servers: Arc<Vec<String>>,
    carrier_address: Arc<Mutex<Option<IpAddr>>>,
}

impl NativeCoreAdapter {
    fn lock(&self) -> MutexGuard<'_, ClientCore> {
        match self.core.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    async fn wait_for_initial_carrier(
        &self,
        config: &ClientConfig,
    ) -> anyhow::Result<ConnectedCarrier> {
        let needs_protect =
            self.lock().platform_capabilities() & super::platform_capability::SOCKET_PROTECT != 0;
        if !needs_protect {
            let connected = carrier::connect(carrier::open(config)?, config).await?;
            self.note_carrier(&connected);
            return Ok(connected);
        }

        #[cfg(not(unix))]
        anyhow::bail!("socket protection requires a Unix descriptor");

        #[cfg(unix)]
        {
            let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
            let deadline = Instant::now() + timeout;
            loop {
                if self.cancel.load(Ordering::Acquire) {
                    anyhow::bail!("transport cancelled while waiting for socket protection");
                }
                let socket = {
                    let mut core = self.lock();
                    match core.state {
                        ClientState::Connecting => core
                            .protected_wire_socket
                            .take()
                            .map(|protected| protected._socket),
                        ClientState::Failed => {
                            anyhow::bail!("platform rejected the initial carrier socket")
                        }
                        state => {
                            anyhow::bail!("initial carrier is unavailable in core state {state:?}")
                        }
                    }
                };
                if let Some(socket) = socket {
                    let connected = carrier::connect(socket, config).await?;
                    self.note_carrier(&connected);
                    return Ok(connected);
                }
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "platform did not protect the initial carrier within {timeout:?}"
                    );
                }
                tokio::time::sleep(PLATFORM_ACK_POLL).await;
            }
        }
    }

    async fn protect_socket(&self, _socket: &Socket) -> anyhow::Result<()> {
        if self.lock().platform_capabilities() & super::platform_capability::SOCKET_PROTECT == 0 {
            return Ok(());
        }
        #[cfg(not(unix))]
        anyhow::bail!("socket protection requires a Unix descriptor");
        #[cfg(unix)]
        {
            let mut result = {
                let mut core = self.lock();
                let (_, result) = core.request_socket_protect(_socket.as_raw_fd())?;
                result
            };
            loop {
                tokio::select! {
                    result = &mut result => {
                        return match result {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(reason)) => Err(anyhow::anyhow!(reason)),
                            Err(_) => Err(anyhow::anyhow!("socket-protect request was cancelled")),
                        };
                    }
                    _ = tokio::time::sleep(PLATFORM_ACK_POLL) => {
                        if self.cancel.load(Ordering::Acquire) {
                            anyhow::bail!("transport cancelled while protecting a bonded socket");
                        }
                    }
                }
            }
        }
    }

    async fn dial_tcp(&self, config: &ClientConfig) -> anyhow::Result<TcpStream> {
        let socket = carrier::open(config)?;
        self.protect_socket(&socket).await?;
        let ConnectedCarrier::Tcp(stream) = carrier::connect(socket, config).await? else {
            anyhow::bail!("TCP dialer received a UDP carrier")
        };
        configure_tcp(&stream, config)?;
        Ok(stream)
    }

    fn note_carrier(&self, carrier: &ConnectedCarrier) {
        let peer = match carrier {
            ConnectedCarrier::Tcp(stream) => stream.peer_addr().ok(),
            ConnectedCarrier::Udp(socket) => socket.peer_addr().ok(),
        }
        .map(|address| address.ip());
        if let Some(peer) = peer {
            *self
                .carrier_address
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(peer);
        }
    }
}

impl ClientPlatform for NativeCoreAdapter {
    fn next_generation(&mut self) -> u64 {
        self.lock().last_plan_generation.saturating_add(1)
    }

    fn device_id(&self) -> anyhow::Result<[u8; crate::protocol::DEVICE_ID_LEN]> {
        self.lock()
            .device_id
            .ok_or_else(|| anyhow::anyhow!("platform device id was not supplied before start"))
    }

    fn identity_verifier(&self, _config: &ClientConfig) -> IdentityVerifier {
        let adapter = self.clone();
        Arc::new(move |public_key| {
            let adapter = adapter.clone();
            Box::pin(async move {
                let mut result = {
                    let mut core = adapter.lock();
                    let (_, result) = core.request_server_identity(public_key)?;
                    result
                };
                loop {
                    tokio::select! {
                        result = &mut result => {
                            return match result {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(reason)) => Err(anyhow::anyhow!(reason)),
                                Err(_) => Err(anyhow::anyhow!("server-identity request was cancelled")),
                            };
                        }
                        _ = tokio::time::sleep(PLATFORM_ACK_POLL) => {
                            if adapter.cancel.load(Ordering::Acquire) {
                                anyhow::bail!("transport cancelled while awaiting server trust");
                            }
                        }
                    }
                }
            })
        })
    }

    fn prepare_tunnel(
        &mut self,
        _config: &ClientConfig,
        mut plan: NetworkPlan,
        _network: &HandshakeNetwork<'_>,
    ) -> anyhow::Result<TunnelSetup> {
        let carrier_address = *self
            .carrier_address
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        plan.carrier_address = carrier_address.map(|address| address.to_string());
        if plan.dns_servers.is_empty() {
            plan.dns_servers.extend(
                self.fallback_dns_servers
                    .iter()
                    .cloned()
                    .map(|address| NetworkDns { address, port: 53 }),
            );
        }
        let generation = plan.generation;
        self.lock().publish_network_plan(plan)?;

        let deadline = Instant::now() + NETWORK_ACK_TIMEOUT;
        loop {
            if self.cancel.load(Ordering::Acquire) {
                anyhow::bail!("transport cancelled while awaiting NetworkPlan ACK");
            }
            let result: Option<anyhow::Result<TunnelSetup>> = {
                let mut core = self.lock();
                match core.state {
                    ClientState::Running => {
                        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "ios"))]
                        {
                            if core.platform_capabilities()
                                & super::platform_capability::TUN_PACKET_BATCH
                                != 0
                            {
                                Some(
                                    core.take_packet_tun_pump(generation)
                                        .map(TunnelSetup::packet)
                                        .map_err(anyhow::Error::from),
                                )
                            } else {
                                Some(Err(anyhow::anyhow!(
                                    "platform advertised neither packet IO nor a usable TUN fd"
                                )))
                            }
                        }
                        #[cfg(target_os = "android")]
                        {
                            Some(
                                core.take_attached_tun_fds(generation)
                                    .map(|(reader, writer)| TunnelSetup::external(reader, writer))
                                    .map_err(anyhow::Error::from),
                            )
                        }
                    }
                    ClientState::Failed => Some(Err(anyhow::anyhow!(
                        "platform rejected NetworkPlan {generation}"
                    ))),
                    ClientState::AwaitingNetwork => None,
                    state => Some(Err(anyhow::anyhow!(
                        "NetworkPlan {generation} left pending in state {state:?}"
                    ))),
                }
            };
            if let Some(result) = result {
                return result;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("platform did not acknowledge NetworkPlan {generation} within 45s");
            }
            std::thread::sleep(PLATFORM_ACK_POLL);
        }
    }

    fn cancel_token(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    fn counters(&self) -> Arc<RuntimeCounters> {
        self.counters.clone()
    }
}

pub(crate) fn run(core: Arc<Mutex<ClientCore>>, input: RuntimeInput) -> anyhow::Result<()> {
    validate_input(&input)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("qeli-transport")
        .build()?;
    runtime.block_on(run_async(core, input))
}

async fn run_async(core: Arc<Mutex<ClientCore>>, input: RuntimeInput) -> anyhow::Result<()> {
    let (config, cancel, counters) = {
        let mut guard = lock_core(&core);
        if guard.state != ClientState::Connecting {
            anyhow::bail!(
                "native transport requires Connecting state, got {:?}",
                guard.state
            );
        }
        if guard.runtime_active {
            anyhow::bail!("a native transport runner is already active");
        }
        if guard.device_id.is_none() {
            anyhow::bail!("device id must be set before running transport");
        }
        let cancel = guard.runtime_cancel.clone();
        let counters = Arc::new(RuntimeCounters::default());
        guard.runtime_counters = Some(counters.clone());
        guard.runtime_active = true;
        (guard.config.clone(), cancel, counters)
    };

    let mut adapter = NativeCoreAdapter {
        core: core.clone(),
        cancel: cancel.clone(),
        counters: counters.clone(),
        fallback_dns_servers: Arc::new(input.fallback_dns_servers),
        carrier_address: Arc::new(Mutex::new(None)),
    };
    let result = run_attempt(&mut adapter, &config).await;
    let cancelled = cancel.load(Ordering::Acquire);
    finish_generation(&core, &counters, cancelled, result.as_ref().err());
    if cancelled {
        Ok(())
    } else {
        result.and_then(|()| Err(anyhow::anyhow!("transport disconnected")))
    }
}

async fn run_attempt(adapter: &mut NativeCoreAdapter, config: &ClientConfig) -> anyhow::Result<()> {
    let password = config
        .auth
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| anyhow::anyhow!("native runtime requires an inline password"))?;
    let initial = adapter.wait_for_initial_carrier(config).await?;
    match initial {
        ConnectedCarrier::Tcp(stream) => run_tcp(adapter, stream, config, password).await,
        ConnectedCarrier::Udp(socket) => {
            configure_udp(&socket, config)?;
            run_udp_tunnel(socket, config, password, adapter).await
        }
    }
}

async fn run_tcp(
    adapter: &mut NativeCoreAdapter,
    stream: TcpStream,
    config: &ClientConfig,
    password: &str,
) -> anyhow::Result<()> {
    configure_tcp(&stream, config)?;
    match config.obfuscation.mode.as_str() {
        "obfs" => {
            if config.obfuscation.obfs_key.trim().is_empty() {
                anyhow::bail!("obfs wire mode requires a non-empty obfuscation.obfs_key");
            }
            let first = wrap_obfs(stream, config).await?;
            let dialer = adapter.clone();
            let cfg = Arc::new(config.clone());
            let connector: StreamConnector<_> = Arc::new(move || {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move {
                    let stream = dialer.dial_tcp(&cfg).await?;
                    wrap_obfs(stream, &cfg).await
                })
            });
            run_tcp_tunnel(first, connector, config, password, adapter).await
        }
        "reality-tls" => {
            let first = wrap_reality(stream, config).await?;
            let dialer = adapter.clone();
            let cfg = Arc::new(config.clone());
            let connector: StreamConnector<_> = Arc::new(move || {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move {
                    let stream = dialer.dial_tcp(&cfg).await?;
                    wrap_reality(stream, &cfg).await
                })
            });
            run_tcp_tunnel(first, connector, config, password, adapter).await
        }
        "fake-tls" | "plain" => {
            let dialer = adapter.clone();
            let cfg = Arc::new(config.clone());
            let connector: StreamConnector<_> = Arc::new(move || {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move { dialer.dial_tcp(&cfg).await })
            });
            run_tcp_tunnel(stream, connector, config, password, adapter).await
        }
        mode => anyhow::bail!("unsupported TCP wire mode '{mode}'"),
    }
}

async fn wrap_obfs(
    stream: TcpStream,
    config: &ClientConfig,
) -> anyhow::Result<ObfsStream<TcpStream>> {
    let key = crate::protocol::obfs::derive_obfs_key(&config.obfuscation.obfs_key);
    let awg = AwgParams {
        enabled: config.obfuscation.awg.enabled,
        jc: config.obfuscation.awg.jc,
        jmin: config.obfuscation.awg.jmin,
        jmax: config.obfuscation.awg.jmax,
    };
    let host = match config.obfuscation.sni.as_deref() {
        Some(value) if !value.is_empty() => Some(value),
        _ if config.server.address.parse::<IpAddr>().is_ok() => None,
        _ => Some(config.server.address.as_str()),
    };
    ObfsStream::connect_with_host(
        stream,
        &key,
        config.obfuscation.fronting == "websocket",
        awg,
        host,
    )
    .await
    .map_err(anyhow::Error::from)
}

async fn wrap_reality(
    mut stream: TcpStream,
    config: &ClientConfig,
) -> anyhow::Result<crate::protocol::realtls::stream::RealTlsStream<TcpStream>> {
    let server_name = match config.obfuscation.sni.as_deref() {
        Some(value) if !value.is_empty() => value.to_string(),
        _ if config.server.address.parse::<IpAddr>().is_ok() => {
            crate::protocol::pick_random_sni().to_string()
        }
        _ => config.server.address.clone(),
    };
    let ephemeral = crate::crypto::Keypair::generate();
    let short_id = config
        .obfuscation
        .reality_short_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("reality-tls requires reality_short_id"))?;
    let public_key = config
        .auth
        .server_public_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .and_then(crate::crypto::parse_pubkey_hex)
        .ok_or_else(|| anyhow::anyhow!("reality-tls requires a pinned server_public_key"))?;
    let public_key = crate::crypto::PublicKey::from_bytes(&public_key);
    let short_id = crate::crypto::reality::short_id_from_hex(short_id);
    let session_id = crate::crypto::reality::seal_session_id(&public_key, &ephemeral, &short_id);
    let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let established = tokio::time::timeout(
        timeout,
        crate::protocol::realtls::client::client_handshake(
            &mut stream,
            ephemeral,
            session_id,
            &server_name,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("reality-tls handshake timed out"))??;
    Ok(crate::protocol::realtls::stream::RealTlsStream::new(
        stream,
        established,
    ))
}

fn configure_tcp(stream: &TcpStream, config: &ClientConfig) -> anyhow::Result<()> {
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    let socket = socket2::SockRef::from(stream);
    set_socket_buffers(
        &socket,
        config.performance.send_buffer_size,
        config.performance.recv_buffer_size,
    )?;
    let seconds = config.server.tcp_keepalive_secs;
    if seconds > 0 {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(seconds))
            .with_interval(Duration::from_secs((seconds / 3).max(10)))
            .with_retries(3);
        socket.set_tcp_keepalive(&keepalive)?;
    }
    Ok(())
}

fn configure_udp(socket: &UdpSocket, config: &ClientConfig) -> anyhow::Result<()> {
    let socket = socket2::SockRef::from(socket);
    set_socket_buffers(
        &socket,
        config.performance.send_buffer_size,
        config.performance.recv_buffer_size,
    )
}

fn set_socket_buffers(
    socket: &socket2::SockRef<'_>,
    send: u32,
    receive: u32,
) -> anyhow::Result<()> {
    if send > 0 {
        socket.set_send_buffer_size(send as usize)?;
    }
    if receive > 0 {
        socket.set_recv_buffer_size(receive as usize)?;
    }
    Ok(())
}

fn validate_input(input: &RuntimeInput) -> anyhow::Result<()> {
    if input.fallback_dns_servers.len() > 8 {
        anyhow::bail!("at most 8 fallback DNS servers are accepted");
    }
    for server in &input.fallback_dns_servers {
        server
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid fallback DNS server '{server}'"))?;
    }
    Ok(())
}

fn finish_generation(
    shared: &Arc<Mutex<ClientCore>>,
    counters: &Arc<RuntimeCounters>,
    cancelled: bool,
    error: Option<&anyhow::Error>,
) {
    let mut core = lock_core(shared);
    if !core
        .runtime_counters
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, counters))
    {
        return;
    }
    core.tx_packets = core
        .tx_packets
        .saturating_add(counters.tx_packets.load(portable_atomic::Ordering::Relaxed));
    core.tx_bytes = core
        .tx_bytes
        .saturating_add(counters.tx_bytes.load(portable_atomic::Ordering::Relaxed));
    core.rx_packets = core
        .rx_packets
        .saturating_add(counters.rx_packets.load(portable_atomic::Ordering::Relaxed));
    core.rx_bytes = core
        .rx_bytes
        .saturating_add(counters.rx_bytes.load(portable_atomic::Ordering::Relaxed));
    core.runtime_counters = None;
    core.runtime_active = false;

    if cancelled || matches!(core.state, ClientState::Stopping | ClientState::Stopped) {
        return;
    }
    core.state = ClientState::Failed;
    if core.events.len().saturating_add(2) <= core.event_capacity {
        let message: String = error
            .map(ToString::to_string)
            .unwrap_or_else(|| "transport disconnected".into())
            .chars()
            .take(512)
            .collect();
        core.push_event(
            EventKind::Error,
            None,
            None,
            None,
            Some(CoreFault {
                code: ErrorCode::PlatformRejected,
                message,
            }),
        );
        core.push_event(EventKind::StateChanged, None, None, None, None);
    }
}

fn lock_core(shared: &Arc<Mutex<ClientCore>>) -> MutexGuard<'_, ClientCore> {
    match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
