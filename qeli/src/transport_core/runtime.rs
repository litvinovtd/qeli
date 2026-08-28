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
use super::{ClientCore, ClientState, NetworkPlan, RuntimeCounters};
use crate::client::{
    run_tcp_tunnel, run_udp_tunnel, ClientPlatform, IdentityVerifier, StreamConnectRequest,
    StreamConnector, TunnelSetup,
};
#[cfg(feature = "experimental-roaming")]
use crate::client::{CorePathController, PathAckFuture, PathController};
use crate::config::client::ClientConfig;
use crate::protocol::obfs::{AwgParams, ObfsStream};
use crate::transport_core::network::HandshakeNetwork;
use serde::Deserialize;
use socket2::Socket;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const PLATFORM_ACK_POLL: Duration = Duration::from_millis(20);
const NETWORK_ACK_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_SUPPLIED_CARRIER_ADDRESSES: usize = 1024;
const MAX_CARRIER_ADDRESSES_PER_FAMILY: usize = 32;

async fn wait_for_runtime_cancel(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(PLATFORM_ACK_POLL).await;
    }
}

fn candidate_connect_budget(deadline: Instant, candidates_left: usize) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let share = remaining / u32::try_from(candidates_left.max(1)).unwrap_or(u32::MAX);
    Some(share.max(Duration::from_millis(250)).min(remaining))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeInput {
    #[serde(default)]
    fallback_dns_servers: Vec<String>,
    /// Ordered A/AAAA records resolved by the platform on its physical network. Supplying
    /// these prevents reconnect DNS from entering a retained/dead TUN and lets TCP try every
    /// carrier address.
    #[serde(default)]
    carrier_addresses: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct NativeCoreAdapter {
    core: Arc<Mutex<ClientCore>>,
    cancel: Arc<AtomicBool>,
    counters: Arc<RuntimeCounters>,
    fallback_dns_servers: Arc<Vec<String>>,
    carrier_addresses: Arc<Mutex<Vec<IpAddr>>>,
    carrier_address: Arc<Mutex<Option<IpAddr>>>,
    #[cfg(feature = "experimental-roaming")]
    path_controller: CorePathController,
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
        let connected = self.connect_primary(config).await?;
        self.note_carrier(&connected);
        Ok(connected)
    }

    async fn carrier_candidates(&self, config: &ClientConfig) -> anyhow::Result<Vec<SocketAddr>> {
        let supplied = self
            .carrier_addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        carrier::resolve_ip_candidates(
            &config.server.address,
            config.server.port,
            supplied.as_slice(),
        )
        .await
    }

    /// Try every A/AAAA record for TCP under one connection deadline. UDP connect cannot prove
    /// reachability, so it uses the first address; platform adapters rotate that ordering on
    /// each reconnect generation.
    async fn connect_primary(&self, config: &ClientConfig) -> anyhow::Result<ConnectedCarrier> {
        let addresses = self.carrier_candidates(config).await?;
        let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
        let deadline = Instant::now() + timeout;
        let mut failures = Vec::new();
        let candidate_count = addresses.len();
        for (index, address) in addresses.into_iter().enumerate() {
            let socket = match carrier::open_for(config, address.ip()) {
                Ok(socket) => socket,
                Err(error) => {
                    // A platform may supply both A and AAAA records while `local` pins one
                    // family. Treat the incompatible candidate like any other dial failure;
                    // aborting here would skip a usable address later in the same DNS set.
                    failures.push(format!("{address}: socket setup failed: {error}"));
                    continue;
                }
            };
            self.protect_socket(&socket).await?;
            let candidates_left = if config.server.protocol == "udp" {
                1
            } else {
                candidate_count.saturating_sub(index)
            };
            let Some(candidate_budget) = candidate_connect_budget(deadline, candidates_left) else {
                break;
            };
            match carrier::connect_to(socket, config, address, candidate_budget).await {
                Ok(connected) => return Ok(connected),
                Err(error) => failures.push(format!("{address}: {error}")),
            }
            if config.server.protocol == "udp" {
                break;
            }
        }
        anyhow::bail!("all carrier candidates failed: {}", failures.join("; "))
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

    async fn dial_tcp(
        &self,
        config: &ClientConfig,
        request: StreamConnectRequest,
    ) -> anyhow::Result<TcpStream> {
        #[cfg(feature = "experimental-roaming")]
        if let Some(candidate) = request.path_candidate.as_ref() {
            return self.dial_candidate_tcp(config, candidate).await;
        }
        #[cfg(not(feature = "experimental-roaming"))]
        let _ = request;
        let addresses = self.carrier_candidates(config).await?;
        let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
        let deadline = Instant::now() + timeout;
        let mut failures = Vec::new();
        let candidate_count = addresses.len();
        for (index, address) in addresses.into_iter().enumerate() {
            let socket = match carrier::open_secondary_for(config, address.ip()) {
                Ok(socket) => socket,
                Err(error) => {
                    failures.push(format!("{address}: socket setup failed: {error}"));
                    continue;
                }
            };
            self.protect_socket(&socket).await?;
            let Some(candidate_budget) =
                candidate_connect_budget(deadline, candidate_count.saturating_sub(index))
            else {
                break;
            };
            match carrier::connect_to(socket, config, address, candidate_budget).await {
                Ok(ConnectedCarrier::Tcp(stream)) => {
                    configure_tcp(&stream, config)?;
                    return Ok(stream);
                }
                Ok(ConnectedCarrier::Udp(_)) => anyhow::bail!("TCP dialer received a UDP carrier"),
                Err(error) => failures.push(format!("{address}: {error}")),
            }
        }
        anyhow::bail!(
            "all bonded TCP carrier candidates failed: {}",
            failures.join("; ")
        )
    }

    #[cfg(feature = "experimental-roaming")]
    async fn dial_candidate_tcp(
        &self,
        config: &ClientConfig,
        candidate: &super::path::PreparedPathCandidate,
    ) -> anyhow::Result<TcpStream> {
        let addresses = candidate
            .update
            .compatible_resolved_addresses()
            .into_iter()
            .map(|address| SocketAddr::new(address, config.server.port))
            .collect::<Vec<_>>();
        let mut setup_failures = Vec::new();
        let (address, socket) = addresses
            .into_iter()
            .find_map(
                |address| match carrier::open_candidate_for(config, address.ip()) {
                    Ok(socket) => Some((address, socket)),
                    Err(error) => {
                        setup_failures.push(format!("{address}: {error}"));
                        None
                    }
                },
            )
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no candidate socket could be created: {}",
                    setup_failures.join("; ")
                )
            })?;
        let socket_fd = candidate_socket_descriptor(&socket)?;
        let binding = self.bind_candidate_socket(candidate, socket_fd)?;
        tokio::time::timeout(NETWORK_ACK_TIMEOUT, binding)
            .await
            .map_err(|_| anyhow::anyhow!("BIND_SOCKET acknowledgement timed out"))??;

        let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
        match carrier::connect_to(socket, config, address, timeout).await {
            Ok(ConnectedCarrier::Tcp(stream)) => {
                configure_tcp(&stream, config)?;
                Ok(stream)
            }
            Ok(ConnectedCarrier::Udp(_)) => anyhow::bail!("TCP candidate dialer received UDP"),
            Err(error) => Err(anyhow::anyhow!(
                "candidate path {} connect to {address} failed: {error}",
                candidate.update.platform_path_id
            )),
        }
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

#[cfg(feature = "experimental-roaming")]
fn candidate_socket_descriptor(socket: &Socket) -> anyhow::Result<i32> {
    #[cfg(unix)]
    {
        Ok(socket.as_raw_fd())
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        anyhow::bail!("candidate socket binding requires an ABI-safe Unix descriptor")
    }
}

#[cfg(feature = "experimental-roaming")]
impl PathController for NativeCoreAdapter {
    fn prepared_candidate(&self) -> Option<super::path::PreparedPathCandidate> {
        let required = super::platform_capability::ROAMING_PATH;
        (self.platform_capabilities() & required == required)
            .then(|| self.path_controller.prepared_candidate())
            .flatten()
    }

    fn bind_candidate_socket(
        &self,
        candidate: &super::path::PreparedPathCandidate,
        socket_fd: i32,
    ) -> anyhow::Result<PathAckFuture> {
        self.path_controller
            .bind_candidate_socket(candidate, socket_fd)
    }

    fn commit_candidate_path(
        &self,
        candidate: &super::path::PreparedPathCandidate,
    ) -> anyhow::Result<PathAckFuture> {
        let commit = self.path_controller.commit_candidate_path(candidate)?;
        let addresses = candidate
            .update
            .resolved_addresses
            .iter()
            .filter_map(|entry| entry.address.parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        let active_addresses = self.carrier_addresses.clone();
        Ok(Box::pin(async move {
            commit.await?;
            *active_addresses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = addresses;
            Ok(())
        }))
    }

    fn abort_candidate_path(
        &self,
        candidate: &super::path::PreparedPathCandidate,
        reason: &str,
    ) -> anyhow::Result<PathAckFuture> {
        self.path_controller.abort_candidate_path(candidate, reason)
    }
}

impl ClientPlatform for NativeCoreAdapter {
    fn next_generation(&mut self) -> u64 {
        self.lock().last_plan_generation.saturating_add(1)
    }

    fn platform_capabilities(&self) -> u64 {
        self.lock().platform_capabilities()
    }

    #[cfg(feature = "experimental-roaming")]
    fn path_controller(&self) -> Option<Arc<dyn PathController>> {
        let required = super::platform_capability::ROAMING_PATH;
        if self.platform_capabilities() & required == required {
            Some(Arc::new(self.clone()))
        } else {
            None
        }
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
                        #[cfg(target_os = "windows")]
                        {
                            if core.platform_capabilities() & super::platform_capability::TUN_WINTUN
                                != 0
                            {
                                Some(
                                    core.take_attached_wintun(generation)
                                        .map(TunnelSetup::wintun)
                                        .map_err(anyhow::Error::from),
                                )
                            } else if core.platform_capabilities()
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
                        #[cfg(target_os = "ios")]
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
                                    "platform advertised no usable packet TUN"
                                )))
                            }
                        }
                        #[cfg(any(target_os = "android", target_os = "macos"))]
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

    fn fallback_dns_servers(&self) -> &[String] {
        self.fallback_dns_servers.as_slice()
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
    let supplied_carrier_count = input.carrier_addresses.len();
    let carrier_addresses = normalize_carrier_addresses(&input.carrier_addresses);
    if carrier_addresses.len() < supplied_carrier_count {
        log::warn!(
            "platform supplied {supplied_carrier_count} carrier addresses; using {} unique \
             candidates after canonicalisation and the per-family limit",
            carrier_addresses.len()
        );
    }
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
        carrier_addresses: Arc::new(Mutex::new(carrier_addresses)),
        carrier_address: Arc::new(Mutex::new(None)),
        #[cfg(feature = "experimental-roaming")]
        path_controller: CorePathController::new(core.clone()),
    };
    // `qeli_client_stop` is the ownership boundary used by every GUI adapter. It must cancel
    // every phase, not only the established data loop: carrier DNS/connect and TLS/qeli
    // handshakes can otherwise retain their socket (and, after NetworkPlan ACK, the Android
    // TUN) until the full connection timeout expires. Dropping the attempt closes pre-tunnel
    // sockets immediately; established tunnel pumps also observe the same token and their
    // Drop implementation synchronously joins descriptor-owning workers.
    let result = tokio::select! {
        biased;
        _ = wait_for_runtime_cancel(cancel.clone()) => Ok(()),
        result = run_attempt(&mut adapter, &config) => result,
    };
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
        ConnectedCarrier::Udp(socket) => run_udp_tunnel(socket, config, password, adapter).await,
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
            let connector: StreamConnector<_> = Arc::new(move |request| {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move {
                    let stream = dialer.dial_tcp(&cfg, request).await?;
                    wrap_obfs(stream, &cfg).await
                })
            });
            run_tcp_tunnel(first, connector, config, password, adapter).await
        }
        "reality-tls" => {
            let first = wrap_reality(stream, config).await?;
            let dialer = adapter.clone();
            let cfg = Arc::new(config.clone());
            let connector: StreamConnector<_> = Arc::new(move |request| {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move {
                    let stream = dialer.dial_tcp(&cfg, request).await?;
                    wrap_reality(stream, &cfg).await
                })
            });
            run_tcp_tunnel(first, connector, config, password, adapter).await
        }
        "fake-tls" | "plain" => {
            let dialer = adapter.clone();
            let cfg = Arc::new(config.clone());
            let connector: StreamConnector<_> = Arc::new(move |request| {
                let dialer = dialer.clone();
                let cfg = cfg.clone();
                Box::pin(async move { dialer.dial_tcp(&cfg, request).await })
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
    let host = config.effective_fronting_host();
    ObfsStream::connect_with_host(
        stream,
        &key,
        config.obfuscation.fronting == "websocket",
        awg,
        Some(&host),
    )
    .await
    .map_err(anyhow::Error::from)
}

async fn wrap_reality(
    mut stream: TcpStream,
    config: &ClientConfig,
) -> anyhow::Result<tokio::io::DuplexStream> {
    let server_name = config.effective_reality_sni().to_string();
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
    let tls = crate::protocol::realtls::stream::RealTlsStream::new(stream, established);
    tokio::time::timeout(
        timeout,
        crate::protocol::h2_carrier::connect(tls, &server_name),
    )
    .await
    .map_err(|_| anyhow::anyhow!("reality-tls HTTP/2 carrier timed out"))?
    .map_err(|error| anyhow::anyhow!("reality-tls HTTP/2 carrier failed: {error}"))
}

fn configure_tcp(stream: &TcpStream, config: &ClientConfig) -> anyhow::Result<()> {
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    let socket = socket2::SockRef::from(stream);
    // Keep TCP autotuning intact. The buffer keys are UDP policy: unlike TCP, a datagram
    // socket has no receive-window autotuner, so pinning the shared 4 MiB default here could
    // cap a fast TCP carrier and changed the pre-refactor desktop/CLI behaviour.
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

fn validate_input(input: &RuntimeInput) -> anyhow::Result<()> {
    if input.fallback_dns_servers.len() > 8 {
        anyhow::bail!("at most 8 fallback DNS servers are accepted");
    }
    for server in &input.fallback_dns_servers {
        server
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid fallback DNS server '{server}'"))?;
    }
    if input.carrier_addresses.len() > MAX_SUPPLIED_CARRIER_ADDRESSES {
        anyhow::bail!(
            "at most {MAX_SUPPLIED_CARRIER_ADDRESSES} supplied carrier addresses are accepted"
        );
    }
    for address in &input.carrier_addresses {
        address
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid carrier IP address '{address}'"))?;
    }
    Ok(())
}

fn normalize_carrier_addresses(addresses: &[String]) -> Vec<IpAddr> {
    let mut output = Vec::new();
    let mut ipv4_count = 0usize;
    let mut ipv6_count = 0usize;
    for raw in addresses {
        let Ok(address) = raw.parse::<IpAddr>() else {
            // `validate_input` owns the diagnostic. Keep this helper total so its output can
            // never accidentally re-introduce an unvalidated string at the socket boundary.
            continue;
        };
        let address = carrier::canonical_carrier_ip(address);
        if output.contains(&address) {
            continue;
        }
        let accepted = match address {
            IpAddr::V4(_) if ipv4_count < MAX_CARRIER_ADDRESSES_PER_FAMILY => {
                ipv4_count += 1;
                true
            }
            IpAddr::V6(_) if ipv6_count < MAX_CARRIER_ADDRESSES_PER_FAMILY => {
                ipv6_count += 1;
                true
            }
            _ => false,
        };
        if accepted {
            output.push(address);
        }
    }
    output
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
    let udp = counters.udp.snapshot();
    core.udp_kernel_drops = core.udp_kernel_drops.saturating_add(udp.kernel_drops);
    core.udp_internal_drops = core.udp_internal_drops.saturating_add(udp.internal_drops);
    core.udp_buffer_grows = core.udp_buffer_grows.saturating_add(udp.grow_events);
    core.udp_recv_buffer_bytes = udp.granted_recv_bytes;
    core.runtime_counters = None;
    core.runtime_active = false;

    if cancelled || matches!(core.state, ClientState::Stopping | ClientState::Stopped) {
        return;
    }
    let message: String = error
        .map(ToString::to_string)
        .unwrap_or_else(|| "transport disconnected".into())
        .chars()
        .take(512)
        .collect();
    core.publish_runtime_failure(message);
}

fn lock_core(shared: &Arc<Mutex<ClientCore>>) -> MutexGuard<'_, ClientCore> {
    match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_dns_can_supply_more_than_sixteen_dual_stack_addresses() {
        let mut carrier_addresses: Vec<String> =
            (1..=40).map(|host| format!("192.0.2.{host}")).collect();
        carrier_addresses.extend(["2001:db8::1".into(), "2001:db8::2".into()]);
        let input = RuntimeInput {
            fallback_dns_servers: Vec::new(),
            carrier_addresses,
        };

        validate_input(&input).unwrap();
        let normalized = normalize_carrier_addresses(&input.carrier_addresses);
        assert_eq!(normalized.len(), 34);
        assert_eq!(
            normalized
                .iter()
                .filter(|address| address.is_ipv4())
                .count(),
            MAX_CARRIER_ADDRESSES_PER_FAMILY
        );
        assert_eq!(
            normalized
                .iter()
                .filter(|address| address.is_ipv6())
                .count(),
            2
        );
    }

    #[test]
    fn mapped_carrier_addresses_are_canonicalised_and_deduplicated() {
        let addresses = vec!["192.0.2.1".into(), "::ffff:192.0.2.1".into()];
        assert_eq!(
            normalize_carrier_addresses(&addresses),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }
}
