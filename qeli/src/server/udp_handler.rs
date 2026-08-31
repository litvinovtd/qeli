use crate::config::QuicMaskingConfig;
use crate::crypto::{derive_data_frag_key, Keypair};
#[cfg(not(feature = "experimental-roaming"))]
use crate::crypto::{derive_keys_hybrid, derive_keys_hybrid_bound};
#[cfg(feature = "experimental-roaming")]
use crate::crypto::{derive_session_material_hybrid, derive_session_material_hybrid_bound};
use crate::protocol::{
    generate_connection_id, looks_like_quic_initial, unwrap_quic_payload, wrap_quic_long,
    wrap_quic_short, wrap_quic_short_into, Obfuscator, PacketCodec,
};
use crate::server::handler::{self, DEFAULT_HEARTBEAT_INTERVAL_MS};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState, ServerTunPacket, TunIngress};
use crate::transport_core::buffer_pool::{BufferPool, PooledBuffer};
use crate::transport_core::udp_buffer::{
    AggregateUdpBudgetPlan, InternalDrop, UdpBufferController, UdpBufferCounters, UdpBufferPolicy,
    AUTO_MAX_RECV_BYTES,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Semaphore};

/// Per-client queue for UDP upload pacing. Packets still come from the profile-wide
/// fixed buffer pool, so this bounds queue metadata and one limited client cannot
/// consume unbounded memory or block the shared socket receive loop.
const UDP_UPLOAD_QUEUE_PACKETS: usize = 256;

/// Upper bound on simultaneous half-open (unauthenticated, `AwaitingAuth`) UDP
/// handshakes per worker. A connectionless listener can't trust the source
/// address, so a spoofed-source flood would otherwise add one `AwaitingAuth`
/// entry per fake IP until the handshake-timeout reaper runs (memory DoS). When
/// the cap is hit, the OLDEST pending handshake is evicted to admit a new one;
/// authenticated sessions are never affected.
const MAX_PENDING_HANDSHAKES: usize = 1024;

/// Upper bound on CONCURRENT new-handshake crypto (Keypair::generate + ML-KEM
/// encapsulate + key derivation) per worker. The per-source-IP rate limiter is
/// bypassed by source spoofing on a connectionless listener, so without this a
/// spoofed flood drives one full PQ handshake per datagram → CPU exhaustion.
/// A datagram that can't grab a permit is DROPPED silently (not queued) so
/// pre-auth crypto/sec stays bounded regardless of source-IP diversity; the
/// client simply retransmits its ClientHello. Sized to a few per core.
fn max_concurrent_udp_handshakes() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    std::cmp::max(64, cores.saturating_mul(4))
}

#[cfg(feature = "experimental-roaming")]
struct UdpRoamingDatagram {
    datagram: crate::transport::udp::PooledUdpDatagram,
    /// Exact socket that received the candidate. A later path challenge must leave through
    /// this socket rather than whichever listener happens to own the session codec.
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
}

#[cfg(feature = "experimental-roaming")]
struct UdpRoamingEvent(crate::transport_core::udp_roaming::UdpRoutedIngress<UdpRoamingDatagram>);

#[cfg(not(feature = "experimental-roaming"))]
enum UdpRoamingEvent {}

#[cfg(feature = "experimental-roaming")]
pub(crate) struct UdpRoamingWorker {
    fabric: crate::transport_core::udp_roaming::UdpWorkerFabric<UdpRoamingDatagram>,
    mailbox: crate::transport_core::udp_roaming::UdpWorkerMailbox<UdpRoamingDatagram>,
}

#[cfg(not(feature = "experimental-roaming"))]
pub(crate) struct UdpRoamingWorker;

impl UdpRoamingWorker {
    #[cfg(feature = "experimental-roaming")]
    async fn recv(&mut self) -> anyhow::Result<UdpRoamingEvent> {
        self.mailbox
            .recv()
            .await
            .map(UdpRoamingEvent)
            .ok_or_else(|| anyhow::anyhow!("profile-wide UDP roaming mailbox closed"))
    }

    #[cfg(not(feature = "experimental-roaming"))]
    async fn recv(&mut self) -> anyhow::Result<UdpRoamingEvent> {
        std::future::pending().await
    }
}

/// Build one non-cloneable receive mailbox for every profile-wide UDP worker. The fabric shares
/// the exact registry populated during AUTH, so CID lookup and session cleanup cannot diverge.
pub(crate) fn build_udp_roaming_workers(
    profile: &Arc<ProfileRuntime>,
    worker_count: usize,
) -> anyhow::Result<Vec<UdpRoamingWorker>> {
    #[cfg(feature = "experimental-roaming")]
    {
        if worker_count == 0 {
            return Ok(Vec::new());
        }
        let (fabric, mailboxes) =
            crate::transport_core::udp_roaming::UdpWorkerFabric::with_registry(
                profile.udp_roaming_registry.clone(),
                worker_count,
                crate::transport::udp::UDP_RECEIVE_QUEUE_PACKETS,
            )
            .map_err(|error| anyhow::anyhow!("invalid UDP roaming worker topology: {error:?}"))?;
        Ok(mailboxes
            .into_iter()
            .map(|mailbox| UdpRoamingWorker {
                fabric: fabric.clone(),
                mailbox,
            })
            .collect())
    }
    #[cfg(not(feature = "experimental-roaming"))]
    {
        let _ = profile;
        Ok((0..worker_count).map(|_| UdpRoamingWorker).collect())
    }
}

/// The data writer must not permanently capture the source address and socket that authenticated
/// the session. A roaming commit replaces this value atomically while the PacketCodec, replay
/// window, rate buckets and TUN ownership remain untouched.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpEgressFraming {
    Unmasked,
    LegacyQuic([u8; 4]),
    #[cfg(feature = "experimental-roaming")]
    RoamingCid([u8; crate::protocol::roaming::CID_LEN]),
}

impl UdpEgressFraming {
    fn legacy(quic_enabled: bool, connection_id: [u8; 4]) -> Self {
        if quic_enabled {
            Self::LegacyQuic(connection_id)
        } else {
            Self::Unmasked
        }
    }

    fn uses_packet_number(self) -> bool {
        !matches!(self, Self::Unmasked)
    }

    fn wrapper_len(self) -> usize {
        match self {
            Self::Unmasked => 0,
            Self::LegacyQuic(_) => crate::protocol::quic::QUIC_SHORT_HEADER_MIN,
            #[cfg(feature = "experimental-roaming")]
            Self::RoamingCid(_) => crate::protocol::roaming::UDP_SHORT_HEADER_LEN,
        }
    }

    fn wrap_into<'a>(
        self,
        record: &'a [u8],
        packet_number: u32,
        output: &'a mut Vec<u8>,
    ) -> &'a [u8] {
        match self {
            Self::Unmasked => record,
            Self::LegacyQuic(connection_id) => {
                wrap_quic_short_into(record, &connection_id, packet_number, output);
                output
            }
            #[cfg(feature = "experimental-roaming")]
            Self::RoamingCid(destination_cid) => {
                crate::protocol::roaming::UdpShortHeader::new(destination_cid, packet_number)
                    .encode_into(record, output);
                output
            }
        }
    }
}

/// Copyable path metadata plus an `Arc` to the exact egress socket. Deliberately no `Debug`:
/// the framing contains the complete destination CID in roaming builds.
#[derive(Clone)]
struct UdpEgressSnapshot {
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
    peer: SocketAddr,
    framing: UdpEgressFraming,
    path_epoch: u64,
}

impl UdpEgressSnapshot {
    fn safe_payload_budget(&self) -> usize {
        crate::protocol::data_frag::conservative_udp_payload_budget(self.peer.is_ipv6())
    }

    fn record_budget(&self, udp_payload_budget: usize) -> Option<usize> {
        udp_payload_budget
            .checked_sub(self.wire_wrapper_len())
            .filter(|value| *value > crate::protocol::data_frag::HEADER_LEN)
    }

    fn wire_wrapper_len(&self) -> usize {
        self.socket.seal_overhead() + self.framing.wrapper_len()
    }

    fn empty_record_padding_cap(&self, codec: &PacketCodec) -> usize {
        let record_budget = self
            .record_budget(self.safe_payload_budget())
            .expect("conservative UDP budget fits the active path framing");
        codec
            .max_padding_for_record_budget(0, record_budget)
            .unwrap_or(0)
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpEgressCommitError {
    StaleEpoch,
    StalePeer,
    InvalidEpoch,
    FamilyMismatch,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
enum UdpEgressPublishError<E> {
    State(UdpEgressCommitError),
    Publish(E),
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpRoamingIngressPath {
    Committed,
    Candidate,
    Draining,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, PartialEq, Eq)]
enum UdpRoamingPmtuAction {
    NotProbe,
    Drop,
    Ack(Vec<u8>),
}

#[cfg(feature = "experimental-roaming")]
fn classify_udp_roaming_uplink_probe(
    payload: &[u8],
    ingress_path: UdpRoamingIngressPath,
) -> UdpRoamingPmtuAction {
    if !crate::protocol::udp_frag::is_fragment(payload) {
        return UdpRoamingPmtuAction::NotProbe;
    }
    match payload[3] {
        crate::protocol::udp_frag::MSG_MTU_PROBE_V2 => {
            if ingress_path != UdpRoamingIngressPath::Committed {
                return UdpRoamingPmtuAction::Drop;
            }
            crate::protocol::udp_frag::parse_mtu_probe_v2_request(payload)
                .map(|(token, size)| {
                    UdpRoamingPmtuAction::Ack(crate::protocol::udp_frag::mtu_probe_v2_ack_datagram(
                        token, size,
                    ))
                })
                .unwrap_or(UdpRoamingPmtuAction::Drop)
        }
        crate::protocol::udp_frag::MSG_MTU_PROBE => {
            if ingress_path != UdpRoamingIngressPath::Committed {
                return UdpRoamingPmtuAction::Drop;
            }
            crate::protocol::udp_frag::parse_mtu_probe_request(payload)
                .map(|(id, size)| {
                    UdpRoamingPmtuAction::Ack(crate::protocol::udp_frag::mtu_probe_ack_datagram(
                        id, size,
                    ))
                })
                .unwrap_or(UdpRoamingPmtuAction::Drop)
        }
        _ => UdpRoamingPmtuAction::NotProbe,
    }
}

#[cfg(feature = "experimental-roaming")]
struct UdpEgressCommit {
    expected_epoch: u64,
    expected_peer: SocketAddr,
    next_epoch: u64,
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
    peer: SocketAddr,
    destination_cid: [u8; crate::protocol::roaming::CID_LEN],
}

#[cfg(feature = "experimental-roaming")]
impl UdpEgressCommit {
    fn from_outcome(
        outcome: crate::transport_core::udp_roaming::CommitOutcome,
        socket: Arc<crate::protocol::obfs::ObfsUdp>,
    ) -> Result<Self, UdpEgressCommitError> {
        Ok(Self {
            expected_epoch: outcome
                .path_epoch()
                .checked_sub(1)
                .ok_or(UdpEgressCommitError::InvalidEpoch)?,
            expected_peer: outcome.old_path().peer(),
            next_epoch: outcome.path_epoch(),
            socket,
            peer: outcome.new_path().peer(),
            destination_cid: *outcome.transmit_cid(),
        })
    }
}

#[cfg(feature = "experimental-roaming")]
struct UdpDrainingIngress {
    snapshot: UdpEgressSnapshot,
    expires_at: std::time::Instant,
}

/// Single atomic publication point for server-to-client UDP traffic. Reads are short synchronous
/// snapshots; no socket send or codec operation happens while the lock is held.
#[derive(Clone)]
struct UdpActiveEgress(
    Arc<std::sync::RwLock<UdpEgressSnapshot>>,
    #[cfg(feature = "experimental-roaming")] Arc<std::sync::Mutex<Option<UdpDrainingIngress>>>,
    #[cfg(feature = "experimental-roaming")] Arc<std::sync::atomic::AtomicBool>,
);

impl UdpActiveEgress {
    fn new_legacy(
        socket: Arc<crate::protocol::obfs::ObfsUdp>,
        peer: SocketAddr,
        quic_enabled: bool,
        connection_id: [u8; 4],
    ) -> Self {
        Self(
            Arc::new(std::sync::RwLock::new(UdpEgressSnapshot {
                socket,
                peer,
                framing: UdpEgressFraming::legacy(quic_enabled, connection_id),
                path_epoch: 0,
            })),
            #[cfg(feature = "experimental-roaming")]
            Arc::new(std::sync::Mutex::new(None)),
            #[cfg(feature = "experimental-roaming")]
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    #[cfg(feature = "experimental-roaming")]
    fn new_roaming(
        socket: Arc<crate::protocol::obfs::ObfsUdp>,
        peer: SocketAddr,
        destination_cid: [u8; crate::protocol::roaming::CID_LEN],
    ) -> Self {
        Self(
            Arc::new(std::sync::RwLock::new(UdpEgressSnapshot {
                socket,
                peer,
                framing: UdpEgressFraming::RoamingCid(destination_cid),
                path_epoch: 0,
            })),
            Arc::new(std::sync::Mutex::new(None)),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    fn snapshot(&self) -> UdpEgressSnapshot {
        self.0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[cfg(feature = "experimental-roaming")]
    fn expire_draining_ingress(&self) {
        if !self.2.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut draining = lock_or_recover(&self.1, "udp::expire_draining_ingress");
        if draining
            .as_ref()
            .is_some_and(|previous| std::time::Instant::now() > previous.expires_at)
        {
            *draining = None;
            self.2.store(false, std::sync::atomic::Ordering::Release);
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn schedule_draining_ingress_expiry(&self) {
        let expires_at = lock_or_recover(&self.1, "udp::schedule_draining_ingress_expiry")
            .as_ref()
            .map(|previous| previous.expires_at);
        let Some(expires_at) = expires_at else {
            return;
        };
        let active_egress = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)).await;
            // A newer commit may already have replaced the snapshot. The shared expiry check
            // clears only the snapshot whose own deadline has elapsed.
            active_egress.expire_draining_ingress();
        });
    }

    /// Classify a routed CID before AEAD/replay state is consumed. The current epoch is valid only
    /// on the exact path already published to the writer; the next epoch may carry candidate
    /// control. Previous or farther-future aliases are rejected before they can advance replay.
    #[cfg(feature = "experimental-roaming")]
    fn classify_roaming_ingress(
        &self,
        path_epoch: u64,
        peer: SocketAddr,
        socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    ) -> Option<UdpRoamingIngressPath> {
        let current = self
            .0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if path_epoch == current.path_epoch {
            let committed = (current.peer == peer
                && Arc::ptr_eq(&current.socket, socket)
                && matches!(&current.framing, UdpEgressFraming::RoamingCid(_)))
            .then_some(UdpRoamingIngressPath::Committed);
            drop(current);
            self.expire_draining_ingress();
            return committed;
        }
        let candidate = current
            .path_epoch
            .checked_add(1)
            .filter(|next| *next == path_epoch)
            .map(|_| UdpRoamingIngressPath::Candidate);
        drop(current);
        self.expire_draining_ingress();
        if candidate.is_some() {
            return candidate;
        }
        if !self.2.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let draining = lock_or_recover(&self.1, "udp::draining_ingress");
        draining.as_ref().and_then(|previous| {
            let snapshot = &previous.snapshot;
            (snapshot.path_epoch == path_epoch
                && snapshot.peer == peer
                && Arc::ptr_eq(&snapshot.socket, socket)
                && matches!(&snapshot.framing, UdpEgressFraming::RoamingCid(_)))
            .then_some(UdpRoamingIngressPath::Draining)
        })
    }

    /// Capture path and PMTU budget under the same read lock. A commit cannot publish a new
    /// family between these two reads, so one record never combines an old socket with a new
    /// path's (possibly larger) payload budget.
    fn snapshot_with_payload_budget(
        &self,
        payload_budget: &std::sync::atomic::AtomicU32,
    ) -> (UdpEgressSnapshot, usize) {
        let current = self
            .0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let budget = payload_budget.load(std::sync::atomic::Ordering::Relaxed) as usize;
        (current.clone(), budget)
    }

    /// Widen a reverse-PMTU budget only while the exact path that carried the probe remains
    /// published. Holding the read guard closes the check-versus-PATH_COMMIT race.
    fn certify_payload_budget(
        &self,
        path_epoch: u64,
        peer: SocketAddr,
        payload_budget: &std::sync::atomic::AtomicU32,
        certified: u32,
    ) -> Option<u32> {
        let current = self
            .0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.path_epoch != path_epoch || current.peer != peer {
            return None;
        }
        Some(payload_budget.swap(certified, std::sync::atomic::Ordering::Relaxed))
    }

    #[cfg(all(feature = "experimental-roaming", test))]
    fn commit_roaming(
        &self,
        commit: UdpEgressCommit,
        payload_budget: &std::sync::atomic::AtomicU32,
    ) -> Result<(), UdpEgressCommitError> {
        match self.commit_roaming_with(commit, payload_budget, |_, _| {
            Ok::<(), std::convert::Infallible>(())
        }) {
            Ok(()) => Ok(()),
            Err(UdpEgressPublishError::State(error)) => Err(error),
            Err(UdpEgressPublishError::Publish(never)) => match never {},
        }
    }

    /// Validate the old publication, synchronously emit the commit marker, and expose the new
    /// writer snapshot only after that marker has been accepted by the socket. The callback runs
    /// while the egress write lock is held and must neither await nor re-enter this object.
    #[cfg(feature = "experimental-roaming")]
    fn commit_roaming_with<E>(
        &self,
        commit: UdpEgressCommit,
        payload_budget: &std::sync::atomic::AtomicU32,
        publish: impl FnOnce(&crate::protocol::obfs::ObfsUdp, SocketAddr) -> Result<(), E>,
    ) -> Result<(), UdpEgressPublishError<E>> {
        if commit.next_epoch
            != commit
                .expected_epoch
                .checked_add(1)
                .ok_or(UdpEgressCommitError::InvalidEpoch)
                .map_err(UdpEgressPublishError::State)?
        {
            return Err(UdpEgressPublishError::State(
                UdpEgressCommitError::InvalidEpoch,
            ));
        }
        let local = commit
            .socket
            .raw_socket()
            .local_addr()
            .map_err(|_| UdpEgressPublishError::State(UdpEgressCommitError::FamilyMismatch))?;
        if local.is_ipv4() != commit.peer.is_ipv4() {
            return Err(UdpEgressPublishError::State(
                UdpEgressCommitError::FamilyMismatch,
            ));
        }
        let mut current = self
            .0
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut draining = lock_or_recover(&self.1, "udp::commit_draining_ingress");
        if current.path_epoch != commit.expected_epoch {
            return Err(UdpEgressPublishError::State(
                UdpEgressCommitError::StaleEpoch,
            ));
        }
        if current.peer != commit.expected_peer {
            return Err(UdpEgressPublishError::State(
                UdpEgressCommitError::StalePeer,
            ));
        }
        let safe_payload_budget =
            crate::protocol::data_frag::conservative_udp_payload_budget(commit.peer.is_ipv6());
        publish(&commit.socket, commit.peer).map_err(UdpEgressPublishError::Publish)?;
        // The writer cannot snapshot the new path until this write guard is released.
        payload_budget.store(
            safe_payload_budget as u32,
            std::sync::atomic::Ordering::Relaxed,
        );
        let drain = matches!(&current.framing, UdpEgressFraming::RoamingCid(_)).then(|| {
            UdpDrainingIngress {
                snapshot: current.clone(),
                expires_at: std::time::Instant::now()
                    + crate::protocol::data_frag::REASSEMBLY_TIMEOUT,
            }
        });
        let has_drain = drain.is_some();
        *draining = drain;
        self.2
            .store(has_drain, std::sync::atomic::Ordering::Release);
        *current = UdpEgressSnapshot {
            socket: commit.socket,
            peer: commit.peer,
            framing: UdpEgressFraming::RoamingCid(commit.destination_cid),
            path_epoch: commit.next_epoch,
        };
        Ok(())
    }

    /// EMSGSIZE may arrive after another task committed a new path. Downgrade the currently
    /// published family, not the stale snapshot that happened to report the error.
    fn downgrade_payload_budget(
        &self,
        attempted_epoch: u64,
        payload_budget: &std::sync::atomic::AtomicU32,
    ) -> usize {
        let current = self
            .0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let safe = current.safe_payload_budget();
        if current.path_epoch != attempted_epoch {
            payload_budget.store(safe as u32, std::sync::atomic::Ordering::Relaxed);
            return safe;
        }
        // Even on the same epoch another control path may already have lowered the budget.
        // `fetch_min` prevents a delayed send error from widening it again.
        payload_budget.fetch_min(safe as u32, std::sync::atomic::Ordering::Relaxed);
        safe
    }
}

fn max_useful_udp_payload_budget(wire_wrapper_len: usize) -> usize {
    crate::protocol::data_frag::MAX_REASSEMBLED_RECORD.saturating_add(wire_wrapper_len)
}

fn sanitized_udp_payload_budget(reported: u16, outer_ipv6: bool, wire_wrapper_len: usize) -> usize {
    usize::from(reported).clamp(
        crate::protocol::data_frag::conservative_udp_payload_budget(outer_ipv6),
        max_useful_udp_payload_budget(wire_wrapper_len),
    )
}

fn downlink_mtu_probe_budgets(
    reported: u16,
    peer_is_ipv6: bool,
    obfs_overhead: usize,
    framing: UdpEgressFraming,
) -> Vec<usize> {
    let wrapper_overhead = obfs_overhead + framing.wrapper_len();
    let target = sanitized_udp_payload_budget(reported, peer_is_ipv6, wrapper_overhead);
    let record_overhead = crate::protocol::udp_frag::UDP_RECORD_PROBE_OVERHEAD + wrapper_overhead;
    let ceiling = i32::try_from(target.saturating_sub(record_overhead)).unwrap_or(i32::MAX);
    if ceiling < crate::config::server::MTU_MIN as i32 {
        return vec![target];
    }
    let outer_overhead = record_overhead + 8 + if peer_is_ipv6 { 40 } else { 20 };
    let floor = if peer_is_ipv6 {
        (1280 - outer_overhead as i32).max(crate::config::server::MTU_MIN as i32)
    } else {
        crate::config::server::MTU_MIN as i32
    }
    .clamp(crate::config::server::MTU_MIN as i32, ceiling);
    crate::protocol::udp_frag::mtu_probe_ladder(ceiling, floor)
        .into_iter()
        .filter_map(|candidate| {
            usize::try_from(candidate)
                .ok()
                .and_then(|inner| inner.checked_add(record_overhead))
        })
        .filter(|budget| *budget <= target)
        .collect()
}

fn note_certified_udp_payload_budget(
    active_egress: &UdpActiveEgress,
    cell: &std::sync::atomic::AtomicU32,
    who: std::fmt::Arguments<'_>,
    expected: DownlinkMtuProbe,
) {
    let Some(previous) = active_egress.certify_payload_budget(
        expected.path_epoch,
        expected.peer,
        cell,
        expected.udp_payload_budget,
    ) else {
        log::debug!(
            "client {who} ignored stale reverse-PMTU ACK for path epoch {}",
            expected.path_epoch
        );
        return;
    };
    if previous != expected.udp_payload_budget {
        log::info!(
            "client {who} reverse-probe certified UDP downlink budget {} bytes (was {previous})",
            expected.udp_payload_budget
        );
    }
}
#[inline]
fn is_message_too_long(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownlinkMtuProbe {
    path_epoch: u64,
    peer: SocketAddr,
    token: u128,
    payload_size: u16,
    udp_payload_budget: u32,
}

const DOWNLINK_MTU_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

fn build_downlink_mtu_probe(
    token: u128,
    udp_payload_budget: usize,
    obfs_overhead: usize,
    framing: UdpEgressFraming,
    packet_number: u32,
) -> Option<(Vec<u8>, u16)> {
    let wrapper_bytes = obfs_overhead + framing.wrapper_len();
    let payload_size = udp_payload_budget.checked_sub(wrapper_bytes)?;
    let payload_size_u16 = u16::try_from(payload_size).ok()?;
    let probe = crate::protocol::udp_frag::mtu_probe_v2_datagram(token, payload_size)?;
    let mut wrapped = Vec::with_capacity(framing.wrapper_len() + probe.len());
    let packet = match framing {
        UdpEgressFraming::Unmasked => probe,
        _ => {
            framing.wrap_into(&probe, packet_number, &mut wrapped);
            wrapped
        }
    };
    debug_assert_eq!(packet.len() + obfs_overhead, udp_payload_budget);
    Some((packet, payload_size_u16))
}

fn set_probe_df(socket: &socket2::Socket, peer_is_ipv6: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // Linux UAPI: IPV6_MTU_DISCOVER uses the IP_PMTUDISC_* values, just like
    // IP_MTU_DISCOVER. The libc crate exposes the latter constants but not this option
    // number; keep it beside the setsockopt call instead of spreading a numeric literal.
    const IPV6_MTU_DISCOVER: libc::c_int = 23;
    let (level, option) = if peer_is_ipv6 {
        (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    let value: libc::c_int = crate::protocol::data_frag::ACTIVE_PMTUDISC_MODE;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Send one reverse PMTU probe through a short-lived unconnected socket. It carries the
/// listener local address/port via SO_REUSEPORT, but never installs an exact connected
/// four-tuple that could capture the immediate ACK. Its private DF option cannot race with
/// data sends on the stable listener, and it is closed as soon as send_to returns.
fn send_downlink_mtu_probe(
    local_addr: SocketAddr,
    peer: SocketAddr,
    packet: &[u8],
    obfs_key: Option<[u8; 32]>,
) -> std::io::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    if local_addr.is_ipv6() != peer.is_ipv6() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reverse PMTU probe address-family mismatch",
        ));
    }
    let domain = if peer.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if peer.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&local_addr.into())?;

    set_probe_df(&socket, peer.is_ipv6())?;

    let sealed;
    let wire = if let Some(key) = obfs_key {
        sealed = crate::protocol::obfs::obfs_datagram_seal(&key, packet);
        sealed.as_slice()
    } else {
        packet
    };
    let peer_addr = peer.into();
    let sent = socket.send_to(wire, &peer_addr)?;
    if sent == wire.len() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "reverse PMTU probe was only partially sent",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn schedule_downlink_mtu_probe(
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    tasks: &super::ProfileTasks,
    profile_name: &str,
    addr: SocketAddr,
    budget_cell: &Arc<std::sync::atomic::AtomicU32>,
    reported: u16,
    obfs_key: Option<[u8; 32]>,
) {
    let (flights, local_addr, probe_peer, pending_probe, active_egress) = {
        let mut guard = sessions.write().await;
        let Some(client) = guard.get_mut(&addr) else {
            return;
        };
        if !matches!(client.state, UdpSessionState::Authenticated { .. })
            || !client.data_frag_enabled
            || client
                .udp_payload_budget
                .as_ref()
                .is_none_or(|cell| !Arc::ptr_eq(cell, budget_cell))
        {
            return;
        }
        let Some(active_egress) = client.active_egress.as_ref() else {
            return;
        };
        let egress = active_egress.snapshot();
        // A report received on a draining address must not start a probe for the new path.
        if egress.peer != addr {
            return;
        }
        let targets = downlink_mtu_probe_budgets(
            reported,
            egress.peer.is_ipv6(),
            egress.socket.seal_overhead(),
            egress.framing,
        )
        .into_iter()
        .filter(|target| {
            (budget_cell.load(std::sync::atomic::Ordering::Relaxed) as usize) < *target
        })
        .collect::<Vec<_>>();
        if targets.is_empty() {
            return;
        }
        let mut pending = lock_or_recover(&client.downlink_mtu_probe, "udp::downlink_probe");
        if pending
            .as_ref()
            .is_some_and(|probe| probe.path_epoch == egress.path_epoch && probe.peer == egress.peer)
        {
            return;
        }
        let flights = targets
            .into_iter()
            .filter_map(|target| {
                let token: u128 = rand::random();
                let packet_number = client
                    .packet_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (packet, payload_size) = build_downlink_mtu_probe(
                    token,
                    target,
                    egress.socket.seal_overhead(),
                    egress.framing,
                    packet_number,
                )?;
                Some((
                    DownlinkMtuProbe {
                        path_epoch: egress.path_epoch,
                        peer: egress.peer,
                        token,
                        payload_size,
                        udp_payload_budget: u32::try_from(target).ok()?,
                    },
                    packet,
                ))
            })
            .collect::<Vec<_>>();
        let Some((first, _)) = flights.first() else {
            return;
        };
        let local_addr = match egress.socket.raw_socket().local_addr() {
            Ok(value) => value,
            Err(error) => {
                log::debug!(
                    "UDP {}: cannot start reverse PMTU probe: {error}",
                    egress.peer
                );
                return;
            }
        };
        *pending = Some(*first);
        drop(pending);
        (
            flights,
            local_addr,
            egress.peer,
            client.downlink_mtu_probe.clone(),
            active_egress.clone(),
        )
    };

    let profile_name = profile_name.to_string();
    tasks.spawn(async move {
        let mut previous = None;
        for (expected, packet) in flights {
            let egress = active_egress.snapshot();
            if egress.path_epoch != expected.path_epoch || egress.peer != expected.peer {
                let mut pending =
                    lock_or_recover(&pending_probe, "udp::downlink_probe_path_changed");
                if previous.is_some_and(|value| *pending == Some(value))
                    || (previous.is_none() && *pending == Some(expected))
                {
                    *pending = None;
                }
                return;
            }
            {
                let mut pending =
                    lock_or_recover(&pending_probe, "udp::downlink_probe_next_rung");
                match previous {
                    None if *pending != Some(expected) => return,
                    Some(value) if *pending != Some(value) => return,
                    Some(_) => *pending = Some(expected),
                    None => {}
                }
            }

            let send_result =
                send_downlink_mtu_probe(local_addr, probe_peer, &packet, obfs_key);
            if send_result.is_ok() {
                tokio::time::sleep(DOWNLINK_MTU_PROBE_TIMEOUT).await;
            }
            let unanswered = {
                let pending = lock_or_recover(&pending_probe, "udp::downlink_probe_timeout");
                *pending == Some(expected)
            };
            if !unanswered {
                // An exact ACK cleared the pending marker and certified this rung, or a newer
                // path transaction invalidated the sequence. Either way this scheduler is done.
                return;
            }
            if let Err(error) = send_result {
                log::debug!(
                    "UDP {probe_peer} on profile '{profile_name}': reverse PMTU probe send failed at {} bytes: {error}",
                    expected.udp_payload_budget
                );
            } else {
                log::debug!(
                    "UDP {probe_peer} on profile '{profile_name}': reverse PMTU probe timed out at {} bytes",
                    expected.udp_payload_budget
                );
            }
            previous = Some(expected);
        }
        if let Some(expected) = previous {
            let mut pending = lock_or_recover(&pending_probe, "udp::downlink_probe_exhausted");
            if *pending == Some(expected) {
                *pending = None;
            }
        }
    });
}

#[allow(dead_code)] // session_id retained for symmetry with the TCP session model
#[allow(clippy::too_many_arguments)]
async fn forward_udp_uplink_packet(
    packet: ServerTunPacket,
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    tasks: &super::ProfileTasks,
    profile: &Arc<ProfileRuntime>,
    addr: SocketAddr,
    obfs_key: Option<[u8; 32]>,
    session_id: u64,
    exit_access: crate::server::ExitAccess,
    tun_tx: &TunIngress,
    path_mtu: &Option<Arc<std::sync::atomic::AtomicU32>>,
    udp_payload_budget: &Option<Arc<std::sync::atomic::AtomicU32>>,
    client_info: &Option<crate::server::handler::ClientInfoCell>,
    src_guard: &Option<crate::server::acl::SrcGuard>,
    dst_acl: &crate::server::acl::DstAcl,
    bandwidth_limit: &Option<Arc<std::sync::atomic::AtomicU32>>,
    upload_tx: &Option<mpsc::Sender<ServerTunPacket>>,
    recv_ctr: &Arc<std::sync::atomic::AtomicU64>,
    client_dropped: &Arc<std::sync::atomic::AtomicU64>,
) {
    if crate::protocol::ctrl::is_ctrl(&packet) {
        if let (Some(cell), Some(mtu)) = (
            path_mtu.as_ref(),
            crate::protocol::ctrl::parse_mtu_report(&packet),
        ) {
            crate::server::handler::note_path_mtu(cell, format_args!("at {addr}"), mtu);
        } else if let (Some(cell), Some(budget)) = (
            udp_payload_budget.as_ref(),
            crate::protocol::ctrl::parse_udp_payload_budget_report(&packet),
        ) {
            schedule_downlink_mtu_probe(
                sessions,
                tasks,
                &profile.name,
                addr,
                cell,
                budget,
                obfs_key,
            )
            .await;
        } else if let (Some(cell), Some((version, platform))) = (
            client_info.as_ref(),
            crate::protocol::ctrl::parse_client_info(&packet),
        ) {
            crate::server::handler::note_client_info(
                cell,
                format_args!("at {addr}"),
                &version,
                &platform,
            );
        }
        return;
    }
    if packet.is_empty() {
        return;
    }
    if src_guard
        .as_ref()
        .is_some_and(|guard| !guard.allows_packet(&packet))
    {
        log::debug!("dropped UDP packet from {} - forged source address", addr);
        return;
    }
    if !dst_acl.is_unrestricted() && !dst_acl.allows_packet(&packet) {
        log::debug!(
            "ACL: dropped UDP packet from {} - destination not in allowed_networks",
            addr
        );
        return;
    }
    let limit = bandwidth_limit
        .as_ref()
        .map(|value| value.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    if limit == 0 {
        recv_ctr.fetch_add(packet.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let _ = tun_tx
            .send_client_packet(profile, session_id, exit_access, packet)
            .await;
    } else if upload_tx
        .as_ref()
        .is_none_or(|tx| tx.try_send(packet).is_err())
    {
        client_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        profile
            .udp_buffer_counters
            .note_internal_drop(InternalDrop::QueueFull);
        log::debug!(
            "UDP upload pacing queue full for {} on profile '{}'; dropping packet",
            addr,
            profile.name
        );
    }
}

enum UdpSessionState {
    AwaitingAuth,
    Authenticated {
        session_id: u64,
        /// Per-device pool/session key — used to release the IP on cleanup.
        device_key: String,
        client_ip: std::net::IpAddr,
    },
}

#[cfg(feature = "experimental-roaming")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct UdpRoamingOwner {
    address: SocketAddr,
    session_generation: u64,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Default)]
struct UdpRoamingOwnerIndex {
    by_session_id: HashMap<u64, UdpRoamingOwner>,
}

#[cfg(feature = "experimental-roaming")]
impl UdpRoamingOwnerIndex {
    fn publish(&mut self, session_id: u64, session_generation: u64, address: SocketAddr) {
        self.by_session_id.insert(
            session_id,
            UdpRoamingOwner {
                address,
                session_generation,
            },
        );
    }

    fn resolve(&self, lookup: crate::transport_core::udp_roaming::CidLookup) -> Option<SocketAddr> {
        self.by_session_id
            .get(&lookup.session_id())
            .filter(|owner| owner.session_generation == lookup.session_generation())
            .map(|owner| owner.address)
    }

    fn remove_if_matches(&mut self, session_id: u64, session_generation: u64, address: SocketAddr) {
        if self.by_session_id.get(&session_id).is_some_and(|owner| {
            owner.address == address && owner.session_generation == session_generation
        }) {
            self.by_session_id.remove(&session_id);
        }
    }
}

/// One worker's address-fast-path table plus the stable session-id index used only after a
/// successful CID lookup. Keeping both behind the same lock gives removal and replacement one
/// transaction; a late teardown cannot erase the owner of a newer session generation.
#[derive(Default)]
struct UdpSessionDirectory {
    by_address: HashMap<SocketAddr, UdpClient>,
    #[cfg(feature = "experimental-roaming")]
    roaming_owners: UdpRoamingOwnerIndex,
}

impl std::ops::Deref for UdpSessionDirectory {
    type Target = HashMap<SocketAddr, UdpClient>;

    fn deref(&self) -> &Self::Target {
        &self.by_address
    }
}

impl std::ops::DerefMut for UdpSessionDirectory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.by_address
    }
}

impl UdpSessionDirectory {
    fn insert(&mut self, address: SocketAddr, client: UdpClient) -> Option<UdpClient> {
        let replaced = self.remove(&address);
        let duplicate = self.by_address.insert(address, client);
        debug_assert!(duplicate.is_none());
        replaced
    }

    fn remove(&mut self, address: &SocketAddr) -> Option<UdpClient> {
        let removed = self.by_address.remove(address)?;
        #[cfg(feature = "experimental-roaming")]
        if let Some((session_id, session_generation)) = removed.roaming_identity() {
            self.roaming_owners
                .remove_if_matches(session_id, session_generation, *address);
        }
        Some(removed)
    }

    /// Remove the address-map entry that currently owns an authenticated logical session.
    /// Roaming changes the address key while `SessionShared::peer` remains the connect-time peer,
    /// so supersede/limit cleanup must resolve the live owner by session id and must never remove
    /// an unrelated replacement that now occupies the fallback address.
    fn remove_session_owner(
        &mut self,
        session_id: u64,
        fallback_address: SocketAddr,
    ) -> Option<UdpClient> {
        #[cfg(feature = "experimental-roaming")]
        if let Some(address) = self
            .roaming_owners
            .by_session_id
            .get(&session_id)
            .map(|owner| owner.address)
            .filter(|address| {
                self.by_address
                    .get(address)
                    .and_then(UdpClient::authenticated_session_id)
                    == Some(session_id)
            })
        {
            return self.remove(&address);
        }
        if self
            .by_address
            .get(&fallback_address)
            .and_then(UdpClient::authenticated_session_id)
            == Some(session_id)
        {
            self.remove(&fallback_address)
        } else {
            None
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn publish_roaming_owner(&mut self, address: SocketAddr) -> bool {
        let Some((session_id, session_generation)) = self
            .by_address
            .get(&address)
            .and_then(UdpClient::roaming_identity)
        else {
            return false;
        };
        self.roaming_owners
            .publish(session_id, session_generation, address);
        true
    }

    #[cfg(feature = "experimental-roaming")]
    fn resolve_roaming_owner(
        &self,
        lookup: crate::transport_core::udp_roaming::CidLookup,
    ) -> Option<SocketAddr> {
        let address = self.roaming_owners.resolve(lookup)?;
        self.by_address
            .get(&address)
            .filter(|client| {
                client
                    ._udp_roaming_registration
                    .as_ref()
                    .is_some_and(|registration| registration.matches_lookup(lookup))
            })
            .map(|_| address)
    }
}

struct UdpClient {
    rx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    tx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    rx_data_frag_key: [u8; 32],
    tx_data_frag_key: [u8; 32],
    /// Handshake-bound directional CID material is retained only until authenticated roaming
    /// registration, then moved into the zeroizing profile registry.
    #[cfg(feature = "experimental-roaming")]
    client_to_server_cid_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
    #[cfg(feature = "experimental-roaming")]
    server_to_client_cid_secret: Option<zeroize::Zeroizing<[u8; 32]>>,
    #[cfg(feature = "experimental-roaming")]
    _udp_roaming_registration: Option<crate::transport_core::udp_roaming::UdpSessionRegistration>,
    #[cfg(feature = "experimental-roaming")]
    _udp_roaming_initial_cids: Option<crate::transport_core::udp_roaming::InitialCids>,
    /// Retained after commit so a freshly encrypted retry of the last PATH_RESPONSE can receive
    /// the same PATH_COMMIT; the next accepted PATH_INIT replaces it with its generation ticket.
    #[cfg(feature = "experimental-roaming")]
    udp_roaming_candidate: Option<crate::transport_core::udp_roaming::CandidateTicket>,
    data_frag_enabled: bool,
    data_reassembler: crate::protocol::data_frag::DataReassembler,
    /// Authenticated PACKET_MUX_V1 receiver. Empty until negotiation completes,
    /// and permanently empty for legacy/off sessions.
    rx_recordizer: Option<crate::protocol::recordizer::Reassembler>,
    state: UdpSessionState,
    last_activity: std::time::Instant,
    /// Inbound (client->server) byte counter, shared with this client's
    /// `SessionShared` so `list-clients` RECV reflects UDP receives. Set on auth
    /// (a placeholder Arc until then) — UDP RECV used to be stuck at 0 because it
    /// was never incremented on the UDP receive path.
    bytes_recv: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Live per-user limit shared with `SessionShared`, updated by set-bandwidth.
    /// `None` until authentication completes.
    bandwidth_limit_mbps: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Bounded path to this client's upload pacing task. Limited UDP traffic must
    /// never sleep in the shared socket receive loop, which would stall every peer.
    upload_tx: Option<mpsc::Sender<ServerTunPacket>>,
    /// Shared with `SessionShared::dropped`, so local ingress-pool pressure is visible in
    /// `list-clients` instead of becoming an unexplained wire loss.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// When the client first appeared — used to evict stale AwaitingAuth entries
    created_at: std::time::Instant,
    connection_id: [u8; 4],
    quic_enabled: bool,
    packet_counter: Arc<std::sync::atomic::AtomicU32>,
    /// Installed only after AUTH succeeds. The writer snapshots it for every record, so a
    /// future PATH_COMMIT can replace socket/address/CID without replacing the session codec.
    active_egress: Option<UdpActiveEgress>,
    /// Crypto material kept to verify the client key-proof at auth time
    /// (require_client_key_proof). Mirrors the TCP handshake.
    ephemeral_shared: [u8; 32],
    static_shared: [u8; 32],
    transcript_hash: [u8; 32],
    /// Per-client flow-shaping cover scheduler (server->client idle cover;
    /// DPI-AUDIT 6.1/6.2). Carries this client's cover budget; disabled unless the
    /// profile enables `obf.traffic_shaping`.
    shaper: crate::protocol::Shaper,
    /// Next instant a cover packet is due for this client (Poisson schedule).
    next_cover_at: std::time::Instant,
    /// Cached RAW ServerHello, for idempotent re-emit while `AwaitingAuth`. A lost
    /// ServerHello leaves the client retransmitting its (fragmented) ClientHello,
    /// which fails AEAD decrypt on the existing-session path and would otherwise be
    /// dropped — stalling the client for the whole `connection_timeout` before a
    /// fresh-port reconnect. Cleared on auth (only needed pre-auth).
    server_hello: Vec<u8>,
    /// Framing the ClientHello used, so the re-emitted ServerHello matches it.
    hello_frag_mode: bool,
    /// Cached post-unwrap AUTH request + framed AuthOK, for idempotent re-emit once
    /// `Authenticated`. A lost AuthOK leaves the client retransmitting the EXACT
    /// AUTH datagram, which the replay window rejects; on a byte match we re-send
    /// the cached AuthOK instead of dropping it. Empty until authenticated.
    ///
    /// A LIST of datagrams, not one: a large pushed-route set splits the AuthOK into
    /// fragments (see `build_auth_ok_datagrams`), and re-emitting only the first of them
    /// would leave the client's reassembly permanently one fragment short — the very stall
    /// this cache exists to prevent. Usually holds exactly one element.
    auth_request: Vec<u8>,
    auth_ok: Vec<Vec<u8>>,
    /// Compiled `allowed_networks` destination ACL for the authenticated user (own or
    /// inherited from the group). Empty = unrestricted; set at auth, checked on every
    /// inner packet before the TUN. Mirrors `SessionShared.dst_acl` on the TCP path.
    dst_acl: crate::server::acl::DstAcl,
    /// Which SOURCE addresses this session may claim. Mirrors
    /// `SessionShared.src_guard` on the TCP path.
    src_guard: Option<crate::server::acl::SrcGuard>,
    /// Per-family authorization for an internal `/0` exit route.
    exit_access: crate::server::ExitAccess,
    /// Shared with this client's `SessionShared`; raised by `kick_all` (kick, quota
    /// cut-off, supersede). `None` until authenticated.
    ///
    /// Ingress is demultiplexed from THIS per-worker map, but every control action edits
    /// `profile.sessions.by_ip` — a different registry. Without this link a revoked
    /// client kept feeding the TUN until the reaper expired it, by which time its pool IP
    /// could already belong to somebody else. (Audit 2026-07-27, A1/A2/A3.)
    revoked: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Shared with this client's `SessionShared.path_mtu` — the tunnel MTU it reported after
    /// probing its path, written here by the receive loop and read by the TUN forwarder.
    /// `None` until authenticated; 0 inside means "never reported". (Audit 2026-07-30, #13.)
    path_mtu: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Complete server→client outer UDP payload size certified in that same direction. The
    /// authenticated client report is only an upper bound used to size a reverse DF probe;
    /// the writer starts at the family-safe minimum and widens only after the probe ACK.
    /// Kept separate from `path_mtu`: DATA_FRAG makes inner MTU and outer datagram size
    /// independent. `None` until authentication completes.
    udp_payload_budget: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// One bounded reverse probe awaiting its matching ACK. Shared with the timeout task so
    /// moving the session's address-map key cannot strand a pending marker.
    downlink_mtu_probe: Arc<std::sync::Mutex<Option<DownlinkMtuProbe>>>,
    /// Shared with this client's `SessionShared.client_info` — the `(version, platform)` it
    /// reported about itself, written here by the receive loop and read by `list-clients`
    /// through the session. `None` until authenticated; `None` inside means "never said".
    client_info: Option<crate::server::handler::ClientInfoCell>,
    /// Fixed-budget encrypted-record storage shared with this client's `SessionShared`.
    /// `None` while the peer is half-open; allocated only after authentication succeeds.
    wire_pool: Option<BufferPool>,
    /// Cumulative anti-amplification budget for this session — an APPROXIMATION of the wire,
    /// deliberately, and read the next paragraph before trusting either number.
    ///
    /// `handle_new_udp_client` bounds the FIRST exchange (a ≥1200 B floor plus an explicit 3×
    /// check), but the idempotent re-emit path below it repeated neither: a 6-byte datagram
    /// carrying the fragment magic re-sent the whole cached ServerHello (~2-3.4 KB) for free,
    /// and could be repeated for the life of the half-open session — a ~500× reflector for a
    /// spoofed source, i.e. exactly the property the initial check exists to deny. Counting
    /// both directions and refusing to exceed 3× received closes the gap for every reply path,
    /// present and future, instead of re-deriving the bound at each of them.
    ///
    /// **What these actually count**, since it is not the same thing on both sides:
    ///
    /// * `amp_received` adds `data.len()` after transparent obfs-open but before QUIC-unwrap.
    ///   The 13-byte obfs envelope and the IP/UDP headers are therefore not included. Omitting
    ///   received bytes makes the allowance stricter, not looser.
    /// * the seed for `amp_received` is the REASSEMBLED ClientHello, not the sum of the
    ///   datagrams that carried it, so a fragmented one is undercounted by the per-fragment
    ///   headers. **Undercounting received makes the budget stricter**, so this errs safe.
    /// * `amp_sent` adds message bodies, not wrapped datagrams: the QUIC and obfs headers put
    ///   around a ServerHello or an AuthOK fragment are not counted. **Undercounting sent
    ///   makes the budget looser** — by roughly 20-30 bytes per datagram, against a 3× bound
    ///   on kilobyte-scale messages.
    ///
    /// So the ratio is real but not exact, and it is not trying to be: the job is to deny a
    /// large multiplier to an unverified source, not to meter traffic. Making it exact would
    /// mean threading the emitted size back out of `send_handshake_response` and the AuthOK
    /// send loop — changing signatures to sharpen a bound whose slack is a rounding error
    /// against what it prevents. If that ever becomes worth doing, do it in those two places
    /// and delete this paragraph; do not leave the doc claiming precision the code lacks,
    /// which is what it did before. (Audit 2026-08-02, §7 of the follow-up.)
    amp_received: u64,
    amp_sent: u64,
    /// AuthOK re-emits already granted to this session, bounded by [`MAX_AUTH_OK_REEMITS`].
    ///
    /// The 3× byte budget above guards the UNVERIFIED path, where a 6-byte datagram carrying
    /// the fragment magic could pull a whole ServerHello out of us. It is the wrong instrument
    /// once the session is `Authenticated`, and actively harmful there: a profile with a large
    /// pushed-route set makes the AuthOK several KB, so re-sending it needs more budget than
    /// the client's ~350-byte AUTH retransmits can earn inside the handshake deadline. The
    /// recovery path would then be denied on exactly the profiles fragmentation was added for.
    ///
    /// An authenticated peer has already proven return-routability — it completed the PQ
    /// handshake and authenticated from this address — so reflection to a spoofed source is not
    /// the risk here. What remains is an on-path attacker replaying the observed AUTH to make
    /// us re-send; a small count cap bounds that to a handful of datagrams per session, which
    /// is all the legitimate path ever needs. (Audit 2026-08-02, §4.)
    auth_ok_reemits: u8,
    /// Whether this session's AuthOK has actually reached the socket.
    ///
    /// NOTHING may precede the AuthOK on an authenticated session, and `Authenticated` alone
    /// does not mean it has been sent: `handle_udp_auth` runs on its own task (spawned off the
    /// recv loop so Argon2 cannot stall the worker), sets this state, and only then takes the
    /// pool lock, checks `max_clients` and programs routes before sending. The select! loop
    /// keeps running throughout, so a heartbeat or cover tick landing in that window found a
    /// session it considered live and wrote to the wire first.
    ///
    /// What the client does with that is not graceful: it takes the first record that decrypts
    /// as the AuthOK, so a cover packet — which decrypts perfectly into an EMPTY payload —
    /// fails the `OK:` parse and the connect dies. On a fragmented AuthOK the stray datagram
    /// also resets reassembly. Rare (the window is short against a 15 s beacon), and a random
    /// UDP auth failure with a reconnect loop is exactly the kind of rare that never gets
    /// diagnosed. (Audit 2026-08-03, P1.)
    auth_ok_sent: bool,
}

impl UdpClient {
    fn authenticated_session_id(&self) -> Option<u64> {
        match self.state {
            UdpSessionState::Authenticated { session_id, .. } => Some(session_id),
            UdpSessionState::AwaitingAuth => None,
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn roaming_identity(&self) -> Option<(u64, u64)> {
        let session_id = self.authenticated_session_id()?;
        let registration = self._udp_roaming_registration.as_ref()?;
        (registration.session_id() == session_id)
            .then_some((session_id, registration.session_generation()))
    }

    #[cfg(feature = "experimental-roaming")]
    fn roaming_enabled(&self) -> bool {
        self.roaming_identity().is_some()
    }
}

/// How many times one session may have its AuthOK re-sent. The client retransmits AUTH on a
/// ~1 s jittered timer inside a 10 s handshake deadline, so the legitimate path needs a few at
/// most; past that the reply is not being lost, it is being milked.
const MAX_AUTH_OK_REEMITS: u8 = 5;

/// Bind one `SO_REUSEPORT` UDP socket. Several of these on the same address let the
/// kernel flow-hash incoming datagrams across them, so multiple workers can decrypt
/// on separate cores. Each flow (client) sticks to one socket → one worker, so its
/// session stays on a single thread.
pub(crate) fn bind_reuseport(
    addr: &str,
    perf: &crate::config::UdpPerfConfig,
    counters: Arc<UdpBufferCounters>,
    aggregate_budget: AggregateUdpBudgetPlan,
) -> anyhow::Result<(UdpSocket, UdpBufferController)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sa: SocketAddr = addr.parse()?;
    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if sa.is_ipv6() {
        // Keep the IPv6 listener in its own address family. Without V6ONLY, binding
        // `[::]:port` can also claim IPv4-mapped traffic and either collide with the
        // explicit `0.0.0.0:port` listener or distribute IPv4 datagrams across the wrong
        // profile/socket set.
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;

    sock.bind(&sa.into())?;
    let socket = UdpSocket::from_std(sock.into())?;
    let controller = UdpBufferController::configure(
        &socket,
        UdpBufferPolicy {
            send_bytes: perf.send_buffer_size,
            receive_bytes: if perf.recv_buffer_auto && perf.recv_buffer_size > 0 {
                aggregate_budget.auto_initial_recv_bytes
            } else {
                perf.recv_buffer_size
            },
            automatic_receive: perf.recv_buffer_auto,
            max_receive_bytes: if perf.recv_buffer_auto && perf.recv_buffer_size > 0 {
                aggregate_budget.auto_max_recv_bytes
            } else {
                AUTO_MAX_RECV_BYTES
            },
        },
        counters,
        format!("server UDP {addr}"),
    );
    Ok((socket, controller))
}

/// How long an authenticated UDP session may go with no received datagram before
/// it is reaped as dead. The RX-liveness deadline exists only when the client is
/// configured to emit heartbeat/shaping traffic. Otherwise a completely idle UDP
/// tunnel is indistinguishable from a dead one, so only an explicit idle timeout may
/// reap it.
fn udp_reap_window(
    idle_timeout: std::time::Duration,
    liveness_deadline: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    let explicit = (idle_timeout.as_secs() > 0).then_some(idle_timeout);
    match (explicit, liveness_deadline) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[allow(clippy::too_many_arguments)] // worker runtime carries profile, socket, routing, TUN and task owners
pub(crate) async fn run_udp_server(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    socket: UdpSocket,
    mut udp_buffer: UdpBufferController,
    worker_id: usize,
    mut roaming_worker: UdpRoamingWorker,
    tun_tx: TunIngress,
    tasks: super::ProfileTasks,
) -> anyhow::Result<()> {
    let pcfg = &profile.config;
    log::info!(
        "UDP worker {} for profile '{}' started",
        worker_id,
        profile.name
    );

    // `obfs` wire mode wraps every datagram in a per-datagram ChaCha20 XOR
    // (transparent here via ObfsUdp). `None` = pass-through (fake-tls mode).
    let obfs_key = if pcfg.obfuscation.mode == "obfs" && !pcfg.obfuscation.obfs_key.is_empty() {
        Some(crate::protocol::obfs::derive_obfs_key(
            &pcfg.obfuscation.obfs_key,
        ))
    } else {
        None
    };
    let socket = Arc::new(crate::protocol::obfs::ObfsUdp::new(socket, obfs_key));

    // Keep one task blocked in recvmsg while this task decrypts, reassembles and forwards the
    // previous datagram. The FIFO is bounded and has exactly one allocation per position, so
    // overload back-pressures into the kernel buffer without unbounded memory growth. Replay,
    // recordizer and session state stay in this task and therefore retain strict wire order.
    let receive_slots = crate::transport::udp::UDP_RECEIVE_QUEUE_PACKETS + 1;
    let (receive_recycler, mut recycled_receivers) = mpsc::channel(receive_slots);
    for _ in 0..receive_slots {
        receive_recycler
            .try_send(bytes::BytesMut::with_capacity(
                crate::transport::udp::MAX_UDP_PACKET_SIZE,
            ))
            .map_err(|_| anyhow::anyhow!("could not initialize UDP receive pool"))?;
    }
    let (received_tx, mut received_rx) =
        mpsc::channel(crate::transport::udp::UDP_RECEIVE_QUEUE_PACKETS);
    let receive_socket = socket.clone();
    let receive_recycler_task = receive_recycler.clone();
    let receive_profile = profile.name.clone();
    if !tasks.spawn(async move {
        while let Some(mut datagram) = recycled_receivers.recv().await {
            match receive_socket.recv_buf_from(&mut datagram).await {
                Ok((0, _)) => {
                    datagram.clear();
                    if receive_recycler_task.send(datagram).await.is_err() {
                        break;
                    }
                }
                Ok((_, addr)) => {
                    let datagram = crate::transport::udp::PooledUdpDatagram::new(
                        datagram,
                        receive_recycler_task.clone(),
                    );
                    if received_tx.send((datagram, addr)).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    log::error!("UDP recv error on profile '{}': {}", receive_profile, error);
                    datagram.clear();
                    if receive_recycler_task.send(datagram).await.is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }) {
        anyhow::bail!("profile stopped before UDP receive pump could start");
    }

    let sessions = Arc::new(RwLock::new(UdpSessionDirectory::default()));
    // Per-worker admission gate for pre-auth handshake crypto (see
    // max_concurrent_udp_handshakes). Acquired just before the PQ handshake in
    // the new-session branch; a datagram that can't get a permit is dropped.
    let handshake_permits = Arc::new(Semaphore::new(max_concurrent_udp_handshakes()));

    // Sources with an authentication in flight. The auth path (tarpit sleep + Argon2) is
    // dispatched off this recv loop — see handle_udp_datagram — because `.await`ing it
    // inline froze the whole SO_REUSEPORT worker, and with it EVERY established session
    // hashed to this worker, for the duration of one login (head-of-line blocking DoS).
    // This set stops a duplicate datagram from the same source launching a SECOND parallel
    // Argon2 while the first is still running. (H1)
    let auth_inflight: Arc<tokio::sync::Mutex<std::collections::HashSet<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

    let idle_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);
    let handshake_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let quic_config = &pcfg.obfuscation.quic;
    // Flow-shaping (DPI-AUDIT 6.1/6.2): when on, per-client Poisson idle cover
    // REPLACES the fixed heartbeat. The tick polls at the gap floor so per-client
    // cover deadlines are honoured at a reasonable granularity.
    let shaping_cfg = pcfg.obfuscation.traffic_shaping.to_shaping();
    let shaping_on = shaping_cfg.enabled && shaping_cfg.budget_bytes_per_sec > 0;

    let tick_ms = if shaping_on {
        shaping_cfg.idle_gap_min_ms.max(20)
    } else if heartbeat_enabled {
        // Per-client absolute deadlines carry the actual randomized schedule. This
        // short maintenance tick only discovers due sessions and does not quantize
        // them back onto the configured interval boundary.
        hb_config.interval_ms.clamp(20, 200)
    } else {
        DEFAULT_HEARTBEAT_INTERVAL_MS
    };
    let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_millis(tick_ms));
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut udp_buffer_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    udp_buffer_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Partial ClientHello reassembly, keyed by source address: the UDP handshake is
    // fragmented to dodge IP fragmentation on mobile / CGNAT paths (which drop IP
    // fragments). Bounded by MAX_PENDING_HANDSHAKES and aged out in the cleanup tick.
    let mut frag_pending: HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler> =
        HashMap::new();
    // Cover and heartbeat records are generated serially by this task. Keep their
    // random padding in task-owned storage instead of allocating a fresh Vec for
    // every client on every tick.
    let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
    let mut quic_record = Vec::with_capacity(
        handler::server_wire_buffer_capacity(pcfg) + crate::protocol::roaming::UDP_SHORT_HEADER_LEN,
    );

    loop {
        tokio::select! {
            roaming = roaming_worker.recv() => {
                let event = roaming?;
                #[cfg(feature = "experimental-roaming")]
                handle_udp_roaming_ingress(
                    &profile,
                    &sessions,
                    worker_id,
                    &tun_tx,
                    &tasks,
                    obfs_key,
                    event.0,
                )
                .await;
                #[cfg(not(feature = "experimental-roaming"))]
                match event {}
            }

            received = received_rx.recv() => {
                let Some((recv_buf, addr)) = received else {
                    return Err(anyhow::anyhow!(
                        "UDP receive pump stopped on profile '{}'",
                        profile.name
                    ));
                };
                let n = recv_buf.len();
                udp_buffer.note_receive(n);
                #[cfg(feature = "experimental-roaming")]
                {
                    // Legacy and roaming short headers deliberately share their QUIC-shaped
                    // first byte. Route only after the full eight-byte CID resolves in the
                    // authenticated registry. If it does not, a known address must retain its
                    // legacy path so an AUTH retransmit can still recover a lost AuthOK.
                    let may_use_roaming = {
                        let guard = sessions.read().await;
                        guard.get(&addr).is_none_or(UdpClient::roaming_enabled)
                    };
                    let roaming_header = may_use_roaming
                        .then(|| crate::protocol::roaming::decode_udp_short(&recv_buf[..n]).ok())
                        .flatten()
                        .map(|(header, _)| header)
                        .filter(|header| {
                            profile
                                .udp_roaming_registry
                                .lookup(header.destination_cid())
                                .is_some()
                        });
                    if let Some(header) = roaming_header {
                        let received_worker = u32::try_from(worker_id).map_err(|_| {
                            anyhow::anyhow!("UDP worker id exceeds roaming wire range")
                        })?;
                        let path = crate::transport_core::udp_roaming::UdpPath::new(
                            received_worker,
                            addr,
                        );
                        let envelope = UdpRoamingDatagram {
                            datagram: recv_buf,
                            socket: socket.clone(),
                        };
                        match roaming_worker.fabric.route_ingress(
                            header.destination_cid(),
                            header.packet_number(),
                            path,
                            envelope,
                        ) {
                            Ok(crate::transport_core::udp_roaming::UdpIngressDispatch::Local(routed)) => {
                                handle_udp_roaming_ingress(
                                    &profile,
                                    &sessions,
                                    worker_id,
                                    &tun_tx,
                                    &tasks,
                                    obfs_key,
                                    routed,
                                )
                                .await;
                            }
                            Ok(crate::transport_core::udp_roaming::UdpIngressDispatch::Queued) => {}
                            Err(failure) => note_udp_roaming_route_failure(&profile, failure),
                        }
                        continue;
                    }
                }
                // Rate-limit only NEW UDP sessions. Applying the limiter to
                // every datagram (as the original code did) caps an active
                // tunnel at 10 packets / 60 s and silently drops the rest,
                // which is why a working handshake produced 100 % loss on the
                // first sustained data flow.
                // A continuation fragment of a ClientHello already being reassembled
                // (addr in frag_pending) is NOT a new session — don't re-charge the
                // new-session rate limiter for each fragment.
                let is_new_session = !sessions.read().await.contains_key(&addr)
                    && !frag_pending.contains_key(&addr);
                if is_new_session {
                    // AWG junk (AmneziaWG-style Jc on UDP): a client may prepend `jc`
                    // throwaway decoy datagrams before its ClientHello to blur the
                    // size/count fingerprint of the first packets. Drop them here —
                    // BEFORE the new-session rate limiter, any crypto or the
                    // reassembler — so junk is free and harmless (a lost / reordered
                    // junk datagram never matters). Junk rides the same QUIC mask as
                    // real datagrams, so peek through it first.
                    // Detect the QUIC mask by signature (not the profile flag): a
                    // udp-quic client wraps its junk in a QUIC long header just like its
                    // ClientHello, so the early drop must peek through it even when this
                    // profile's own `quic.enabled` is off. If detection misses, the junk
                    // still gets dropped one stage later in handle_udp_datagram (pre-crypto).
                    let is_junk = if looks_like_quic_initial(&recv_buf[..n]) {
                        unwrap_quic_payload(&recv_buf[..n])
                            .ok()
                            .map(crate::protocol::udp_frag::is_junk)
                            .unwrap_or(false)
                    } else {
                        crate::protocol::udp_frag::is_junk(&recv_buf[..n])
                    };
                    if is_junk {
                        continue;
                    }
                    let mut rl = profile.rate_limiter.lock().await;
                    if !rl.check_and_record(addr.ip()) {
                        continue;
                    }
                }

                handle_udp_datagram(
                    &server_state,
                    &profile,
                    &sessions,
                    &mut frag_pending,
                    &socket,
                    addr,
                    &recv_buf[..n],
                    worker_id,
                    &tun_tx,
                    quic_config,
                    &handshake_permits,
                    &auth_inflight,
                    &tasks,
                    obfs_key,
                )
                .await;
            }

            _ = udp_buffer_tick.tick() => {
                udp_buffer.tick(socket.raw_socket());
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled || shaping_on => {
                let now = std::time::Instant::now();
                // Collect packets to send before any .await so non-Send types (MutexGuard,
                // Obfuscator/ThreadRng) are guaranteed dropped before the async resume point.
                let to_send: Vec<(UdpEgressSnapshot, PooledBuffer, u32)> = if shaping_on {
                    // Flow-shaping: per-client Poisson idle cover (replaces heartbeat).
                    // Needs a write lock to advance each client's cover deadline + budget.
                    let mut sessions_guard = sessions.write().await;
                    let mut out = Vec::new();
                    for client in sessions_guard.values_mut() {
                        // Authenticated is not enough: the AuthOK may still be in flight on the
                        // auth task. A cover packet reaching the client first is taken for the
                        // AuthOK, decrypts into nothing, and kills the connect. See
                        // `auth_ok_sent`. (Audit 2026-08-03, P1.)
                        if !matches!(client.state, UdpSessionState::Authenticated { .. })
                            || !client.auth_ok_sent
                        {
                            continue;
                        }
                        if now < client.next_cover_at {
                            continue;
                        }
                        client.next_cover_at =
                            now + client.shaper.next_gap(&mut rand::rng());
                        // Fill genuine idle; in STEALTH run cover under load too so
                        // small cover mixes into the (rate-capped) stream.
                        if !client.shaper.stealth()
                            && now.duration_since(client.last_activity)
                                < std::time::Duration::from_millis(50)
                        {
                            continue;
                        }
                        let Some(active_egress) = client.active_egress.as_ref() else {
                            continue;
                        };
                        let egress = active_egress.snapshot();
                        let requested_size = client.shaper.next_size(&mut rand::rng());
                        let size = {
                            let tx = lock_or_recover(&client.tx_codec, "udp::cover_budget");
                            requested_size.min(egress.empty_record_padding_cap(&tx))
                        };
                        if !client.shaper.try_spend(size, now) {
                            continue;
                        }
                        let Some(mut pkt) = client
                            .wire_pool
                            .as_ref()
                            .and_then(BufferPool::try_acquire)
                        else {
                            continue;
                        };
                        let encrypted = {
                            let mut obf = Obfuscator::new();
                            obf.generate_padding_into(size as u16, size as u16, &mut padding);
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::cover");
                            let ok = tx
                                .encrypt_packet_into(&[], &padding, pkt.as_vec_mut())
                                .is_ok();
                            drop(tx);
                            ok
                        };
                        if encrypted {
                            let pn = if egress.framing.uses_packet_number() {
                                client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            } else {
                                0
                            };
                            out.push((egress, pkt, pn));
                        }
                    }
                    out
                } else {
                    let mut sessions_guard = sessions.write().await;
                    let mut out = Vec::new();
                    for client in sessions_guard.values_mut() {
                        // Only beacon AUTHENTICATED clients (a fresh AwaitingAuth entry
                        // is not a real session yet) whose AuthOK has actually gone out —
                        // this loop deliberately does NOT idle-gate (see below), so without
                        // that second condition it is the most likely thing to overtake the
                        // AuthOK. See `auth_ok_sent`. (Audit 2026-08-03, P1.)
                        if !matches!(client.state, UdpSessionState::Authenticated { .. })
                            || !client.auth_ok_sent
                        {
                            continue;
                        }
                        if idle_timeout.as_secs() > 0 && now.duration_since(client.last_activity) > idle_timeout {
                            continue;
                        }
                        if now < client.next_cover_at {
                            continue;
                        }
                        client.next_cover_at = now
                            + crate::protocol::randomized_heartbeat_delay(
                                std::time::Duration::from_millis(hb_config.interval_ms),
                                std::time::Duration::from_millis(hb_config.jitter_ms),
                            );
                        // Beacon every interval REGARDLESS of client->server activity. We
                        // must NOT idle-gate on `client.last_activity`: an idle client
                        // sends its OWN keepalives, which refresh `last_activity` and would
                        // suppress this beacon — so a fully idle tunnel got no server->client
                        // traffic and the client (whose RX-liveness counts server->client
                        // only) reconnected every rx_dead. Beaconing unconditionally fixes
                        // that; the redundant beacon under an active server->client flow is
                        // one small packet per interval — negligible.
                        let Some(active_egress) = client.active_egress.as_ref() else {
                            continue;
                        };
                        let egress = active_egress.snapshot();
                        let Some(mut pkt) = client
                            .wire_pool
                            .as_ref()
                            .and_then(BufferPool::try_acquire)
                        else {
                            continue;
                        };
                        let encrypted = {
                            let mut obf = Obfuscator::new();
                            // saturating: data_size_bytes is a u16 config knob — `+ 32`
                            // would wrap in release / panic in debug at the top of range.
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::heartbeat");
                            let cap = egress.empty_record_padding_cap(&tx).min(u16::MAX as usize) as u16;
                            let low = hb_config.data_size_bytes.min(cap);
                            let high = hb_config.data_size_bytes.saturating_add(32).min(cap);
                            obf.generate_padding_into(low, high, &mut padding);
                            let ok = tx
                                .encrypt_packet_into(&[], &padding, pkt.as_vec_mut())
                                .is_ok();
                            drop(tx);
                            ok
                        };
                        if encrypted {
                            let pn = if egress.framing.uses_packet_number() {
                                client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            } else {
                                0
                            };
                            out.push((egress, pkt, pn));
                        }
                    }
                    out
                };
                // Now we can .await freely — no non-Send types in scope
                for (egress, pkt, packet_number) in to_send {
                    let data = egress
                        .framing
                        .wrap_into(&pkt, packet_number, &mut quic_record);
                    let _ = egress.socket.send_to(data, egress.peer).await;
                }
            }

            _ = cleanup_tick.tick() => {
                let now = std::time::Instant::now();
                #[cfg(feature = "experimental-roaming")]
                {
                    // The registry is profile-wide, so whichever worker wins this maintenance
                    // tick releases every expired validation slot. Per-worker ticket hints are
                    // harmless when stale and are overwritten by the next authenticated INIT.
                    let _ = profile.udp_roaming_registry.expire_candidates();
                }
                // Heartbeat and shaping both generate authenticated client→server
                // traffic, so their cadence is a valid liveness contract. With both
                // disabled only an explicit idle_timeout is meaningful.
                let liveness_deadline = crate::protocol::liveness_deadline(
                    heartbeat_enabled,
                    std::time::Duration::from_millis(hb_config.interval_ms),
                    std::time::Duration::from_millis(hb_config.jitter_ms),
                    shaping_on,
                    std::time::Duration::from_millis(shaping_cfg.idle_gap_max_ms),
                );
                let reap_after = udp_reap_window(idle_timeout, liveness_deadline);
                let expired: Vec<SocketAddr> = {
                    let sessions_guard = sessions.read().await;
                    sessions_guard.iter()
                        .filter(|(_, c)| match &c.state {
                            UdpSessionState::AwaitingAuth => {
                                now.duration_since(c.created_at) > handshake_timeout
                            }
                            UdpSessionState::Authenticated { .. } => reap_after
                                .is_some_and(|limit| now.duration_since(c.last_activity) > limit),
                        })
                        .map(|(addr, _)| *addr)
                        .collect()
                };
                if !expired.is_empty() {
                    // Lock order (finding B): the auth path releases the per-worker
                    // `sessions` guard BEFORE taking profile.pool / profile.sessions.
                    // Collect the authenticated victims' pool/IP keys under the
                    // `sessions` write guard, drop it, then release pool + remove
                    // from profile.sessions in a second loop — same order everywhere.
                    let mut to_release: Vec<(String, std::net::IpAddr, u64)> = Vec::new();
                    {
                        let mut sessions_guard = sessions.write().await;
                        for addr in expired {
                            if let Some(client) = sessions_guard.remove(&addr) {
                                match client.state {
                                    UdpSessionState::Authenticated {
                                        session_id,
                                        device_key,
                                        client_ip,
                                        ..
                                    } => {
                                        to_release.push((device_key, client_ip, session_id));
                                    }
                                    UdpSessionState::AwaitingAuth => {
                                        log::debug!("UDP: evicted stale handshake from {} on profile '{}'", addr, profile.name);
                                    }
                                }
                            }
                        }
                    }
                    for (device_key, client_ip, session_id) in to_release {
                        // A reconnect may have reused this IP under a NEW session_id, or
                        // re-allocated the same device_key elsewhere. Guard both actions on
                        // the reaped session still being the live one — else we'd yank a
                        // live session out of by_ip / free its pool slot from under it.
                        //
                        // Join the same authoritative admission transaction as TCP teardown,
                        // admin kick, quota expiry and authentication. Merely taking `pool`
                        // before checking `profile.sessions` is insufficient: a reconnect can
                        // allocate first, drop the pool lock, and still be building AuthOK
                        // before it publishes the replacement session. A reaper in that gap
                        // sees no live device and frees the newly allocated lease. Admission
                        // covers removal, the liveness decision and release as one transition.
                        let admission_guard = profile.admission.lock().await;
                        let (device_still_live, iroutes) = {
                            let mut prof_sessions = profile.sessions.write().await;
                            let ip_still_ours = prof_sessions
                                .by_ip
                                .get(&client_ip)
                                .map(|s| s.session_id == session_id)
                                .unwrap_or(false);
                            let mut iroutes: Vec<String> = Vec::new();
                            if ip_still_ours {
                                if let Some(sess) = prof_sessions.remove(client_ip) {
                                    // Signal the UDP writer task to exit. Without kick_all it
                                    // parks forever on writer_rx (whose Sender lives in this
                                    // session), leaking the task + session on the normal
                                    // idle/dead reap path — the usual UDP teardown (no clean
                                    // close), so this leaked on essentially every dropped client.
                                    sess.kick_all();
                                    iroutes = prof_sessions.take_client_routes(client_ip);
                                    // Notify (opt-in): UDP session reaped (idle/dead — UDP has
                                    // no clean close). Guarded on session_id, so fire-once.
                                    crate::server::notify::fire_disconnect(
                                        &sess.username,
                                        &profile.name,
                                        sess.peer,
                                    );
                                }
                            }
                            let device_still_live = prof_sessions
                                .by_ip
                                .values()
                                .any(|s| s.device_key == device_key);
                            (device_still_live, iroutes)
                        };
                        if !device_still_live {
                            profile.pool.lock().await.release(&device_key);
                        }
                        // Admission must cover the kernel side of the same ownership change.
                        // Spawning this after dropping the guard lets a reconnect install the
                        // same CIDR first and then lose it to this stale `ip route del`.
                        for cidr in &iroutes {
                            let _ = crate::server::handler::program_client_subnet_route(
                                false,
                                cidr,
                                &profile.config.tun.name,
                            )
                            .await;
                        }
                        drop(admission_guard);
                    }
                }

                // Drop partially-reassembled ClientHellos that never completed (lost
                // fragment / spoofed-source flood) so the buffer can't grow unbounded.
                frag_pending
                    .retain(|_, r| r.age() < crate::protocol::udp_frag::REASSEMBLY_TIMEOUT);
            }

            _ = tokio::signal::ctrl_c() => {
                log::info!("UDP server for profile '{}' shutdown signal received", profile.name);
                break;
            }
        }
    }

    Ok(())
}

/// Send the ServerHello handshake response. A client that fragmented its ClientHello
/// (LTE/CGNAT fix) gets a fragmented response too, so no datagram needs IP
/// fragmentation; a legacy single-datagram client gets one packet, byte-identical to
/// the old behaviour. Each datagram is QUIC-wrapped with `connection_id` when enabled.
async fn send_handshake_response(
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    raw: &[u8],
    quic_enabled: bool,
    connection_id: &[u8; 4],
    fragment_it: bool,
) {
    if fragment_it {
        let frags = match crate::protocol::udp_frag::fragment(
            crate::protocol::udp_frag::MSG_SERVER_HELLO,
            raw,
        ) {
            Ok(f) => f,
            Err(e) => {
                log::error!("ServerHello too large to fragment ({e}) — dropping response");
                return;
            }
        };
        for (i, frag) in frags.into_iter().enumerate() {
            let pkt = if quic_enabled {
                // Initial, matching the single-datagram path below and every new client.
                // The receive side still accepts the historical Handshake-type spelling.
                wrap_quic_long(&frag, connection_id, i as u32)
            } else {
                frag
            };
            let _ = socket.send_to(&pkt, addr).await;
        }
    } else {
        let pkt = if quic_enabled {
            wrap_quic_long(raw, connection_id, 0)
        } else {
            raw.to_vec()
        };
        let _ = socket.send_to(&pkt, addr).await;
    }
}

/// First QUIC packet number the DATA plane may use.
///
/// The handshake numbers positionally: ServerHello is 0, the AuthOK is 1, so the session
/// starts at 2. A fragmented AuthOK consumes 1..=N instead of just 1, and the session counter
/// is pushed past them at auth time — this constant is the floor it starts from, and the
/// arithmetic tying the two together is pinned by `the_data_plane_never_reuses_an_authok_pn`.
const UDP_SESSION_FIRST_PN: u32 = 2;

/// Packet number of the FIRST AuthOK fragment; the rest follow it consecutively.
const AUTH_OK_FIRST_PN: u32 = 1;

/// Turn an encrypted AuthOK record into the datagram(s) that carry it.
///
/// One datagram whenever it fits the fragment budget — byte-identical to what every build
/// before this emitted, which is what keeps clients that predate [`MSG_AUTH_OK`] working. Over
/// the budget it is split, because the alternative is what shipped: a single oversized
/// datagram that an IP-fragment-dropping path (mobile, CGNAT) silently destroys, leaving the
/// client to time out at the AUTHENTICATION step with nothing in either log to say why.
/// (Audit 2026-08-02, §4.)
///
/// Layering matches [`send_handshake_response`]: split first, then QUIC-wrap each fragment
/// separately, so no datagram ever needs IP fragmentation. The AuthOK is post-handshake, so
/// it uses the SHORT header the data plane uses, not the long one — and each fragment gets
/// its own packet number for the same reason the ServerHello's do.
///
/// `Err` only if the record needs more than `MAX_FRAGS` fragments (~28 KB of pushed routes),
/// which the receiver would reject anyway; the caller reports it instead of emitting a
/// message the client silently drops.
fn build_auth_ok_datagrams(
    record: &[u8],
    quic_enabled: bool,
    connection_id: &[u8; 4],
) -> Result<Vec<Vec<u8>>, &'static str> {
    use crate::protocol::udp_frag;
    if record.len() <= udp_frag::MAX_CHUNK {
        return Ok(vec![if quic_enabled {
            wrap_quic_short(record, connection_id, AUTH_OK_FIRST_PN)
        } else {
            record.to_vec()
        }]);
    }
    let frags = udp_frag::fragment(udp_frag::MSG_AUTH_OK, record)?;
    Ok(frags
        .into_iter()
        .enumerate()
        .map(|(i, frag)| {
            if quic_enabled {
                wrap_quic_short(&frag, connection_id, AUTH_OK_FIRST_PN + i as u32)
            } else {
                frag
            }
        })
        .collect())
}

fn build_auth_error_datagrams(
    tx_codec: &mut PacketCodec,
    reason: &str,
    quic_enabled: bool,
    connection_id: &[u8; 4],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let message = handler::build_auth_error(reason);
    let record = tx_codec.encrypt_packet(message.as_bytes(), &[])?;
    build_auth_ok_datagrams(&record, quic_enabled, connection_id).map_err(anyhow::Error::msg)
}

#[cfg(feature = "experimental-roaming")]
fn note_udp_roaming_route_failure(
    profile: &ProfileRuntime,
    failure: crate::transport_core::udp_roaming::UdpWorkerRouteFailure<UdpRoamingDatagram>,
) {
    use crate::transport_core::udp_roaming::UdpWorkerRouteError;

    let kind = failure.kind();
    drop(failure.into_payload());
    match kind {
        UdpWorkerRouteError::QueueFull => profile
            .udp_buffer_counters
            .note_internal_drop(InternalDrop::QueueFull),
        UdpWorkerRouteError::WorkerClosed => log::warn!(
            "UDP roaming ingress dropped on profile '{}': owner worker is closed",
            profile.name
        ),
        UdpWorkerRouteError::InvalidTopology | UdpWorkerRouteError::UnknownWorker => log::error!(
            "UDP roaming ingress dropped on profile '{}': invalid worker topology",
            profile.name
        ),
        UdpWorkerRouteError::UnknownCid => {
            // The receive path performs the same lookup before routing. Reaching this branch
            // means teardown won the race, which is a normal fail-closed outcome.
        }
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpRoamingControlError {
    FragmentNotNegotiated,
    FragmentPending,
    BadFragment,
    PoolExhausted,
    Oversize,
    Decrypt,
    BadControl,
    FragmentedControl,
    UnexpectedDirection,
}

#[cfg(feature = "experimental-roaming")]
struct UdpRoamingControlIngress {
    message_id: u32,
    message: crate::protocol::roaming::PathControl,
}

#[cfg(feature = "experimental-roaming")]
enum UdpRoamingIngress {
    Control(UdpRoamingControlIngress),
    Data(PooledBuffer),
}

#[cfg(feature = "experimental-roaming")]
enum UdpRoamingDispatch {
    Control(UdpRoamingControlIngress),
    Uplink(UdpPreparedUplink),
}

/// Decrypt one session-wide record exactly once. `None` is authenticated ordinary data;
/// path-control frames are parsed strictly here so malformed or server-direction control can
/// never fall through into the TUN path after advancing the replay window.
#[cfg(feature = "experimental-roaming")]
fn decrypt_udp_roaming_record(
    codec: &mut PacketCodec,
    record: &mut Vec<u8>,
) -> Result<Option<UdpRoamingControlIngress>, UdpRoamingControlError> {
    codec
        .decrypt_packet_in_place(record)
        .map_err(|_| UdpRoamingControlError::Decrypt)?;
    if !crate::protocol::control_v2::is_control_v2(record) {
        return Ok(None);
    }
    let frame = crate::protocol::control_v2::decode(record)
        .map_err(|_| UdpRoamingControlError::BadControl)?;
    if frame.flags != 0 || frame.part_index != 0 || frame.part_count != 1 {
        return Err(UdpRoamingControlError::FragmentedControl);
    }
    let message = crate::protocol::roaming::PathControl::decode(frame.message_type, frame.payload)
        .map_err(|_| UdpRoamingControlError::BadControl)?;
    if !matches!(
        &message,
        crate::protocol::roaming::PathControl::Init { .. }
            | crate::protocol::roaming::PathControl::Response { .. }
    ) {
        return Err(UdpRoamingControlError::UnexpectedDirection);
    }
    Ok(Some(UdpRoamingControlIngress {
        message_id: frame.message_id,
        message,
    }))
}

#[cfg(feature = "experimental-roaming")]
fn decode_udp_roaming_ingress(
    client: &mut UdpClient,
    encrypted_payload: &[u8],
    pool: &BufferPool,
) -> Result<UdpRoamingIngress, UdpRoamingControlError> {
    let reassembled_record;
    let record = if crate::protocol::data_frag::is_data_fragment(encrypted_payload) {
        if !client.data_frag_enabled {
            return Err(UdpRoamingControlError::FragmentNotNegotiated);
        }
        match client
            .data_reassembler
            .push(encrypted_payload, &client.rx_data_frag_key)
        {
            Ok(Some(record)) => {
                reassembled_record = record;
                reassembled_record.as_slice()
            }
            Ok(None) => return Err(UdpRoamingControlError::FragmentPending),
            Err(_) => return Err(UdpRoamingControlError::BadFragment),
        }
    } else {
        encrypted_payload
    };
    let Some(mut plaintext) = pool.try_acquire() else {
        return Err(UdpRoamingControlError::PoolExhausted);
    };
    if record.len() > plaintext.capacity() {
        return Err(UdpRoamingControlError::Oversize);
    }
    plaintext.as_vec_mut().extend_from_slice(record);
    let control = {
        let mut codec = lock_or_recover(&client.rx_codec, "udp::roaming_decrypt");
        decrypt_udp_roaming_record(&mut codec, plaintext.as_vec_mut())?
    };
    Ok(match control {
        Some(control) => UdpRoamingIngress::Control(control),
        None => UdpRoamingIngress::Data(plaintext),
    })
}

#[cfg(feature = "experimental-roaming")]
struct UdpPreparedUplink {
    first: Option<ServerTunPacket>,
    extra: Vec<ServerTunPacket>,
    session_id: u64,
    exit_access: crate::server::ExitAccess,
    path_mtu: Option<Arc<std::sync::atomic::AtomicU32>>,
    udp_payload_budget: Option<Arc<std::sync::atomic::AtomicU32>>,
    client_info: Option<crate::server::handler::ClientInfoCell>,
    src_guard: Option<crate::server::acl::SrcGuard>,
    dst_acl: crate::server::acl::DstAcl,
    bandwidth_limit: Option<Arc<std::sync::atomic::AtomicU32>>,
    upload_tx: Option<mpsc::Sender<ServerTunPacket>>,
    recv_ctr: Arc<std::sync::atomic::AtomicU64>,
    client_dropped: Arc<std::sync::atomic::AtomicU64>,
}

/// Convert one authenticated plaintext record into the same bounded uplink work used by the
/// legacy source-address path. Recordizer output stays pool-backed and all mutable codec state is
/// consumed while the session-directory lock is held by the caller.
#[cfg(feature = "experimental-roaming")]
fn prepare_udp_roaming_uplink(
    client: &mut UdpClient,
    plaintext: PooledBuffer,
    pool: &BufferPool,
    profile: &ProfileRuntime,
    addr: SocketAddr,
) -> Option<UdpPreparedUplink> {
    let session_id = client.authenticated_session_id()?;
    let recordizer_active = client.rx_recordizer.is_some();
    let mut decoded_first = None;
    let mut decoded_extra = Vec::new();
    if recordizer_active && !plaintext.is_empty() {
        let mut pool_exhausted_drops = 0_u64;
        let mut oversize_drops = 0_u64;
        let decode_result = client
            .rx_recordizer
            .as_mut()
            .expect("recordizer presence was checked")
            .decode_with(&plaintext, |bytes| {
                let Some(mut packet) = pool.try_acquire() else {
                    pool_exhausted_drops = pool_exhausted_drops.saturating_add(1);
                    return;
                };
                if bytes.len() > packet.capacity() {
                    oversize_drops = oversize_drops.saturating_add(1);
                    return;
                }
                packet.as_vec_mut().extend_from_slice(bytes);
                let packet = ServerTunPacket::Pooled(packet);
                if decoded_first.is_none() {
                    decoded_first = Some(packet);
                } else {
                    decoded_extra.push(packet);
                }
            });
        let total_drops = pool_exhausted_drops.saturating_add(oversize_drops);
        client
            .dropped
            .fetch_add(total_drops, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..pool_exhausted_drops {
            profile
                .udp_buffer_counters
                .note_internal_drop(InternalDrop::PoolExhausted);
        }
        for _ in 0..oversize_drops {
            profile
                .udp_buffer_counters
                .note_internal_drop(InternalDrop::Oversize);
        }
        if let Err(error) = decode_result {
            log::debug!(
                "UDP roaming recordizer decode error from {} on profile '{}': {}",
                addr,
                profile.name,
                error
            );
            return None;
        }
    }
    let first = if recordizer_active {
        drop(plaintext);
        decoded_first
    } else {
        Some(ServerTunPacket::Pooled(plaintext))
    };
    client.last_activity = std::time::Instant::now();
    Some(UdpPreparedUplink {
        first,
        extra: decoded_extra,
        session_id,
        exit_access: client.exit_access,
        path_mtu: client.path_mtu.clone(),
        udp_payload_budget: client.udp_payload_budget.clone(),
        client_info: client.client_info.clone(),
        src_guard: client.src_guard.clone(),
        dst_acl: client.dst_acl.clone(),
        bandwidth_limit: client.bandwidth_limit_mbps.clone(),
        upload_tx: client.upload_tx.clone(),
        recv_ctr: client.bytes_recv.clone(),
        client_dropped: client.dropped.clone(),
    })
}

#[cfg(feature = "experimental-roaming")]
#[allow(clippy::too_many_arguments)] // mirrors the established UDP uplink forwarding context
async fn forward_udp_roaming_uplink(
    prepared: UdpPreparedUplink,
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    tasks: &super::ProfileTasks,
    profile: &Arc<ProfileRuntime>,
    addr: SocketAddr,
    obfs_key: Option<[u8; 32]>,
    tun_tx: &TunIngress,
) {
    let UdpPreparedUplink {
        first,
        extra,
        session_id,
        exit_access,
        path_mtu,
        udp_payload_budget,
        client_info,
        src_guard,
        dst_acl,
        bandwidth_limit,
        upload_tx,
        recv_ctr,
        client_dropped,
    } = prepared;
    for packet in first.into_iter().chain(extra) {
        forward_udp_uplink_packet(
            packet,
            sessions,
            tasks,
            profile,
            addr,
            obfs_key,
            session_id,
            exit_access,
            tun_tx,
            &path_mtu,
            &udp_payload_budget,
            &client_info,
            &src_guard,
            &dst_acl,
            &bandwidth_limit,
            &upload_tx,
            &recv_ctr,
            &client_dropped,
        )
        .await;
    }
}

#[cfg(feature = "experimental-roaming")]
fn random_udp_path_challenge() -> [u8; crate::protocol::roaming::PATH_CHALLENGE_LEN] {
    loop {
        let token = rand::random();
        if token != [0; crate::protocol::roaming::PATH_CHALLENGE_LEN] {
            return token;
        }
    }
}

#[cfg(feature = "experimental-roaming")]
fn encrypt_udp_roaming_control(
    tx_codec: &Arc<std::sync::Mutex<PacketCodec>>,
    packet_counter: &std::sync::atomic::AtomicU32,
    destination_cid: [u8; crate::protocol::roaming::CID_LEN],
    message_id: u32,
    message: &crate::protocol::roaming::PathControl,
) -> anyhow::Result<Vec<u8>> {
    let mut frames = crate::protocol::control_v2::fragment_message(
        message.message_type(),
        0,
        message_id,
        &message.encode_body(),
    )?;
    anyhow::ensure!(
        frames.len() == 1,
        "fixed UDP path control unexpectedly required fragmentation"
    );
    let frame = frames
        .pop()
        .expect("a fixed UDP path control produces one frame");
    let record = {
        let mut codec = lock_or_recover(tx_codec, "udp::roaming_encrypt");
        codec.encrypt_packet(&frame, &[])?
    };
    let packet_number = packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(
        crate::protocol::roaming::UdpShortHeader::new(destination_cid, packet_number)
            .encode(&record),
    )
}

#[cfg(feature = "experimental-roaming")]
async fn handle_udp_roaming_ingress(
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    worker_id: usize,
    tun_tx: &TunIngress,
    tasks: &super::ProfileTasks,
    obfs_key: Option<[u8; 32]>,
    routed: crate::transport_core::udp_roaming::UdpRoutedIngress<UdpRoamingDatagram>,
) {
    let lookup = routed.lookup();
    let received_path = routed.received_path();
    if usize::try_from(lookup.owner_worker_id()).ok() != Some(worker_id) {
        log::error!(
            "UDP roaming ingress reached the wrong owner worker on profile '{}'",
            profile.name
        );
        return;
    }
    let owner_address = {
        let guard = sessions.read().await;
        guard.resolve_roaming_owner(lookup)
    };
    let Some(owner_address) = owner_address else {
        // The directory and registry are independently generation-checked. Teardown between
        // route and mailbox delivery therefore becomes a silent stale-packet drop.
        return;
    };

    let outer_packet_number = routed.packet_number();
    let envelope = routed.into_payload();
    let local_family_matches = envelope
        .socket
        .raw_socket()
        .local_addr()
        .is_ok_and(|local| local.is_ipv4() == received_path.peer().is_ipv4());
    if !local_family_matches {
        log::error!(
            "UDP roaming ingress has inconsistent socket/address family on profile '{}'",
            profile.name
        );
        return;
    }
    let roaming_payload = &envelope.datagram[crate::protocol::roaming::UDP_SHORT_HEADER_LEN..];
    let action = {
        let mut guard = sessions.write().await;
        let revoked = guard
            .get(&owner_address)
            .and_then(|client| client.revoked.as_ref())
            .is_some_and(|revoked| revoked.load(std::sync::atomic::Ordering::Relaxed));
        if revoked {
            guard.remove(&owner_address);
            return;
        }
        let Some(client) = guard.get_mut(&owner_address).filter(|client| {
            client.auth_ok_sent
                && client
                    ._udp_roaming_registration
                    .as_ref()
                    .is_some_and(|registration| registration.matches_lookup(lookup))
        }) else {
            return;
        };
        let Some(active_egress) = client.active_egress.as_ref() else {
            log::error!(
                "UDP roaming ingress rejected on profile '{}': authenticated session has no active egress",
                profile.name
            );
            return;
        };
        let Some(ingress_path) = active_egress.classify_roaming_ingress(
            lookup.path_epoch(),
            received_path.peer(),
            &envelope.socket,
        ) else {
            log::debug!(
                "UDP roaming ingress rejected on profile '{}': CID epoch or receiving path is stale",
                profile.name
            );
            return;
        };
        // Bare PMTU probes share the negotiated directional CID framing but deliberately are not
        // PacketCodec records. Handle them only after the CID resolved this session and the exact
        // current epoch/socket/peer was classified as committed. A candidate path still carries
        // authenticated PATH_* only, so this exception cannot bypass return-path validation or
        // its anti-amplification budget.
        if crate::protocol::udp_frag::is_mtu_probe_ack_v2(roaming_payload) {
            if ingress_path != UdpRoamingIngressPath::Committed {
                return;
            }
            let certified = crate::protocol::udp_frag::parse_mtu_probe_v2_ack(roaming_payload)
                .and_then(|(token, payload_size)| {
                    let mut pending =
                        lock_or_recover(&client.downlink_mtu_probe, "udp::downlink_probe_ack");
                    let expected = (*pending)?;
                    if expected.token != token
                        || expected.payload_size != payload_size
                        || expected.path_epoch != lookup.path_epoch()
                        || expected.peer != received_path.peer()
                    {
                        return None;
                    }
                    *pending = None;
                    client
                        .udp_payload_budget
                        .as_ref()
                        .map(|cell| (cell.clone(), expected))
                });
            if let Some((cell, expected)) = certified {
                note_certified_udp_payload_budget(
                    active_egress,
                    &cell,
                    format_args!("at {}", received_path.peer()),
                    expected,
                );
            }
            return;
        }
        // The 16-bit ACK is the response to the client-driven uplink ladder. It is consumed by
        // the client's receive loop, never by the server; a replay arriving here is carrier
        // control rather than an encrypted tunnel record.
        if crate::protocol::udp_frag::is_mtu_probe_ack(roaming_payload) {
            return;
        }
        let roaming_pmtu_ack =
            match classify_udp_roaming_uplink_probe(roaming_payload, ingress_path) {
                UdpRoamingPmtuAction::NotProbe => None,
                UdpRoamingPmtuAction::Drop => return,
                UdpRoamingPmtuAction::Ack(ack) => Some(ack),
            };
        if let Some(ack) = roaming_pmtu_ack {
            let egress = active_egress.snapshot();
            // Classification above pins the exact receiving path. Recheck the immutable
            // snapshot used to build/send the ACK so a future refactor cannot combine a
            // current CID with another socket or peer.
            if egress.path_epoch != lookup.path_epoch()
                || egress.peer != received_path.peer()
                || !Arc::ptr_eq(&egress.socket, &envelope.socket)
            {
                return;
            }
            let packet_number = client
                .packet_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut wrapped = Vec::with_capacity(egress.framing.wrapper_len() + ack.len());
            let packet = egress.framing.wrap_into(&ack, packet_number, &mut wrapped);
            if let Err(error) = egress.socket.try_send_to(packet, egress.peer) {
                log::trace!(
                    "UDP roaming PMTU probe ACK send failed on profile '{}' to {}: {}",
                    profile.name,
                    egress.peer,
                    error
                );
            }
            return;
        }
        match decode_udp_roaming_ingress(client, roaming_payload, &tun_tx.pool) {
            Ok(UdpRoamingIngress::Control(control)) => {
                if ingress_path == UdpRoamingIngressPath::Draining {
                    // Previous-path receive drain exists only for already in-flight DATA and
                    // DATA_FRAG. Control and PMTU must act on the committed/candidate path.
                    return;
                }
                // Candidate liveness is authenticated only after PacketCodec accepted the
                // record and advanced the one session-wide replay window.
                client.last_activity = std::time::Instant::now();
                UdpRoamingDispatch::Control(control)
            }
            Ok(UdpRoamingIngress::Data(plaintext)) => {
                if ingress_path == UdpRoamingIngressPath::Candidate {
                    log::debug!(
                        "UDP roaming DATA rejected on profile '{}': candidate CID may carry only path control",
                        profile.name
                    );
                    return;
                }
                let Some(prepared) = prepare_udp_roaming_uplink(
                    client,
                    plaintext,
                    &tun_tx.pool,
                    profile,
                    received_path.peer(),
                ) else {
                    return;
                };
                UdpRoamingDispatch::Uplink(prepared)
            }
            Err(UdpRoamingControlError::FragmentPending) => return,
            Err(error) => {
                if matches!(
                    error,
                    UdpRoamingControlError::PoolExhausted | UdpRoamingControlError::Oversize
                ) {
                    client
                        .dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                match error {
                    UdpRoamingControlError::PoolExhausted => profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::PoolExhausted),
                    UdpRoamingControlError::Oversize => profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::Oversize),
                    _ => {}
                }
                log::debug!(
                    "UDP roaming ingress rejected on profile '{}' ({error:?})",
                    profile.name
                );
                return;
            }
        }
    };
    let control = match action {
        UdpRoamingDispatch::Control(control) => control,
        UdpRoamingDispatch::Uplink(prepared) => {
            forward_udp_roaming_uplink(
                prepared,
                sessions,
                tasks,
                profile,
                received_path.peer(),
                obfs_key,
                tun_tx,
            )
            .await;
            return;
        }
    };
    match control.message {
        crate::protocol::roaming::PathControl::Init { cid, epoch } => {
            let challenge = match profile
                .udp_roaming_registry
                .observe_authenticated_candidate(
                    lookup,
                    received_path,
                    &cid,
                    epoch,
                    envelope.datagram.len(),
                    random_udp_path_challenge(),
                ) {
                Ok(challenge) => challenge,
                Err(error) => {
                    log::debug!(
                        "UDP PATH_INIT rejected on profile '{}' ({error})",
                        profile.name
                    );
                    return;
                }
            };
            let ticket = challenge.ticket();
            let response = crate::protocol::roaming::PathControl::Challenge {
                epoch,
                token: *challenge.token(),
            };
            let wire = {
                let mut guard = sessions.write().await;
                let Some(client) = guard.get_mut(&owner_address).filter(|client| {
                    client
                        ._udp_roaming_registration
                        .as_ref()
                        .is_some_and(|registration| registration.matches_lookup(lookup))
                }) else {
                    profile.udp_roaming_registry.abort_candidate(ticket);
                    return;
                };
                client.udp_roaming_candidate = Some(ticket);
                encrypt_udp_roaming_control(
                    &client.tx_codec,
                    &client.packet_counter,
                    cid,
                    control.message_id,
                    &response,
                )
            };
            let wire = match wire {
                Ok(wire) => wire,
                Err(error) => {
                    profile.udp_roaming_registry.abort_candidate(ticket);
                    let mut guard = sessions.write().await;
                    if let Some(client) = guard.get_mut(&owner_address) {
                        if client.udp_roaming_candidate == Some(ticket) {
                            client.udp_roaming_candidate = None;
                        }
                    }
                    log::warn!(
                        "UDP PATH_CHALLENGE build failed on profile '{}': {}",
                        profile.name,
                        error
                    );
                    return;
                }
            };
            let accounted_wire_bytes = wire.len().saturating_add(envelope.socket.seal_overhead());
            if let Err(error) = profile
                .udp_roaming_registry
                .authorize_candidate_send(ticket, accounted_wire_bytes)
            {
                if !matches!(
                    &error,
                    crate::transport_core::udp_roaming::UdpRoamingError::AmplificationLimit
                ) {
                    let mut guard = sessions.write().await;
                    if let Some(client) = guard.get_mut(&owner_address) {
                        if client.udp_roaming_candidate == Some(ticket) {
                            client.udp_roaming_candidate = None;
                        }
                    }
                }
                log::debug!(
                    "UDP PATH_CHALLENGE suppressed on profile '{}' ({error})",
                    profile.name
                );
                return;
            }
            if let Err(error) = envelope.socket.send_to(&wire, received_path.peer()).await {
                log::debug!(
                    "UDP PATH_CHALLENGE send failed on profile '{}': {}",
                    profile.name,
                    error
                );
                return;
            }
            log::info!(
                "UDP PATH_CHALLENGE sent by owner worker {} on profile '{}' to {} at epoch {} (message {}, outer packet {})",
                worker_id,
                profile.name,
                received_path.peer(),
                epoch,
                control.message_id,
                outer_packet_number
            );
        }
        crate::protocol::roaming::PathControl::Response { epoch, token } => {
            let new_peer = received_path.peer();
            let safe_payload_budget = u16::try_from(
                crate::protocol::data_frag::conservative_udp_payload_budget(new_peer.is_ipv6()),
            )
            .expect("conservative UDP payload budget fits u16");
            let replayed = {
                let mut guard = sessions.write().await;
                if new_peer != owner_address && guard.contains_key(&new_peer) {
                    log::warn!(
                        "UDP PATH_RESPONSE rejected on profile '{}': candidate address already owns another session",
                        profile.name
                    );
                    return;
                }
                let Some(client) = guard.get(&owner_address).filter(|client| {
                    client
                        ._udp_roaming_registration
                        .as_ref()
                        .is_some_and(|registration| registration.matches_lookup(lookup))
                }) else {
                    return;
                };
                let Some(ticket) = client.udp_roaming_candidate else {
                    log::debug!(
                        "UDP PATH_RESPONSE rejected on profile '{}': no matching candidate ticket",
                        profile.name
                    );
                    return;
                };
                let Some(active_egress) = client.active_egress.clone() else {
                    log::error!(
                        "UDP PATH_RESPONSE rejected on profile '{}': authenticated session has no active egress",
                        profile.name
                    );
                    return;
                };
                let Some(payload_budget) = client.udp_payload_budget.clone() else {
                    log::error!(
                        "UDP PATH_RESPONSE rejected on profile '{}': roaming session has no shared payload budget",
                        profile.name
                    );
                    return;
                };
                let tx_codec = client.tx_codec.clone();
                let packet_counter = client.packet_counter.clone();
                let decision = match profile
                    .udp_roaming_registry
                    .validate_response_and_commit_with(
                        ticket,
                        received_path,
                        epoch,
                        &token,
                        envelope.datagram.len(),
                        safe_payload_budget,
                        |outcome| -> anyhow::Result<()> {
                            let commit =
                                UdpEgressCommit::from_outcome(outcome, envelope.socket.clone())
                                    .map_err(|error| {
                                        anyhow::anyhow!("invalid UDP egress commit: {error:?}")
                                    })?;
                            let response = crate::protocol::roaming::PathControl::Commit {
                                cid: *outcome.receive_cid(),
                                epoch: outcome.path_epoch(),
                            };
                            active_egress
                                .commit_roaming_with(
                                    commit,
                                    &payload_budget,
                                    |socket, peer| -> anyhow::Result<()> {
                                        let wire = encrypt_udp_roaming_control(
                                            &tx_codec,
                                            &packet_counter,
                                            *outcome.transmit_cid(),
                                            control.message_id,
                                            &response,
                                        )?;
                                        socket.try_send_to(&wire, peer)?;
                                        Ok(())
                                    },
                                )
                                .map_err(|error| match error {
                                    UdpEgressPublishError::State(error) => anyhow::anyhow!(
                                        "atomic PATH_COMMIT state validation failed: {error:?}"
                                    ),
                                    UdpEgressPublishError::Publish(error) => anyhow::anyhow!(
                                        "atomic PATH_COMMIT socket publication failed: {error:?}"
                                    ),
                                })
                        },
                    ) {
                    Ok(decision) => decision,
                    Err(crate::transport_core::udp_roaming::UdpRoamingCommitError::State(
                        error,
                    )) => {
                        log::debug!(
                            "UDP PATH_RESPONSE rejected on profile '{}' ({error})",
                            profile.name
                        );
                        return;
                    }
                    Err(crate::transport_core::udp_roaming::UdpRoamingCommitError::Publish(
                        error,
                    )) => {
                        log::warn!(
                            "UDP PATH_RESPONSE could not publish egress on profile '{}' ({error:?})",
                            profile.name
                        );
                        return;
                    }
                };
                if !decision.is_replay() {
                    active_egress.schedule_draining_ingress_expiry();
                }
                let outcome = decision.outcome();
                if decision.is_replay() {
                    let response = crate::protocol::roaming::PathControl::Commit {
                        cid: *outcome.receive_cid(),
                        epoch: outcome.path_epoch(),
                    };
                    let replay = encrypt_udp_roaming_control(
                        &tx_codec,
                        &packet_counter,
                        *outcome.transmit_cid(),
                        control.message_id,
                        &response,
                    )
                    .and_then(|wire| {
                        envelope
                            .socket
                            .try_send_to(&wire, new_peer)
                            .map_err(anyhow::Error::from)
                    });
                    if let Err(error) = replay {
                        log::warn!(
                            "UDP PATH_COMMIT replay failed on profile '{}': {}",
                            profile.name,
                            error
                        );
                        return;
                    }
                }
                if owner_address != new_peer {
                    let Some(client) = guard.remove(&owner_address) else {
                        log::error!(
                            "UDP PATH_COMMIT lost its directory owner on profile '{}'",
                            profile.name
                        );
                        return;
                    };
                    let replaced = guard.insert(new_peer, client);
                    debug_assert!(replaced.is_none(), "candidate address was preflighted");
                    guard.roaming_owners.publish(
                        lookup.session_id(),
                        lookup.session_generation(),
                        new_peer,
                    );
                }
                decision.is_replay()
            };
            log::info!(
                "UDP PATH_COMMIT {} by owner worker {} on profile '{}' to {} at epoch {} (message {}, outer packet {})",
                if replayed { "replayed" } else { "sent" },
                worker_id,
                profile.name,
                new_peer,
                epoch,
                control.message_id,
                outer_packet_number
            );
        }
        _ => unreachable!("client direction was checked by the authenticated decoder"),
    }
}

#[allow(clippy::too_many_arguments)] // datagram dispatch threads the shared UDP state
async fn handle_udp_datagram(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    frag_pending: &mut HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    data: &[u8],
    worker_id: usize,
    tun_tx: &TunIngress,
    quic_config: &QuicMaskingConfig,
    handshake_permits: &Arc<Semaphore>,
    auth_inflight: &Arc<tokio::sync::Mutex<std::collections::HashSet<SocketAddr>>>,
    tasks: &super::ProfileTasks,
    obfs_key: Option<[u8; 32]>,
) {
    // Decide whether this datagram is QUIC-masked. For an ESTABLISHED session we honour
    // the choice recorded at handshake time — a QUIC data packet is a short header over
    // ciphertext and cannot be classified by signature. For a BRAND-NEW source we
    // classify by the first packet's signature (a QUIC v1 long-header Initial), so a
    // udp-quic client is accepted even when THIS profile's own `quic.enabled` is off:
    // the server mirrors the client's choice for the whole connection, exactly like it
    // already does for fragmentation. `quic.enabled` now only governs whether the server
    // stamps `quic=1` into the qeli:// links it generates. (#69)
    let session_quic = {
        let guard = sessions.read().await;
        guard.get(&addr).map(|c| c.quic_enabled)
    };
    let treat_as_quic = match session_quic {
        Some(q) => q,
        None => looks_like_quic_initial(data),
    };
    let (payload, quic_detected) = if treat_as_quic {
        match unwrap_quic_payload(data) {
            Ok(payload) => (payload, true),
            Err(e) => {
                log::debug!(
                    "UDP drop from {} on profile '{}': QUIC unwrap failed ({})",
                    addr,
                    profile.name,
                    e
                );
                return;
            }
        }
    } else {
        (data, false)
    };

    // AWG junk decoy — carries no real data. The receive loop already drops junk from
    // a brand-new source before the rate limiter; this also catches junk that arrived
    // reordered AFTER the first ClientHello fragment (is_new_session was false then),
    // so it is never fed to the per-source reassembler.
    if crate::protocol::udp_frag::is_junk(payload) {
        return;
    }

    // Reverse PMTU ACK: only an exact response to the one outstanding server→client probe
    // may widen this session. It is deliberately handled before PacketCodec because the
    // full-size probe/short ACK exchange is carrier framing, not encrypted inner traffic.
    if crate::protocol::udp_frag::is_mtu_probe_ack_v2(payload) {
        let certified = if let Some((token, payload_size)) =
            crate::protocol::udp_frag::parse_mtu_probe_v2_ack(payload)
        {
            let guard = sessions.read().await;
            guard.get(&addr).and_then(|client| {
                let active_egress = client.active_egress.as_ref()?.clone();
                let mut pending =
                    lock_or_recover(&client.downlink_mtu_probe, "udp::downlink_probe_ack");
                let expected = (*pending)?;
                if expected.token != token
                    || expected.payload_size != payload_size
                    || expected.peer != addr
                {
                    return None;
                }
                *pending = None;
                client
                    .udp_payload_budget
                    .as_ref()
                    .map(|cell| (active_egress, cell.clone(), expected))
            })
        } else {
            None
        };
        if let Some((active_egress, cell, expected)) = certified {
            note_certified_udp_payload_budget(
                &active_egress,
                &cell,
                format_args!("at {addr}"),
                expected,
            );
        }
        return;
    }
    // Legacy ACKs from older client-driven uplink ladders are never sufficient proof for
    // widening the opposite direction. Drop them as carrier frames.
    if crate::protocol::udp_frag::is_mtu_probe_ack(payload) {
        return;
    }

    // Current client-to-server PMTU probe. Echo the exact 128-bit token and size only for an
    // authenticated session, preventing a blind source-spoofing attacker from certifying an
    // oversized uplink budget by guessing the former 16-bit id.
    if crate::protocol::udp_frag::is_mtu_probe_v2(payload) {
        if let Some((token, size)) = crate::protocol::udp_frag::parse_mtu_probe_v2_request(payload)
        {
            let wrap = {
                let guard = sessions.read().await;
                guard.get(&addr).map(|client| {
                    let packet_number = client
                        .packet_counter
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (client.quic_enabled, client.connection_id, packet_number)
                })
            };
            if let Some((quic, cid, packet_number)) = wrap {
                let ack = crate::protocol::udp_frag::mtu_probe_v2_ack_datagram(token, size);
                let packet = if quic {
                    wrap_quic_short(&ack, &cid, packet_number)
                } else {
                    ack
                };
                let _ = socket.send_to(&packet, addr).await;
            }
        }
        return;
    }

    // Path-MTU probe (client→server): echo a tiny ACK carrying the same id+size so the
    // client's probe ladder learns which datagram sizes traverse the path unfragmented.
    // A probe is NOT an AEAD data packet — echo and STOP before the decrypt below (its
    // oversized chunk would also be rejected by the reassembler). Only a known session
    // is echoed (gates it to an authenticated peer); the ACK is QUIC-wrapped with the
    // session's connection id + next packet number, exactly like the heartbeat reply.
    if crate::protocol::udp_frag::is_mtu_probe(payload) {
        if let Some((id, size)) = crate::protocol::udp_frag::parse_mtu_probe_request(payload) {
            let wrap = {
                let guard = sessions.read().await;
                guard.get(&addr).map(|c| {
                    let pn = c
                        .packet_counter
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (c.quic_enabled, c.connection_id, pn)
                })
            };
            if let Some((quic, cid, pn)) = wrap {
                let ack = crate::protocol::udp_frag::mtu_probe_ack_datagram(id, size);
                let pkt = if quic {
                    wrap_quic_short(&ack, &cid, pn)
                } else {
                    ack
                };
                let _ = socket.send_to(&pkt, addr).await;
            }
        }
        return;
    }

    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            // Idempotent handshake re-emit BEFORE decrypt: a lost server->client
            // handshake datagram (ServerHello or AuthOK) leaves the client
            // retransmitting its request, which the normal path drops — a
            // retransmitted ClientHello is a plaintext fragment that fails AEAD, and a
            // retransmitted AUTH is an exact replay the window rejects. Detect the
            // retransmit and re-send the CACHED response so the client recovers in
            // ~1 RTT instead of stalling the full connection_timeout before a
            // fresh-port reconnect. This never creates or mutates crypto state.
            // Everything this source sends counts toward its budget, including the
            // datagrams that trigger a re-emit — otherwise the trigger would be free.
            // `data` is the datagram after transparent obfs-open but before QUIC-unwrap; see
            // the note on `amp_received` for what the two counters do and do not include.
            client.amp_received = client.amp_received.saturating_add(data.len() as u64);

            let reemit_auth_response =
                !client.auth_ok.is_empty() && payload == client.auth_request.as_slice();
            let reemit_hello = !reemit_auth_response
                && matches!(client.state, UdpSessionState::AwaitingAuth)
                && crate::protocol::udp_frag::is_fragment(payload);
            if reemit_hello || reemit_auth_response {
                // NOTE: `last_activity` is deliberately NOT touched here — see below.
                let hello = client.server_hello.clone();
                let cid = client.connection_id;
                let quic = client.quic_enabled;
                let frag = client.hello_frag_mode;
                let authok = client.auth_ok.clone();
                // Every fragment goes back on the wire, so every fragment is charged.
                //
                // Note the asymmetry: the AuthOK is cached AS DATAGRAMS, so summing them is
                // exact, while the ServerHello is cached as the MESSAGE and re-fragmented and
                // re-wrapped on the way out — its charge therefore misses the per-datagram
                // QUIC/obfs headers. Undercounting what we send is the loose direction; see
                // the note on `amp_received` for why that slack is accepted rather than
                // plumbed away.
                let reply_len: u64 = if reemit_hello {
                    hello.len() as u64
                } else {
                    authok.iter().map(|d| d.len() as u64).sum()
                };
                // Two different instruments, because the two paths carry different risk.
                //
                // ServerHello (half-open, source UNVERIFIED): the cumulative 3× bound. The
                // trigger can be a 6-byte datagram, so without it this is a ~500× reflector
                // for a spoofed source — the exact property the initial check exists to deny.
                //
                // AuthOK (session AUTHENTICATED): a count cap instead. Return-routability is
                // already proven here, and the byte bound actively breaks the recovery path
                // for a large pushed-route set — several KB of AuthOK cannot be earned back
                // by ~350-byte AUTH retransmits inside the handshake deadline, so the client
                // would sit there re-asking for a reply it is never allowed to receive.
                // (Audit 2026-08-02, §4.)
                if reemit_hello {
                    let over_budget = client.amp_sent.saturating_add(reply_len)
                        > client.amp_received.saturating_mul(3);
                    if over_budget {
                        log::debug!(
                            "UDP {}: suppressing handshake re-emit — would exceed the 3x \
                             anti-amplification budget (sent {}B + {}B vs received {}B)",
                            addr,
                            client.amp_sent,
                            reply_len,
                            client.amp_received
                        );
                        return;
                    }
                } else if client.auth_ok_reemits >= MAX_AUTH_OK_REEMITS {
                    log::debug!(
                        "UDP {}: suppressing AuthOK re-emit — already re-sent {} times, which \
                         is past what a lost reply needs",
                        addr,
                        client.auth_ok_reemits
                    );
                    return;
                } else {
                    client.auth_ok_reemits = client.auth_ok_reemits.saturating_add(1);
                }
                // Liveness is proven by a datagram we could DECRYPT, never by a replayed one.
                //
                // `last_activity` used to be bumped at the top of this branch, before the
                // budget/count checks and without any AEAD. The trigger condition for the
                // AuthOK path is `payload == client.auth_request` — a byte-for-byte replay of
                // an AUTH datagram this peer sent earlier. On UDP the session map is keyed on
                // the source address alone, so anyone who observed that datagram, or who can
                // simply spoof the source, could retransmit it forever and keep the entry
                // alive: `cleanup_tick` reaps on `last_activity`, so the session never aged
                // out, and its pool address, its `max_clients` slot and its `by_ip` entry were
                // held indefinitely after the real client had gone. Worse, the suppression
                // above returns EARLY, so once the re-emit budget was spent the timer kept
                // being refreshed while nothing was sent — the throttle stopped the reply and
                // not the resource hold.
                //
                // The TCP path states the same rule explicitly and only moves rx-liveness
                // after a successful decrypt. Bumping it only when we actually re-emit keeps
                // the legitimate case working (a client whose reply was lost is genuinely
                // there and gets MAX_AUTH_OK_REEMITS worth of grace) and bounds the abuse to
                // that same small count. (Audit 2026-08-04.)
                client.last_activity = std::time::Instant::now();
                client.amp_sent = client.amp_sent.saturating_add(reply_len);
                drop(sessions_guard);
                if reemit_hello {
                    if !hello.is_empty() {
                        send_handshake_response(socket, addr, &hello, quic, &cid, frag).await;
                    }
                } else {
                    for pkt in &authok {
                        let _ = socket.send_to(pkt, addr).await;
                    }
                }
                return;
            }
            // Revoked? Forget the peer and drop the datagram, before spending any AEAD.
            //
            // `kick_all` raises this flag; the control plane calls it for an admin kick,
            // for the quota sweep's cut-off, and when a reconnect supersedes an old
            // session. Previously none of those reached ingress at all — they edit
            // `profile.sessions.by_ip`, whereas this loop demultiplexes from the
            // per-worker map — so a kicked client went on injecting packets into the TUN
            // for the remaining 30-45 s of its reaper window, using a source address the
            // pool had already released and might have reassigned.
            // (Audit 2026-07-27, A2/A3.)
            let revoked_now = client
                .revoked
                .as_ref()
                .is_some_and(|r| r.load(std::sync::atomic::Ordering::Relaxed));
            if revoked_now {
                sessions_guard.remove(&addr);
                drop(sessions_guard);
                log::debug!(
                    "UDP {}: dropping datagram — session revoked (kick / quota / supersede)",
                    addr
                );
                return;
            }
            let source_session_id = match &client.state {
                UdpSessionState::Authenticated { session_id, .. } => Some(*session_id),
                UdpSessionState::AwaitingAuth => None,
            };
            let is_awaiting_auth = source_session_id.is_none();
            let reassembled_record;
            let payload = if crate::protocol::data_frag::is_data_fragment(payload) {
                if is_awaiting_auth || !client.data_frag_enabled {
                    log::debug!(
                        "UDP drop from {} on profile '{}': DATA_FRAG_V1 was not negotiated",
                        addr,
                        profile.name
                    );
                    return;
                }
                match client
                    .data_reassembler
                    .push(payload, &client.rx_data_frag_key)
                {
                    Ok(Some(record)) => {
                        reassembled_record = record;
                        reassembled_record.as_slice()
                    }
                    Ok(None) => return,
                    Err(error) => {
                        log::debug!(
                            "UDP drop from {} on profile '{}': bad data fragment ({})",
                            addr,
                            profile.name,
                            error
                        );
                        return;
                    }
                }
            } else {
                payload
            };
            let Some(mut plaintext) = tun_tx.pool.try_acquire() else {
                client
                    .dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                profile
                    .udp_buffer_counters
                    .note_internal_drop(InternalDrop::PoolExhausted);
                log::debug!(
                    "UDP drop from {} on profile '{}': inbound TUN pool exhausted",
                    addr,
                    profile.name
                );
                return;
            };
            if payload.len() > plaintext.capacity() {
                client
                    .dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                profile
                    .udp_buffer_counters
                    .note_internal_drop(InternalDrop::Oversize);
                log::debug!(
                    "UDP drop from {} on profile '{}': {}-byte record exceeds inbound pool slot",
                    addr,
                    profile.name,
                    payload.len()
                );
                return;
            }
            plaintext.as_vec_mut().extend_from_slice(payload);
            {
                let mut rx = lock_or_recover(&client.rx_codec, "udp::decrypt");
                if let Err(e) = rx.decrypt_packet_in_place(plaintext.as_vec_mut()) {
                    log::debug!(
                        "UDP decrypt error from {} on profile '{}': {}",
                        addr,
                        profile.name,
                        e
                    );
                    return;
                }
            }
            let recordizer_active = !is_awaiting_auth && client.rx_recordizer.is_some();
            let mut decoded_first = None;
            let mut decoded_extra = Vec::new();
            if recordizer_active && !plaintext.is_empty() {
                let mut pool_exhausted_drops = 0_u64;
                let mut oversize_drops = 0_u64;
                let decode_result =
                    client
                        .rx_recordizer
                        .as_mut()
                        .unwrap()
                        .decode_with(&plaintext, |bytes| {
                            let Some(mut packet) = tun_tx.pool.try_acquire() else {
                                pool_exhausted_drops = pool_exhausted_drops.saturating_add(1);
                                return;
                            };
                            if bytes.len() > packet.capacity() {
                                oversize_drops = oversize_drops.saturating_add(1);
                                return;
                            }
                            packet.as_vec_mut().extend_from_slice(bytes);
                            if decoded_first.is_none() {
                                decoded_first = Some(packet);
                            } else {
                                decoded_extra.push(packet);
                            }
                        });
                let total_drops = pool_exhausted_drops.saturating_add(oversize_drops);
                client
                    .dropped
                    .fetch_add(total_drops, std::sync::atomic::Ordering::Relaxed);
                for _ in 0..pool_exhausted_drops {
                    profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::PoolExhausted);
                }
                for _ in 0..oversize_drops {
                    profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::Oversize);
                }
                if let Err(error) = decode_result {
                    log::debug!(
                        "UDP recordizer decode error from {} on profile '{}': {}",
                        addr,
                        profile.name,
                        error
                    );
                    return;
                }
            }
            client.last_activity = std::time::Instant::now();
            // Account inbound (client->server) bytes so `list-clients` RECV is correct
            // (the UDP path never incremented this → RECV always showed 0). Captured
            // before the lock drops; counts plaintext.len() like the TCP path. For an
            // AwaitingAuth client this is a placeholder Arc that is never incremented.
            let recv_ctr = client.bytes_recv.clone();
            let client_dropped = client.dropped.clone();
            let bandwidth_limit = client.bandwidth_limit_mbps.clone();
            let upload_tx = client.upload_tx.clone();
            // Captured with the lock, like recv_ctr — the ACL is consulted below after
            // the guard is dropped. Cheap: an unrestricted ACL is an empty Vec.
            let dst_acl = client.dst_acl.clone();
            let src_guard = client.src_guard.clone();
            let exit_access = client.exit_access;
            // Same reason as recv_ctr: taken with the lock, used after it drops.
            let path_mtu = client.path_mtu.clone();
            let udp_payload_budget = client.udp_payload_budget.clone();
            let client_info = client.client_info.clone();
            drop(sessions_guard);

            if recordizer_active {
                drop(plaintext);
                let session_id = source_session_id.expect("authenticated UDP session has an id");
                for packet in decoded_first.into_iter().chain(decoded_extra) {
                    forward_udp_uplink_packet(
                        ServerTunPacket::Pooled(packet),
                        sessions,
                        tasks,
                        profile,
                        addr,
                        obfs_key,
                        session_id,
                        exit_access,
                        tun_tx,
                        &path_mtu,
                        &udp_payload_budget,
                        &client_info,
                        &src_guard,
                        &dst_acl,
                        &bandwidth_limit,
                        &upload_tx,
                        &recv_ctr,
                        &client_dropped,
                    )
                    .await;
                }
                return;
            }
            if is_awaiting_auth {
                // Dispatch the auth OFF the recv loop: it runs the per-username tarpit sleep
                // and the memory-hard Argon2 (behind argon2_gate), and `.await`ing it here
                // stalled every established session on this worker (H1). The in-flight guard
                // makes a duplicate/retransmitted AUTH from the same source a no-op instead
                // of a second parallel Argon2. On completion the guard is cleared; the auth
                // itself installs the session under the sessions lock as before.
                let already_running = {
                    let mut inflight = auth_inflight.lock().await;
                    !inflight.insert(addr)
                };
                if already_running {
                    return;
                }
                let server_state = server_state.clone();
                let profile = profile.clone();
                let sessions = sessions.clone();
                let socket = socket.clone();
                let quic_config = quic_config.clone();
                let auth_inflight = auth_inflight.clone();
                let auth_tun_tx = tun_tx.clone();
                let raw = payload.to_vec();
                let auth_tasks = tasks.clone();
                tasks.spawn(async move {
                    handle_udp_auth(
                        &server_state,
                        &profile,
                        &sessions,
                        &socket,
                        addr,
                        &plaintext,
                        worker_id,
                        &raw,
                        &quic_config,
                        auth_tun_tx,
                        auth_tasks,
                    )
                    .await;
                    auth_inflight.lock().await.remove(&addr);
                });
            } else if crate::protocol::ctrl::is_ctrl(&plaintext) {
                // In-tunnel control frame, not a packet: authenticated by the AEAD above and
                // bound to THIS session — which is why the MTU report rides here rather than
                // as a bare datagram alongside the UDP path-MTU probes, whose only identity
                // is a source address anyone could spoof. Handled before the packet path so
                // it never reaches the ACLs or the TUN. (Audit 2026-07-30, #13.)
                if let (Some(cell), Some(mtu)) = (
                    path_mtu.as_ref(),
                    crate::protocol::ctrl::parse_mtu_report(&plaintext),
                ) {
                    crate::server::handler::note_path_mtu(cell, format_args!("at {addr}"), mtu);
                } else if let (Some(cell), Some(budget)) = (
                    udp_payload_budget.as_ref(),
                    crate::protocol::ctrl::parse_udp_payload_budget_report(&plaintext),
                ) {
                    schedule_downlink_mtu_probe(
                        sessions,
                        tasks,
                        &profile.name,
                        addr,
                        cell,
                        budget,
                        obfs_key,
                    )
                    .await;
                } else if let (Some(cell), Some((v, p))) = (
                    client_info.as_ref(),
                    crate::protocol::ctrl::parse_client_info(&plaintext),
                ) {
                    crate::server::handler::note_client_info(
                        cell,
                        format_args!("at {addr}"),
                        &v,
                        &p,
                    );
                }
                return;
            } else if !plaintext.is_empty() {
                // Destination ACL — after AEAD/replay (authenticated traffic only),
                // before the TUN. Unrestricted sessions short-circuit.
                // Source guard first — a forged source is a lie about identity,
                // so judge it before anything that reasons about this session's
                // rights. `None` only for a session that has not authenticated yet,
                // which cannot reach here.
                if let Some(ref g) = src_guard {
                    if !g.allows_packet(&plaintext) {
                        log::debug!("dropped UDP packet from {} — forged source address", addr);
                        return;
                    }
                }
                if !dst_acl.is_unrestricted() && !dst_acl.allows_packet(&plaintext) {
                    log::debug!(
                        "ACL: dropped UDP packet from {} — destination not in allowed_networks",
                        addr
                    );
                    return;
                }
                // Apply the user cap to UDP upload too. Limited packets go through the
                // client's own pacing task; unlimited packets retain the direct hot path.
                let limit = bandwidth_limit
                    .as_ref()
                    .map(|value| value.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(0);
                if limit == 0 {
                    // Preserve the direct fast path for unlimited users.
                    recv_ctr
                        .fetch_add(plaintext.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    // Keep exit-node/default iroutes out of the host routing table. The
                    // direct branch still enters the common TUN downlink forwarder, so UDP
                    // receives the same MTU, fragmentation, rate and encryption treatment.
                    let _ = tun_tx
                        .send_client_packet(
                            profile,
                            source_session_id.expect("authenticated UDP session has an id"),
                            exit_access,
                            ServerTunPacket::Pooled(plaintext),
                        )
                        .await;
                } else if upload_tx
                    .as_ref()
                    .is_none_or(|tx| tx.try_send(ServerTunPacket::Pooled(plaintext)).is_err())
                {
                    // Never await a full per-client pacing queue in this shared receive loop:
                    // one capped peer must not head-of-line block every UDP session.
                    client_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::QueueFull);
                    log::debug!(
                        "UDP upload pacing queue full for {} on profile '{}'; dropping packet",
                        addr,
                        profile.name
                    );
                }
            }
            return;
        }
    }

    // New source address: this is the ClientHello. It arrives fragmented (LTE/CGNAT
    // fix) — reassemble it; a legacy single-datagram ClientHello (no fragment magic)
    // is accepted as-is for backward compatibility. We reply in the same shape.
    let (ch, frag_mode): (Vec<u8>, bool) = if crate::protocol::udp_frag::is_fragment(payload) {
        // Bound the reassembly map against a spoofed-source flood: evict the oldest
        // partial when full (same cap as half-open sessions). Only the full,
        // reassembled ClientHello triggers a response (anti-amplification preserved).
        if !frag_pending.contains_key(&addr) && frag_pending.len() >= MAX_PENDING_HANDSHAKES {
            if let Some(oldest) = frag_pending
                .iter()
                .max_by_key(|(_, r)| r.age())
                .map(|(a, _)| *a)
            {
                frag_pending.remove(&oldest);
            }
        }
        match frag_pending.entry(addr).or_default().push(payload) {
            Ok(Some(full)) => {
                frag_pending.remove(&addr);
                (full, true)
            }
            Ok(None) => return, // need more fragments
            Err(_) => {
                frag_pending.remove(&addr); // malformed — drop the partial
                return;
            }
        }
    } else {
        (payload.to_vec(), false)
    };

    // Bound concurrent pre-auth handshake crypto per worker. A spoofed-source
    // flood can bypass the per-IP rate limiter, so without this each ClientHello
    // would run a full PQ handshake (Keypair::generate + ML-KEM + derive) →
    // CPU exhaustion. If no permit is free, DROP silently (don't queue): the
    // client retransmits its ClientHello. The permit is held across the
    // handshake crypto and released when `_permit` drops at the end of this arm.
    let _permit = match handshake_permits.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            log::debug!(
                "UDP drop from {} on profile '{}': no handshake permit (pre-auth crypto saturated)",
                addr,
                profile.name
            );
            return;
        }
    };

    let hide_identity = server_state.config.auth.require_client_key_proof;
    let bind_static = server_state.config.auth.bind_static_to_session;
    match handle_new_udp_client(
        profile,
        &ch,
        addr,
        quic_detected,
        hide_identity,
        bind_static,
    )
    .await
    {
        Ok((mut client, raw_response)) => {
            let cid = client.connection_id;
            // Cache the ServerHello so a retransmitted ClientHello (i.e. a lost
            // ServerHello) can be answered idempotently — see the existing-session
            // re-emit branch. Freed on auth.
            client.server_hello = raw_response.clone();
            client.hello_frag_mode = frag_mode;
            let mut sessions_guard = sessions.write().await;
            // Bound half-open handshakes (U2): under a spoofed-source flood, evict a
            // still-unauthenticated entry instead of growing without limit.
            // Authenticated sessions are skipped by the filter.
            //
            // Evict a RANDOM half-open, not the oldest: under a flood the real,
            // about-to-authenticate clients are a tiny and transient fraction of the
            // AwaitingAuth set (they auth within ~1 RTT), so a random pick hits a real
            // entry only with probability ≈ that small fraction, whereas always taking
            // the oldest can systematically evict a legitimate client whose ServerHello
            // was lost and is retransmitting. Reservoir sample of size 1 in a single
            // pass (no allocation), then remove after the borrow ends.
            let pending = sessions_guard
                .values()
                .filter(|c| matches!(c.state, UdpSessionState::AwaitingAuth))
                .count();
            if pending >= MAX_PENDING_HANDSHAKES {
                let mut victim: Option<SocketAddr> = None;
                let mut seen: u64 = 0;
                for (a, c) in sessions_guard.iter() {
                    if matches!(c.state, UdpSessionState::AwaitingAuth) {
                        seen += 1;
                        // Reservoir sample of size 1: replace the pick with probability
                        // 1/seen (`random % seen == 0`, i.e. a multiple of `seen`).
                        if rand::random::<u64>().is_multiple_of(seen) {
                            victim = Some(*a);
                        }
                    }
                }
                if let Some(stale_addr) = victim {
                    sessions_guard.remove(&stale_addr);
                    log::debug!(
                        "UDP: pending-handshake cap on profile '{}' — evicted a half-open {}",
                        profile.name,
                        stale_addr
                    );
                }
            }
            sessions_guard.insert(addr, client);
            drop(sessions_guard);
            // Reply in the same shape the client used: fragmented for a fragmenting
            // client (no IP fragmentation → works on LTE), single for a legacy one.
            send_handshake_response(socket, addr, &raw_response, quic_detected, &cid, frag_mode)
                .await;
            log::info!(
                "UDP handshake started for {} on profile '{}' ({}{})",
                addr,
                profile.name,
                if frag_mode { "fragmented" } else { "single" },
                if quic_detected { ", QUIC-masked" } else { "" }
            );
        }
        Err(e) => {
            log::debug!(
                "UDP handshake failed for {} on profile '{}': {}",
                addr,
                profile.name,
                e
            );
        }
    }
}

#[allow(clippy::too_many_arguments)] // auth dispatch threads the shared UDP state
async fn handle_udp_auth(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<UdpSessionDirectory>>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    plaintext: &[u8],
    _worker_id: usize,
    // The RAW (post-unwrap, pre-decrypt) AUTH datagram — cached on success so a
    // retransmit (i.e. a lost AuthOK) is recognised and answered idempotently.
    raw_request: &[u8],
    _quic_config: &QuicMaskingConfig,
    tun_tx: TunIngress,
    tasks: super::ProfileTasks,
) {
    let pcfg = &profile.config;
    // Auth plaintext: [client_key_proof:32]([0x00][device_id:16])?[username:password]
    if plaintext.len() < 32 {
        sessions.write().await.remove(&addr);
        return;
    }
    let mut client_key_proof = [0u8; 32];
    client_key_proof.copy_from_slice(&plaintext[..32]);
    let (device_id, auth_bytes) = handler::split_device_id(&plaintext[32..]);
    let (capabilities, creds) =
        match crate::protocol::capabilities::split_client_capabilities(auth_bytes) {
            Ok(value) => value,
            Err(error) => {
                log::warn!("UDP: invalid client capability extension from {addr}: {error}");
                sessions.write().await.remove(&addr);
                return;
            }
        };
    let auth_str = match String::from_utf8(creds.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&addr);
            return;
        }
    };
    let (username, password) = match auth_str.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&addr);
            return;
        }
    };

    log::info!(
        "AUTH attempt UDP from {}: user={} on profile '{}'",
        addr,
        crate::util::log_identity(&username),
        profile.name
    );

    // Pull the channel-binding material captured during the handshake so the
    // shared verifier can check the server-key proof, then run the identical
    // auth policy as TCP (key-proof, brute-force, user lookup, Argon2, profile).
    let (static_shared, ephemeral_shared, transcript_hash) = {
        let g = sessions.read().await;
        match g
            .get(&addr)
            .map(|c| (c.static_shared, c.ephemeral_shared, c.transcript_hash))
        {
            Some(m) => m,
            None => return,
        }
    };
    if let Err(e) = handler::verify_client_auth(
        server_state,
        profile,
        addr,
        "UDP",
        &client_key_proof,
        &username,
        &password,
        &static_shared,
        &ephemeral_shared,
        &transcript_hash,
    )
    .await
    {
        log::debug!(
            "UDP auth rejected for {} on profile '{}': {}",
            addr,
            profile.name,
            e
        );
        sessions.write().await.remove(&addr);
        return;
    }

    let negotiation =
        crate::protocol::capabilities::negotiated_profile_ip_mode(pcfg.tun.ip_mode, capabilities)
            .map_err(|error| error.to_string())
            .and_then(|mode| {
                crate::protocol::capabilities::negotiate_recordizer(
                    &pcfg.obfuscation.recordizer,
                    capabilities,
                )
                .map(|recordizer| (mode, recordizer))
                .map_err(|error| error.to_string())
            });
    let (negotiated_ip_mode, negotiated_recordizer) = match negotiation {
        Ok(value) => value,
        Err(error) => {
            let reason = error.clone();
            let response_result: anyhow::Result<Vec<Vec<u8>>> = {
                let mut sessions_guard = sessions.write().await;
                let Some(client) = sessions_guard.get_mut(&addr) else {
                    return;
                };
                let packets = {
                    let mut tx = lock_or_recover(&client.tx_codec, "udp::auth_error");
                    build_auth_error_datagrams(
                        &mut tx,
                        &reason,
                        client.quic_enabled,
                        &client.connection_id,
                    )
                };
                match packets {
                    Ok(packets) => {
                        client.auth_request = raw_request.to_vec();
                        client.auth_ok = packets.clone();
                        client.server_hello.clear();
                        client.hello_frag_mode = false;
                        client.packet_counter.fetch_max(
                            AUTH_OK_FIRST_PN + packets.len() as u32,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        let response_len: u64 =
                            packets.iter().map(|packet| packet.len() as u64).sum();
                        client.amp_sent = client.amp_sent.saturating_add(response_len);
                        Ok(packets)
                    }
                    Err(send_error) => Err(send_error),
                }
            };
            let response_pkts = match response_result {
                Ok(packets) => packets,
                Err(send_error) => {
                    log::warn!(
                        "UDP: cannot build negotiation error for {addr} on profile '{}': \
                         {send_error}",
                        profile.name
                    );
                    sessions.write().await.remove(&addr);
                    return;
                }
            };
            for packet in &response_pkts {
                let _ = socket.send_to(packet, addr).await;
            }
            log::warn!(
                "UDP: client {addr} cannot use profile '{}': {error}",
                profile.name
            );
            return;
        }
    };
    let data_frag_enabled = capabilities.is_some_and(|caps| {
        caps.core_bits & crate::protocol::capabilities::client_capability::UDP_DATA_FRAG_V1 != 0
    });
    let negotiated_rx_recordizer = negotiated_recordizer.as_ref().map(|config| {
        crate::protocol::recordizer::RuntimeConfig::from_config(
            config,
            crate::protocol::packet::MAX_TUNNEL_MTU,
            crate::protocol::packet::MAX_TUNNEL_MTU,
        )
        .expect("validated UDP recordizer configuration")
    });

    // Per-device key (same as the TCP path) — pool IPs + sessions are keyed by it
    // so multiple devices of one login coexist.
    let dkey = handler::device_key(&username, device_id);
    // Serialize the state-changing half of authentication with TCP and the other UDP
    // workers. The guard is released only after the session and kernel iroutes commit.
    let admission_guard = profile.admission.lock().await;
    // Addresses freed by an eviction, released ONLY under the same pool lock that allocates
    // ours. Releasing each one immediately — as this used to — put it on the pool's `freed`
    // stack and then dropped the lock, and `allocate` pops `freed` FIRST: a concurrent
    // handler was handed the address we had just evicted someone from, and our
    // `allocate_fixed` took it back in the pool's bookkeeping only, without killing that
    // session. Two live sessions on one tunnel IP. Same defect and same fix as the TCP path.
    // (Audit 2026-08-04.)
    let mut deferred_release: Vec<String> = Vec::new();
    let mut evicted_iroutes: Vec<String> = Vec::new();
    let mut evicted_sessions: Vec<Arc<handler::SessionShared>> = Vec::new();

    // Supersede this exact device before enforcing either limit. Its pool lease is kept
    // for the replacement, but its session and iroutes must no longer be authoritative.
    let stale_device_sessions: Vec<std::net::IpAddr> = {
        let session_map = profile.sessions.read().await;
        session_map
            .by_ip
            .iter()
            .filter(|(_, session)| session.device_key == dkey)
            .map(|(primary, _)| *primary)
            .collect()
    };
    for primary in stale_device_sessions {
        let old = {
            let mut session_map = profile.sessions.write().await;
            let old = session_map.remove(primary);
            if old.is_some() {
                evicted_iroutes.extend(session_map.take_client_routes(primary));
            }
            old
        };
        if let Some(old) = old {
            old.kick_all();
            sessions
                .write()
                .await
                .remove_session_owner(old.session_id, old.peer);
            evicted_sessions.push(old);
        }
    }

    // Per-user session cap (0 = unlimited): evict this user's oldest device(s) so the
    // new one fits. A reconnecting device keeps its own IP (pool is per-device), so we
    // count only OTHER devices here; its self-supersede happens at the IP step below.
    {
        let max_sessions = {
            let db = server_state.users_db.read().await;
            db.find_user(&username)
                .map(|u| u.effective_max_sessions(&db.groups))
                .unwrap_or(0)
        };
        if max_sessions > 0 {
            loop {
                let victim = {
                    let sess_map = profile.sessions.read().await;
                    let mut others: Vec<(
                        SocketAddr,
                        std::net::IpAddr,
                        std::time::Instant,
                        String,
                    )> = sess_map
                        .by_ip
                        .iter()
                        .filter(|(_, s)| s.username == username && s.device_key != dkey)
                        .map(|(ip, s)| (s.peer, *ip, s.connected_at, s.device_key.clone()))
                        .collect();
                    if others.len() < max_sessions as usize {
                        None
                    } else {
                        others.sort_by_key(|(_, _, t, _)| *t); // oldest first
                        Some(others.swap_remove(0))
                    }
                };
                match victim {
                    Some((peer, ip, _, ev_dkey)) => {
                        let old = {
                            let mut sm = profile.sessions.write().await;
                            match sm.remove(ip) {
                                Some(old) => {
                                    // Strip the evicted session's iroutes (map only — a new
                                    // session is admitted at this IP; no kernel del to race it).
                                    evicted_iroutes.extend(sm.take_client_routes(ip));
                                    Some(old)
                                }
                                None => None,
                            }
                        };
                        deferred_release.push(ev_dkey.clone());
                        if let Some(old) = old {
                            old.kick_all();
                            sessions
                                .write()
                                .await
                                .remove_session_owner(old.session_id, peer);
                            evicted_sessions.push(old);
                        }
                        log::info!(
                            "User '{}' at session cap {} — evicting oldest device {} on profile '{}' for new device '{}'",
                            crate::util::log_identity(&username), max_sessions, ip, profile.name, crate::util::log_device_identity(&dkey)
                        );
                    }
                    None => break,
                }
            }
        }
    }

    // Static IP (variant-b): a user's fixed address always wins. Resolved from the LIVE
    // users db (a panel edit + SIGHUP applies at once). Evict its current holder (a
    // different device, or a dynamic user who took it while the owner was offline) from
    // BOTH the shared session map and the per-source-addr UDP map, then steal it below —
    // so a reconnect from a new source IP always lands on the same tunnel address.
    let fixed_addresses = {
        let db = server_state.users_db.read().await;
        handler::resolve_static_addresses(&db, pcfg, &username, negotiated_ip_mode)
    };
    let (fixed_ip, fixed_ipv6) = match fixed_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            log::error!(
                "UDP: refusing user '{}' on profile '{}': {error}",
                crate::util::log_identity(&username),
                profile.name
            );
            sessions.write().await.remove(&addr);
            return;
        }
    };
    if negotiated_ip_mode != crate::config::server::IpMode::Ipv6 {
        if let Some(ip) = fixed_ip {
            let primary = std::net::IpAddr::V4(ip);
            let holder = {
                let sess_map = profile.sessions.read().await;
                sess_map
                    .by_ip
                    .get(&primary)
                    .map(|s| (s.peer, s.device_key.clone()))
            };
            if let Some((peer, ev_dkey)) = holder {
                if ev_dkey != dkey {
                    let old = {
                        let mut sm = profile.sessions.write().await;
                        match sm.remove(primary) {
                            Some(old) => {
                                // Strip the evicted holder's iroutes (map only — a new session is
                                // admitted at this IP; no kernel del to race its re-program).
                                evicted_iroutes.extend(sm.take_client_routes(primary));
                                Some(old)
                            }
                            None => None,
                        }
                    };
                    deferred_release.push(ev_dkey.clone());
                    if let Some(old) = old {
                        old.kick_all();
                        sessions
                            .write()
                            .await
                            .remove_session_owner(old.session_id, peer);
                        evicted_sessions.push(old);
                    }
                    log::info!(
                    "Static IP {} for user '{}' — evicting current holder device '{}' on profile '{}'",
                    ip, crate::util::log_identity(&username), crate::util::log_device_identity(&ev_dkey), profile.name
                );
                }
            }
        }
    }
    if negotiated_ip_mode != crate::config::server::IpMode::Ipv4 {
        if let Some(address) = fixed_ipv6 {
            let requested = std::net::IpAddr::V6(address);
            let holder = {
                let session_map = profile.sessions.read().await;
                session_map
                    .get_by_address(requested)
                    .map(|session| (session.client_ip, session.peer, session.device_key.clone()))
            };
            if let Some((primary, peer, evicted_key)) = holder {
                if evicted_key != dkey {
                    let old = {
                        let mut session_map = profile.sessions.write().await;
                        let old = session_map.remove(primary);
                        if let Some(old) = &old {
                            evicted_iroutes.extend(session_map.take_client_routes(old.client_ip));
                        }
                        old
                    };
                    deferred_release.push(evicted_key.clone());
                    if let Some(old) = old {
                        old.kick_all();
                        sessions
                            .write()
                            .await
                            .remove_session_owner(old.session_id, peer);
                        evicted_sessions.push(old);
                    }
                    log::info!(
                        "Static IPv6 {} for user '{}' evicts holder device '{}' on profile '{}'",
                        address,
                        crate::util::log_identity(&username),
                        crate::util::log_device_identity(&evicted_key),
                        profile.name
                    );
                }
            }
        }
    }

    let max_clients = profile.config.performance.connection.max_clients as usize;
    let capacity_rejected = {
        let session_map = profile.sessions.read().await;
        session_map.by_ip.len() >= max_clients
    };
    for old in &evicted_sessions {
        crate::server::notify::fire_disconnect(&old.username, &profile.name, old.peer);
    }
    if capacity_rejected {
        {
            let mut pool = profile.pool.lock().await;
            for key in &deferred_release {
                pool.release(key);
            }
            pool.release(&dkey);
        }
        for cidr in &evicted_iroutes {
            let _ =
                handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
        }
        sessions.write().await.remove(&addr);
        drop(admission_guard);
        log::warn!(
            "UDP: profile '{}' at max_clients ({}) - rejecting {}",
            profile.name,
            max_clients,
            addr
        );
        return;
    }

    // Delete routes of evicted owners before the replacement can install the same CIDR.
    for cidr in &evicted_iroutes {
        let _ = handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
    }

    let assigned_result: Result<crate::server::pool::AssignedAddresses, String> = {
        let mut pool = profile.pool.lock().await;
        for k in &deferred_release {
            pool.release(k);
        }
        let result = pool
            .allocate_for_mode(&dkey, negotiated_ip_mode, fixed_ip, fixed_ipv6)
            .map_err(|error| {
                format!(
                    "cannot allocate {} address set for '{}' on profile '{}': {}",
                    negotiated_ip_mode,
                    crate::util::log_identity(&username),
                    profile.name,
                    error
                )
            });
        // The old UDP ownership was already evicted under the profile admission lock. If
        // allocation restored an earlier lease and then failed, no live session would own it;
        // release it before publishing the error so the pool cannot shrink on failed mode
        // upgrades (for example IPv4 -> dual while the IPv6 pool is exhausted).
        if result.is_err() {
            pool.release(&dkey);
        }
        result
    };
    let assigned = match assigned_result {
        Ok(assigned) => assigned,
        Err(error) => {
            log::warn!("UDP: {error}");
            sessions.write().await.remove(&addr);
            return;
        }
    };
    let client_ip = assigned
        .ipv4
        .map(std::net::IpAddr::V4)
        .or_else(|| assigned.ipv6.map(std::net::IpAddr::V6))
        .expect("negotiated address mode assigns at least one family");

    let session_id: u64 = loop {
        let candidate = rand::random();
        if candidate != 0 {
            break candidate;
        }
    };

    // Move the handshake-bound CID material into the profile-wide registry before AuthOK can
    // advertise this session. The capability is still unadvertised, so production sessions take
    // the `None` path and immediately zeroize the unused material.
    #[cfg(feature = "experimental-roaming")]
    let mut udp_roaming_registration = {
        let mut sessions_guard = sessions.write().await;
        let Some(client) = sessions_guard.get_mut(&addr) else {
            drop(sessions_guard);
            profile.pool.lock().await.release(&dkey);
            return;
        };
        let negotiated = data_frag_enabled
            && crate::protocol::capabilities::udp_roaming_negotiated(
                Some(
                    crate::protocol::capabilities::udp_server_capabilities_for_profile(
                        profile.config.roaming.enabled,
                    ),
                ),
                capabilities,
            );
        let client_to_server_cid_secret = client.client_to_server_cid_secret.take();
        let server_to_client_cid_secret = client.server_to_client_cid_secret.take();
        if negotiated {
            let result = (|| -> anyhow::Result<_> {
                let client_to_server_cid_secret = client_to_server_cid_secret
                    .ok_or_else(|| anyhow::anyhow!("missing client-to-server CID secret"))?;
                let server_to_client_cid_secret = server_to_client_cid_secret
                    .ok_or_else(|| anyhow::anyhow!("missing server-to-client CID secret"))?;
                let worker_id = u32::try_from(_worker_id)
                    .map_err(|_| anyhow::anyhow!("UDP worker id exceeds u32"))?;
                let safe_payload_budget = u16::try_from(
                    crate::protocol::data_frag::conservative_udp_payload_budget(addr.is_ipv6()),
                )
                .map_err(|_| anyhow::anyhow!("safe UDP payload budget exceeds u16"))?;
                profile
                    .udp_roaming_registry
                    .register_owned_session(
                        session_id,
                        *client_to_server_cid_secret,
                        *server_to_client_cid_secret,
                        crate::transport_core::udp_roaming::UdpPath::new(worker_id, addr),
                        safe_payload_budget,
                    )
                    .map(Some)
                    .map_err(anyhow::Error::new)
            })();
            drop(sessions_guard);
            match result {
                Ok(registration) => registration,
                Err(error) => {
                    log::warn!(
                        "UDP: refusing roaming bootstrap for {} on profile '{}': {}",
                        addr,
                        profile.name,
                        error
                    );
                    sessions.write().await.remove(&addr);
                    profile.pool.lock().await.release(&dkey);
                    return;
                }
            }
        } else {
            None
        }
    };
    #[cfg(feature = "experimental-roaming")]
    let initial_roaming_transmit_cid = udp_roaming_registration
        .as_ref()
        .map(|(initial_cids, _)| *initial_cids.transmit());

    // Extract session data in a scoped borrow so sessions_guard is free for error handling
    let (
        auth_response,
        quic_enabled,
        connection_id,
        writer_codec,
        writer_pn,
        writer_data_frag_key,
        exit_access,
    ) = {
        let mut sessions_guard = sessions.write().await;
        let client = match sessions_guard.get_mut(&addr) {
            Some(c) => c,
            None => {
                log::warn!(
                    "UDP: session for {} vanished before auth completion on profile '{}'",
                    addr,
                    profile.name
                );
                // Release the pool IP reserved above, matching the encrypt-failure branch
                // below. Only reachable if the single-task-per-worker invariant is ever
                // broken, but an unguarded leak here would slowly exhaust the pool. (L1)
                drop(sessions_guard);
                profile.pool.lock().await.release(&dkey);
                return;
            }
        };

        let (routes_json, exit_access) = {
            let db = server_state.users_db.read().await;
            let raw_routes = handler::build_routes_json_pub(pcfg, &db, &username, assigned);
            (
                handler::routes_without_exit_defaults(&raw_routes),
                handler::exit_access_from_routes_json(&raw_routes),
            )
        };

        let qe = client.quic_enabled;
        let cid = client.connection_id;
        let wc = client.tx_codec.clone();
        let wpn = client.packet_counter.clone();
        let fragment_key = client.tx_data_frag_key;
        #[cfg(feature = "experimental-roaming")]
        let udp_roaming_session_id = udp_roaming_registration.as_ref().map(|_| session_id);
        #[cfg(not(feature = "experimental-roaming"))]
        let udp_roaming_session_id = None;
        #[cfg(feature = "experimental-roaming")]
        if let Some((initial_cids, registration)) = udp_roaming_registration.take() {
            client._udp_roaming_initial_cids = Some(initial_cids);
            client._udp_roaming_registration = Some(registration);
        }

        // Self-describing keyed OK payload, same as the TCP path (handler.rs).
        let enc_result = {
            // UDP has no head-of-line blocking, so no stream bonding: empty token,
            // single stream.
            let msg = handler::build_auth_ok_for_addresses_with_udp_roaming(
                assigned,
                pcfg,
                &routes_json,
                &[0u8; crate::server::handler::JOIN_TOKEN_LEN],
                1,
                capabilities,
                udp_roaming_session_id,
            );
            let mut tx = lock_or_recover(&client.tx_codec, "udp::auth_response");
            tx.encrypt_packet(msg.as_bytes(), &[])
        };

        match enc_result {
            Ok(enc) => (enc, qe, cid, wc, wpn, fragment_key, exit_access),
            Err(e) => {
                log::error!(
                    "UDP: failed to encrypt auth response for {} on profile '{}': {}",
                    addr,
                    profile.name,
                    e
                );
                sessions_guard.remove(&addr);
                drop(sessions_guard);
                profile.pool.lock().await.release(&dkey);
                return;
            }
        }
    };

    #[cfg(feature = "experimental-roaming")]
    let active_egress = match initial_roaming_transmit_cid {
        Some(destination_cid) => {
            UdpActiveEgress::new_roaming(socket.clone(), addr, destination_cid)
        }
        None => UdpActiveEgress::new_legacy(socket.clone(), addr, quic_enabled, connection_id),
    };
    #[cfg(not(feature = "experimental-roaming"))]
    let active_egress =
        UdpActiveEgress::new_legacy(socket.clone(), addr, quic_enabled, connection_id);
    // Shared inbound counter: the UdpClient (RX path) and the SessionShared
    // (read by list-clients) point at the SAME AtomicU64, so UDP receives are
    // accounted (RECV used to be stuck at 0 — never incremented on UDP).
    let bytes_recv = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Build the AuthOK first so the same bytes can be BOTH sent and cached for
    // idempotent re-emit. Usually one datagram; more when the pushed route list puts the
    // record over the fragment budget (see `build_auth_ok_datagrams`).
    let auth_ok_len = auth_response.len();
    let response_pkts = match build_auth_ok_datagrams(&auth_response, quic_enabled, &connection_id)
    {
        Ok(p) => p,
        Err(e) => {
            log::error!(
                "Profile '{}': the AuthOK for '{}' is {} bytes and cannot be fragmented ({}). \
                 This profile pushes more than the UDP handshake can carry — reduce the pushed \
                 routes for this user/profile, or use a TCP profile.",
                profile.name,
                crate::util::log_identity(&username),
                auth_ok_len,
                e
            );
            sessions.write().await.remove(&addr);
            profile.pool.lock().await.release(&dkey);
            return;
        }
    };
    // Reserve the packet numbers the AuthOK just consumed.
    //
    // The wire convention is positional: ServerHello is 0, AuthOK is 1, and the session
    // counter therefore starts at 2. Fragmenting the AuthOK broke that arithmetic — N
    // fragments take 1..=N, so with two or more the data plane's first packet reused PN 2
    // (and beyond). Nothing rejects it today, because the QUIC wrapper is a mask rather
    // than a protocol and no client replay-filters it; but a duplicate packet number is a
    // lie about the wire, and it would fail the moment anything started checking.
    //
    // `fetch_max` rather than `store`: the counter is shared with the writer task and the
    // MTU-probe reply path, so it may only ever move FORWARD. For the single-datagram case
    // this is `max(2, 2)` — the pre-existing behaviour, byte for byte.
    writer_pn.fetch_max(
        AUTH_OK_FIRST_PN + response_pkts.len() as u32,
        std::sync::atomic::Ordering::Relaxed,
    );

    // Destination ACL (`allowed_networks`), own or inherited from the group — compiled
    // once here (before the session goes Authenticated) so the data path can check it
    // per packet with a few masks. Empty = unrestricted, the documented default.
    let dst_acl = {
        let db = server_state.users_db.read().await;
        crate::server::acl::DstAcl::compile(
            &db.find_user(&username)
                .map(|u| crate::server::acl::effective_allowed_networks(u, &db.groups))
                .unwrap_or_default(),
            &crate::util::log_identity(&username),
        )
    };
    if !dst_acl.is_unrestricted() {
        log::info!(
            "User '{}' is restricted to {} destination network(s) (allowed_networks)",
            crate::util::log_identity(&username),
            dst_acl.rule_count()
        );
    }
    // Subnets routed behind this client (iroute) are legitimate sources too.
    let src_subnets: Vec<String> = {
        let db = server_state.users_db.read().await;
        db.find_user(&username)
            .map(|u| u.client_subnets.clone())
            .unwrap_or_default()
    };

    let wire_pool = match handler::server_wire_pool(pcfg) {
        Ok(pool) => pool,
        Err(error) => {
            log::error!(
                "UDP: cannot allocate the bounded wire-record pool for '{}' on profile '{}': {}",
                crate::util::log_identity(&username),
                profile.name,
                error
            );
            sessions.write().await.remove(&addr);
            profile.pool.lock().await.release(&dkey);
            return;
        }
    };

    // Resolve the live per-user policy once and share it with both directions. The
    // control socket updates the same AtomicU32, so set-bandwidth takes effect for the
    // UDP upload pacing task and download writer without reconnecting the client.
    let (initial_bw, client_subnets) = {
        let db = server_state.users_db.read().await;
        let user = db.find_user(&username);
        (
            user.map(|entry| entry.effective_bandwidth_limit(&db.groups))
                .unwrap_or(0),
            user.map(|entry| entry.client_subnets.clone())
                .unwrap_or_default(),
        )
    };
    let bandwidth_limit_mbps = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(initial_bw));
    let rates = crate::server::handler::DirectionalRateBuckets::new();
    let revoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // UDP has one shared socket receive loop for all peers. Sleeping there would let one
    // capped client stall the entire profile, so limited uploads are handed to a bounded
    // per-client pacing task. Unlimited clients retain the direct fast path above.
    let (upload_tx, mut upload_rx) = mpsc::channel::<ServerTunPacket>(UDP_UPLOAD_QUEUE_PACKETS);
    let upload_limit = bandwidth_limit_mbps.clone();
    let upload_rate = rates.upload.clone();
    let upload_bytes = bytes_recv.clone();
    let upload_tun = tun_tx.clone();
    let upload_profile = profile.clone();
    let upload_session_id = session_id;
    let upload_exit_access = exit_access;
    let upload_revoked = revoked.clone();
    tasks.spawn(async move {
        while let Some(packet) = upload_rx.recv().await {
            // Dropping the per-worker UdpClient closes the only long-lived sender.
            // A kick/quota/supersede raises `revoked` even before that map entry is
            // removed. In either case discard the queued tail instead of injecting
            // traffic after the session has lost its IP/authorization.
            if upload_rx.is_closed() || upload_revoked.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let limit = upload_limit.load(std::sync::atomic::Ordering::Relaxed);
            let delay = upload_rate.consume(packet.len() as u64 * 8, limit);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if upload_rx.is_closed() || upload_revoked.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            upload_bytes.fetch_add(packet.len() as u64, std::sync::atomic::Ordering::Relaxed);
            if upload_tun
                .send_client_packet(
                    &upload_profile,
                    upload_session_id,
                    upload_exit_access,
                    packet,
                )
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Update session state now that encryption succeeded
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.bytes_recv = bytes_recv.clone();
            client.dropped = dropped.clone();
            client.bandwidth_limit_mbps = Some(bandwidth_limit_mbps.clone());
            client.upload_tx = Some(upload_tx);
            client.revoked = Some(revoked.clone());
            client.state = UdpSessionState::Authenticated {
                session_id,
                device_key: dkey.clone(),
                client_ip,
            };
            client.data_frag_enabled = data_frag_enabled;
            client.active_egress = Some(active_egress.clone());
            client.rx_recordizer =
                negotiated_rx_recordizer.map(crate::protocol::recordizer::Reassembler::new);
            // Cache for idempotent AuthOK re-emit: a lost AuthOK leaves the client
            // retransmitting THIS exact AUTH datagram, which the replay window would
            // drop — the existing-session re-emit branch resends `auth_ok` on a byte
            // match. Free the ServerHello cache (only needed pre-auth).
            client.auth_request = raw_request.to_vec();
            client.auth_ok = response_pkts.clone();
            client.server_hello = Vec::new();
            client.hello_frag_mode = false;
            // Destination ACL now that we know WHICH user this session belongs to;
            // the data path below checks it on every inner packet.
            client.dst_acl = dst_acl.clone();
            let assigned_sources: Vec<std::net::IpAddr> = assigned
                .ipv4
                .map(std::net::IpAddr::V4)
                .into_iter()
                .chain(assigned.ipv6.map(std::net::IpAddr::V6))
                .collect();
            client.src_guard = Some(crate::server::acl::SrcGuard::new_dual(
                &assigned_sources,
                &src_subnets,
                &crate::util::log_identity(&username),
            ));
            client.exit_access = exit_access;
            client.wire_pool = Some(wire_pool.clone());
        }
        #[cfg(feature = "experimental-roaming")]
        sessions_guard.publish_roaming_owner(addr);
    }

    // Over the budget the AuthOK now goes out fragmented rather than as one oversized
    // datagram an LTE/CGNAT path would silently eat. Worth saying out loud even so: a client
    // built before `MSG_AUTH_OK` cannot reassemble it, and this is the size at which such a
    // client stops being able to connect over UDP at all. (Audit 2026-08-02, §4.)
    if response_pkts.len() > 1 {
        log::info!(
            "Profile '{}': the AuthOK for '{}' is {} bytes, above the {}-byte UDP handshake \
             budget, and is being sent as {} fragments. Clients older than 0.7.14 cannot \
             reassemble it — reduce the pushed routes for this user/profile, or use a TCP \
             profile, if any are still in the field.",
            profile.name,
            crate::util::log_identity(&username),
            auth_ok_len,
            crate::protocol::udp_frag::MAX_CHUNK,
            response_pkts.len()
        );
    }
    // The AuthOK is NOT sent here. It is built and cached now, and goes on the wire only
    // once `max_clients` has admitted this client — see the send below the capacity check.

    let (writer_tx, mut writer_rx) = mpsc::channel::<PooledBuffer>(wire_pool.buffer_count());
    let writer_egress = active_egress;
    let initial_writer_egress = writer_egress.snapshot();
    let initial_udp_payload_budget = initial_writer_egress.safe_payload_budget();
    let writer_udp_payload_budget = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(
        initial_udp_payload_budget as u32,
    ));
    let initial_record_budget = initial_writer_egress
        .record_budget(initial_udp_payload_budget)
        .expect("conservative UDP budget always fits the data-fragment header");
    let writer_task_codec = writer_codec.clone();
    let writer_profile_config = profile.config.clone();
    let writer_mux_payload_budget = lock_or_recover(&writer_task_codec, "udp::recordizer_budget")
        .max_data_for_record_budget(initial_record_budget)
        .expect("conservative UDP budget fits encrypted record overhead");
    let writer_recordizer_config = negotiated_recordizer.clone();
    let writer_recordizer_runtime = writer_recordizer_config.as_ref().map(|config| {
        crate::protocol::recordizer::RuntimeConfig::from_config(
            config,
            writer_mux_payload_budget,
            crate::protocol::packet::MAX_TUNNEL_MTU,
        )
        .expect("validated UDP recordizer configuration")
    });

    // Per-user bandwidth cap (own value, else group, else 0 = unlimited). Upload and
    // download use independent session-wide buckets, and `set-bandwidth` updates both.
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    // UDP is a single logical stream per session (no bonding).
    // Built before the struct literal: `username` is moved into it below.
    let assigned_sources: Vec<std::net::IpAddr> = assigned
        .ipv4
        .map(std::net::IpAddr::V4)
        .into_iter()
        .chain(assigned.ipv6.map(std::net::IpAddr::V6))
        .collect();
    let src_guard = crate::server::acl::SrcGuard::new_dual(
        &assigned_sources,
        &src_subnets,
        &crate::util::log_identity(&username),
    );
    let session = std::sync::Arc::new(crate::server::handler::SessionShared {
        session_id,
        username,
        device_key: dkey,
        client_ip,
        client_ipv4: assigned.ipv4,
        client_ipv6: assigned.ipv6,
        peer: addr,
        token: [0u8; crate::server::handler::JOIN_TOKEN_LEN],
        max_streams: 1,
        wire_pool: wire_pool.clone(),
        streams: std::sync::Mutex::new(vec![crate::server::handler::StreamHandle {
            #[cfg(feature = "experimental-roaming")]
            logical_slot_id: 0,
            #[cfg(feature = "experimental-roaming")]
            ready: true,
            stream_id: session_id,
            codec: writer_codec,
            writer: writer_tx,
            kick_tx,
            // UDP has no long-lived reader task to stop: every inbound datagram is
            // re-matched against the sessions map, so removing the session already
            // cuts ingress at the next packet. The field exists for the TCP reader;
            // here it is a sink so `kick_all` stays uniform across transports.
            shutdown_tx: tokio::sync::watch::channel(false).0,
        }]),
        #[cfg(feature = "experimental-roaming")]
        tcp_roaming: None,
        #[cfg(feature = "experimental-roaming")]
        tcp_control_v2: false,
        connected_at: std::time::Instant::now(),
        bytes_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        bytes_recv,
        dropped,
        bandwidth_limit_mbps,
        rates,
        cover_budget: crate::protocol::Shaper::shared_budget(
            &profile.config.obfuscation.traffic_shaping.to_shaping(),
            std::time::Instant::now(),
        ),
        recordizer: negotiated_recordizer.clone(),
        dst_acl: dst_acl.clone(),
        src_guard,
        exit_access,
        // 0 = not reported yet; the receive loop fills it in from the client's in-tunnel
        // control frame, and the TUN forwarder reads it. (Audit 2026-07-30, #13.)
        path_mtu: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        // None = the client has not said what it is; filled in from the same control
        // frame path as the MTU report above.
        client_info: std::sync::Arc::new(std::sync::Mutex::new(None)),
        revoked,
        closing: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    // The writer task outlives this function and needs the rate bucket + byte
    // counter, but `session` is moved into the profile map below — clone first.
    let writer_session = session.clone();

    // Kick any previous session occupying this IP before inserting, and register this
    // client's inbound iroute subnets (#13) — the same helper as the TCP path, so a
    // UDP-profile user with client_subnets gets inbound routing too (previously a no-op).
    let server_tun = crate::server::handler::configured_tun_addresses(&profile.config);
    let (old_to_evict, replaced_iroutes, programmed_iroutes) = {
        let mut sess_map = profile.sessions.write().await;
        let primary = client_ip;
        let old = sess_map.remove(primary);
        // Enforce max_clients on UDP too — the TCP auth path does (T7), but this one never
        // did, so a UDP profile admitted clients up to the pool size and silently ignored a
        // smaller configured cap. A brand-new client (no prior session at this IP) beyond
        // the cap is refused under the same lock as the insert; a reconnect reusing its own
        // IP is not counted. The reserved pool IP is released below on rejection. (M3)
        let replaced_routes = if old.is_some() {
            sess_map.take_client_routes(primary)
        } else {
            Vec::new()
        };
        if let Some(previous) = sess_map.insert(session) {
            previous.kick_all();
        }
        let programmed = crate::server::handler::register_client_subnets(
            &mut sess_map,
            &client_subnets,
            client_ip,
            &writer_session,
            &server_tun,
            &writer_session.username,
            &profile.name,
        );
        (old, replaced_routes, programmed)
    };
    for cidr in &replaced_iroutes {
        let _ = handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
    }
    if let Some(old) = old_to_evict {
        old.kick_all();
        if old.device_key != writer_session.device_key {
            profile.pool.lock().await.release(&old.device_key);
        }
        sessions
            .write()
            .await
            .remove_session_owner(old.session_id, old.peer);
    }
    let mut installed_iroutes: Vec<String> = Vec::new();
    for cidr in &programmed_iroutes {
        if let Err(error) =
            handler::program_client_subnet_route(true, cidr, &profile.config.tun.name).await
        {
            let orphan_routes = {
                let mut session_map = profile.sessions.write().await;
                if session_map
                    .by_ip
                    .get(&client_ip)
                    .is_some_and(|current| current.session_id == writer_session.session_id)
                {
                    session_map.remove(client_ip);
                    session_map.take_client_routes(client_ip)
                } else {
                    Vec::new()
                }
            };
            for installed in installed_iroutes.iter().rev() {
                let _ = handler::program_client_subnet_route(
                    false,
                    installed,
                    &profile.config.tun.name,
                )
                .await;
            }
            profile
                .pool
                .lock()
                .await
                .release(&writer_session.device_key);
            sessions.write().await.remove(&addr);
            log::warn!(
                "UDP: refusing client {} on profile '{}' because client_subnet '{}' could not be installed: {} ({} in-memory route(s) rolled back)",
                addr,
                profile.name,
                cidr,
                error,
                orphan_routes.len()
            );
            drop(admission_guard);
            return;
        }
        installed_iroutes.push(cidr.clone());
    }
    // Publish every authenticated-session cell before AuthOK. Once AuthOK is on the wire the
    // client may immediately send its one-shot info and path reports on another worker turn;
    // linking these cells afterwards created a race where those valid control frames saw
    // `None` and were silently ignored. Admission and route programming are already complete,
    // so an early authenticated frame cannot observe a half-admitted session.
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.revoked = Some(writer_session.revoked.clone());
            client.path_mtu = Some(writer_session.path_mtu.clone());
            if data_frag_enabled {
                client.udp_payload_budget = Some(writer_udp_payload_budget.clone());
            }
            client.client_info = Some(writer_session.client_info.clone());
        }
    }

    // ADMITTED — only now does the client learn it is authenticated.
    //
    // Charge what actually goes on the wire first: this send used to be invisible to the
    // budget, so `amp_sent` described a server that had replied with the ServerHello and
    // nothing since, and every later decision was made against a history missing its largest
    // entry. (Audit 2026-08-02, §4.)
    let sent_now: u64 = response_pkts.iter().map(|d| d.len() as u64).sum();
    if let Some(client) = sessions.write().await.get_mut(&addr) {
        client.amp_sent = client.amp_sent.saturating_add(sent_now);
    }
    for pkt in &response_pkts {
        let _ = socket.send_to(pkt, addr).await;
    }
    // The AuthOK is on the wire — the beacon and cover loops may write to this session now.
    // Set AFTER the sends, not before: the whole point is that nothing precedes it, and the
    // flag exists to make that an invariant rather than a timing accident. See `auth_ok_sent`.
    if let Some(client) = sessions.write().await.get_mut(&addr) {
        client.auth_ok_sent = true;
    }

    // Do not let another transport supersede this session between the authoritative insert
    // and its first client-visible AuthOK. UDP sends are bounded to the already-built
    // fragment list, so this does not place an unbounded operation under the admission lock.
    drop(admission_guard);
    log::info!(
        "UDP client {} authenticated on profile '{}', IP: {}",
        addr,
        profile.name,
        client_ip
    );

    // Notify (opt-in, off by default): a new UDP session came up.
    crate::server::notify::fire_connect(&writer_session.username, &profile.name, addr);

    let profile_name = profile.name.clone();
    tasks.spawn(async move {
        let mut quic_record = Vec::with_capacity(
            wire_pool.buffer_capacity() + crate::protocol::roaming::UDP_SHORT_HEADER_LEN,
        );
        let mut record_id: u64 = rand::random();
        let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
        let mut encrypted_record =
            Vec::with_capacity(crate::protocol::packet::TLS_RECORD_HEADER
                + crate::protocol::packet::MAX_RECORD_SIZE);
        let mut recordizer =
            writer_recordizer_runtime.map(crate::protocol::recordizer::Recordizer::new);
        let mut active_mux_payload_budget = writer_mux_payload_budget;
        'writer: loop {
            let (current_egress, current_udp_payload_budget) =
                writer_egress.snapshot_with_payload_budget(&writer_udp_payload_budget);
            let current_mux_payload_budget =
                current_egress
                    .record_budget(current_udp_payload_budget)
                .and_then(|record_budget| {
                    lock_or_recover(&writer_task_codec, "udp::recordizer_budget_update")
                        .max_data_for_record_budget(record_budget)
                        .ok()
                });
            if let Some(new_budget) = current_mux_payload_budget
                .filter(|budget| *budget > active_mux_payload_budget)
            {
                if let (Some(mux), Some(config)) =
                    (recordizer.as_mut(), writer_recordizer_config.as_ref())
                {
                    let runtime = crate::protocol::recordizer::RuntimeConfig::from_config(
                        config,
                        new_budget,
                        crate::protocol::packet::MAX_TUNNEL_MTU,
                    )
                    .expect("validated UDP recordizer configuration");
                    mux.raise_runtime(runtime)
                        .expect("certified UDP PMTU only raises the recordizer budget");
                    log::info!(
                        "UDP recordizer widened server payload budget from {} to {} bytes",
                        active_mux_payload_budget,
                        new_budget
                    );
                }
                active_mux_payload_budget = new_budget;
            }
            let mux_deadline = recordizer
                .as_ref()
                .and_then(|mux| mux.deadline())
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| {
                    tokio::time::Instant::now() + std::time::Duration::from_secs(86_400)
                });
            let payloads = tokio::select! {
                biased;
                _ = kick_rx.recv() => {
                    let peer = writer_egress.snapshot().peer;
                    log::info!("UDP writer for {} kicked on profile '{}'", peer, profile_name);
                    break 'writer;
                }
                _ = tokio::time::sleep_until(mux_deadline),
                    if recordizer.as_ref().is_some_and(|mux| mux.is_pending()) =>
                {
                    match recordizer.as_mut().and_then(|mux| {
                        mux.flush_due(std::time::Instant::now())
                    }) {
                        Some(payload) => vec![payload],
                        None => continue,
                    }
                }
                msg = writer_rx.recv() => {
                    match msg {
                        Some(packet) => {
                            if let Some(mux) = recordizer.as_mut() {
                                match mux.push(packet.as_ref(), std::time::Instant::now()) {
                                    Ok(payloads) => payloads,
                                    Err(error) => {
                                        log::debug!("server UDP recordizer dropped a packet: {error}");
                                        writer_session
                                            .dropped
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        continue;
                                    }
                                }
                            } else {
                                vec![packet.to_vec()]
                            }
                        }
                        None => match recordizer.as_mut().and_then(|mux| mux.flush()) {
                            Some(payload) => vec![payload],
                            None => break 'writer,
                        },
                    }
                }
            };
            for payload in payloads {
                if !handler::encrypt_server_stream_payload(
                    &writer_task_codec,
                    &payload,
                    active_mux_payload_budget,
                    &writer_profile_config,
                    &mut encrypted_record,
                    &mut padding,
                ) {
                    writer_session
                        .dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                let data: &[u8] = &encrypted_record;
                    // Aggregate per-session DOWNLOAD throttle. The independent upload
                    // pacing task applies the same limit concurrently. Also account
                    // outbound bytes for list-clients and quota tracking.
                    let limit = writer_session
                        .bandwidth_limit_mbps
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let mut retried_at_floor = false;
                    'budget_attempt: loop {
                        // One complete encrypted record uses one immutable egress snapshot. A
                        // concurrent commit may affect the next record, never split fragments
                        // of this one across old and new paths.
                        let (egress, current_udp_payload_budget) =
                            writer_egress.snapshot_with_payload_budget(&writer_udp_payload_budget);
                        let safe_udp_payload_budget = egress.safe_payload_budget();
                        let writer_record_budget = egress
                            .record_budget(current_udp_payload_budget)
                            .or_else(|| egress.record_budget(safe_udp_payload_budget))
                            .expect("conservative UDP budget fits the active path framing");
                        if data_frag_enabled && data.len() > writer_record_budget {
                            let this_record_id = record_id;
                            record_id = record_id.wrapping_add(1);
                            let fragments = match crate::protocol::data_frag::fragment_record(
                                data,
                                &writer_data_frag_key,
                                this_record_id,
                                writer_record_budget - crate::protocol::data_frag::HEADER_LEN,
                            ) {
                                Ok(fragments) => fragments,
                                Err(error) => {
                                    log::warn!(
                                        "UDP writer for {} could not fragment a data record: {}",
                                        egress.peer, error
                                    );
                                    writer_session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    break 'budget_attempt;
                                }
                            };
                            let wrappers = egress.wire_wrapper_len();
                            let attempted_wire_len: u64 = fragments
                                .iter()
                                .map(|fragment| (fragment.len() + wrappers) as u64)
                                .sum();
                            let delay = writer_session
                                .rates
                                .download
                                .consume(attempted_wire_len * 8, limit);
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            let mut sent_wire_len = 0u64;
                            let mut send_error = None;
                            for fragment in fragments {
                                let packet_number = if egress.framing.uses_packet_number() {
                                    writer_pn.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                } else {
                                    0
                                };
                                let pkt = egress.framing.wrap_into(
                                    &fragment,
                                    packet_number,
                                    &mut quic_record,
                                );
                                match egress.socket.send_to(pkt, egress.peer).await {
                                    Ok(sent) => sent_wire_len += sent as u64,
                                    Err(error) => {
                                        send_error = Some(error);
                                        break;
                                    }
                                }
                            }
                            if sent_wire_len > 0 {
                                writer_session
                                    .bytes_sent
                                    .fetch_add(sent_wire_len, std::sync::atomic::Ordering::Relaxed);
                            }
                            if let Some(error) = send_error {
                                if is_message_too_long(&error)
                                    && !retried_at_floor
                                    && current_udp_payload_budget > safe_udp_payload_budget
                                {
                                    let applied_floor = writer_egress.downgrade_payload_budget(
                                        egress.path_epoch,
                                        &writer_udp_payload_budget,
                                    );
                                    retried_at_floor = true;
                                    log::warn!(
                                        "UDP writer for {} hit EMSGSIZE at {} bytes; retrying the complete record at the conservative {}-byte budget",
                                        egress.peer,
                                        current_udp_payload_budget,
                                        applied_floor
                                    );
                                    continue 'budget_attempt;
                                }
                                writer_session
                                    .dropped
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                log::warn!(
                                    "UDP writer for {} dropped a fragmented record after send failure: {}",
                                    egress.peer, error
                                );
                            }
                            break 'budget_attempt;
                        }

                        // Build the actual wire datagram before accounting. Only a successful
                        // send is charged; a local EMSGSIZE after a path change downgrades the
                        // session and retries the SAME encrypted record through DATA_FRAG.
                        let packet_number = if egress.framing.uses_packet_number() {
                            writer_pn.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        } else {
                            0
                        };
                        let pkt = egress
                            .framing
                            .wrap_into(data, packet_number, &mut quic_record);
                        let wire_len = (pkt.len() + egress.socket.seal_overhead()) as u64;
                        let delay = writer_session.rates.download.consume(wire_len * 8, limit);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        match egress.socket.send_to(pkt, egress.peer).await {
                            Ok(sent) => {
                                writer_session
                                    .bytes_sent
                                    .fetch_add(sent as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(error)
                                if data_frag_enabled
                                    && is_message_too_long(&error)
                                    && !retried_at_floor
                                    && current_udp_payload_budget > safe_udp_payload_budget =>
                            {
                                let applied_floor = writer_egress.downgrade_payload_budget(
                                    egress.path_epoch,
                                    &writer_udp_payload_budget,
                                );
                                retried_at_floor = true;
                                log::warn!(
                                    "UDP writer for {} hit EMSGSIZE at {} bytes; retrying through DATA_FRAG at the conservative {}-byte budget",
                                    egress.peer,
                                    current_udp_payload_budget,
                                    applied_floor
                                );
                                continue 'budget_attempt;
                            }
                            Err(error) => {
                                writer_session
                                    .dropped
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                log::warn!(
                                    "UDP writer for {} dropped a record after send failure: {}",
                                    egress.peer, error
                                );
                            }
                        }
                        break 'budget_attempt;
                    }
                }
            }
    });
}

#[allow(clippy::too_many_arguments)] // handshake threads server-auth policy flags
async fn handle_new_udp_client(
    profile: &Arc<ProfileRuntime>,
    initial_packet: &[u8],
    _addr: SocketAddr,
    quic_detected: bool,
    hide_identity: bool,
    bind_static: bool,
) -> anyhow::Result<(UdpClient, Vec<u8>)> {
    // Anti-amplification (QUIC RFC 9000 §8 style). This does NOT make reflection
    // impossible — our handshake response is still larger than the request (~2-3.4 KB vs
    // ~1.35 KB) — but it BOUNDS the gain: the size floor here plus the explicit 3× check
    // after the response is built keep a spoofed-source attacker from turning us into a
    // high-gain reflector (the reply stays within the QUIC-accepted 3× of bytes received).
    // Legitimate clients pad their UDP ClientHello to ≥1200B (see client/mod.rs).
    const MIN_UDP_INITIAL: usize = 1200;
    if initial_packet.len() < MIN_UDP_INITIAL {
        return Err(anyhow::anyhow!(
            "UDP initial too small ({}B < {}B) — anti-amplification guard",
            initial_packet.len(),
            MIN_UDP_INITIAL
        ));
    }

    // Build the handshake records + channel-binding transcript via the shared
    // helper (identical to the TCP path in handler.rs). The "ClientHello" is the
    // unwrapped initial datagram; the transcript order matches the client
    // (ClientHello‖ServerHello‖Cert‖Finished).
    let server_kp = Keypair::generate();
    let handler::HandshakeRecords {
        client_pub,
        server_hello,
        ccs,
        cert,
        finished,
        nst,
        transcript_hash,
        mlkem_shared,
    } = handler::build_handshake_records(initial_packet, server_kp.public())?;

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order client public key"))?;
    // UDP is always a fake-tls-family mode (plain is TCP-only), so always hybrid PQ.
    // H-1: optionally bind the keys to the server static identity (es folded in).
    let es = bind_static.then(|| profile.static_keypair.derive_shared(&client_pub).0);
    #[cfg(feature = "experimental-roaming")]
    let session_material = match &es {
        Some(es) => derive_session_material_hybrid_bound(&shared.0, &mlkem_shared, es),
        None => derive_session_material_hybrid(&shared.0, &mlkem_shared),
    };
    #[cfg(feature = "experimental-roaming")]
    let (server_to_client_key, client_to_server_key) = session_material.data_keys();
    #[cfg(feature = "experimental-roaming")]
    let client_to_server_cid_secret =
        zeroize::Zeroizing::new(*session_material.client_to_server_cid_secret());
    #[cfg(feature = "experimental-roaming")]
    let server_to_client_cid_secret =
        zeroize::Zeroizing::new(*session_material.server_to_client_cid_secret());
    #[cfg(not(feature = "experimental-roaming"))]
    let (server_to_client_key, client_to_server_key) = match &es {
        Some(es) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, es),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };
    let tx_data_frag_key = derive_data_frag_key(&server_to_client_key);
    let rx_data_frag_key = derive_data_frag_key(&client_to_server_key);

    let mut server_tx = PacketCodec::new(server_to_client_key);
    let server_rx = PacketCodec::new(client_to_server_key);

    let static_shared = profile.static_keypair.derive_shared(&client_pub);
    let auth_proof_encrypted = {
        let auth_msg = handler::build_server_auth_msg_with_capabilities(
            &profile.static_keypair,
            &client_pub,
            &shared.0,
            &transcript_hash,
            hide_identity,
            crate::protocol::capabilities::udp_server_capabilities_for_profile(
                profile.config.roaming.enabled,
            ),
        );
        server_tx.encrypt_packet(&auth_msg, &[])?
    };

    let mut response = Vec::with_capacity(
        server_hello.len()
            + ccs.len()
            + cert.len()
            + finished.len()
            + nst.len()
            + auth_proof_encrypted.len(),
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&ccs);
    response.extend_from_slice(&cert);
    response.extend_from_slice(&finished);
    response.extend_from_slice(&nst);
    response.extend_from_slice(&auth_proof_encrypted);

    // Enforce the 3× anti-amplification bound explicitly (see MIN_UDP_INITIAL above). Today
    // the response is well under 3× a ≥1200B initial, but a future larger cert / handshake
    // extension could push it over — refuse to reply rather than become a high-gain
    // reflector for a spoofed source.
    if response.len() > 3 * initial_packet.len() {
        return Err(anyhow::anyhow!(
            "handshake response {}B exceeds 3x the {}B initial datagram — refusing to reply \
             (anti-amplification)",
            response.len(),
            initial_packet.len()
        ));
    }

    let connection_id = if quic_detected {
        generate_connection_id()
    } else {
        [0u8; 4]
    };

    // Return the RAW handshake response. The caller fragments it (LTE/CGNAT fix) and
    // QUIC-wraps each fragment with the client's `connection_id` — see
    // `send_handshake_response`.
    let now = std::time::Instant::now();
    Ok((
        UdpClient {
            rx_codec: Arc::new(std::sync::Mutex::new(server_rx)),
            tx_codec: Arc::new(std::sync::Mutex::new(server_tx)),
            rx_data_frag_key,
            tx_data_frag_key,
            #[cfg(feature = "experimental-roaming")]
            client_to_server_cid_secret: Some(client_to_server_cid_secret),
            #[cfg(feature = "experimental-roaming")]
            server_to_client_cid_secret: Some(server_to_client_cid_secret),
            #[cfg(feature = "experimental-roaming")]
            _udp_roaming_registration: None,
            #[cfg(feature = "experimental-roaming")]
            _udp_roaming_initial_cids: None,
            #[cfg(feature = "experimental-roaming")]
            udp_roaming_candidate: None,
            data_frag_enabled: false,
            data_reassembler: crate::protocol::data_frag::DataReassembler::new(),
            rx_recordizer: None,
            state: UdpSessionState::AwaitingAuth,
            src_guard: None,
            exit_access: crate::server::ExitAccess::default(),
            revoked: None,
            path_mtu: None,
            udp_payload_budget: None,
            downlink_mtu_probe: Arc::new(std::sync::Mutex::new(None)),
            client_info: None,
            wire_pool: None,
            // Seed the budget with the exchange that just happened, so the session starts
            // already accounted for rather than with a free allowance. Both sides are the
            // MESSAGE, not the datagrams: a fragmented ClientHello is undercounted by its
            // fragment headers (stricter) and the ServerHello by its QUIC/obfs wrappers
            // (looser). See the note on `amp_received`.
            amp_received: initial_packet.len() as u64,
            amp_sent: response.len() as u64,
            auth_ok_reemits: 0,
            auth_ok_sent: false,
            last_activity: now,
            bytes_recv: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            bandwidth_limit_mbps: None,
            upload_tx: None,
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            created_at: now,
            connection_id,
            quic_enabled: quic_detected,
            packet_counter: Arc::new(std::sync::atomic::AtomicU32::new(UDP_SESSION_FIRST_PN)),
            active_egress: None,
            ephemeral_shared: shared.0,
            static_shared: static_shared.0,
            transcript_hash,
            shaper: {
                // Stealth is TCP-only: on UDP the rate-cap + cover-under-load was
                // measured to crater throughput (lock contention under load), so
                // UDP keeps Phase-1 idle cover only. (bench_stealth.py)
                let mut sh = profile.config.obfuscation.traffic_shaping.to_shaping();
                sh.stealth = false;
                crate::protocol::Shaper::new(sh, now)
            },
            next_cover_at: if profile.config.obfuscation.traffic_shaping.enabled {
                now
            } else {
                now + crate::protocol::randomized_heartbeat_delay(
                    std::time::Duration::from_millis(
                        profile.config.obfuscation.heartbeat.interval_ms,
                    ),
                    std::time::Duration::from_millis(
                        profile.config.obfuscation.heartbeat.jitter_ms,
                    ),
                )
            },
            server_hello: Vec::new(),
            hello_frag_mode: false,
            auth_request: Vec::new(),
            auth_ok: Vec::new(), // no datagrams cached until authenticated
            dst_acl: crate::server::acl::DstAcl::compile(&[], "unauthenticated UDP session"),
        },
        response,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_auth_error_datagrams, build_auth_ok_datagrams, build_downlink_mtu_probe,
        max_useful_udp_payload_budget, sanitized_udp_payload_budget, udp_reap_window,
        UdpEgressFraming, AUTH_OK_FIRST_PN, UDP_SESSION_FIRST_PN,
    };
    #[cfg(feature = "experimental-roaming")]
    use super::{
        classify_udp_roaming_uplink_probe, decrypt_udp_roaming_record, encrypt_udp_roaming_control,
        UdpActiveEgress, UdpEgressCommit, UdpEgressCommitError, UdpEgressPublishError,
        UdpRoamingControlError, UdpRoamingIngressPath, UdpRoamingOwnerIndex, UdpRoamingPmtuAction,
    };
    use crate::protocol::udp_frag;
    use std::time::Duration;

    #[cfg(feature = "experimental-roaming")]
    fn encrypted_path_control(
        codec: &mut crate::protocol::PacketCodec,
        message_id: u32,
        message: &crate::protocol::roaming::PathControl,
    ) -> Vec<u8> {
        let frame = crate::protocol::control_v2::fragment_message(
            message.message_type(),
            0,
            message_id,
            &message.encode_body(),
        )
        .unwrap()
        .pop()
        .unwrap();
        codec.encrypt_packet(&frame, &[]).unwrap()
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_roaming_pmtu_ingress_echoes_v2_only_on_committed_path() {
        let token = 0x0123456789abcdef_fedcba9876543210u128;
        let probe = udp_frag::mtu_probe_v2_datagram(token, 1400).expect("V2 probe");

        let action = classify_udp_roaming_uplink_probe(&probe, UdpRoamingIngressPath::Committed);
        let UdpRoamingPmtuAction::Ack(ack) = action else {
            panic!("committed V2 probe was not acknowledged: {action:?}");
        };
        assert_eq!(udp_frag::parse_mtu_probe_v2_ack(&ack), Some((token, 1400)));

        for path in [
            UdpRoamingIngressPath::Candidate,
            UdpRoamingIngressPath::Draining,
        ] {
            assert_eq!(
                classify_udp_roaming_uplink_probe(&probe, path),
                UdpRoamingPmtuAction::Drop,
                "non-committed path must not receive a PMTU ACK"
            );
        }

        let mut malformed = probe.clone();
        malformed.truncate(udp_frag::FRAG_HDR_LEN + udp_frag::PROBE_V2_BODY_LEN);
        assert_eq!(
            classify_udp_roaming_uplink_probe(&malformed, UdpRoamingIngressPath::Committed,),
            UdpRoamingPmtuAction::Drop,
            "declared and received V2 probe sizes must match"
        );

        let legacy = udp_frag::mtu_probe_datagram(0xBEEF, 1200).expect("legacy probe");
        let legacy_action =
            classify_udp_roaming_uplink_probe(&legacy, UdpRoamingIngressPath::Committed);
        let UdpRoamingPmtuAction::Ack(legacy_ack) = legacy_action else {
            panic!("committed legacy probe was not acknowledged: {legacy_action:?}");
        };
        assert_eq!(
            udp_frag::parse_mtu_probe_ack(&legacy_ack),
            Some((0xBEEF, 1200))
        );
        assert_eq!(
            classify_udp_roaming_uplink_probe(
                b"PacketCodec record",
                UdpRoamingIngressPath::Committed,
            ),
            UdpRoamingPmtuAction::NotProbe
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_roaming_control_decoder_shares_packet_codec_and_accepts_client_direction() {
        use crate::protocol::roaming::PathControl;

        let key = [0x61; 32];
        let mut sender = crate::protocol::PacketCodec::new(key);
        let mut receiver = crate::protocol::PacketCodec::new(key);
        let expected = PathControl::Init {
            cid: [0x72; 8],
            epoch: 4,
        };
        let mut record = encrypted_path_control(&mut sender, 17, &expected);
        let decoded = decrypt_udp_roaming_record(&mut receiver, &mut record)
            .unwrap()
            .expect("PATH_INIT is control");
        assert_eq!(decoded.message_id, 17);
        assert!(decoded.message == expected);

        let mut response = encrypted_path_control(
            &mut sender,
            18,
            &PathControl::Response {
                epoch: 4,
                token: [0x83; 16],
            },
        );
        let mut replay = response.clone();
        assert!(decrypt_udp_roaming_record(&mut receiver, &mut response)
            .unwrap()
            .is_some());
        assert_eq!(
            decrypt_udp_roaming_record(&mut receiver, &mut replay).err(),
            Some(UdpRoamingControlError::Decrypt)
        );

        let expected_data = b"authenticated post-commit data";
        let mut data = sender.encrypt_packet(expected_data, &[]).unwrap();
        assert!(decrypt_udp_roaming_record(&mut receiver, &mut data)
            .unwrap()
            .is_none());
        assert_eq!(data, expected_data);
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_roaming_control_decoder_rejects_server_direction_and_fragmented_control() {
        use crate::protocol::roaming::PathControl;

        let key = [0x91; 32];
        let mut sender = crate::protocol::PacketCodec::new(key);
        let mut receiver = crate::protocol::PacketCodec::new(key);
        let mut challenge = encrypted_path_control(
            &mut sender,
            21,
            &PathControl::Challenge {
                epoch: 2,
                token: [0xA2; 16],
            },
        );
        assert_eq!(
            decrypt_udp_roaming_record(&mut receiver, &mut challenge).err(),
            Some(UdpRoamingControlError::UnexpectedDirection)
        );

        let fragmented = crate::protocol::control_v2::Frame {
            message_type: crate::protocol::control_v2::TYPE_PATH_INIT,
            flags: 0,
            message_id: 22,
            part_index: 0,
            part_count: 2,
            payload: &[],
        }
        .encode()
        .unwrap();
        let mut fragmented = sender.encrypt_packet(&fragmented, &[]).unwrap();
        assert_eq!(
            decrypt_udp_roaming_record(&mut receiver, &mut fragmented).err(),
            Some(UdpRoamingControlError::FragmentedControl)
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_path_control_egress_uses_verified_cids_and_authenticated_shapes() {
        use crate::protocol::roaming::PathControl;

        let key = [0xB1; 32];
        let sender = std::sync::Arc::new(std::sync::Mutex::new(crate::protocol::PacketCodec::new(
            key,
        )));
        let counter = std::sync::atomic::AtomicU32::new(29);
        let destination_cid = [0xC2; crate::protocol::roaming::CID_LEN];
        let challenge = PathControl::Challenge {
            epoch: 3,
            token: [0xD3; crate::protocol::roaming::PATH_CHALLENGE_LEN],
        };
        let wire = encrypt_udp_roaming_control(&sender, &counter, destination_cid, 31, &challenge)
            .unwrap();
        let (header, record) = crate::protocol::roaming::decode_udp_short(&wire).unwrap();
        assert_eq!(header.destination_cid(), &destination_cid);
        assert_eq!(header.packet_number(), 29);
        let mut receiver = crate::protocol::PacketCodec::new(key);
        let plaintext = receiver.decrypt_packet(record).unwrap();
        let frame = crate::protocol::control_v2::decode(&plaintext).unwrap();
        assert_eq!(frame.message_id, 31);
        assert_eq!(frame.flags, 0);
        assert!(PathControl::decode(frame.message_type, frame.payload).unwrap() == challenge);

        let commit_destination_cid = [0xE4; crate::protocol::roaming::CID_LEN];
        let commit = PathControl::Commit {
            cid: [0xF5; crate::protocol::roaming::CID_LEN],
            epoch: 3,
        };
        let wire =
            encrypt_udp_roaming_control(&sender, &counter, commit_destination_cid, 32, &commit)
                .unwrap();
        let (header, record) = crate::protocol::roaming::decode_udp_short(&wire).unwrap();
        assert_eq!(header.destination_cid(), &commit_destination_cid);
        assert_eq!(header.packet_number(), 30);
        let plaintext = receiver.decrypt_packet(record).unwrap();
        let frame = crate::protocol::control_v2::decode(&plaintext).unwrap();
        assert_eq!(frame.message_id, 32);
        assert_eq!(frame.flags, 0);
        assert!(PathControl::decode(frame.message_type, frame.payload).unwrap() == commit);
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_roaming_owner_index_rejects_stale_generation_cleanup() {
        use crate::transport_core::udp_roaming::{UdpPath, UdpRoamingRegistry};

        let registry = UdpRoamingRegistry::new(2);
        let old_address = "127.0.0.1:41001".parse().unwrap();
        let new_address = "127.0.0.1:41002".parse().unwrap();
        let first = registry
            .register_session(7, [1; 32], [2; 32], UdpPath::new(0, old_address), 1200)
            .unwrap();
        let first_lookup = registry.lookup(first.receive()).unwrap();

        let mut index = UdpRoamingOwnerIndex::default();
        index.publish(
            first_lookup.session_id(),
            first_lookup.session_generation(),
            old_address,
        );
        assert_eq!(index.resolve(first_lookup), Some(old_address));

        assert!(registry.remove_session(7));
        let second = registry
            .register_session(7, [3; 32], [4; 32], UdpPath::new(0, new_address), 1200)
            .unwrap();
        let second_lookup = registry.lookup(second.receive()).unwrap();
        assert_ne!(
            first_lookup.session_generation(),
            second_lookup.session_generation()
        );
        index.publish(
            second_lookup.session_id(),
            second_lookup.session_generation(),
            new_address,
        );
        index.remove_if_matches(7, first_lookup.session_generation(), old_address);
        assert_eq!(index.resolve(second_lookup), Some(new_address));
    }

    #[test]
    fn negotiation_error_uses_the_authenticated_record_and_quic_framing() {
        let key = [0x5au8; 32];
        let cid = [9u8, 8, 7, 6];
        for quic_enabled in [false, true] {
            let mut tx = crate::protocol::PacketCodec::new(key);
            let mut rx = crate::protocol::PacketCodec::new(key);
            let packets = build_auth_error_datagrams(
                &mut tx,
                "profile requires IPv6 capability",
                quic_enabled,
                &cid,
            )
            .expect("ERR response builds");
            assert_eq!(packets.len(), 1);
            let record = if quic_enabled {
                crate::protocol::quic::unwrap_quic(&packets[0])
                    .expect("QUIC response")
                    .payload
            } else {
                packets[0].clone()
            };
            let response = String::from_utf8(rx.decrypt_packet(&record).unwrap()).unwrap();
            assert_eq!(response, "ERR:profile requires IPv6 capability");
        }
    }

    /// A small AuthOK must go out EXACTLY as it always did.
    ///
    /// This is the whole backward-compatibility argument for adding `MSG_AUTH_OK`: clients
    /// that predate it keep working because they never see a fragment in any case that works
    /// today. If this test ever goes red, every deployed client breaks at once.
    #[test]
    fn a_small_auth_ok_is_still_one_unfragmented_datagram() {
        let record = vec![0xABu8; 400];
        let plain = build_auth_ok_datagrams(&record, false, &[0; 4]).expect("fits");
        assert_eq!(plain, vec![record.clone()], "byte-identical to the record");
        assert!(!udp_frag::is_fragment(&plain[0]), "no fragment envelope");

        // Exactly at the budget is still one datagram — the boundary the receiver's
        // MAX_CHUNK bound is written against.
        let edge = vec![0x11u8; udp_frag::MAX_CHUNK];
        assert_eq!(
            build_auth_ok_datagrams(&edge, false, &[0; 4])
                .expect("fits")
                .len(),
            1
        );

        // With QUIC masking on it is the short header, not the long one: the AuthOK is
        // post-handshake, so it must look like the data plane that follows it.
        let masked = build_auth_ok_datagrams(&record, true, &[9, 8, 7, 6]).expect("fits");
        assert_eq!(masked.len(), 1);
        assert_ne!(masked[0], record, "QUIC wrapper applied");
    }

    /// Over the budget it splits, and every piece is small enough to cross a path that
    /// drops IP fragments — the LTE/CGNAT failure this exists to remove.
    #[test]
    fn a_large_auth_ok_is_split_and_reassembles_to_the_same_record() {
        // ~40 pushed routes' worth: the size at which the single datagram was being eaten.
        let record: Vec<u8> = (0..3_000u32).map(|i| (i * 7) as u8).collect();
        let dgrams = build_auth_ok_datagrams(&record, false, &[0; 4]).expect("splits");
        assert!(
            dgrams.len() > 1,
            "must not be sent as one oversized datagram"
        );

        let mut re = udp_frag::Reassembler::new();
        let mut done = None;
        for d in &dgrams {
            assert!(
                udp_frag::is_auth_ok_fragment(d),
                "the client recognizes it by MSG_AUTH_OK, not by guessing"
            );
            assert!(
                d.len() <= udp_frag::FRAG_HDR_LEN + udp_frag::MAX_CHUNK,
                "fragment {} is over the per-datagram budget",
                d.len()
            );
            done = re.push(d).expect("well-formed fragment");
        }
        assert_eq!(
            done.expect("completes"),
            record,
            "reassembly must return the encrypted record unchanged — it is decrypted after"
        );
    }

    /// No packet number may be issued twice — not between fragments, and not between the
    /// fragments and the DATA plane that follows them.
    ///
    /// The wire numbers positionally: ServerHello 0, AuthOK 1, session from
    /// [`UDP_SESSION_FIRST_PN`]. Fragmenting the AuthOK broke that arithmetic, because N
    /// fragments consume 1..=N and the session counter still started at 2 — so with two or
    /// more fragments the first data packet reused PN 2. The earlier version of this test
    /// compared the fragments only WITH EACH OTHER and was green throughout.
    /// (Audit 2026-08-02, §8.)
    #[test]
    fn the_data_plane_never_reuses_an_authok_pn() {
        use crate::protocol::quic::unwrap_quic;
        let cid = [1u8, 2, 3, 4];

        for record_len in [400usize, 3_000, 9_000] {
            let record: Vec<u8> = (0..record_len).map(|i| (i * 7) as u8).collect();
            let dgrams = build_auth_ok_datagrams(&record, true, &cid).expect("builds");

            let pns: Vec<u32> = dgrams
                .iter()
                .map(|d| unwrap_quic(d).expect("QUIC-wrapped").packet_number)
                .collect();
            let expected: Vec<u32> = (0..dgrams.len() as u32)
                .map(|i| AUTH_OK_FIRST_PN + i)
                .collect();
            assert_eq!(
                pns, expected,
                "{record_len}B: fragments must number consecutively"
            );

            // What the auth path reserves, and the invariant that makes it correct.
            let reserved = AUTH_OK_FIRST_PN + dgrams.len() as u32;
            assert!(
                pns.iter().all(|&pn| pn < reserved),
                "{record_len}B: the reservation must clear every fragment's PN"
            );
            // The session counter only moves forward (`fetch_max`), so the first data packet
            // takes max(UDP_SESSION_FIRST_PN, reserved) — which must clear the fragments too.
            let first_data_pn = reserved.max(UDP_SESSION_FIRST_PN);
            assert!(
                !pns.contains(&first_data_pn),
                "{record_len}B: the data plane's first PN collides with a fragment"
            );
        }

        // The single-datagram case must be untouched: PN 1, session still starts at 2.
        let small = build_auth_ok_datagrams(&[0xAB; 400], true, &cid).expect("fits");
        assert_eq!(small.len(), 1);
        assert_eq!(
            unwrap_quic(&small[0]).unwrap().packet_number,
            AUTH_OK_FIRST_PN
        );
        assert_eq!(
            AUTH_OK_FIRST_PN + small.len() as u32,
            UDP_SESSION_FIRST_PN,
            "the reservation must be a no-op for an unfragmented AuthOK"
        );
    }

    /// Past `MAX_FRAGS` the receiver would reject the message, so the sender must refuse
    /// it here rather than emit something the client silently drops.
    #[test]
    fn an_unfragmentable_auth_ok_is_refused_not_emitted() {
        let huge = vec![0u8; udp_frag::MAX_FRAGS as usize * udp_frag::MAX_CHUNK + 1];
        assert!(build_auth_ok_datagrams(&huge, false, &[0; 4]).is_err());
    }

    #[test]
    fn reap_window_uses_configured_liveness_when_idle_disabled() {
        assert_eq!(
            udp_reap_window(Duration::ZERO, Some(Duration::from_secs(45))),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            udp_reap_window(Duration::ZERO, Some(Duration::from_secs(30))),
            Some(Duration::from_secs(30))
        );
        assert_eq!(udp_reap_window(Duration::ZERO, None), None);
    }

    #[test]
    fn reap_window_honors_shorter_idle_timeout() {
        // An explicit idle_timeout shorter than the liveness window wins (reap sooner).
        assert_eq!(
            udp_reap_window(Duration::from_secs(10), Some(Duration::from_secs(45))),
            Some(Duration::from_secs(10))
        );
        // A longer idle_timeout is capped by the liveness window (dead detection).
        assert_eq!(
            udp_reap_window(Duration::from_secs(600), Some(Duration::from_secs(45))),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            udp_reap_window(Duration::from_secs(600), None),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn reported_udp_budget_never_drops_below_the_family_safe_floor() {
        assert_eq!(sanitized_udp_payload_budget(1, false, 0), 548);
        assert_eq!(sanitized_udp_payload_budget(1, true, 0), 1232);
        assert_eq!(sanitized_udp_payload_budget(1500, false, 13), 1500);
        assert_eq!(sanitized_udp_payload_budget(1500, true, 13), 1500);
        assert_eq!(
            sanitized_udp_payload_budget(u16::MAX, false, 13),
            max_useful_udp_payload_budget(13),
            "an authenticated client still cannot make the server emit a useless 64K probe"
        );
    }

    #[test]
    #[cfg(feature = "experimental-roaming")]
    fn reverse_probe_ladder_can_certify_a_narrower_downlink_than_reported_uplink() {
        let framing = UdpEgressFraming::RoamingCid([9; 8]);
        let budgets = super::downlink_mtu_probe_budgets(1461, false, 0, framing);
        assert_eq!(budgets.first().copied(), Some(1461));
        let highest_fitting = budgets
            .iter()
            .copied()
            .find(|budget| budget + 8 + 20 <= 1280)
            .expect("the IPv4 floor fits");
        assert_eq!(highest_fitting, 1161);
        assert!(budgets.windows(2).all(|pair| pair[0] > pair[1]));

        let ipv6 = super::downlink_mtu_probe_budgets(1461, true, 0, framing);
        assert_eq!(
            ipv6.last().copied(),
            Some(crate::protocol::data_frag::conservative_udp_payload_budget(
                true
            )),
            "the final IPv6 rung must exactly fit the 1280-byte path minimum"
        );
    }

    #[test]
    fn reverse_probe_exactly_fills_the_reported_udp_payload_budget() {
        for (obfs, framing) in [
            (0usize, UdpEgressFraming::Unmasked),
            (13, UdpEgressFraming::Unmasked),
            (0, UdpEgressFraming::LegacyQuic([1, 2, 3, 4])),
            (13, UdpEgressFraming::LegacyQuic([1, 2, 3, 4])),
        ] {
            let target = 1500;
            let (packet, payload_size) =
                build_downlink_mtu_probe(7, target, obfs, framing, 9).expect("target fits");
            assert_eq!(packet.len() + obfs, target);
            assert_eq!(
                usize::from(payload_size) + obfs + framing.wrapper_len(),
                target
            );
        }
        #[cfg(feature = "experimental-roaming")]
        {
            let framing = UdpEgressFraming::RoamingCid([9; 8]);
            let (packet, payload_size) =
                build_downlink_mtu_probe(11, 1500, 13, framing, 17).expect("target fits");
            assert_eq!(packet.len() + 13, 1500);
            assert_eq!(usize::from(payload_size) + 13 + framing.wrapper_len(), 1500);
            let (header, record) = crate::protocol::roaming::decode_udp_short(&packet)
                .expect("roaming header decodes");
            assert_eq!(header.destination_cid(), &[9; 8]);
            assert_eq!(header.packet_number(), 17);
            assert_eq!(record.len(), usize::from(payload_size));
        }
    }

    #[cfg(feature = "experimental-roaming")]
    #[tokio::test]
    async fn udp_writer_path_commit_is_atomic_epoch_guarded_and_uses_the_new_cid() {
        let first_socket = std::sync::Arc::new(crate::protocol::obfs::ObfsUdp::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            None,
        ));
        let second_socket = std::sync::Arc::new(crate::protocol::obfs::ObfsUdp::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            None,
        ));
        let first_peer = "127.0.0.1:41001".parse().unwrap();
        let second_peer = "127.0.0.1:41002".parse().unwrap();

        let bootstrapped = UdpActiveEgress::new_roaming(first_socket.clone(), first_peer, [6; 8]);
        let bootstrapped_snapshot = bootstrapped.snapshot();
        let mut bootstrapped_wire = Vec::new();
        assert_eq!(
            bootstrapped_snapshot
                .framing
                .wrap_into(b"record", 6, &mut bootstrapped_wire),
            crate::protocol::roaming::UdpShortHeader::new([6; 8], 6).encode(b"record")
        );
        assert_eq!(
            bootstrapped.classify_roaming_ingress(0, first_peer, &first_socket),
            Some(UdpRoamingIngressPath::Committed)
        );
        assert_eq!(
            bootstrapped.classify_roaming_ingress(1, second_peer, &second_socket),
            Some(UdpRoamingIngressPath::Candidate)
        );

        let active =
            UdpActiveEgress::new_legacy(first_socket.clone(), first_peer, true, [1, 2, 3, 4]);

        let mut wire = Vec::new();
        let initial = active.snapshot();
        let encoded = initial.framing.wrap_into(b"record", 7, &mut wire);
        assert_eq!(
            encoded,
            crate::protocol::quic::wrap_quic_short(b"record", &[1, 2, 3, 4], 7)
        );
        assert_eq!(initial.peer, first_peer);
        assert!(std::sync::Arc::ptr_eq(&initial.socket, &first_socket));
        assert_eq!(
            active.classify_roaming_ingress(0, first_peer, &first_socket),
            None,
            "the current CID must not carry DATA until roaming framing is committed"
        );
        assert_eq!(
            active.classify_roaming_ingress(1, second_peer, &second_socket),
            Some(UdpRoamingIngressPath::Candidate)
        );
        assert_eq!(
            initial.record_budget(548),
            Some(548 - crate::protocol::quic::QUIC_SHORT_HEADER_MIN)
        );

        let payload_budget = std::sync::atomic::AtomicU32::new(1500);
        assert_eq!(
            active.commit_roaming(
                UdpEgressCommit {
                    expected_epoch: 1,
                    expected_peer: first_peer,
                    next_epoch: 2,
                    socket: second_socket.clone(),
                    peer: second_peer,
                    destination_cid: [9; 8],
                },
                &payload_budget
            ),
            Err(UdpEgressCommitError::StaleEpoch)
        );
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            1500
        );
        assert_eq!(active.snapshot().peer, first_peer);
        assert_eq!(
            active.certify_payload_budget(0, first_peer, &payload_budget, 1492),
            Some(1500)
        );
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            1492
        );
        let rejected = active.commit_roaming_with(
            UdpEgressCommit {
                expected_epoch: 0,
                expected_peer: first_peer,
                next_epoch: 1,
                socket: second_socket.clone(),
                peer: second_peer,
                destination_cid: [9; 8],
            },
            &payload_budget,
            |_, _| Err("socket busy"),
        );
        assert!(matches!(
            rejected,
            Err(UdpEgressPublishError::Publish("socket busy"))
        ));
        let unchanged = active.snapshot();
        assert_eq!(unchanged.path_epoch, 0);
        assert_eq!(unchanged.peer, first_peer);
        assert!(std::sync::Arc::ptr_eq(&unchanged.socket, &first_socket));
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            1492,
            "a failed PATH_COMMIT send must leave the old path and PMTU intact"
        );
        active
            .commit_roaming(
                UdpEgressCommit {
                    expected_epoch: 0,
                    expected_peer: first_peer,
                    next_epoch: 1,
                    socket: second_socket.clone(),
                    peer: second_peer,
                    destination_cid: [9; 8],
                },
                &payload_budget,
            )
            .unwrap();
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            548
        );

        let committed = active.snapshot();
        assert_eq!(committed.path_epoch, 1);
        assert_eq!(committed.peer, second_peer);
        assert!(std::sync::Arc::ptr_eq(&committed.socket, &second_socket));
        assert_eq!(
            active.classify_roaming_ingress(1, second_peer, &second_socket),
            Some(UdpRoamingIngressPath::Committed)
        );
        assert_eq!(
            active.classify_roaming_ingress(0, first_peer, &first_socket),
            None,
            "legacy bootstrap framing is not a roaming receive-drain alias"
        );
        assert_eq!(
            active.classify_roaming_ingress(0, second_peer, &first_socket),
            None,
            "the draining epoch still pins its exact peer and socket"
        );
        assert_eq!(
            active.classify_roaming_ingress(2, first_peer, &first_socket),
            Some(UdpRoamingIngressPath::Candidate)
        );
        assert_eq!(
            active.classify_roaming_ingress(0, second_peer, &second_socket),
            None,
            "a previous CID epoch cannot migrate to the new peer/socket"
        );
        assert_eq!(
            active.classify_roaming_ingress(1, first_peer, &second_socket),
            None
        );
        assert_eq!(
            active.classify_roaming_ingress(1, second_peer, &first_socket),
            None,
            "a same-family listener cannot impersonate the committed receiving socket"
        );
        assert_eq!(
            committed.record_budget(548),
            Some(548 - crate::protocol::roaming::UDP_SHORT_HEADER_LEN)
        );
        assert_eq!(
            active.certify_payload_budget(0, first_peer, &payload_budget, 1492),
            None,
            "an ACK for the old path cannot widen the committed path budget"
        );
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            548
        );
        assert_eq!(
            active.certify_payload_budget(1, second_peer, &payload_budget, 1472),
            Some(548)
        );
        assert_eq!(
            payload_budget.load(std::sync::atomic::Ordering::Relaxed),
            1472
        );
        let encoded = committed.framing.wrap_into(b"record", 8, &mut wire);
        assert_eq!(
            encoded,
            crate::protocol::roaming::UdpShortHeader::new([9; 8], 8).encode(b"record")
        );
        assert_eq!(
            active.commit_roaming(
                UdpEgressCommit {
                    expected_epoch: 1,
                    expected_peer: first_peer,
                    next_epoch: 2,
                    socket: first_socket.clone(),
                    peer: first_peer,
                    destination_cid: [7; 8],
                },
                &payload_budget
            ),
            Err(UdpEgressCommitError::StalePeer)
        );
        assert_eq!(
            active.commit_roaming(
                UdpEgressCommit {
                    expected_epoch: 0,
                    expected_peer: first_peer,
                    next_epoch: 1,
                    socket: first_socket.clone(),
                    peer: first_peer,
                    destination_cid: [7; 8],
                },
                &payload_budget
            ),
            Err(UdpEgressCommitError::StaleEpoch)
        );
        active
            .commit_roaming(
                UdpEgressCommit {
                    expected_epoch: 1,
                    expected_peer: second_peer,
                    next_epoch: 2,
                    socket: first_socket.clone(),
                    peer: first_peer,
                    destination_cid: [7; 8],
                },
                &payload_budget,
            )
            .unwrap();
        assert_eq!(active.snapshot().peer, first_peer);
        assert_eq!(
            active.classify_roaming_ingress(2, first_peer, &first_socket),
            Some(UdpRoamingIngressPath::Committed)
        );
        assert_eq!(
            active.classify_roaming_ingress(1, second_peer, &second_socket),
            Some(UdpRoamingIngressPath::Draining),
            "the exact previous roaming path remains receive-only for bounded DATA_FRAG drain"
        );
        assert_eq!(
            active.classify_roaming_ingress(1, first_peer, &second_socket),
            None,
            "the draining epoch remains pinned to its exact peer and socket"
        );
        {
            let mut draining = active
                .1
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            draining.as_mut().expect("draining snapshot").expires_at =
                std::time::Instant::now() - std::time::Duration::from_millis(1);
        }
        assert_eq!(
            active.classify_roaming_ingress(1, second_peer, &second_socket),
            None,
            "previous roaming ingress is rejected after the bounded drain expires"
        );
        assert!(
            !active.2.load(std::sync::atomic::Ordering::Acquire),
            "classifying current or stale ingress releases the expired socket snapshot"
        );
    }
}
