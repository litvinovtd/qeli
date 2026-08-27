//! Bounded profile-wide state for authenticated UDP path migration.
//!
//! This module deliberately owns no sockets or packet codecs. The server hot path performs
//! AEAD/replay verification first, then presents an authenticated CID lookup and exact path to
//! this table. Keeping registry mutation, candidate ownership, anti-amplification accounting,
//! CID rotation and PMTU generations under one mutable owner makes worker handoff atomic without
//! changing the default/non-negotiated UDP data plane.

use crate::protocol::roaming::{derive_udp_cid, CID_LEN, PATH_CHALLENGE_LEN};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub const MAX_CID_ALIASES_PER_SESSION: usize = 3;
pub const ANTI_AMPLIFICATION_FACTOR: u64 = 3;
/// Only accounting is retained, never candidate payloads. Capping the counter prevents an
/// authenticated peer from manufacturing an effectively unlimited pre-validation send budget.
pub const MAX_CANDIDATE_ACCOUNTED_BYTES: u64 = 1024 * 1024;
/// A profile may have many authenticated sessions, but unfinished path validation must remain a
/// small, independently bounded resource.
pub const MAX_UDP_ROAMING_CANDIDATES_PER_PROFILE: usize = 1024;
pub const UDP_ROAMING_CANDIDATE_TTL: Duration = Duration::from_secs(10);
pub const UDP_ROAMING_CANDIDATE_RATE_WINDOW: Duration = Duration::from_secs(1);
pub const MAX_UDP_ROAMING_CANDIDATE_STARTS_PER_WINDOW: usize = 64;

pub type UdpCid = [u8; CID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpPath {
    worker_id: u32,
    peer: SocketAddr,
}

impl UdpPath {
    pub fn new(worker_id: u32, peer: SocketAddr) -> Self {
        Self { worker_id, peer }
    }

    pub fn worker_id(self) -> u32 {
        self.worker_id
    }

    pub fn peer(self) -> SocketAddr {
        self.peer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidLookup {
    session_id: u64,
    session_generation: u64,
    owner_worker_id: u32,
    path_epoch: u64,
}

impl CidLookup {
    pub fn session_id(self) -> u64 {
        self.session_id
    }

    pub fn session_generation(self) -> u64 {
        self.session_generation
    }

    pub fn owner_worker_id(self) -> u32 {
        self.owner_worker_id
    }

    pub fn path_epoch(self) -> u64 {
        self.path_epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidateTicket {
    session_id: u64,
    session_generation: u64,
    candidate_id: u64,
    path_epoch: u64,
}

impl CandidateTicket {
    pub fn session_id(self) -> u64 {
        self.session_id
    }

    pub fn candidate_id(self) -> u64 {
        self.candidate_id
    }

    pub fn path_epoch(self) -> u64 {
        self.path_epoch
    }
}

/// Challenge material is intentionally not `Debug`: full tokens must never reach logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CandidateChallenge {
    ticket: CandidateTicket,
    token: [u8; PATH_CHALLENGE_LEN],
}

impl CandidateChallenge {
    pub fn ticket(self) -> CandidateTicket {
        self.ticket
    }

    pub fn token(&self) -> &[u8; PATH_CHALLENGE_LEN] {
        &self.token
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PmtuTicket {
    session_id: u64,
    session_generation: u64,
    path_epoch: u64,
    pmtu_generation: u64,
    path: UdpPath,
}

impl PmtuTicket {
    pub fn path_epoch(self) -> u64 {
        self.path_epoch
    }

    pub fn path(self) -> UdpPath {
        self.path
    }
}

/// Initial directional CIDs are secrets-on-the-wire and intentionally omit `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InitialCids {
    receive: UdpCid,
    transmit: UdpCid,
    pmtu: PmtuTicket,
}

impl InitialCids {
    pub fn receive(&self) -> &UdpCid {
        &self.receive
    }

    pub fn transmit(&self) -> &UdpCid {
        &self.transmit
    }

    pub fn pmtu(self) -> PmtuTicket {
        self.pmtu
    }
}

/// Commit output crosses into the socket-owning actor and therefore also omits `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    old_path: UdpPath,
    new_path: UdpPath,
    path_epoch: u64,
    receive_cid: UdpCid,
    transmit_cid: UdpCid,
    pmtu: PmtuTicket,
}

impl CommitOutcome {
    pub fn old_path(self) -> UdpPath {
        self.old_path
    }

    pub fn new_path(self) -> UdpPath {
        self.new_path
    }

    pub fn path_epoch(self) -> u64 {
        self.path_epoch
    }

    pub fn receive_cid(&self) -> &UdpCid {
        &self.receive_cid
    }

    pub fn transmit_cid(&self) -> &UdpCid {
        &self.transmit_cid
    }

    pub fn pmtu(self) -> PmtuTicket {
        self.pmtu
    }
}

/// Distinguishes the first registry/path publication from an exact retry after a lost
/// `PATH_COMMIT`. It deliberately omits `Debug` because the nested outcome contains CIDs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommitDecision {
    outcome: CommitOutcome,
    replayed: bool,
}

impl CommitDecision {
    pub fn outcome(self) -> CommitOutcome {
        self.outcome
    }

    pub fn is_replay(self) -> bool {
        self.replayed
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UdpRoamingError {
    #[error("UDP roaming requires a non-zero session id and payload budget")]
    InvalidSession,
    #[error("UDP roaming session already exists")]
    SessionExists,
    #[error("UDP roaming session limit reached")]
    SessionLimit,
    #[error("UDP roaming session or CID lookup is stale")]
    StaleSession,
    #[error("UDP CID collision")]
    CidCollision,
    #[error("UDP path init CID does not match the negotiated session epoch")]
    InvalidCid,
    #[error("UDP path epoch is stale or not the next expected epoch")]
    StaleEpoch,
    #[error("another UDP path candidate already owns this session")]
    CandidateBusy,
    #[error("UDP path candidate limit reached for this profile")]
    CandidateLimit,
    #[error("UDP path candidate creation rate exceeded for this profile")]
    CandidateRateLimited,
    #[error("UDP path candidate ticket or source path is stale")]
    StaleCandidate,
    #[error("UDP path response does not match the outstanding challenge")]
    InvalidResponse,
    #[error("UDP candidate exceeded the 3x anti-amplification budget")]
    AmplificationLimit,
    #[error("UDP roaming generation space is exhausted")]
    GenerationExhausted,
    #[error("UDP PMTU result belongs to an old path generation")]
    StalePmtu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpRoamingCommitError<E> {
    State(UdpRoamingError),
    Publish(E),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CidOwner {
    session_id: u64,
    session_generation: u64,
    path_epoch: u64,
}

#[derive(Clone, Copy)]
struct ActivePath {
    path: UdpPath,
    epoch: u64,
    receive_cid: UdpCid,
    transmit_cid: UdpCid,
    payload_budget: u16,
    pmtu_generation: u64,
}

struct CandidatePath {
    ticket: CandidateTicket,
    path: UdpPath,
    challenge: [u8; PATH_CHALLENGE_LEN],
    created_at: Instant,
    received_bytes: u64,
    sent_bytes: u64,
}

struct CommittedPath {
    ticket: CandidateTicket,
    path: UdpPath,
    challenge: [u8; PATH_CHALLENGE_LEN],
    outcome: CommitOutcome,
}

struct UdpSession {
    generation: u64,
    owner_worker_id: u32,
    client_to_server_cid_secret: Zeroizing<[u8; 32]>,
    server_to_client_cid_secret: Zeroizing<[u8; 32]>,
    aliases: Vec<(UdpCid, u64)>,
    active: ActivePath,
    candidate: Option<CandidatePath>,
    last_commit: Option<CommittedPath>,
}

/// One instance is owned by a profile actor (or protected by one profile-wide mutex).
/// All operations are O(1) except rotation/cleanup over at most three aliases per session.
pub struct UdpRoamingTable {
    max_sessions: usize,
    max_candidates: usize,
    candidate_ttl: Duration,
    candidate_rate_window: Duration,
    max_candidate_starts_per_window: usize,
    candidate_starts: VecDeque<Instant>,
    candidate_count: usize,
    next_session_generation: u64,
    next_candidate_id: u64,
    cid_index: HashMap<UdpCid, CidOwner>,
    sessions: HashMap<u64, UdpSession>,
}

impl UdpRoamingTable {
    pub fn new(max_sessions: usize) -> Self {
        Self::with_candidate_policy(
            max_sessions,
            max_sessions.min(MAX_UDP_ROAMING_CANDIDATES_PER_PROFILE),
            UDP_ROAMING_CANDIDATE_TTL,
            UDP_ROAMING_CANDIDATE_RATE_WINDOW,
            MAX_UDP_ROAMING_CANDIDATE_STARTS_PER_WINDOW,
        )
    }

    fn with_candidate_policy(
        max_sessions: usize,
        max_candidates: usize,
        candidate_ttl: Duration,
        candidate_rate_window: Duration,
        max_candidate_starts_per_window: usize,
    ) -> Self {
        debug_assert!(!candidate_ttl.is_zero());
        debug_assert!(!candidate_rate_window.is_zero());
        Self {
            max_sessions,
            max_candidates,
            candidate_ttl,
            candidate_rate_window,
            max_candidate_starts_per_window,
            candidate_starts: VecDeque::with_capacity(max_candidate_starts_per_window),
            candidate_count: 0,
            next_session_generation: 1,
            next_candidate_id: 1,
            cid_index: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn cid_count(&self) -> usize {
        self.cid_index.len()
    }

    pub fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    pub fn lookup(&self, cid: &UdpCid) -> Option<CidLookup> {
        self.cid_index.get(cid).copied().and_then(|owner| {
            let owner_worker_id = self.sessions.get(&owner.session_id)?.owner_worker_id;
            Some(CidLookup {
                session_id: owner.session_id,
                session_generation: owner.session_generation,
                owner_worker_id,
                path_epoch: owner.path_epoch,
            })
        })
    }

    pub fn register_session(
        &mut self,
        session_id: u64,
        client_to_server_cid_secret: [u8; 32],
        server_to_client_cid_secret: [u8; 32],
        active_path: UdpPath,
        safe_payload_budget: u16,
    ) -> Result<InitialCids, UdpRoamingError> {
        if session_id == 0 || safe_payload_budget == 0 {
            return Err(UdpRoamingError::InvalidSession);
        }
        if self.sessions.contains_key(&session_id) {
            return Err(UdpRoamingError::SessionExists);
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(UdpRoamingError::SessionLimit);
        }
        let generation = self.allocate_session_generation()?;
        let receive_aliases = derive_aliases(&client_to_server_cid_secret, session_id, 0)?;
        self.ensure_aliases_available(session_id, generation, &receive_aliases)?;
        let receive_cid = receive_aliases[0].0;
        let transmit_cid = derive_udp_cid(&server_to_client_cid_secret, session_id, 0);
        for (cid, path_epoch) in &receive_aliases {
            self.cid_index.insert(
                *cid,
                CidOwner {
                    session_id,
                    session_generation: generation,
                    path_epoch: *path_epoch,
                },
            );
        }
        let pmtu = PmtuTicket {
            session_id,
            session_generation: generation,
            path_epoch: 0,
            pmtu_generation: 0,
            path: active_path,
        };
        self.sessions.insert(
            session_id,
            UdpSession {
                generation,
                owner_worker_id: active_path.worker_id,
                client_to_server_cid_secret: Zeroizing::new(client_to_server_cid_secret),
                server_to_client_cid_secret: Zeroizing::new(server_to_client_cid_secret),
                aliases: receive_aliases,
                active: ActivePath {
                    path: active_path,
                    epoch: 0,
                    receive_cid,
                    transmit_cid,
                    payload_budget: safe_payload_budget,
                    pmtu_generation: 0,
                },
                candidate: None,
                last_commit: None,
            },
        );
        Ok(InitialCids {
            receive: receive_cid,
            transmit: transmit_cid,
            pmtu,
        })
    }

    pub fn observe_authenticated_candidate(
        &mut self,
        lookup: CidLookup,
        path: UdpPath,
        init_transmit_cid: &UdpCid,
        init_epoch: u64,
        received_bytes: usize,
        challenge: [u8; PATH_CHALLENGE_LEN],
    ) -> Result<CandidateChallenge, UdpRoamingError> {
        self.observe_authenticated_candidate_at(
            lookup,
            path,
            init_transmit_cid,
            init_epoch,
            received_bytes,
            challenge,
            Instant::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_authenticated_candidate_at(
        &mut self,
        lookup: CidLookup,
        path: UdpPath,
        init_transmit_cid: &UdpCid,
        init_epoch: u64,
        received_bytes: usize,
        challenge: [u8; PATH_CHALLENGE_LEN],
        now: Instant,
    ) -> Result<CandidateChallenge, UdpRoamingError> {
        if received_bytes == 0 {
            return Err(UdpRoamingError::InvalidResponse);
        }
        self.expire_candidate_for_session_at(lookup.session_id, now);
        let received_bytes = u64::try_from(received_bytes)
            .unwrap_or(u64::MAX)
            .min(MAX_CANDIDATE_ACCOUNTED_BYTES);
        {
            let session = self
                .sessions
                .get_mut(&lookup.session_id)
                .ok_or(UdpRoamingError::StaleSession)?;
            validate_lookup(session, lookup)?;
            let expected = session
                .active
                .epoch
                .checked_add(1)
                .ok_or(UdpRoamingError::GenerationExhausted)?;
            if lookup.path_epoch != expected
                || init_epoch != expected
                || path == session.active.path
            {
                return Err(UdpRoamingError::StaleEpoch);
            }
            let expected_transmit_cid = derive_udp_cid(
                &session.server_to_client_cid_secret,
                lookup.session_id,
                expected,
            );
            if init_transmit_cid != &expected_transmit_cid {
                return Err(UdpRoamingError::InvalidCid);
            }
            if let Some(candidate) = session.candidate.as_mut() {
                if candidate.ticket.path_epoch != lookup.path_epoch || candidate.path != path {
                    return Err(UdpRoamingError::CandidateBusy);
                }
                candidate.received_bytes = candidate
                    .received_bytes
                    .saturating_add(received_bytes)
                    .min(MAX_CANDIDATE_ACCOUNTED_BYTES);
                return Ok(CandidateChallenge {
                    ticket: candidate.ticket,
                    token: candidate.challenge,
                });
            }
        }
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(UdpRoamingError::InvalidResponse);
        }
        if self.candidate_count >= self.max_candidates {
            self.expire_candidates_at(now);
            if self.candidate_count >= self.max_candidates {
                return Err(UdpRoamingError::CandidateLimit);
            }
        }
        self.prune_candidate_starts(now);
        if self.candidate_starts.len() >= self.max_candidate_starts_per_window {
            return Err(UdpRoamingError::CandidateRateLimited);
        }
        let candidate_id = self.allocate_candidate_id()?;
        let session = self
            .sessions
            .get_mut(&lookup.session_id)
            .expect("validated session remains present");
        let ticket = CandidateTicket {
            session_id: lookup.session_id,
            session_generation: lookup.session_generation,
            candidate_id,
            path_epoch: lookup.path_epoch,
        };
        session.candidate = Some(CandidatePath {
            ticket,
            path,
            challenge,
            created_at: now,
            received_bytes,
            sent_bytes: 0,
        });
        self.candidate_count += 1;
        self.candidate_starts.push_back(now);
        Ok(CandidateChallenge {
            ticket,
            token: challenge,
        })
    }

    /// Reserve exact unvalidated wire bytes before sending them to a candidate address.
    pub fn authorize_candidate_send(
        &mut self,
        ticket: CandidateTicket,
        wire_bytes: usize,
    ) -> Result<(), UdpRoamingError> {
        self.expire_candidate_for_session_at(ticket.session_id, Instant::now());
        let candidate = self.candidate_mut(ticket)?;
        let wire_bytes = u64::try_from(wire_bytes).unwrap_or(u64::MAX);
        let next_sent = candidate.sent_bytes.saturating_add(wire_bytes);
        let limit = candidate
            .received_bytes
            .saturating_mul(ANTI_AMPLIFICATION_FACTOR);
        if next_sent > limit {
            return Err(UdpRoamingError::AmplificationLimit);
        }
        candidate.sent_bytes = next_sent;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_response_and_commit(
        &mut self,
        ticket: CandidateTicket,
        path: UdpPath,
        response_epoch: u64,
        response_token: &[u8; PATH_CHALLENGE_LEN],
        received_bytes: usize,
        safe_payload_budget: u16,
    ) -> Result<CommitOutcome, UdpRoamingError> {
        match self.validate_response_and_commit_with(
            ticket,
            path,
            response_epoch,
            response_token,
            received_bytes,
            safe_payload_budget,
            |_| Ok::<(), std::convert::Infallible>(()),
        ) {
            Ok(decision) => Ok(decision.outcome()),
            Err(UdpRoamingCommitError::State(error)) => Err(error),
            Err(UdpRoamingCommitError::Publish(never)) => match never {},
        }
    }

    /// Validate a response, publish the external socket/address state, and only then rotate the
    /// registry. The synchronous callback runs while this table is locked: it must neither await
    /// nor re-enter the registry. A publication error leaves aliases, active path, PMTU generation,
    /// and candidate ownership unchanged. An exact authenticated retry of the last committed
    /// response returns the cached decision without invoking `publish` or changing path state.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_response_and_commit_with<E>(
        &mut self,
        ticket: CandidateTicket,
        path: UdpPath,
        response_epoch: u64,
        response_token: &[u8; PATH_CHALLENGE_LEN],
        received_bytes: usize,
        safe_payload_budget: u16,
        publish: impl FnOnce(CommitOutcome) -> Result<(), E>,
    ) -> Result<CommitDecision, UdpRoamingCommitError<E>> {
        if received_bytes == 0 || safe_payload_budget == 0 {
            return Err(UdpRoamingCommitError::State(
                UdpRoamingError::InvalidResponse,
            ));
        }
        if let Some(replayed) = self
            .replayed_commit(ticket, path, response_epoch, response_token)
            .map_err(UdpRoamingCommitError::State)?
        {
            return Ok(replayed);
        }
        self.expire_candidate_for_session_at(ticket.session_id, Instant::now());
        let challenge = {
            let candidate = self
                .candidate_mut(ticket)
                .map_err(UdpRoamingCommitError::State)?;
            if candidate.path != path {
                return Err(UdpRoamingCommitError::State(
                    UdpRoamingError::StaleCandidate,
                ));
            }
            if response_epoch != ticket.path_epoch || response_token != &candidate.challenge {
                return Err(UdpRoamingCommitError::State(
                    UdpRoamingError::InvalidResponse,
                ));
            }
            candidate.received_bytes = candidate
                .received_bytes
                .saturating_add(u64::try_from(received_bytes).unwrap_or(u64::MAX))
                .min(MAX_CANDIDATE_ACCOUNTED_BYTES);
            candidate.challenge
        };

        let (generation, old_path, client_to_server_secret, server_to_client_secret, pmtu) = {
            let session = self
                .sessions
                .get(&ticket.session_id)
                .ok_or(UdpRoamingError::StaleSession)
                .map_err(UdpRoamingCommitError::State)?;
            if session.generation != ticket.session_generation {
                return Err(UdpRoamingCommitError::State(UdpRoamingError::StaleSession));
            }
            let pmtu_generation = session
                .active
                .pmtu_generation
                .checked_add(1)
                .ok_or(UdpRoamingError::GenerationExhausted)
                .map_err(UdpRoamingCommitError::State)?;
            (
                session.generation,
                session.active.path,
                Zeroizing::new(*session.client_to_server_cid_secret),
                Zeroizing::new(*session.server_to_client_cid_secret),
                pmtu_generation,
            )
        };
        let aliases = derive_aliases(
            &client_to_server_secret,
            ticket.session_id,
            ticket.path_epoch,
        )
        .map_err(UdpRoamingCommitError::State)?;
        if let Err(error) = self.ensure_aliases_available(ticket.session_id, generation, &aliases) {
            self.abort_candidate(ticket);
            return Err(UdpRoamingCommitError::State(error));
        }
        let receive_cid = aliases
            .iter()
            .find_map(|(cid, epoch)| (*epoch == ticket.path_epoch).then_some(*cid))
            .expect("current epoch alias is present");
        let transmit_cid = derive_udp_cid(
            &server_to_client_secret,
            ticket.session_id,
            ticket.path_epoch,
        );
        let new_pmtu = PmtuTicket {
            session_id: ticket.session_id,
            session_generation: generation,
            path_epoch: ticket.path_epoch,
            pmtu_generation: pmtu,
            path,
        };
        let outcome = CommitOutcome {
            old_path,
            new_path: path,
            path_epoch: ticket.path_epoch,
            receive_cid,
            transmit_cid,
            pmtu: new_pmtu,
        };
        publish(outcome).map_err(UdpRoamingCommitError::Publish)?;

        let old_aliases = self
            .sessions
            .get(&ticket.session_id)
            .expect("validated session remains present")
            .aliases
            .clone();
        for (cid, _) in old_aliases {
            if !aliases.iter().any(|(wanted, _)| wanted == &cid)
                && self.cid_index.get(&cid).is_some_and(|owner| {
                    owner.session_id == ticket.session_id && owner.session_generation == generation
                })
            {
                self.cid_index.remove(&cid);
            }
        }
        for (cid, path_epoch) in &aliases {
            self.cid_index.insert(
                *cid,
                CidOwner {
                    session_id: ticket.session_id,
                    session_generation: generation,
                    path_epoch: *path_epoch,
                },
            );
        }

        let session = self
            .sessions
            .get_mut(&ticket.session_id)
            .expect("validated session remains present");
        session.aliases = aliases;
        session.active = ActivePath {
            path,
            epoch: ticket.path_epoch,
            receive_cid,
            transmit_cid,
            payload_budget: safe_payload_budget,
            pmtu_generation: pmtu,
        };
        session.last_commit = Some(CommittedPath {
            ticket,
            path,
            challenge,
            outcome,
        });
        let removed_candidate = session.candidate.take().is_some();
        debug_assert!(removed_candidate, "validated candidate remains present");
        self.candidate_count -= usize::from(removed_candidate);
        Ok(CommitDecision {
            outcome,
            replayed: false,
        })
    }

    pub fn abort_candidate(&mut self, ticket: CandidateTicket) -> bool {
        let removed = self
            .sessions
            .get_mut(&ticket.session_id)
            .filter(|session| session.generation == ticket.session_generation)
            .is_some_and(|session| {
                if session
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.ticket == ticket)
                {
                    session.candidate = None;
                    true
                } else {
                    false
                }
            });
        self.candidate_count -= usize::from(removed);
        removed
    }

    /// Remove all candidates whose fixed validation lifetime elapsed. Duplicate PATH_INIT packets
    /// deliberately do not refresh this deadline, so an authenticated peer cannot pin a slot.
    pub fn expire_candidates(&mut self) -> Vec<CandidateTicket> {
        self.expire_candidates_at(Instant::now())
    }

    pub fn current_pmtu_ticket(&self, session_id: u64) -> Option<PmtuTicket> {
        self.sessions.get(&session_id).map(|session| PmtuTicket {
            session_id,
            session_generation: session.generation,
            path_epoch: session.active.epoch,
            pmtu_generation: session.active.pmtu_generation,
            path: session.active.path,
        })
    }

    /// PMTU can widen only the currently committed path generation. A late result is rejected.
    pub fn raise_payload_budget(
        &mut self,
        ticket: PmtuTicket,
        payload_budget: u16,
    ) -> Result<bool, UdpRoamingError> {
        let session = self
            .sessions
            .get_mut(&ticket.session_id)
            .ok_or(UdpRoamingError::StalePmtu)?;
        if session.generation != ticket.session_generation
            || session.active.epoch != ticket.path_epoch
            || session.active.pmtu_generation != ticket.pmtu_generation
            || session.active.path != ticket.path
        {
            return Err(UdpRoamingError::StalePmtu);
        }
        if payload_budget > session.active.payload_budget {
            session.active.payload_budget = payload_budget;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn payload_budget(&self, session_id: u64) -> Option<u16> {
        self.sessions
            .get(&session_id)
            .map(|session| session.active.payload_budget)
    }

    pub fn active_path(&self, session_id: u64) -> Option<UdpPath> {
        self.sessions
            .get(&session_id)
            .map(|session| session.active.path)
    }

    pub fn active_epoch(&self, session_id: u64) -> Option<u64> {
        self.sessions
            .get(&session_id)
            .map(|session| session.active.epoch)
    }

    pub fn active_receive_cid(&self, session_id: u64) -> Option<UdpCid> {
        self.sessions
            .get(&session_id)
            .map(|session| session.active.receive_cid)
    }

    pub fn active_transmit_cid(&self, session_id: u64) -> Option<UdpCid> {
        self.sessions
            .get(&session_id)
            .map(|session| session.active.transmit_cid)
    }

    pub fn remove_session(&mut self, session_id: u64) -> bool {
        let Some(session) = self.sessions.remove(&session_id) else {
            return false;
        };
        self.candidate_count -= usize::from(session.candidate.is_some());
        for (cid, _) in session.aliases {
            if self.cid_index.get(&cid).is_some_and(|owner| {
                owner.session_id == session_id && owner.session_generation == session.generation
            }) {
                self.cid_index.remove(&cid);
            }
        }
        true
    }

    fn remove_session_generation(&mut self, session_id: u64, generation: u64) -> bool {
        if self
            .sessions
            .get(&session_id)
            .is_none_or(|session| session.generation != generation)
        {
            return false;
        }
        self.remove_session(session_id)
    }

    fn allocate_session_generation(&mut self) -> Result<u64, UdpRoamingError> {
        let generation = self.next_session_generation;
        self.next_session_generation = generation
            .checked_add(1)
            .ok_or(UdpRoamingError::GenerationExhausted)?;
        Ok(generation)
    }

    fn allocate_candidate_id(&mut self) -> Result<u64, UdpRoamingError> {
        let candidate_id = self.next_candidate_id;
        self.next_candidate_id = candidate_id
            .checked_add(1)
            .ok_or(UdpRoamingError::GenerationExhausted)?;
        Ok(candidate_id)
    }

    fn expire_candidate_for_session_at(
        &mut self,
        session_id: u64,
        now: Instant,
    ) -> Option<CandidateTicket> {
        let expired = self
            .sessions
            .get(&session_id)
            .and_then(|session| session.candidate.as_ref())
            .is_some_and(|candidate| {
                now.checked_duration_since(candidate.created_at)
                    .is_some_and(|age| age >= self.candidate_ttl)
            });
        if !expired {
            return None;
        }
        let ticket = self
            .sessions
            .get_mut(&session_id)
            .and_then(|session| session.candidate.take())
            .map(|candidate| candidate.ticket)
            .expect("expired candidate remains present");
        self.candidate_count -= 1;
        Some(ticket)
    }

    fn expire_candidates_at(&mut self, now: Instant) -> Vec<CandidateTicket> {
        let expired_sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                session.candidate.as_ref().and_then(|candidate| {
                    now.checked_duration_since(candidate.created_at)
                        .is_some_and(|age| age >= self.candidate_ttl)
                        .then_some(*session_id)
                })
            })
            .collect();
        let expired = expired_sessions
            .into_iter()
            .filter_map(|session_id| self.expire_candidate_for_session_at(session_id, now))
            .collect();
        self.prune_candidate_starts(now);
        expired
    }

    fn prune_candidate_starts(&mut self, now: Instant) {
        while self.candidate_starts.front().is_some_and(|started_at| {
            now.checked_duration_since(*started_at)
                .is_some_and(|age| age >= self.candidate_rate_window)
        }) {
            self.candidate_starts.pop_front();
        }
    }

    fn ensure_aliases_available(
        &self,
        session_id: u64,
        session_generation: u64,
        aliases: &[(UdpCid, u64)],
    ) -> Result<(), UdpRoamingError> {
        for (cid, path_epoch) in aliases {
            if let Some(owner) = self.cid_index.get(cid) {
                if owner.session_id != session_id
                    || owner.session_generation != session_generation
                    || owner.path_epoch != *path_epoch
                {
                    return Err(UdpRoamingError::CidCollision);
                }
            }
        }
        Ok(())
    }

    fn replayed_commit(
        &self,
        ticket: CandidateTicket,
        path: UdpPath,
        response_epoch: u64,
        response_token: &[u8; PATH_CHALLENGE_LEN],
    ) -> Result<Option<CommitDecision>, UdpRoamingError> {
        let session = self
            .sessions
            .get(&ticket.session_id)
            .ok_or(UdpRoamingError::StaleCandidate)?;
        if session.generation != ticket.session_generation {
            return Err(UdpRoamingError::StaleCandidate);
        }
        let Some(committed) = session
            .last_commit
            .as_ref()
            .filter(|committed| committed.ticket == ticket)
        else {
            return Ok(None);
        };
        if committed.path != path {
            return Err(UdpRoamingError::StaleCandidate);
        }
        if response_epoch != ticket.path_epoch || response_token != &committed.challenge {
            return Err(UdpRoamingError::InvalidResponse);
        }
        Ok(Some(CommitDecision {
            outcome: committed.outcome,
            replayed: true,
        }))
    }

    fn candidate_mut(
        &mut self,
        ticket: CandidateTicket,
    ) -> Result<&mut CandidatePath, UdpRoamingError> {
        let session = self
            .sessions
            .get_mut(&ticket.session_id)
            .ok_or(UdpRoamingError::StaleCandidate)?;
        if session.generation != ticket.session_generation {
            return Err(UdpRoamingError::StaleCandidate);
        }
        session
            .candidate
            .as_mut()
            .filter(|candidate| candidate.ticket == ticket)
            .ok_or(UdpRoamingError::StaleCandidate)
    }
}

/// Cloneable profile-wide owner of UDP migration state. Keeping this handle independent from the
/// typed worker mailboxes lets authentication register the session before the ingress payload
/// plumbing is selected, while both still share one exact table.
#[derive(Clone)]
pub struct UdpRoamingRegistry {
    table: Arc<Mutex<UdpRoamingTable>>,
}

impl UdpRoamingRegistry {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            table: Arc::new(Mutex::new(UdpRoamingTable::new(max_sessions))),
        }
    }

    fn lock_table(&self) -> std::sync::MutexGuard<'_, UdpRoamingTable> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn register_session(
        &self,
        session_id: u64,
        client_to_server_cid_secret: [u8; 32],
        server_to_client_cid_secret: [u8; 32],
        active_path: UdpPath,
        safe_payload_budget: u16,
    ) -> Result<InitialCids, UdpRoamingError> {
        self.lock_table().register_session(
            session_id,
            client_to_server_cid_secret,
            server_to_client_cid_secret,
            active_path,
            safe_payload_budget,
        )
    }

    /// Register a session and return generation-scoped ownership. Dropping an old owner after a
    /// reconnect cannot remove a replacement that happens to reuse the same random session id.
    pub fn register_owned_session(
        &self,
        session_id: u64,
        client_to_server_cid_secret: [u8; 32],
        server_to_client_cid_secret: [u8; 32],
        active_path: UdpPath,
        safe_payload_budget: u16,
    ) -> Result<(InitialCids, UdpSessionRegistration), UdpRoamingError> {
        let initial = self.register_session(
            session_id,
            client_to_server_cid_secret,
            server_to_client_cid_secret,
            active_path,
            safe_payload_budget,
        )?;
        Ok((
            initial,
            UdpSessionRegistration {
                registry: self.clone(),
                session_id,
                session_generation: initial.pmtu.session_generation,
                active: true,
            },
        ))
    }

    pub fn lookup(&self, cid: &UdpCid) -> Option<CidLookup> {
        self.lock_table().lookup(cid)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_authenticated_candidate(
        &self,
        lookup: CidLookup,
        path: UdpPath,
        init_transmit_cid: &UdpCid,
        init_epoch: u64,
        received_bytes: usize,
        challenge: [u8; PATH_CHALLENGE_LEN],
    ) -> Result<CandidateChallenge, UdpRoamingError> {
        self.lock_table().observe_authenticated_candidate(
            lookup,
            path,
            init_transmit_cid,
            init_epoch,
            received_bytes,
            challenge,
        )
    }

    pub fn authorize_candidate_send(
        &self,
        ticket: CandidateTicket,
        wire_bytes: usize,
    ) -> Result<(), UdpRoamingError> {
        self.lock_table()
            .authorize_candidate_send(ticket, wire_bytes)
    }

    /// Hold the registry lock across external publication and commit so the socket owner and CID
    /// table cannot expose different path generations. The callback is synchronous and must not
    /// await or re-enter this registry.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_response_and_commit_with<E>(
        &self,
        ticket: CandidateTicket,
        path: UdpPath,
        response_epoch: u64,
        response_token: &[u8; PATH_CHALLENGE_LEN],
        received_bytes: usize,
        safe_payload_budget: u16,
        publish: impl FnOnce(CommitOutcome) -> Result<(), E>,
    ) -> Result<CommitDecision, UdpRoamingCommitError<E>> {
        self.lock_table().validate_response_and_commit_with(
            ticket,
            path,
            response_epoch,
            response_token,
            received_bytes,
            safe_payload_budget,
            publish,
        )
    }

    pub fn abort_candidate(&self, ticket: CandidateTicket) -> bool {
        self.lock_table().abort_candidate(ticket)
    }

    pub fn expire_candidates(&self) -> Vec<CandidateTicket> {
        self.lock_table().expire_candidates()
    }

    pub fn remove_session(&self, session_id: u64) -> bool {
        self.lock_table().remove_session(session_id)
    }

    fn remove_session_generation(&self, session_id: u64, generation: u64) -> bool {
        self.lock_table()
            .remove_session_generation(session_id, generation)
    }

    pub fn session_count(&self) -> usize {
        self.lock_table().session_count()
    }

    pub fn cid_count(&self) -> usize {
        self.lock_table().cid_count()
    }

    pub fn candidate_count(&self) -> usize {
        self.lock_table().candidate_count()
    }
}

/// Exact lifecycle owner for one generation of a registered UDP session. It deliberately omits
/// `Clone` and `Debug`: there must be one cleanup authority and no CID-bearing state in logs.
pub struct UdpSessionRegistration {
    registry: UdpRoamingRegistry,
    session_id: u64,
    session_generation: u64,
    active: bool,
}

impl UdpSessionRegistration {
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn session_generation(&self) -> u64 {
        self.session_generation
    }

    pub fn matches_lookup(&self, lookup: CidLookup) -> bool {
        self.session_id == lookup.session_id && self.session_generation == lookup.session_generation
    }
}

impl Drop for UdpSessionRegistration {
    fn drop(&mut self) {
        if self.active {
            self.registry
                .remove_session_generation(self.session_id, self.session_generation);
            self.active = false;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpWorkerRouteError {
    InvalidTopology,
    UnknownCid,
    UnknownWorker,
    QueueFull,
    WorkerClosed,
}

/// A failed route returns ownership of the payload without implementing `Debug`: encrypted
/// datagrams and their complete CID-bearing envelopes must not be formatted into logs.
pub struct UdpWorkerRouteFailure<T> {
    kind: UdpWorkerRouteError,
    payload: T,
}

impl<T> UdpWorkerRouteFailure<T> {
    fn new(kind: UdpWorkerRouteError, payload: T) -> Self {
        Self { kind, payload }
    }

    pub fn kind(&self) -> UdpWorkerRouteError {
        self.kind
    }

    pub fn into_payload(self) -> T {
        self.payload
    }
}

/// One authenticated-CID datagram delivered to the worker that owns the session codec.
/// The payload intentionally omits `Debug` for the same reason as [`UdpWorkerRouteFailure`].
pub struct UdpRoutedIngress<T> {
    lookup: CidLookup,
    received_path: UdpPath,
    packet_number: u32,
    payload: T,
}

impl<T> UdpRoutedIngress<T> {
    pub fn lookup(&self) -> CidLookup {
        self.lookup
    }

    pub fn received_path(&self) -> UdpPath {
        self.received_path
    }

    pub fn packet_number(&self) -> u32 {
        self.packet_number
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_payload(self) -> T {
        self.payload
    }
}

pub enum UdpIngressDispatch<T> {
    /// The source worker already owns the codec, so no channel hop is necessary.
    Local(UdpRoutedIngress<T>),
    /// Ownership was moved into the bounded home-worker mailbox.
    Queued,
}

/// Receive half owned by exactly one UDP worker. It cannot be cloned, which prevents two tasks
/// from concurrently consuming one session owner's routed ingress stream.
pub struct UdpWorkerMailbox<T> {
    worker_id: u32,
    receiver: mpsc::Receiver<UdpRoutedIngress<T>>,
}

impl<T> UdpWorkerMailbox<T> {
    pub fn worker_id(&self) -> u32 {
        self.worker_id
    }

    pub async fn recv(&mut self) -> Option<UdpRoutedIngress<T>> {
        self.receiver.recv().await
    }

    pub fn try_recv(&mut self) -> Result<UdpRoutedIngress<T>, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

/// Profile-wide bounded dispatch fabric. Session crypto remains owned by one worker; a packet
/// received on another SO_REUSEPORT socket crosses only this bounded mailbox after CID lookup.
/// Registry operations hold a non-async mutex for short O(1) state transitions and never await.
pub struct UdpWorkerFabric<T> {
    registry: UdpRoamingRegistry,
    routes: Vec<mpsc::Sender<UdpRoutedIngress<T>>>,
}

impl<T> Clone for UdpWorkerFabric<T> {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            routes: self.routes.clone(),
        }
    }
}

impl<T> UdpWorkerFabric<T> {
    pub fn new(
        worker_count: usize,
        queue_capacity: usize,
        max_sessions: usize,
    ) -> Result<(Self, Vec<UdpWorkerMailbox<T>>), UdpWorkerRouteError> {
        Self::with_registry(
            UdpRoamingRegistry::new(max_sessions),
            worker_count,
            queue_capacity,
        )
    }

    pub fn with_registry(
        registry: UdpRoamingRegistry,
        worker_count: usize,
        queue_capacity: usize,
    ) -> Result<(Self, Vec<UdpWorkerMailbox<T>>), UdpWorkerRouteError> {
        if worker_count == 0 || queue_capacity == 0 || u32::try_from(worker_count).is_err() {
            return Err(UdpWorkerRouteError::InvalidTopology);
        }
        let mut routes = Vec::with_capacity(worker_count);
        let mut mailboxes = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            let worker_id =
                u32::try_from(worker).map_err(|_| UdpWorkerRouteError::InvalidTopology)?;
            let (sender, receiver) = mpsc::channel(queue_capacity);
            routes.push(sender);
            mailboxes.push(UdpWorkerMailbox {
                worker_id,
                receiver,
            });
        }
        Ok((Self { registry, routes }, mailboxes))
    }

    pub fn register_session(
        &self,
        session_id: u64,
        client_to_server_cid_secret: [u8; 32],
        server_to_client_cid_secret: [u8; 32],
        active_path: UdpPath,
        safe_payload_budget: u16,
    ) -> Result<InitialCids, UdpRoamingError> {
        let worker =
            usize::try_from(active_path.worker_id).map_err(|_| UdpRoamingError::InvalidSession)?;
        if worker >= self.routes.len() {
            return Err(UdpRoamingError::InvalidSession);
        }
        self.registry.register_session(
            session_id,
            client_to_server_cid_secret,
            server_to_client_cid_secret,
            active_path,
            safe_payload_budget,
        )
    }

    pub fn remove_session(&self, session_id: u64) -> bool {
        self.registry.remove_session(session_id)
    }

    pub fn route_ingress(
        &self,
        destination_cid: &UdpCid,
        packet_number: u32,
        received_path: UdpPath,
        payload: T,
    ) -> Result<UdpIngressDispatch<T>, UdpWorkerRouteFailure<T>> {
        let received_worker = match usize::try_from(received_path.worker_id) {
            Ok(worker) if worker < self.routes.len() => worker,
            _ => {
                return Err(UdpWorkerRouteFailure::new(
                    UdpWorkerRouteError::UnknownWorker,
                    payload,
                ));
            }
        };
        let lookup = match self.registry.lookup(destination_cid) {
            Some(lookup) => lookup,
            None => {
                return Err(UdpWorkerRouteFailure::new(
                    UdpWorkerRouteError::UnknownCid,
                    payload,
                ));
            }
        };
        let owner = match usize::try_from(lookup.owner_worker_id) {
            Ok(worker) if worker < self.routes.len() => worker,
            _ => {
                return Err(UdpWorkerRouteFailure::new(
                    UdpWorkerRouteError::UnknownWorker,
                    payload,
                ));
            }
        };
        let routed = UdpRoutedIngress {
            lookup,
            received_path,
            packet_number,
            payload,
        };
        if owner == received_worker {
            return Ok(UdpIngressDispatch::Local(routed));
        }
        match self.routes[owner].try_send(routed) {
            Ok(()) => Ok(UdpIngressDispatch::Queued),
            Err(mpsc::error::TrySendError::Full(routed)) => Err(UdpWorkerRouteFailure::new(
                UdpWorkerRouteError::QueueFull,
                routed.into_payload(),
            )),
            Err(mpsc::error::TrySendError::Closed(routed)) => Err(UdpWorkerRouteFailure::new(
                UdpWorkerRouteError::WorkerClosed,
                routed.into_payload(),
            )),
        }
    }
}

fn validate_lookup(session: &UdpSession, lookup: CidLookup) -> Result<(), UdpRoamingError> {
    if session.generation != lookup.session_generation {
        return Err(UdpRoamingError::StaleSession);
    }
    Ok(())
}

fn derive_aliases(
    cid_secret: &[u8; 32],
    session_id: u64,
    active_epoch: u64,
) -> Result<Vec<(UdpCid, u64)>, UdpRoamingError> {
    let mut epochs = Vec::with_capacity(MAX_CID_ALIASES_PER_SESSION);
    if let Some(previous) = active_epoch.checked_sub(1) {
        epochs.push(previous);
    }
    epochs.push(active_epoch);
    if let Some(future) = active_epoch.checked_add(1) {
        epochs.push(future);
    }
    let mut aliases = Vec::with_capacity(epochs.len());
    for epoch in epochs {
        let cid = derive_udp_cid(cid_secret, session_id, epoch);
        if aliases
            .iter()
            .any(|(existing, _): &(UdpCid, u64)| existing == &cid)
        {
            return Err(UdpRoamingError::CidCollision);
        }
        aliases.push((cid, epoch));
    }
    Ok(aliases)
}

#[cfg(test)]
mod tests {
    use super::*;

    const C2S: [u8; 32] = [0x11; 32];
    const S2C: [u8; 32] = [0x22; 32];
    const TOKEN: [u8; PATH_CHALLENGE_LEN] = [0x33; PATH_CHALLENGE_LEN];

    fn path(worker_id: u32, port: u16) -> UdpPath {
        UdpPath::new(
            worker_id,
            format!("192.0.2.{worker_id}:{port}").parse().unwrap(),
        )
    }

    fn table() -> (UdpRoamingTable, InitialCids) {
        let mut table = UdpRoamingTable::new(4);
        let cids = table
            .register_session(7, C2S, S2C, path(1, 1000), 1232)
            .unwrap();
        (table, cids)
    }

    fn transmit_cid(epoch: u64) -> UdpCid {
        derive_udp_cid(&S2C, 7, epoch)
    }

    fn candidate(table: &mut UdpRoamingTable) -> CandidateChallenge {
        let future = derive_udp_cid(&C2S, 7, 1);
        let lookup = table.lookup(&future).expect("future CID alias");
        table
            .observe_authenticated_candidate(lookup, path(2, 2000), &transmit_cid(1), 1, 100, TOKEN)
            .unwrap()
    }

    #[test]
    fn registration_installs_only_current_and_future_aliases_and_cleanup_is_exact() {
        let (mut table, initial) = table();
        assert_eq!(table.session_count(), 1);
        assert_eq!(table.cid_count(), 2);
        assert_eq!(initial.receive(), &derive_udp_cid(&C2S, 7, 0));
        assert_eq!(initial.transmit(), &derive_udp_cid(&S2C, 7, 0));
        assert_eq!(
            table.lookup(initial.receive()).unwrap().owner_worker_id(),
            1
        );
        assert_eq!(table.lookup(initial.receive()).unwrap().path_epoch(), 0);
        assert_eq!(
            table
                .lookup(&derive_udp_cid(&C2S, 7, 1))
                .unwrap()
                .path_epoch(),
            1
        );
        assert!(table.remove_session(7));
        assert!(!table.remove_session(7));
        assert_eq!((table.session_count(), table.cid_count()), (0, 0));
    }

    #[test]
    fn only_the_next_epoch_on_a_new_path_can_create_one_candidate() {
        let (mut table, initial) = table();
        let current = table.lookup(initial.receive()).unwrap();
        assert!(matches!(
            table.observe_authenticated_candidate(
                current,
                path(2, 2000),
                &transmit_cid(0),
                0,
                100,
                TOKEN,
            ),
            Err(UdpRoamingError::StaleEpoch)
        ));
        let future = table.lookup(&derive_udp_cid(&C2S, 7, 1)).unwrap();
        assert!(matches!(
            table.observe_authenticated_candidate(
                future,
                path(2, 2000),
                &[0xAB; CID_LEN],
                1,
                100,
                TOKEN,
            ),
            Err(UdpRoamingError::InvalidCid)
        ));
        assert!(matches!(
            table.observe_authenticated_candidate(
                future,
                path(2, 2000),
                &transmit_cid(1),
                2,
                100,
                TOKEN,
            ),
            Err(UdpRoamingError::StaleEpoch)
        ));
        let first = table
            .observe_authenticated_candidate(future, path(2, 2000), &transmit_cid(1), 1, 100, TOKEN)
            .unwrap();
        let duplicate = table
            .observe_authenticated_candidate(
                future,
                path(2, 2000),
                &transmit_cid(1),
                1,
                50,
                [0x44; 16],
            )
            .unwrap();
        assert_eq!(first.ticket(), duplicate.ticket());
        assert_eq!(first.token(), duplicate.token());
        assert!(matches!(
            table.observe_authenticated_candidate(
                future,
                path(3, 3000),
                &transmit_cid(1),
                1,
                100,
                [0x55; 16],
            ),
            Err(UdpRoamingError::CandidateBusy)
        ));
        assert_eq!(table.candidate_count(), 1);
    }

    #[test]
    fn candidate_expiry_frees_the_profile_slot_without_refreshing_on_duplicate() {
        let ttl = Duration::from_secs(10);
        let rate_window = Duration::from_secs(1);
        let mut table = UdpRoamingTable::with_candidate_policy(4, 1, ttl, rate_window, 4);
        table
            .register_session(7, C2S, S2C, path(1, 1000), 1232)
            .unwrap();
        let other_c2s = [0x41; 32];
        let other_s2c = [0x42; 32];
        table
            .register_session(8, other_c2s, other_s2c, path(3, 3000), 1232)
            .unwrap();
        let started_at = Instant::now();
        let first_lookup = table.lookup(&derive_udp_cid(&C2S, 7, 1)).unwrap();
        let first = table
            .observe_authenticated_candidate_at(
                first_lookup,
                path(2, 2000),
                &transmit_cid(1),
                1,
                100,
                TOKEN,
                started_at,
            )
            .unwrap();
        let duplicate = table
            .observe_authenticated_candidate_at(
                first_lookup,
                path(2, 2000),
                &transmit_cid(1),
                1,
                20,
                [0x44; PATH_CHALLENGE_LEN],
                started_at + ttl - Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(duplicate.ticket(), first.ticket());

        let second_lookup = table.lookup(&derive_udp_cid(&other_c2s, 8, 1)).unwrap();
        assert!(matches!(
            table.observe_authenticated_candidate_at(
                second_lookup,
                path(4, 4000),
                &derive_udp_cid(&other_s2c, 8, 1),
                1,
                100,
                [0x55; PATH_CHALLENGE_LEN],
                started_at + ttl - Duration::from_millis(1),
            ),
            Err(UdpRoamingError::CandidateLimit)
        ));
        assert_eq!(
            table.expire_candidates_at(started_at + ttl),
            vec![first.ticket()]
        );
        assert_eq!(table.candidate_count(), 0);
        table
            .observe_authenticated_candidate_at(
                second_lookup,
                path(4, 4000),
                &derive_udp_cid(&other_s2c, 8, 1),
                1,
                100,
                [0x55; PATH_CHALLENGE_LEN],
                started_at + ttl,
            )
            .unwrap();
        assert_eq!(table.candidate_count(), 1);
    }

    #[test]
    fn candidate_creation_rate_is_profile_wide_and_bounded() {
        let rate_window = Duration::from_secs(1);
        let mut table =
            UdpRoamingTable::with_candidate_policy(4, 4, Duration::from_secs(10), rate_window, 1);
        table
            .register_session(7, C2S, S2C, path(1, 1000), 1232)
            .unwrap();
        let other_c2s = [0x41; 32];
        let other_s2c = [0x42; 32];
        table
            .register_session(8, other_c2s, other_s2c, path(3, 3000), 1232)
            .unwrap();
        let started_at = Instant::now();
        let first_lookup = table.lookup(&derive_udp_cid(&C2S, 7, 1)).unwrap();
        let first = table
            .observe_authenticated_candidate_at(
                first_lookup,
                path(2, 2000),
                &transmit_cid(1),
                1,
                100,
                TOKEN,
                started_at,
            )
            .unwrap();
        assert!(table.abort_candidate(first.ticket()));
        let second_lookup = table.lookup(&derive_udp_cid(&other_c2s, 8, 1)).unwrap();
        assert!(matches!(
            table.observe_authenticated_candidate_at(
                second_lookup,
                path(4, 4000),
                &derive_udp_cid(&other_s2c, 8, 1),
                1,
                100,
                [0x55; PATH_CHALLENGE_LEN],
                started_at + Duration::from_millis(999),
            ),
            Err(UdpRoamingError::CandidateRateLimited)
        ));
        table
            .observe_authenticated_candidate_at(
                second_lookup,
                path(4, 4000),
                &derive_udp_cid(&other_s2c, 8, 1),
                1,
                100,
                [0x55; PATH_CHALLENGE_LEN],
                started_at + rate_window,
            )
            .unwrap();
    }

    #[test]
    fn candidate_egress_is_limited_to_three_times_authenticated_ingress() {
        let (mut table, _) = table();
        let challenge = candidate(&mut table);
        table
            .authorize_candidate_send(challenge.ticket(), 300)
            .unwrap();
        assert_eq!(
            table.authorize_candidate_send(challenge.ticket(), 1),
            Err(UdpRoamingError::AmplificationLimit)
        );
        let future = table.lookup(&derive_udp_cid(&C2S, 7, 1)).unwrap();
        table
            .observe_authenticated_candidate(
                future,
                path(2, 2000),
                &transmit_cid(1),
                1,
                10,
                [0x99; 16],
            )
            .unwrap();
        table
            .authorize_candidate_send(challenge.ticket(), 30)
            .unwrap();
    }

    #[test]
    fn response_binds_candidate_epoch_path_and_token_before_atomic_commit() {
        let (mut table, initial) = table();
        let challenge = candidate(&mut table);
        assert!(matches!(
            table.validate_response_and_commit(
                challenge.ticket(),
                path(3, 3000),
                1,
                challenge.token(),
                32,
                1212,
            ),
            Err(UdpRoamingError::StaleCandidate)
        ));
        assert!(matches!(
            table.validate_response_and_commit(
                challenge.ticket(),
                path(2, 2000),
                1,
                &[0x77; 16],
                32,
                1212,
            ),
            Err(UdpRoamingError::InvalidResponse)
        ));
        assert_eq!(table.active_path(7), Some(path(1, 1000)));
        let committed = table
            .validate_response_and_commit(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1212,
            )
            .unwrap();
        assert_eq!(committed.old_path(), path(1, 1000));
        assert_eq!(committed.new_path(), path(2, 2000));
        assert_eq!(committed.path_epoch(), 1);
        assert_eq!(committed.receive_cid(), &derive_udp_cid(&C2S, 7, 1));
        assert_eq!(committed.transmit_cid(), &derive_udp_cid(&S2C, 7, 1));
        assert_eq!(table.active_epoch(7), Some(1));
        assert_eq!(table.payload_budget(7), Some(1212));
        assert_eq!(table.candidate_count(), 0);
        assert_eq!(table.cid_count(), MAX_CID_ALIASES_PER_SESSION);
        assert_eq!(table.lookup(initial.receive()).unwrap().path_epoch(), 0);
        assert_eq!(
            table
                .lookup(&derive_udp_cid(&C2S, 7, 2))
                .unwrap()
                .path_epoch(),
            2
        );
    }

    #[test]
    fn rejected_external_publish_leaves_candidate_retryable() {
        let (mut table, initial) = table();
        let challenge = candidate(&mut table);
        let rejected = table.validate_response_and_commit_with(
            challenge.ticket(),
            path(2, 2000),
            1,
            challenge.token(),
            32,
            1212,
            |outcome| {
                assert_eq!(outcome.old_path(), path(1, 1000));
                assert_eq!(outcome.new_path(), path(2, 2000));
                Err("publish rejected")
            },
        );
        assert!(matches!(
            rejected,
            Err(UdpRoamingCommitError::Publish("publish rejected"))
        ));
        assert_eq!(table.active_path(7), Some(path(1, 1000)));
        assert_eq!(table.active_epoch(7), Some(0));
        assert_eq!(table.payload_budget(7), Some(1232));
        assert_eq!(table.candidate_count(), 1);
        assert_eq!(table.cid_count(), 2);
        assert!(table.lookup(initial.receive()).is_some());

        let committed = table
            .validate_response_and_commit_with(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1212,
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        assert!(!committed.is_replay());
        assert_eq!(committed.outcome().path_epoch(), 1);
        assert_eq!(table.active_path(7), Some(path(2, 2000)));
        assert_eq!(table.candidate_count(), 0);
    }

    #[test]
    fn exact_committed_response_is_replayed_without_republication() {
        let (mut table, _) = table();
        let challenge = candidate(&mut table);
        let publications = std::cell::Cell::new(0usize);
        let committed = table
            .validate_response_and_commit_with(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1212,
                |_| {
                    publications.set(publications.get() + 1);
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
        assert!(!committed.is_replay());
        assert_eq!(publications.get(), 1);
        let outcome = committed.outcome();
        assert!(table.raise_payload_budget(outcome.pmtu(), 1400).unwrap());

        let replayed = table
            .validate_response_and_commit_with(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1200,
                |_| -> Result<(), ()> { panic!("replay must not republish path state") },
            )
            .unwrap();
        assert!(replayed.is_replay());
        assert!(replayed.outcome() == outcome);
        assert_eq!(publications.get(), 1);
        assert_eq!(table.active_epoch(7), Some(1));
        assert_eq!(table.active_path(7), Some(path(2, 2000)));
        assert_eq!(table.payload_budget(7), Some(1400));
        assert_eq!(table.candidate_count(), 0);

        assert!(matches!(
            table.validate_response_and_commit_with(
                challenge.ticket(),
                path(2, 2000),
                1,
                &[0x77; PATH_CHALLENGE_LEN],
                32,
                1200,
                |_| -> Result<(), ()> { panic!("invalid replay must not publish") },
            ),
            Err(UdpRoamingCommitError::State(
                UdpRoamingError::InvalidResponse
            ))
        ));
    }

    #[test]
    fn cid_collision_aborts_only_candidate_and_keeps_active_path() {
        let (mut table, _) = table();
        let challenge = candidate(&mut table);
        let future = derive_udp_cid(&C2S, 7, 2);
        table.cid_index.insert(
            future,
            CidOwner {
                session_id: 99,
                session_generation: 1,
                path_epoch: 0,
            },
        );
        assert!(matches!(
            table.validate_response_and_commit(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1212,
            ),
            Err(UdpRoamingError::CidCollision)
        ));
        assert_eq!(table.active_path(7), Some(path(1, 1000)));
        assert_eq!(table.active_epoch(7), Some(0));
        assert_eq!(table.candidate_count(), 0);
    }

    #[test]
    fn stale_pmtu_result_cannot_raise_a_new_path_budget() {
        let (mut table, initial) = table();
        assert!(table.raise_payload_budget(initial.pmtu(), 1400).unwrap());
        let challenge = candidate(&mut table);
        let committed = table
            .validate_response_and_commit(
                challenge.ticket(),
                path(2, 2000),
                1,
                challenge.token(),
                32,
                1200,
            )
            .unwrap();
        assert_eq!(
            table.raise_payload_budget(initial.pmtu(), 1500),
            Err(UdpRoamingError::StalePmtu)
        );
        assert!(table.raise_payload_budget(committed.pmtu(), 1300).unwrap());
        assert!(!table.raise_payload_budget(committed.pmtu(), 1250).unwrap());
        assert_eq!(table.payload_budget(7), Some(1300));
    }

    #[test]
    fn aborted_and_removed_generations_reject_late_tickets() {
        let (mut table, _) = table();
        let first = candidate(&mut table);
        assert!(table.abort_candidate(first.ticket()));
        assert!(!table.abort_candidate(first.ticket()));
        assert_eq!(
            table.authorize_candidate_send(first.ticket(), 1),
            Err(UdpRoamingError::StaleCandidate)
        );
        let second = candidate(&mut table);
        assert!(table.remove_session(7));
        assert!(matches!(
            table.validate_response_and_commit(
                second.ticket(),
                path(2, 2000),
                1,
                second.token(),
                32,
                1200,
            ),
            Err(UdpRoamingError::StaleCandidate)
        ));
    }

    #[test]
    fn repeated_rotations_keep_only_previous_current_and_future_aliases() {
        let (mut table, initial) = table();
        let mut retired = *initial.receive();
        for epoch in 1u64..=32 {
            let future_cid = derive_udp_cid(&C2S, 7, epoch);
            let lookup = table.lookup(&future_cid).expect("next CID is reserved");
            let new_path = UdpPath::new(
                u32::try_from(epoch + 1).unwrap(),
                format!("198.51.100.1:{}", 2000 + epoch).parse().unwrap(),
            );
            let token = [u8::try_from(epoch).unwrap(); PATH_CHALLENGE_LEN];
            let challenge = table
                .observe_authenticated_candidate(
                    lookup,
                    new_path,
                    &transmit_cid(epoch),
                    epoch,
                    128,
                    token,
                )
                .unwrap();
            table
                .authorize_candidate_send(challenge.ticket(), 64)
                .unwrap();
            table
                .validate_response_and_commit(
                    challenge.ticket(),
                    new_path,
                    epoch,
                    challenge.token(),
                    32,
                    1200,
                )
                .unwrap();
            assert_eq!(table.active_epoch(7), Some(epoch));
            assert_eq!(table.cid_count(), MAX_CID_ALIASES_PER_SESSION);
            assert_eq!(table.lookup(&future_cid).unwrap().path_epoch(), epoch);
            if epoch >= 2 {
                assert!(table.lookup(&retired).is_none());
            }
            retired = derive_udp_cid(&C2S, 7, epoch.saturating_sub(1));
        }
    }

    #[test]
    fn registration_is_bounded_and_collision_is_atomic() {
        let mut table = UdpRoamingTable::new(1);
        let first = table
            .register_session(1, C2S, S2C, path(1, 1000), 1232)
            .unwrap();
        assert!(matches!(
            table.register_session(2, [3; 32], [4; 32], path(2, 2000), 1232),
            Err(UdpRoamingError::SessionLimit)
        ));
        assert_eq!((table.session_count(), table.cid_count()), (1, 2));
        assert!(table.lookup(first.receive()).is_some());

        let mut collision = UdpRoamingTable::new(2);
        let cid = derive_udp_cid(&C2S, 9, 0);
        collision.cid_index.insert(
            cid,
            CidOwner {
                session_id: 100,
                session_generation: 1,
                path_epoch: 0,
            },
        );
        assert!(matches!(
            collision.register_session(9, C2S, S2C, path(1, 1000), 1232),
            Err(UdpRoamingError::CidCollision)
        ));
        assert_eq!(collision.session_count(), 0);
        assert_eq!(collision.cid_count(), 1);
    }

    #[test]
    fn owned_registry_cleanup_is_generation_scoped() {
        let registry = UdpRoamingRegistry::new(2);
        let (first_cids, first_owner) = registry
            .register_owned_session(7, C2S, S2C, path(0, 1000), 1200)
            .unwrap();
        assert_eq!(registry.session_count(), 1);
        // Epoch zero has no previous alias yet: current plus one bounded future CID.
        assert_eq!(registry.cid_count(), 2);

        assert!(registry.remove_session(7));
        let (replacement_cids, replacement_owner) = registry
            .register_owned_session(7, C2S, S2C, path(0, 2000), 1200)
            .unwrap();
        assert_eq!(first_cids.receive(), replacement_cids.receive());

        drop(first_owner);
        assert_eq!(registry.session_count(), 1);
        assert!(registry.lookup(replacement_cids.receive()).is_some());

        drop(replacement_owner);
        assert_eq!(registry.session_count(), 0);
        assert_eq!(registry.cid_count(), 0);
    }

    #[test]
    fn worker_fabric_uses_the_pre_registered_profile_table() {
        let registry = UdpRoamingRegistry::new(2);
        let (initial, owner) = registry
            .register_owned_session(7, C2S, S2C, path(0, 1000), 1200)
            .unwrap();
        let (fabric, mut mailboxes) =
            UdpWorkerFabric::with_registry(registry.clone(), 2, 2).unwrap();

        assert!(matches!(
            fabric.route_ingress(initial.receive(), 9, path(1, 2000), vec![4]),
            Ok(UdpIngressDispatch::Queued)
        ));
        let routed = mailboxes[0].try_recv().unwrap();
        assert_eq!(routed.lookup().session_id(), 7);
        assert_eq!(routed.received_path(), path(1, 2000));
        assert_eq!(routed.into_payload(), vec![4]);

        drop(owner);
        let failure = fabric
            .route_ingress(initial.receive(), 10, path(1, 2000), vec![5])
            .err()
            .expect("dropped registration removes the shared lookup");
        assert_eq!(failure.kind(), UdpWorkerRouteError::UnknownCid);
        assert_eq!(failure.into_payload(), vec![5]);
    }

    #[test]
    fn worker_fabric_routes_locally_or_to_the_immutable_codec_owner() {
        let (fabric, mut mailboxes) = UdpWorkerFabric::new(2, 2, 4).unwrap();
        let initial = fabric
            .register_session(7, C2S, S2C, path(1, 1000), 1200)
            .unwrap();
        assert_eq!(mailboxes[0].worker_id(), 0);
        assert_eq!(mailboxes[1].worker_id(), 1);

        let local = fabric
            .route_ingress(initial.receive(), 11, path(1, 2000), vec![1])
            .ok()
            .expect("local ingress is accepted");
        let UdpIngressDispatch::Local(local) = local else {
            panic!("home-worker ingress must not take a channel hop");
        };
        assert_eq!(local.lookup().owner_worker_id(), 1);
        assert_eq!(local.received_path(), path(1, 2000));
        assert_eq!(local.packet_number(), 11);
        assert_eq!(local.payload(), &vec![1]);

        assert!(matches!(
            fabric.route_ingress(initial.receive(), 12, path(0, 3000), vec![2]),
            Ok(UdpIngressDispatch::Queued)
        ));
        assert!(matches!(
            mailboxes[0].try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let routed = mailboxes[1].try_recv().unwrap();
        assert_eq!(routed.lookup().session_id(), 7);
        assert_eq!(routed.received_path(), path(0, 3000));
        assert_eq!(routed.into_payload(), vec![2]);
    }

    #[test]
    fn worker_fabric_is_bounded_and_returns_dropped_payload_ownership() {
        let (fabric, _mailboxes) = UdpWorkerFabric::new(2, 1, 4).unwrap();
        let initial = fabric
            .register_session(7, C2S, S2C, path(1, 1000), 1200)
            .unwrap();
        assert!(matches!(
            fabric.route_ingress(initial.receive(), 1, path(0, 2000), vec![1]),
            Ok(UdpIngressDispatch::Queued)
        ));
        let failure = fabric
            .route_ingress(initial.receive(), 2, path(0, 2000), vec![9])
            .err()
            .expect("full mailbox fails closed");
        assert_eq!(failure.kind(), UdpWorkerRouteError::QueueFull);
        assert_eq!(failure.into_payload(), vec![9]);
    }

    #[test]
    fn worker_fabric_rejects_unknown_cids_workers_and_closed_mailboxes() {
        assert!(matches!(
            UdpWorkerFabric::<Vec<u8>>::new(0, 1, 1),
            Err(UdpWorkerRouteError::InvalidTopology)
        ));
        assert!(matches!(
            UdpWorkerFabric::<Vec<u8>>::new(1, 0, 1),
            Err(UdpWorkerRouteError::InvalidTopology)
        ));

        let (fabric, mailboxes) = UdpWorkerFabric::new(2, 1, 4).unwrap();
        let initial = fabric
            .register_session(7, C2S, S2C, path(1, 1000), 1200)
            .unwrap();
        let unknown = fabric
            .route_ingress(&[0xFF; CID_LEN], 1, path(0, 2000), vec![3])
            .err()
            .unwrap();
        assert_eq!(unknown.kind(), UdpWorkerRouteError::UnknownCid);
        assert_eq!(unknown.into_payload(), vec![3]);
        let bad_worker = fabric
            .route_ingress(initial.receive(), 2, path(9, 2000), vec![4])
            .err()
            .unwrap();
        assert_eq!(bad_worker.kind(), UdpWorkerRouteError::UnknownWorker);
        drop(mailboxes);
        let closed = fabric
            .route_ingress(initial.receive(), 3, path(0, 2000), vec![5])
            .err()
            .unwrap();
        assert_eq!(closed.kind(), UdpWorkerRouteError::WorkerClosed);
        assert_eq!(closed.into_payload(), vec![5]);
        assert!(fabric.remove_session(7));
    }
}
