//! Bounded profile-wide state for authenticated UDP path migration.
//!
//! This module deliberately owns no sockets or packet codecs. The server hot path performs
//! AEAD/replay verification first, then presents an authenticated CID lookup and exact path to
//! this table. Keeping registry mutation, candidate ownership, anti-amplification accounting,
//! CID rotation and PMTU generations under one mutable owner makes worker handoff atomic without
//! changing the default/non-negotiated UDP data plane.

use crate::protocol::roaming::{derive_udp_cid, CID_LEN, PATH_CHALLENGE_LEN};
use std::collections::HashMap;
use std::net::SocketAddr;
use zeroize::Zeroizing;

pub const MAX_CID_ALIASES_PER_SESSION: usize = 3;
pub const ANTI_AMPLIFICATION_FACTOR: u64 = 3;
/// Only accounting is retained, never candidate payloads. Capping the counter prevents an
/// authenticated peer from manufacturing an effectively unlimited pre-validation send budget.
pub const MAX_CANDIDATE_ACCOUNTED_BYTES: u64 = 1024 * 1024;

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
    path_epoch: u64,
}

impl CidLookup {
    pub fn session_id(self) -> u64 {
        self.session_id
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
    #[error("UDP path epoch is stale or not the next expected epoch")]
    StaleEpoch,
    #[error("another UDP path candidate already owns this session")]
    CandidateBusy,
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
    received_bytes: u64,
    sent_bytes: u64,
}

struct UdpSession {
    generation: u64,
    client_to_server_cid_secret: Zeroizing<[u8; 32]>,
    server_to_client_cid_secret: Zeroizing<[u8; 32]>,
    aliases: Vec<(UdpCid, u64)>,
    active: ActivePath,
    candidate: Option<CandidatePath>,
}

/// One instance is owned by a profile actor (or protected by one profile-wide mutex).
/// All operations are O(1) except rotation/cleanup over at most three aliases per session.
pub struct UdpRoamingTable {
    max_sessions: usize,
    next_session_generation: u64,
    next_candidate_id: u64,
    cid_index: HashMap<UdpCid, CidOwner>,
    sessions: HashMap<u64, UdpSession>,
}

impl UdpRoamingTable {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
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
        self.sessions
            .values()
            .filter(|session| session.candidate.is_some())
            .count()
    }

    pub fn lookup(&self, cid: &UdpCid) -> Option<CidLookup> {
        self.cid_index.get(cid).copied().map(|owner| CidLookup {
            session_id: owner.session_id,
            session_generation: owner.session_generation,
            path_epoch: owner.path_epoch,
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
        received_bytes: usize,
        challenge: [u8; PATH_CHALLENGE_LEN],
    ) -> Result<CandidateChallenge, UdpRoamingError> {
        if received_bytes == 0 {
            return Err(UdpRoamingError::InvalidResponse);
        }
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
            if lookup.path_epoch != expected || path == session.active.path {
                return Err(UdpRoamingError::StaleEpoch);
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
            received_bytes,
            sent_bytes: 0,
        });
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
        if received_bytes == 0 || safe_payload_budget == 0 {
            return Err(UdpRoamingError::InvalidResponse);
        }
        {
            let candidate = self.candidate_mut(ticket)?;
            if candidate.path != path {
                return Err(UdpRoamingError::StaleCandidate);
            }
            candidate.received_bytes = candidate
                .received_bytes
                .saturating_add(u64::try_from(received_bytes).unwrap_or(u64::MAX))
                .min(MAX_CANDIDATE_ACCOUNTED_BYTES);
            if response_epoch != ticket.path_epoch || response_token != &candidate.challenge {
                return Err(UdpRoamingError::InvalidResponse);
            }
        }

        let (generation, old_path, client_to_server_secret, server_to_client_secret, pmtu) = {
            let session = self
                .sessions
                .get(&ticket.session_id)
                .ok_or(UdpRoamingError::StaleSession)?;
            if session.generation != ticket.session_generation {
                return Err(UdpRoamingError::StaleSession);
            }
            let pmtu_generation = session
                .active
                .pmtu_generation
                .checked_add(1)
                .ok_or(UdpRoamingError::GenerationExhausted)?;
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
        )?;
        if let Err(error) = self.ensure_aliases_available(ticket.session_id, generation, &aliases) {
            if let Some(session) = self.sessions.get_mut(&ticket.session_id) {
                session.candidate = None;
            }
            return Err(error);
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

        let new_pmtu = PmtuTicket {
            session_id: ticket.session_id,
            session_generation: generation,
            path_epoch: ticket.path_epoch,
            pmtu_generation: pmtu,
            path,
        };
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
        session.candidate = None;
        Ok(CommitOutcome {
            old_path,
            new_path: path,
            path_epoch: ticket.path_epoch,
            receive_cid,
            transmit_cid,
            pmtu: new_pmtu,
        })
    }

    pub fn abort_candidate(&mut self, ticket: CandidateTicket) -> bool {
        self.sessions
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
            })
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
        for (cid, _) in session.aliases {
            if self.cid_index.get(&cid).is_some_and(|owner| {
                owner.session_id == session_id && owner.session_generation == session.generation
            }) {
                self.cid_index.remove(&cid);
            }
        }
        true
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

    fn candidate(table: &mut UdpRoamingTable) -> CandidateChallenge {
        let future = derive_udp_cid(&C2S, 7, 1);
        let lookup = table.lookup(&future).expect("future CID alias");
        table
            .observe_authenticated_candidate(lookup, path(2, 2000), 100, TOKEN)
            .unwrap()
    }

    #[test]
    fn registration_installs_only_current_and_future_aliases_and_cleanup_is_exact() {
        let (mut table, initial) = table();
        assert_eq!(table.session_count(), 1);
        assert_eq!(table.cid_count(), 2);
        assert_eq!(initial.receive(), &derive_udp_cid(&C2S, 7, 0));
        assert_eq!(initial.transmit(), &derive_udp_cid(&S2C, 7, 0));
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
            table.observe_authenticated_candidate(current, path(2, 2000), 100, TOKEN),
            Err(UdpRoamingError::StaleEpoch)
        ));
        let future = table.lookup(&derive_udp_cid(&C2S, 7, 1)).unwrap();
        let first = table
            .observe_authenticated_candidate(future, path(2, 2000), 100, TOKEN)
            .unwrap();
        let duplicate = table
            .observe_authenticated_candidate(future, path(2, 2000), 50, [0x44; 16])
            .unwrap();
        assert_eq!(first.ticket(), duplicate.ticket());
        assert_eq!(first.token(), duplicate.token());
        assert!(matches!(
            table.observe_authenticated_candidate(future, path(3, 3000), 100, [0x55; 16]),
            Err(UdpRoamingError::CandidateBusy)
        ));
        assert_eq!(table.candidate_count(), 1);
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
            .observe_authenticated_candidate(future, path(2, 2000), 10, [0x99; 16])
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
                .observe_authenticated_candidate(lookup, new_path, 128, token)
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
}
