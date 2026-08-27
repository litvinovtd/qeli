//! Race-safe server lifecycle primitives for TCP resume and make-before-break handover.
//!
//! The default-off `experimental-roaming` server handler owns this lifecycle and advertises its
//! TCP support. Session activation still requires authenticated client opt-in; make-before-break
//! additionally requires the complete authenticated client/platform path contract. The state
//! machine keeps JOIN/reaper/kick races testable and preserves every non-negotiated legacy path.

use crate::protocol::roaming::{TcpResumeJoin, SESSION_LOCATOR_LEN};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active,
    Orphaned,
    Resuming,
    Closing,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachReason {
    /// Carrier/path loss, wake, or another recoverable I/O failure.
    Unexpected,
    /// Authenticated CLOSE_SESSION or orderly local shutdown.
    CleanClose,
    /// Kick, quota/expiry, protocol violation, profile shutdown, or admin revoke.
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachOutcome {
    StreamRemains,
    Orphaned(ReapTicket),
    Closing,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReapTicket {
    session_id: u64,
    generation: u64,
    deadline: Instant,
}

impl ReapTicket {
    pub fn session_id(self) -> u64 {
        self.session_id
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn deadline(self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeReservation {
    session_id: u64,
    generation: u64,
    resume_epoch: u64,
    logical_slot_id: u32,
    handover: bool,
}

impl ResumeReservation {
    pub fn session_id(self) -> u64 {
        self.session_id
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn resume_epoch(self) -> u64 {
        self.resume_epoch
    }

    pub fn logical_slot_id(self) -> u32 {
        self.logical_slot_id
    }

    pub fn is_handover(self) -> bool {
        self.handover
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Previous transport in this stable slot. Stop it, then acknowledge the exact generation.
    pub drain_transport: Option<u64>,
    pub slot_generation: u64,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("TCP roaming requires a non-zero session id and at least one logical slot")]
    InvalidSession,
    #[error("session is closing or revoked")]
    Terminal,
    #[error("initial TCP transport has not entered the live scheduler yet")]
    InitialTransportPending,
    #[error("another resume transaction already owns this session")]
    ResumeBusy,
    #[error("resume proof or fresh-handshake transcript does not match")]
    InvalidProof,
    #[error("resume locator does not identify this session")]
    WrongLocator,
    #[error("resume epoch is stale or was already consumed")]
    StaleEpoch,
    #[error("logical slot is outside the negotiated session limit")]
    InvalidSlot,
    #[error("make-before-break handover was not negotiated for this session")]
    HandoverNotNegotiated,
    #[error("logical slot still has a draining transport")]
    SlotDraining,
    #[error("resume reservation is stale or belongs to another transaction")]
    StaleReservation,
    #[error("orphan session or retained-byte limit reached")]
    OrphanLimit,
    #[error("orphan ownership already exists for this session generation")]
    DuplicateOrphan,
    #[error("session generation is exhausted")]
    GenerationExhausted,
}

/// Profile-wide bound for sessions retained during TCP grace.
///
/// Ownership is generation-tagged. Releasing a stale ticket is a no-op, so a delayed reaper
/// cannot subtract the bytes of a newer orphan generation or underflow the counters.
pub struct OrphanLimiter {
    max_sessions: usize,
    max_bytes: usize,
    sessions: usize,
    bytes: usize,
    leases: HashMap<(u64, u64), usize>,
}

impl OrphanLimiter {
    pub fn new(max_sessions: usize, max_bytes: usize) -> Self {
        Self {
            max_sessions,
            max_bytes,
            sessions: 0,
            bytes: 0,
            leases: HashMap::new(),
        }
    }

    pub fn sessions(&self) -> usize {
        self.sessions
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn reserve(
        &mut self,
        session_id: u64,
        generation: u64,
        retained_bytes: usize,
    ) -> Result<(), LifecycleError> {
        let key = (session_id, generation);
        if self.leases.contains_key(&key) {
            return Err(LifecycleError::DuplicateOrphan);
        }
        let next_sessions = self
            .sessions
            .checked_add(1)
            .ok_or(LifecycleError::OrphanLimit)?;
        let next_bytes = self
            .bytes
            .checked_add(retained_bytes)
            .ok_or(LifecycleError::OrphanLimit)?;
        if next_sessions > self.max_sessions || next_bytes > self.max_bytes {
            return Err(LifecycleError::OrphanLimit);
        }
        self.leases.insert(key, retained_bytes);
        self.sessions = next_sessions;
        self.bytes = next_bytes;
        Ok(())
    }

    fn release(&mut self, ticket: ReapTicket) -> bool {
        let Some(bytes) = self.leases.remove(&(ticket.session_id, ticket.generation)) else {
            return false;
        };
        self.sessions = self.sessions.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(bytes);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalSlot {
    generation: u64,
    ready: Option<u64>,
    draining: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeFallback {
    Active,
    Orphaned(ReapTicket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Active,
    Orphaned(ReapTicket),
    Resuming {
        reservation: ResumeReservation,
        fallback: ResumeFallback,
    },
    Closing,
    Revoked,
}

/// One logical TCP session. Locators and proofs never implement Debug through this owner.
pub struct SessionLifecycle {
    session_id: u64,
    locator: [u8; SESSION_LOCATOR_LEN],
    max_slots: u32,
    grace: Duration,
    generation: u64,
    last_resume_epoch: u64,
    state: State,
    slots: BTreeMap<u32, LogicalSlot>,
}

impl SessionLifecycle {
    pub fn new(
        session_id: u64,
        locator: [u8; SESSION_LOCATOR_LEN],
        max_slots: u32,
        grace: Duration,
        primary_transport: u64,
    ) -> Result<Self, LifecycleError> {
        if session_id == 0 || max_slots == 0 {
            return Err(LifecycleError::InvalidSession);
        }
        let mut slots = BTreeMap::new();
        slots.insert(
            0,
            LogicalSlot {
                generation: 1,
                ready: Some(primary_transport),
                draining: None,
            },
        );
        Ok(Self {
            session_id,
            locator,
            max_slots,
            grace,
            generation: 1,
            last_resume_epoch: 0,
            state: State::Active,
            slots,
        })
    }

    pub fn state(&self) -> LifecycleState {
        match self.state {
            State::Active => LifecycleState::Active,
            State::Orphaned(_) => LifecycleState::Orphaned,
            State::Resuming { .. } => LifecycleState::Resuming,
            State::Closing => LifecycleState::Closing,
            State::Revoked => LifecycleState::Revoked,
        }
    }

    pub fn ready_streams(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.ready.is_some())
            .count()
    }

    pub fn ready_transport(&self, logical_slot_id: u32) -> Option<u64> {
        self.slots.get(&logical_slot_id).and_then(|slot| slot.ready)
    }

    pub fn draining_transport(&self, logical_slot_id: u32) -> Option<u64> {
        self.slots
            .get(&logical_slot_id)
            .and_then(|slot| slot.draining)
    }

    fn bump_generation(&mut self) -> Result<u64, LifecycleError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(LifecycleError::GenerationExhausted)?;
        Ok(self.generation)
    }

    fn orphan(
        &mut self,
        now: Instant,
        retained_bytes: usize,
        limiter: &mut OrphanLimiter,
    ) -> Result<ReapTicket, LifecycleError> {
        let generation = self.bump_generation()?;
        let deadline = now
            .checked_add(self.grace)
            .ok_or(LifecycleError::GenerationExhausted)?;
        let ticket = ReapTicket {
            session_id: self.session_id,
            generation,
            deadline,
        };
        if let Err(error) = limiter.reserve(self.session_id, generation, retained_bytes) {
            self.state = State::Closing;
            return Err(error);
        }
        self.state = State::Orphaned(ticket);
        Ok(ticket)
    }

    fn release_orphan_fallback(&self, limiter: &mut OrphanLimiter) {
        match self.state {
            State::Orphaned(ticket)
            | State::Resuming {
                fallback: ResumeFallback::Orphaned(ticket),
                ..
            } => {
                limiter.release(ticket);
            }
            _ => {}
        }
    }

    fn terminal(&mut self, revoked: bool, limiter: &mut OrphanLimiter) -> Vec<u64> {
        self.release_orphan_fallback(limiter);
        let mut transports = Vec::new();
        for slot in self.slots.values_mut() {
            if let Some(ready) = slot.ready.take() {
                transports.push(ready);
            }
            if let Some(draining) = slot.draining.take() {
                transports.push(draining);
            }
        }
        self.state = if revoked {
            State::Revoked
        } else {
            State::Closing
        };
        transports
    }

    pub fn detach(
        &mut self,
        transport_id: u64,
        reason: DetachReason,
        now: Instant,
        retained_bytes: usize,
        limiter: &mut OrphanLimiter,
    ) -> Result<DetachOutcome, LifecycleError> {
        match self.state {
            State::Closing => return Ok(DetachOutcome::Closing),
            State::Revoked => return Ok(DetachOutcome::Revoked),
            _ => {}
        }
        if reason == DetachReason::CleanClose {
            self.terminal(false, limiter);
            return Ok(DetachOutcome::Closing);
        }
        if reason == DetachReason::Revoked {
            self.terminal(true, limiter);
            return Ok(DetachOutcome::Revoked);
        }

        let mut found = false;
        for slot in self.slots.values_mut() {
            if slot.ready == Some(transport_id) {
                slot.ready = None;
                found = true;
                break;
            }
            if slot.draining == Some(transport_id) {
                slot.draining = None;
                return Ok(DetachOutcome::StreamRemains);
            }
        }
        if !found || self.ready_streams() > 0 {
            return Ok(DetachOutcome::StreamRemains);
        }

        match self.state {
            State::Active => self
                .orphan(now, retained_bytes, limiter)
                .map(DetachOutcome::Orphaned),
            State::Orphaned(ticket) => Ok(DetachOutcome::Orphaned(ticket)),
            State::Resuming {
                reservation,
                fallback,
            } => {
                if let ResumeFallback::Orphaned(ticket) = fallback {
                    return Ok(DetachOutcome::Orphaned(ticket));
                }
                let generation = self.bump_generation()?;
                let deadline = now
                    .checked_add(self.grace)
                    .ok_or(LifecycleError::GenerationExhausted)?;
                let ticket = ReapTicket {
                    session_id: self.session_id,
                    generation,
                    deadline,
                };
                if let Err(error) = limiter.reserve(self.session_id, generation, retained_bytes) {
                    self.state = State::Closing;
                    return Err(error);
                }
                self.state = State::Resuming {
                    reservation,
                    fallback: ResumeFallback::Orphaned(ticket),
                };
                Ok(DetachOutcome::Orphaned(ticket))
            }
            State::Closing | State::Revoked => Err(LifecycleError::Terminal),
        }
    }

    pub fn begin_resume(
        &mut self,
        join: &TcpResumeJoin,
        fresh_transcript_hash: &[u8; 32],
        resume_secret: &[u8; 32],
    ) -> Result<ResumeReservation, LifecycleError> {
        let fallback = match self.state {
            State::Active => ResumeFallback::Active,
            State::Orphaned(ticket) => ResumeFallback::Orphaned(ticket),
            State::Resuming { .. } => return Err(LifecycleError::ResumeBusy),
            State::Closing | State::Revoked => return Err(LifecycleError::Terminal),
        };
        if join.input().session_locator() != &self.locator {
            return Err(LifecycleError::WrongLocator);
        }
        if !join.matches_transcript(fresh_transcript_hash) || !join.verify(resume_secret) {
            return Err(LifecycleError::InvalidProof);
        }
        let input = join.input();
        let resume_epoch = input.resume_epoch();
        if resume_epoch <= self.last_resume_epoch {
            return Err(LifecycleError::StaleEpoch);
        }
        let logical_slot_id = input.logical_slot_id();
        if logical_slot_id >= self.max_slots {
            return Err(LifecycleError::InvalidSlot);
        }
        // A hard-resume client may know that its carrier is dead before the server sees EOF/RST.
        // Therefore an authenticated non-handover resume is allowed to replace the ready
        // transport in the same stable slot. ResumeBusy bounds this to one candidate and commit
        // atomically marks the old server-side carrier draining before it is kicked.
        if let Some(slot) = self.slots.get(&logical_slot_id) {
            if slot.draining.is_some() {
                return Err(LifecycleError::SlotDraining);
            }
        }

        // Burn at reservation time. A failed socket retries with a fresh handshake and epoch.
        self.last_resume_epoch = resume_epoch;
        let generation = self.bump_generation()?;
        let reservation = ResumeReservation {
            session_id: self.session_id,
            generation,
            resume_epoch,
            logical_slot_id,
            handover: input.is_handover(),
        };
        self.state = State::Resuming {
            reservation,
            fallback,
        };
        Ok(reservation)
    }

    pub fn commit_resume(
        &mut self,
        reservation: ResumeReservation,
        new_transport_id: u64,
        limiter: &mut OrphanLimiter,
    ) -> Result<CommitOutcome, LifecycleError> {
        let fallback = match self.state {
            State::Resuming {
                reservation: current,
                fallback,
            } if current == reservation => fallback,
            State::Closing | State::Revoked => return Err(LifecycleError::Terminal),
            _ => return Err(LifecycleError::StaleReservation),
        };
        let slot = self
            .slots
            .entry(reservation.logical_slot_id)
            .or_insert(LogicalSlot {
                generation: 0,
                ready: None,
                draining: None,
            });
        if slot.draining.is_some() {
            return Err(LifecycleError::SlotDraining);
        }
        let old = slot.ready.replace(new_transport_id);
        slot.draining = old;
        slot.generation = slot
            .generation
            .checked_add(1)
            .ok_or(LifecycleError::GenerationExhausted)?;
        if let ResumeFallback::Orphaned(ticket) = fallback {
            limiter.release(ticket);
        }
        self.state = State::Active;
        Ok(CommitOutcome {
            drain_transport: old,
            slot_generation: slot.generation,
        })
    }

    pub fn abort_resume(&mut self, reservation: ResumeReservation) -> Result<(), LifecycleError> {
        let fallback = match self.state {
            State::Resuming {
                reservation: current,
                fallback,
            } if current == reservation => fallback,
            State::Closing | State::Revoked => return Err(LifecycleError::Terminal),
            _ => return Err(LifecycleError::StaleReservation),
        };
        self.state = match fallback {
            ResumeFallback::Active => State::Active,
            ResumeFallback::Orphaned(ticket) => State::Orphaned(ticket),
        };
        Ok(())
    }

    pub fn complete_drain(
        &mut self,
        logical_slot_id: u32,
        slot_generation: u64,
        transport_id: u64,
    ) -> bool {
        let Some(slot) = self.slots.get_mut(&logical_slot_id) else {
            return false;
        };
        if slot.generation != slot_generation || slot.draining != Some(transport_id) {
            return false;
        }
        slot.draining = None;
        true
    }

    pub fn reap(&mut self, ticket: ReapTicket, now: Instant, limiter: &mut OrphanLimiter) -> bool {
        if !matches!(self.state, State::Orphaned(current) if current == ticket)
            || now < ticket.deadline
        {
            return false;
        }
        limiter.release(ticket);
        self.state = State::Closing;
        true
    }

    pub fn revoke(&mut self, limiter: &mut OrphanLimiter) -> Vec<u64> {
        self.terminal(true, limiter)
    }

    pub fn close(&mut self, limiter: &mut OrphanLimiter) -> Vec<u64> {
        self.terminal(false, limiter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::roaming::ResumeProofInput;

    const LOCATOR: [u8; SESSION_LOCATOR_LEN] = [0x44; SESSION_LOCATOR_LEN];
    const SECRET: [u8; 32] = [0x55; 32];

    fn lifecycle(id: u64, transport: u64) -> SessionLifecycle {
        SessionLifecycle::new(id, LOCATOR, 4, Duration::from_secs(30), transport).unwrap()
    }

    fn join(transcript: [u8; 32], epoch: u64, slot: u32, handover: bool) -> TcpResumeJoin {
        TcpResumeJoin::new(
            ResumeProofInput::new(transcript, LOCATOR, epoch, slot, handover),
            &SECRET,
        )
    }

    #[test]
    fn authenticated_handover_binds_transcript_epoch_locator_and_slot() {
        let mut limiter = OrphanLimiter::new(8, 1 << 20);
        let mut session = lifecycle(7, 100);
        let transcript = [0x33; 32];
        let reservation = session
            .begin_resume(&join(transcript, 1, 0, true), &transcript, &SECRET)
            .unwrap();
        let committed = session
            .commit_resume(reservation, 200, &mut limiter)
            .unwrap();
        assert_eq!(committed.drain_transport, Some(100));
        assert_eq!(session.ready_transport(0), Some(200));
        assert_eq!(session.draining_transport(0), Some(100));
        assert!(session.complete_drain(0, committed.slot_generation, 100));
        assert!(!session.complete_drain(0, committed.slot_generation, 100));
        assert_eq!(
            session.begin_resume(&join(transcript, 1, 0, true), &transcript, &SECRET),
            Err(LifecycleError::StaleEpoch)
        );
        assert_eq!(
            session.begin_resume(&join([9; 32], 2, 0, true), &transcript, &SECRET),
            Err(LifecycleError::InvalidProof)
        );
        let wrong_locator = TcpResumeJoin::new(
            ResumeProofInput::new(transcript, [9; 16], 2, 0, true),
            &SECRET,
        );
        assert_eq!(
            session.begin_resume(&wrong_locator, &transcript, &SECRET),
            Err(LifecycleError::WrongLocator)
        );
    }

    #[test]
    fn hard_handover_keeps_session_and_releases_budget_on_commit() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(2, 4096);
        let mut session = lifecycle(1, 10);
        let ticket = match session
            .detach(10, DetachReason::Unexpected, now, 1024, &mut limiter)
            .unwrap()
        {
            DetachOutcome::Orphaned(ticket) => ticket,
            other => panic!("unexpected detach outcome: {other:?}"),
        };
        assert_eq!(session.state(), LifecycleState::Orphaned);
        assert_eq!((limiter.sessions(), limiter.bytes()), (1, 1024));
        let transcript = [3; 32];
        let reservation = session
            .begin_resume(&join(transcript, 9, 0, false), &transcript, &SECRET)
            .unwrap();
        assert!(!session.reap(ticket, ticket.deadline(), &mut limiter));
        session
            .commit_resume(reservation, 11, &mut limiter)
            .unwrap();
        assert_eq!(session.ready_transport(0), Some(11));
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
        assert!(!session.reap(ticket, ticket.deadline(), &mut limiter));
    }

    #[test]
    fn old_path_may_die_after_reservation_without_losing_the_pending_join() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(2, 4096);
        let mut session = lifecycle(2, 20);
        let transcript = [4; 32];
        let reservation = session
            .begin_resume(&join(transcript, 1, 0, true), &transcript, &SECRET)
            .unwrap();

        let ticket = match session
            .detach(20, DetachReason::Unexpected, now, 512, &mut limiter)
            .unwrap()
        {
            DetachOutcome::Orphaned(ticket) => ticket,
            other => panic!("unexpected detach outcome: {other:?}"),
        };
        assert_eq!(session.state(), LifecycleState::Resuming);
        assert_eq!((limiter.sessions(), limiter.bytes()), (1, 512));
        assert!(
            !session.reap(ticket, ticket.deadline(), &mut limiter),
            "a reaper cannot win while a reserved fresh JOIN is being validated"
        );

        let committed = session
            .commit_resume(reservation, 21, &mut limiter)
            .unwrap();
        assert_eq!(committed.drain_transport, None);
        assert_eq!(session.state(), LifecycleState::Active);
        assert_eq!(session.ready_transport(0), Some(21));
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }

    #[test]
    fn orphan_caps_fail_closed_without_counter_leaks() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(1, 1024);
        let mut first = lifecycle(1, 10);
        let mut second = lifecycle(2, 20);
        first
            .detach(10, DetachReason::Unexpected, now, 800, &mut limiter)
            .unwrap();
        assert_eq!(
            second.detach(20, DetachReason::Unexpected, now, 300, &mut limiter),
            Err(LifecycleError::OrphanLimit)
        );
        assert_eq!(second.state(), LifecycleState::Closing);
        assert_eq!((limiter.sessions(), limiter.bytes()), (1, 800));
        first.revoke(&mut limiter);
        first.revoke(&mut limiter);
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }

    #[test]
    fn stale_reaper_cannot_remove_revived_or_newer_generation() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(4, 4096);
        let mut session = lifecycle(9, 90);
        let first = match session
            .detach(90, DetachReason::Unexpected, now, 100, &mut limiter)
            .unwrap()
        {
            DetachOutcome::Orphaned(ticket) => ticket,
            _ => unreachable!(),
        };
        let transcript = [7; 32];
        let reservation = session
            .begin_resume(&join(transcript, 1, 0, false), &transcript, &SECRET)
            .unwrap();
        session
            .commit_resume(reservation, 91, &mut limiter)
            .unwrap();
        let second = match session
            .detach(
                91,
                DetachReason::Unexpected,
                now + Duration::from_secs(1),
                100,
                &mut limiter,
            )
            .unwrap()
        {
            DetachOutcome::Orphaned(ticket) => ticket,
            _ => unreachable!(),
        };
        assert_ne!(first.generation(), second.generation());
        assert!(!session.reap(first, now + Duration::from_secs(60), &mut limiter));
        assert!(!session.reap(
            second,
            second.deadline() - Duration::from_millis(1),
            &mut limiter
        ));
        assert!(session.reap(second, second.deadline(), &mut limiter));
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }

    #[test]
    fn revoke_wins_over_inflight_resume_and_releases_once() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(1, 1024);
        let mut session = lifecycle(3, 30);
        session
            .detach(30, DetachReason::Unexpected, now, 512, &mut limiter)
            .unwrap();
        let transcript = [8; 32];
        let reservation = session
            .begin_resume(&join(transcript, 1, 0, false), &transcript, &SECRET)
            .unwrap();
        assert!(session.revoke(&mut limiter).is_empty());
        assert_eq!(
            session.commit_resume(reservation, 31, &mut limiter),
            Err(LifecycleError::Terminal)
        );
        session.revoke(&mut limiter);
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }

    #[test]
    fn abort_returns_to_orphan_but_burns_epoch() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(2, 1024);
        let mut session = lifecycle(4, 40);
        session
            .detach(40, DetachReason::Unexpected, now, 256, &mut limiter)
            .unwrap();
        let transcript = [6; 32];
        let proof = join(transcript, 11, 0, false);
        let reservation = session.begin_resume(&proof, &transcript, &SECRET).unwrap();
        session.abort_resume(reservation).unwrap();
        assert_eq!(session.state(), LifecycleState::Orphaned);
        assert_eq!(
            session.begin_resume(&proof, &transcript, &SECRET),
            Err(LifecycleError::StaleEpoch)
        );
    }

    #[test]
    fn hard_resume_replaces_server_stale_carrier_and_rejects_late_drain_ack() {
        let mut limiter = OrphanLimiter::new(2, 1024);
        let mut session = lifecycle(5, 50);
        let transcript = [5; 32];
        let reservation = session
            .begin_resume(&join(transcript, 1, 0, false), &transcript, &SECRET)
            .unwrap();
        assert!(!reservation.is_handover());
        let committed = session
            .commit_resume(reservation, 51, &mut limiter)
            .unwrap();
        assert_eq!(committed.drain_transport, Some(50));
        assert_eq!(
            session.begin_resume(&join(transcript, 2, 0, false), &transcript, &SECRET),
            Err(LifecycleError::SlotDraining)
        );
        assert!(!session.complete_drain(0, committed.slot_generation + 1, 50));
        assert_eq!(session.draining_transport(0), Some(50));
    }

    #[test]
    fn clean_close_never_enters_grace() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(4, 4096);
        let mut session = lifecycle(6, 60);
        assert_eq!(
            session
                .detach(60, DetachReason::CleanClose, now, 1024, &mut limiter)
                .unwrap(),
            DetachOutcome::Closing
        );
        assert_eq!(session.state(), LifecycleState::Closing);
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }

    #[test]
    fn explicit_close_is_terminal_idempotent_and_never_orphans() {
        let now = Instant::now();
        let mut limiter = OrphanLimiter::new(4, 4096);
        let mut session = lifecycle(8, 80);
        assert_eq!(session.close(&mut limiter), vec![80]);
        assert!(session.close(&mut limiter).is_empty());
        assert_eq!(
            session
                .detach(80, DetachReason::Unexpected, now, 1024, &mut limiter)
                .unwrap(),
            DetachOutcome::Closing
        );
        assert_eq!(session.state(), LifecycleState::Closing);
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
    }
}
