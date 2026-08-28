//! Transport-neutral client state for authenticated UDP path migration.
//!
//! This module owns the protocol state that must be identical on every client: directional CID
//! rotation, epoch/message correlation, challenge/response, bounded retransmission and two-phase
//! commit. It deliberately owns no sockets or OS routes. A platform adapter only prepares and
//! binds the candidate socket, feeds authenticated server control into this state machine, applies
//! the returned commit to the OS, and then publishes that commit back here.

use crate::protocol::packet::PacketError;
use crate::protocol::roaming::{
    decode_udp_short, derive_udp_cid, PathControl, RoamingWireError, UdpShortHeader, CID_LEN,
    PATH_CHALLENGE_LEN,
};
use crate::protocol::{control_v2, PacketCodec};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const UDP_CLIENT_PATH_VALIDATION_TIMEOUT: Duration =
    super::udp_roaming::UDP_ROAMING_CANDIDATE_TTL;
pub const UDP_CLIENT_PATH_RETRY_INTERVAL: Duration = Duration::from_millis(500);
pub const UDP_CLIENT_PATH_MAX_TRANSMISSIONS: u8 = 4;

pub type UdpClientCid = [u8; CID_LEN];

#[derive(Debug, thiserror::Error)]
pub enum UdpClientRoamingWireError {
    #[error(transparent)]
    Outer(#[from] RoamingWireError),
    #[error(transparent)]
    Record(#[from] PacketError),
    #[error(transparent)]
    Control(#[from] control_v2::ControlV2Error),
    #[error("UDP roaming path control must not carry CONTROL_V2 flags")]
    InvalidControlFlags,
    #[error("UDP roaming path control must fit one complete CONTROL_V2 frame")]
    FragmentedControl,
}

/// One authenticated roaming datagram after removal of the eight-byte CID header and AEAD
/// record. The type deliberately omits `Debug`: it retains the complete destination CID and may
/// contain a path challenge. The socket actor can route ordinary plaintext to the data plane and
/// ask [`decode_authenticated_path_control`] to classify the infrequent control messages.
pub struct UdpClientAuthenticatedPacket {
    destination_cid: UdpClientCid,
    packet_number: u32,
    plaintext: Vec<u8>,
}

impl UdpClientAuthenticatedPacket {
    pub fn destination_cid(&self) -> &UdpClientCid {
        &self.destination_cid
    }

    pub fn packet_number(&self) -> u32 {
        self.packet_number
    }

    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn into_plaintext(self) -> Vec<u8> {
        self.plaintext
    }
}

/// Owned CONTROL_V2 path message extracted from one authenticated packet. This also omits
/// `Debug` because the body may contain a full CID or challenge token.
pub struct UdpClientAuthenticatedControl {
    message_id: u32,
    control: PathControl,
}

impl UdpClientAuthenticatedControl {
    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    pub fn control(&self) -> &PathControl {
        &self.control
    }
}

/// Encode one state-machine transmit intent using the session-wide PacketCodec sequence and the
/// roaming short header. Keeping this in the Rust core prevents Android, Apple and desktop
/// adapters from acquiring subtly different CONTROL_V2 or CID framing.
pub fn encrypt_path_transmit(
    tx: &mut PacketCodec,
    packet_number: u32,
    transmit: &UdpClientPathTransmit,
) -> Result<Vec<u8>, UdpClientRoamingWireError> {
    let body = transmit.control.encode_body();
    let frame = control_v2::Frame {
        message_type: transmit.control.message_type(),
        flags: 0,
        message_id: transmit.message_id,
        part_index: 0,
        part_count: 1,
        payload: &body,
    }
    .encode()?;
    let record = tx.encrypt_packet(&frame, &[])?;
    Ok(UdpShortHeader::new(transmit.destination_cid, packet_number).encode(&record))
}

/// Authenticate one roaming datagram with the same receive codec/replay window as ordinary data.
/// The caller should pre-filter the cleartext CID against the active/candidate generations before
/// invoking this function; successfully authenticated data and controls intentionally share one
/// packet sequence and replay window.
pub fn decrypt_authenticated_packet(
    rx: &mut PacketCodec,
    wire: &[u8],
) -> Result<UdpClientAuthenticatedPacket, UdpClientRoamingWireError> {
    let (header, record) = decode_udp_short(wire)?;
    let plaintext = rx.decrypt_packet(record)?;
    Ok(UdpClientAuthenticatedPacket {
        destination_cid: *header.destination_cid(),
        packet_number: header.packet_number(),
        plaintext,
    })
}

/// Classify a decrypted roaming packet. Non-control plaintext is returned as `None`; anything
/// carrying the CONTROL_V2 marker must be one complete, flag-free PATH_* frame or is rejected.
pub fn decode_authenticated_path_control(
    packet: &UdpClientAuthenticatedPacket,
) -> Result<Option<UdpClientAuthenticatedControl>, UdpClientRoamingWireError> {
    if !control_v2::is_control_v2(packet.plaintext()) {
        return Ok(None);
    }
    let frame = control_v2::decode(packet.plaintext())?;
    if frame.flags != 0 {
        return Err(UdpClientRoamingWireError::InvalidControlFlags);
    }
    if frame.part_index != 0 || frame.part_count != 1 {
        return Err(UdpClientRoamingWireError::FragmentedControl);
    }
    let control = PathControl::decode(frame.message_type, frame.payload)?;
    Ok(Some(UdpClientAuthenticatedControl {
        message_id: frame.message_id,
        control,
    }))
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum UdpClientRoamingError {
    #[error("UDP client roaming requires a non-zero session id")]
    InvalidSession,
    #[error("UDP client roaming requires a non-zero platform candidate id")]
    InvalidCandidate,
    #[error("another UDP client path candidate is already active")]
    CandidateBusy,
    #[error("UDP client path candidate is absent or stale")]
    StaleCandidate,
    #[error("UDP client path epoch space is exhausted")]
    GenerationExhausted,
    #[error("UDP client path control is stale or belongs to another candidate")]
    StaleControl,
    #[error("UDP client path control is invalid for the current state")]
    InvalidControl,
    #[error("UDP client path validation expired")]
    CandidateExpired,
    #[error("UDP client path validation exhausted its retransmission budget")]
    RetryLimit,
}

/// One encrypted control record that the socket-owning actor must send on the candidate path.
/// It omits `Debug` because both the destination CID and nested challenge token are secret-on-wire.
#[derive(Clone, PartialEq, Eq)]
pub struct UdpClientPathTransmit {
    candidate_id: u64,
    destination_cid: UdpClientCid,
    message_id: u32,
    control: PathControl,
}

impl UdpClientPathTransmit {
    pub fn candidate_id(&self) -> u64 {
        self.candidate_id
    }

    pub fn destination_cid(&self) -> &UdpClientCid {
        &self.destination_cid
    }

    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    pub fn control(&self) -> &PathControl {
        &self.control
    }
}

/// Exact state proposed by an authenticated PATH_COMMIT. The platform must first commit its OS
/// path transaction and only then pass this value to [`UdpClientRoaming::commit_candidate`].
/// Until that call the old socket/CIDs/epoch remain authoritative and rollback is still possible.
/// This type omits `Debug` because it contains both directional CIDs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UdpClientPathCommit {
    candidate_id: u64,
    epoch: u64,
    transmit_cid: UdpClientCid,
    receive_cid: UdpClientCid,
}

impl UdpClientPathCommit {
    pub fn candidate_id(self) -> u64 {
        self.candidate_id
    }

    pub fn epoch(self) -> u64 {
        self.epoch
    }

    pub fn transmit_cid(&self) -> &UdpClientCid {
        &self.transmit_cid
    }

    pub fn receive_cid(&self) -> &UdpClientCid {
        &self.receive_cid
    }
}

/// Result of one authenticated server-to-client path-control record.
pub enum UdpClientPathAction {
    /// Send an authenticated PATH_RESPONSE over the exact candidate socket.
    Transmit(UdpClientPathTransmit),
    /// Apply COMMIT_PATH in the platform and then publish the supplied snapshot to the core.
    CommitReady(UdpClientPathCommit),
    /// The peer rejected this candidate. The platform must execute ABORT_PATH.
    PeerAbort { candidate_id: u64, code: u16 },
}

enum UdpClientCandidatePhase {
    WaitingChallenge,
    WaitingCommit { token: [u8; PATH_CHALLENGE_LEN] },
    CommitReady,
}

struct UdpClientCandidate {
    candidate_id: u64,
    message_id: u32,
    epoch: u64,
    transmit_cid: UdpClientCid,
    receive_cid: UdpClientCid,
    phase: UdpClientCandidatePhase,
    created_at: Instant,
    last_sent_at: Instant,
    transmissions: u8,
}

impl UdpClientCandidate {
    fn init_transmit(&self) -> UdpClientPathTransmit {
        UdpClientPathTransmit {
            candidate_id: self.candidate_id,
            destination_cid: self.transmit_cid,
            message_id: self.message_id,
            // Tell the server which CID its candidate-path packets must use in this direction.
            control: PathControl::Init {
                cid: self.receive_cid,
                epoch: self.epoch,
            },
        }
    }

    fn response_transmit(&self, token: [u8; PATH_CHALLENGE_LEN]) -> UdpClientPathTransmit {
        UdpClientPathTransmit {
            candidate_id: self.candidate_id,
            destination_cid: self.transmit_cid,
            message_id: self.message_id,
            control: PathControl::Response {
                epoch: self.epoch,
                token,
            },
        }
    }

    fn commit(&self) -> UdpClientPathCommit {
        UdpClientPathCommit {
            candidate_id: self.candidate_id,
            epoch: self.epoch,
            transmit_cid: self.transmit_cid,
            receive_cid: self.receive_cid,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= UDP_CLIENT_PATH_VALIDATION_TIMEOUT
    }

    fn note_transmit(&mut self, now: Instant) -> Result<(), UdpClientRoamingError> {
        if self.transmissions >= UDP_CLIENT_PATH_MAX_TRANSMISSIONS {
            return Err(UdpClientRoamingError::RetryLimit);
        }
        self.transmissions = self.transmissions.saturating_add(1);
        self.last_sent_at = now;
        Ok(())
    }
}

/// One session-wide client protocol actor. PacketCodec/replay state remains in the surrounding UDP
/// tunnel actor; only successfully decrypted, single-part server controls may enter this object.
/// The type omits `Debug` because it retains CID derivation secrets and candidate control material.
pub struct UdpClientRoaming {
    session_id: u64,
    client_to_server_cid_secret: Zeroizing<[u8; 32]>,
    server_to_client_cid_secret: Zeroizing<[u8; 32]>,
    active_epoch: u64,
    active_transmit_cid: UdpClientCid,
    active_receive_cid: UdpClientCid,
    candidate: Option<UdpClientCandidate>,
}

impl UdpClientRoaming {
    pub fn new(
        session_id: u64,
        client_to_server_cid_secret: [u8; 32],
        server_to_client_cid_secret: [u8; 32],
    ) -> Result<Self, UdpClientRoamingError> {
        if session_id == 0 {
            return Err(UdpClientRoamingError::InvalidSession);
        }
        Ok(Self {
            session_id,
            client_to_server_cid_secret: Zeroizing::new(client_to_server_cid_secret),
            server_to_client_cid_secret: Zeroizing::new(server_to_client_cid_secret),
            active_epoch: 0,
            active_transmit_cid: derive_udp_cid(&client_to_server_cid_secret, session_id, 0),
            active_receive_cid: derive_udp_cid(&server_to_client_cid_secret, session_id, 0),
            candidate: None,
        })
    }

    pub fn active_epoch(&self) -> u64 {
        self.active_epoch
    }

    pub fn active_transmit_cid(&self) -> &UdpClientCid {
        &self.active_transmit_cid
    }

    pub fn active_receive_cid(&self) -> &UdpClientCid {
        &self.active_receive_cid
    }

    pub fn candidate_id(&self) -> Option<u64> {
        self.candidate
            .as_ref()
            .map(|candidate| candidate.candidate_id)
    }

    pub fn candidate_epoch(&self) -> Option<u64> {
        self.candidate.as_ref().map(|candidate| candidate.epoch)
    }

    /// Start validation only after PREPARE_PATH and BIND_SOCKET succeeded for this exact platform
    /// candidate. The returned PATH_INIT is encrypted and sent by the surrounding UDP actor.
    pub fn begin_candidate(
        &mut self,
        candidate_id: u64,
        message_id: u32,
        now: Instant,
    ) -> Result<UdpClientPathTransmit, UdpClientRoamingError> {
        if candidate_id == 0 {
            return Err(UdpClientRoamingError::InvalidCandidate);
        }
        if self.candidate.is_some() {
            return Err(UdpClientRoamingError::CandidateBusy);
        }
        let epoch = self
            .active_epoch
            .checked_add(1)
            .ok_or(UdpClientRoamingError::GenerationExhausted)?;
        let candidate = UdpClientCandidate {
            candidate_id,
            message_id,
            epoch,
            transmit_cid: derive_udp_cid(&self.client_to_server_cid_secret, self.session_id, epoch),
            receive_cid: derive_udp_cid(&self.server_to_client_cid_secret, self.session_id, epoch),
            phase: UdpClientCandidatePhase::WaitingChallenge,
            created_at: now,
            last_sent_at: now,
            transmissions: 1,
        };
        let transmit = candidate.init_transmit();
        self.candidate = Some(candidate);
        Ok(transmit)
    }

    /// Advance state from one authenticated, replay-checked, unfragmented server control. The
    /// caller supplies the cleartext destination CID from the candidate packet header so a valid
    /// record delivered on an old or unrelated path cannot commit the candidate.
    pub fn accept_authenticated_control(
        &mut self,
        destination_cid: &UdpClientCid,
        message_id: u32,
        control: &PathControl,
        now: Instant,
    ) -> Result<UdpClientPathAction, UdpClientRoamingError> {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.expired(now))
        {
            self.candidate = None;
            return Err(UdpClientRoamingError::CandidateExpired);
        }
        let candidate = self
            .candidate
            .as_mut()
            .ok_or(UdpClientRoamingError::StaleCandidate)?;
        if destination_cid != &candidate.receive_cid || message_id != candidate.message_id {
            return Err(UdpClientRoamingError::StaleControl);
        }

        match control {
            PathControl::Challenge { epoch, token } => {
                if *epoch != candidate.epoch || token.iter().all(|byte| *byte == 0) {
                    return Err(UdpClientRoamingError::InvalidControl);
                }
                let response_token = match &candidate.phase {
                    UdpClientCandidatePhase::WaitingChallenge => *token,
                    UdpClientCandidatePhase::WaitingCommit { token: expected }
                        if expected == token =>
                    {
                        *expected
                    }
                    _ => return Err(UdpClientRoamingError::StaleControl),
                };
                candidate.note_transmit(now)?;
                candidate.phase = UdpClientCandidatePhase::WaitingCommit {
                    token: response_token,
                };
                Ok(UdpClientPathAction::Transmit(
                    candidate.response_transmit(response_token),
                ))
            }
            PathControl::Commit { cid, epoch } => {
                if *epoch != candidate.epoch || cid != &candidate.transmit_cid {
                    return Err(UdpClientRoamingError::InvalidControl);
                }
                if !matches!(
                    &candidate.phase,
                    UdpClientCandidatePhase::WaitingCommit { .. }
                        | UdpClientCandidatePhase::CommitReady
                ) {
                    return Err(UdpClientRoamingError::StaleControl);
                }
                candidate.phase = UdpClientCandidatePhase::CommitReady;
                Ok(UdpClientPathAction::CommitReady(candidate.commit()))
            }
            PathControl::Abort { epoch, code } => {
                if *epoch != candidate.epoch {
                    return Err(UdpClientRoamingError::StaleControl);
                }
                let candidate_id = candidate.candidate_id;
                let code = *code;
                self.candidate = None;
                Ok(UdpClientPathAction::PeerAbort { candidate_id, code })
            }
            PathControl::Init { .. } | PathControl::Response { .. } => {
                Err(UdpClientRoamingError::InvalidControl)
            }
        }
    }

    /// Return an exact re-encryption intent when the current phase has been silent for one retry
    /// interval. Every call is bounded; reaching the transmission ceiling removes the candidate
    /// so the platform can run ABORT_PATH and fall back to a full reconnect.
    pub fn retransmit_due(
        &mut self,
        now: Instant,
    ) -> Result<Option<UdpClientPathTransmit>, UdpClientRoamingError> {
        let Some(candidate) = self.candidate.as_mut() else {
            return Ok(None);
        };
        if candidate.expired(now) {
            self.candidate = None;
            return Err(UdpClientRoamingError::CandidateExpired);
        }
        if now.saturating_duration_since(candidate.last_sent_at) < UDP_CLIENT_PATH_RETRY_INTERVAL {
            return Ok(None);
        }
        let transmit = match &candidate.phase {
            UdpClientCandidatePhase::WaitingChallenge => candidate.init_transmit(),
            UdpClientCandidatePhase::WaitingCommit { token } => candidate.response_transmit(*token),
            UdpClientCandidatePhase::CommitReady => return Ok(None),
        };
        if let Err(error) = candidate.note_transmit(now) {
            self.candidate = None;
            return Err(error);
        }
        Ok(Some(transmit))
    }

    /// Publish a path only after the platform's COMMIT_PATH acknowledgement succeeded. A stale
    /// completion can neither roll the active epoch back nor steal a newer candidate.
    pub fn commit_candidate(
        &mut self,
        commit: UdpClientPathCommit,
    ) -> Result<(), UdpClientRoamingError> {
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(UdpClientRoamingError::StaleCandidate)?;
        if !matches!(&candidate.phase, UdpClientCandidatePhase::CommitReady)
            || candidate.commit() != commit
        {
            return Err(UdpClientRoamingError::StaleCandidate);
        }
        self.active_epoch = commit.epoch;
        self.active_transmit_cid = commit.transmit_cid;
        self.active_receive_cid = commit.receive_cid;
        self.candidate = None;
        Ok(())
    }

    /// Drop only the exact platform candidate generation. Returns false for late cleanup from a
    /// superseded path so that cleanup cannot accidentally abort a newer transaction.
    pub fn abort_candidate(&mut self, candidate_id: u64) -> bool {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.candidate_id == candidate_id)
        {
            self.candidate = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_ID: u64 = 0x0102_0304_0506_0708;
    const C2S: [u8; 32] = [0x11; 32];
    const S2C: [u8; 32] = [0x22; 32];
    const TOKEN: [u8; PATH_CHALLENGE_LEN] = [0x33; PATH_CHALLENGE_LEN];

    fn roaming() -> UdpClientRoaming {
        UdpClientRoaming::new(SESSION_ID, C2S, S2C).unwrap()
    }

    fn begin(
        roaming: &mut UdpClientRoaming,
        candidate_id: u64,
        message_id: u32,
        now: Instant,
    ) -> UdpClientPathTransmit {
        roaming
            .begin_candidate(candidate_id, message_id, now)
            .unwrap()
    }

    #[test]
    fn full_validation_is_directional_and_commit_is_two_phase() {
        let now = Instant::now();
        let mut roaming = roaming();
        assert_eq!(roaming.active_epoch(), 0);
        assert_eq!(
            roaming.active_transmit_cid(),
            &derive_udp_cid(&C2S, SESSION_ID, 0)
        );
        assert_eq!(
            roaming.active_receive_cid(),
            &derive_udp_cid(&S2C, SESSION_ID, 0)
        );

        let init = begin(&mut roaming, 7, 19, now);
        let next_transmit = derive_udp_cid(&C2S, SESSION_ID, 1);
        let next_receive = derive_udp_cid(&S2C, SESSION_ID, 1);
        assert_eq!(init.candidate_id(), 7);
        assert_eq!(init.message_id(), 19);
        assert_eq!(init.destination_cid(), &next_transmit);
        assert!(
            init.control()
                == &PathControl::Init {
                    cid: next_receive,
                    epoch: 1
                }
        );

        let action = roaming
            .accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Challenge {
                    epoch: 1,
                    token: TOKEN,
                },
                now + Duration::from_millis(10),
            )
            .unwrap();
        let UdpClientPathAction::Transmit(response) = action else {
            panic!("PATH_CHALLENGE must produce PATH_RESPONSE");
        };
        assert_eq!(response.destination_cid(), &next_transmit);
        assert!(
            response.control()
                == &PathControl::Response {
                    epoch: 1,
                    token: TOKEN
                }
        );

        let action = roaming
            .accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Commit {
                    cid: next_transmit,
                    epoch: 1,
                },
                now + Duration::from_millis(20),
            )
            .unwrap();
        let UdpClientPathAction::CommitReady(commit) = action else {
            panic!("PATH_COMMIT must produce a platform commit snapshot");
        };
        assert_eq!(
            roaming.active_epoch(),
            0,
            "wire commit must not bypass OS commit"
        );
        roaming.commit_candidate(commit).unwrap();
        assert_eq!(roaming.active_epoch(), 1);
        assert_eq!(roaming.active_transmit_cid(), &next_transmit);
        assert_eq!(roaming.active_receive_cid(), &next_receive);
        assert_eq!(roaming.candidate_id(), None);
    }

    #[test]
    fn stale_or_wrong_direction_control_cannot_advance_the_candidate() {
        let now = Instant::now();
        let mut roaming = roaming();
        begin(&mut roaming, 7, 19, now);
        let next_transmit = derive_udp_cid(&C2S, SESSION_ID, 1);
        let next_receive = derive_udp_cid(&S2C, SESSION_ID, 1);

        assert!(matches!(
            roaming.begin_candidate(8, 20, now),
            Err(UdpClientRoamingError::CandidateBusy)
        ));
        assert!(matches!(
            roaming.accept_authenticated_control(
                &next_transmit,
                19,
                &PathControl::Challenge {
                    epoch: 1,
                    token: TOKEN,
                },
                now,
            ),
            Err(UdpClientRoamingError::StaleControl)
        ));
        assert!(matches!(
            roaming.accept_authenticated_control(
                &next_receive,
                20,
                &PathControl::Challenge {
                    epoch: 1,
                    token: TOKEN,
                },
                now,
            ),
            Err(UdpClientRoamingError::StaleControl)
        ));
        assert!(matches!(
            roaming.accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Commit {
                    cid: next_transmit,
                    epoch: 1,
                },
                now,
            ),
            Err(UdpClientRoamingError::StaleControl)
        ));
        assert!(matches!(
            roaming.accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Challenge {
                    epoch: 2,
                    token: TOKEN,
                },
                now,
            ),
            Err(UdpClientRoamingError::InvalidControl)
        ));
        assert_eq!(roaming.candidate_id(), Some(7));
        assert_eq!(roaming.active_epoch(), 0);
    }

    #[test]
    fn retransmission_and_lifetime_are_bounded() {
        let now = Instant::now();
        let mut roaming = roaming();
        let first = begin(&mut roaming, 7, 19, now);
        assert!(roaming
            .retransmit_due(now + UDP_CLIENT_PATH_RETRY_INTERVAL - Duration::from_millis(1))
            .unwrap()
            .is_none());
        for transmission in 2..=UDP_CLIENT_PATH_MAX_TRANSMISSIONS {
            let retry = roaming
                .retransmit_due(now + UDP_CLIENT_PATH_RETRY_INTERVAL * u32::from(transmission - 1))
                .unwrap()
                .expect("retry is due");
            assert!(retry == first);
        }
        assert!(matches!(
            roaming.retransmit_due(
                now + UDP_CLIENT_PATH_RETRY_INTERVAL * u32::from(UDP_CLIENT_PATH_MAX_TRANSMISSIONS)
            ),
            Err(UdpClientRoamingError::RetryLimit)
        ));
        assert_eq!(roaming.candidate_id(), None);

        begin(&mut roaming, 8, 20, now);
        assert!(matches!(
            roaming.retransmit_due(now + UDP_CLIENT_PATH_VALIDATION_TIMEOUT),
            Err(UdpClientRoamingError::CandidateExpired)
        ));
        assert_eq!(roaming.candidate_id(), None);
    }

    #[test]
    fn duplicate_challenge_is_idempotent_and_abort_is_generation_scoped() {
        let now = Instant::now();
        let mut roaming = roaming();
        begin(&mut roaming, 7, 19, now);
        let next_receive = derive_udp_cid(&S2C, SESSION_ID, 1);
        for offset in [1, 2] {
            let action = roaming
                .accept_authenticated_control(
                    &next_receive,
                    19,
                    &PathControl::Challenge {
                        epoch: 1,
                        token: TOKEN,
                    },
                    now + Duration::from_millis(offset),
                )
                .unwrap();
            let UdpClientPathAction::Transmit(response) = action else {
                panic!("exact duplicate challenge must resend the response");
            };
            assert!(
                response.control()
                    == &PathControl::Response {
                        epoch: 1,
                        token: TOKEN,
                    }
            );
        }
        assert!(!roaming.abort_candidate(6));
        assert_eq!(roaming.candidate_id(), Some(7));
        assert!(roaming.abort_candidate(7));
        assert_eq!(roaming.candidate_id(), None);

        begin(&mut roaming, 8, 20, now);
        let action = roaming
            .accept_authenticated_control(
                &next_receive,
                20,
                &PathControl::Abort { epoch: 1, code: 17 },
                now + Duration::from_millis(3),
            )
            .unwrap();
        assert!(matches!(
            action,
            UdpClientPathAction::PeerAbort {
                candidate_id: 8,
                code: 17
            }
        ));
        assert_eq!(roaming.candidate_id(), None);
        assert_eq!(roaming.active_epoch(), 0);
    }

    #[test]
    fn stale_platform_commit_cannot_publish_after_abort() {
        let now = Instant::now();
        let mut roaming = roaming();
        begin(&mut roaming, 7, 19, now);
        let next_transmit = derive_udp_cid(&C2S, SESSION_ID, 1);
        let next_receive = derive_udp_cid(&S2C, SESSION_ID, 1);
        let action = roaming
            .accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Challenge {
                    epoch: 1,
                    token: TOKEN,
                },
                now,
            )
            .unwrap();
        assert!(matches!(action, UdpClientPathAction::Transmit(_)));
        let action = roaming
            .accept_authenticated_control(
                &next_receive,
                19,
                &PathControl::Commit {
                    cid: next_transmit,
                    epoch: 1,
                },
                now,
            )
            .unwrap();
        let UdpClientPathAction::CommitReady(commit) = action else {
            panic!("expected commit snapshot");
        };
        assert!(roaming.abort_candidate(7));
        assert_eq!(
            roaming.commit_candidate(commit),
            Err(UdpClientRoamingError::StaleCandidate)
        );
        assert_eq!(roaming.active_epoch(), 0);
    }

    #[test]
    fn shared_wire_codec_round_trips_one_state_machine_transmit() {
        let now = Instant::now();
        let mut roaming = roaming();
        let transmit = begin(&mut roaming, 7, 19, now);
        let key = [0x44; 32];
        let mut tx = PacketCodec::new(key);
        let mut rx = PacketCodec::new(key);

        let wire = encrypt_path_transmit(&mut tx, 23, &transmit).unwrap();
        let (header, _) = decode_udp_short(&wire).unwrap();
        assert_eq!(header.destination_cid(), transmit.destination_cid());
        assert_eq!(header.packet_number(), 23);

        let packet = decrypt_authenticated_packet(&mut rx, &wire).unwrap();
        assert_eq!(packet.destination_cid(), transmit.destination_cid());
        assert_eq!(packet.packet_number(), 23);
        let decoded = decode_authenticated_path_control(&packet)
            .unwrap()
            .expect("PATH_INIT is control");
        assert_eq!(decoded.message_id(), transmit.message_id());
        assert!(decoded.control() == transmit.control());
    }

    #[test]
    fn shared_wire_codec_distinguishes_data_and_rejects_fragmented_path_control() {
        let key = [0x55; 32];
        let cid = [0x66; CID_LEN];
        let mut tx = PacketCodec::new(key);
        let mut rx = PacketCodec::new(key);
        let data_record = tx.encrypt_packet(b"ordinary tunnel data", &[]).unwrap();
        let data_wire = UdpShortHeader::new(cid, 1).encode(&data_record);
        let packet = decrypt_authenticated_packet(&mut rx, &data_wire).unwrap();
        assert!(decode_authenticated_path_control(&packet)
            .unwrap()
            .is_none());
        assert_eq!(packet.into_plaintext(), b"ordinary tunnel data");

        let body = PathControl::Abort { epoch: 1, code: 2 }.encode_body();
        let fragmented = control_v2::Frame {
            message_type: control_v2::TYPE_PATH_ABORT,
            flags: 0,
            message_id: 9,
            part_index: 0,
            part_count: 2,
            payload: &body,
        }
        .encode()
        .unwrap();
        let record = tx.encrypt_packet(&fragmented, &[]).unwrap();
        let wire = UdpShortHeader::new(cid, 2).encode(&record);
        let packet = decrypt_authenticated_packet(&mut rx, &wire).unwrap();
        assert!(matches!(
            decode_authenticated_path_control(&packet),
            Err(UdpClientRoamingWireError::FragmentedControl)
        ));
    }

    #[test]
    fn shared_wire_codec_uses_the_session_replay_window() {
        let key = [0x77; 32];
        let cid = [0x88; CID_LEN];
        let mut tx = PacketCodec::new(key);
        let mut rx = PacketCodec::new(key);
        let record = tx.encrypt_packet(b"data", &[]).unwrap();
        let wire = UdpShortHeader::new(cid, 7).encode(&record);
        decrypt_authenticated_packet(&mut rx, &wire).unwrap();
        assert!(decrypt_authenticated_packet(&mut rx, &wire).is_err());
    }
}
