//! Wire contracts shared by future TCP resume and UDP path migration.
//!
//! UDP remains a protocol-only contract. Under the default-off `experimental-roaming` feature,
//! the Linux server now advertises and consumes the authenticated TCP resume/handover messages;
//! the client core still advertises neither bit, so ordinary and production sessions are unchanged.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::control_v2;

type HmacSha256 = Hmac<Sha256>;

pub const CID_LEN: usize = 8;
pub const SESSION_LOCATOR_LEN: usize = 16;
pub const PATH_CHALLENGE_LEN: usize = 16;
pub const RESUME_PROOF_LEN: usize = 32;

pub const UDP_SHORT_MARKER: [u8; 2] = [0xD1, 0x52];
/// marker(2) + destination CID(8) + outer packet number(4).
pub const UDP_SHORT_HEADER_LEN: usize = 2 + CID_LEN + 4;

const CID_LABEL: &[u8] = b"qeli-udp-cid-v1";
const RESUME_PROOF_LABEL: &[u8] = b"qeli-tcp-resume-proof-v1";
pub const TCP_RESUME_MAGIC: [u8; 8] = *b"QELIRSM1";
pub const TCP_RESUME_VERSION: u8 = 1;
pub const TCP_RESUME_FLAG_HANDOVER: u8 = 1 << 0;
const TCP_RESUME_KNOWN_FLAGS: u8 = TCP_RESUME_FLAG_HANDOVER;
/// magic(8) + version(1) + flags(1) + locator(16) + epoch(8) + slot(4) +
/// fresh-handshake transcript hash(32) + proof(32).
pub const TCP_RESUME_JOIN_LEN: usize = 102;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RoamingWireError {
    #[error("truncated roaming wire message")]
    Truncated,
    #[error("unexpected roaming wire marker, version or flags")]
    Unsupported,
    #[error("invalid roaming message length")]
    InvalidLength,
    #[error("unknown roaming path message type {0}")]
    UnknownPathType(u8),
}

/// Derive a directional 64-bit locator from its CID secret, stable session id and epoch.
/// The profile registry still has to reject collisions atomically before advertising it.
pub fn derive_udp_cid(cid_secret: &[u8; 32], session_id: u64, epoch: u64) -> [u8; CID_LEN] {
    let mut mac = <HmacSha256>::new_from_slice(cid_secret).expect("HMAC accepts 32-byte keys");
    mac.update(CID_LABEL);
    mac.update(&session_id.to_be_bytes());
    mac.update(&epoch.to_be_bytes());
    let digest: [u8; 32] = mac.finalize().into_bytes().into();
    let digest = Zeroizing::new(digest);
    let mut cid = [0u8; CID_LEN];
    cid.copy_from_slice(&digest[..CID_LEN]);
    cid
}

/// Fixed UDP locator header. It intentionally has no `Debug` implementation because full CIDs
/// must not reach logs. The encrypted PacketCodec record follows this header unchanged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UdpShortHeader {
    destination_cid: [u8; CID_LEN],
    packet_number: u32,
}

impl UdpShortHeader {
    pub fn new(destination_cid: [u8; CID_LEN], packet_number: u32) -> Self {
        Self {
            destination_cid,
            packet_number,
        }
    }

    pub fn destination_cid(&self) -> &[u8; CID_LEN] {
        &self.destination_cid
    }

    pub fn packet_number(&self) -> u32 {
        self.packet_number
    }

    pub fn encode(&self, encrypted_record: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_SHORT_HEADER_LEN + encrypted_record.len());
        out.extend_from_slice(&UDP_SHORT_MARKER);
        out.extend_from_slice(&self.destination_cid);
        out.extend_from_slice(&self.packet_number.to_be_bytes());
        out.extend_from_slice(encrypted_record);
        out
    }
}

pub fn decode_udp_short(bytes: &[u8]) -> Result<(UdpShortHeader, &[u8]), RoamingWireError> {
    if bytes.len() < UDP_SHORT_HEADER_LEN {
        return Err(RoamingWireError::Truncated);
    }
    if bytes[..UDP_SHORT_MARKER.len()] != UDP_SHORT_MARKER {
        return Err(RoamingWireError::Unsupported);
    }
    let mut cid = [0u8; CID_LEN];
    cid.copy_from_slice(&bytes[2..10]);
    let packet_number = u32::from_be_bytes(bytes[10..14].try_into().expect("fixed header slice"));
    Ok((
        UdpShortHeader::new(cid, packet_number),
        &bytes[UDP_SHORT_HEADER_LEN..],
    ))
}

/// Canonical input to the TCP resume proof. It contains locators and therefore deliberately
/// implements neither `Debug` nor serde traits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResumeProofInput {
    transcript_hash: [u8; 32],
    session_locator: [u8; SESSION_LOCATOR_LEN],
    resume_epoch: u64,
    logical_slot_id: u32,
    handover: bool,
}

impl ResumeProofInput {
    pub fn new(
        transcript_hash: [u8; 32],
        session_locator: [u8; SESSION_LOCATOR_LEN],
        resume_epoch: u64,
        logical_slot_id: u32,
        handover: bool,
    ) -> Self {
        Self {
            transcript_hash,
            session_locator,
            resume_epoch,
            logical_slot_id,
            handover,
        }
    }

    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    pub fn session_locator(&self) -> &[u8; SESSION_LOCATOR_LEN] {
        &self.session_locator
    }

    pub fn resume_epoch(&self) -> u64 {
        self.resume_epoch
    }

    pub fn logical_slot_id(&self) -> u32 {
        self.logical_slot_id
    }

    pub fn is_handover(&self) -> bool {
        self.handover
    }
}

pub fn make_resume_proof(
    resume_secret: &[u8; 32],
    input: &ResumeProofInput,
) -> [u8; RESUME_PROOF_LEN] {
    let mut mac = <HmacSha256>::new_from_slice(resume_secret).expect("HMAC accepts 32-byte keys");
    mac.update(RESUME_PROOF_LABEL);
    mac.update(&input.transcript_hash);
    mac.update(&input.session_locator);
    mac.update(&input.resume_epoch.to_be_bytes());
    mac.update(&input.logical_slot_id.to_be_bytes());
    mac.update(&[u8::from(input.handover)]);
    mac.finalize().into_bytes().into()
}

pub fn verify_resume_proof(
    resume_secret: &[u8; 32],
    input: &ResumeProofInput,
    received: &[u8; RESUME_PROOF_LEN],
) -> bool {
    make_resume_proof(resume_secret, input)
        .ct_eq(received)
        .into()
}

/// First authenticated plaintext after a fresh TCP key exchange. Possession of the locator
/// alone is insufficient: the proof binds the new handshake transcript, wide epoch, stable
/// logical slot and handover intent to the original session's resume secret.
pub struct TcpResumeJoin {
    input: ResumeProofInput,
    proof: [u8; RESUME_PROOF_LEN],
}

impl TcpResumeJoin {
    pub fn new(input: ResumeProofInput, resume_secret: &[u8; 32]) -> Self {
        let proof = make_resume_proof(resume_secret, &input);
        Self { input, proof }
    }

    pub fn input(&self) -> &ResumeProofInput {
        &self.input
    }

    pub fn verify(&self, resume_secret: &[u8; 32]) -> bool {
        verify_resume_proof(resume_secret, &self.input, &self.proof)
    }

    pub fn matches_transcript(&self, transcript_hash: &[u8; 32]) -> bool {
        self.input.transcript_hash.ct_eq(transcript_hash).into()
    }

    pub fn encode(&self) -> [u8; TCP_RESUME_JOIN_LEN] {
        let mut out = [0u8; TCP_RESUME_JOIN_LEN];
        out[..8].copy_from_slice(&TCP_RESUME_MAGIC);
        out[8] = TCP_RESUME_VERSION;
        out[9] = u8::from(self.input.handover) * TCP_RESUME_FLAG_HANDOVER;
        out[10..26].copy_from_slice(&self.input.session_locator);
        out[26..34].copy_from_slice(&self.input.resume_epoch.to_be_bytes());
        out[34..38].copy_from_slice(&self.input.logical_slot_id.to_be_bytes());
        out[38..70].copy_from_slice(&self.input.transcript_hash);
        out[70..].copy_from_slice(&self.proof);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RoamingWireError> {
        if bytes.len() != TCP_RESUME_JOIN_LEN {
            return Err(if bytes.len() < TCP_RESUME_JOIN_LEN {
                RoamingWireError::Truncated
            } else {
                RoamingWireError::InvalidLength
            });
        }
        if bytes[..8] != TCP_RESUME_MAGIC || bytes[8] != TCP_RESUME_VERSION {
            return Err(RoamingWireError::Unsupported);
        }
        let flags = bytes[9];
        if flags & !TCP_RESUME_KNOWN_FLAGS != 0 {
            return Err(RoamingWireError::Unsupported);
        }
        let mut locator = [0u8; SESSION_LOCATOR_LEN];
        locator.copy_from_slice(&bytes[10..26]);
        let resume_epoch = u64::from_be_bytes(bytes[26..34].try_into().expect("fixed slice"));
        let logical_slot_id = u32::from_be_bytes(bytes[34..38].try_into().expect("fixed slice"));
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&bytes[38..70]);
        let mut proof = [0u8; RESUME_PROOF_LEN];
        proof.copy_from_slice(&bytes[70..]);
        Ok(Self {
            input: ResumeProofInput::new(
                transcript_hash,
                locator,
                resume_epoch,
                logical_slot_id,
                flags & TCP_RESUME_FLAG_HANDOVER != 0,
            ),
            proof,
        })
    }
}

/// Exact CONTROL_V2 roaming bodies. As with headers containing CIDs/challenges, this enum has no
/// `Debug` implementation to prevent accidental full-token logging.
#[derive(Clone, PartialEq, Eq)]
pub enum PathControl {
    Init {
        cid: [u8; CID_LEN],
        epoch: u64,
    },
    Challenge {
        epoch: u64,
        token: [u8; PATH_CHALLENGE_LEN],
    },
    Response {
        epoch: u64,
        token: [u8; PATH_CHALLENGE_LEN],
    },
    Commit {
        cid: [u8; CID_LEN],
        epoch: u64,
    },
    Abort {
        epoch: u64,
        code: u16,
    },
}

impl PathControl {
    pub fn message_type(&self) -> u8 {
        match self {
            Self::Init { .. } => control_v2::TYPE_PATH_INIT,
            Self::Challenge { .. } => control_v2::TYPE_PATH_CHALLENGE,
            Self::Response { .. } => control_v2::TYPE_PATH_RESPONSE,
            Self::Commit { .. } => control_v2::TYPE_PATH_COMMIT,
            Self::Abort { .. } => control_v2::TYPE_PATH_ABORT,
        }
    }

    pub fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        match self {
            Self::Init { cid, epoch } | Self::Commit { cid, epoch } => {
                out.extend_from_slice(cid);
                out.extend_from_slice(&epoch.to_be_bytes());
            }
            Self::Challenge { epoch, token } | Self::Response { epoch, token } => {
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(token);
            }
            Self::Abort { epoch, code } => {
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(message_type: u8, body: &[u8]) -> Result<Self, RoamingWireError> {
        match message_type {
            control_v2::TYPE_PATH_INIT | control_v2::TYPE_PATH_COMMIT => {
                if body.len() != 16 {
                    return Err(RoamingWireError::InvalidLength);
                }
                let mut cid = [0u8; CID_LEN];
                cid.copy_from_slice(&body[..8]);
                let epoch = u64::from_be_bytes(body[8..].try_into().expect("fixed body slice"));
                if message_type == control_v2::TYPE_PATH_INIT {
                    Ok(Self::Init { cid, epoch })
                } else {
                    Ok(Self::Commit { cid, epoch })
                }
            }
            control_v2::TYPE_PATH_CHALLENGE | control_v2::TYPE_PATH_RESPONSE => {
                if body.len() != 24 {
                    return Err(RoamingWireError::InvalidLength);
                }
                let epoch = u64::from_be_bytes(body[..8].try_into().expect("fixed body slice"));
                let mut token = [0u8; PATH_CHALLENGE_LEN];
                token.copy_from_slice(&body[8..]);
                if message_type == control_v2::TYPE_PATH_CHALLENGE {
                    Ok(Self::Challenge { epoch, token })
                } else {
                    Ok(Self::Response { epoch, token })
                }
            }
            control_v2::TYPE_PATH_ABORT => {
                if body.len() != 10 {
                    return Err(RoamingWireError::InvalidLength);
                }
                Ok(Self::Abort {
                    epoch: u64::from_be_bytes(body[..8].try_into().expect("fixed body slice")),
                    code: u16::from_be_bytes(body[8..].try_into().expect("fixed body slice")),
                })
            }
            other => Err(RoamingWireError::UnknownPathType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::capabilities::{
        client_capability, implemented_client_core_capabilities, implemented_server_capabilities,
        server_capability,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn roaming_capabilities_follow_the_integration_gates() {
        let server_roaming =
            implemented_server_capabilities().bits & server_capability::ROAMING_RESERVED;
        #[cfg(feature = "experimental-roaming")]
        assert_eq!(
            server_roaming,
            server_capability::TCP_RESUME_V1 | server_capability::TCP_HANDOVER_V1
        );
        #[cfg(not(feature = "experimental-roaming"))]
        assert_eq!(server_roaming, 0);

        // No client supervisor emits an authenticated resume yet. Keeping both bits absent here
        // prevents a feature-enabled server from changing normal sessions before that lands.
        assert_eq!(
            implemented_client_core_capabilities() & client_capability::ROAMING_RESERVED,
            0
        );
    }

    #[test]
    fn cid_and_resume_proof_match_known_answers() {
        let cid = derive_udp_cid(&[0x11; 32], 0x0102_0304_0506_0708, 9);
        assert_eq!(hex(&cid), "2b5dfe529662f69f");
        let input = ResumeProofInput::new(
            [0x33; 32],
            [0x44; SESSION_LOCATOR_LEN],
            0x0102_0304_0506_0708,
            0x1122_3344,
            true,
        );
        let proof = make_resume_proof(&[0x22; 32], &input);
        assert_eq!(
            hex(&proof),
            "c8f4708335b6611c0e6c871dc86a6004d969238052a93258585f0ed688588fe2"
        );
        assert!(verify_resume_proof(&[0x22; 32], &input, &proof));
    }

    #[test]
    fn proof_binds_every_resume_field() {
        let secret = [7u8; 32];
        let base = ResumeProofInput::new([1; 32], [2; 16], 3, 4, false);
        let proof = make_resume_proof(&secret, &base);
        for changed in [
            ResumeProofInput::new([9; 32], [2; 16], 3, 4, false),
            ResumeProofInput::new([1; 32], [9; 16], 3, 4, false),
            ResumeProofInput::new([1; 32], [2; 16], 9, 4, false),
            ResumeProofInput::new([1; 32], [2; 16], 3, 9, false),
            ResumeProofInput::new([1; 32], [2; 16], 3, 4, true),
        ] {
            assert!(!verify_resume_proof(&secret, &changed, &proof));
        }
    }

    #[test]
    fn tcp_join_requires_a_fresh_matching_transcript_and_exact_wire_shape() {
        let secret = [5u8; 32];
        let input = ResumeProofInput::new([6; 32], [7; 16], u64::MAX - 1, 300, true);
        let wire = TcpResumeJoin::new(input, &secret).encode();
        assert_eq!(wire.len(), TCP_RESUME_JOIN_LEN);
        assert_eq!(&wire[..8], &TCP_RESUME_MAGIC);
        let parsed = TcpResumeJoin::decode(&wire).unwrap();
        assert!(parsed.verify(&secret));
        let mut changed = wire;
        changed[38] ^= 1;
        assert!(!TcpResumeJoin::decode(&changed).unwrap().verify(&secret));
        assert_eq!(
            TcpResumeJoin::decode(&wire[..wire.len() - 1]).err(),
            Some(RoamingWireError::Truncated)
        );
    }

    #[test]
    fn udp_marker_precedes_the_cid_and_never_depends_on_source_address() {
        let header = UdpShortHeader::new([0xAB; CID_LEN], 0x0102_0304);
        let wire = header.encode(b"ciphertext");
        assert_eq!(&wire[..2], &UDP_SHORT_MARKER);
        assert_eq!(&wire[2..10], &[0xAB; CID_LEN]);
        let (parsed, record) = decode_udp_short(&wire).unwrap();
        assert_eq!(parsed.destination_cid(), &[0xAB; CID_LEN]);
        assert_eq!(parsed.packet_number(), 0x0102_0304);
        assert_eq!(record, b"ciphertext");
        assert_eq!(
            decode_udp_short(&wire[..13]).err(),
            Some(RoamingWireError::Truncated)
        );
        let mut bad = wire;
        bad[0] ^= 1;
        assert_eq!(
            decode_udp_short(&bad).err(),
            Some(RoamingWireError::Unsupported)
        );
    }

    #[test]
    fn path_control_bodies_are_strict_and_epoch_is_u64() {
        let messages = [
            PathControl::Init {
                cid: [1; 8],
                epoch: u64::MAX,
            },
            PathControl::Challenge {
                epoch: 2,
                token: [3; 16],
            },
            PathControl::Response {
                epoch: 4,
                token: [5; 16],
            },
            PathControl::Commit {
                cid: [6; 8],
                epoch: 7,
            },
            PathControl::Abort { epoch: 8, code: 9 },
        ];
        for message in messages {
            let ty = message.message_type();
            let body = message.encode_body();
            let decoded = PathControl::decode(ty, &body).unwrap();
            assert!(decoded == message);
            assert_eq!(
                PathControl::decode(ty, &body[..body.len() - 1]).err(),
                Some(RoamingWireError::InvalidLength)
            );
        }
        assert_eq!(
            PathControl::decode(0xFF, &[]).err(),
            Some(RoamingWireError::UnknownPathType(0xFF))
        );
    }
}
