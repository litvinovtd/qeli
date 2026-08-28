//! Client-side UDP data-plane framing after authentication.
//!
//! The handshake always uses the legacy four-byte QUIC-shaped connection id. Once AuthOK
//! negotiates UDP roaming, ordinary records and bare carrier controls switch atomically to
//! directional eight-byte CIDs. Keeping that choice here prevents the platform adapters and
//! the PMTU/data paths from drifting into different wire formats or overhead calculations.

use crate::protocol::quic::{unwrap_quic_payload, wrap_quic_short_into, QuicError};
#[cfg(feature = "experimental-roaming")]
use crate::protocol::roaming::{decode_udp_short, RoamingWireError, UdpShortHeader, CID_LEN};

/// Immutable framing snapshot for one active UDP path. It intentionally omits `Debug`: the
/// roaming form retains both complete directional CIDs, which must not reach diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpClientFraming {
    Unmasked,
    LegacyQuic([u8; 4]),
    #[cfg(feature = "experimental-roaming")]
    RoamingCid {
        transmit_cid: [u8; CID_LEN],
        receive_cid: [u8; CID_LEN],
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UdpClientFramingError {
    #[error(transparent)]
    LegacyQuic(#[from] QuicError),
    #[cfg(feature = "experimental-roaming")]
    #[error(transparent)]
    RoamingCid(#[from] RoamingWireError),
    #[cfg(feature = "experimental-roaming")]
    #[error("UDP roaming datagram carries an unexpected destination CID")]
    UnexpectedDestinationCid,
}

impl UdpClientFraming {
    pub(crate) fn legacy(quic_enabled: bool, connection_id: [u8; 4]) -> Self {
        if quic_enabled {
            Self::LegacyQuic(connection_id)
        } else {
            Self::Unmasked
        }
    }

    #[cfg(feature = "experimental-roaming")]
    pub(crate) fn roaming(transmit_cid: [u8; CID_LEN], receive_cid: [u8; CID_LEN]) -> Self {
        Self::RoamingCid {
            transmit_cid,
            receive_cid,
        }
    }

    pub(crate) fn uses_packet_number(self) -> bool {
        !matches!(self, Self::Unmasked)
    }

    pub(crate) fn wrapper_len(self) -> usize {
        match self {
            Self::Unmasked => 0,
            Self::LegacyQuic(_) => crate::protocol::quic::QUIC_SHORT_HEADER_MIN,
            #[cfg(feature = "experimental-roaming")]
            Self::RoamingCid { .. } => crate::protocol::roaming::UDP_SHORT_HEADER_LEN,
        }
    }

    pub(crate) fn wrap_into<'a>(
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
            Self::RoamingCid { transmit_cid, .. } => {
                UdpShortHeader::new(transmit_cid, packet_number).encode_into(record, output);
                output
            }
        }
    }

    pub(crate) fn unwrap(self, datagram: &[u8]) -> Result<&[u8], UdpClientFramingError> {
        match self {
            Self::Unmasked => Ok(datagram),
            // Preserve the legacy parser's rolling-upgrade behaviour: historically the client
            // accepted the server's QUIC-shaped payload without pinning the four-byte CID.
            Self::LegacyQuic(_) => Ok(unwrap_quic_payload(datagram)?),
            #[cfg(feature = "experimental-roaming")]
            Self::RoamingCid { receive_cid, .. } => {
                let (header, record) = decode_udp_short(datagram)?;
                if header.destination_cid() != &receive_cid {
                    return Err(UdpClientFramingError::UnexpectedDestinationCid);
                }
                Ok(record)
            }
        }
    }
}

/// Wrap one post-auth datagram and advance the outer packet number only when a QUIC-shaped
/// envelope is active. Unmasked profiles retain their previous packet-number behaviour.
pub(crate) fn wrap_next_udp_record<'a>(
    framing: UdpClientFraming,
    record: &'a [u8],
    packet_number: &mut u32,
    output: &'a mut Vec<u8>,
) -> &'a [u8] {
    let current = *packet_number;
    if framing.uses_packet_number() {
        *packet_number = packet_number.wrapping_add(1);
    }
    framing.wrap_into(record, current, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmasked_is_a_borrowed_passthrough() {
        let record = b"record";
        let mut output = vec![9, 9];
        let decoded = UdpClientFraming::legacy(false, [1, 2, 3, 4])
            .unwrap(record)
            .expect("unmasked record");
        assert_eq!(decoded, record);
        assert_eq!(output, [9, 9]);
        assert_eq!(
            UdpClientFraming::legacy(false, [1, 2, 3, 4]).wrap_into(record, 7, &mut output),
            record
        );
    }

    #[test]
    fn legacy_wire_remains_byte_for_byte_compatible() {
        let connection_id = [1, 2, 3, 4];
        let framing = UdpClientFraming::legacy(true, connection_id);
        let expected = crate::protocol::quic::wrap_quic_short(b"record", &connection_id, 7);
        let mut actual = Vec::new();
        assert_eq!(framing.wrap_into(b"record", 7, &mut actual), expected);
        assert_eq!(framing.unwrap(&actual).expect("legacy payload"), b"record");
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn roaming_uses_directional_cids_and_rejects_the_wrong_direction() {
        let transmit_cid = [0x11; CID_LEN];
        let receive_cid = [0x22; CID_LEN];
        let framing = UdpClientFraming::roaming(transmit_cid, receive_cid);
        let mut wire = Vec::new();
        framing.wrap_into(b"uplink", 9, &mut wire);
        let (header, payload) = decode_udp_short(&wire).expect("uplink header");
        assert_eq!(header.destination_cid(), &transmit_cid);
        assert_eq!(payload, b"uplink");

        UdpShortHeader::new(receive_cid, 10).encode_into(b"downlink", &mut wire);
        assert_eq!(framing.unwrap(&wire).expect("downlink CID"), b"downlink");
        UdpShortHeader::new(transmit_cid, 11).encode_into(b"stale", &mut wire);
        assert!(matches!(
            framing.unwrap(&wire),
            Err(UdpClientFramingError::UnexpectedDestinationCid)
        ));
    }
}
