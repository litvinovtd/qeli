pub mod capabilities;
pub mod control_v2;
pub mod ctrl;
pub mod data_frag;
pub mod h2_carrier;
pub mod icmp;
pub mod ip;
pub mod obfs;
pub mod obfuscate;
pub mod packet;
pub mod quic;
pub mod realtls;
pub mod recordizer;
pub mod roaming;
pub mod shaper;
pub mod tls;
pub mod udp_frag;

pub use obfuscate::Obfuscator;
pub use packet::{read_record, read_record_into, read_tls_record, Framing, PacketCodec};
pub use quic::{
    generate_connection_id, looks_like_quic_initial, unwrap_quic, unwrap_quic_payload,
    wrap_quic_long, wrap_quic_long_into, wrap_quic_short, wrap_quic_short_into,
};
pub use shaper::{
    liveness_deadline, randomized_heartbeat_delay, Shaper, ShapingConfig, SharedCoverBudget,
};
pub use tls::FakeTlsHandshake;

/// Stream bonding (multipath): a secondary connection's first post-handshake
/// message is `JOIN_MAGIC ‖ token(JOIN_TOKEN_LEN) ‖ stream_index(1)`, presenting
/// the per-session token from AUTH OK. The 8-byte magic can't collide with a real
/// auth packet's random 32-byte proof, so old single-stream clients (no tag) are
/// still parsed as AUTH. Shared by the server (parse) and client (build).
pub const JOIN_MAGIC: &[u8; 8] = b"QELIJOIN";
pub const JOIN_TOKEN_LEN: usize = 16;

/// Hash of an IPv4 or IPv6 packet's flow tuple: address family, protocol,
/// source/destination address, and (for unfragmented TCP/UDP) source/destination
/// port. Multipath uses it to PIN each inner flow to ONE bonded
/// stream, so a single connection's packets keep their order. Round-robin striping
/// instead split one flow across streams, and with no resequencing the receiver
/// saw reordering → inner-TCP dup-ACKs/retransmits that could hurt throughput.
/// Each side hashes only its own outbound packets (the two directions decide
/// independently), so the hash need not agree across peers — only be deterministic
/// per flow within one process. Every fragment of one datagram is pinned by its
/// fragment ID; malformed/non-IP records hash by their complete bytes.
pub fn flow_hash(pkt: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match ip::parse_ip_packet(pkt) {
        Ok(meta) => {
            meta.version.hash(&mut h);
            meta.source.hash(&mut h);
            meta.destination.hash(&mut h);
            if let Some(fragment) = meta.fragment.filter(|fragment| fragment.is_fragmented()) {
                // IPv6 fragment zero may carry Destination Options or AH after the Fragment
                // Header, while later fragments begin in the middle of the fragmentable part.
                // `meta.protocol` is therefore not stable across the datagram. The protocol
                // copied from the fragmentation header is stable by construction.
                fragment.protocol.hash(&mut h);
                fragment.id.hash(&mut h);
            } else {
                meta.protocol.hash(&mut h);
                if let Some(ports) = meta.ports(pkt) {
                    ports.hash(&mut h);
                }
            }
        }
        Err(_) => pkt.hash(&mut h),
    }
    h.finish()
}

/// Stable per-device identifier (random, persisted by the client). Sent in the
/// auth plaintext right after the 32-byte proof, prefixed by a single `0x00`
/// marker byte: `[proof:32][0x00][device_id:DEVICE_ID_LEN][user:pass]`. Old clients
/// omit it (their first post-proof byte is a username char, never `0x00`), so the
/// field is backward compatible. The server keys sessions/pool IPs by
/// `username:hex(device_id)` so several devices share one login without evicting
/// each other, while the SAME device cleanly supersedes its own old session on an
/// IP change (Wi-Fi <-> LTE).
pub const DEVICE_ID_LEN: usize = 16;

#[cfg(test)]
mod flow_hash_tests {
    use super::flow_hash;

    fn ipv6_fragment(offset: u16, more: bool) -> Vec<u8> {
        let mut packet = vec![0u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 44;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&[0xfd, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40] = 17;
        let wire = (offset << 3) | u16::from(more);
        packet[42..44].copy_from_slice(&wire.to_be_bytes());
        packet[44..48].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        packet
    }

    fn ipv6_fragment_with_post_fragment_destination_options(offset: u16, more: bool) -> Vec<u8> {
        let mut packet = ipv6_fragment(offset, more);
        packet[40] = 60; // Fragment Header -> Destination Options.
        if offset == 0 {
            // Destination Options -> UDP. Only fragment zero is guaranteed to begin with this
            // header; later fragments may begin anywhere in the fragmentable payload.
            packet[48] = 17;
            packet[49] = 0;
        }
        packet
    }

    #[test]
    fn ipv6_fragments_of_one_datagram_use_one_bonded_stream() {
        let first = ipv6_fragment(0, true);
        let later = ipv6_fragment(1, false);
        assert_eq!(flow_hash(&first), flow_hash(&later));
    }

    #[test]
    fn ipv6_fragment_ids_separate_independent_datagrams() {
        let first = ipv6_fragment(0, true);
        let mut other = first.clone();
        other[44..48].copy_from_slice(&0x8765_4321u32.to_be_bytes());
        assert_ne!(flow_hash(&first), flow_hash(&other));
    }

    #[test]
    fn ipv6_post_fragment_extensions_do_not_change_fragment_affinity() {
        let first = ipv6_fragment_with_post_fragment_destination_options(0, true);
        let later = ipv6_fragment_with_post_fragment_destination_options(1, false);
        assert_eq!(flow_hash(&first), flow_hash(&later));
    }
}
