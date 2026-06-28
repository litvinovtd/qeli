pub mod obfs;
pub mod obfuscate;
pub mod packet;
pub mod quic;
pub mod realtls;
pub mod shaper;
pub mod tls;
pub mod udp_frag;

pub use obfuscate::Obfuscator;
pub use packet::{read_record, read_tls_record, Framing, PacketCodec};
pub use quic::{generate_connection_id, unwrap_quic, wrap_quic_long, wrap_quic_short};
pub use shaper::{Shaper, ShapingConfig};
pub use tls::{pick_random_sni, FakeTlsHandshake};

/// Stream bonding (multipath): a secondary connection's first post-handshake
/// message is `JOIN_MAGIC ‖ token(JOIN_TOKEN_LEN) ‖ stream_index(1)`, presenting
/// the per-session token from AUTH OK. The 8-byte magic can't collide with a real
/// auth packet's random 32-byte proof, so old single-stream clients (no tag) are
/// still parsed as AUTH. Shared by the server (parse) and client (build).
pub const JOIN_MAGIC: &[u8; 8] = b"QELIJOIN";
pub const JOIN_TOKEN_LEN: usize = 16;

/// Hash of an IPv4 packet's flow tuple — protocol, src/dst address, and (for
/// TCP/UDP) src/dst port. Multipath uses it to PIN each inner flow to ONE bonded
/// stream, so a single connection's packets keep their order. Round-robin striping
/// instead split one flow across streams, and with no resequencing the receiver
/// saw reordering → inner-TCP dup-ACKs/retransmits that could hurt throughput.
/// Each side hashes only its own outbound packets (the two directions decide
/// independently), so the hash need not agree across peers — only be deterministic
/// per flow within one process. Non-IPv4 / truncated packets hash by their bytes.
pub fn flow_hash(pkt: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    if pkt.len() >= 20 && (pkt[0] >> 4) == 4 {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        pkt[9].hash(&mut h); // protocol
        pkt[12..20].hash(&mut h); // src+dst IPv4
        if matches!(pkt[9], 6 | 17) && pkt.len() >= ihl + 4 {
            pkt[ihl..ihl + 4].hash(&mut h); // src+dst ports (TCP/UDP)
        }
    } else {
        pkt.hash(&mut h);
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
