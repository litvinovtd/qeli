pub mod obfs;
pub mod obfuscate;
pub mod packet;
pub mod quic;
pub mod realtls;
pub mod tls;

pub use obfuscate::Obfuscator;
pub use packet::{read_record, read_tls_record, Framing, PacketCodec};
pub use quic::{generate_connection_id, unwrap_quic, wrap_quic_long, wrap_quic_short};
pub use tls::{pick_random_sni, FakeTlsHandshake};

/// Stream bonding (multipath): a secondary connection's first post-handshake
/// message is `JOIN_MAGIC ‖ token(JOIN_TOKEN_LEN) ‖ stream_index(1)`, presenting
/// the per-session token from AUTH OK. The 8-byte magic can't collide with a real
/// auth packet's random 32-byte proof, so old single-stream clients (no tag) are
/// still parsed as AUTH. Shared by the server (parse) and client (build).
pub const JOIN_MAGIC: &[u8; 8] = b"QELIJOIN";
pub const JOIN_TOKEN_LEN: usize = 16;
