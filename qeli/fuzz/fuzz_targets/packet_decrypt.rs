#![no_main]
//! Fuzz the data-plane record codec on arbitrary input. The key is fixed: we are
//! exercising the record framing — header/length checks, nonce/tag slicing,
//! padding-length handling, replay accounting — that runs around the AEAD, not
//! the cipher itself. decrypt_packet must reject any malformed input with an
//! error, never panic or over-read.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::PacketCodec;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    // TLS-dressed framing (fake-tls / obfs / reality / udp wire modes).
    let _ = PacketCodec::new(key).decrypt_packet(data);
    // Bare length-prefixed framing (the `plain` wire mode).
    let _ = PacketCodec::new_raw(key).decrypt_packet(data);
});
