#![no_main]
//! Fuzz the UDP obfs datagram opener on arbitrary input. The flag/nonce slicing and
//! ChaCha20 keystream framing must reject any malformed datagram with `None`, never
//! panic or over-read. The key is fixed — we exercise the framing, not the cipher.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::obfs::obfs_datagram_open;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    let _ = obfs_datagram_open(&key, data);
});
