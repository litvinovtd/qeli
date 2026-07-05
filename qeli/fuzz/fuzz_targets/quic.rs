#![no_main]
//! Fuzz the QUIC short/long-header unmasking parser on arbitrary input. The
//! header-byte, connection-id and packet-number slicing must reject a malformed
//! packet with an error, never panic or over-read.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::unwrap_quic;

fuzz_target!(|data: &[u8]| {
    let _ = unwrap_quic(data);
});
