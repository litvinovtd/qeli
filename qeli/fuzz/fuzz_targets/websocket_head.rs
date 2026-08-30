#![no_main]
//! The WebSocket upgrade head is processed before authentication. Arbitrary
//! binary input must be rejected without panicking or unbounded parsing.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x5au8; 32];
    let _ = qeli_core::protocol::obfs::ws::build_response(data, &key);
});
