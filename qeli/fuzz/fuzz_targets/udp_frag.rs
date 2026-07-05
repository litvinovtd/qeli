#![no_main]
//! Fuzz the UDP handshake-fragment reassembler on arbitrary input. The count/index
//! header, chunk-length bounds (MAX_FRAGS / MAX_CHUNK), and the per-peer buffer
//! accounting must reject any malformed fragment with an error, never panic or
//! over-allocate.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::udp_frag::{is_fragment, Reassembler};

fuzz_target!(|data: &[u8]| {
    let _ = is_fragment(data);
    // Feed the same bytes twice — exercises index/count validation and the
    // already-seen-slot / duplicate path without needing a second input.
    let mut r = Reassembler::new();
    let _ = r.push(data);
    let _ = r.push(data);
});
