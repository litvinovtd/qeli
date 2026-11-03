#![no_main]
//! Exercise both arbitrary heads and mutations of a valid authenticated-path
//! upgrade. Random bytes alone rarely reach critical header validation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0x5au8; 32];
    let _ = qeli_core::protocol::obfs::ws::build_response(data, &key);
    let path = qeli_core::protocol::obfs::ws::derive_path(&key);
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
    ).into_bytes();
    assert!(qeli_core::protocol::obfs::ws::build_response(&head, &key).is_some());
    // Bounded edits reach the request line, critical headers and terminator.
    for edit in data.chunks_exact(3).take(4096) {
        let index = u16::from_be_bytes([edit[0], edit[1]]) as usize % head.len();
        head[index] = edit[2];
    }
    let _ = qeli_core::protocol::obfs::ws::build_response(&head, &key);
});
