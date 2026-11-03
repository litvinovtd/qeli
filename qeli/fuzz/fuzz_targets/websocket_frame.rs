#![no_main]
//! Raw and structured binary/control frame mutations use the shipping parser.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    qeli_core::protocol::obfs::fuzz_websocket_frames(data);
    let flags = data.first().copied().unwrap_or(0);
    let mut structured = vec![flags];
    if flags & 1 != 0 {
        structured.extend_from_slice(&[0x82, 0x81, 0, 0, 0, 0, 7]);
    } else {
        structured.extend_from_slice(&[0x82, 1, 7]);
    }
    structured.extend_from_slice(data);
    qeli_core::protocol::obfs::fuzz_websocket_frames(&structured);
});
