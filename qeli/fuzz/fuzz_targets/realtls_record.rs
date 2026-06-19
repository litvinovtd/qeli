#![no_main]
//! Fuzz the hand-rolled realtls TLS-record decrypt path on arbitrary bytes. This
//! is part of the largest unaudited surface (see docs/eng/THREAT-MODEL.md). The
//! key/IV are fixed — the AEAD will reject random data, so what we are stressing
//! is the record-length and bounds handling that runs *before* the tag check.
//! decrypt must return None (or empty) on malformed input, never panic.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::realtls::record::RecordCrypto;

fuzz_target!(|data: &[u8]| {
    let mut rc = RecordCrypto::new(&[0x11u8; 16], &[0x22u8; 12]);
    let _ = rc.decrypt(data);
});
