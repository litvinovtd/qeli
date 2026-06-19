#![no_main]
//! Fuzz the fake-TLS / REALITY ClientHello parsers — the server's first contact
//! with fully attacker-controlled bytes from a hostile network. None of these
//! must panic, over-read, or hang on any input.
use libfuzzer_sys::fuzz_target;
use qeli::protocol::FakeTlsHandshake;

fuzz_target!(|data: &[u8]| {
    // Plain ClientHello key-share extraction.
    let _ = FakeTlsHandshake::parse_client_hello(data);
    // REALITY path: session_id + x25519 key_share recovery.
    let _ = FakeTlsHandshake::parse_client_hello_full(data);
    // Hybrid PQ path: the X25519MLKEM768 encapsulation key.
    let _ = FakeTlsHandshake::extract_client_mlkem_ek(data);
});
