#![no_main]
//! Exercise both client INI entry points with arbitrary untrusted text. Imported
//! profiles and qeli:// conversions eventually reach these parsers; malformed
//! input must return an error, never panic or loop.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = qeli_core::config::parse_client_config(&text);
    let _ = qeli_core::config::parse_client_config_strict(&text);
    let _ = qeli_core::config::share::ClientLink::from_uri(&text);
});
