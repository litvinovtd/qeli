#![no_main]
//! Exercise the bounded IPv4/IPv6 parser on arbitrary inner packets. In addition to
//! version and length validation this reaches IPv4 options/fragmentation and bounded
//! IPv6 extension/fragment chains. Successful parses also exercise the guarded L4
//! port lookup, which must never index beyond the original record.
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::ip::parse_ip_packet;

fuzz_target!(|data: &[u8]| {
    if let Ok(meta) = parse_ip_packet(data) {
        let _ = meta.ports(data);
    }
});
