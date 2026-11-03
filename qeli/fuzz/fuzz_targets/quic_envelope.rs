#![no_main]
//! Arbitrary and structured mutations of the shared camouflage envelope.
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::quic::{
    looks_like_quic_initial, unwrap_quic, wrap_quic_long, wrap_quic_short,
};
fuzz_target!(|data: &[u8]| {
    let _ = unwrap_quic(data);
    let _ = looks_like_quic_initial(data);
    for mut packet in [
        wrap_quic_long(data, &[1, 2, 3, 4], 7),
        wrap_quic_short(data, &[1, 2, 3, 4], 7),
    ] {
        let parsed = unwrap_quic(&packet).expect("own envelope");
        assert_eq!(parsed.payload, data);
        if let Some(&offset) = data.first() {
            let index = usize::from(offset) % packet.len();
            packet[index] ^= data.last().copied().unwrap_or(0);
        }
        let _ = unwrap_quic(&packet);
    }
});
