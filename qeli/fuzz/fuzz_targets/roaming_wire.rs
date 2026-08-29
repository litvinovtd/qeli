#![no_main]
//! Fuzz the roaming wire contracts on arbitrary bytes and drive canonical UDP locator,
//! TCP resume-proof, and PATH_* control round trips from the same input.

use libfuzzer_sys::fuzz_target;
use qeli::protocol::roaming::{
    decode_udp_short, derive_udp_cid, PathControl, ResumeProofInput, TcpResumeJoin, UdpShortHeader,
    PATH_CHALLENGE_LEN, RESUME_PROOF_LEN, SESSION_LOCATOR_LEN, TCP_RESUME_JOIN_LEN,
};

const MAX_PAYLOAD: usize = 64 * 1024;

fn material<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let input = if data.is_empty() {
            0
        } else {
            data[(offset + index) % data.len()]
        };
        *byte = input ^ (index as u8).wrapping_mul(31);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // Every network-facing decoder must reject arbitrary bytes without panicking or over-reading.
    let _ = decode_udp_short(data);
    let _ = TcpResumeJoin::decode(data);
    let message_type = data.first().copied().unwrap_or_default();
    let body = data.get(1..).unwrap_or_default();
    let _ = PathControl::decode(message_type, body);

    let secret = material::<32>(data, 1);
    let session_id = u64::from_be_bytes(material::<8>(data, 9));
    let epoch = u64::from_be_bytes(material::<8>(data, 17));
    let cid = derive_udp_cid(&secret, session_id, epoch);
    let packet_number = u32::from_be_bytes(material::<4>(data, 25));
    let header = UdpShortHeader::new(cid, packet_number);
    let payload = &data[..data.len().min(MAX_PAYLOAD)];
    let encoded = header.encode(payload);
    let (decoded_header, decoded_payload) =
        decode_udp_short(&encoded).expect("canonical UDP roaming header must decode");
    assert_eq!(decoded_header.destination_cid(), &cid);
    assert_eq!(decoded_header.packet_number(), packet_number);
    assert_eq!(decoded_payload, payload);

    let transcript = material::<32>(data, 33);
    let locator = material::<SESSION_LOCATOR_LEN>(data, 65);
    let slot = u32::from_be_bytes(material::<4>(data, 81));
    let handover = message_type & 1 != 0;
    let input = ResumeProofInput::new(transcript, locator, epoch, slot, handover);
    let join = TcpResumeJoin::new(input, &secret);
    let mut join_wire = join.encode();
    let decoded_join =
        TcpResumeJoin::decode(&join_wire).expect("canonical TCP resume JOIN must decode");
    assert!(decoded_join.verify(&secret));
    assert!(decoded_join.matches_transcript(&transcript));
    assert_eq!(decoded_join.input().session_locator(), &locator);
    assert_eq!(decoded_join.input().resume_epoch(), epoch);
    assert_eq!(decoded_join.input().logical_slot_id(), slot);
    assert_eq!(decoded_join.input().is_handover(), handover);

    // A one-byte proof mutation must remain parseable but lose resume authority.
    let proof_offset = TCP_RESUME_JOIN_LEN - RESUME_PROOF_LEN;
    join_wire[proof_offset] ^= 0x80;
    let tampered = TcpResumeJoin::decode(&join_wire).expect("proof mutation must preserve framing");
    assert!(!tampered.verify(&secret));

    let token = material::<PATH_CHALLENGE_LEN>(data, 85);
    let control = match message_type % 5 {
        0 => PathControl::Init { cid, epoch },
        1 => PathControl::Challenge { epoch, token },
        2 => PathControl::Response { epoch, token },
        3 => PathControl::Commit { cid, epoch },
        _ => PathControl::Abort {
            epoch,
            code: u16::from_be_bytes(material::<2>(data, 101)),
        },
    };
    let control_type = control.message_type();
    let control_body = control.encode_body();
    let decoded_control = PathControl::decode(control_type, &control_body)
        .expect("canonical PATH control body must decode");
    assert!(decoded_control == control);
});
