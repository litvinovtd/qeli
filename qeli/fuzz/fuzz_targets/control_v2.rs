#![no_main]
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::{control_v2::*, ctrl};
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    let _ = ctrl::parse(data);
    let _ = ctrl::parse_client_info(data);
    let _ = decode(data);
    let mut generic = Reassembler::new();
    let mut management = Reassembler::new();
    let mut now = Instant::now();
    // Bounded stateful actions include valid, conflicting and expired fragments.
    for action in data.chunks(16).take(128) {
        if action.len() < 8 {
            break;
        }
        now += Duration::from_millis(u16::from_be_bytes([action[6], action[7]]) as u64);
        let id = (action[0] % 12) as u32;
        let payload: &[u8] = if action[1] & 1 == 0 {
            br#"{"reason":"administrative","message":"Stopped","reconnect_allowed":false}"#
        } else {
            &action[8..]
        };
        let frame = Frame {
            message_type: if action[2] & 1 == 0 {
                TYPE_KICK
            } else {
                action[2]
            },
            flags: action[3],
            message_id: id,
            part_index: (action[4] % 18) as u16,
            part_count: (action[5] % 18) as u16,
            payload,
        };
        if let Ok(wire) = frame.encode() {
            let decoded = decode(&wire).unwrap();
            assert_eq!(decoded, frame);
            if let Ok(ReassemblyOutcome::Complete(message)) = generic.push(now, decoded) {
                assert!(message.payload.len() <= MAX_MESSAGE_SIZE);
            }
            if let Ok(ReassemblyOutcome::Complete(message)) =
                management.push_management(now, decoded)
            {
                assert!(decode_management(&message).unwrap().is_some());
            }
        }
        generic.expire(now);
        management.expire(now);
    }
    // Refusals must leave room for a fresh valid management ID.
    let kick = ManagementEvent::Kick(Kick {
        reason: KickReason::Administrative,
        message: "Stopped".into(),
        reconnect_allowed: false,
    });
    let wire = management_frames(&kick, u32::MAX).unwrap().remove(0);
    assert!(matches!(
        management
            .push_management(now, decode(&wire).unwrap())
            .unwrap(),
        ReassemblyOutcome::Complete(_)
    ));
    assert_eq!(
        management
            .push_management(now, decode(&wire).unwrap())
            .unwrap(),
        ReassemblyOutcome::Duplicate
    );
});
