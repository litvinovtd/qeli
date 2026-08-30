#![no_main]
//! Fuzz the authenticated UDP data-record fragment parser and bounded reassembler.
//! Arbitrary bytes exercise the reject path; derived, correctly authenticated fragments
//! drive reorder, duplicate, completion, and conflicting-record state transitions.

use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::data_frag::{fragment_record, is_data_fragment, DataReassembler};

const MAX_GENERATED_RECORD: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];

    // Fully attacker-controlled datagrams must be rejected without allocation blow-up,
    // panic, or a state transition that makes a duplicate unsafe.
    let _ = is_data_fragment(data);
    let mut raw = DataReassembler::new();
    let _ = raw.push(data, &key);
    let _ = raw.push(data, &key);

    if data.len() < 3 {
        return;
    }
    let selector = usize::from(data[0]);
    let record = &data[1..data.len().min(MAX_GENERATED_RECORD + 1)];
    if record.len() < 2 {
        return;
    }

    // Always choose a payload size that yields 2..=64 fragments, so valid stateful paths
    // receive sustained coverage instead of almost every generated case failing at HMAC.
    let minimum_payload = record.len().div_ceil(64).max(1);
    let payload_span = record.len() - minimum_payload;
    let max_payload = minimum_payload + selector % payload_span;
    let Ok(fragments) = fragment_record(record, &key, 7, max_payload) else {
        return;
    };

    let mut reordered = DataReassembler::new();
    if selector & 1 == 0 {
        for fragment in fragments.iter().rev() {
            let _ = reordered.push(fragment, &key);
        }
    } else {
        for fragment in &fragments {
            let _ = reordered.push(fragment, &key);
            let _ = reordered.push(fragment, &key);
        }
    }

    // Same authenticated metadata with different bytes must enter the conflict path and
    // discard the partial record rather than combine two records under one record id.
    let mut changed = record.to_vec();
    let changed_index = selector % changed.len();
    changed[changed_index] ^= 0x80;
    if let Ok(conflicting) = fragment_record(&changed, &key, 7, max_payload) {
        let mut conflict = DataReassembler::new();
        let _ = conflict.push(&fragments[0], &key);
        let _ = conflict.push(&conflicting[0], &key);
    }
});
