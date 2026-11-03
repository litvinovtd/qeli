#![no_main]
//! Arbitrary datagrams plus authenticated state transitions with exact-result oracles.
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::data_frag::{
    fragment_record, is_data_fragment, DataFragError, DataReassembler, MAX_REASSEMBLY_RECORDS,
};

const MAX_GENERATED_RECORD: usize = 16 * 1024;

fn complete(
    r: &mut DataReassembler,
    fragments: &[Vec<u8>],
    key: &[u8; 32],
    record: &[u8],
    reverse: bool,
) {
    for position in 0..fragments.len() {
        let index = if reverse {
            fragments.len() - 1 - position
        } else {
            position
        };
        let result = r.push(&fragments[index], key).unwrap();
        if position + 1 == fragments.len() {
            assert_eq!(result.as_deref(), Some(record));
        } else {
            assert_eq!(result, None);
            assert_eq!(r.push(&fragments[index], key).unwrap(), None);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    let _ = is_data_fragment(data);
    let mut raw = DataReassembler::new();
    let _ = raw.push(data, &key);
    let _ = raw.push(data, &key);
    if data.len() < 3 {
        return;
    }
    let selector = usize::from(data[0]);
    let record = &data[1..data.len().min(MAX_GENERATED_RECORD + 1)];
    let minimum_payload = record.len().div_ceil(64).max(1);
    let max_payload = minimum_payload + selector % (record.len() - minimum_payload);
    let fragments = fragment_record(record, &key, 7, max_payload).unwrap();
    let mut reordered = DataReassembler::new();
    complete(&mut reordered, &fragments, &key, record, selector & 1 == 0);
    // Completion must release the record ID and accounting for another full record.
    complete(&mut reordered, &fragments, &key, record, selector & 1 != 0);

    // Mutate a byte IN the first fragment, then authenticate it correctly.
    let mut changed = record.to_vec();
    changed[selector % max_payload] ^= 0x80;
    let conflicting = fragment_record(&changed, &key, 7, max_payload).unwrap();
    let mut conflict = DataReassembler::new();
    assert_eq!(conflict.push(&fragments[0], &key).unwrap(), None);
    assert_eq!(
        conflict.push(&conflicting[0], &key),
        Err(DataFragError::Conflict)
    );
    complete(&mut conflict, &conflicting, &key, &changed, false);

    // A forged payload must be rejected without poisoning an authenticated partial.
    let mut corrupt = fragments[0].clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut authenticated = DataReassembler::new();
    assert_eq!(authenticated.push(&fragments[0], &key).unwrap(), None);
    assert_eq!(
        authenticated.push(&corrupt, &key),
        Err(DataFragError::Authentication)
    );
    complete(&mut authenticated, &fragments, &key, record, false);

    if selector & 31 == 0 {
        // Fill both public limits: 32 partials * 16 KiB = 512 KiB.
        let pressure = vec![data[1]; 16 * 1024 + 1];
        let mut limited = DataReassembler::new();
        let pending: Vec<_> = (0..MAX_REASSEMBLY_RECORDS as u64)
            .map(|id| fragment_record(&pressure, &key, id, 16 * 1024).unwrap())
            .collect();
        for parts in &pending {
            assert_eq!(limited.push(&parts[0], &key).unwrap(), None);
        }
        let excess = fragment_record(&pressure, &key, u64::MAX, 16 * 1024).unwrap();
        assert_eq!(
            limited.push(&excess[0], &key),
            Err(DataFragError::ResourceLimit)
        );
        // Exceeding the byte cap drops this partial, releasing one slot and its bytes.
        assert_eq!(
            limited.push(&pending[0][1], &key),
            Err(DataFragError::ResourceLimit)
        );
        for parts in pending.iter().skip(1) {
            assert_eq!(
                limited.push(&parts[1], &key).unwrap().as_deref(),
                Some(pressure.as_slice())
            );
        }
        complete(&mut limited, &excess, &key, &pressure, false);
    }
});
