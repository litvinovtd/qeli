// Additional Q21 properties, compiled against the actual reviewed production modules.
#[cfg(test)]
mod audit_boundaries {
    use crate::protocol::{data_frag::*, icmp, ip};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    const KEY: [u8; 32] = [0x42; 32];

    fn retag(packet: &mut [u8]) {
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(&packet[..28]); mac.update(&packet[44..]);
        let tag = mac.finalize().into_bytes(); packet[28..44].copy_from_slice(&tag[..16]);
    }

    #[test]
    fn record_count_limit_rejects_then_recovers_after_completion() {
        let mut receiver = DataReassembler::new();
        let mut sets = Vec::new();
        for id in 0..MAX_REASSEMBLY_RECORDS as u64 {
            let fragments = fragment_record(&vec![7; 1000], &KEY, id, 500).unwrap();
            assert_eq!(receiver.push(&fragments[0], &KEY), Ok(None)); sets.push(fragments);
        }
        let extra = fragment_record(&vec![8; 1000], &KEY, 100, 500).unwrap();
        assert_eq!(receiver.push(&extra[0], &KEY), Err(DataFragError::ResourceLimit));
        assert_eq!(receiver.push(&sets[0][1], &KEY), Ok(Some(vec![7; 1000])));
        assert_eq!(receiver.push(&extra[0], &KEY), Ok(None));
        assert_eq!(receiver.push(&extra[1], &KEY), Ok(Some(vec![8; 1000])));
    }

    #[test]
    fn byte_budget_is_bounded_and_failed_record_releases_its_charge() {
        assert_eq!(MAX_REASSEMBLY_BYTES, 32 * 16_384);
        let mut receiver = DataReassembler::new(); let mut sets = Vec::new();
        for id in 0..32 {
            let fragments = fragment_record(&vec![9; MAX_REASSEMBLED_RECORD], &KEY, id, 16_384).unwrap();
            assert_eq!(receiver.push(&fragments[0], &KEY), Ok(None)); sets.push(fragments);
        }
        assert_eq!(receiver.push(&sets[0][1], &KEY), Err(DataFragError::ResourceLimit));
        let small = fragment_record(&vec![1; 1000], &KEY, 100, 500).unwrap();
        assert_eq!(receiver.push(&small[0], &KEY), Ok(None));
        assert_eq!(receiver.push(&small[1], &KEY), Ok(Some(vec![1; 1000])));
    }

    #[test]
    fn authenticated_overlap_gap_and_id_reuse_never_mix_records() {
        let mut receiver = DataReassembler::new();
        let mut overlap = fragment_record(&vec![1; 1000], &KEY, 1, 500).unwrap();
        overlap[1][14..18].copy_from_slice(&400u32.to_le_bytes()); retag(&mut overlap[1]);
        assert_eq!(receiver.push(&overlap[0], &KEY), Ok(None));
        assert_eq!(receiver.push(&overlap[1], &KEY), Err(DataFragError::Conflict));
        let mut gap = fragment_record(&vec![2; 1000], &KEY, 1, 500).unwrap();
        for packet in &mut gap { packet[18..22].copy_from_slice(&1001u32.to_le_bytes()); retag(packet); }
        gap[1][14..18].copy_from_slice(&501u32.to_le_bytes()); retag(&mut gap[1]);
        assert_eq!(receiver.push(&gap[0], &KEY), Ok(None));
        assert_eq!(receiver.push(&gap[1], &KEY), Err(DataFragError::Conflict));
        for value in [3, 4] {
            let valid = fragment_record(&vec![value; 1000], &KEY, 1, 500).unwrap();
            assert_eq!(receiver.push(&valid[0], &KEY), Ok(None));
            assert_eq!(receiver.push(&valid[1], &KEY), Ok(Some(vec![value; 1000])));
        }
        // Record-id reuse itself is legal; PacketCodec's AEAD replay check remains mandatory.
    }

    #[test]
    fn corrupt_tags_never_consume_reassembly_slots() {
        let mut receiver = DataReassembler::new();
        for id in 0..1000 {
            let mut bad = fragment_record(&vec![3; 1000], &KEY, id, 500).unwrap().remove(0);
            bad[28] ^= 1;
            assert_eq!(receiver.push(&bad, &KEY), Err(DataFragError::Authentication));
        }
        for id in 0..MAX_REASSEMBLY_RECORDS as u64 {
            let fragment = fragment_record(&vec![5; 1000], &KEY, id, 500).unwrap();
            assert_eq!(receiver.push(&fragment[0], &KEY), Ok(None));
        }
    }

    #[test]
    fn maximum_record_and_fragment_count_have_exact_boundaries() {
        let maximum = vec![0xaa; MAX_REASSEMBLED_RECORD];
        let chunks = maximum.len().div_ceil(MAX_FRAGMENTS as usize);
        let fragments = fragment_record(&maximum, &KEY, 1, chunks).unwrap();
        let mut receiver = DataReassembler::new(); let mut result = None;
        for fragment in fragments.iter().rev() { if let Some(packet) = receiver.push(fragment, &KEY).unwrap() { result = Some(packet); } }
        assert_eq!(result, Some(maximum));
        assert_eq!(fragment_record(&vec![0; MAX_REASSEMBLED_RECORD+1], &KEY, 2, chunks), Err(DataFragError::RecordTooLarge));
        assert_eq!(fragment_record(&vec![0; 65], &KEY, 2, 1), Err(DataFragError::TooManyFragments));
        assert_eq!(fragment_record(&vec![0; 64], &KEY, 2, 1).unwrap().len(), 64);
    }

    #[test]
    fn deterministic_untrusted_packet_corpus_stays_bounded() {
        let mut seed = 0x71656c69u64;
        for size in 0..512 {
            for version in 0..16 {
                let mut packet = vec![0u8; size];
                for byte in &mut packet { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; *byte = seed as u8; }
                if size != 0 { packet[0] = (packet[0] & 15) | (version << 4); }
                if let Ok(meta) = ip::parse_ip_packet(&packet) {
                    assert_eq!(meta.packet_len, packet.len());
                    if let Some(offset) = meta.l4_offset { assert!(offset <= packet.len()); }
                    let _ = meta.ports(&packet);
                }
                let _ = icmp::packet_too_big_v6(&packet, "fd86::1".parse().unwrap(), 1280);
                let mut ethernet = vec![0; 14]; ethernet.extend_from_slice(&packet);
                let _ = crate::tap::strip_ethernet_header(&ethernet);
            }
        }
    }

    #[test]
    fn ipv4_fragment_sweep_preserves_payload_offsets_and_mtu() {
        for size in [65, 577, 1281, 1501, 16_000, 65_535] {
            for mtu in [68, 576, 1280, 1400] {
                if size <= mtu { continue; }
                let mut packet = vec![0x71; size]; packet[..20].fill(0); packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(size as u16).to_be_bytes()); packet[4..6].copy_from_slice(&7u16.to_be_bytes());
                packet[8] = 64; packet[9] = 17; packet[12..16].copy_from_slice(&[10, 9, 0, 2]); packet[16..20].copy_from_slice(&[10, 9, 0, 1]);
                let fragments = icmp::fragment_ipv4(&packet, mtu).unwrap(); let mut payload = Vec::new();
                for (index, fragment) in fragments.iter().enumerate() {
                    assert!(fragment.len() <= mtu); let meta = ip::parse_ip_packet(fragment).unwrap();
                    let info = meta.fragment.unwrap(); assert_eq!(info.id, 7); assert_eq!(info.offset as usize * 8, payload.len());
                    assert_eq!(info.more, index+1 != fragments.len()); payload.extend_from_slice(&fragment[20..]);
                }
                assert_eq!(payload, packet[20..]);
            }
        }
    }
}
