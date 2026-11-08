use super::*;
use crate::config::client::ClientConfig;
use crate::protocol::data_frag::{
    is_data_fragment, unfragmented_record_budget_with_wrapper, DataReassembler,
};
use crate::transport_core::udp_client_framing::UdpClientFraming;

/// Exercise the production sender, encryption, DATA_FRAG and carrier wrappers over
/// loopback sockets. No TUN, routes, DNS, or active PMTU probe is involved.
#[tokio::test]
async fn manual_udp_payload_bounds_actual_data_and_control_datagrams() {
    let mut framings = vec![
        UdpClientFraming::legacy(false, [0; 4]),
        UdpClientFraming::legacy(true, [1; 4]),
    ];
    #[cfg(feature = "experimental-roaming")]
    framings.push(UdpClientFraming::roaming([2; 8], [2; 8]));
    for limit in [548, 1232, 1472] {
        for framing in &framings {
            for obfs_key in [
                None,
                Some(crate::protocol::obfs::derive_obfs_key(
                    "manual-limit-fixture",
                )),
            ] {
                let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                a.connect(b.local_addr().unwrap()).await.unwrap();
                b.connect(a.local_addr().unwrap()).await.unwrap();
                let sender = crate::protocol::obfs::ObfsUdp::new(a, obfs_key);
                let receiver = crate::protocol::obfs::ObfsUdp::new(b, obfs_key);
                let mut record_budget = unfragmented_record_budget_with_wrapper(
                    limit,
                    sender.seal_overhead(),
                    framing.wrapper_len(),
                )
                .unwrap();
                let mut tx = PacketCodec::new([3; 32]);
                let mut rx = PacketCodec::new([3; 32]);
                let payload_budget = tx.max_data_for_record_budget(record_budget).unwrap();
                let frag_key = [4; 32];
                let mut record_id = 0;
                let mut pn = 0;
                let mut wire = Vec::new();
                let mut carrier = Vec::new();
                let mut padding = Vec::new();
                let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(
                    crate::transport_core::udp_batch::MAX_BATCH,
                );
                let counters = crate::transport_core::udp_buffer::UdpPathCounters::default();
                let config = ClientConfig::from_ini(&crate::config::format::IniDoc::parse(
                    "[qeli]\nserver=localhost:443\nproto=udp\nbind_static=false\npadding=true\npadding_min=0\npadding_max=400\n"
                ).unwrap()).unwrap();
                // Include metadata and small/large records. All must use the same bound.
                for payload in [
                    crate::protocol::ctrl::udp_manual_payload(limit as u16),
                    vec![0x45; 80],
                    vec![0x45; 4096],
                ] {
                    let outcome = send_client_udp_payloads(
                        std::slice::from_ref(&payload),
                        &mut tx,
                        &config.obfuscation,
                        payload_budget,
                        &mut record_budget,
                        Some(limit),
                        true,
                        &frag_key,
                        &mut record_id,
                        &sender,
                        *framing,
                        &mut pn,
                        &mut wire,
                        &mut carrier,
                        &mut padding,
                        &mut scratch,
                        &counters,
                    )
                    .await;
                    assert_eq!(outcome, ClientUdpPayloadSendOutcome::Sent);
                    let mut reassembler = DataReassembler::new();
                    let mut buf = vec![0; 65536];
                    loop {
                        let raw_len = tokio::time::timeout(
                            Duration::from_secs(2),
                            receiver.raw_socket().peek(&mut buf),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert!(
                            raw_len <= limit,
                            "wire payload {raw_len} exceeds manual limit {limit}"
                        );
                        let n = receiver.recv(&mut buf).await.unwrap();
                        let record = framing.unwrap(&buf[..n]).unwrap();
                        let assembled = if is_data_fragment(record) {
                            reassembler.push(record, &frag_key).unwrap()
                        } else {
                            Some(record.to_vec())
                        };
                        if let Some(record) = assembled {
                            assert_eq!(rx.decrypt_packet(&record).unwrap(), payload);
                            break;
                        }
                    }
                }
                let mut extra = [0; 2048];
                assert!(
                    tokio::time::timeout(Duration::from_millis(5), receiver.recv(&mut extra))
                        .await
                        .is_err(),
                    "no extra probe datagrams"
                );
            }
        }
    }
}

/// Run in an isolated namespace with QELI_MANUAL_UDP_MTU_FIXTURE=1 and lo MTU=1280.
/// Uses actual kernel EMSGSIZE, production codecs and both recordizer policies.
#[tokio::test]
#[ignore = "requires isolated Linux network namespace with lo MTU 1280"]
async fn manual_udp_emsgsize_retries_without_carrier_replacement() {
    assert_eq!(
        std::env::var("QELI_MANUAL_UDP_MTU_FIXTURE").as_deref(),
        Ok("1")
    );
    use crate::protocol::data_frag::{is_data_fragment, DataReassembler};
    for recordized in [false, true] {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        let sender = crate::protocol::obfs::ObfsUdp::new(a, None);
        let receiver = crate::protocol::obfs::ObfsUdp::new(b, None);
        assert!(begin_mtu_probe(&sender));
        let framing = UdpClientFraming::legacy(false, [0; 4]);
        let mut tx = PacketCodec::new([8; 32]);
        let mut rx = PacketCodec::new([8; 32]);
        let config = ClientConfig::from_ini(
            &crate::config::format::IniDoc::parse("[qeli]\nserver=h:443\nbind_static=false\n")
                .unwrap(),
        )
        .unwrap();
        let original = vec![0x45; 4096];
        let payloads = if recordized {
            let mut mux = crate::protocol::recordizer::Recordizer::new(
                crate::protocol::recordizer::RuntimeConfig::from_config(
                    &crate::config::RecordizerConfig::default(),
                    1400,
                    crate::protocol::packet::MAX_TUNNEL_MTU,
                )
                .unwrap(),
            );
            prepare_client_udp_control_payloads(&original, Some(&mut mux)).unwrap()
        } else {
            vec![original.clone()]
        };
        let mut budget = 1472;
        let mut id = 0;
        let mut pn = 0;
        let mut wire = Vec::new();
        let mut carrier = Vec::new();
        let mut padding = Vec::new();
        let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(
            crate::transport_core::udp_batch::MAX_BATCH,
        );
        let counters = crate::transport_core::udp_buffer::UdpPathCounters::default();
        assert_eq!(
            send_client_udp_payloads(
                &payloads,
                &mut tx,
                &config.obfuscation,
                1400,
                &mut budget,
                Some(1472),
                true,
                &[9; 32],
                &mut id,
                &sender,
                framing,
                &mut pn,
                &mut wire,
                &mut carrier,
                &mut padding,
                &mut scratch,
                &counters
            )
            .await,
            ClientUdpPayloadSendOutcome::Sent
        );
        assert_eq!(budget, 548);
        assert_eq!(
            counters.snapshot().path.fallback_reason,
            Some("local_emsgsize")
        );
        let mut fragments = DataReassembler::new();
        let mut got = Vec::new();
        let mut data = vec![0; 65536];
        let mut saw_retry = false;
        let mut received_sizes = Vec::new();
        while got.len() < payloads.len() {
            let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut data))
                .await
                .unwrap()
                .unwrap();
            assert!(n <= 1472, "configured ceiling always applies");
            received_sizes.push(n);
            let record = framing.unwrap(&data[..n]).unwrap();
            if is_data_fragment(record) {
                // ID 0 belongs to the initial attempt. A partial batch or an
                // earlier Recordizer record may already have been accepted
                // before the kernel reports EMSGSIZE. The retry uses ID 1;
                // every later record must keep the lowered budget as well.
                let record_id = u64::from_le_bytes(record[6..14].try_into().unwrap());
                saw_retry |= record_id >= 1;
            }
            if saw_retry {
                assert!(n <= 548, "retry and subsequent datagrams use the floor");
            }
            let record = if is_data_fragment(record) {
                fragments.push(record, &[9; 32]).unwrap()
            } else {
                Some(record.to_vec())
            };
            if let Some(record) = record {
                got.push(rx.decrypt_packet(&record).unwrap());
            }
        }
        assert_eq!(got, payloads);
        assert!(
            saw_retry,
            "complete record retried with a fresh fragment ID"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), receiver.recv(&mut data))
                .await
                .is_err(),
            "no extra probes or duplicate complete records"
        );
        eprintln!("recordizer={recordized}, effective={budget}, received={received_sizes:?}");
    }
}
