use super::*;
use crate::transport_core::udp_client_framing::UdpClientFraming;

/// Actual Linux EMSGSIZE on a connected carrier, including a successfully sent
/// prefix record. Run only with lo MTU1280 in a private network namespace.
#[tokio::test]
#[ignore = "requires private Linux netns, lo MTU1280, QELI_AUTO_UDP_MTU_FIXTURE=1"]
async fn auto_udp_emsgsize_preserves_socket_records_and_batch_prefix() {
    assert_eq!(
        std::env::var("QELI_AUTO_UDP_MTU_FIXTURE").as_deref(),
        Ok("1")
    );
    // Exercise the same precise-prefix path used by Windows/Apple backends.
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(b.local_addr().unwrap()).await.unwrap();
    let sender = crate::protocol::obfs::ObfsUdp::new(a, None);
    assert!(begin_mtu_probe(&sender));
    let mut batch = vec![vec![1; 20], vec![2; 1472]];
    let error = flush_client_udp_datagrams_portable(&mut batch, &sender)
        .await
        .unwrap_err();
    assert_eq!(error.sent, 1);
    assert_eq!(error.datagram_bytes, 1472);
    assert!(udp_message_too_large(&error.error));
    let mut small = [0; 32];
    assert_eq!(b.recv(&mut small).await.unwrap(), 20);
    let mut framings = vec![
        UdpClientFraming::legacy(false, [0; 4]),
        UdpClientFraming::legacy(true, [1; 4]),
    ];
    #[cfg(feature = "experimental-roaming")]
    framings.push(UdpClientFraming::roaming([2; 8], [2; 8]));
    for framing in framings {
        for keyed in [false, true] {
            let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            a.connect(b.local_addr().unwrap()).await.unwrap();
            b.connect(a.local_addr().unwrap()).await.unwrap();
            let key = keyed.then(|| crate::protocol::obfs::derive_obfs_key("auto-pmtu-fixture"));
            let sender = crate::protocol::obfs::ObfsUdp::new(a, key);
            let receiver = crate::protocol::obfs::ObfsUdp::new(b, key);
            let original_addr = sender.raw_socket().local_addr().unwrap();
            assert!(begin_mtu_probe(&sender));
            let cfg = crate::config::client::ClientConfig::from_ini(
                &crate::config::format::IniDoc::parse("[qeli]\nserver=h:443\nbind_static=false\n")
                    .unwrap(),
            )
            .unwrap();
            let mut tx = PacketCodec::new([3; 32]);
            let mut rx = PacketCodec::new([3; 32]);
            let frag_key = [4; 32];
            let payloads = vec![
                vec![0x45; 48],
                vec![0x46; 1360],
                vec![0x47; 4096],
                vec![0x48; 83],
            ];
            let mut budget = crate::protocol::data_frag::unfragmented_record_budget_with_wrapper(
                1472,
                sender.seal_overhead(),
                framing.wrapper_len(),
            )
            .unwrap();
            let mut record_id = 1;
            let mut pn = 0;
            let mut wire = vec![];
            let mut carrier = vec![];
            let mut padding = vec![];
            let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(
                crate::transport_core::udp_batch::MAX_BATCH,
            );
            let counters = crate::transport_core::udp_buffer::UdpPathCounters::default();
            assert_eq!(
                send_client_udp_payloads(
                    &payloads,
                    &mut tx,
                    &cfg.obfuscation,
                    1400,
                    &mut budget,
                    None,
                    true,
                    &frag_key,
                    &mut record_id,
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
            assert_eq!(sender.raw_socket().local_addr().unwrap(), original_addr);
            assert_eq!(
                budget + sender.seal_overhead() + framing.wrapper_len(),
                1252
            );
            assert_eq!(counters.snapshot().path.udp_payload_budget, 1252);
            assert_eq!(
                counters.snapshot().path.fallback_reason,
                Some("local_emsgsize")
            );
            let mut fragments = crate::protocol::data_frag::DataReassembler::new();
            let mut got = Vec::new();
            let mut data = vec![0; 65536];
            while got.len() < payloads.len() {
                let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut data))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n + receiver.seal_overhead() <= 1252);
                let record = framing.unwrap(&data[..n]).unwrap();
                let record = if crate::protocol::data_frag::is_data_fragment(record) {
                    fragments.push(record, &frag_key).unwrap()
                } else {
                    Some(record.to_vec())
                };
                if let Some(record) = record {
                    got.push(
                        rx.decrypt_packet(&record)
                            .expect("accepted prefix must not be replayed"),
                    );
                }
            }
            assert_eq!(got, payloads);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), receiver.recv(&mut data))
                    .await
                    .is_err()
            );
            // Subsequent control and full records use the same reduced socket.
            let control = vec![0x49; 1400];
            tx.encrypt_packet_into(&control, &[], &mut wire).unwrap();
            send_client_udp_record(
                &wire,
                &mut budget,
                None,
                &frag_key,
                &mut record_id,
                &sender,
                framing,
                &mut pn,
                &mut carrier,
                &mut scratch,
                &counters,
            )
            .await
            .unwrap();
            assert_eq!(sender.raw_socket().local_addr().unwrap(), original_addr);
        }
    }
}

#[test]
fn size_failure_is_not_a_carrier_failure() {
    let code = if cfg!(target_os = "windows") {
        10040
    } else {
        libc::EMSGSIZE
    };
    assert_eq!(
        client_udp_send_failure(&std::io::Error::from_raw_os_error(code)),
        ClientUdpPayloadSendOutcome::MtuFailed
    );
    assert_eq!(
        client_udp_send_failure(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ClientUdpPayloadSendOutcome::CarrierFailed
    );
}
