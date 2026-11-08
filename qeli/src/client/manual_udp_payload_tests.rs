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
                let record_budget = unfragmented_record_budget_with_wrapper(
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
                        &[payload.clone()],
                        &mut tx,
                        &config.obfuscation,
                        payload_budget,
                        record_budget,
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
