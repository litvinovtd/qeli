use super::*;
use crate::transport_core::udp_client_framing::UdpClientFraming;

/// Exercise real DF datagrams and connected-socket IP_MTU without changing
/// the host network. The loopback link stays at 1500 throughout the fixture.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires private Linux netns, lo up at MTU 1500, QELI_LIVE_PMTU_FIXTURE=1"]
async fn live_pmtu_ceiling_survives_kernel_route_refresh() {
    assert_eq!(std::env::var("QELI_LIVE_PMTU_FIXTURE").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
    );
    let link = std::process::Command::new("ip")
        .args(["-o", "link", "show", "dev", "lo"])
        .output()
        .unwrap();
    assert!(link.status.success());
    assert!(String::from_utf8(link.stdout)
        .unwrap()
        .contains(" mtu 1500 "));

    fn set_route_mtu(mtu: &str) {
        assert!(std::process::Command::new("ip")
            .args([
                "route",
                "replace",
                "local",
                "127.0.0.1/32",
                "dev",
                "lo",
                "table",
                "local",
                "mtu",
                mtu,
            ])
            .status()
            .unwrap()
            .success());
    }

    async fn send_probe(
        sender: &crate::protocol::obfs::ObfsUdp,
        receiver: &crate::protocol::obfs::ObfsUdp,
        state: &mut LiveUdpMtuProbe,
        expected_budget: usize,
    ) {
        let framing = UdpClientFraming::legacy(true, [1; 4]);
        let wrapper = sender.seal_overhead() + framing.wrapper_len();
        let candidate = crate::protocol::pmtu::probe_ceiling(
            1400,
            UDP_RECORD_PROBE_OVERHEAD + wrapper + 28,
            state.observe_socket_mtu(sender),
        );
        let record_size = candidate as usize + UDP_RECORD_PROBE_OVERHEAD;
        let probe = crate::protocol::udp_frag::mtu_probe_v2_datagram(7, record_size).unwrap();
        let mut wire = Vec::new();
        let datagram = framing.wrap_into(&probe, 0, &mut wire);
        assert!(begin_mtu_probe(sender));
        assert_eq!(sender.send(datagram).await.unwrap(), expected_budget);
        let mut received = [0; 1600];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(n + receiver.seal_overhead(), expected_budget);
        assert_eq!(
            crate::protocol::udp_frag::parse_mtu_probe_v2_request(
                framing.unwrap(&received[..n]).unwrap()
            ),
            Some((7, record_size as u16))
        );
    }

    let key = crate::protocol::obfs::derive_obfs_key("live-pmtu-fixture");
    let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let receiver = crate::protocol::obfs::ObfsUdp::new(listener, Some(key));
    let connected_sender = || async move {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(peer).await.unwrap();
        crate::protocol::obfs::ObfsUdp::new(socket, Some(key))
    };
    let mut state = LiveUdpMtuProbe::default();

    set_route_mtu("1480");
    let first = connected_sender().await;
    let framing = UdpClientFraming::legacy(true, [1; 4]);
    let overhead = UDP_RECORD_PROBE_OVERHEAD + first.seal_overhead() + framing.wrapper_len() + 28;
    // Start with a stale upper bound while the real socket already enforces
    // 1480. Run the production startup ladder and retain what it learns.
    let ceiling = crate::protocol::pmtu::probe_ceiling(1400, overhead, Some(1500));
    let responder = async {
        let mut bytes = [0; 1600];
        loop {
            let (len, peer) = receiver.recv_from(&mut bytes).await.unwrap();
            let Ok(record) = framing.unwrap(&bytes[..len]) else {
                continue;
            };
            let Some((token, size)) = crate::protocol::udp_frag::parse_mtu_probe_v2_request(record)
            else {
                continue;
            };
            let ack = crate::protocol::udp_frag::mtu_probe_v2_ack_datagram(token, size);
            let mut wire = Vec::new();
            receiver
                .send_to(framing.wrap_into(&ack, 0, &mut wire), peer)
                .await
                .unwrap();
        }
    };
    let mut rx = PacketCodec::new([1; 32]);
    let mut tx = PacketCodec::new([2; 32]);
    let management = std::sync::Mutex::new(crate::protocol::control_v2::Reassembler::new());
    let (management_sender, _) = tokio::sync::watch::channel(None);
    let mut pn = 0;
    let startup = probe_udp_mtu(
        &first,
        &mut state,
        framing,
        &mut pn,
        &mut rx,
        &mut tx,
        false,
        &management,
        &management_sender,
        ceiling,
        true,
    );
    let certified = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(5), startup) => {
            result.expect("startup search finished").unwrap().unwrap()
        },
        _ = responder => unreachable!("PMTU echo loop terminated"),
    };
    assert_eq!(
        udp_payload_budget_for_probe(certified, first.seal_overhead(), framing.wrapper_len()),
        1452
    );
    assert_eq!(state.path_mtu_ceiling, Some(1480));
    let original_addr = first.raw_socket().local_addr().unwrap();

    set_route_mtu("1500");
    first.raw_socket().connect(peer).await.unwrap();
    assert_eq!(first.raw_socket().local_addr().unwrap(), original_addr);
    assert_eq!(
        crate::protocol::pmtu::socket_path_mtu(first.raw_socket(), false),
        Some(1500)
    );
    send_probe(&first, &receiver, &mut state, 1452).await;

    state.reset_path();
    let second = connected_sender().await;
    send_probe(&second, &receiver, &mut state, 1472).await;

    set_route_mtu("1480");
    state.reset_path();
    let third = connected_sender().await;
    send_probe(&third, &receiver, &mut state, 1452).await;
}

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

#[cfg(target_os = "linux")]
fn inject_size_advisory(socket: &UdpSocket) {
    use socket2::{Domain, Protocol, Socket, Type};
    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let std::net::SocketAddr::V4(local) = socket.local_addr().unwrap() else {
        panic!()
    };
    let std::net::SocketAddr::V4(peer) = socket.peer_addr().unwrap() else {
        panic!()
    };
    let mut packet = [0u8; 44];
    packet[0] = 3; // ICMP destination unreachable / fragmentation needed.
    packet[1] = 4;
    packet[6..8].copy_from_slice(&1280u16.to_be_bytes());
    let ip = &mut packet[8..28];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&1500u16.to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&local.ip().octets());
    ip[16..20].copy_from_slice(&peer.ip().octets());
    let check = checksum(ip);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    packet[28..30].copy_from_slice(&local.port().to_be_bytes());
    packet[30..32].copy_from_slice(&peer.port().to_be_bytes());
    packet[32..34].copy_from_slice(&1480u16.to_be_bytes());
    let check = checksum(&packet);
    packet[2..4].copy_from_slice(&check.to_be_bytes());
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    raw.send_to(
        &packet,
        &std::net::SocketAddr::new((*local.ip()).into(), 0).into(),
    )
    .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires private Linux netns and CAP_NET_RAW, QELI_ASYNC_PMTU_FIXTURE=1"]
async fn asynchronous_pmtu_error_preserves_receive_pump_and_fitting_floor_record() {
    assert_eq!(std::env::var("QELI_ASYNC_PMTU_FIXTURE").as_deref(), Ok("1"));
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(b.local_addr().unwrap()).await.unwrap();
    b.connect(a.local_addr().unwrap()).await.unwrap();
    let socket = Arc::new(crate::protocol::obfs::ObfsUdp::new(a, None));
    assert!(begin_mtu_probe(&socket));
    // First prove this fixture produces a real pending kernel EMSGSIZE.
    inject_size_advisory(socket.raw_socket());
    let advisory = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(error) = socket2::SockRef::from(socket.raw_socket())
                .take_error()
                .unwrap()
            {
                break error;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(udp_message_too_large(&advisory), "{advisory}");

    let mut tasks = crate::transport_core::tasks::TaskGroup::default();
    let (tx, mut rx) = mpsc::channel(4);
    let queue =
        crate::transport_core::receive_queue::ReceiveQueue::new(Default::default(), "PMTU fixture");
    inject_size_advisory(socket.raw_socket());
    let mut pump = spawn_client_udp_receive_pump(socket.clone(), 7, tx, &tasks.spawner(), queue);
    tokio::time::sleep(Duration::from_millis(20)).await;
    b.send(b"after-ICMP").await.unwrap();
    let batch = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let batch = batch.into_inner();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].path_epoch, 7);
    assert_eq!(&*batch[0].datagram, b"after-ICMP");
    drop(batch);
    pump.finish().await;
    tasks.finish().await;

    // A second advisory belongs to a larger probe, not the current floor record.
    inject_size_advisory(socket.raw_socket());
    let framing = UdpClientFraming::legacy(false, [0; 4]);
    let mut budget = 548;
    let counters = crate::transport_core::udp_buffer::UdpPathCounters::default();
    let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(32);
    let mut pn = 0;
    let mut record_id = 0;
    let mut carrier = vec![];
    send_client_udp_record(
        &[0x42; 300],
        &mut budget,
        None,
        &[3; 32],
        &mut record_id,
        &socket,
        framing,
        &mut pn,
        &mut carrier,
        &mut scratch,
        &counters,
    )
    .await
    .unwrap();
    assert_eq!(
        budget, 548,
        "a fitting floor record must not force a reconnect or size reduction"
    );
    let mut received = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), b.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..n], &[0x42; 300]);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires private Linux netns, lo MTU400, QELI_SMALL_PMTU_FIXTURE=1"]
async fn permanently_unusable_floor_fails_with_bounded_retries() {
    assert_eq!(std::env::var("QELI_SMALL_PMTU_FIXTURE").as_deref(), Ok("1"));
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(b.local_addr().unwrap()).await.unwrap();
    let socket = crate::protocol::obfs::ObfsUdp::new(a, None);
    assert!(begin_mtu_probe(&socket));
    assert_eq!(
        crate::protocol::pmtu::socket_path_mtu(socket.raw_socket(), false),
        Some(400)
    );
    let original = socket.raw_socket().local_addr().unwrap();
    let mut budget = 548;
    let counters = crate::transport_core::udp_buffer::UdpPathCounters::default();
    let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(32);
    let mut pn = 0;
    let mut record_id = 0;
    let mut carrier = vec![];
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        send_client_udp_record(
            &[0x42; 548],
            &mut budget,
            None,
            &[3; 32],
            &mut record_id,
            &socket,
            UdpClientFraming::legacy(false, [0; 4]),
            &mut pn,
            &mut carrier,
            &mut scratch,
            &counters,
        ),
    )
    .await
    .expect("permanent errors must not spin")
    .unwrap_err();
    assert!(udp_message_too_large(&error));
    assert_eq!(budget, 548);
    assert_eq!(socket.raw_socket().local_addr().unwrap(), original);
}
