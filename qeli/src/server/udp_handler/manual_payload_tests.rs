use super::*;
use std::sync::atomic::{AtomicU32, Ordering};

#[tokio::test]
async fn manual_udp_budget_is_bounded_idempotent_and_not_probe_certification() {
    let socket = Arc::new(crate::protocol::obfs::ObfsUdp::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        None,
    ));
    let peer = "127.0.0.1:41001".parse().unwrap();
    let active = UdpActiveEgress::new_legacy(socket, peer, false, [0; 4]);
    let cell = AtomicU32::new(548);
    assert!(!active.set_manual_payload_size("127.0.0.1:41002".parse().unwrap(), &cell, 1472));
    for size in [0, 547, 65508, 65535] {
        assert!(!active.set_manual_payload_size(peer, &cell, size));
    }
    assert_eq!(cell.load(Ordering::Relaxed), 548);
    let before = active.snapshot();
    assert!(active.set_manual_payload_size(peer, &cell, 1472));
    assert_eq!(cell.load(Ordering::Relaxed), 1472);
    assert_eq!(active.snapshot().manual_payload_size, Some(1472));
    assert!(!active.snapshot_is_current(&before));
    let current = active.snapshot();
    assert_eq!(
        active.certify_payload_budget(
            current.path_epoch,
            peer,
            current.budget_revision,
            &cell,
            2000
        ),
        None
    );
    active.downgrade_payload_budget(current.path_epoch, &cell);
    assert_eq!(cell.load(Ordering::Relaxed), 548);
    assert!(active.set_manual_payload_size(peer, &cell, 1472));
    assert_eq!(
        cell.load(Ordering::Relaxed),
        548,
        "retransmitted policy must not undo EMSGSIZE"
    );
}

#[cfg(feature = "experimental-roaming")]
#[tokio::test]
async fn manual_udp_budget_survives_authenticated_path_commit() {
    let first = Arc::new(crate::protocol::obfs::ObfsUdp::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        None,
    ));
    let next = Arc::new(crate::protocol::obfs::ObfsUdp::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        None,
    ));
    let peer = "127.0.0.1:41001".parse().unwrap();
    let active = UdpActiveEgress::new_roaming(first, peer, [3; 8]);
    let cell = AtomicU32::new(548);
    assert!(active.set_manual_payload_size(peer, &cell, 1400));
    let new_peer = "127.0.0.1:41002".parse().unwrap();
    active
        .commit_roaming_with(
            UdpEgressCommit {
                expected_epoch: 0,
                expected_peer: peer,
                next_epoch: 1,
                socket: next,
                peer: new_peer,
                destination_cid: [4; 8],
            },
            &cell,
            |_, _| Ok::<(), ()>(()),
        )
        .unwrap();
    assert_eq!(active.snapshot().manual_payload_size, Some(1400));
    assert_eq!(cell.load(Ordering::Relaxed), 1400);
    assert!(
        !active.set_manual_payload_size(peer, &cell, 2000),
        "old path cannot alter the new budget"
    );
}

#[test]
fn manual_udp_capability_is_required_in_both_authenticated_directions() {
    use crate::protocol::capabilities::*;
    let server = implemented_udp_server_capabilities();
    let client = ClientCapabilities {
        core_bits: implemented_client_core_capabilities(),
        ..Default::default()
    };
    assert!(manual_udp_payload_negotiated(Some(server), Some(client)));
    assert!(!manual_udp_payload_negotiated(None, Some(client)));
    assert!(!manual_udp_payload_negotiated(Some(server), None));
    for bit in [
        server_capability::UDP_MANUAL_PAYLOAD_V1,
        server_capability::UDP_MANUAL_PAYLOAD_AUTH_V1,
        server_capability::UDP_DATA_FRAG_V1,
    ] {
        assert!(!manual_udp_payload_negotiated(
            Some(ServerCapabilities {
                bits: server.bits & !bit
            }),
            Some(client)
        ));
    }
    for bit in [
        client_capability::UDP_MANUAL_PAYLOAD_V1,
        client_capability::UDP_MANUAL_PAYLOAD_AUTH_V1,
        client_capability::UDP_DATA_FRAG_V1,
    ] {
        assert!(!manual_udp_payload_negotiated(
            Some(server),
            Some(ClientCapabilities {
                core_bits: client.core_bits & !bit,
                ..client
            })
        ));
    }
}
