use super::*;
use crate::protocol::obfs::ObfsUdp;
use crate::transport_core::udp_batch::{self, BatchScratch};
use bytes::BytesMut;
use std::time::Duration;
use tokio::net::UdpSocket;

#[test]
fn ancillary_rejects_missing_truncated_and_invalid_headers() {
    let mut control = Control::default();
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    assert!(control.decode(&header).is_err());
    control.receive(&mut header);
    assert!(control.decode(&header).is_err()); // zero cmsg length
    header.msg_flags = libc::MSG_CTRUNC;
    assert!(control.decode(&header).is_err());
    header.msg_flags = 0;
    header.msg_controllen = 9999;
    assert!(control.decode(&header).is_err());
    control.receive(&mut header);
    unsafe {
        (*libc::CMSG_FIRSTHDR(&header)).cmsg_len = usize::MAX as _;
    }
    assert!(control.decode(&header).is_err());
}

fn received_control(ip: Ipv4Addr) -> (Control, libc::msghdr) {
    let mut control = Control::default();
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    control
        .send(LocalAddress::new(ip.into(), 0).unwrap(), &mut header)
        .unwrap();
    unsafe {
        let info = libc::CMSG_DATA(libc::CMSG_FIRSTHDR(&header)).cast::<libc::in_pktinfo>();
        (*info).ipi_addr = (*info).ipi_spec_dst;
    }
    // Header addresses are not used by decode; do not carry a dangling pointer.
    header.msg_control = std::ptr::null_mut();
    (control, header)
}

#[test]
fn ancillary_rejects_duplicate_address_and_broadcast_destination() {
    let ip = Ipv4Addr::new(127, 0, 0, 3);
    let (mut control, mut header) = received_control(ip);
    assert_eq!(
        control.decode(&header).unwrap().socket_addr(7),
        SocketAddr::from((ip, 7))
    );
    #[allow(clippy::unnecessary_cast)] // Native libc ABI field width.
    let size = header.msg_controllen as usize;
    let byte_len = std::mem::size_of_val(&control.0);
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(control.0.as_mut_ptr().cast::<u8>(), byte_len) };
    bytes.copy_within(0..size, size);
    header.msg_controllen = (size * 2) as _;
    assert!(control.decode(&header).is_err());
    let (mut control, mut header) = received_control(ip);
    control.receive(&mut header);
    header.msg_controllen = size as _;
    unsafe {
        let info = libc::CMSG_DATA(libc::CMSG_FIRSTHDR(&header)).cast::<libc::in_pktinfo>();
        (*info).ipi_addr.s_addr = u32::MAX;
    }
    assert!(control.decode(&header).is_err());
}

#[test]
fn local_address_retains_only_required_ipv6_scope() {
    let link: IpAddr = "fe80::3".parse().unwrap();
    assert!(LocalAddress::new(link, 0).is_err());
    assert_eq!(
        LocalAddress::new(link, 17).unwrap().socket_addr(443),
        "[fe80::3%17]:443".parse().unwrap()
    );
    assert_eq!(
        LocalAddress::new("fd42::3".parse().unwrap(), 17)
            .unwrap()
            .socket_addr(443),
        "[fd42::3]:443".parse().unwrap()
    );
    for ip in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "::", "ff02::1"] {
        assert!(LocalAddress::new(ip.parse().unwrap(), 1).is_err());
    }
}

async fn interleaved(bind: SocketAddr, destinations: [IpAddr; 2], key: Option<[u8; 32]>) {
    let server = ObfsUdp::server(UdpSocket::bind(bind).await.unwrap(), key).unwrap();
    let port = server.local_addr().unwrap().port();
    let mut clients = Vec::new();
    for ip in destinations {
        let raw = UdpSocket::bind(if ip.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .await
        .unwrap();
        raw.connect(SocketAddr::new(ip, port)).await.unwrap();
        clients.push(ObfsUdp::new(raw, key));
    }
    for (i, client) in clients.iter().enumerate() {
        client.send(&[i as u8 + 1]).await.unwrap();
    }
    let mut scratch = BatchScratch::new(8);
    let mut slots = (0..8)
        .map(|_| BytesMut::with_capacity(2048))
        .collect::<Vec<_>>();
    let mut peers = vec![bind; 8];
    let mut paths = Vec::new();
    while paths.len() < 2 {
        for slot in &mut slots {
            slot.clear();
        }
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            server.recv_batch_local(&mut slots, &mut peers, &mut scratch),
        )
        .await
        .unwrap()
        .unwrap();
        for i in 0..n {
            let marker = slots[i][0];
            let local = scratch.local_address(i).unwrap();
            assert_eq!(
                local.socket_addr(port).ip(),
                destinations[usize::from(marker - 1)]
            );
            let path = server.reply_from(local);
            assert!(path.same_path(&server.reply_from(local)));
            assert!(!path.same_path(&server));
            assert_eq!(path.as_raw_fd(), server.as_raw_fd()); // no additional kernel sockets
            paths.push((path, peers[i], marker));
        }
    }
    assert!(!paths[0].0.same_path(&paths[1].0));
    // Receive on both destinations before replying: last arrival must not change an old view.
    for (path, peer, marker) in paths.iter().rev() {
        path.send_to(&[*marker, 1], *peer).await.unwrap();
        loop {
            path.raw_socket().writable().await.unwrap();
            match path.try_send_to(&[*marker, 2], *peer) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{e}"),
            }
        }
        let packets = [vec![*marker, 3], vec![*marker, 4]];
        let refs = packets.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut sent = 0;
        while sent < 2 {
            sent += path
                .send_batch_to(&refs[sent..], *peer, &mut scratch)
                .await
                .unwrap();
        }
    }
    for (i, client) in clients.iter().enumerate() {
        for sequence in 1..=4 {
            let mut packet = [0u8; 100];
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&packet[..n], &[i as u8 + 1, sequence]);
        }
    }
}

#[tokio::test]
async fn interleaved_ipv4_wildcard_replies_preserve_plain_and_obfs_paths() {
    for key in [None, Some([39; 32])] {
        interleaved(
            "0.0.0.0:0".parse().unwrap(),
            ["127.0.0.2".parse().unwrap(), "127.0.0.3".parse().unwrap()],
            key,
        )
        .await;
    }
}

#[tokio::test]
async fn missing_pktinfo_fails_without_reusing_an_old_source() {
    let server = ObfsUdp::new(UdpSocket::bind("0.0.0.0:0").await.unwrap(), None);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut scratch = BatchScratch::new(1);
    let mut slots = [BytesMut::with_capacity(128)];
    let mut peers = [client.local_addr().unwrap()];
    let target = SocketAddr::from((
        [127, 0, 0, 3],
        server.raw_socket().local_addr().unwrap().port(),
    ));
    enable(server.raw_socket()).unwrap();
    client.send_to(b"first", target).await.unwrap();
    assert_eq!(
        server
            .recv_batch_local(&mut slots, &mut peers, &mut scratch)
            .await
            .unwrap(),
        1
    );
    assert!(scratch.local_address(0).is_some());
    slots[0].clear();
    let disabled: libc::c_int = 0;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&disabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&disabled) as _,
            )
        },
        0
    );
    client.send_to(b"second", target).await.unwrap();
    assert!(server
        .recv_batch_local(&mut slots, &mut peers, &mut scratch)
        .await
        .is_err());
    assert!(scratch.local_address(0).is_none());
}

#[tokio::test]
async fn short_batch_address_buffer_returns_error_before_receiving() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut slots = [BytesMut::with_capacity(128)];
    let mut scratch = BatchScratch::new(1);
    let error =
        udp_batch::recv_batch(&socket, &mut slots, Some(&mut []), &mut scratch).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated network namespace"]
fn native_ipv6_wildcard_replies_preserve_both_local_addresses() {
    std::thread::spawn(|| {
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        for args in [
            vec!["link", "set", "lo", "up"],
            vec!["-6", "addr", "add", "fd42::1/128", "dev", "lo", "nodad"],
            vec!["-6", "addr", "add", "fd42::3/128", "dev", "lo", "nodad"],
        ] {
            assert!(std::process::Command::new("ip")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for key in [None, Some([39; 32])] {
                    interleaved(
                        "[::]:0".parse().unwrap(),
                        ["fd42::1".parse().unwrap(), "fd42::3".parse().unwrap()],
                        key,
                    )
                    .await;
                }
            });
    })
    .join()
    .unwrap();
}
