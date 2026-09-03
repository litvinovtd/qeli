//! Batched UDP datagram I/O.
//!
//! The UDP data plane used to cost exactly one syscall per datagram in each direction. At an
//! MTU of 1400 that is ~45 000 `recvfrom` and ~45 000 `sendto` per second per direction at
//! 500 Mbit/s, and an `strace` of a live run confirmed the ratio almost exactly (67 194
//! datagrams received against 67 208 `recvfrom` calls). The TCP transport never paid this:
//! one `read` returns tens of kilobytes holding many records, so its per-byte syscall cost is
//! two orders of magnitude lower. A same-window old/new lab A/B did not show a meaningful
//! goodput gain; a repeated per-thread run also did not reproduce the first run's apparent CPU
//! reduction. A syscall trace did confirm successful receive batches averaging 3.55 datagrams
//! on server upload ingress and 4.46 on client download ingress. Treat batching as a verified
//! reduction in receive syscalls rather than a throughput or CPU promise; framing, crypto, the
//! serial consumer and the still-per-record egress path remain separate costs.
//! The next measured step removed that remaining egress bottleneck: client and server callers
//! opportunistically drain already-queued records into `sendmmsg` without a coalescing timer.
//! A same-window two-vCPU A/B raised median upload from 320.8 to 694.7 Mbit/s and download from
//! 359.8 to 697.5 Mbit/s while reducing relative sender CPU by 13.2% and 7.9%, respectively.
//! Kernel tracepoints confirmed that roughly 360k `sendto` calls became 34-37k `sendmmsg` calls
//! per measurement window. This uses independent datagrams and therefore keeps the Recordizer's
//! deliberately varied record sizes intact.
//!
//!
//! `recvmmsg`/`sendmmsg` move up to [`MAX_BATCH`] datagrams per syscall. Unlike `UDP_SEGMENT`
//! (GSO) they place **no constraint on datagram sizes**, so the Recordizer's deliberately
//! randomised record sizes — the `B` surface of the masking model — are untouched. That is the
//! reason this is the first optimisation and GSO is not.
//!
//! Every function here is non-blocking and expects the caller to own readiness (tokio's
//! `async_io`/`readable`). The batch is never waited on: `recvmmsg` returns as soon as at
//! least one datagram is queued, so batching adds no latency, only removes syscalls.

use bytes::BytesMut;
use std::io;
use std::net::SocketAddr;

/// Datagrams per syscall. Sized to cover a full receive burst at line rate without making one
/// wakeup arbitrarily long: 32 x 1400 B is ~45 KiB, about 0.7 ms of traffic at 500 Mbit/s.
pub(crate) const MAX_BATCH: usize = 32;

/// The portable fallback may return a useful partial batch only when the next non-blocking
/// operation says that the socket is drained. A permanent carrier error must not be hidden merely
/// because an earlier datagram in the same loop succeeded: on some platforms that error is
/// one-shot, so swallowing it can postpone failure detection indefinitely.
#[cfg(any(test, not(any(target_os = "linux", target_os = "android"))))]
fn finishes_partial_batch(error: &io::Error, completed: usize) -> bool {
    completed > 0 && error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use std::os::fd::AsRawFd;

    /// Reusable `mmsghdr`/`iovec`/`sockaddr` arrays. Rebuilt per call (32 stores, negligible
    /// beside a syscall) so no pointer can outlive the buffers it was derived from.
    pub(crate) struct BatchScratch {
        headers: Vec<libc::mmsghdr>,
        iovecs: Vec<libc::iovec>,
        names: Vec<libc::sockaddr_storage>,
    }

    impl BatchScratch {
        pub(crate) fn new(batch: usize) -> Self {
            let batch = batch.clamp(1, MAX_BATCH);
            Self {
                // SAFETY: all three are plain C aggregates of integers and pointers, fully
                // overwritten before every syscall that reads them.
                headers: vec![unsafe { std::mem::zeroed() }; batch],
                iovecs: vec![unsafe { std::mem::zeroed() }; batch],
                names: vec![unsafe { std::mem::zeroed() }; batch],
            }
        }

        pub(crate) fn capacity(&self) -> usize {
            self.headers.len()
        }

        /// Drop every pointer the last syscall used. Nothing reads these between calls — each
        /// is rewritten before the next one — but leaving them dangling would make a future
        /// caller that forgot to rebuild them fail silently on stale memory instead of loudly
        /// with `EFAULT`. It is also what makes the `Send` impl below a checkable claim rather
        /// than an asserted one: a parked scratch holds no pointer into anything.
        fn release_pointers(&mut self, used: usize) {
            for header in self.headers.iter_mut().take(used) {
                header.msg_hdr.msg_iov = std::ptr::null_mut();
                header.msg_hdr.msg_name = std::ptr::null_mut();
                header.msg_hdr.msg_namelen = 0;
                header.msg_hdr.msg_iovlen = 0 as _;
            }
            for iovec in self.iovecs.iter_mut().take(used) {
                iovec.iov_base = std::ptr::null_mut();
                iovec.iov_len = 0;
            }
        }
    }

    // SAFETY: `BatchScratch` owns its three vectors and nothing else. The only non-`Send`
    // members are the raw pointers inside `mmsghdr`/`iovec`; every one of them is written
    // immediately before the syscall that reads it and cleared immediately after
    // (`release_pointers`), so a scratch that crosses a thread boundary carries no pointer at
    // all — least of all one into another thread's memory.
    unsafe impl Send for BatchScratch {}

    /// Read up to `slots.len()` datagrams into the spare capacity of each slot.
    ///
    /// Slots must be empty; on return the first `n` have their lengths set. When `addrs` is
    /// given the peer address of each datagram is written to it (unconnected sockets).
    pub(crate) fn recv_batch(
        socket: &tokio::net::UdpSocket,
        slots: &mut [BytesMut],
        mut addrs: Option<&mut [SocketAddr]>,
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        let count = slots.len().min(scratch.capacity());
        if count == 0 {
            return Ok(0);
        }
        let want_addr = addrs.is_some();
        for (i, slot) in slots.iter_mut().enumerate().take(count) {
            let spare = slot.spare_capacity_mut();
            scratch.iovecs[i] = libc::iovec {
                iov_base: spare.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: spare.len(),
            };
            let iovec_ptr = std::ptr::addr_of_mut!(scratch.iovecs[i]);
            let name_ptr = std::ptr::addr_of_mut!(scratch.names[i]).cast::<libc::c_void>();
            let header = &mut scratch.headers[i];
            header.msg_hdr.msg_iov = iovec_ptr;
            header.msg_hdr.msg_iovlen = 1 as _;
            header.msg_hdr.msg_control = std::ptr::null_mut();
            header.msg_hdr.msg_controllen = 0 as _;
            header.msg_hdr.msg_flags = 0;
            header.msg_len = 0;
            if want_addr {
                header.msg_hdr.msg_name = name_ptr;
                header.msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            } else {
                header.msg_hdr.msg_name = std::ptr::null_mut();
                header.msg_hdr.msg_namelen = 0;
            }
        }

        // SAFETY: `headers[..count]` is initialised above and each entry points at an iovec
        // and (optionally) a sockaddr owned by the same `scratch`, both alive for this call.
        // The iovecs point at the slots' spare capacity, which cannot move while borrowed.
        let received = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                scratch.headers.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            scratch.release_pointers(count);
            return Err(error);
        }
        let received = (received as usize).min(count);
        for i in 0..received {
            // A datagram is never longer than the buffer offered, but a truncating kernel
            // reports the untruncated size, so clamp rather than trust the number.
            let written = (scratch.headers[i].msg_len as usize)
                .min(slots[i].capacity().saturating_sub(slots[i].len()));
            // SAFETY: the kernel initialised at least `written` bytes of this slot's spare
            // capacity, and `written` is clamped to that capacity above.
            unsafe {
                let len = slots[i].len();
                slots[i].set_len(len + written);
            }
            if let Some(addrs) = addrs.as_deref_mut() {
                addrs[i] =
                    decode_sockaddr(&scratch.names[i], scratch.headers[i].msg_hdr.msg_namelen)
                        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            }
        }
        scratch.release_pointers(count);
        Ok(received)
    }

    /// Send up to `datagrams.len()` datagrams. Returns how many the kernel accepted, which may
    /// be fewer: `sendmmsg` stops at the first datagram it cannot queue and reports the prefix
    /// it did send. The caller must retry the remainder rather than assume all-or-nothing.
    pub(crate) fn send_batch(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        send_batch_inner(socket, datagrams, None, scratch)
    }

    /// Unconnected counterpart of [`send_batch`]. Every datagram in one call goes to the same
    /// immutable peer snapshot; callers split a batch when roaming publishes a new path.
    #[allow(dead_code)] // server-only in client/FFI feature builds
    pub(crate) fn send_batch_to(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
        peer: SocketAddr,
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        send_batch_inner(socket, datagrams, Some(peer), scratch)
    }

    fn send_batch_inner(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
        peer: Option<SocketAddr>,
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        let count = datagrams.len().min(scratch.capacity());
        if count == 0 {
            return Ok(0);
        }
        for (i, datagram) in datagrams.iter().enumerate().take(count) {
            scratch.iovecs[i] = libc::iovec {
                iov_base: datagram.as_ptr() as *mut libc::c_void,
                iov_len: datagram.len(),
            };
            let iovec_ptr = std::ptr::addr_of_mut!(scratch.iovecs[i]);
            let (name_ptr, name_len) = if let Some(peer) = peer {
                let name_len = encode_sockaddr(peer, &mut scratch.names[i]);
                (
                    std::ptr::addr_of_mut!(scratch.names[i]).cast::<libc::c_void>(),
                    name_len,
                )
            } else {
                (std::ptr::null_mut(), 0)
            };
            let header = &mut scratch.headers[i];
            header.msg_hdr.msg_iov = iovec_ptr;
            header.msg_hdr.msg_iovlen = 1 as _;
            header.msg_hdr.msg_control = std::ptr::null_mut();
            header.msg_hdr.msg_controllen = 0 as _;
            header.msg_hdr.msg_flags = 0;
            header.msg_len = 0;
            header.msg_hdr.msg_name = name_ptr;
            header.msg_hdr.msg_namelen = name_len;
        }

        // SAFETY: as in `recv_batch` — headers, iovecs and names all live in `scratch`, and
        // the payload slices outlive this call.
        let sent = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                scratch.headers.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT as _,
            )
        };
        scratch.release_pointers(count);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((sent as usize).min(count))
    }

    fn encode_sockaddr(
        address: SocketAddr,
        storage: &mut libc::sockaddr_storage,
    ) -> libc::socklen_t {
        // SAFETY: sockaddr_storage is a plain C aggregate and is fully initialised below.
        *storage = unsafe { std::mem::zeroed() };
        match address {
            SocketAddr::V4(address) => {
                // SAFETY: sockaddr_storage is aligned and large enough for sockaddr_in.
                let raw = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in) };
                raw.sin_family = libc::AF_INET as libc::sa_family_t;
                raw.sin_port = address.port().to_be();
                raw.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(address) => {
                // SAFETY: sockaddr_storage is aligned and large enough for sockaddr_in6.
                let raw = unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in6) };
                raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                raw.sin6_port = address.port().to_be();
                raw.sin6_flowinfo = address.flowinfo().to_be();
                raw.sin6_addr.s6_addr = address.ip().octets();
                raw.sin6_scope_id = address.scope_id();
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }

    fn decode_sockaddr(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                // SAFETY: the kernel reported AF_INET and a length covering sockaddr_in.
                let raw = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
                Some(SocketAddr::from((
                    std::net::Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr)),
                    u16::from_be(raw.sin_port),
                )))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                // SAFETY: the kernel reported AF_INET6 and a length covering sockaddr_in6.
                let raw = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(raw.sin6_addr.s6_addr),
                    u16::from_be(raw.sin6_port),
                    u32::from_be(raw.sin6_flowinfo),
                    raw.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use super::*;

    /// No batching syscall on this platform; the loop below keeps the call sites identical.
    pub(crate) struct BatchScratch {
        capacity: usize,
    }

    impl BatchScratch {
        pub(crate) fn new(batch: usize) -> Self {
            Self {
                capacity: batch.clamp(1, MAX_BATCH),
            }
        }

        pub(crate) fn capacity(&self) -> usize {
            self.capacity
        }
    }

    pub(crate) fn recv_batch(
        socket: &tokio::net::UdpSocket,
        slots: &mut [BytesMut],
        mut addrs: Option<&mut [SocketAddr]>,
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        let count = slots.len().min(scratch.capacity());
        let mut filled = 0;
        while filled < count {
            let outcome = match addrs.as_deref_mut() {
                Some(addrs) => socket
                    .try_recv_buf_from(&mut slots[filled])
                    .map(|(read, from)| {
                        addrs[filled] = from;
                        read
                    }),
                None => socket.try_recv_buf(&mut slots[filled]),
            };
            match outcome {
                Ok(_) => filled += 1,
                // Drain only what is already queued: never wait to fill the batch.
                Err(error) if finishes_partial_batch(&error, filled) => break,
                Err(error) => return Err(error),
            }
        }
        if filled == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(filled)
    }

    pub(crate) fn send_batch(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        let count = datagrams.len().min(scratch.capacity());
        let mut sent = 0;
        while sent < count {
            match socket.try_send(datagrams[sent]) {
                Ok(_) => sent += 1,
                // A partial batch is normal only when the socket is temporarily full; the
                // caller retries the remainder after writable readiness. Real carrier errors
                // remain visible even if this loop already sent an earlier datagram.
                Err(error) if finishes_partial_batch(&error, sent) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }

    #[allow(dead_code)] // server-only in client/FFI feature builds
    pub(crate) fn send_batch_to(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
        peer: SocketAddr,
        scratch: &mut BatchScratch,
    ) -> io::Result<usize> {
        let count = datagrams.len().min(scratch.capacity());
        let mut sent = 0;
        while sent < count {
            match socket.try_send_to(datagrams[sent], peer) {
                Ok(_) => sent += 1,
                Err(error) if finishes_partial_batch(&error, sent) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(sent)
    }
}

pub(crate) use imp::{recv_batch, send_batch, send_batch_to, BatchScratch};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    async fn pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        (a, b)
    }

    fn slots(count: usize, capacity: usize) -> Vec<BytesMut> {
        (0..count)
            .map(|_| BytesMut::with_capacity(capacity))
            .collect()
    }

    #[test]
    fn portable_partial_batch_policy_never_hides_carrier_errors() {
        let would_block = io::Error::from(io::ErrorKind::WouldBlock);
        let connection_reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(finishes_partial_batch(&would_block, 1));
        assert!(!finishes_partial_batch(&would_block, 0));
        assert!(!finishes_partial_batch(&connection_reset, 1));
    }

    #[tokio::test]
    async fn one_call_carries_many_datagrams_of_different_sizes() {
        // The whole point of choosing mmsg over GSO: sizes may vary freely, so the
        // Recordizer's randomised record sizes survive batching untouched.
        let (sender, receiver) = pair().await;
        let payloads: Vec<Vec<u8>> = (1..=8).map(|i| vec![i as u8; i * 137]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();

        let mut send_scratch = BatchScratch::new(MAX_BATCH);
        sender.writable().await.unwrap();
        let sent = send_batch(&sender, &refs, &mut send_scratch).unwrap();
        assert_eq!(sent, payloads.len());

        let mut received = Vec::new();
        let mut recv_scratch = BatchScratch::new(MAX_BATCH);
        while received.len() < payloads.len() {
            receiver.readable().await.unwrap();
            let mut buffers = slots(MAX_BATCH, 4096);
            match recv_batch(&receiver, &mut buffers, None, &mut recv_scratch) {
                Ok(n) => received.extend(buffers.into_iter().take(n)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("recv_batch failed: {error}"),
            }
        }
        for (got, want) in received.iter().zip(payloads.iter()) {
            assert_eq!(got.as_ref(), want.as_slice());
        }
    }

    #[tokio::test]
    async fn an_empty_socket_reports_would_block_rather_than_zero() {
        // A zero return would read as "peer closed" to the pump; UDP has no such state.
        let (_sender, receiver) = pair().await;
        let mut buffers = slots(MAX_BATCH, 2048);
        let mut scratch = BatchScratch::new(MAX_BATCH);
        let error = recv_batch(&receiver, &mut buffers, None, &mut scratch).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn unconnected_receive_reports_each_peer_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        one.send_to(b"from-one", target).await.unwrap();
        two.send_to(b"from-two", target).await.unwrap();

        let mut seen = std::collections::HashMap::new();
        let mut scratch = BatchScratch::new(MAX_BATCH);
        while seen.len() < 2 {
            server.readable().await.unwrap();
            let mut buffers = slots(MAX_BATCH, 2048);
            let mut addrs = vec![SocketAddr::from(([0, 0, 0, 0], 0)); MAX_BATCH];
            match recv_batch(&server, &mut buffers, Some(&mut addrs), &mut scratch) {
                Ok(n) => {
                    for i in 0..n {
                        seen.insert(addrs[i], buffers[i].to_vec());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("recv_batch failed: {error}"),
            }
        }
        assert_eq!(
            seen.get(&one.local_addr().unwrap()).map(|v| v.as_slice()),
            Some(b"from-one".as_slice())
        );
        assert_eq!(
            seen.get(&two.local_addr().unwrap()).map(|v| v.as_slice()),
            Some(b"from-two".as_slice())
        );
    }

    #[tokio::test]
    async fn unconnected_batch_send_preserves_order_and_peer() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let payloads: Vec<Vec<u8>> = (1..=8).map(|i| vec![i as u8; i * 113]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|payload| payload.as_slice()).collect();
        let mut send_scratch = BatchScratch::new(MAX_BATCH);
        sender.writable().await.unwrap();
        let sent = send_batch_to(&sender, &refs, peer, &mut send_scratch).unwrap();
        assert_eq!(sent, payloads.len());

        let mut received = Vec::new();
        let mut receive_scratch = BatchScratch::new(MAX_BATCH);
        while received.len() < payloads.len() {
            receiver.readable().await.unwrap();
            let mut buffers = slots(MAX_BATCH, 2048);
            match recv_batch(&receiver, &mut buffers, None, &mut receive_scratch) {
                Ok(count) => received.extend(buffers.into_iter().take(count)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("recv_batch failed: {error}"),
            }
        }
        for (actual, expected) in received.iter().zip(payloads.iter()) {
            assert_eq!(actual.as_ref(), expected.as_slice());
        }
    }

    #[tokio::test]
    async fn unconnected_ipv6_batch_send_preserves_order_and_peer() {
        let Ok(sender) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let Ok(receiver) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let peer = receiver.local_addr().unwrap();
        let payloads: Vec<Vec<u8>> = (1..=8).map(|i| vec![i as u8; i * 97]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|payload| payload.as_slice()).collect();
        let mut send_scratch = BatchScratch::new(MAX_BATCH);
        sender.writable().await.unwrap();
        let sent = send_batch_to(&sender, &refs, peer, &mut send_scratch).unwrap();
        assert_eq!(sent, payloads.len());

        let mut received = Vec::new();
        let mut receive_scratch = BatchScratch::new(MAX_BATCH);
        while received.len() < payloads.len() {
            receiver.readable().await.unwrap();
            let mut buffers = slots(MAX_BATCH, 2048);
            match recv_batch(&receiver, &mut buffers, None, &mut receive_scratch) {
                Ok(count) => received.extend(buffers.into_iter().take(count)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("IPv6 recv_batch failed: {error}"),
            }
        }
        assert_eq!(received, payloads);
    }

    #[tokio::test]
    async fn a_batch_larger_than_the_scratch_is_capped_not_truncated_silently() {
        let (sender, _receiver) = pair().await;
        let payloads: Vec<Vec<u8>> = (0..MAX_BATCH + 8).map(|_| vec![7u8; 64]).collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let mut scratch = BatchScratch::new(4);
        sender.writable().await.unwrap();
        let sent = send_batch(&sender, &refs, &mut scratch).unwrap();
        assert!(
            sent <= 4,
            "scratch capacity must bound one call, sent {sent}"
        );
    }
}
