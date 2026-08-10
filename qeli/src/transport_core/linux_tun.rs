//! Unix fd-backed TUN/TAP packet backend for the shared client core.
//!
//! The TCP and UDP transports consume and produce IP packets. This backend alone owns
//! the duplicated TUN file descriptors, blocking workers, bounded queues and TAP framing,
//! so reconnect teardown has one implementation independent of the selected wire mode.

use super::buffer_pool::{BufferPool, PooledBuffer};
use std::io;
use std::ops::{Deref, Range};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;

const FROM_TUN_CAPACITY: usize = 4096;
const TO_TUN_CAPACITY: usize = 2048;
const MAX_REUSABLE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MIN_REUSABLE_BUFFERS: usize = 4;
const MAX_REUSABLE_BUFFERS: usize = 64;
const MAX_DOWNLINK_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MIN_DOWNLINK_BUFFERS: usize = 4;
const MAX_DOWNLINK_BUFFERS: usize = 256;
const DOWNLINK_BUFFER_CAPACITY: usize =
    crate::protocol::packet::TLS_RECORD_HEADER + crate::protocol::packet::MAX_RECORD_SIZE;
const POLL_TIMEOUT_MS: i32 = 250;
const WRITER_STOP_POLL: Duration = Duration::from_millis(100);
const READER_BUFFER_POLL: Duration = Duration::from_millis(100);
const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

fn strip_ethernet_header(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return None;
    }
    Some(&frame[ETHERNET_HEADER_LEN..])
}

fn ethernet_header(dst_mac: &[u8; 6], src_mac: &[u8; 6]) -> [u8; ETHERNET_HEADER_LEN] {
    let mut header = [0u8; ETHERNET_HEADER_LEN];
    header[..6].copy_from_slice(dst_mac);
    header[6..12].copy_from_slice(src_mac);
    header[12..].copy_from_slice(&ETHERTYPE_IPV4);
    header
}

#[derive(Debug, Clone, Copy)]
pub struct TapHeaders {
    pub client_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
}

/// Framing carried by one fd-backed TUN implementation.
#[derive(Debug, Clone, Copy)]
pub enum TunFraming {
    /// Linux/Android IFF_NO_PI raw IP packets.
    Raw,
    /// Linux TAP Ethernet frames.
    Tap(TapHeaders),
    /// macOS utun packets with a four-byte big-endian address-family prefix.
    Utun,
}

#[derive(Debug, Clone, Copy)]
pub struct LinuxTunPumpConfig {
    pub buffer_size: usize,
    pub framing: TunFraming,
}

/// Cloneable, non-owning cancellation handle used by the platform teardown guard.
#[derive(Clone)]
pub struct LinuxTunPumpStop(Arc<AtomicBool>);

impl LinuxTunPumpStop {
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// One IP packet backed by a connection-scoped reusable TUN read buffer.
///
/// Dropping the value returns its allocation to the reader. The full backing buffer keeps
/// its configured length; `range` exposes only the bytes read from TUN (or the IP payload
/// inside a TAP frame), so reuse never needs to zero or resize 64 KiB on the hot path.
pub struct TunPacket {
    buffer: Option<Vec<u8>>,
    range: Range<usize>,
    recycle: std_mpsc::SyncSender<Vec<u8>>,
}

impl TunPacket {
    fn new(buffer: Vec<u8>, range: Range<usize>, recycle: std_mpsc::SyncSender<Vec<u8>>) -> Self {
        Self {
            buffer: Some(buffer),
            range,
            recycle,
        }
    }
}

impl Deref for TunPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self
            .buffer
            .as_ref()
            .expect("TUN packet buffer is present until drop")[self.range.clone()]
    }
}

impl AsRef<[u8]> for TunPacket {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for TunPacket {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            // The pool has exactly one slot per allocated buffer, so Full would indicate
            // a bookkeeping bug. On shutdown the receiver is gone; dropping is correct.
            let _ = self.recycle.try_send(buffer);
        }
    }
}

/// Cloneable receive-side boundary shared by every bonded TCP stream (or one UDP loop).
/// Checked-out buffers stay pooled while queued to the blocking TUN writer.
#[derive(Clone)]
pub(crate) struct TunWriter {
    to_tun: std_mpsc::SyncSender<PooledBuffer>,
    pool: BufferPool,
}

impl TunWriter {
    pub(crate) async fn acquire(&self) -> Option<PooledBuffer> {
        self.pool.acquire().await
    }

    pub(crate) fn try_acquire(&self) -> Option<PooledBuffer> {
        self.pool.try_acquire()
    }

    pub(crate) fn try_send(
        &self,
        packet: PooledBuffer,
    ) -> Result<(), std_mpsc::TrySendError<PooledBuffer>> {
        self.to_tun.try_send(packet)
    }
}

/// Owns the Unix TUN packet workers and their queues for one connection generation.
pub struct LinuxTunPump {
    from_tun: mpsc::Receiver<TunPacket>,
    to_tun: Option<std_mpsc::SyncSender<PooledBuffer>>,
    downlink_pool: BufferPool,
    stop: LinuxTunPumpStop,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl LinuxTunPump {
    pub fn start(
        reader_fd: OwnedFd,
        writer_fd: OwnedFd,
        config: LinuxTunPumpConfig,
    ) -> io::Result<Self> {
        let pool_capacity = reusable_buffer_count(config.buffer_size);
        Self::start_with_pool_capacity(reader_fd, writer_fd, config, pool_capacity)
    }

    fn start_with_pool_capacity(
        reader_fd: OwnedFd,
        writer_fd: OwnedFd,
        config: LinuxTunPumpConfig,
        pool_capacity: usize,
    ) -> io::Result<Self> {
        if config.buffer_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN buffer size must be non-zero",
            ));
        }
        if pool_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN buffer pool capacity must be non-zero",
            ));
        }
        set_nonblocking(&reader_fd)?;
        set_nonblocking(&writer_fd)?;

        let stop = LinuxTunPumpStop(Arc::new(AtomicBool::new(false)));
        let (from_tun_tx, mut from_tun) = mpsc::channel(FROM_TUN_CAPACITY);
        let (to_tun_tx, to_tun_rx) = std_mpsc::sync_channel(TO_TUN_CAPACITY);
        let downlink_pool = BufferPool::new(
            reusable_downlink_buffer_count(DOWNLINK_BUFFER_CAPACITY),
            DOWNLINK_BUFFER_CAPACITY,
        )?;
        let (recycle_tx, recycle_rx) = std_mpsc::sync_channel(pool_capacity);
        for _ in 0..pool_capacity {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(config.buffer_size)
                .map_err(|error| {
                    io::Error::other(format!(
                        "could not reserve {}-byte TUN packet buffer: {error}",
                        config.buffer_size
                    ))
                })?;
            buffer.resize(config.buffer_size, 0);
            recycle_tx
                .send(buffer)
                .expect("new TUN buffer pool has all slots available");
        }

        let reader_stop = stop.clone();
        let reader = std::thread::Builder::new()
            .name("qeli-tun-reader".into())
            .spawn(move || {
                reader_loop(
                    reader_fd,
                    from_tun_tx,
                    recycle_tx,
                    recycle_rx,
                    reader_stop,
                    config,
                )
            })?;

        let writer_stop = stop.clone();
        let writer = match std::thread::Builder::new()
            .name("qeli-tun-writer".into())
            .spawn(move || writer_loop(writer_fd, to_tun_rx, writer_stop, config.framing))
        {
            Ok(writer) => writer,
            Err(error) => {
                stop.request_stop();
                from_tun.close();
                drop(to_tun_tx);
                let _ = reader.join();
                return Err(error);
            }
        };

        Ok(Self {
            from_tun,
            to_tun: Some(to_tun_tx),
            downlink_pool,
            stop,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    pub fn stop_handle(&self) -> LinuxTunPumpStop {
        self.stop.clone()
    }

    pub(crate) fn sender_to_tun(&self) -> TunWriter {
        TunWriter {
            to_tun: self
                .to_tun
                .as_ref()
                .expect("TUN sender is unavailable after shutdown")
                .clone(),
            pool: self.downlink_pool.clone(),
        }
    }

    pub async fn recv_from_tun(&mut self) -> Option<TunPacket> {
        self.from_tun.recv().await
    }

    /// Stop both workers, close their descriptors and wait until ownership is released.
    pub async fn shutdown(mut self) {
        self.request_stop();
        let reader = self.reader.take();
        let writer = self.writer.take();
        if reader.is_none() && writer.is_none() {
            return;
        }
        let joined = tokio::task::spawn_blocking(move || {
            if let Some(reader) = reader {
                let _ = reader.join();
            }
            if let Some(writer) = writer {
                let _ = writer.join();
            }
        })
        .await;
        if let Err(error) = joined {
            log::warn!("TUN worker join failed: {error}");
        }
    }

    fn request_stop(&mut self) {
        self.stop.request_stop();
        self.from_tun.close();
        self.to_tun.take();
    }
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0
        && unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reusable_buffer_count(buffer_size: usize) -> usize {
    if buffer_size == 0 {
        return MIN_REUSABLE_BUFFERS;
    }
    (MAX_REUSABLE_BUFFER_BYTES / buffer_size).clamp(MIN_REUSABLE_BUFFERS, MAX_REUSABLE_BUFFERS)
}

fn reusable_downlink_buffer_count(buffer_capacity: usize) -> usize {
    if buffer_capacity == 0 {
        return MIN_DOWNLINK_BUFFERS;
    }
    (MAX_DOWNLINK_BUFFER_BYTES / buffer_capacity).clamp(MIN_DOWNLINK_BUFFERS, MAX_DOWNLINK_BUFFERS)
}

impl Drop for LinuxTunPump {
    fn drop(&mut self) {
        // Error paths cannot await, but closing both queues plus the stop flag makes the
        // detached workers release their OwnedFd values within one bounded poll interval.
        self.request_stop();
    }
}

fn reader_loop(
    reader_fd: OwnedFd,
    from_tun: mpsc::Sender<TunPacket>,
    recycle: std_mpsc::SyncSender<Vec<u8>>,
    available: std_mpsc::Receiver<Vec<u8>>,
    stop: LinuxTunPumpStop,
    config: LinuxTunPumpConfig,
) {
    log::info!("TUN reader started");
    'reader: loop {
        if stop.0.load(Ordering::Acquire) {
            break;
        }
        let mut buffer = match available.recv_timeout(READER_BUFFER_POLL) {
            Ok(buffer) => buffer,
            Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        };

        let read = loop {
            if stop.0.load(Ordering::Acquire) {
                break 'reader;
            }
            let read = unsafe {
                libc::read(
                    reader_fd.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if read >= 0 {
                break read;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {
                    let mut poll_fd = libc::pollfd {
                        fd: reader_fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let poll_result = unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MS) };
                    if poll_result < 0 {
                        let poll_error = io::Error::last_os_error();
                        if poll_error.raw_os_error() != Some(libc::EINTR) {
                            log::warn!("TUN poll error: {poll_error}");
                            break 'reader;
                        }
                    }
                    continue;
                }
                _ => {
                    log::error!("TUN read error: {error}");
                    break 'reader;
                }
            }
        };
        if read == 0 {
            break;
        }

        let raw = &buffer[..read as usize];
        let range = match config.framing {
            TunFraming::Tap(_) => match strip_ethernet_header(raw) {
                Some(ip) => {
                    let start = ip.as_ptr() as usize - raw.as_ptr() as usize;
                    start..start + ip.len()
                }
                None => {
                    let _ = recycle.try_send(buffer);
                    continue;
                }
            },
            TunFraming::Utun => {
                if raw.len() <= 4 {
                    let _ = recycle.try_send(buffer);
                    continue;
                }
                4..raw.len()
            }
            TunFraming::Raw => 0..raw.len(),
        };
        let packet = TunPacket::new(buffer, range, recycle.clone());
        if from_tun.blocking_send(packet).is_err() {
            break;
        }
    }
    log::info!("TUN reader stopped");
}

fn writer_loop(
    writer_fd: OwnedFd,
    to_tun: std_mpsc::Receiver<PooledBuffer>,
    stop: LinuxTunPumpStop,
    framing: TunFraming,
) {
    log::info!("TUN writer started");
    'writer: loop {
        if stop.0.load(Ordering::Acquire) {
            break;
        }
        let packet = match to_tun.recv_timeout(WRITER_STOP_POLL) {
            Ok(packet) => packet,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if stop.0.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if packet.is_empty() {
            continue;
        }

        let mut header = [0u8; ETHERNET_HEADER_LEN];
        let header_len = match framing {
            TunFraming::Raw => 0,
            TunFraming::Tap(headers) => {
                header = ethernet_header(&headers.client_mac, &headers.gateway_mac);
                ETHERNET_HEADER_LEN
            }
            TunFraming::Utun => {
                // AF_INET = 2 in network byte order, matching the Darwin utun contract.
                header[..4].copy_from_slice(&2u32.to_be_bytes());
                4
            }
        };
        let expected = header_len + packet.len();
        loop {
            let written = unsafe {
                if header_len == 0 {
                    libc::write(
                        writer_fd.as_raw_fd(),
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                    )
                } else {
                    let vectors = [
                        libc::iovec {
                            iov_base: header.as_mut_ptr() as *mut libc::c_void,
                            iov_len: header_len,
                        },
                        libc::iovec {
                            iov_base: packet.as_ptr() as *mut libc::c_void,
                            iov_len: packet.len(),
                        },
                    ];
                    libc::writev(
                        writer_fd.as_raw_fd(),
                        vectors.as_ptr(),
                        vectors.len() as i32,
                    )
                }
            };
            if written >= 0 {
                if written as usize != expected {
                    log::warn!(
                        "TUN writer accepted only {written} of {} packet bytes",
                        expected
                    );
                }
                break;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOBUFS) | Some(libc::EAGAIN) => {
                    log::debug!("TUN writer dropped packet ({error})");
                    break;
                }
                _ => {
                    log::warn!("TUN writer fatal write error ({error}) - stopping");
                    break 'writer;
                }
            }
        }
    }
    log::info!("TUN writer stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    fn packet_pair() -> (UnixDatagram, OwnedFd) {
        let (test_end, pump_end) = UnixDatagram::pair().unwrap();
        pump_end.set_nonblocking(true).unwrap();
        (test_end, pump_end.into())
    }

    #[test]
    fn reusable_pool_stays_within_its_memory_budget() {
        for buffer_size in [576, 1500, 65_535, 1024 * 1024] {
            let count = reusable_buffer_count(buffer_size);
            assert!((MIN_REUSABLE_BUFFERS..=MAX_REUSABLE_BUFFERS).contains(&count));
            assert!(count * buffer_size <= MAX_REUSABLE_BUFFER_BYTES);
        }
        let count = reusable_downlink_buffer_count(DOWNLINK_BUFFER_CAPACITY);
        assert!((MIN_DOWNLINK_BUFFERS..=MAX_DOWNLINK_BUFFERS).contains(&count));
        assert!(count * DOWNLINK_BUFFER_CAPACITY <= MAX_DOWNLINK_BUFFER_BYTES);
    }

    #[tokio::test]
    async fn pumps_packets_in_both_directions() {
        let (reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
            },
        )
        .unwrap();

        let uplink = [0x45, 0, 0, 20, 1, 2, 3, 4];
        reader_test.send(&uplink).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .expect("TUN reader did not forward a packet")
            .expect("TUN reader stopped unexpectedly");
        assert_eq!(&*received, &uplink);

        let downlink = vec![0x60, 0, 0, 0, 5, 6, 7, 8];
        let tun_writer = pump.sender_to_tun();
        let mut packet = tun_writer.acquire().await.unwrap();
        packet.as_vec_mut().extend_from_slice(&downlink);
        tun_writer.try_send(packet).unwrap();
        let mut received = [0u8; 64];
        let count = writer_test.recv(&mut received).unwrap();
        assert_eq!(&received[..count], downlink);

        pump.shutdown().await;
    }

    #[tokio::test]
    async fn writer_returns_downlink_allocation_after_the_write() {
        let (_reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
            },
        )
        .unwrap();
        let writer = pump.sender_to_tun();
        let pool_count = reusable_downlink_buffer_count(DOWNLINK_BUFFER_CAPACITY);
        let mut packet = writer.acquire().await.unwrap();
        packet.as_vec_mut().extend_from_slice(&[0x45, 0, 0, 20]);
        let allocation = packet.as_ptr();
        let mut held = Vec::with_capacity(pool_count - 1);
        for _ in 1..pool_count {
            held.push(writer.acquire().await.unwrap());
        }
        assert!(writer.try_acquire().is_none());

        writer.try_send(packet).unwrap();
        let mut received = [0u8; 64];
        assert_eq!(writer_test.recv(&mut received).unwrap(), 4);
        let reused = tokio::time::timeout(Duration::from_secs(1), writer.acquire())
            .await
            .expect("TUN writer did not return its completed allocation")
            .unwrap();
        assert_eq!(reused.as_ptr(), allocation);

        drop(held);
        drop(reused);
        pump.shutdown().await;
    }

    #[tokio::test]
    async fn tap_mode_strips_and_restores_ethernet_headers() {
        let (reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let headers = TapHeaders {
            client_mac: [2, 0, 0, 0, 0, 2],
            gateway_mac: [2, 0, 0, 0, 0, 1],
        };
        let mut pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Tap(headers),
            },
        )
        .unwrap();
        let ip_packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut frame = ethernet_header(&headers.gateway_mac, &headers.client_mac).to_vec();
        frame.extend_from_slice(&ip_packet);
        reader_test.send(&frame).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .expect("TAP reader did not forward an IP packet")
            .expect("TAP reader stopped unexpectedly");
        assert_eq!(&*received, ip_packet);

        let tun_writer = pump.sender_to_tun();
        let mut packet = tun_writer.acquire().await.unwrap();
        packet.as_vec_mut().extend_from_slice(&ip_packet);
        tun_writer.try_send(packet).unwrap();
        let mut received = [0u8; 128];
        let count = writer_test.recv(&mut received).unwrap();
        let mut expected = ethernet_header(&headers.client_mac, &headers.gateway_mac).to_vec();
        expected.extend_from_slice(&ip_packet);
        assert_eq!(&received[..count], expected);

        pump.shutdown().await;
    }

    #[tokio::test]
    async fn utun_mode_strips_and_restores_address_family_prefix() {
        let (reader_test, reader_fd) = packet_pair();
        let (writer_test, writer_fd) = packet_pair();
        writer_test
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Utun,
            },
        )
        .unwrap();
        let ip_packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut framed = 2u32.to_be_bytes().to_vec();
        framed.extend_from_slice(&ip_packet);
        reader_test.send(&framed).unwrap();

        let outbound = pump.recv_from_tun().await.unwrap();
        assert_eq!(&*outbound, ip_packet);

        let writer = pump.sender_to_tun();
        let mut inbound = writer.acquire().await.unwrap();
        inbound.as_vec_mut().extend_from_slice(&ip_packet);
        writer.try_send(inbound).unwrap();
        let mut got = [0u8; 64];
        let read = writer_test.recv(&mut got).unwrap();
        assert_eq!(&got[..read], framed);

        pump.shutdown().await;
    }

    #[tokio::test]
    async fn reader_waits_for_and_reuses_a_returned_buffer() {
        let (reader_test, reader_fd) = packet_pair();
        let (_writer_test, writer_fd) = packet_pair();
        let mut pump = LinuxTunPump::start_with_pool_capacity(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
            },
            2,
        )
        .unwrap();
        let packets = [
            [0x45, 0, 0, 20, 1, 0, 0, 1],
            [0x45, 0, 0, 20, 2, 0, 0, 2],
            [0x45, 0, 0, 20, 3, 0, 0, 3],
        ];

        reader_test.send(&packets[0]).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .unwrap()
            .unwrap();
        let first_allocation = first.as_ptr();
        reader_test.send(&packets[1]).unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .unwrap()
            .unwrap();

        // Both pool buffers are held by the caller. The third datagram may wait in the
        // kernel, but the reader must not allocate a fallback buffer to forward it.
        reader_test.send(&packets[2]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), pump.recv_from_tun())
                .await
                .is_err()
        );

        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), pump.recv_from_tun())
            .await
            .expect("reader did not resume after a pooled buffer was returned")
            .expect("TUN reader stopped unexpectedly");
        assert_eq!(&*third, &packets[2]);
        assert_eq!(third.as_ptr(), first_allocation);

        drop(second);
        drop(third);
        pump.shutdown().await;
    }

    #[tokio::test]
    async fn idle_shutdown_releases_both_descriptors() {
        let (_reader_test, reader_fd) = packet_pair();
        let (_writer_test, writer_fd) = packet_pair();
        let pump = LinuxTunPump::start(
            reader_fd,
            writer_fd,
            LinuxTunPumpConfig {
                buffer_size: 2048,
                framing: TunFraming::Raw,
            },
        )
        .unwrap();

        tokio::time::timeout(Duration::from_secs(1), pump.shutdown())
            .await
            .expect("idle TUN workers did not stop within their bounded poll interval");
    }
}
