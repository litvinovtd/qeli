//! Bounded packet bridge for platforms whose TUN API is not a transferable file descriptor.
//!
//! iOS uses `NEPacketTunnelFlow`; ABI 1.7 compatibility adapters may expose the same packet seam.
//! The platform keeps those small OS adapters while Rust owns every transport byte. Both
//! directions use fixed pools and bounded queues; the FFI never allocates
//! a fallback packet when the platform outruns the core.

use super::buffer_pool::{BufferPool, PooledBuffer};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, MutexGuard};
use tokio::sync::mpsc;

pub(crate) const MAX_PACKET_BYTES: usize = 65_535;
pub(crate) const MAX_BATCH_PACKETS: usize = 64;
#[cfg(target_os = "ios")]
const PACKET_POOL_CAPACITY: usize = 32;
#[cfg(not(target_os = "ios"))]
const PACKET_POOL_CAPACITY: usize = 64;
#[cfg(target_os = "ios")]
const FROM_PLATFORM_CAPACITY: usize = 128;
#[cfg(not(target_os = "ios"))]
const FROM_PLATFORM_CAPACITY: usize = 256;
#[cfg(target_os = "ios")]
const TO_PLATFORM_CAPACITY: usize = 128;
#[cfg(not(target_os = "ios"))]
const TO_PLATFORM_CAPACITY: usize = 256;

struct DownlinkQueue {
    receiver: std_mpsc::Receiver<PooledBuffer>,
    pending: Option<PooledBuffer>,
}

/// Cloneable synchronous side retained by [`ClientCore`](super::ClientCore) for FFI calls.
#[derive(Clone)]
pub(crate) struct PacketTunBridge {
    generation: u64,
    from_platform: mpsc::Sender<PooledBuffer>,
    uplink_pool: BufferPool,
    to_platform: Arc<Mutex<DownlinkQueue>>,
    active: Arc<AtomicBool>,
}

impl PacketTunBridge {
    fn downlink(&self) -> MutexGuard<'_, DownlinkQueue> {
        self.to_platform
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Copy as much of one contiguous packet batch as the fixed uplink pool accepts.
    pub(crate) fn push_batch(&self, packets: &[u8], lengths: &[u32]) -> io::Result<usize> {
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet bridge is stopped",
            ));
        }
        if lengths.is_empty() || lengths.len() > MAX_BATCH_PACKETS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("packet batch must contain 1..={MAX_BATCH_PACKETS} packets"),
            ));
        }
        let total = lengths.iter().try_fold(0usize, |total, length| {
            let length = *length as usize;
            if length == 0 || length > MAX_PACKET_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("packet length must be 1..={MAX_PACKET_BYTES}"),
                ));
            }
            total.checked_add(length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "packet batch length overflow")
            })
        })?;
        if total != packets.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet lengths total {total}, input contains {} bytes",
                    packets.len()
                ),
            ));
        }

        let mut offset = 0usize;
        let mut accepted = 0usize;
        for length in lengths {
            let length = *length as usize;
            let Some(mut packet) = self.uplink_pool.try_acquire() else {
                break;
            };
            packet
                .as_vec_mut()
                .extend_from_slice(&packets[offset..offset + length]);
            match self.from_platform.try_send(packet) {
                Ok(()) => accepted += 1,
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.stop();
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "native packet receiver is closed",
                    ));
                }
            }
            offset += length;
        }
        Ok(accepted)
    }

    /// Copy a bounded downlink batch into platform-owned output storage.
    pub(crate) fn pull_batch(
        &self,
        packets: &mut [u8],
        lengths: &mut [u32],
    ) -> io::Result<(usize, usize)> {
        if packets.len() < MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("packet output capacity must be at least {MAX_PACKET_BYTES}"),
            ));
        }
        if lengths.is_empty() || lengths.len() > MAX_BATCH_PACKETS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("length output must contain 1..={MAX_BATCH_PACKETS} slots"),
            ));
        }

        let mut queue = self.downlink();
        let mut count = 0usize;
        let mut bytes = 0usize;
        while count < lengths.len() {
            let packet = match queue.pending.take() {
                Some(packet) => packet,
                None => match queue.receiver.try_recv() {
                    Ok(packet) => packet,
                    Err(std_mpsc::TryRecvError::Empty) => break,
                    Err(std_mpsc::TryRecvError::Disconnected) => {
                        self.stop();
                        break;
                    }
                },
            };
            if bytes + packet.len() > packets.len() {
                queue.pending = Some(packet);
                break;
            }
            packets[bytes..bytes + packet.len()].copy_from_slice(&packet);
            lengths[count] = packet.len() as u32;
            bytes += packet.len();
            count += 1;
        }
        Ok((count, bytes))
    }
}

/// Async side consumed by the common TCP/UDP packet loops.
pub(crate) struct PacketTunPump {
    from_platform: mpsc::Receiver<PooledBuffer>,
    to_platform: Option<std_mpsc::SyncSender<PooledBuffer>>,
    downlink_pool: BufferPool,
    active: Arc<AtomicBool>,
}

#[derive(Clone)]
pub(crate) struct TunWriter {
    to_platform: std_mpsc::SyncSender<PooledBuffer>,
    pool: BufferPool,
}

impl TunWriter {
    pub(crate) fn from_parts(
        to_platform: std_mpsc::SyncSender<PooledBuffer>,
        pool: BufferPool,
    ) -> Self {
        Self { to_platform, pool }
    }

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
        self.to_platform.try_send(packet)
    }
}

impl PacketTunPump {
    pub(crate) fn new(generation: u64) -> io::Result<(PacketTunBridge, Self)> {
        let uplink_pool = BufferPool::new(PACKET_POOL_CAPACITY, MAX_PACKET_BYTES)?;
        let downlink_pool = BufferPool::new(PACKET_POOL_CAPACITY, MAX_PACKET_BYTES)?;
        let (from_platform_tx, from_platform) = mpsc::channel(FROM_PLATFORM_CAPACITY);
        let (to_platform, to_platform_rx) = std_mpsc::sync_channel(TO_PLATFORM_CAPACITY);
        let active = Arc::new(AtomicBool::new(true));
        let bridge = PacketTunBridge {
            generation,
            from_platform: from_platform_tx,
            uplink_pool,
            to_platform: Arc::new(Mutex::new(DownlinkQueue {
                receiver: to_platform_rx,
                pending: None,
            })),
            active: active.clone(),
        };
        let pump = Self {
            from_platform,
            to_platform: Some(to_platform),
            downlink_pool,
            active,
        };
        Ok((bridge, pump))
    }

    pub(crate) fn sender_to_tun(&self) -> TunWriter {
        TunWriter::from_parts(
            self.to_platform
                .as_ref()
                .expect("packet sender is unavailable after shutdown")
                .clone(),
            self.downlink_pool.clone(),
        )
    }

    pub(crate) async fn recv_from_tun(&mut self) -> Option<PooledBuffer> {
        self.from_platform.recv().await
    }

    pub(crate) async fn shutdown(mut self) {
        self.active.store(false, Ordering::Release);
        self.from_platform.close();
        self.to_platform.take();
    }
}

impl Drop for PacketTunPump {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.from_platform.close();
        self.to_platform.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packet_bridge_moves_bounded_batches_both_directions() {
        let (bridge, mut pump) = PacketTunPump::new(7).unwrap();
        assert_eq!(bridge.generation(), 7);
        assert_eq!(bridge.push_batch(b"abcdef", &[2, 4]).unwrap(), 2);
        assert_eq!(&*pump.recv_from_tun().await.unwrap(), b"ab");
        assert_eq!(&*pump.recv_from_tun().await.unwrap(), b"cdef");

        let writer = pump.sender_to_tun();
        for value in [b"one".as_slice(), b"second".as_slice()] {
            let mut packet = writer.acquire().await.unwrap();
            packet.as_vec_mut().extend_from_slice(value);
            writer.try_send(packet).unwrap();
        }
        let mut bytes = vec![0; MAX_PACKET_BYTES];
        let mut lengths = [0u32; 4];
        let (count, used) = bridge.pull_batch(&mut bytes, &mut lengths).unwrap();
        assert_eq!((count, used), (2, 9));
        assert_eq!(&lengths[..count], &[3, 6]);
        assert_eq!(&bytes[..used], b"onesecond");

        pump.shutdown().await;
        assert!(bridge.push_batch(b"x", &[1]).is_err());
    }

    #[test]
    fn malformed_batches_are_rejected_without_partial_delivery() {
        let (bridge, _pump) = PacketTunPump::new(3).unwrap();
        assert!(bridge.push_batch(b"abc", &[2]).is_err());
        assert!(bridge.push_batch(b"", &[]).is_err());
        assert!(bridge.push_batch(b"", &[0]).is_err());
    }
}
