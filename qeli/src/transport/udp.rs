use bytes::BytesMut;
use std::ops::Deref;
use tokio::sync::mpsc;

/// Maximum UDP datagram we read into a recv buffer (theoretical IPv4 maximum).
pub const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Extra user-space receive depth for one UDP socket. The kernel remains the first queue;
/// this bounded FIFO only decouples `recvmsg` from decrypt/reassembly/TUN forwarding bursts.
pub(crate) const UDP_RECEIVE_QUEUE_PACKETS: usize = 128;

/// A receive allocation that returns itself to its socket-local pool on every exit path.
///
/// `BytesMut` lets Tokio receive directly into spare capacity, so a 65 KiB safety ceiling does
/// not require zeroing 65 KiB for every ordinary MTU-sized datagram. Keeping the theoretical
/// UDP maximum preserves all existing handshake, DATA_FRAG and PMTU behaviour.
pub(crate) struct PooledUdpDatagram {
    bytes: Option<BytesMut>,
    recycler: mpsc::Sender<BytesMut>,
}

impl PooledUdpDatagram {
    pub(crate) fn new(bytes: BytesMut, recycler: mpsc::Sender<BytesMut>) -> Self {
        Self {
            bytes: Some(bytes),
            recycler,
        }
    }
}

impl Deref for PooledUdpDatagram {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes
            .as_deref()
            .expect("UDP receive slot exists until drop")
    }
}

impl Drop for PooledUdpDatagram {
    fn drop(&mut self) {
        if let Some(mut bytes) = self.bytes.take() {
            bytes.clear();
            // There is one channel position per allocated slot. Full is therefore impossible
            // unless a programming error duplicated a slot; closed is normal during shutdown.
            let result = self.recycler.try_send(bytes);
            debug_assert!(!matches!(result, Err(mpsc::error::TrySendError::Full(_))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropped_datagram_recycles_the_same_cleared_allocation() {
        let (recycler, mut recycled) = mpsc::channel(1);
        let mut bytes = BytesMut::with_capacity(MAX_UDP_PACKET_SIZE);
        bytes.extend_from_slice(b"one datagram");
        let original_ptr = bytes.as_ptr();

        drop(PooledUdpDatagram::new(bytes, recycler));

        let bytes = recycled.recv().await.expect("receive slot is recycled");
        assert!(bytes.is_empty());
        assert_eq!(bytes.as_ptr(), original_ptr);
        assert!(bytes.capacity() >= MAX_UDP_PACKET_SIZE);
    }
}
