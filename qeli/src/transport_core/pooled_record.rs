//! Receive a framed record without reserving a shared packet slot during idle time.

use super::buffer_pool::{BufferPool, PooledBuffer};
use crate::protocol::packet::{read_record_into, Framing, PacketError};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Cancellation is terminal: once any byte has been consumed, the caller must drop
/// the stream rather than retry this operation. A cancelled/failed read returns its
/// pooled buffer through RAII. Only the one-byte prefix is retained while waiting
/// for a pool slot; idle readers reserve no packet allocations or permits.
pub(crate) async fn read_pooled_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    framing: Framing,
    pool: &BufferPool,
) -> Result<PooledBuffer, PacketError> {
    let mut prefix = [0u8; 1];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_| PacketError::ConnectionClosed)?;
    let mut packet = pool.acquire().await.ok_or(PacketError::ConnectionClosed)?;
    let mut prefixed = prefix.as_slice().chain(reader);
    read_record_into(&mut prefixed, framing, packet.as_vec_mut()).await?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packet::{PacketCodec, MAX_RECORD_SIZE, TLS_RECORD_HEADER};
    use tokio::io::AsyncWriteExt;

    fn pool() -> BufferPool {
        BufferPool::new(1, MAX_RECORD_SIZE + TLS_RECORD_HEADER).unwrap()
    }

    #[tokio::test]
    async fn idle_reader_leaves_shared_slot_available() {
        let pool = pool();
        let (_writer, mut reader) = tokio::io::duplex(64);
        let read = read_pooled_record(&mut reader, Framing::Tls, &pool);
        tokio::pin!(read);
        tokio::select! {
            biased;
            result = &mut read => panic!("idle read completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        assert!(
            pool.try_acquire().is_some(),
            "idle carrier reserved the shared slot"
        );
    }

    #[tokio::test]
    async fn prefix_preserves_consecutive_records_in_both_framings() {
        let key = [0x31; 32];
        for framing in [Framing::Tls, Framing::Raw] {
            let pool = pool();
            let make_codec = || match framing {
                Framing::Tls => PacketCodec::new(key),
                Framing::Raw => PacketCodec::new_raw(key),
            };
            let mut encoder = make_codec();
            let mut decoder = make_codec();
            let mut wire = Vec::new();
            for size in [1, 1400, 5000] {
                wire.extend_from_slice(&encoder.encrypt_packet(&vec![0x42; size], &[]).unwrap());
            }
            let mut reader = wire.as_slice();
            for size in [1, 1400, 5000] {
                let mut record = read_pooled_record(&mut reader, framing, &pool)
                    .await
                    .unwrap();
                decoder
                    .decrypt_packet_in_place(record.as_vec_mut())
                    .unwrap();
                assert_eq!(&*record, vec![0x42; size]);
            }
            assert!(matches!(
                read_pooled_record(&mut reader, framing, &pool).await,
                Err(PacketError::ConnectionClosed)
            ));
            assert!(pool.try_acquire().is_some());
        }
    }

    #[tokio::test]
    async fn terminal_cancel_of_partial_record_returns_slot() {
        let pool = pool();
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[0x17, 0x03, 0x03, 0, 32, 0xAA])
            .await
            .unwrap();
        {
            let read = read_pooled_record(&mut reader, Framing::Tls, &pool);
            tokio::pin!(read);
            tokio::select! {
                biased;
                result = &mut read => panic!("partial read completed: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
            assert!(pool.try_acquire().is_none());
        }
        drop(reader); // A partial read is never resumed or retried on this stream.
        assert!(pool.try_acquire().is_some());
    }

    #[tokio::test]
    async fn partial_eof_returns_slot() {
        let pool = pool();
        let mut reader = [0x17, 0x03, 0x03, 0, 32, 0xAA].as_slice();
        assert!(matches!(
            read_pooled_record(&mut reader, Framing::Tls, &pool).await,
            Err(PacketError::ConnectionClosed)
        ));
        assert!(pool.try_acquire().is_some());
    }
}
