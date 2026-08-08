//! Fixed-budget reusable buffers for transport data planes.
//!
//! A [`PooledBuffer`] owns one allocation until every queue consumer has finished with it.
//! Dropping the value returns that allocation to the pool, so queue depth and memory use are
//! bounded by the same fixed number of buffers. The pool never allocates a fallback buffer when
//! exhausted: async stream readers wait, while datagram callers may use [`BufferPool::try_acquire`]
//! and drop the datagram instead.

use std::io;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Clone)]
pub(crate) struct BufferPool {
    available: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    recycle: mpsc::Sender<Vec<u8>>,
}

impl BufferPool {
    pub(crate) fn new(buffer_count: usize, buffer_capacity: usize) -> io::Result<Self> {
        if buffer_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer pool capacity must be non-zero",
            ));
        }
        if buffer_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pooled buffer capacity must be non-zero",
            ));
        }

        let (recycle, available) = mpsc::channel(buffer_count);
        for _ in 0..buffer_count {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(buffer_capacity).map_err(|error| {
                io::Error::other(format!(
                    "could not reserve {buffer_capacity}-byte pooled buffer: {error}"
                ))
            })?;
            recycle
                .try_send(buffer)
                .expect("new buffer pool has every slot available");
        }

        Ok(Self {
            available: Arc::new(Mutex::new(available)),
            recycle,
        })
    }

    /// Wait for an existing allocation. No fallback allocation is ever created.
    pub(crate) async fn acquire(&self) -> Option<PooledBuffer> {
        let buffer = self.available.lock().await.recv().await?;
        Some(PooledBuffer::new(buffer, self.recycle.clone()))
    }

    /// Take an allocation without waiting. Intended for datagram receive loops that must keep
    /// servicing timers when the downstream writer is congested.
    pub(crate) fn try_acquire(&self) -> Option<PooledBuffer> {
        let mut available = self.available.try_lock().ok()?;
        let buffer = available.try_recv().ok()?;
        Some(PooledBuffer::new(buffer, self.recycle.clone()))
    }
}

/// One reusable allocation checked out from a [`BufferPool`].
pub(crate) struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    recycle: mpsc::Sender<Vec<u8>>,
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffer = self
            .buffer
            .as_ref()
            .expect("pooled allocation is present until drop");
        formatter
            .debug_struct("PooledBuffer")
            .field("len", &buffer.len())
            .field("capacity", &buffer.capacity())
            .finish()
    }
}

impl PooledBuffer {
    fn new(mut buffer: Vec<u8>, recycle: mpsc::Sender<Vec<u8>>) -> Self {
        buffer.clear();
        Self {
            buffer: Some(buffer),
            recycle,
        }
    }

    pub(crate) fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
            .as_mut()
            .expect("pooled allocation is present until drop")
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer
            .as_ref()
            .expect("pooled allocation is present until drop")
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut buffer) = self.buffer.take() {
            buffer.clear();
            // Exactly one slot was removed for this value, so Full would be a bookkeeping
            // bug. Closed is normal during connection teardown; dropping the allocation then
            // is correct.
            let _ = self.recycle.try_send(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn exhausted_pool_waits_and_reuses_returned_allocation() {
        let pool = BufferPool::new(2, 256).unwrap();
        let mut first = pool.acquire().await.unwrap();
        let second = pool.acquire().await.unwrap();
        first.as_vec_mut().extend_from_slice(b"first payload");
        let first_allocation = first.as_ptr();

        assert!(pool.try_acquire().is_none());
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await.unwrap() })
        };
        assert!(tokio::time::timeout(Duration::from_millis(50), async {
            while !waiter.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err());

        drop(first);
        let reused = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter did not resume after a buffer was returned")
            .unwrap();
        assert!(reused.is_empty());
        assert_eq!(reused.as_ptr(), first_allocation);

        drop(second);
        drop(reused);
    }

    #[test]
    fn invalid_pool_dimensions_are_rejected() {
        assert!(BufferPool::new(0, 128).is_err());
        assert!(BufferPool::new(4, 0).is_err());
    }
}
