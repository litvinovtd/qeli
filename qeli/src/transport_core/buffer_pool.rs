//! Fixed-budget reusable buffers for transport data planes.
//!
//! A [`PooledBuffer`] owns one allocation until every queue consumer has finished with it.
//! Dropping the value returns that allocation to the pool, so queue depth and memory use are
//! bounded by the same fixed number of buffers. The pool never allocates a fallback buffer when
//! exhausted: async stream readers wait, while datagram callers may use [`BufferPool::try_acquire`]
//! and drop the datagram instead.

use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::Semaphore;

/// Reserve room for the other carriers and one temporary resume candidate.
/// A single stalled queue must never retain the session's entire packet pool.
pub(crate) fn bonded_queue_capacity(buffer_count: usize, max_streams: u32) -> usize {
    if max_streams <= 1 {
        return buffer_count.max(1);
    }
    (buffer_count.saturating_sub(1) / (max_streams as usize + 1)).max(1)
}

#[derive(Clone)]
pub(crate) struct BufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    available: Mutex<Vec<Vec<u8>>>,
    permits: Arc<Semaphore>,
    buffer_count: usize,
    buffer_capacity: usize,
}

impl PoolInner {
    fn available(&self) -> MutexGuard<'_, Vec<Vec<u8>>> {
        self.available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn take_buffer(&self) -> io::Result<Vec<u8>> {
        if let Some(buffer) = self.available().pop() {
            return Ok(buffer);
        }
        // A held permit reserves a slot even when its buffer has not been allocated yet.
        // Allocation failure returns the permit through its guard; it cannot lose capacity.
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(self.buffer_capacity)
            .map_err(|error| {
                io::Error::other(format!(
                    "could not reserve {}-byte pooled buffer: {error}",
                    self.buffer_capacity
                ))
            })?;
        Ok(buffer)
    }
}

impl BufferPool {
    pub(crate) fn new(buffer_count: usize, buffer_capacity: usize) -> io::Result<Self> {
        Self::with_initial_buffers(buffer_count, buffer_capacity, buffer_count)
    }

    /// Reserve queue slots now, but allocate packet storage only when traffic uses a slot.
    /// Idle authenticated server sessions keep the same maximum queue budget without
    /// reserving several MiB of packet allocations that they may never use.
    #[cfg(any(test, feature = "server"))]
    pub(crate) fn new_lazy(buffer_count: usize, buffer_capacity: usize) -> io::Result<Self> {
        Self::with_initial_buffers(buffer_count, buffer_capacity, 0)
    }

    fn with_initial_buffers(
        buffer_count: usize,
        buffer_capacity: usize,
        initial_buffers: usize,
    ) -> io::Result<Self> {
        if buffer_count == 0 || buffer_count > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer pool count must fit the semaphore and be non-zero",
            ));
        }
        if buffer_capacity == 0 || buffer_capacity > isize::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pooled buffer capacity must fit an allocation and be non-zero",
            ));
        }

        let mut available = Vec::new();
        available.try_reserve_exact(buffer_count).map_err(|error| {
            io::Error::other(format!("could not reserve pool slot metadata: {error}"))
        })?;
        for _ in 0..initial_buffers {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(buffer_capacity).map_err(|error| {
                io::Error::other(format!(
                    "could not reserve {buffer_capacity}-byte pooled buffer: {error}"
                ))
            })?;
            available.push(buffer);
        }

        Ok(Self {
            inner: Arc::new(PoolInner {
                available: Mutex::new(available),
                permits: Arc::new(Semaphore::new(buffer_count)),
                buffer_count,
                buffer_capacity,
            }),
        })
    }

    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    pub(crate) fn buffer_count(&self) -> usize {
        self.inner.buffer_count
    }

    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    pub(crate) fn buffer_capacity(&self) -> usize {
        self.inner.buffer_capacity
    }

    /// Reserve a pool slot, waiting when all slots are borrowed. Lazy pools allocate
    /// a slot on first use; exhausted pools never allocate a fallback slot.
    pub(crate) async fn acquire(&self) -> Option<PooledBuffer> {
        let permit = self.inner.permits.clone().acquire_owned().await.ok()?;
        let buffer = self.inner.take_buffer().ok()?;
        permit.forget();
        Some(PooledBuffer::new(buffer, self.inner.clone()))
    }

    /// Take an allocation without waiting. Intended for datagram receive loops that must keep
    /// servicing timers when the downstream writer is congested.
    pub(crate) fn try_acquire(&self) -> Option<PooledBuffer> {
        self.try_acquire_with(|| self.inner.take_buffer())
    }

    fn try_acquire_with(
        &self,
        take_buffer: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> Option<PooledBuffer> {
        let permit = self.inner.permits.clone().try_acquire_owned().ok()?;
        let buffer = take_buffer().ok()?;
        permit.forget();
        Some(PooledBuffer::new(buffer, self.inner.clone()))
    }
}

/// One reusable allocation checked out from a [`BufferPool`].
pub(crate) struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<PoolInner>,
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
    fn new(mut buffer: Vec<u8>, pool: Arc<PoolInner>) -> Self {
        buffer.clear();
        Self {
            buffer: Some(buffer),
            pool,
        }
    }

    pub(crate) fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        self.buffer
            .as_mut()
            .expect("pooled allocation is present until drop")
    }

    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    pub(crate) fn capacity(&self) -> usize {
        self.buffer
            .as_ref()
            .expect("pooled allocation is present until drop")
            .capacity()
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
            {
                let mut available = self.pool.available();
                debug_assert!(available.len() < self.pool.buffer_count);
                available.push(buffer);
            }
            self.pool.permits.add_permits(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stalled_bonded_queue_cannot_exhaust_the_shared_packet_pool() {
        let pool = BufferPool::new(64, 128).unwrap();
        let capacity = bonded_queue_capacity(pool.buffer_count(), 3);
        let (stalled, _receiver) = tokio::sync::mpsc::channel::<PooledBuffer>(capacity);
        for _ in 0..pool.buffer_count() {
            let packet = pool.try_acquire().expect("stalled queue must leave room");
            let _ = stalled.try_send(packet);
        }
        let (healthy, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut packet = pool
            .try_acquire()
            .expect("healthy carrier retains capacity");
        packet.as_vec_mut().extend_from_slice(b"healthy flow");
        assert!(healthy.try_send(packet).is_ok());
        assert_eq!(receiver.recv().await.unwrap().as_ref(), b"healthy flow");
        drop(stalled);
        drop(_receiver);
        assert_eq!(pool.inner.permits.available_permits(), pool.buffer_count());
    }

    #[test]
    fn bonded_queue_share_reserves_space_without_multiplying_the_pool() {
        for budget in [4, 16, 64, 128, 256, 2048] {
            assert_eq!(bonded_queue_capacity(budget, 1), budget);
            for streams in 2..=16 {
                let capacity = bonded_queue_capacity(budget, streams);
                assert!(capacity > 0 && capacity < budget);
                if budget > streams as usize + 1 {
                    assert!(capacity * (streams as usize + 1) < budget);
                }
            }
        }
    }

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
    fn lazy_pool_allocates_only_borrowed_slots_and_reuses_them() {
        let pool = BufferPool::new_lazy(4096, 2048).unwrap();
        assert!(pool.inner.available().is_empty());
        assert_eq!(pool.inner.permits.available_permits(), 4096);
        let mut packet = pool.try_acquire().unwrap();
        packet.as_vec_mut().extend_from_slice(b"packet");
        let allocation = packet.as_ptr();
        drop(packet);
        assert_eq!(pool.inner.available().len(), 1);
        let packet = pool.try_acquire().unwrap();
        assert_eq!(packet.as_ptr(), allocation);
        assert!(packet.is_empty());
        drop(packet);
        assert_eq!(pool.inner.available().len(), 1);
    }

    #[test]
    fn failed_lazy_allocation_returns_the_reserved_permit() {
        let pool = BufferPool::new_lazy(1, 64).unwrap();
        assert!(pool
            .try_acquire_with(|| Err(io::Error::other("injected allocation failure")))
            .is_none());
        assert_eq!(pool.inner.permits.available_permits(), 1);
        assert!(pool.inner.available().is_empty());
        let packet = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
        drop(packet);
        assert_eq!(pool.inner.permits.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_pool_stays_bounded_under_concurrent_borrow() {
        let pool = BufferPool::new_lazy(3, 128).unwrap();
        let mut tasks = Vec::new();
        for id in 0..12u8 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..64 {
                    let mut packet = pool.acquire().await.unwrap();
                    packet.as_vec_mut().extend_from_slice(&[id; 128]);
                    tokio::task::yield_now().await;
                    assert_eq!(packet.as_ref(), &[id; 128]);
                    drop(packet);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(pool.inner.permits.available_permits(), 3);
        assert!(pool.inner.available().len() <= 3);
    }

    #[tokio::test]
    async fn cancelled_lazy_waiter_preserves_all_pool_slots() {
        let pool = BufferPool::new_lazy(1, 64).unwrap();
        let packet = pool.acquire().await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        drop(packet);
        assert!(pool.try_acquire().is_some());
        assert_eq!(pool.inner.permits.available_permits(), 1);
    }

    #[test]
    fn invalid_pool_dimensions_are_rejected() {
        assert!(BufferPool::new(0, 128).is_err());
        assert!(BufferPool::new(4, 0).is_err());
        assert!(BufferPool::new_lazy(0, 128).is_err());
        assert!(BufferPool::new_lazy(4, 0).is_err());
        assert!(BufferPool::new_lazy(usize::MAX, 128).is_err());
        assert!(BufferPool::new_lazy(4, usize::MAX).is_err());
    }
}
