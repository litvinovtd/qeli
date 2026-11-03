//! Bounded handoff from a dedicated TUN reader thread to its async forwarder.
use tokio::sync::mpsc::{
    error::{SendError, TrySendError},
    Sender,
};

/// Avoid Tokio's blocking-send wrapper when the queue has spare capacity.
/// A full queue still applies the same backpressure and retains the same packet;
/// neither the channel capacity nor the pool budget is enlarged. Call only from
/// a dedicated blocking reader thread: the full-queue fallback can park it.
pub(super) fn send<T>(sender: &Sender<T>, packet: T) -> Result<(), SendError<T>> {
    match sender.try_send(packet) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(packet)) => sender.blocking_send(packet),
        Err(TrySendError::Closed(packet)) => Err(SendError(packet)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_core::buffer_pool::BufferPool;
    use std::time::Duration;

    #[tokio::test]
    async fn spare_capacity_does_not_enter_a_blocking_runtime() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        send(&tx, 7).unwrap();
        assert_eq!(rx.recv().await, Some(7));
        assert_eq!(tx.capacity(), 1);
    }

    #[tokio::test]
    async fn full_queue_keeps_backpressure_and_fifo_order() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(1).unwrap();
        let (finished, mut result) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let _ = finished.send(send(&tx, 2));
        });
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut result)
            .await
            .is_err());
        assert_eq!(rx.len(), 1);
        assert_eq!(rx.recv().await, Some(1));
        tokio::time::timeout(Duration::from_secs(5), result)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(rx.recv().await, Some(2));
        assert_eq!(rx.recv().await, None);
        thread.join().unwrap();
    }

    #[test]
    fn closed_queue_returns_the_same_loan_until_caller_drops_it() {
        let pool = BufferPool::new(1, 1400).unwrap();
        let packet = pool.try_acquire().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let error = send(&tx, packet).err().unwrap();
        assert!(pool.try_acquire().is_none());
        drop(error);
        assert!(pool.try_acquire().is_some());
    }
}
