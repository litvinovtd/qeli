//! Keep the config write lease with blocking work, including after request cancellation.
use tokio::sync::OwnedMutexGuard;

/// Return the guard to the caller so a multi-stage transaction stays exclusive between
/// blocking phases. If the caller is dropped, Tokio drops this result only after the
/// blocking operation finishes; dropping a JoinHandle does not stop that operation.
pub(crate) async fn blocking<T: Send + 'static>(
    guard: OwnedMutexGuard<()>,
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<(OwnedMutexGuard<()>, T), tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || {
        let result = operation();
        (guard, result)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;
    use tokio::sync::{oneshot, Mutex};

    const LIMIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn cancelled_request_cannot_release_an_active_writer() {
        let lock = Arc::new(Mutex::new(()));
        let guard = lock.clone().lock_owned().await;
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let request = tokio::spawn(blocking(guard, move || {
            started_tx.send(()).unwrap();
            // A bounded gate also releases the test worker if an assertion fails.
            finish_rx.recv_timeout(LIMIT).unwrap();
        }));
        tokio::time::timeout(LIMIT, started_rx)
            .await
            .unwrap()
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        let still_exclusive = lock.try_lock().is_err();
        finish_tx.send(()).unwrap();
        let _next_writer = tokio::time::timeout(LIMIT, lock.lock()).await.unwrap();
        assert!(
            still_exclusive,
            "cancelled request exposed files still being mutated"
        );
    }

    #[tokio::test]
    async fn returned_lease_keeps_successive_backup_phases_exclusive() {
        let lock = Arc::new(Mutex::new(()));
        let guard = lock.clone().lock_owned().await;
        let (guard, bytes) = blocking(guard, || vec![1, 2, 3]).await.unwrap();
        assert!(lock.try_lock().is_err());
        let (guard, result) = blocking(guard, move || {
            assert_eq!(bytes, [1, 2, 3]);
            Err::<(), _>("archive validation failed")
        })
        .await
        .unwrap();
        assert_eq!(result, Err("archive validation failed"));
        assert!(lock.try_lock().is_err());
        drop(guard);
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn panicking_worker_releases_the_lease() {
        let lock = Arc::new(Mutex::new(()));
        let guard = lock.clone().lock_owned().await;
        assert!(blocking(guard, || panic!("injected worker failure"))
            .await
            .unwrap_err()
            .is_panic());
        assert!(lock.try_lock().is_ok());
    }
}
