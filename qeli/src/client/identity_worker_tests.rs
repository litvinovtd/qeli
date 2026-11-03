use super::*;
use std::time::Duration;

fn cancel() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
fn blocked(fail: bool) -> (Verifier, Worker, oneshot::Receiver<()>, mpsc::Sender<()>) {
    let (started, entered) = oneshot::channel();
    let mut started = Some(started);
    let (release, wait) = mpsc::channel();
    let (verifier, worker) = Worker::start(move |_| {
        let _ = started.take().unwrap().send(());
        wait.recv().unwrap();
        if fail {
            anyhow::bail!("late fsync failure")
        }
        Ok(())
    })
    .unwrap();
    (verifier, worker, entered, release)
}
#[tokio::test]
async fn cancelled_or_unpolled_request_never_reaches_storage() {
    let (verifier, mut worker) = Worker::start(|_| panic!("not admitted")).unwrap();
    drop(verifier.verify([1; 32], cancel()));
    assert!(verifier
        .verify([1; 32], Arc::new(AtomicBool::new(true)))
        .await
        .is_err());
    verifier.drain().await.unwrap();
    worker.finish().await.unwrap();
}
#[tokio::test]
async fn handshake_timeout_keeps_executor_live_and_retains_late_failure() {
    let (verifier, mut worker, entered, release) = blocked(true);
    let request = verifier.clone();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_millis(80), request.verify([1; 32], cancel())).await
    });
    entered.await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), verifier.drain())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    assert!(verifier
        .drain()
        .await
        .unwrap_err()
        .to_string()
        .contains("late fsync failure"));
    worker.finish().await.unwrap();
}
#[tokio::test]
async fn delivered_but_unpolled_error_is_not_lost() {
    use std::future::Future;
    let (verifier, mut worker, entered, release) = blocked(true);
    let mut request = Box::pin(verifier.verify([1; 32], cancel()));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(request.as_mut().poll(&mut cx).is_pending());
    entered.await.unwrap();
    release.send(()).unwrap();
    // Wait for the send/worker exit without polling the response. This proves the
    // delivered-but-unobserved branch without relying on scheduler timing.
    worker.shared.close();
    worker.completion.take().unwrap().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), worker.finish())
            .await
            .is_err()
    );
    drop(request);
    assert!(worker
        .finish()
        .await
        .unwrap_err()
        .to_string()
        .contains("late fsync failure"));
}
#[tokio::test]
async fn observed_error_is_returned_once() {
    let (verifier, mut worker) = Worker::start(|_| anyhow::bail!("known pin mismatch")).unwrap();
    assert!(verifier
        .verify([1; 32], cancel())
        .await
        .unwrap_err()
        .to_string()
        .contains("known pin mismatch"));
    verifier.drain().await.unwrap();
    worker.finish().await.unwrap();
}
#[tokio::test]
async fn waiting_request_is_cancelled_without_queueing_another_write() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let (started, entered) = oneshot::channel();
    let mut started = Some(started);
    let (release, wait) = mpsc::channel();
    let (verifier, mut worker) = Worker::start(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        started.take().unwrap().send(()).unwrap();
        wait.recv().unwrap();
        Ok(())
    })
    .unwrap();
    let first = verifier.clone();
    let task = tokio::spawn(async move { first.verify([1; 32], cancel()).await });
    entered.await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        verifier.verify([2; 32], cancel())
    )
    .await
    .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
    verifier.drain().await.unwrap();
    worker.finish().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn cancelled_finish_can_be_resumed_and_closes_admission() {
    let (verifier, mut worker, entered, release) = blocked(false);
    let first = verifier.clone();
    let task = tokio::spawn(async move { first.verify([1; 32], cancel()).await });
    entered.await.unwrap();
    task.abort();
    let _ = task.await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), worker.finish())
            .await
            .is_err()
    );
    assert!(verifier.verify([2; 32], cancel()).await.is_err());
    release.send(()).unwrap();
    worker.finish().await.unwrap();
}
#[tokio::test]
async fn stop_after_admission_waits_for_successful_write() {
    let (verifier, mut worker, entered, release) = blocked(false);
    let stop = cancel();
    let signal = stop.clone();
    let first = verifier.clone();
    let task = tokio::spawn(async move { first.verify([1; 32], signal).await });
    entered.await.unwrap();
    stop.store(true, Ordering::Release);
    assert!(tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), verifier.drain())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    verifier.drain().await.unwrap();
    worker.finish().await.unwrap();
}
#[tokio::test]
async fn worker_panic_closes_admission_and_is_reported_on_join() {
    let (verifier, mut worker) = Worker::start(|_| panic!("injected verifier panic")).unwrap();
    assert!(verifier.verify([1; 32], cancel()).await.is_err());
    assert!(verifier.verify([2; 32], cancel()).await.is_err());
    assert!(worker
        .finish()
        .await
        .unwrap_err()
        .to_string()
        .contains("panicked"));
}
#[tokio::test]
async fn forced_owner_drop_joins_admitted_work() {
    let (verifier, worker, entered, release) = blocked(false);
    let first = verifier.clone();
    let task = tokio::spawn(async move { first.verify([1; 32], cancel()).await });
    entered.await.unwrap();
    task.abort();
    let _ = task.await;
    let (joined, done) = oneshot::channel();
    let dropper = std::thread::spawn(move || {
        drop(worker);
        joined.send(()).unwrap();
    });
    let mut done = Box::pin(done);
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut done)
        .await
        .is_err());
    release.send(()).unwrap();
    done.await.unwrap();
    dropper.join().unwrap();
    assert!(verifier.verify([2; 32], cancel()).await.is_err());
}
