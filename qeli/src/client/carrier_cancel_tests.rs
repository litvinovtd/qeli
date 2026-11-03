use super::*;

#[tokio::test]
async fn stopped_carrier_is_never_polled() {
    let result: anyhow::Result<()> =
        connect_before_tunnel(Arc::new(AtomicBool::new(true)), async {
            panic!("cancelled carrier must not begin")
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn stopping_pending_carrier_drops_its_resources() {
    struct Owned(Arc<AtomicBool>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let stopped = cancel.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = dropped.clone();
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(connect_before_tunnel(cancel, async move {
        let _owned = Owned(dropped);
        ready.send(()).unwrap();
        std::future::pending::<anyhow::Result<()>>().await
    }));
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();
    stopped.store(true, Ordering::Release);
    assert!(tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert!(observed.load(Ordering::Acquire));
}
