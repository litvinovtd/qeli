use super::*;
const CONFIG: &str =
    "[qeli]\nserver = 127.0.0.1:443\nproto = tcp\nuser = test\npass = secret\nmode = fake-tls\n";
#[tokio::test]
async fn device_fallback_is_cached_for_the_entire_adapter_lifetime() {
    let dir = identity_files::tests::Directory::new();
    let (mut core, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
    assert!(core.device_id().is_err());
    assert!(core
        .load_device_identity(dir.path().to_str().unwrap().into(), std::future::pending())
        .await
        .unwrap());
    let id = core.device_id().unwrap();
    let other = dir.path().join("different");
    std::fs::write(&other, [0x55; crate::protocol::DEVICE_ID_LEN]).unwrap();
    assert!(core
        .load_device_identity(other.to_str().unwrap().into(), std::future::pending())
        .await
        .unwrap());
    assert_eq!(core.device_id().unwrap(), id);
}
#[tokio::test]
async fn cancelled_identity_admission_never_touches_the_file() {
    let dir = identity_files::tests::Directory::new();
    let path = dir.path().join("id");
    let (mut core, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
    assert!(!core
        .load_device_identity(path.to_str().unwrap().into(), std::future::ready(()))
        .await
        .unwrap());
    assert!(core.device_id().is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[tokio::test]
async fn stop_during_identity_lock_awaits_the_worker_without_stalling_runtime() {
    let dir = identity_files::tests::Directory::new();
    let path = dir.path().join("id");
    let lock = crate::util::FileLock::acquire(&path).unwrap();
    let (mut core, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    let mut load = Box::pin(
        core.load_device_identity(path.to_str().unwrap().into(), async move {
            while !stop.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }),
    );
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut load)
        .await
        .is_err());
    cancel.store(true, Ordering::Release);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut load)
        .await
        .is_err());
    assert!(!path.exists());
    drop(lock);
    assert!(tokio::time::timeout(Duration::from_secs(5), &mut load)
        .await
        .unwrap()
        .unwrap());
    drop(load);
    assert_eq!(std::fs::read(&path).unwrap(), core.device_id().unwrap());
}
