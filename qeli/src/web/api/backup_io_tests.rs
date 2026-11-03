use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[test]
fn expired_preflight_does_not_open_config() {
    let (status, message) = backup_preflight("/does/not/exist", Instant::now()).unwrap_err();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(message.contains("timed out"));
}

#[test]
fn preflight_rejects_fifo_without_waiting_for_writer() {
    let path = std::env::temp_dir().join(format!("qeli-backup-fifo-{}", rand::random::<u64>()));
    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let result = backup_preflight(
        path.to_str().unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    std::fs::remove_file(path).unwrap();
    let (status, message) = result.unwrap_err();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(message.contains("regular file"));
}

#[test]
#[ignore = "requires private /etc/qeli and /tmp, plus audit file-I/O preload shim"]
fn native_backup_preflight_io_and_cancel_ownership() {
    assert_eq!(std::env::var("QELI_AUDIT_PRIVATE_FS").as_deref(), Ok("1"));
    let mode = std::env::var("QELI_AUDIT_IO_MODE").unwrap();
    assert_eq!(mode, "backup-read");
    let cancel = std::env::var("QELI_AUDIT_CANCEL").is_ok_and(|v| v == "1");
    let marker = std::path::PathBuf::from(std::env::var_os("QELI_AUDIT_MARKER").unwrap());
    let raw = "[auth]\nusers_file=/etc/qeli/users.conf\n[web]\nenabled=false\ntls=false\n[profile:test]\nidentity_key=/etc/qeli/test.key\nbind.port=443\ntun.name=vpn0\ntun.address=10.73.0.1\npool.cidr=10.73.0.0/24\nobf.mode=fake-tls\n";
    let config = crate::config::parse_server_config(raw).unwrap();
    std::fs::write("/etc/qeli/server.ini", raw).unwrap();
    std::fs::write("/etc/qeli/users.conf", "").unwrap();
    std::fs::write("/etc/qeli/test.key", [42u8; 32]).unwrap();
    let state = crate::server::test_api_state(config, Path::new("/etc/qeli/server.ini"));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let ticks = Arc::new(AtomicUsize::new(0));
            let counter = ticks.clone();
            let heartbeat = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            });
            let start = Instant::now();
            let request = tokio::spawn(download_backup(
                axum::extract::State(state.clone()),
                auth::AuthGuard,
            ));
            if cancel {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !marker.exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
                request.abort();
                assert!(request.await.unwrap_err().is_cancelled());
                assert!(
                    state.config_write_lock.try_lock().is_err(),
                    "cancelled preflight released live transaction"
                );
                let _next =
                    tokio::time::timeout(Duration::from_secs(5), state.config_write_lock.lock())
                        .await
                        .unwrap();
            } else {
                let response = request.await.unwrap().unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), PORTABLE_ARCHIVE_LIMIT)
                    .await
                    .unwrap();
                assert!(bytes.starts_with(&[0x1f, 0x8b]));
            }
            let observed = ticks.load(Ordering::Relaxed);
            eprintln!(
                "backup cancel={cancel}: elapsed={:?}, heartbeat={observed}",
                start.elapsed()
            );
            heartbeat.abort();
            let _ = heartbeat.await;
            assert!(marker.exists(), "shim did not intercept config read");
            assert!(start.elapsed() >= Duration::from_secs(1));
            assert!(
                observed >= 20,
                "backup preflight blocked current-thread executor: {observed} ticks"
            );
            assert_eq!(
                std::fs::read_to_string("/etc/qeli/server.ini").unwrap(),
                raw
            );
        });
}
