use super::*;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn fixture() -> (String, PathBuf, PathBuf) {
    assert_eq!(std::env::var("QELI_AUDIT_PRIVATE_FS").as_deref(), Ok("1"));
    (
        std::env::var("QELI_AUDIT_IO_MODE").unwrap(),
        std::env::var_os("QELI_AUDIT_MARKER").unwrap().into(),
        std::env::var_os("QELI_AUDIT_RAN").unwrap().into(),
    )
}
async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
fn assert_context_removed(marker: &Path) {
    let name = std::fs::read_to_string(marker).unwrap();
    assert!(name.starts_with("/tmp/qeli-hook-"), "{name}");
    assert!(
        !Path::new(name.trim()).exists(),
        "context outlived hook owner"
    );
}

#[test]
#[ignore = "requires private /tmp and the audit file-I/O preload shim"]
fn native_hook_file_io_keeps_executor_live() {
    let (mode, marker, _) = fixture();
    assert!(matches!(mode.as_str(), "hook-write" | "hook-unlink"));
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
            let start = std::time::Instant::now();
            let result = run_with_context(
                "io-fixture",
                "test -r \"$QELI_CONTEXT_FILE\"",
                &[],
                &[],
                Some("{}"),
            )
            .await;
            let elapsed = start.elapsed();
            let observed = ticks.load(Ordering::Relaxed);
            eprintln!("hook {mode}: elapsed={elapsed:?}, heartbeat={observed}");
            heartbeat.abort();
            let _ = heartbeat.await;
            assert_eq!(result, HookStatus::Success);
            assert!(
                elapsed >= Duration::from_secs(1),
                "shim did not delay file I/O"
            );
            assert_context_removed(&marker);
            assert!(
                observed >= 20,
                "hook file I/O blocked current-thread executor: {observed} ticks"
            );
        });
}

#[test]
#[ignore = "requires private /tmp and the audit file-I/O preload shim"]
fn native_cancel_during_hook_preparation_joins_cleanup_without_spawn() {
    let (mode, marker, ran) = fixture();
    assert_eq!(mode, "hook-write");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let output = ran.clone();
            let task = tokio::spawn(async move {
                run_with_context(
                    "cancel-prepare",
                    "printf ran > \"$QELI_AUDIT_RAN\"",
                    &[(
                        "QELI_AUDIT_RAN".into(),
                        output.to_string_lossy().into_owned(),
                    )],
                    &[],
                    Some("{}"),
                )
                .await
            });
            wait_file(&marker).await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_context_removed(&marker);
            assert!(!ran.exists(), "cancelled preparation spawned its command");
        });
}

#[test]
#[ignore = "requires private /tmp; checks real process cancellation and reaping"]
fn native_cancel_running_hook_reaps_before_context_cleanup_returns() {
    let (_, marker, pid_file) = fixture();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let marker_arg = marker.clone(); let pid_arg = pid_file.clone();
        let task = tokio::spawn(async move {
            run_with_context("cancel-running", "printf '%s' \"$QELI_CONTEXT_FILE\" > \"$QELI_AUDIT_MARKER\"; printf '%s' \"$$\" > \"$QELI_AUDIT_RAN\"; exec sleep 60",
                &[("QELI_AUDIT_MARKER".into(), marker_arg.to_string_lossy().into_owned()), ("QELI_AUDIT_RAN".into(), pid_arg.to_string_lossy().into_owned())], &[], Some("{}")).await
        });
        wait_file(&pid_file).await;
        let pid: libc::pid_t = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        task.abort(); assert!(task.await.unwrap_err().is_cancelled());
        assert_context_removed(&marker);
        assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    });
}

#[tokio::test]
async fn hook_worker_reports_panic_without_stranding_waiter() {
    let error = worker::run(|_| async { panic!("hook worker fixture") })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("panicked"));
}
