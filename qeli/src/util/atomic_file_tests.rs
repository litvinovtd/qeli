//! Publication boundaries: failed preparation keeps the old file; failed directory
//! sync reports uncertainty after publication. Linux additionally injects a real
//! partial-write error in a disposable subprocess, never changing test-runner limits.
use super::*;
use std::{io, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qeli-atomic-fault-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn no_temporary_files(&self) {
        assert!(
            std::fs::read_dir(&self.0).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".qeli-tmp-")),
            "incomplete temporary file survived"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn rename_failure_preserves_destination_and_removes_prepared_file() {
    let f = Fixture::new();
    let path = f.0.join("destination");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("sentinel"), b"keep").unwrap();
    assert!(write_atomic_private(&path, b"new state").is_err());
    assert_eq!(std::fs::read(path.join("sentinel")).unwrap(), b"keep");
    f.no_temporary_files();
}
#[test]
fn directory_sync_failure_reports_published_data_and_allows_retry() {
    let f = Fixture::new();
    let path = f.0.join("state");
    std::fs::write(&path, b"old").unwrap();
    let error = write_atomic_with_sync(&path, b"new", true, |_| {
        Err(io::Error::other("injected directory I/O failure"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("published"));
    assert!(error.to_string().contains("persistence is uncertain"));
    assert!(atomic_write_was_published(&error));
    assert!(atomic_write_was_published(
        &error.context("users transaction")
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    f.no_temporary_files();
    write_atomic_private(&path, b"retry").unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"retry");
    f.no_temporary_files();
}
#[test]
fn parent_open_failure_never_publishes_or_creates_directories() {
    let f = Fixture::new();
    let parent = f.0.join("missing");
    assert!(write_atomic_private(parent.join("state"), b"new").is_err());
    assert!(!parent.exists());
    assert_eq!(std::fs::read_dir(&f.0).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn native_partial_write_failure_does_not_leave_private_fragments() {
    let f = Fixture::new();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "util::atomic_file_tests::file_size_limit_child",
            "--nocapture",
        ])
        .env("QELI_TEST_ATOMIC_FILE_LIMIT", &f.0);
    let output = crate::system_command::Command::from(child)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    f.no_temporary_files();
}
#[cfg(target_os = "linux")]
#[test]
fn file_size_limit_child() {
    let Some(dir) = std::env::var_os("QELI_TEST_ATOMIC_FILE_LIMIT") else {
        return;
    };
    let f = Fixture(PathBuf::from(dir));
    let existing = f.0.join("existing");
    std::fs::write(&existing, b"original").unwrap();
    // This test is explicitly selected in a separate process; no other test or
    // application thread shares its signal disposition or resource limit.
    let limit = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1024,
    };
    unsafe {
        assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
    for (path, private) in [
        (&existing, false),
        (&existing, true),
        (&f.0.join("absent"), true),
    ] {
        let error = write_atomic_inner(path, &vec![b'x'; 8192], private).unwrap_err();
        assert!(
            error.to_string().contains("write"),
            "unexpected error: {error}"
        );
        assert_eq!(std::fs::read(&existing).unwrap(), b"original");
        assert!(!f.0.join("absent").exists());
        f.no_temporary_files();
    }
    // Parent owns this directory and verifies it again after the subprocess exits.
    std::mem::forget(f);
}
