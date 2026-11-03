//! Bounded pre-logger INI loading shared by both Linux client entry points.
//! File-output trust belongs to the same opened inode as these config bytes.
use std::path::Path;
use zeroize::Zeroizing;

/// The validation CLI reads the same bounded regular-file snapshot as runtime.
/// Validation does not execute file commands; credentials are wiped on drop.
pub fn read_config_text(path: &Path) -> std::io::Result<Zeroizing<String>> {
    let (snapshot, _) = crate::config_source::load_client(path)?;
    Ok(Zeroizing::new(snapshot.into_parts().0))
}

/// Inspect a valid client profile before initializing the process logger.
/// Invalid/unreadable profiles keep diagnostics on stderr and are rejected by
/// the normal runtime loader. A symlink or untrusted file cannot select a sink.
pub fn peek_logging(path: &Path) -> (String, Option<String>, String) {
    let fallback = || ("info".to_string(), None, "datetime".to_string());
    let Ok((snapshot, _)) = crate::config_source::load_client(path) else {
        return fallback();
    };
    let (contents, trust) = snapshot.into_parts();
    let contents = Zeroizing::new(contents);
    let Ok(config) = crate::config::parse_client_config_strict(&contents) else {
        return fallback();
    };
    let logging = config.logging.clone();
    let file = logging.file.and_then(|path| match trust.check() {
        Ok(()) => Some(path),
        Err(reason) => {
            eprintln!("qeli: ignoring logging.file — {reason}");
            None
        }
    });
    (logging.level, file, logging.time_format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    use std::time::{Duration, Instant};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-cli-bootstrap-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn config(&self, text: &str, mode: u32) -> std::path::PathBuf {
            let path = self.0.join("client.ini");
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
        fn text(&self) -> String {
            format!("[QELI]\nSERVER = 127.0.0.1:1\nUSER = fixture\nPASS = fixture-only\nKEY = {}\nMODE = plain\nRECONNECT = false\n[LoGgInG]\nLEVEL = debug\nFILE = {}\nTIME_FORMAT = none\n", "11".repeat(32), self.0.join("sink.log").display())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn trusted_mixed_case_logging_matches_runtime_parser() {
        let fixture = Fixture::new();
        let text = fixture.text();
        let path = fixture.config(&text, 0o600);
        let runtime = crate::config::parse_client_config_strict(&text).unwrap();
        assert_eq!(
            peek_logging(&path),
            (
                runtime.logging.level.clone(),
                runtime.logging.file.clone(),
                runtime.logging.time_format.clone()
            )
        );
        assert_eq!(peek_logging(&path).0, "debug");
        assert!(!fixture.0.join("sink.log").exists());
    }

    #[test]
    fn untrusted_and_symlink_configs_cannot_choose_file_output() {
        let fixture = Fixture::new();
        let path = fixture.config(&fixture.text(), 0o666);
        let (level, file, time) = peek_logging(&path);
        assert_eq!((level.as_str(), time.as_str()), ("debug", "none"));
        assert!(file.is_none());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(peek_logging(&path).1.is_some());
        let link = fixture.0.join("linked.ini");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(peek_logging(&link).1.is_none());
        assert!(!fixture.0.join("sink.log").exists());
    }

    #[test]
    fn logging_and_validation_share_exact_file_limit() {
        let fixture = Fixture::new();
        let mut text = fixture.text();
        text.push('#');
        text.extend(std::iter::repeat_n(
            'x',
            crate::transport_core::MAX_CONFIG_BYTES - text.len(),
        ));
        let path = fixture.config(&text, 0o600);
        assert_eq!(
            read_config_text(&path).unwrap().len(),
            crate::transport_core::MAX_CONFIG_BYTES
        );
        assert!(peek_logging(&path).1.is_some());
        // Reject by size before decoding invalid UTF-8 or reading the declared sink.
        std::fs::write(
            &path,
            vec![0xff; crate::transport_core::MAX_CONFIG_BYTES + 1],
        )
        .unwrap();
        assert!(read_config_text(&path)
            .unwrap_err()
            .to_string()
            .contains("maximum is 262144"));
        assert_eq!(
            peek_logging(&path),
            ("info".to_string(), None, "datetime".to_string())
        );
        assert!(!fixture.0.join("sink.log").exists());
    }

    #[test]
    fn malformed_profile_does_not_select_log_sink() {
        let fixture = Fixture::new();
        let path = fixture.config(
            &format!("{}\n[qeli]\nunknown_key = forbidden\n", fixture.text()),
            0o600,
        );
        assert_eq!(
            peek_logging(&path),
            ("info".to_string(), None, "datetime".to_string())
        );
        assert!(!fixture.0.join("sink.log").exists());
    }

    #[test]
    fn fifo_log_sink_is_rejected_with_and_without_a_reader() {
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        let path = fixture.0.join("fifo.log");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(crate::logging::RotatingLog::open(&path).is_err());
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        assert_eq!(
            crate::logging::RotatingLog::open(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn regular_log_sink_creates_parents_and_preserves_append_behavior() {
        use std::io::Write;
        let fixture = Fixture::new();
        let path = fixture.0.join("logs/client.log");
        crate::logging::RotatingLog::open(&path)
            .unwrap()
            .write_all(b"first\n")
            .unwrap();
        crate::logging::RotatingLog::open(&path)
            .unwrap()
            .write_all(b"second\n")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        let fixture = Fixture::new();
        let path = fixture.0.join("fifo.ini");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(read_config_text(&path).is_err());
        assert_eq!(
            peek_logging(&path),
            ("info".to_string(), None, "datetime".to_string())
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
