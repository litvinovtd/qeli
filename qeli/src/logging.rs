//! Linux process logging. A separate advisory lock serializes supervisor/worker
//! rotation; every write reopens the active path so no process retains an archive.
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
pub const ARCHIVE_COUNT: usize = 3;

fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log and lock paths must be regular files with a single hard link",
        ));
    }
    Ok(file)
}

fn suffix(path: &Path, value: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(value);
    PathBuf::from(name)
}

#[derive(Debug)]
pub struct RotatingLog {
    path: PathBuf,
    lock: File,
    max_bytes: u64,
    warned: bool,
}

struct Unlock<'a>(&'a File);
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        // Closing the process also releases flock after a crash.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl RotatingLog {
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let lock = open_regular(&suffix(path, ".lock"))?;
        open_regular(path)?;
        Ok(Self {
            path: path.into(),
            lock,
            max_bytes: MAX_FILE_BYTES,
            warned: false,
        })
    }

    fn write_record(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log record exceeds file limit",
            ));
        }
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let _unlock = Unlock(&self.lock);
        let mut active = open_regular(&self.path)?;
        let len = active.metadata()?.len();
        if len > 0 && len.saturating_add(bytes.len() as u64) > self.max_bytes {
            // Validate all existing destinations before removing any old archive.
            for n in 1..=ARCHIVE_COUNT {
                match std::fs::symlink_metadata(suffix(&self.path, &format!(".{n}"))) {
                    Ok(meta) if !meta.is_file() || meta.nlink() != 1 => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "unsafe log archive path",
                        ));
                    }
                    Ok(_) => (),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e),
                }
            }
            drop(active);
            for n in (1..=ARCHIVE_COUNT).rev() {
                let old = if n == 1 {
                    self.path.clone()
                } else {
                    suffix(&self.path, &format!(".{}", n - 1))
                };
                let new = suffix(&self.path, &format!(".{n}"));
                match std::fs::rename(old, new) {
                    Ok(()) => (),
                    Err(e) if e.kind() == io::ErrorKind::NotFound && n > 1 => (),
                    Err(e) => return Err(e),
                }
            }
            active = open_regular(&self.path)?;
        }
        active.write_all(bytes)
    }
}

impl Write for RotatingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = self.write_record(bytes) {
            if !self.warned {
                eprintln!("qeli: log file write/rotation failed: {error} — logging failed records to stderr");
                self.warned = true;
            }
            io::stderr().write_all(bytes)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// JSON is a log record format, not an alternative configuration format.
pub fn format_record(
    out: &mut impl Write,
    record: &log::Record<'_>,
    time: &str,
    format: &str,
) -> io::Result<()> {
    let timestamp = crate::util::log_timestamp(time);
    if format == "json" {
        let mut value = serde_json::json!({
            "level": record.level().as_str(), "target": record.target(),
            "message": record.args().to_string(), "pid": std::process::id(),
        });
        if !timestamp.is_empty() {
            value["timestamp"] = timestamp.into();
        }
        serde_json::to_writer(&mut *out, &value)?;
        writeln!(out)
    } else if timestamp.is_empty() {
        writeln!(
            out,
            "{:<5} {}: {}",
            record.level(),
            record.target(),
            record.args()
        )
    } else {
        writeln!(
            out,
            "{} {:<5} {}: {}",
            timestamp,
            record.level(),
            record.target(),
            record.args()
        )
    }
}

pub fn init(level: &str, file: Option<&str>, time: &str, format: &str) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    let time = time.to_string();
    let format = if matches!(format, "plain" | "json") {
        format
    } else {
        eprintln!("qeli: unknown logging.format '{format}' — using plain");
        "plain"
    }
    .to_string();
    builder.format(move |out, record| format_record(out, record, &time, &format));
    if let Some(path) = file {
        match RotatingLog::open(Path::new(path)) {
            Ok(writer) => {
                builder.target(env_logger::Target::Pipe(Box::new(writer)));
            }
            Err(error) => {
                eprintln!("qeli: cannot open log file {path}: {error} — logging to stderr")
            }
        }
    }
    builder.init();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-log-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn two_independent_writers_follow_rotation_and_bound_archives() {
        let fixture = Fixture::new();
        let path = fixture.0.join("server.log");
        let mut a = RotatingLog::open(&path).unwrap();
        let mut b = RotatingLog::open(&path).unwrap();
        a.max_bytes = 12;
        b.max_bytes = 12;
        for n in 0..10 {
            let writer = if n % 2 == 0 { &mut a } else { &mut b };
            writeln!(writer, "line{n}").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "line8\nline9\n");
        for n in 1..=3 {
            assert_eq!(
                std::fs::read_to_string(suffix(&path, &format!(".{n}"))).unwrap(),
                format!("line{}\nline{}\n", 8 - n * 2, 9 - n * 2)
            );
            assert!(
                std::fs::metadata(suffix(&path, &format!(".{n}")))
                    .unwrap()
                    .len()
                    <= 12
            );
        }
        assert!(!suffix(&path, ".4").exists());
    }

    #[test]
    fn subprocess_writer() {
        let Ok(path) = std::env::var("QELI_LOG_TEST_PATH") else {
            return;
        };
        let owner = std::env::var("QELI_LOG_TEST_OWNER").unwrap();
        let mut writer = RotatingLog::open(Path::new(&path)).unwrap();
        writer.max_bytes = 96;
        for n in 0..96 {
            writer
                .write_record(format!("{owner}:{n:03}\n").as_bytes())
                .unwrap();
        }
    }

    #[test]
    fn concurrent_processes_serialize_rotation_without_partial_or_duplicate_records() {
        let fixture = Fixture::new();
        let path = fixture.0.join("server.log");
        let spawn = |owner| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["logging::tests::subprocess_writer", "--exact"])
                .env("QELI_LOG_TEST_PATH", &path)
                .env("QELI_LOG_TEST_OWNER", owner)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut a = spawn("A");
        let mut b = spawn("B");
        assert!(a.wait().unwrap().success());
        assert!(b.wait().unwrap().success());
        let mut seen = std::collections::HashSet::new();
        for name in [
            path.clone(),
            suffix(&path, ".1"),
            suffix(&path, ".2"),
            suffix(&path, ".3"),
        ] {
            let text = std::fs::read_to_string(name).unwrap();
            assert_eq!(text.len(), 96);
            for line in text.lines() {
                assert_eq!(line.len(), 5);
                assert!(line.starts_with("A:") || line.starts_with("B:"));
                assert!(line[2..].parse::<u32>().unwrap() < 100);
                assert!(seen.insert(line.to_string()));
            }
        }
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn oversized_existing_file_rotates_before_append() {
        let fixture = Fixture::new();
        let path = fixture.0.join("server.log");
        std::fs::write(&path, b"old oversized content").unwrap();
        let mut log = RotatingLog::open(&path).unwrap();
        log.max_bytes = 8;
        log.write_record(b"new\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
        assert_eq!(
            std::fs::read(suffix(&path, ".1")).unwrap(),
            b"old oversized content"
        );
        assert!(log.write_record(b"too large for limit").is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4);
    }

    #[test]
    fn rejects_symlink_fifo_hardlink_and_unsafe_archive() {
        let fixture = Fixture::new();
        let path = fixture.0.join("server.log");
        let target = fixture.0.join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(RotatingLog::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(RotatingLog::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(RotatingLog::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let mut log = RotatingLog::open(&path).unwrap();
        log.max_bytes = 4;
        log.write_record(b"one\n").unwrap();
        std::os::unix::fs::symlink(&target, suffix(&path, ".1")).unwrap();
        assert!(log.write_record(b"two\n").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"one\n");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn json_escapes_messages_and_plain_and_time_none_are_preserved() {
        let record = log::Record::builder()
            .args(format_args!("quoted \"message\"\nsecond line"))
            .level(log::Level::Warn)
            .target("fixture")
            .build();
        let mut output = vec![];
        format_record(&mut output, &record, "none", "json").unwrap();
        assert_eq!(output.iter().filter(|b| **b == b'\n').count(), 1);
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["message"], "quoted \"message\"\nsecond line");
        assert_eq!(value["level"], "WARN");
        assert!(value.get("timestamp").is_none());
        output.clear();
        format_record(&mut output, &record, "rfc3339", "json").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(value["timestamp"].as_str().unwrap().ends_with('Z'));
        output.clear();
        format_record(&mut output, &record, "none", "plain").unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .starts_with("WARN  fixture: quoted"));
    }
}
