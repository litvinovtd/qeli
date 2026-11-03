//! Bounded regular-file credential reads, isolated from async runtime workers.
//! Ordinary filesystem syscalls cannot be force-cancelled; stop waits for an active
//! read to return. A permit remains with the blocking job even if its caller is dropped.
use crate::config_source::Stamp;
use crate::secret_buffer::{SecretBuffer, SecretDataError, MAX_SECRET_BYTES};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinHandle};
use zeroize::Zeroizing;

static FILE_READ_SLOT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
const READ_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(crate) enum FileError {
    #[error("auth.password_file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("auth.password_file must resolve to a regular file")]
    NotRegular,
    #[error("auth.password_file exceeds {MAX_SECRET_BYTES} bytes; password was rejected")]
    TooLarge,
    #[error("auth.password_file is not valid UTF-8; password was rejected")]
    InvalidUtf8,
    #[error("auth.password_file changed while reading; retry with a stable file")]
    Changed,
    #[error("auth.password_file exceeded its read deadline")]
    Timeout,
    #[error("auth.password_file cancelled by client shutdown")]
    Cancelled,
    #[error("auth.password_file reader task failed")]
    Worker,
}
impl From<SecretDataError> for FileError {
    fn from(error: SecretDataError) -> Self {
        match error {
            SecretDataError::TooLarge => Self::TooLarge,
            SecretDataError::InvalidUtf8 => Self::InvalidUtf8,
        }
    }
}

#[derive(Clone)]
struct ReadControl {
    cancelled: Arc<AtomicBool>,
    until: Instant,
}
impl ReadControl {
    fn check(&self) -> Result<(), FileError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(FileError::Cancelled)
        } else if Instant::now() >= self.until {
            Err(FileError::Timeout)
        } else {
            Ok(())
        }
    }
}

struct OpenedSecret {
    file: std::fs::File,
    before: std::fs::Metadata,
}
impl OpenedSecret {
    fn open(path: &Path, control: &ReadControl) -> Result<Self, FileError> {
        control.check()?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Secret-store symlinks are supported. NONBLOCK prevents waiting for a FIFO
            // writer before fstat can reject it. No config-command ownership policy applies.
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options.open(path)?;
        control.check()?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(FileError::NotRegular);
        }
        if before.len() > MAX_SECRET_BYTES as u64 {
            return Err(FileError::TooLarge);
        }
        Ok(Self { file, before })
    }

    fn read(mut self, control: &ReadControl) -> Result<Zeroizing<String>, FileError> {
        let mut output = SecretBuffer::new();
        let mut scratch = Zeroizing::new([0u8; 4096]);
        let mut total = 0u64;
        loop {
            control.check()?;
            let count = match self.file.read(&mut scratch[..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            control.check()?;
            if count == 0 {
                break;
            }
            output.append(&scratch[..count])?;
            total += count as u64;
        }
        control.check()?;
        let after = self.file.metadata()?;
        if Stamp::of(&self.before) != Stamp::of(&after) || total != self.before.len() {
            return Err(FileError::Changed);
        }
        control.check()?;
        output.decode().map_err(Into::into)
    }
}

fn read_file(path: &Path, control: &ReadControl) -> Result<Zeroizing<String>, FileError> {
    OpenedSecret::open(path, control)?.read(control)
}

struct FileJob {
    task: JoinHandle<Result<Zeroizing<String>, FileError>>,
    cancelled: Arc<AtomicBool>,
}
impl FileJob {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // Cancels a queued spawn_blocking job. A started syscall must finish naturally.
        self.task.abort();
    }
}
impl Drop for FileJob {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) async fn password(
    path: &str,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Zeroizing<String>, FileError> {
    let path = PathBuf::from(path);
    run_job(
        FILE_READ_SLOT.clone(),
        READ_DEADLINE,
        stop,
        move |control| read_file(&path, &control),
    )
    .await
}

async fn run_job<F>(
    slot: Arc<Semaphore>,
    deadline: Duration,
    stop: impl std::future::Future<Output = ()>,
    read: F,
) -> Result<Zeroizing<String>, FileError>
where
    F: FnOnce(ReadControl) -> Result<Zeroizing<String>, FileError> + Send + 'static,
{
    let until = tokio::time::Instant::now() + deadline;
    tokio::pin!(stop);
    let permit = tokio::select! {
        biased;
        _ = &mut stop => return Err(FileError::Cancelled),
        result = tokio::time::timeout_at(until, slot.acquire_owned()) =>
            result.map_err(|_| FileError::Timeout)?.map_err(|_| FileError::Worker)?,
    };
    let control = ReadControl {
        cancelled: Arc::new(AtomicBool::new(false)),
        until: until.into_std(),
    };
    control.check()?;
    let cancelled = control.cancelled.clone();
    let task = tokio::task::spawn_blocking(move || {
        // Keep admission occupied until I/O and its temporary secret buffers finish,
        // not just until the async caller stops waiting.
        let _permit = permit;
        control.check()?;
        read(control)
    });
    let mut job = FileJob { task, cancelled };
    let reason = tokio::select! {
        biased;
        _ = &mut stop => FileError::Cancelled,
        _ = tokio::time::sleep_until(until) => FileError::Timeout,
        result = &mut job.task => return result.map_err(|_| FileError::Worker)?,
    };
    job.cancel();
    // Do not hide an ongoing filesystem operation behind a successful stop/timeout.
    // On forced future Drop, the job still owns the one global permit and its buffers.
    let _ = (&mut job.task).await;
    Err(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DEADLINE: Duration = Duration::from_secs(5);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-secret-file-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, data: &[u8]) -> PathBuf {
            let path = self.0.join("secret");
            std::fs::write(&path, data).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only unlink immediate fixture files/symlinks/FIFOs; never recurse.
            for entry in std::fs::read_dir(&self.0).unwrap() {
                let _ = std::fs::remove_file(entry.unwrap().path());
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    fn control() -> ReadControl {
        ReadControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            until: Instant::now() + DEADLINE,
        }
    }

    #[tokio::test]
    async fn actual_file_uses_shared_utf8_trim_and_size_policy() {
        let dir = Fixture::new();
        let path = dir.file(" \tпароль with space\r\n".as_bytes());
        let secret = password(path.to_str().unwrap(), std::future::pending())
            .await
            .unwrap();
        assert_eq!(secret.as_str(), "пароль with space");
        for (length, accepted) in [(MAX_SECRET_BYTES, true), (MAX_SECRET_BYTES + 1, false)] {
            std::fs::write(&path, vec![b'x'; length]).unwrap();
            let result = password(path.to_str().unwrap(), std::future::pending()).await;
            if accepted {
                assert_eq!(result.unwrap().len(), length);
            } else {
                assert!(matches!(result, Err(FileError::TooLarge)));
            }
        }
    }

    #[test]
    fn malformed_empty_missing_and_directory_sources_are_explicit() {
        let dir = Fixture::new();
        let path = dir.file(b"secret-marker\xff");
        let error = read_file(&path, &control()).unwrap_err();
        assert!(matches!(error, FileError::InvalidUtf8));
        assert!(!format!("{error:?} {error}").contains("secret-marker"));
        std::fs::write(&path, b" \r\n").unwrap();
        assert_eq!(read_file(&path, &control()).unwrap().as_str(), "");
        assert!(matches!(
            read_file(&dir.0.join("missing"), &control()),
            Err(FileError::Io(_))
        ));
        // Windows can reject directory open before we reach fstat.
        assert!(matches!(
            read_file(&dir.0, &control()),
            Err(FileError::NotRegular | FileError::Io(_))
        ));
    }

    #[test]
    fn in_place_change_since_open_is_rejected() {
        let dir = Fixture::new();
        let path = dir.file(b"before");
        let opened = OpenedSecret::open(&path, &control()).unwrap();
        std::fs::write(path, b"new-content").unwrap();
        assert!(matches!(opened.read(&control()), Err(FileError::Changed)));
    }

    #[test]
    fn replacing_path_after_open_cannot_supply_replacement_bytes() {
        let dir = Fixture::new();
        let path = dir.file(b"before");
        let opened = OpenedSecret::open(&path, &control()).unwrap();
        std::fs::rename(&path, dir.0.join("previous")).unwrap();
        std::fs::write(path, b"different-secret").unwrap();
        match opened.read(&control()) {
            Ok(secret) => assert_eq!(secret.as_str(), "before"),
            Err(FileError::Changed) => {} // Rename may change the opened inode's ctime.
            Err(error) => panic!("unexpected file error: {error}"),
        }
    }

    #[tokio::test]
    async fn pre_cancel_and_admission_timeout_do_not_start_io() {
        let slot = Arc::new(Semaphore::new(0));
        let result = run_job(slot.clone(), DEADLINE, std::future::ready(()), |_| {
            panic!("pre-cancelled I/O started")
        })
        .await;
        assert!(matches!(result, Err(FileError::Cancelled)));
        let result = run_job(
            slot,
            Duration::from_millis(20),
            std::future::pending(),
            |_| panic!("I/O bypassed admission"),
        )
        .await;
        assert!(matches!(result, Err(FileError::Timeout)));
    }

    #[tokio::test]
    async fn stop_waits_for_inflight_io_and_discards_its_late_secret() {
        let slot = Arc::new(Semaphore::new(1));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let mut task = tokio::spawn(run_job(
            slot.clone(),
            DEADLINE,
            async {
                let _ = stopped.await;
            },
            move |control| {
                started.send(control.cancelled.clone()).unwrap();
                let _ = blocked.recv();
                Ok(Zeroizing::new("late-secret".into()))
            },
        ));
        let cancelled = tokio::time::timeout(DEADLINE, ready)
            .await
            .unwrap()
            .unwrap();
        stop.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut task)
            .await
            .is_err());
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(slot.available_permits(), 0);
        release.send(()).unwrap();
        assert!(matches!(
            tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(),
            Err(FileError::Cancelled)
        ));
        assert_eq!(slot.available_permits(), 1);
    }

    #[tokio::test]
    async fn deadline_marks_active_job_but_still_waits_for_its_io() {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let mut task = tokio::spawn(run_job(
            Arc::new(Semaphore::new(1)),
            Duration::from_millis(500),
            std::future::pending(),
            move |control| {
                started.send(control.cancelled.clone()).unwrap();
                let _ = blocked.recv();
                Ok(Zeroizing::new("late-secret".into()))
            },
        ));
        let cancelled = tokio::time::timeout(DEADLINE, ready)
            .await
            .unwrap()
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(550), &mut task)
            .await
            .is_err());
        assert!(cancelled.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert!(matches!(
            tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(),
            Err(FileError::Timeout)
        ));
    }

    #[tokio::test]
    async fn forced_cancellation_keeps_permit_until_blocking_job_finishes() {
        let slot = Arc::new(Semaphore::new(1));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let task = tokio::spawn(run_job(
            slot.clone(),
            DEADLINE,
            std::future::pending(),
            move |control| {
                started.send(control.cancelled.clone()).unwrap();
                let _ = blocked.recv();
                control.check()?;
                Ok(Zeroizing::new("never returned".into()))
            },
        ));
        let cancelled = tokio::time::timeout(DEADLINE, ready)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(cancelled.load(Ordering::Acquire));
        let result = run_job(
            slot.clone(),
            Duration::from_millis(20),
            std::future::pending(),
            |_| panic!("second blocking job admitted"),
        )
        .await;
        assert!(matches!(result, Err(FileError::Timeout)));
        release.send(()).unwrap();
        let permit = tokio::time::timeout(DEADLINE, slot.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(slot.available_permits(), 1);
    }

    #[tokio::test]
    async fn reader_panic_is_reported_without_payload_and_releases_admission() {
        let slot = Arc::new(Semaphore::new(1));
        let error = run_job(slot.clone(), DEADLINE, std::future::pending(), |_| {
            panic!("fixture-worker-panic")
        })
        .await
        .unwrap_err();
        assert!(matches!(error, FileError::Worker));
        assert!(!format!("{error:?} {error}").contains("fixture-worker-panic"));
        assert_eq!(slot.available_permits(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn secret_store_symlink_stays_supported_and_devices_are_rejected() {
        let dir = Fixture::new();
        let path = dir.file(b"valid-secret\n");
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            read_file(&link, &control()).unwrap().as_str(),
            "valid-secret"
        );
        assert!(matches!(
            read_file(Path::new("/dev/null"), &control()),
            Err(FileError::NotRegular)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_open_does_not_wait_for_a_writer() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let dir = Fixture::new();
        let path = dir.0.join("fifo");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let input = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(read_file(&input, &control()));
        });
        let result = rx.recv_timeout(DEADLINE);
        if result.is_err() {
            let _wake = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
                .unwrap();
            reader.join().unwrap();
            panic!("password_file waited for a FIFO writer");
        }
        reader.join().unwrap();
        assert!(matches!(result.unwrap(), Err(FileError::NotRegular)));
    }
}
