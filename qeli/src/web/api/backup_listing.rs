//! Bounded, streaming validation before restore. No extraction or live config writes.
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 5_000;
const MAX_LINE: usize = 8 * 1024;
const MAX_STDERR: usize = 16 * 1024;

#[derive(Default)]
struct Listing {
    line: Vec<u8>,
    entries: usize,
    bytes: u64,
}

impl Listing {
    fn feed(&mut self, bytes: &[u8]) -> Result<(), String> {
        for &byte in bytes {
            if byte == b'\n' {
                self.entry()?;
                self.line.clear();
            } else {
                if self.line.len() == MAX_LINE {
                    return Err("refused: archive listing line too long".into());
                }
                self.line.push(byte);
            }
        }
        Ok(())
    }

    fn entry(&mut self) -> Result<(), String> {
        let line = std::str::from_utf8(&self.line)
            .map_err(|_| "refused: non-UTF8 archive listing")?
            .trim();
        if line.is_empty() {
            return Ok(());
        }
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return Err(format!(
                "refused: archive contains more than {MAX_ENTRIES} entries"
            ));
        }
        if !matches!(line.as_bytes()[0], b'-' | b'd') {
            return Err("refused: archive contains a symlink/hardlink/special entry".into());
        }
        let mut fields = line.split_whitespace();
        let size = fields
            .nth(2)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("refused: invalid archive entry size")?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or("refused: archive size overflow")?;
        if self.bytes > MAX_BYTES {
            return Err("refused: archive expands to more than 64 MiB".into());
        }
        let name = fields.skip(2).collect::<Vec<_>>().join(" ");
        if name.is_empty()
            || name.starts_with('/')
            || name.contains("..")
            || !(name == "qeli" || name.starts_with("qeli/"))
        {
            return Err("refused: archive path must be under qeli/ without '..'".into());
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<usize, String> {
        if !self.line.is_empty() {
            self.entry()?;
            self.line.clear();
        }
        if self.entries == 0 {
            return Err("archive is empty".into());
        }
        Ok(self.entries)
    }
}

struct Process(Child, bool);
impl Drop for Process {
    fn drop(&mut self) {
        if !self.1 {
            // tar may spawn gzip; kill the isolated process group, then reap the leader.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<(), String> {
    let fd = pipe.as_raw_fd();
    // SAFETY: the live pipe owns fd; only its file status flags are changed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!("tar pipe setup: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn run(mut command: Command, deadline: Duration) -> Result<usize, String> {
    let mut process = Process(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| format!("tar list failed: {e}"))?,
        false,
    );
    let mut stdout = process.0.stdout.take().ok_or("missing tar stdout")?;
    let mut stderr = process.0.stderr.take().ok_or("missing tar stderr")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let start = Instant::now();
    let mut listing = Listing::default();
    let mut errors = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    let mut buffer = [0u8; 4096];
    loop {
        if start.elapsed() >= deadline {
            return Err("tar listing timed out".into());
        }
        // At most one bounded chunk per pipe/iteration; neither a chatty child nor a
        // full stderr pipe can starve the deadline or the other pipe.
        if !out_eof {
            match stdout.read(&mut buffer) {
                Ok(0) => out_eof = true,
                Ok(n) => listing.feed(&buffer[..n])?,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(format!("tar stdout: {e}")),
            }
        }
        if !err_eof {
            match stderr.read(&mut buffer) {
                Ok(0) => err_eof = true,
                Ok(n) => {
                    if errors.len() + n > MAX_STDERR {
                        return Err("tar diagnostics limit exceeded".into());
                    }
                    errors.extend_from_slice(&buffer[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(format!("tar stderr: {e}")),
            }
        }
        if out_eof && err_eof {
            if let Some(status) = process.0.try_wait().map_err(|e| format!("tar wait: {e}"))? {
                process.1 = true;
                if !status.success() {
                    return Err(format!(
                        "not a valid tar.gz: {}",
                        String::from_utf8_lossy(&errors)
                    ));
                }
                return listing.finish();
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) fn validate_archive(path: &str) -> Result<usize, String> {
    let mut command = Command::new("tar");
    command
        .env("LC_ALL", "C")
        .env_remove("TAR_OPTIONS")
        .args(["tzvf", path]);
    run(command, Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_tar_valid_archive_and_many_empty_entries() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "qeli-listing-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir(dir.join("qeli")).unwrap();
        let archive = dir.join("test.tgz");
        for count in [1, MAX_ENTRIES + 1] {
            let mut tar = Command::new("tar")
                .env_remove("TAR_OPTIONS")
                .arg("czf")
                .arg(&archive)
                .arg("--no-recursion")
                .arg("-C")
                .arg(&dir)
                .args(["-T", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            tar.stdin
                .take()
                .unwrap()
                .write_all("qeli\n".repeat(count).as_bytes())
                .unwrap();
            assert!(tar.wait().unwrap().success());
            let result = validate_archive(archive.to_str().unwrap());
            if count == 1 {
                assert_eq!(result.unwrap(), 1);
            } else {
                assert!(result.unwrap_err().contains("entries"));
            }
        }
    }

    #[test]
    fn budgets_apply_incrementally() {
        let row = b"-rw------- root/root 0 2026-09-16 12:00 qeli/config.ini\n";
        let mut listing = Listing::default();
        for _ in 0..MAX_ENTRIES {
            listing.feed(row).unwrap();
        }
        assert!(listing.feed(row).unwrap_err().contains("entries"));
        assert_eq!(listing.entries, MAX_ENTRIES + 1);
        assert!(Listing::default().feed(&vec![b'x'; MAX_LINE + 1]).is_err());
        assert!(Listing::default()
            .feed(b"-rw------- root/root 67108865 date time qeli/a\n")
            .is_err());
        for row in [
            b"lrwxrwxrwx root/root 0 date time qeli/link\n".as_slice(),
            b"-rw------- root/root 0 date time qeli/../etc/passwd\n",
            b"-rw------- root/root invalid date time qeli/a\n",
        ] {
            assert!(Listing::default().feed(row).is_err());
        }
    }

    #[test]
    fn hanging_child_and_stderr_flood_are_bounded() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30"]);
        let start = Instant::now();
        assert!(run(command, Duration::from_millis(100))
            .unwrap_err()
            .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(3));
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "while :; do printf 'lots of diagnostics\\n' >&2; done",
        ]);
        assert!(run(command, Duration::from_secs(2))
            .unwrap_err()
            .contains("diagnostics limit"));
    }
}
