//! Bounded Linux client identity files. File I/O is separate from parsing and trust policy.
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

const LOCK_WAIT: Duration = Duration::from_secs(15);
const MAX_KNOWN_HOSTS: usize = 1024 * 1024;
type DeviceId = [u8; crate::protocol::DEVICE_ID_LEN];

fn open_regular(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO must not block open before we can validate the opened object.
        // Existing operator symlinks to regular files keep working.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "identity store is not a regular file",
        ));
    }
    Ok(file)
}

fn read_device_prefix(mut reader: impl Read) -> io::Result<Option<DeviceId>> {
    let mut id = [0; crate::protocol::DEVICE_ID_LEN];
    match reader.read_exact(&mut id) {
        // Preserve the historical nonzero-prefix contract, without reading a suffix.
        Ok(()) => Ok((id != [0; crate::protocol::DEVICE_ID_LEN]).then_some(id)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}
fn existing_device_id(path: &Path) -> io::Result<Option<DeviceId>> {
    match open_regular(path) {
        Ok(file) => read_device_prefix(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn random_device_id() -> DeviceId {
    use rand::Rng;
    let mut id = [0; crate::protocol::DEVICE_ID_LEN];
    while id == [0; crate::protocol::DEVICE_ID_LEN] {
        rand::rng().fill_bytes(&mut id);
    }
    id
}

pub(super) fn device_id_at(path: &str) -> DeviceId {
    device_id_with_wait(Path::new(path), LOCK_WAIT)
}
fn device_id_with_wait(path: &Path, wait: Duration) -> DeviceId {
    let load = || -> anyhow::Result<DeviceId> {
        if let Some(id) = existing_device_id(path)? {
            return Ok(id);
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let _lock = crate::util::FileLock::acquire_timeout(path, wait)?;
        // A different process may have published an ID while we waited.
        if let Some(id) = existing_device_id(path)? {
            return Ok(id);
        }
        let id = random_device_id();
        if let Err(error) = crate::util::write_atomic_private(path, &id) {
            log::warn!(
                "device id could not be persisted at '{}': {error}",
                path.display()
            );
        }
        Ok(id)
    };
    match load() {
        Ok(id) => id,
        Err(error) => {
            // Never replace an unreadable/special file as though it were missing.
            // The adapter caches this fallback across every reconnect in this run.
            log::warn!(
                "device id will be per-run because '{}' is unavailable: {error}",
                path.display()
            );
            random_device_id()
        }
    }
}

fn read_known_hosts(reader: impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_KNOWN_HOSTS + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_KNOWN_HOSTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "known_hosts exceeds 1 MiB",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "known_hosts is not valid UTF-8"))
}
fn snapshot(path: &str) -> anyhow::Result<String> {
    match open_regular(Path::new(path)) {
        Ok(file) => read_known_hosts(file).map_err(Into::into),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error.into()),
    }
    .map_err(|error: anyhow::Error| {
        error.context(format!(
            "cannot read known_hosts store {path}; refusing a new trust decision"
        ))
    })
}
fn check_pin(content: &str, server_id: &str, received_hex: &str) -> anyhow::Result<bool> {
    let mut found = false;
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (id, key) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        if id != server_id {
            continue;
        }
        // Check every matching record: a first matching key must not hide conflicts.
        let key = key.trim();
        anyhow::ensure!(
            key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid known_hosts pin for {server_id}; repair the store before reconnecting"
        );
        anyhow::ensure!(key.eq_ignore_ascii_case(received_hex), "SERVER KEY MISMATCH for {server_id} — possible MITM attack! Remove the old pin only after verifying an intentional server-key rotation");
        found = true;
    }
    Ok(found)
}

pub(super) fn trust_on_first_use_at(
    path: &str,
    server_id: &str,
    received_hex: &str,
    allow_unpinned: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !server_id.is_empty()
            && !server_id
                .chars()
                .any(|c| c.is_whitespace() || c.is_control()),
        "invalid server identity for known_hosts"
    );
    anyhow::ensure!(
        received_hex.len() == 64 && received_hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid server key for known_hosts"
    );
    // Read/parse errors are never an empty store, including in allow_unpinned mode.
    let content = snapshot(path)?;
    if check_pin(&content, server_id, received_hex)? {
        return Ok(());
    }
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        let _ = std::fs::create_dir_all(parent);
    }
    let _lock = match crate::util::FileLock::acquire_timeout(path, LOCK_WAIT) {
        Ok(lock) => lock,
        Err(error) => return persistence_failure(path, server_id, allow_unpinned, error),
    };
    let mut content = snapshot(path)?;
    if check_pin(&content, server_id, received_hex)? {
        return Ok(());
    }
    // Atomic replacement preserves the old store on a partial write/file-fsync error.
    // Insert a separator when an operator's last record has no final newline.
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!("{server_id} {received_hex}\n"));
    anyhow::ensure!(
        content.len() <= MAX_KNOWN_HOSTS,
        "known_hosts exceeds 1 MiB after adding a pin"
    );
    if let Err(error) = crate::util::write_atomic_private(path, content.as_bytes()) {
        return persistence_failure(path, server_id, allow_unpinned, error);
    }
    log::warn!("Pinned server key for {server_id} on first use (TOFU) → recorded in {path}. A future key change will abort; pin explicitly to verify out-of-band.");
    Ok(())
}
fn persistence_failure(
    path: &str,
    server_id: &str,
    allow_unpinned: bool,
    error: anyhow::Error,
) -> anyhow::Result<()> {
    if !allow_unpinned {
        return Err(error.context(format!(
            "cannot pin server key for {server_id} in {path}; refusing to connect unpinned"
        )));
    }
    log::warn!("cannot persist first-trust key for {server_id} in {path} ({error}) — continuing UNPINNED by explicit allow_unpinned_tofu");
    Ok(())
}

#[cfg(test)]
#[path = "identity_files_tests.rs"]
pub(super) mod tests;
