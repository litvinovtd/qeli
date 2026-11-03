//! Read configuration and authorize its commands from the same opened file.
//! Trust is immutable for these bytes, never recomputed from a later pathname lookup.
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{self, Read},
    path::Path,
    time::SystemTime,
};

/// Largest server INI accepted by the worker, CLI and panel. The panel's
/// request-body ceiling is also 16 MiB; serialized edits are checked again
/// before writing because JSON-to-INI expansion can exceed the request size.
#[cfg(any(feature = "server", test))]
pub(crate) const MAX_SERVER_INI_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct CommandTrust(Result<(), String>);
impl CommandTrust {
    pub(crate) fn denied(reason: impl Into<String>) -> Self {
        Self(Err(reason.into()))
    }
    pub(crate) fn check(&self) -> Result<(), &str> {
        self.0.as_ref().map(|_| ()).map_err(String::as_str)
    }
}

// Never derive Debug for a snapshot: contents can contain passwords/private keys.
pub(crate) struct ConfigSnapshot {
    contents: String,
    trust: CommandTrust,
}
impl ConfigSnapshot {
    pub(crate) fn into_parts(self) -> (String, CommandTrust) {
        (self.contents, self.trust)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    readonly: bool,
    #[cfg(unix)]
    unix: (u64, u64, u32, u32, u32, i64, i64, i64, i64),
}
impl Stamp {
    pub(crate) fn of(md: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            len: md.len(),
            modified: md.modified().ok(),
            readonly: md.permissions().readonly(),
            #[cfg(unix)]
            unix: (
                md.dev(),
                md.ino(),
                md.mode(),
                md.uid(),
                md.gid(),
                md.mtime(),
                md.mtime_nsec(),
                md.ctime(),
                md.ctime_nsec(),
            ),
        }
    }
}

// Kept separate from platform metadata extraction so the complete Unix policy also runs
// in host tests without impersonation, chown or privileged filesystem operations.
#[cfg(any(unix, test))]
fn unix_command_policy(mode: u32, owner: u32, effective_uid: u32) -> CommandTrust {
    if mode & 0o022 != 0 {
        return CommandTrust::denied(format!(
            "config snapshot is group/world-writable (mode {:o}); use chmod 600 and restart",
            mode & 0o777
        ));
    }
    if owner != 0 && owner != effective_uid {
        return CommandTrust::denied(format!(
            "config snapshot is owned by uid {owner} (we run as {effective_uid})"
        ));
    }
    CommandTrust(Ok(()))
}

fn command_policy(md: &Metadata) -> CommandTrust {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        unix_command_policy(md.mode(), md.uid(), unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        CommandTrust::denied("file-command authorization is unsupported on this platform")
    }
}

struct OpenedConfig {
    file: File,
    stamp: Stamp,
    trust: CommandTrust,
}
impl OpenedConfig {
    fn from_file(
        file: File,
        forced_denial: Option<&str>,
        policy: fn(&Metadata) -> CommandTrust,
    ) -> io::Result<Self> {
        let md = file.metadata()?;
        if !md.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configuration must be a regular file",
            ));
        }
        let trust = forced_denial
            .map(CommandTrust::denied)
            .unwrap_or_else(|| policy(&md));
        Ok(Self {
            file,
            stamp: Stamp::of(&md),
            trust,
        })
    }

    #[cfg(any(feature = "server", test))]
    fn read(self) -> io::Result<ConfigSnapshot> {
        self.read_with_limit(MAX_SERVER_INI_BYTES)
    }

    fn read_with_limit(mut self, max_bytes: u64) -> io::Result<ConfigSnapshot> {
        if self.stamp.len > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "configuration is {} bytes; maximum is {max_bytes}",
                    self.stamp.len
                ),
            ));
        }
        let mut contents = String::new();
        // Stop at the observed size plus one byte even if a writer keeps appending.
        // Any growth, truncation or other detected metadata change rejects the load.
        self.file
            .by_ref()
            .take(self.stamp.len.saturating_add(1))
            .read_to_string(&mut contents)?;
        // Detect in-place edits, permission/owner changes and truncation while reading.
        // Atomic replacement of the pathname cannot change which descriptor is read.
        let after = Stamp::of(&self.file.metadata()?);
        if self.stamp != after || contents.len() as u64 != after.len {
            return Err(io::Error::other(
                "configuration changed while reading; retry with a stable file",
            ));
        }
        Ok(ConfigSnapshot {
            contents,
            trust: self.trust,
        })
    }
}

fn open(path: &Path) -> io::Result<OpenedConfig> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK lets us reject a FIFO by fstat instead of waiting forever in open().
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        match options.open(path) {
            Ok(file) => OpenedConfig::from_file(file, None, command_policy),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                // Preserve symlink configs for tunnels without file commands. Even if the
                // pathname changes before this fallback open, command trust stays denied.
                options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
                OpenedConfig::from_file(
                    options.open(path)?,
                    Some("config was opened through a symlink; file commands are disabled"),
                    command_policy,
                )
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    OpenedConfig::from_file(options.open(path)?, None, command_policy)
}

#[cfg(any(feature = "server", test))]
pub(crate) fn load(path: impl AsRef<Path>) -> io::Result<ConfigSnapshot> {
    open(path.as_ref())?.read()
}

/// Read another INI sidecar through the same stable, regular-file descriptor,
/// with its own smaller size budget.
pub(crate) fn load_bounded(path: impl AsRef<Path>, max_bytes: u64) -> io::Result<ConfigSnapshot> {
    open(path.as_ref())?.read_with_limit(max_bytes)
}

// Match the shared client-core limit before allocating or reading file contents.
// Return advisory permissions from that same opened inode, never a later pathname.
#[cfg(all(target_os = "linux", feature = "client"))]
pub(crate) fn load_client(path: impl AsRef<Path>) -> io::Result<(ConfigSnapshot, u32)> {
    let opened = open(path.as_ref())?;
    let mode = opened.stamp.unix.2 & 0o777;
    Ok((
        opened.read_with_limit(crate::transport_core::MAX_CONFIG_BYTES as u64)?,
        mode,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "qeli-config-source-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn write(&self, name: &str, contents: &[u8], readonly: bool) -> PathBuf {
            let path = self.path(name);
            std::fs::write(&path, contents).unwrap();
            Self::permissions(&path, readonly);
            path
        }
        fn permissions(path: &Path, readonly: bool) {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(if readonly { 0o400 } else { 0o600 });
            }
            #[cfg(not(unix))]
            permissions.set_readonly(readonly);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only immediate children of our newly created fixture; no recursive deletion.
            for entry in std::fs::read_dir(&self.0).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    Self::permissions(&entry.path(), false);
                }
                let _ = std::fs::remove_file(entry.path());
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    // Host race tests use a read-only bit as a deterministic policy marker, not as
    // a substitute for Unix authorization. The actual Unix policy is tested separately.
    fn host_policy(md: &Metadata) -> CommandTrust {
        if md.permissions().readonly() {
            CommandTrust(Ok(()))
        } else {
            CommandTrust::denied("untrusted fixture")
        }
    }
    fn host_open(path: &Path) -> OpenedConfig {
        OpenedConfig::from_file(File::open(path).unwrap(), None, host_policy).unwrap()
    }

    #[test]
    fn bounded_snapshot_accepts_exact_limit_and_rejects_oversize_before_reading() {
        let dir = Fixture::new();
        let limit = crate::transport_core::MAX_CONFIG_BYTES;
        let path = dir.write("config", &vec![b'#'; limit], false);
        assert_eq!(
            host_open(&path)
                .read_with_limit(limit as u64)
                .unwrap()
                .into_parts()
                .0
                .len(),
            limit
        );
        // Invalid UTF-8 would yield a different error if oversized bytes were read.
        std::fs::write(&path, vec![0xff; limit + 1]).unwrap();
        let error = host_open(&path)
            .read_with_limit(limit as u64)
            .err()
            .unwrap();
        assert!(error.to_string().contains("maximum is 262144"));
    }

    #[test]
    fn server_snapshot_rejects_oversize_before_reading() {
        let dir = Fixture::new();
        let path = dir.write("server.conf", b"", false);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_SERVER_INI_BYTES + 1)
            .unwrap();
        let error = load(&path).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("maximum is 16777216"));
    }

    #[test]
    fn growth_after_bounded_open_still_rejects_the_snapshot() {
        let dir = Fixture::new();
        let path = dir.write("config", b"short", false);
        let opened = host_open(&path);
        std::fs::write(&path, vec![b'x'; 1024]).unwrap();
        assert!(opened
            .read_with_limit(32)
            .err()
            .unwrap()
            .to_string()
            .contains("changed while reading"));
    }

    #[test]
    fn regular_utf8_snapshot_preserves_exact_parser_input() {
        let dir = Fixture::new();
        let contents = "# comment\r\n[profile:test]\r\nrouting.post_up = echo привет\r\n";
        let path = dir.write("config", contents.as_bytes(), true);
        let (actual, trust) = load(&path).unwrap().into_parts();
        assert_eq!(actual, contents);
        #[cfg(unix)]
        trust.check().unwrap();
        #[cfg(not(unix))]
        assert!(
            trust.check().is_err(),
            "unsupported platforms cannot authorize commands"
        );
    }

    #[test]
    fn owner_and_write_permissions_enforce_unix_policy() {
        for (mode, owner, euid, allowed) in [
            (0o600, 1000, 1000, true),
            (0o644, 0, 1000, true),
            (0o600, 1001, 1000, false),
            (0o600, 1000, 0, false),
            (0o620, 0, 0, false),
            (0o602, 1000, 1000, false),
            (0o666, 0, 0, false),
        ] {
            assert_eq!(
                unix_command_policy(mode, owner, euid).check().is_ok(),
                allowed
            );
        }
    }

    #[test]
    fn untrusted_bytes_cannot_be_authorized_by_path_replacement() {
        let dir = Fixture::new();
        let path = dir.write("config", b"post_up = untrusted-fixture", false);
        let snapshot = host_open(&path).read().unwrap();
        std::fs::rename(&path, dir.path("old")).unwrap();
        dir.write("config", b"post_up = trusted-fixture", true);
        // The former separate path gate sees a trusted replacement and would grant
        // permission to the earlier untrusted command. The immutable snapshot refuses.
        assert!(host_policy(&std::fs::metadata(&path).unwrap())
            .check()
            .is_ok());
        let (contents, trust) = snapshot.into_parts();
        assert_eq!(contents, "post_up = untrusted-fixture");
        assert!(trust.check().is_err());
        assert!(
            trust.clone().check().is_err(),
            "retry retains the same decision"
        );
    }

    #[test]
    fn replacing_path_after_open_never_supplies_replacement_bytes() {
        let dir = Fixture::new();
        let path = dir.write("config", b"original", true);
        let opened = host_open(&path);
        std::fs::rename(&path, dir.path("old")).unwrap();
        dir.write("config", b"replacement", true);
        match opened.read() {
            Ok(snapshot) => assert_eq!(snapshot.into_parts().0, "original"),
            // Unix rename may update the opened inode's ctime. Refusal is safe too.
            Err(error) => assert!(error.to_string().contains("changed while reading")),
        }
    }

    #[test]
    fn trusted_cleanup_survives_path_removal_and_replacement() {
        let dir = Fixture::new();
        let path = dir.write("config", b"post_down = approved-cleanup", true);
        let (contents, trust) = host_open(&path).read().unwrap().into_parts();
        Fixture::permissions(&path, false);
        std::fs::remove_file(&path).unwrap();
        trust.check().unwrap();
        dir.write("config", b"post_down = other-command", false);
        assert_eq!(contents, "post_down = approved-cleanup");
        trust.clone().check().unwrap();
    }

    #[test]
    fn in_place_edit_after_open_is_rejected() {
        let dir = Fixture::new();
        let path = dir.write("config", b"old", false);
        let opened = host_open(&path);
        std::fs::write(&path, b"different length").unwrap();
        assert!(opened
            .read()
            .err()
            .unwrap()
            .to_string()
            .contains("changed while reading"));
    }

    #[test]
    fn permission_change_during_read_does_not_upgrade_trust() {
        let dir = Fixture::new();
        let path = dir.write("config", b"command", false);
        let opened = host_open(&path);
        Fixture::permissions(&path, true);
        assert!(opened
            .read()
            .err()
            .unwrap()
            .to_string()
            .contains("changed while reading"));
    }

    #[test]
    fn forced_symlink_denial_cannot_be_overridden_by_trusted_target() {
        let dir = Fixture::new();
        let path = dir.write("config", b"command", true);
        let opened = OpenedConfig::from_file(
            File::open(path).unwrap(),
            Some("symlink fallback"),
            host_policy,
        )
        .unwrap();
        let (_, trust) = opened.read().unwrap().into_parts();
        assert_eq!(trust.check(), Err("symlink fallback"));
    }

    #[test]
    fn invalid_utf8_is_not_replaced_or_parsed_as_default() {
        let dir = Fixture::new();
        let path = dir.write("config", b"invalid \xff", false);
        assert_eq!(load(path).err().unwrap().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_and_directory_sources_are_errors() {
        let dir = Fixture::new();
        assert_eq!(
            load(dir.path("missing")).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert!(load(&dir.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_remains_readable_but_cannot_authorize_commands() {
        let dir = Fixture::new();
        let target = dir.write("target", b"post_up = approved", true);
        let link = dir.path("link");
        std::os::unix::fs::symlink(target, &link).unwrap();
        let (contents, trust) = load(link).unwrap().into_parts();
        assert_eq!(contents, "post_up = approved");
        assert!(trust.check().unwrap_err().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn chmod_after_loading_requires_a_new_snapshot_to_authorize_commands() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Fixture::new();
        let path = dir.write("config", b"post_up = echo fixture", false);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (_, old_trust) = load(&path).unwrap().into_parts();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(old_trust.check().is_err());
        load(&path).unwrap().into_parts().1.check().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let dir = Fixture::new();
        let path = dir.path("fifo");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let input = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(load(input).map(|_| ()));
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        if result.is_err() {
            // Wake a regressed blocking open before failing, so the test does not leak
            // a blocked reader into the test process. fstat then rejects the FIFO.
            let _wake = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
                .unwrap();
            reader.join().unwrap();
            panic!("config open waited for a FIFO writer");
        }
        reader.join().unwrap();
        assert_eq!(
            result.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
