use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "qeli-state-dir-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn symlink_and_writable_parents_are_refused_before_creating_state() {
    let f = Fixture::new();
    let real = f.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = f.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(Directory::open(&link.join("state")).is_err());
    assert!(!real.join("state").exists());
    fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Directory::open(&real.join("state")).is_err());
    assert!(!real.join("state").exists());
    assert!(Directory::open(&real).is_err());
    assert!(Directory::open(Path::new("relative/state")).is_err());
    assert!(Directory::open(&f.0.join("missing/../state")).is_err());
    assert!(!f.0.join("missing").exists());
}
#[test]
fn pinned_directory_keeps_lock_read_write_and_remove_on_original_tree() {
    let f = Fixture::new();
    let original = f.0.join("state");
    let directory = Directory::open(&original).unwrap();
    let anchored = directory.journal_path("sysctls.state").unwrap();
    let moved = f.0.join("moved");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    let foreign = original.join("sysctls.state");
    fs::write(&foreign, b"replacement must survive").unwrap();
    let _lease =
        crate::util::FileLock::acquire_timeout_owned(&anchored, Duration::ZERO, directory.owner())
            .unwrap();
    crate::util::write_atomic_private(&anchored, b"original state").unwrap();
    assert_eq!(
        super::super::journal_file::Opened::open(&anchored, 100)
            .unwrap()
            .unwrap()
            .read()
            .unwrap(),
        b"original state"
    );
    assert!(moved.join("sysctls.state.lock").exists());
    assert!(!original.join("sysctls.state.lock").exists());
    crate::util::remove_file_synced(&anchored).unwrap();
    assert!(!moved.join("sysctls.state").exists());
    assert_eq!(fs::read(foreign).unwrap(), b"replacement must survive");
}
#[test]
fn permissive_lock_or_changed_directory_does_not_authorize_a_journal() {
    let f = Fixture::new();
    let directory = Directory::open(&f.0.join("state")).unwrap();
    let anchored = directory.journal_path("sysctls.state").unwrap();
    let lock = anchored.with_extension("state.lock");
    fs::write(&lock, b"lock sentinel").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(crate::util::FileLock::acquire_timeout_owned(
        &anchored,
        Duration::ZERO,
        directory.owner()
    )
    .is_err());
    assert_eq!(fs::read(&lock).unwrap(), b"lock sentinel");
    assert!(!anchored.exists());
    fs::write(&anchored, b"state").unwrap();
    fs::set_permissions(f.0.join("state"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(directory.verify().is_err());
    assert!(super::super::journal_file::Opened::open(&anchored, 100).is_err());
}

#[test]
#[ignore = "requires root for isolated service-user ownership test"]
fn native_root_and_service_share_state_but_foreign_inodes_are_refused() {
    use std::os::unix::process::CommandExt;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let f = Fixture(PathBuf::from(format!(
        "/tmp/qeli-state-service-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir(&f.0).unwrap();
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o755)).unwrap();
    // /tmp is root-owned/sticky; this root-owned protected intermediate directory
    // authorizes a dedicated service-owned child without trusting foreign squatters.
    let state = f.0.join("state");
    fs::create_dir(&state).unwrap();
    let chown = |path: &Path, owner: u32| {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), owner, owner) }, 0);
    };
    chown(&state, 65534);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
    let directory = Directory::open(&state).unwrap();
    let path = directory.journal_path("sysctls.state").unwrap();
    {
        let _lock =
            crate::util::FileLock::acquire_timeout_owned(&path, Duration::ZERO, directory.owner())
                .unwrap();
        crate::util::write_atomic_private(&path, b"root wrote this").unwrap();
    }
    let lock = state.join("sysctls.state.lock");
    for item in [&path, &lock] {
        let md = fs::metadata(item).unwrap();
        assert_eq!(md.uid(), 65534);
        assert_eq!(md.mode() & 0o777, 0o600);
    }
    // The build tree may be root-private; copy only the test executable into this
    // disposable accessible fixture, without changing build-tree permissions.
    let executable = f.0.join("test-runner");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = std::process::Command::new(&executable);
    command
        .args(["state_dir::native_tests::service_child", "--nocapture"])
        .env("QELI_TEST_STATE_SERVICE", &state)
        .uid(65534)
        .gid(65534);
    let output = crate::system_command::Command::from(command)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&path).unwrap(), b"service wrote this");
    // A moved-in inode with an unrelated owner cannot supply recovery evidence or
    // have its owner silently normalized before refusal.
    chown(&path, 65533);
    assert!(super::super::journal_file::Opened::open(&path, 100).is_err());
    chown(&lock, 65533);
    assert!(
        crate::util::FileLock::acquire_timeout_owned(&path, Duration::ZERO, directory.owner())
            .is_err()
    );
    assert_eq!(fs::metadata(&lock).unwrap().uid(), 65533);
    assert_eq!(fs::read(&path).unwrap(), b"service wrote this");
}
#[test]
fn service_child() {
    let Some(path) = std::env::var_os("QELI_TEST_STATE_SERVICE") else {
        return;
    };
    assert_eq!(unsafe { libc::geteuid() }, 65534);
    let directory = Directory::open(Path::new(&path)).unwrap();
    let path = directory.journal_path("sysctls.state").unwrap();
    let _lock =
        crate::util::FileLock::acquire_timeout_owned(&path, Duration::ZERO, directory.owner())
            .unwrap();
    assert_eq!(
        super::super::journal_file::Opened::open(&path, 100)
            .unwrap()
            .unwrap()
            .read()
            .unwrap(),
        b"root wrote this"
    );
    crate::util::write_atomic_private(&path, b"service wrote this").unwrap();
}

#[test]
fn lock_replaced_while_waiting_never_splits_the_state_transaction() {
    for trusted in [false, true] {
        let f = Fixture::new();
        let directory = Directory::open(&f.0.join("state")).unwrap();
        let path = directory.journal_path("sysctls.state").unwrap();
        let lock_path = path.with_extension("state.lock");
        let first =
            crate::util::FileLock::acquire_timeout_owned(&path, Duration::ZERO, directory.owner())
                .unwrap();
        let md = fs::metadata(&lock_path).unwrap();
        let identity = (md.dev(), md.ino());
        let owner = directory.owner();
        let waiter = std::thread::spawn(move || {
            if trusted {
                crate::util::FileLock::acquire_timeout_owned(&path, Duration::from_secs(5), owner)
                    .is_err()
            } else {
                crate::util::FileLock::acquire_timeout(&path, Duration::from_secs(5)).is_err()
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut opened = false;
        while std::time::Instant::now() < deadline {
            let count = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|e| fs::metadata(e.path()).ok())
                .filter(|m| (m.dev(), m.ino()) == identity)
                .count();
            if count >= 2 {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if opened {
            fs::rename(&lock_path, f.0.join("old-lock")).unwrap();
            fs::write(&lock_path, b"replacement lock").unwrap();
        }
        drop(first);
        let refused = waiter.join().unwrap();
        assert!(opened, "waiter never opened the held lock");
        assert!(refused, "waiter accepted the removed lock domain");
        assert_eq!(fs::read(lock_path).unwrap(), b"replacement lock");
    }
}
