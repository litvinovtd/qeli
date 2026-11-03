//! Per-interface sysctl evidence. A saved procfs inode is meaningful only while
//! a live v3 owner retains the corresponding open file; ctime also separates
//! an inode-counter wrap from the original object. Never use it after all
//! witnesses have died: procfs may evict/reuse inodes independently of a link.
#[cfg(test)]
use super::host;
use super::namespace;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    lease: String,
    object: String,
}
impl Identity {
    pub(super) fn valid(&self) -> bool {
        self.lease.len() == 32
            && self
                .lease
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.lease != "00000000000000000000000000000000"
            && valid_object(&self.object)
    }
    pub(super) fn lease(&self) -> &str {
        &self.lease
    }
}

fn valid_object(value: &str) -> bool {
    let fields: Vec<_> = value.split(':').collect();
    let [dev, ino, sec, nsec] = fields.as_slice() else {
        return false;
    };
    match (
        dev.parse::<u64>(),
        ino.parse::<u64>(),
        sec.parse::<i64>(),
        nsec.parse::<u32>(),
    ) {
        (Ok(dev), Ok(ino), Ok(sec), Ok(nsec)) => {
            ino != 0 && nsec < 1_000_000_000 && value == format!("{dev}:{ino}:{sec}:{nsec}")
        }
        _ => false,
    }
}

pub(super) struct Pin {
    object: String,
    context: namespace::Context,
    #[cfg(test)]
    path: String,
    #[cfg(all(not(test), target_os = "linux"))]
    file: std::fs::File,
}
impl Pin {
    fn open(path: &str, context: &namespace::Guard) -> anyhow::Result<Self> {
        #[cfg(test)]
        let object = context.io(|| host::target_identity(path))?;
        #[cfg(all(not(test), target_os = "linux"))]
        let (object, file) = {
            let file = context.io(|| live_open(path))?;
            (object_identity(&file)?, file)
        };
        if !valid_object(&object) {
            anyhow::bail!("invalid per-interface sysctl object identity for {path}");
        }
        Ok(Self {
            object,
            context: context.context().clone(),
            #[cfg(test)]
            path: path.to_owned(),
            #[cfg(all(not(test), target_os = "linux"))]
            file,
        })
    }
    fn verify_context(&self, context: &namespace::Guard) -> anyhow::Result<()> {
        context.check()?;
        if self.context != *context.context() {
            anyhow::bail!("per-interface sysctl descriptor belongs to another namespace context");
        }
        Ok(())
    }
    pub(super) fn read(&self, context: &namespace::Guard) -> io::Result<String> {
        self.verify_context(context)
            .map_err(|e| io::Error::other(e.to_string()))?;
        context.io(|| {
            #[cfg(test)]
            {
                if host::target_identity(&self.path)? != self.object {
                    return Err(io::ErrorKind::NotFound.into());
                }
                host::read(&self.path)
            }
            #[cfg(all(not(test), target_os = "linux"))]
            {
                live_read(&self.file)
            }
        })
    }
    pub(super) fn write(&self, value: &str, context: &namespace::Guard) -> io::Result<()> {
        self.verify_context(context)
            .map_err(|e| io::Error::other(e.to_string()))?;
        context.io(|| {
            #[cfg(test)]
            {
                if host::target_identity(&self.path)? != self.object {
                    return Err(io::ErrorKind::NotFound.into());
                }
                host::write(&self.path, value)
            }
            #[cfg(all(not(test), target_os = "linux"))]
            {
                live_write(&self.file, value)
            }
        })
    }
}

#[cfg(target_os = "linux")]
fn live_open(path: &str) -> io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid fd and writable statfs storage. Read only after successful fstatfs.
    if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fs = unsafe { fs.assume_init() };
    // libc exposes f_type as signed on glibc and unsigned on musl. A lossless
    // common integer representation keeps the same check on 32- and 64-bit targets.
    if i128::from(fs.f_type) != i128::from(libc::PROC_SUPER_MAGIC) || !file.metadata()?.is_file() {
        return Err(io::Error::other(
            "per-interface sysctl must be a regular procfs file",
        ));
    }
    Ok(file)
}
#[cfg(target_os = "linux")]
fn object_identity(file: &std::fs::File) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    // procfs get_next_ino is a wrapping allocator. Include the inode's ctime
    // instead of assuming that an open inode number can never collide.
    Ok(format!(
        "{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.ctime(),
        m.ctime_nsec()
    ))
}
#[cfg(target_os = "linux")]
fn live_read(file: &std::fs::File) -> io::Result<String> {
    use std::os::unix::fs::FileExt;
    let mut bytes = [0u8; 16];
    let count = file.read_at(&mut bytes, 0)?;
    if count == bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized sysctl value",
        ));
    }
    String::from_utf8(bytes[..count].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
#[cfg(target_os = "linux")]
fn live_write(file: &std::fs::File, value: &str) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    if file.write_at(value.as_bytes(), 0)? != value.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short sysctl write",
        ));
    }
    Ok(())
}

struct Cached {
    scope: PathBuf,
    pin: Arc<Pin>,
}
type Cache = BTreeMap<String, Cached>;
#[cfg(not(test))]
fn with_cache<T>(run: impl FnOnce(&mut Cache) -> T) -> T {
    static CACHE: std::sync::Mutex<Cache> = std::sync::Mutex::new(BTreeMap::new());
    run(&mut CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}
#[cfg(test)]
fn with_cache<T>(run: impl FnOnce(&mut Cache) -> T) -> T {
    thread_local! { static CACHE: std::cell::RefCell<Cache> = const { std::cell::RefCell::new(BTreeMap::new()) }; }
    CACHE.with(|cache| run(&mut cache.borrow_mut()))
}
#[cfg(test)]
pub(super) fn clear_test_cache() {
    with_cache(|cache| cache.clear());
}

fn remember(identity: &Identity, pin: Arc<Pin>, scope: &Path) -> anyhow::Result<()> {
    with_cache(|cache| {
        if cache.len() >= 256 {
            anyhow::bail!("per-interface sysctl descriptor limit reached; complete pending cleanup before acquiring more links");
        }
        if cache.contains_key(&identity.lease) {
            anyhow::bail!("duplicate per-interface sysctl lease identity");
        }
        cache.insert(
            identity.lease.clone(),
            Cached {
                scope: scope.to_owned(),
                pin,
            },
        );
        Ok(())
    })
}

pub(super) fn capture(
    path: &str,
    context: &namespace::Guard,
) -> anyhow::Result<(Identity, Arc<Pin>)> {
    let pin = Arc::new(Pin::open(path, context)?);
    let identity = Identity {
        lease: format!("{:032x}", rand::random::<u128>().max(1)),
        object: pin.object.clone(),
    };
    remember(&identity, pin.clone(), context.scope())?;
    Ok((identity, pin))
}

pub(super) fn resolve(
    path: &str,
    identity: Option<&Identity>,
    context: &namespace::Guard,
    live_witness: Option<&dyn Fn() -> anyhow::Result<bool>>,
) -> anyhow::Result<Arc<Pin>> {
    let identity = identity.ok_or_else(|| anyhow::anyhow!("missing per-interface sysctl identity for {path}; keep the journal for manual recovery"))?;
    let cached = with_cache(|cache| {
        cache
            .get(&identity.lease)
            .map(|cached| (cached.scope.clone(), cached.pin.clone()))
    });
    if let Some((scope, pin)) = cached {
        if scope != context.scope() || pin.object != identity.object {
            anyhow::bail!("per-interface sysctl lease identity mismatch for {path}");
        }
        pin.verify_context(context)?;
        return Ok(pin);
    }
    let live_witness = live_witness.ok_or_else(|| anyhow::anyhow!(
        "lost live per-interface sysctl evidence for {path}; keep the journal and inspect the original interface before manual recovery"
    ))?;
    // A confirmed live v3 owner holds the original procfs inode. Opening the same
    // inode adds our own witness before we publish ownership. A dead owner is
    // never evidence: without its fd a matching inode number might be reused.
    let pin = Arc::new(Pin::open(path, context)?);
    // Probe AFTER opening: a witness may die between an earlier liveness check
    // and open, freeing the old inode for reuse. Our open must overlap its life.
    if !live_witness()? {
        anyhow::bail!("lost live per-interface sysctl witness for {path}; keep the journal for manual recovery");
    }
    if pin.object != identity.object {
        anyhow::bail!("per-interface sysctl object changed for {path}; refusing the replacement");
    }
    remember(identity, pin.clone(), context.scope())?;
    Ok(pin)
}

pub(super) fn retain(scope: &Path, leases: BTreeSet<&str>) {
    with_cache(|cache| {
        cache.retain(|id, cached| cached.scope != scope || leases.contains(id.as_str()))
    });
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; private network namespace"]
fn native_descriptor_refuses_recreated_interface_with_reused_index() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: only this disposable thread changes namespace.
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let run = |args: &[&str]| -> anyhow::Result<()> {
            anyhow::ensure!(crate::system_command::Command::new("ip")
                .args(args)
                .output()?
                .status
                .success());
            Ok(())
        };
        run(&["link", "add", "pin-test", "index", "42", "type", "dummy"])?;
        let path = "/proc/sys/net/ipv6/conf/pin-test/accept_ra";
        let original = live_open(path)?;
        live_write(&original, "2\n")?;
        anyhow::ensure!(live_read(&original)?.trim() == "2");
        let id = object_identity(&original)?;
        run(&["link", "del", "pin-test"])?;
        run(&["link", "add", "pin-test", "index", "42", "type", "dummy"])?;
        let replacement = live_open(path)?;
        live_write(&replacement, "2\n")?;
        anyhow::ensure!(object_identity(&replacement)? != id);
        anyhow::ensure!(live_read(&original).unwrap_err().raw_os_error() == Some(libc::ENOENT));
        anyhow::ensure!(
            live_write(&original, "1\n").unwrap_err().raw_os_error() == Some(libc::ENOENT)
        );
        anyhow::ensure!(live_read(&replacement)?.trim() == "2");
        Ok(())
    })
    .join()
    .expect("sysctl target native test panicked")
}

#[cfg(test)]
pub(super) fn test_cache_len() -> usize {
    with_cache(|cache| cache.len())
}
