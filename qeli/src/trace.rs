//! Opt-in packet timeline for diagnosing the data plane.
//!
//! Off unless `QELI_TRACE` names a file. When on it records only packet *shapes* —
//! a monotonic timestamp, a direction, the call site, a byte count and an optional
//! stream index. Never payloads and never addresses: a trace should be safe to hand
//! to someone else, and a dump of a user's tunnel is not.
//!
//! Design constraints, in order of importance:
//!  * zero cost when off — one relaxed atomic load per call site;
//!  * never block the data plane — the ring sits behind a `try_lock`, and a contended
//!    write is dropped (and counted) rather than waited on, because stalling to log a
//!    packet would distort the very timings being measured;
//!  * bounded memory — a fixed ring; the oldest events are overwritten.
//!
//! Both ends write their own file, so a client and a server trace line up into one
//! timeline. There is no shared packet id to join on (the codec's counter is not
//! exposed at these call sites), so correlation is by time and size — good enough to
//! answer "did this packet leave, and when did the other end see it".
//!
//! Dump with `SIGUSR1` (see [`watch`]). Shutdown does not dump automatically.

use std::io::Write;
// AtomicU64 via portable-atomic, not std: mipsel (Keenetic routers) has no native 64-bit
// atomics, so `std::sync::atomic::AtomicU64` does not exist there and the router client
// fails to build. Same reason client/mod.rs imports it from here.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Events held in memory (~40 B each ⇒ ~2.6 MB).
const CAPACITY: usize = 65_536;

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Events lost to ring wrap-around, and to lock contention. Both are reported in the
/// dump header so a trace is never silently partial.
static OVERWRITTEN: AtomicU64 = AtomicU64::new(0);
static CONTENDED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub enum Dir {
    /// Read off the local TUN, heading for the wire.
    Tx,
    /// Arrived from the wire, heading for the local TUN.
    Rx,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::Tx => "tx",
            Dir::Rx => "rx",
        }
    }
}

#[derive(Clone, Copy)]
struct Event {
    t_us: u64,
    dir: Dir,
    site: &'static str,
    size: u32,
    seq: u64,
}

struct Ring {
    buf: Vec<Event>,
    next: usize,
    wrapped: bool,
}

struct Trace {
    start: Instant,
    path: String,
    ring: Mutex<Ring>,
}

static TRACE: OnceLock<Trace> = OnceLock::new();
// One snapshot/write at a time, including a blocking dump whose watcher was cancelled.
static DUMPS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Arm tracing if `QELI_TRACE` names a destination file. Call once at startup;
/// everything else in this module is a no-op until it has run.
pub fn init() {
    let Ok(path) = std::env::var("QELI_TRACE") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let trace = Trace {
        start: Instant::now(),
        path: path.clone(),
        ring: Mutex::new(Ring {
            buf: vec![
                Event {
                    t_us: 0,
                    dir: Dir::Tx,
                    site: "",
                    size: 0,
                    seq: 0,
                };
                CAPACITY
            ],
            next: 0,
            wrapped: false,
        }),
    };
    if TRACE.set(trace).is_err() {
        return; // already armed
    }
    ENABLED.store(true, Ordering::Relaxed);
    log::info!(
        "packet trace armed: last {} events, SIGUSR1 dumps to {} (shapes only — no payloads)",
        CAPACITY,
        path
    );
}

/// Record one packet. `seq` carries a stream index where the call site has one
/// (bonded streams) and 0 otherwise.
pub fn record(dir: Dir, site: &'static str, size: usize, seq: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Some(trace) = TRACE.get() else {
        return;
    };
    let event = Event {
        t_us: trace.start.elapsed().as_micros() as u64,
        dir,
        site,
        size: size as u32,
        seq,
    };
    // Never wait: a held lock means another writer or a dump in progress, and blocking
    // the data plane for a diagnostic would skew the measurement it exists to take.
    let Ok(mut ring) = trace.ring.try_lock() else {
        CONTENDED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if ring.wrapped {
        OVERWRITTEN.fetch_add(1, Ordering::Relaxed);
    }
    let i = ring.next;
    ring.buf[i] = event;
    ring.next = i + 1;
    if ring.next == CAPACITY {
        ring.next = 0;
        ring.wrapped = true;
    }
}

/// Write the ring to the configured file, oldest event first. Returns how many events
/// were written (0 when tracing was never armed).
pub fn dump() -> std::io::Result<usize> {
    let Some(trace) = TRACE.get() else {
        return Ok(0);
    };
    let _permit = DUMPS.try_acquire().map_err(|_| dump_busy())?;
    dump_trace(trace)
}

fn dump_busy() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "packet trace dump already in progress",
    )
}

fn dump_trace(trace: &Trace) -> std::io::Result<usize> {
    // Copy under the lock and format outside it, so writers are blocked for as short a
    // time as possible (a dump is disk IO; the data plane is not).
    let (events, next, wrapped, overwritten, contended) = {
        let ring = trace
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            ring.buf.clone(),
            ring.next,
            ring.wrapped,
            OVERWRITTEN.load(Ordering::Relaxed),
            CONTENDED.load(Ordering::Relaxed),
        )
    };
    // Render before publication. Atomic private replacement never truncates the last
    // complete dump or follows a destination symlink/FIFO. Memory stays bounded by
    // the fixed ring and static capture-site labels, with only one admitted dump.
    let mut file = Vec::new();
    writeln!(
        file,
        "# qeli packet trace — shapes only, no payloads, no addresses"
    )?;
    writeln!(
        file,
        "# overwritten={} contended={}",
        overwritten, contended
    )?;
    writeln!(file, "t_us,dir,site,size,seq")?;
    let order: Box<dyn Iterator<Item = usize>> = if wrapped {
        Box::new((next..events.len()).chain(0..next)) // oldest is where we are about to write
    } else {
        Box::new(0..next)
    };
    let mut written = 0usize;
    for i in order {
        let e = &events[i];
        writeln!(
            file,
            "{},{},{},{},{}",
            e.t_us,
            e.dir.as_str(),
            e.site,
            e.size,
            e.seq
        )?;
        written += 1;
    }
    crate::util::write_atomic_private(&trace.path, &file).map_err(std::io::Error::other)?;
    Ok(written)
}

// Admission precedes spawn_blocking, so repeated signals/watchers cannot queue
// unbounded snapshots. Filesystem syscalls cannot be force-cancelled: a running
// job keeps admission after its async caller is dropped.
async fn background_dump(
    gate: &'static tokio::sync::Semaphore,
    write: impl FnOnce() -> std::io::Result<usize> + Send + 'static,
) -> std::io::Result<usize> {
    let permit = gate.try_acquire().map_err(|_| dump_busy())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        write()
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Dump on every `SIGUSR1`. Returns immediately when tracing is not armed, so it is
/// safe to spawn unconditionally.
#[cfg(unix)]
pub async fn watch() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
    {
        Ok(s) => s,
        Err(e) => {
            log::warn!("packet trace: cannot install the SIGUSR1 handler: {}", e);
            return;
        }
    };
    while sig.recv().await.is_some() {
        let Some(trace) = TRACE.get() else {
            return;
        };
        match background_dump(&DUMPS, move || dump_trace(trace)).await {
            Ok(n) => log::info!("packet trace: wrote {} events", n),
            Err(e) => log::warn!("packet trace: dump failed: {}", e),
        }
    }
}

#[cfg(not(unix))]
pub async fn watch() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_is_a_noop_until_armed() {
        // The whole point of the ENABLED gate: call sites stay free in production.
        record(Dir::Tx, "test", 1234, 0);
        assert!(!ENABLED.load(Ordering::Relaxed));
        assert_eq!(dump().unwrap(), 0);
    }

    #[test]
    fn ring_reports_oldest_first_after_wrapping() {
        // Exercises the ordering logic directly (arming is process-global, so the ring
        // is driven here rather than through init()).
        let mut ring = Ring {
            buf: vec![
                Event {
                    t_us: 0,
                    dir: Dir::Tx,
                    site: "",
                    size: 0,
                    seq: 0
                };
                4
            ],
            next: 0,
            wrapped: false,
        };
        for n in 0..6u64 {
            let i = ring.next;
            ring.buf[i] = Event {
                t_us: n,
                dir: Dir::Tx,
                site: "t",
                size: 0,
                seq: n,
            };
            ring.next = i + 1;
            if ring.next == 4 {
                ring.next = 0;
                ring.wrapped = true;
            }
        }
        assert!(ring.wrapped);
        let order: Vec<usize> = (ring.next..4).chain(0..ring.next).collect();
        let seen: Vec<u64> = order.iter().map(|&i| ring.buf[i].t_us).collect();
        assert_eq!(
            seen,
            vec![2, 3, 4, 5],
            "oldest surviving event must come first"
        );
    }
    fn fixture() -> (std::path::PathBuf, Trace) {
        let root = std::env::temp_dir().join(format!(
            "qeli-trace-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        let trace = Trace {
            start: Instant::now(),
            path: root.join("trace.csv").to_str().unwrap().to_string(),
            ring: Mutex::new(Ring {
                buf: vec![Event {
                    t_us: 7,
                    dir: Dir::Rx,
                    site: "fixture",
                    size: 42,
                    seq: 3,
                }],
                next: 1,
                wrapped: false,
            }),
        };
        (root, trace)
    }

    #[test]
    fn atomic_dump_keeps_symlink_target_and_replaces_fifo_without_waiting() {
        use std::{
            ffi::CString,
            os::unix::{
                ffi::OsStrExt,
                fs::{symlink, PermissionsExt},
            },
        };
        let (root, trace) = fixture();
        let path = std::path::Path::new(&trace.path);
        let other = root.join("other");
        std::fs::write(&other, "previous-secret").unwrap();
        symlink(&other, path).unwrap();
        assert_eq!(dump_trace(&trace).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "previous-secret");
        assert!(!std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let csv = std::fs::read_to_string(path).unwrap();
        assert!(csv.ends_with("7,rx,fixture,42,3\n"));
        std::fs::remove_file(path).unwrap();
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // The overall isolated test process has a deadline as a regression backstop.
        assert_eq!(dump_trace(&trace).unwrap(), 1);
        assert!(std::fs::metadata(path).unwrap().is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_publication_leaves_existing_destination_intact() {
        let (root, mut trace) = fixture();
        let directory = root.join("directory");
        std::fs::create_dir(&directory).unwrap();
        let previous = directory.join("previous");
        std::fs::write(&previous, "preserved").unwrap();
        trace.path = directory.to_str().unwrap().to_string();
        assert!(dump_trace(&trace).is_err());
        assert_eq!(std::fs::read_to_string(previous).unwrap(), "preserved");
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            1,
            "failed temporary dump must be cleaned up"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dump_io_does_not_block_runtime_and_cancellation_keeps_admission() {
        let gate = Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
        let (start, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let caller = tokio::spawn(background_dump(gate, move || {
            let _ = start.send(());
            released
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            Ok(1)
        }));
        started.await.unwrap();
        // This timer must run while the filesystem job is stalled on the single-thread runtime.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let error = background_dump(gate, || panic!("dump bypassed admission"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(gate.available_permits(), 0);
        release.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), gate.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(background_dump(gate, || Ok(2)).await.unwrap(), 2);
    }
}
