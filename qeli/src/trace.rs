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
//! Dump with `SIGUSR1` (see [`watch`]) or at a clean shutdown.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    // Copy under the lock and format outside it, so writers are blocked for as short a
    // time as possible (a dump is disk IO; the data plane is not).
    let (events, next, wrapped) = {
        let ring = trace
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (ring.buf.clone(), ring.next, ring.wrapped)
    };
    let mut file = std::fs::File::create(&trace.path)?;
    writeln!(
        file,
        "# qeli packet trace — shapes only, no payloads, no addresses"
    )?;
    writeln!(
        file,
        "# overwritten={} contended={}",
        OVERWRITTEN.load(Ordering::Relaxed),
        CONTENDED.load(Ordering::Relaxed)
    )?;
    writeln!(file, "t_us,dir,site,size,seq")?;
    let order: Box<dyn Iterator<Item = usize>> = if wrapped {
        Box::new((next..CAPACITY).chain(0..next)) // oldest is where we are about to write
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
    file.flush()?;
    Ok(written)
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
        match dump() {
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
}
