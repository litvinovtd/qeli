//! Per-user lifetime traffic accounting + quota bookkeeping (Tier-2).
//!
//! Server-side only — no wire/protocol change, so every client keeps working
//! unchanged. Consumption is kept in a sidecar `usage.json` (NOT the users file,
//! which holds password hashes and is rewritten on every CRUD), so accounting
//! never risks that file.
//!
//! Sessions register their existing atomic counters once. The store keeps those counters
//! until their last writer has gone, so short sessions and shutdown tails survive removal
//! from the live session registry. Sweeps, flushes and resets fold monotonic deltas; the
//! packet path has no additional work.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Sidecar file (qeli-owned, lives beside the config). Re-read by the panel.
#[cfg(all(target_os = "linux", feature = "server"))]
pub const USAGE_PATH: &str = "/etc/qeli/usage.json";

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Migrate a pre-split sidecar in place: an old entry carries only `used_bytes`
/// (down/up default to 0). The historical total can't be split retroactively, so
/// attribute it to DOWNLOAD — the dominant VPN direction and the one the cap
/// limits, so enforcement stays equivalent. Idempotent: once down/up are populated
/// it only re-derives `used_bytes = down + up`, so it's safe to run on every read.
fn migrate_legacy(map: &mut HashMap<String, UserUsage>) {
    for e in map.values_mut() {
        if e.used_down == 0 && e.used_up == 0 && e.used_bytes > 0 {
            e.used_down = e.used_bytes;
        }
        e.used_bytes = e.used_down.saturating_add(e.used_up);
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct UserUsage {
    /// Download: bytes the server sent TO the client (`bytes_sent`). This is the
    /// direction the data cap limits.
    #[serde(default)]
    pub used_down: u64,
    /// Upload: bytes the server received FROM the client (`bytes_recv`).
    #[serde(default)]
    pub used_up: u64,
    /// Combined total (`used_down + used_up`). Kept in sync so pre-split readers and
    /// the legacy sidecar format keep working; the split fields are authoritative.
    pub used_bytes: u64,
    pub last_seen: i64,
    #[serde(default)]
    pub sessions: u64,
}

#[derive(Default)]
struct Inner {
    /// Persisted per-user totals.
    usage: HashMap<String, UserUsage>,
    /// In-memory: `(down, up)` already folded for a live `session_id` (idempotency).
    committed: HashMap<u64, (u64, u64)>,
    tracked: HashMap<u64, SessionCounters>,
}

struct SessionCounters {
    user: String,
    down: Arc<AtomicU64>,
    up: Arc<AtomicU64>,
}

pub struct UsageStore {
    path: String,
    inner: Mutex<Inner>,
    /// When set, this handle NEVER writes: `flush` is a no-op and `Drop` does nothing.
    ///
    /// The supervisor and the worker are separate processes (`qeli _worker`) that each
    /// open this same file. Only the worker accumulates — it folds live counters and
    /// flushes periodically, then flushes once more on SIGTERM before
    /// `std::process::exit(0)`, which deliberately skips destructors. The supervisor
    /// merely serves `/api/usage`, refreshing its copy with `reload()` when the panel
    /// asks. But it held a full read-write store, so its `Drop::flush` fired on a normal
    /// shutdown and wrote back the snapshot it had read at STARTUP — silently rolling the
    /// file back to that point. Every `systemctl restart qeli`, including the panel's
    /// "Apply & Restart" button, therefore discarded all accounting since the supervisor
    /// booted, and users past their quota passed the check again. Quotas effectively did
    /// not survive a restart. (Audit 2026-07-27, K3.)
    read_only: bool,
}

impl UsageStore {
    /// Load the sidecar read-write (the worker's handle).
    ///
    /// Absence is the normal first-run state. Any other read or parse error is fatal for the
    /// worker: starting empty would disable quota enforcement and the next flush would erase
    /// the only recoverable copy of the accounting data.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let usage = Self::read_usage(path)?;
        Ok(UsageStore {
            path: path.to_string(),
            inner: Mutex::new(Inner {
                usage,
                ..Inner::default()
            }),
            read_only: false,
        })
    }

    /// Load the sidecar for READING only — see the `read_only` field.
    ///
    /// Also skips moving a corrupt file aside: that is a write, and the worker owns this
    /// file. Two processes renaming it concurrently is exactly the race this avoids.
    pub fn load_read_only(path: &str) -> Self {
        let usage = match Self::read_usage(path) {
            Ok(usage) => usage,
            Err(error) => {
                log::warn!(
                    "usage: cannot load {path} in the read-only panel process ({error}); \
                     reporting an empty view without modifying the worker-owned file"
                );
                HashMap::new()
            }
        };
        UsageStore {
            path: path.to_string(),
            inner: Mutex::new(Inner {
                usage,
                ..Inner::default()
            }),
            read_only: true,
        }
    }

    fn read_usage(path: &str) -> anyhow::Result<HashMap<String, UserUsage>> {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(error) => anyhow::bail!("failed to read {path}: {error}"),
        };
        let mut usage = serde_json::from_str::<HashMap<String, UserUsage>>(&contents)
            .map_err(|error| anyhow::anyhow!("failed to parse {path}: {error}"))?;
        migrate_legacy(&mut usage);
        Ok(usage)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Retain counters, not the session or its resources. Writers may outlive the registry
    /// entry; keeping the atomic pair lets the next sweep account for their final bytes.
    pub fn track(&self, session_id: u64, user: &str, down: Arc<AtomicU64>, up: Arc<AtomicU64>) {
        self.lock()
            .tracked
            .entry(session_id)
            .or_insert_with(|| SessionCounters {
                user: user.to_string(),
                down,
                up,
            });
    }

    fn fold_inner(g: &mut Inner, session_id: u64, user: &str, cur_down: u64, cur_up: u64) {
        let (prev_down, prev_up) = g.committed.get(&session_id).copied().unwrap_or((0, 0));
        if cur_down > prev_down || cur_up > prev_up {
            let first = !g.committed.contains_key(&session_id);
            g.committed
                .insert(session_id, (cur_down.max(prev_down), cur_up.max(prev_up)));
            let e = g.usage.entry(user.to_string()).or_default();
            e.used_down = e
                .used_down
                .saturating_add(cur_down.saturating_sub(prev_down));
            e.used_up = e.used_up.saturating_add(cur_up.saturating_sub(prev_up));
            e.used_bytes = e.used_down.saturating_add(e.used_up);
            e.last_seen = now_unix();
            if first {
                e.sessions = e.sessions.saturating_add(1);
            }
        }
    }

    #[cfg(test)]
    fn fold(&self, session_id: u64, user: &str, down: u64, up: u64) {
        Self::fold_inner(&mut self.lock(), session_id, user, down, up);
    }

    fn collect_inner(inner: &mut Inner) {
        let mut tracked = std::mem::take(&mut inner.tracked);
        tracked.retain(|id, counters| {
            // get_mut establishes exclusive ownership (including absence of weak refs).
            // Unlike a relaxed strong_count snapshot, it synchronizes with the last
            // writer's drop before we sample and retire its counters.
            let finished = Arc::get_mut(&mut counters.down).is_some()
                && Arc::get_mut(&mut counters.up).is_some();
            Self::fold_inner(
                inner,
                *id,
                &counters.user,
                counters.down.load(Ordering::Relaxed),
                counters.up.load(Ordering::Relaxed),
            );
            if finished {
                inner.committed.remove(id);
            }
            !finished
        });
        inner.tracked = tracked;
    }

    pub fn collect(&self) {
        Self::collect_inner(&mut self.lock());
    }

    /// Combined lifetime total (download + upload).
    pub fn used_bytes(&self, user: &str) -> u64 {
        self.lock()
            .usage
            .get(user)
            .map(|u| u.used_bytes)
            .unwrap_or(0)
    }

    /// Lifetime DOWNLOAD total (server→client). This is the direction the data cap
    /// limits, so quota enforcement reads this, not the combined total.
    pub fn used_down(&self, user: &str) -> u64 {
        self.lock()
            .usage
            .get(user)
            .map(|u| u.used_down)
            .unwrap_or(0)
    }

    /// Zero a user's counters and persist the change as one transaction.
    ///
    /// Keep the mutex across serialization and atomic replacement so the usage sweep cannot
    /// fold a delta between mutation and publication. Failures before rename restore the
    /// previous counters. If rename succeeded but directory sync failed, retain the published
    /// reset and report uncertain durability; restoring memory would disagree with the file.
    pub fn reset_and_flush(&self, user: &str) -> anyhow::Result<()> {
        self.reset_with_writer(user, |path, bytes| crate::util::write_atomic(path, bytes))
    }

    fn reset_with_writer(
        &self,
        user: &str,
        write: impl FnOnce(&str, &[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        if self.read_only {
            anyhow::bail!("cannot reset usage through a read-only store");
        }
        let mut inner = self.lock();
        // Advance live baselines before resetting, including traffic not swept yet.
        Self::collect_inner(&mut inner);
        let previous = inner.usage.get(user).cloned();
        if let Some(usage) = inner.usage.get_mut(user) {
            usage.used_down = 0;
            usage.used_up = 0;
            usage.used_bytes = 0;
        }
        let result = serde_json::to_vec_pretty(&inner.usage)
            .map_err(|error| anyhow::anyhow!("failed to encode {}: {error}", self.path))
            .and_then(|json| {
                write(&self.path, &json)
                    .map_err(|error| error.context(format!("failed to persist {}", self.path)))
            });
        if let Err(error) = result {
            // Publication is irreversible here. Preserve the typed cause through context,
            // so the control API can distinguish uncertainty from an unchanged store.
            if crate::util::atomic_write_was_published(&error) {
                return Err(error);
            }
            match previous {
                Some(usage) => {
                    inner.usage.insert(user.to_string(), usage);
                }
                None => {
                    inner.usage.remove(user);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> HashMap<String, UserUsage> {
        self.lock().usage.clone()
    }

    /// Keep mutex waits as well as disk I/O off the reactor. The owned host
    /// worker joins on cancellation; no flush can outlive the worker's lease.
    pub async fn track_async(
        self: &Arc<Self>,
        session_id: u64,
        user: String,
        down: Arc<AtomicU64>,
        up: Arc<AtomicU64>,
    ) -> anyhow::Result<()> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-read", move || {
            store.track(session_id, &user, down, up);
        })
        .await
    }

    pub async fn collect_snapshot_async(
        self: &Arc<Self>,
    ) -> anyhow::Result<HashMap<String, UserUsage>> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-read", move || {
            store.collect();
            store.snapshot()
        })
        .await
    }

    pub async fn used_down_async(self: &Arc<Self>, user: String) -> anyhow::Result<u64> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-read", move || store.used_down(&user)).await
    }

    pub async fn reset_and_flush_async(self: &Arc<Self>, user: String) -> anyhow::Result<()> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-save", move || store.reset_and_flush(&user))
            .await?
    }

    pub async fn reload_snapshot_async(
        self: &Arc<Self>,
    ) -> anyhow::Result<HashMap<String, UserUsage>> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-read", move || {
            store.reload()?;
            Ok(store.snapshot())
        })
        .await?
    }

    pub async fn flush_async(self: &Arc<Self>) -> anyhow::Result<()> {
        self.flush_with_writer_async(|path, bytes| crate::util::write_atomic(path, bytes))
            .await
    }

    async fn flush_with_writer_async(
        self: &Arc<Self>,
        write: impl FnOnce(&str, &[u8]) -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<()> {
        let store = self.clone();
        crate::profile_teardown::blocking("qeli-usage-save", move || store.flush_with_writer(write))
            .await?
    }

    /// Re-read the on-disk file — used by the supervisor/panel to observe the
    /// worker's flushes (the two run in separate processes).
    pub fn reload(&self) -> anyhow::Result<()> {
        // Parse into a new map first. On failure the last good snapshot stays available for
        // diagnostics, but the caller receives the error and must not present it as current.
        let usage = Self::read_usage(&self.path)?;
        self.lock().usage = usage;
        Ok(())
    }

    /// Persist atomically (temp + rename) so a crash can't truncate the file.
    ///
    /// A read-only handle never writes — see the `read_only` field for why the
    /// supervisor must not.
    pub fn flush(&self) -> anyhow::Result<()> {
        self.flush_with_writer(|path, bytes| crate::util::write_atomic(path, bytes))
    }

    fn flush_with_writer(
        &self,
        write: impl FnOnce(&str, &[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        if self.read_only {
            log::trace!("usage: flush skipped (read-only handle)");
            return Ok(());
        }
        // Serialize and replace while holding the same lock used by reset_and_flush. If a
        // periodic flush took a snapshot and released the lock before writing, it could write
        // that stale snapshot *after* a successful admin reset and silently undo the reset.
        let mut inner = self.lock();
        Self::collect_inner(&mut inner);
        let json = serde_json::to_vec_pretty(&inner.usage)
            .map_err(|error| anyhow::anyhow!("failed to encode {}: {error}", self.path))?;
        write(&self.path, &json)
            .map_err(|error| anyhow::anyhow!("failed to persist {}: {error}", self.path))
    }
}

impl Drop for UsageStore {
    /// Best-effort collection and final flush on graceful teardown, including
    /// counters whose sessions have already left the live registry. A hard
    /// `SIGKILL` still skips this (Drop can't run). Changes since the last successful
    /// periodic persistence can be lost.
    fn drop(&mut self) {
        if let Err(error) = self.flush() {
            log::error!("usage: final flush failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocked_usage_persistence_leaves_reactor_live_and_reset_ordered() {
        let path = empty_store_path("async-blocked-flush");
        let store = Arc::new(UsageStore::load(&path).unwrap());
        let (down, up) = counters(&store, 71);
        down.store(700, Ordering::Relaxed);
        up.store(30, Ordering::Relaxed);
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let saving = store.clone();
        let flush = tokio::spawn(async move {
            saving
                .flush_with_writer_async(move |path, bytes| {
                    assert_eq!(std::thread::current().name(), Some("qeli-usage-save"));
                    let _ = entered.send(());
                    held.recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    crate::util::write_atomic(path, bytes)
                })
                .await
        });
        waiting.await.unwrap();
        let resetting = store.clone();
        let reset =
            tokio::spawn(async move { resetting.reset_and_flush_async("alice".into()).await });
        let tracking = store.clone();
        let track = tokio::spawn(async move {
            tracking
                .track_async(
                    73,
                    "bob".into(),
                    Arc::new(AtomicU64::new(30)),
                    Arc::new(AtomicU64::new(0)),
                )
                .await
        });
        // A single-thread Tokio runtime must still serve timers while both disk
        // I/O and the reset's mutex acquisition are blocked on owned OS threads.
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::time::sleep(std::time::Duration::from_millis(2)),
        )
        .await
        .unwrap();
        assert!(!flush.is_finished());
        assert!(!reset.is_finished());
        assert!(!track.is_finished());
        release.send(()).unwrap();
        flush.await.unwrap().unwrap();
        reset.await.unwrap().unwrap();
        track.await.unwrap().unwrap();
        down.fetch_add(20, Ordering::Relaxed);
        store.flush_async().await.unwrap();
        assert_eq!(store.used_down_async("alice".into()).await.unwrap(), 20);
        assert_eq!(UsageStore::load_read_only(&path).used_down("alice"), 20);
        assert_eq!(store.used_down_async("bob".into()).await.unwrap(), 30);
        drop((down, up, store));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn async_usage_failure_preserves_accounting_for_retry() {
        let path = empty_store_path("async-failed-flush");
        let store = Arc::new(UsageStore::load(&path).unwrap());
        let (down, up) = counters(&store, 72);
        down.store(90, Ordering::Relaxed);
        assert!(store
            .flush_with_writer_async(|_, _| anyhow::bail!("injected write failure"))
            .await
            .is_err());
        assert_eq!(
            store.collect_snapshot_async().await.unwrap()["alice"].used_down,
            90
        );
        store.flush_async().await.unwrap();
        assert_eq!(
            store.reload_snapshot_async().await.unwrap()["alice"].used_down,
            90
        );
        drop((down, up, store));
        std::fs::remove_file(path).unwrap();
    }

    /// A path for a store that must start EMPTY.
    ///
    /// These used to point at `/nonexistent/…`, on the assumption that the directory
    /// could never be written to. That assumption is environmental, not guaranteed —
    /// on a host where `/nonexistent` happens to exist (ours does), `Drop::flush`
    /// succeeds, the next `load()` reads the previous run's totals back, and the
    /// counts grow by one run every time (`sessions: 2` became 6 after three runs).
    /// Use a unique private temp path so parallel runs cannot inherit or erase each other.
    fn empty_store_path(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "qeli-usage-test-{tag}-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        p.to_string_lossy().into_owned()
    }
    /// A read-only handle must not write the file — not via `flush`, and not via `Drop`.
    ///
    /// Reproduces the supervisor/worker interaction that rolled accounting back on every
    /// restart: the supervisor loads at T0, the worker accumulates to T1, the supervisor
    /// exits and its destructor writes T0 over T1. (Audit 2026-07-27, K3.)
    #[test]
    fn read_only_handle_never_writes_the_file() {
        let path = empty_store_path("k3");

        // T0: the supervisor's view at startup — empty.
        let supervisor = UsageStore::load_read_only(&path);
        assert!(supervisor.snapshot().is_empty());

        // The worker accumulates and persists T1.
        {
            let worker = UsageStore::load(&path).unwrap();
            worker.fold(1, "alice", 1_000, 100);
            worker.flush().unwrap();
        }
        let after_worker = std::fs::read_to_string(&path).expect("worker must have written");
        assert!(after_worker.contains("alice"));

        // An explicit flush on the read-only handle must be a no-op...
        supervisor.flush().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after_worker,
            "read-only flush must not touch the file"
        );

        // ...and so must its Drop, which is what actually caused the regression.
        drop(supervisor);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after_worker,
            "read-only Drop must not roll the file back to the startup snapshot"
        );

        // Sanity: the writable handle still round-trips what the worker stored.
        let reread = UsageStore::load(&path).unwrap();
        assert_eq!(reread.used_down("alice"), 1_000);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_only_reload_reports_corruption_and_keeps_the_last_good_snapshot() {
        let path = empty_store_path("reload-corrupt");
        {
            let worker = UsageStore::load(&path).unwrap();
            worker.fold(1, "alice", 1_000, 100);
            worker.flush().unwrap();
        }
        let panel = UsageStore::load_read_only(&path);
        assert_eq!(panel.used_down("alice"), 1_000);

        std::fs::write(&path, b"{ broken usage json").unwrap();
        assert!(panel.reload().is_err());
        assert_eq!(
            panel.used_down("alice"),
            1_000,
            "a failed refresh must not replace the last diagnostic snapshot"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writable_store_refuses_corrupt_accounting_without_modifying_it() {
        let path = empty_store_path("corrupt");
        let original = b"{ definitely not usage json";
        std::fs::write(&path, original).unwrap();

        let result = UsageStore::load(&path);
        assert!(result.is_err(), "quota enforcement must fail closed");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "the only recoverable accounting copy must remain untouched"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fold_counts_each_session_once() {
        let s = UsageStore::load(&empty_store_path("a4")).unwrap();
        s.fold(1, "alice", 80, 20); // down 80, up 20
        s.fold(1, "alice", 200, 50); // same session grows → still ONE connection
        s.fold(2, "alice", 40, 10); // a second session for alice
        s.fold(3, "bob", 10, 0);
        let snap = s.snapshot();
        assert_eq!(
            snap["alice"].sessions, 2,
            "two distinct session_ids = 2 connections"
        );
        assert_eq!(snap["alice"].used_down, 240, "200 + 40");
        assert_eq!(snap["alice"].used_up, 60, "50 + 10");
        assert_eq!(snap["alice"].used_bytes, 300, "down + up");
        assert_eq!(s.used_down("alice"), 240, "quota reads download only");
        assert_eq!(snap["bob"].sessions, 1);
    }

    #[test]
    fn fold_does_not_double_count_a_live_session() {
        let s = UsageStore::load(&empty_store_path("a4b")).unwrap();
        for (d, u) in [(10u64, 1u64), (20, 3), (30, 6), (40, 10)] {
            s.fold(7, "carol", d, u);
        }
        let snap = s.snapshot();
        assert_eq!(
            snap["carol"].sessions, 1,
            "repeated folds of one session = 1"
        );
        assert_eq!(snap["carol"].used_down, 40, "latest download total");
        assert_eq!(snap["carol"].used_up, 10, "latest upload total");
    }

    #[test]
    fn migrate_attributes_legacy_total_to_download() {
        let mut m = HashMap::new();
        // Pre-split entry: only used_bytes set, down/up default 0.
        m.insert(
            "old".to_string(),
            UserUsage {
                used_bytes: 1500,
                last_seen: 1,
                sessions: 3,
                ..Default::default()
            },
        );
        // Already-split entry must be left alone (only used_bytes re-derived).
        m.insert(
            "new".to_string(),
            UserUsage {
                used_down: 200,
                used_up: 50,
                used_bytes: 0,
                last_seen: 1,
                sessions: 1,
            },
        );
        migrate_legacy(&mut m);
        assert_eq!(m["old"].used_down, 1500, "legacy total → download");
        assert_eq!(m["old"].used_up, 0);
        assert_eq!(m["old"].used_bytes, 1500);
        assert_eq!(m["new"].used_down, 200, "split entry untouched");
        assert_eq!(m["new"].used_up, 50);
        assert_eq!(m["new"].used_bytes, 250, "used_bytes re-derived");
    }

    #[test]
    fn reset_zeroes_both_directions() {
        let s = UsageStore::load(&empty_store_path("a4c")).unwrap();
        s.fold(1, "dave", 500, 100);
        s.reset_and_flush("dave").unwrap();
        let snap = s.snapshot();
        assert_eq!(snap["dave"].used_down, 0);
        assert_eq!(snap["dave"].used_up, 0);
        assert_eq!(snap["dave"].used_bytes, 0);
    }

    #[test]
    fn failed_reset_persistence_restores_in_memory_counters() {
        let unwritable_path = std::env::temp_dir().join(format!(
            "qeli-usage-reset-directory-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&unwritable_path).unwrap();
        let store = UsageStore {
            path: unwritable_path.to_string_lossy().into_owned(),
            inner: Mutex::new(Inner::default()),
            read_only: false,
        };
        let down = Arc::new(AtomicU64::new(700));
        let up = Arc::new(AtomicU64::new(30));
        store.track(1, "erin", down.clone(), up.clone());

        assert!(store.reset_and_flush("erin").is_err());
        assert_eq!(store.used_down("erin"), 700);
        assert_eq!(store.snapshot()["erin"].used_up, 30);
        down.fetch_add(20, Ordering::Relaxed);
        drop((down, up));
        store.collect();
        assert_eq!(store.used_down("erin"), 720);

        drop(store);
        std::fs::remove_dir(&unwritable_path).unwrap();
    }

    fn counters(store: &UsageStore, id: u64) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        let down = Arc::new(AtomicU64::new(0));
        let up = Arc::new(AtomicU64::new(0));
        store.track(id, "alice", down.clone(), up.clone());
        (down, up)
    }

    #[test]
    fn completed_session_between_sweeps_is_persisted_and_retired() {
        let path = empty_store_path("short-session");
        let store = UsageStore::load(&path).unwrap();
        let (down, up) = counters(&store, 1);
        down.store(900, Ordering::Relaxed);
        up.store(70, Ordering::Relaxed);
        drop((down, up)); // No live session remains when the first sweep runs.
        store.flush().unwrap();
        store.flush().unwrap();
        let persisted = UsageStore::load_read_only(&path).snapshot();
        assert_eq!(persisted["alice"].used_down, 900);
        assert_eq!(persisted["alice"].used_up, 70);
        assert_eq!(persisted["alice"].sessions, 1);
        assert!(store.lock().tracked.is_empty());
        assert!(store.lock().committed.is_empty());
    }

    #[test]
    fn writer_outliving_session_keeps_baseline_until_final_bytes() {
        let store = UsageStore::load(&empty_store_path("writer-tail")).unwrap();
        let (down, up) = counters(&store, 2);
        down.store(100, Ordering::Relaxed);
        up.store(10, Ordering::Relaxed);
        store.collect();
        let writer = down.clone();
        drop((down, up)); // registry/session drops, but its writer is still finishing.
        store.collect();
        assert_eq!(store.lock().tracked.len(), 1);
        writer.fetch_add(40, Ordering::Relaxed);
        store.collect();
        writer.fetch_add(60, Ordering::Relaxed);
        drop(writer);
        store.collect();
        store.collect();
        assert_eq!(store.used_down("alice"), 200);
        assert_eq!(store.used_bytes("alice"), 210);
        assert_eq!(store.snapshot()["alice"].sessions, 1);
        assert!(store.lock().tracked.is_empty());
        assert!(store.lock().committed.is_empty());
    }

    #[test]
    fn reset_collects_unswept_traffic_and_preserves_live_baseline() {
        let store = UsageStore::load(&empty_store_path("reset-live")).unwrap();
        let (down, up) = counters(&store, 3);
        down.store(100, Ordering::Relaxed);
        up.store(25, Ordering::Relaxed);
        store.reset_and_flush("alice").unwrap();
        assert_eq!(store.used_bytes("alice"), 0);
        down.fetch_add(30, Ordering::Relaxed);
        up.fetch_add(5, Ordering::Relaxed);
        drop((down, up));
        store.flush().unwrap();
        assert_eq!(store.used_down("alice"), 30);
        assert_eq!(store.snapshot()["alice"].used_up, 5);
        assert_eq!(store.snapshot()["alice"].sessions, 1);
    }

    #[test]
    fn final_drop_collects_tail_after_last_periodic_sweep() {
        let path = empty_store_path("drop-tail");
        let store = UsageStore::load(&path).unwrap();
        let (down, up) = counters(&store, 4);
        down.store(50, Ordering::Relaxed);
        store.collect();
        down.fetch_add(250, Ordering::Relaxed);
        up.store(25, Ordering::Relaxed);
        drop((down, up));
        drop(store);
        let persisted = UsageStore::load_read_only(&path);
        assert_eq!(persisted.used_down("alice"), 300);
        assert_eq!(persisted.used_bytes("alice"), 325);
    }

    #[test]
    fn concurrent_writers_and_collection_account_exact_total() {
        let store = UsageStore::load(&empty_store_path("concurrent-writers")).unwrap();
        let (down, up) = counters(&store, 5);
        let writer = std::thread::spawn(move || {
            for _ in 0..20_000 {
                down.fetch_add(3, Ordering::Relaxed);
                up.fetch_add(2, Ordering::Relaxed);
            }
        });
        for _ in 0..100 {
            store.collect();
        }
        writer.join().unwrap();
        store.collect();
        assert_eq!(store.used_down("alice"), 60_000);
        assert_eq!(store.used_bytes("alice"), 100_000);
        assert_eq!(store.snapshot()["alice"].sessions, 1);
        assert!(store.lock().tracked.is_empty());
    }

    #[test]
    fn repeated_registration_and_empty_flush_do_not_reset_baseline() {
        let store = UsageStore::load(&empty_store_path("registration")).unwrap();
        let (down, up) = counters(&store, 6);
        store.flush().unwrap();
        assert_eq!(store.lock().tracked.len(), 1);
        down.store(80, Ordering::Relaxed);
        store.collect();
        store.track(6, "alice", down.clone(), up.clone());
        down.fetch_add(20, Ordering::Relaxed);
        drop((down, up));
        store.flush().unwrap();
        assert_eq!(store.used_down("alice"), 100);
        assert_eq!(store.snapshot()["alice"].sessions, 1);
    }

    #[test]
    fn published_reset_sync_error_keeps_memory_and_file_consistent() {
        let path = empty_store_path("reset-published");
        let store = UsageStore::load(&path).unwrap();
        let (down, up) = counters(&store, 7);
        down.store(700, Ordering::Relaxed);
        up.store(30, Ordering::Relaxed);
        store.fold(8, "bob", 90, 10);
        store.flush().unwrap();

        let error = store
            .reset_with_writer("alice", |path, bytes| {
                crate::util::write_atomic_test_sync_failure(std::path::Path::new(path), bytes)
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("persistence is uncertain"));
        let published = UsageStore::load_read_only(&path);
        assert_eq!(
            published.used_down("alice"),
            0,
            "rename really published reset"
        );
        assert_eq!(
            store.used_down("alice"),
            0,
            "cannot fabricate rollback after rename"
        );
        assert!(crate::util::atomic_write_was_published(&error));
        assert_eq!(store.used_bytes("bob"), 100);
        assert_eq!(published.used_bytes("bob"), 100);

        // A subsequent sweep must count only new traffic and never undo the reset.
        down.fetch_add(20, Ordering::Relaxed);
        up.fetch_add(5, Ordering::Relaxed);
        drop((down, up));
        store.flush().unwrap();
        store.flush().unwrap();
        let persisted = UsageStore::load_read_only(&path);
        assert_eq!(store.used_down("alice"), 20);
        assert_eq!(persisted.used_bytes("alice"), 25);
        assert_eq!(persisted.snapshot()["alice"].sessions, 1);
        assert!(store.lock().tracked.is_empty());
        drop(store);
        std::fs::remove_file(&path).unwrap();
    }
}
