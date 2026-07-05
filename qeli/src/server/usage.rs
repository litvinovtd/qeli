//! Per-user lifetime traffic accounting + quota bookkeeping (Tier-2).
//!
//! Server-side only — no wire/protocol change, so every client keeps working
//! unchanged. Consumption is kept in a sidecar `usage.json` (NOT the users file,
//! which holds password hashes and is rewritten on every CRUD), so accounting
//! never risks that file.
//!
//! Accounting is driven by the worker's usage sweep (see `server::usage_sweep`):
//! once every few seconds it reads each live session's byte counters — which the
//! data plane already increments per packet — and folds the *delta since last
//! seen* into the per-user total. Folding is keyed by `session_id` and idempotent
//! (`committed` marker), so nothing is double-counted and the hot path is never
//! touched: zero added per-packet work.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sidecar file (qeli-owned, lives beside the config). Re-read by the panel.
pub const USAGE_PATH: &str = "/etc/qeli/usage.json";

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct UserUsage {
    pub used_bytes: u64,
    pub last_seen: i64,
    #[serde(default)]
    pub sessions: u64,
}

#[derive(Default)]
struct Inner {
    /// Persisted per-user totals.
    usage: HashMap<String, UserUsage>,
    /// In-memory: bytes already folded for a live `session_id` (idempotency).
    committed: HashMap<u64, u64>,
}

pub struct UsageStore {
    path: String,
    inner: Mutex<Inner>,
}

impl UsageStore {
    /// Load the sidecar. Absent → empty (normal first run). Present-but-unparsable
    /// → empty too, but LOUD: silently resetting the file wiped every user's
    /// lifetime total (and quota) with no trace, and the next `flush` would then
    /// overwrite the corrupt file with the empty set — so warn before that happens.
    pub fn load(path: &str) -> Self {
        let usage = match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<HashMap<String, UserUsage>>(&s) {
                Ok(u) => u,
                Err(e) => {
                    log::warn!(
                        "usage: {path} exists but is unparsable ({e}) — starting from EMPTY \
                         totals; existing usage/quota accounting was NOT loaded and the next \
                         flush will overwrite the file. Restore from backup before that if the \
                         data matters."
                    );
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        UsageStore {
            path: path.to_string(),
            inner: Mutex::new(Inner {
                usage,
                committed: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Accrue a live session's running byte total. Idempotent per `session_id`:
    /// only the increase since the last fold is added, so calling it repeatedly
    /// (the sweep) never double-counts.
    pub fn fold(&self, session_id: u64, user: &str, cur_bytes: u64) {
        let mut g = self.lock();
        let prev = g.committed.get(&session_id).copied().unwrap_or(0);
        if cur_bytes > prev {
            let delta = cur_bytes - prev;
            // committed never stores 0 (we only insert when cur_bytes > prev, first
            // insert has prev=0 so the value is > 0), so prev==0 means this session_id
            // is new → count one connection for the user. Markers are pruned only for
            // dead sessions, so a live session is counted exactly once.
            let first = prev == 0;
            g.committed.insert(session_id, cur_bytes);
            let e = g.usage.entry(user.to_string()).or_default();
            e.used_bytes += delta;
            e.last_seen = now_unix();
            if first {
                e.sessions += 1;
            }
        }
    }

    pub fn used_bytes(&self, user: &str) -> u64 {
        self.lock()
            .usage
            .get(user)
            .map(|u| u.used_bytes)
            .unwrap_or(0)
    }

    /// Forget committed markers for sessions that are no longer live, so the map
    /// can't grow without bound.
    pub fn prune(&self, live: &HashSet<u64>) {
        self.lock().committed.retain(|id, _| live.contains(id));
    }

    /// Zero a user's counter (admin "reset usage").
    pub fn reset(&self, user: &str) {
        if let Some(u) = self.lock().usage.get_mut(user) {
            u.used_bytes = 0;
        }
    }

    pub fn snapshot(&self) -> HashMap<String, UserUsage> {
        self.lock().usage.clone()
    }

    /// Re-read the on-disk file — used by the supervisor/panel to observe the
    /// worker's flushes (the two run in separate processes).
    pub fn reload(&self) {
        if let Ok(s) = std::fs::read_to_string(&self.path) {
            if let Ok(u) = serde_json::from_str::<HashMap<String, UserUsage>>(&s) {
                self.lock().usage = u;
            }
        }
    }

    /// Persist atomically (temp + rename) so a crash can't truncate the file.
    pub fn flush(&self) {
        let snap = self.snapshot();
        if let Ok(json) = serde_json::to_vec_pretty(&snap) {
            if let Err(e) = crate::util::write_atomic(&self.path, &json) {
                // Non-fatal: also runs from Drop, so never panic. Surface the
                // error (disk full / permission / rename race) so a persistently
                // failing flush -- silently dropping folded deltas -- is visible.
                log::warn!("usage: failed to persist {}: {e}", self.path);
            }
        }
    }
}

impl Drop for UsageStore {
    /// Best-effort final flush on a graceful teardown, so the deltas folded since
    /// the last sweep aren't lost when the store is dropped between sweeps. A hard
    /// `SIGKILL` still skips this (Drop can't run) — the periodic sweep bounds that
    /// loss to one interval.
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // load() on a missing path = empty store; flush (via Drop) is best-effort and
    // no-ops on an unwritable path, so these need no real file.
    #[test]
    fn fold_counts_each_session_once() {
        let s = UsageStore::load("/nonexistent/qeli-usage-test-a4.json");
        s.fold(1, "alice", 100);
        s.fold(1, "alice", 250); // same session grows → still ONE connection
        s.fold(2, "alice", 50); // a second session for alice
        s.fold(3, "bob", 10);
        let snap = s.snapshot();
        assert_eq!(
            snap["alice"].sessions, 2,
            "two distinct session_ids = 2 connections"
        );
        assert_eq!(snap["alice"].used_bytes, 300, "250 + 50");
        assert_eq!(snap["bob"].sessions, 1);
    }

    #[test]
    fn fold_does_not_double_count_a_live_session() {
        let s = UsageStore::load("/nonexistent/qeli-usage-test-a4b.json");
        for b in [10u64, 20, 30, 40] {
            s.fold(7, "carol", b);
        }
        assert_eq!(
            s.snapshot()["carol"].sessions,
            1,
            "repeated folds of one session = 1"
        );
    }
}
