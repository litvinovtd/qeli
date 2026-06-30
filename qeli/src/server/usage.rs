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
    /// Load the sidecar (empty if absent / unparsable).
    pub fn load(path: &str) -> Self {
        let usage = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<HashMap<String, UserUsage>>(&s).ok())
            .unwrap_or_default();
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
            g.committed.insert(session_id, cur_bytes);
            let e = g.usage.entry(user.to_string()).or_default();
            e.used_bytes += delta;
            e.last_seen = now_unix();
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
            let _ = crate::util::write_atomic(&self.path, &json);
        }
    }
}
