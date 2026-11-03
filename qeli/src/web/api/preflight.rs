//! Observe networking before serializing a config edit; re-read config/users under the lock.
use crate::server::{preflight, ServerState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedMutexGuard;
use tokio::time::Instant;

// A queued writer must not use a snapshot collected an unbounded time ago.
const FRESHNESS: Duration = Duration::from_secs(5);
// Removing the config mutex from probes must not create an unbounded child-process fanout.
static OBSERVATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub(super) struct Snapshot {
    pub host: Option<preflight::HostNet>,
    pub ipv6_firewall_available: bool,
    valid_until: Instant,
}

impl Snapshot {
    pub fn check(&self, config: &crate::config::server::ServerConfig) -> anyhow::Result<()> {
        if Instant::now() >= self.valid_until {
            anyhow::bail!(
                "network preflight expired while preparing the config; retry the operation"
            );
        }
        preflight::check_observed(config, self.host.as_ref())
    }
}

pub(super) async fn observe(quickstart: bool) -> Result<Snapshot, String> {
    let until = Instant::now() + preflight::PROBE_BUDGET;
    let _permit = tokio::time::timeout_at(until, OBSERVATIONS.acquire())
        .await
        .map_err(|_| "network preflight is busy; retry the operation".to_string())?
        .map_err(|_| "network preflight is unavailable".to_string())?;
    if Instant::now() >= until {
        return Err("network preflight expired in the probe queue; retry the operation".into());
    }
    let host = preflight::gather_host_net_async(until).await;
    let ipv6_firewall_available = quickstart
        && crate::server::nat::ip6tables_path_async(until)
            .await
            .is_some();
    Ok(Snapshot {
        host,
        ipv6_firewall_available,
        valid_until: Instant::now() + FRESHNESS,
    })
}

pub(super) async fn lock(
    state: &Arc<ServerState>,
    quickstart: bool,
) -> Result<(OwnedMutexGuard<()>, Snapshot), String> {
    lock_after_observation(state.config_write_lock.clone(), observe(quickstart)).await
}

async fn lock_after_observation(
    lock: Arc<tokio::sync::Mutex<()>>,
    observe: impl std::future::Future<Output = Result<Snapshot, String>>,
) -> Result<(OwnedMutexGuard<()>, Snapshot), String> {
    let snapshot = observe.await?;
    lock_observed(lock, snapshot).await
}

async fn lock_observed(
    lock: Arc<tokio::sync::Mutex<()>>,
    snapshot: Snapshot,
) -> Result<(OwnedMutexGuard<()>, Snapshot), String> {
    let guard = tokio::time::timeout_at(snapshot.valid_until, lock.lock_owned())
        .await
        .map_err(|_| {
            "config is busy; network preflight expired, retry the operation".to_string()
        })?;
    // timeout_at may poll an immediately ready lock at an already expired deadline.
    if Instant::now() >= snapshot.valid_until {
        return Err(
            "network preflight expired while waiting for the config lock; retry the operation"
                .into(),
        );
    }
    Ok((guard, snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(valid_until: Instant) -> Snapshot {
        Snapshot {
            host: None,
            ipv6_firewall_available: false,
            valid_until,
        }
    }

    #[tokio::test]
    async fn expired_or_busy_snapshot_cannot_admit_a_config_write() {
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        assert!(lock_observed(lock.clone(), snapshot(Instant::now()))
            .await
            .is_err());
        let guard = lock.lock().await;
        assert!(lock_observed(
            lock.clone(),
            snapshot(Instant::now() + Duration::from_millis(20))
        )
        .await
        .is_err());
        drop(guard);
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn timeout_does_not_release_the_running_writer() {
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let guard = lock.lock().await;
        assert!(lock_observed(
            lock.clone(),
            snapshot(Instant::now() + Duration::from_millis(20))
        )
        .await
        .is_err());
        assert!(lock.try_lock().is_err());
        drop(guard);
        let (guard, observed) = lock_observed(lock.clone(), snapshot(Instant::now() + FRESHNESS))
            .await
            .unwrap();
        assert!(observed.check(&Default::default()).is_ok());
        drop(guard);
    }

    #[tokio::test]
    async fn pending_preflight_does_not_block_an_unrelated_config_writer() {
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let transaction = tokio::spawn(lock_after_observation(lock.clone(), async move {
            started_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            Ok(snapshot(Instant::now() + FRESHNESS))
        }));
        started_rx.await.unwrap();
        let unrelated_writer = lock
            .try_lock()
            .expect("preflight must not hold the config lease");
        drop(unrelated_writer);
        finish_tx.send(()).unwrap();
        let (guard, _) = transaction.await.unwrap().unwrap();
        assert!(lock.try_lock().is_err());
        drop(guard);
    }

    #[tokio::test]
    async fn expired_snapshot_is_not_the_fail_open_missing_ip_case() {
        assert!(snapshot(Instant::now()).check(&Default::default()).is_err());
        assert!(snapshot(Instant::now() + FRESHNESS)
            .check(&Default::default())
            .is_ok());
    }
}
