use std::sync::Mutex;

/// The last pending handshake operation, retained when its future is cancelled.
#[derive(Default)]
pub(super) struct AttachProgress(Mutex<&'static str>);

impl AttachProgress {
    pub(super) fn set(&self, stage: &'static str) {
        *crate::util::lock_or_recover(&self.0, "tcp_attach::progress") = stage;
    }

    #[cfg(feature = "experimental-roaming")]
    pub(super) fn stage(&self) -> &'static str {
        *crate::util::lock_or_recover(&self.0, "tcp_attach::progress")
    }
}

#[cfg(feature = "experimental-roaming")]
pub(super) const PREPARE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(feature = "experimental-roaming")]
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
#[cfg(feature = "experimental-roaming")]
const PREPARE_ATTEMPTS: usize = 2;

#[cfg(feature = "experimental-roaming")]
const _: () = assert!(
    PREPARE_TIMEOUT.as_secs() * (PREPARE_ATTEMPTS as u64 + 1)
        + 1 + crate::protocol::tcp_slot_probe::BUDGET.as_secs()
        < crate::protocol::tcp_slot_probe::REQUEST_TTL.as_secs()
);

/// Retry only a stalled, uncommitted candidate. No probe nonce or COMMIT has
/// been sent at this boundary, so the server's one-use probe remains available.
#[cfg(feature = "experimental-roaming")]
pub(super) async fn prepare_candidate<T, F, Fut>(
    configured_timeout: std::time::Duration,
    progress: &AttachProgress,
    mut prepare: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    use anyhow::Context;
    let timeout = configured_timeout.min(PREPARE_TIMEOUT);
    for attempt in 1..=PREPARE_ATTEMPTS {
        progress.set("carrier connect");
        match tokio::time::timeout(timeout, prepare()).await {
            Ok(result) => {
                // Authentication and protocol failures are terminal for this
                // request. Never turn a rejected identity into a fallback retry.
                return result.with_context(|| {
                    format!("TCP candidate preparation failed at {}", progress.stage())
                });
            }
            Err(_) => {
                log::warn!(
                    "TCP candidate preparation timed out at {} after {}ms (attempt {}/{})",
                    progress.stage(), timeout.as_millis(), attempt, PREPARE_ATTEMPTS
                );
                if progress.stage() == "JOIN identity verification" {
                    anyhow::bail!("TCP candidate identity verification timed out");
                }
                if attempt < PREPARE_ATTEMPTS {
                    // Dropping the preparation future closes this fresh socket.
                    // Let the server abort its reservation before a new epoch.
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    anyhow::bail!(
        "TCP candidate preparation timed out at {} after {} fresh-socket attempts",
        progress.stage(), PREPARE_ATTEMPTS
    )
}

#[cfg(all(test, feature = "experimental-roaming"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn stalled_hello_retries_preparation_on_a_fresh_attempt() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let value = prepare_candidate(Duration::from_millis(20), &progress, || {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed);
            let progress = &progress;
            async move {
                progress.set("JOIN ServerHello");
                if attempt == 0 {
                    std::future::pending::<()>().await;
                }
                Ok(7)
            }
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn authentication_rejection_does_not_retry() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let error = prepare_candidate(Duration::from_secs(1), &progress, || {
            attempts.fetch_add(1, Ordering::Relaxed);
            progress.set("JOIN identity verification");
            async { Err::<(), _>(anyhow::anyhow!("identity rejected")) }
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(error.to_string().contains("JOIN identity verification"));
        assert!(format!("{error:#}").contains("identity rejected"));
    }

    #[tokio::test]
    async fn a_pending_identity_decision_does_not_open_another_candidate() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let error = prepare_candidate(Duration::from_millis(20), &progress, || {
            attempts.fetch_add(1, Ordering::Relaxed);
            progress.set("JOIN identity verification");
            std::future::pending::<anyhow::Result<()>>()
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(error.to_string().contains("identity verification"));
    }

    #[tokio::test]
    async fn stalled_candidates_are_bounded_and_report_the_pending_stage() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let error = prepare_candidate(Duration::from_millis(20), &progress, || {
            attempts.fetch_add(1, Ordering::Relaxed);
            progress.set("JOIN ServerHello");
            std::future::pending::<anyhow::Result<()>>()
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::Relaxed), PREPARE_ATTEMPTS);
        assert!(error.to_string().contains("JOIN ServerHello"));
        // Include the probe and commit budgets, rather than only TCP connect.
        assert!(
            PREPARE_TIMEOUT * PREPARE_ATTEMPTS as u32 + RETRY_DELAY
                + crate::protocol::tcp_slot_probe::BUDGET + PREPARE_TIMEOUT
                < crate::protocol::tcp_slot_probe::REQUEST_TTL
        );
    }
}
