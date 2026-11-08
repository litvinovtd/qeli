use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

/// Typed handshake boundaries keep timeout/retry policy aligned with protocol side effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    CarrierConnect,
    KeyExchange,
    ClientHelloWrite,
    ServerHelloRead,
    ChangeCipherSpecRead,
    CertificateRead,
    FinishedRead,
    NewSessionTicketRead,
    AuthProofRead,
    IdentityVerification,
    ProofWrite,
    PreparedAckRead,
    CommitWrite,
    CommitAckRead,
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[tokio::test]
    async fn every_preauth_io_stage_retries_without_waiting_for_the_full_budget() {
        for stage in [
            Stage::CarrierConnect,
            Stage::KeyExchange,
            Stage::ClientHelloWrite,
            Stage::ServerHelloRead,
            Stage::ChangeCipherSpecRead,
            Stage::CertificateRead,
            Stage::FinishedRead,
            Stage::NewSessionTicketRead,
            Stage::AuthProofRead,
        ] {
            let progress = AttachProgress::default();
            let attempts = AtomicUsize::new(0);
            let started = std::time::Instant::now();
            let value = prepare_candidate_with_stall(
                Duration::from_secs(2),
                Duration::from_millis(10),
                &progress,
                RetryScope::Legacy,
                || {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    let progress = &progress;
                    async move {
                        progress.set(stage);
                        if attempt == 0 {
                            std::future::pending::<()>().await;
                        }
                        Ok(12)
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(value, 12);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
            assert!(started.elapsed() < Duration::from_secs(1), "{stage}");
        }
    }

    #[tokio::test]
    async fn legacy_submitted_join_and_any_commit_are_never_replayed() {
        for (scope, stage) in [
            (RetryScope::Legacy, Stage::ProofWrite),
            (RetryScope::Legacy, Stage::PreparedAckRead),
            (RetryScope::Resume, Stage::CommitWrite),
            (RetryScope::Resume, Stage::CommitAckRead),
        ] {
            let progress = AttachProgress::default();
            let attempts = AtomicUsize::new(0);
            let error = prepare_candidate_with_stall(
                Duration::from_millis(20),
                Duration::from_millis(1),
                &progress,
                scope,
                || {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    progress.set(stage);
                    std::future::pending::<anyhow::Result<()>>()
                },
            )
            .await
            .unwrap_err();
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
            assert!(error.to_string().contains("not safe to replay"));
        }
    }

    #[tokio::test]
    async fn cancelled_preparation_drops_its_socket_owner_before_the_next_attempt() {
        struct Owner(Arc<AtomicBool>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let attempts = AtomicUsize::new(0);
        let progress = AttachProgress::default();
        prepare_candidate_with_stall(
            Duration::from_secs(2),
            Duration::from_millis(10),
            &progress,
            RetryScope::Resume,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                let dropped = dropped.clone();
                async move {
                    if attempt == 0 {
                        let _owner = Owner(dropped);
                        std::future::pending::<()>().await;
                    } else {
                        assert!(dropped.load(Ordering::Acquire));
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn aborting_an_attach_task_releases_shared_join_admission() {
        let flag = Arc::new(AtomicBool::new(false));
        let active = flag.clone();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _permit = JoinPermit::acquire(active).unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        assert!(JoinPermit::acquire(flag.clone()).is_none());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let permit = JoinPermit::acquire(flag.clone()).unwrap();
        assert!(JoinPermit::acquire(flag.clone()).is_none());
        drop(permit);
        assert!(!flag.load(Ordering::Acquire));
    }
}

impl Stage {
    fn preauth(self) -> bool {
        matches!(
            self,
            Self::CarrierConnect
                | Self::KeyExchange
                | Self::ClientHelloWrite
                | Self::ServerHelloRead
                | Self::ChangeCipherSpecRead
                | Self::CertificateRead
                | Self::FinishedRead
                | Self::NewSessionTicketRead
                | Self::AuthProofRead
        )
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CarrierConnect => "carrier connect",
            Self::KeyExchange => "JOIN key exchange",
            Self::ClientHelloWrite => "JOIN ClientHello write",
            Self::ServerHelloRead => "JOIN ServerHello read",
            Self::ChangeCipherSpecRead => "JOIN ChangeCipherSpec read",
            Self::CertificateRead => "JOIN Certificate read",
            Self::FinishedRead => "JOIN Finished read",
            Self::NewSessionTicketRead => "JOIN NewSessionTicket read",
            Self::AuthProofRead => "JOIN auth proof read",
            Self::IdentityVerification => "JOIN identity verification",
            Self::ProofWrite => "JOIN proof write",
            Self::PreparedAckRead => "JOIN prepared ACK read",
            Self::CommitWrite => "JOIN COMMIT write",
            Self::CommitAckRead => "JOIN COMMIT_ACK read",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryScope {
    Resume,
    Legacy,
}

impl RetryScope {
    fn permits(self, stage: Stage) -> bool {
        stage.preauth()
            || (self == Self::Resume && matches!(stage, Stage::ProofWrite | Stage::PreparedAckRead))
    }
}

/// The last pending operation survives cancellation, including its last progress timestamp.
pub(super) struct AttachProgress(Mutex<(Stage, std::time::Instant)>);
impl Default for AttachProgress {
    fn default() -> Self {
        Self(Mutex::new((
            Stage::CarrierConnect,
            std::time::Instant::now(),
        )))
    }
}
impl AttachProgress {
    pub(super) fn set(&self, stage: Stage) {
        *crate::util::lock_or_recover(&self.0, "tcp_attach::progress") =
            (stage, std::time::Instant::now());
    }
    pub(super) fn stage(&self) -> Stage {
        crate::util::lock_or_recover(&self.0, "tcp_attach::progress").0
    }
}

/// All additional carriers share this admission guard. The server accepts one resume
/// reservation per session; cancellation must release admission without detaching work.
pub(super) struct JoinPermit(Arc<AtomicBool>);
impl JoinPermit {
    pub(super) fn acquire(flag: Arc<AtomicBool>) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Self(flag))
    }
}
impl Drop for JoinPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) const PREPARE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(feature = "experimental-roaming")]
pub(super) const PROBE_COMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const FIRST_PREAUTH_STALL: std::time::Duration = std::time::Duration::from_secs(1);
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const PREPARE_ATTEMPTS: usize = 2;

#[cfg(feature = "experimental-roaming")]
const _: () = assert!(
    PREPARE_TIMEOUT.as_millis() * PREPARE_ATTEMPTS as u128
        + RETRY_DELAY.as_millis()
        + crate::protocol::tcp_slot_probe::CLIENT_BUDGET.as_millis()
        + PROBE_COMMIT_TIMEOUT.as_millis()
        + super::TCP_RESUME_MAINTENANCE_TICK.as_millis()
        < crate::protocol::tcp_slot_probe::REQUEST_TTL.as_millis()
);

async fn wait_first_preauth_stall(progress: &AttachProgress, budget: std::time::Duration) {
    loop {
        let (stage, changed) = *crate::util::lock_or_recover(&progress.0, "tcp_attach::progress");
        if stage.preauth() && changed.elapsed() >= budget {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// The resume epoch is fresh on each attempt; the probe nonce and COMMIT are outside this
/// retry boundary. Authentication/protocol errors never trigger a fallback retry.
#[cfg(feature = "experimental-roaming")]
pub(super) async fn prepare_candidate<T, F, Fut>(
    configured_timeout: std::time::Duration,
    progress: &AttachProgress,
    prepare: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    prepare_candidate_with_stall(
        configured_timeout,
        FIRST_PREAUTH_STALL,
        progress,
        RetryScope::Resume,
        prepare,
    )
    .await
}

/// Fixed, adaptive and hard-resume carriers use the same bounded preparation as a quality
/// candidate. A legacy JOIN may already be active when its reply is lost: never retry its proof.
pub(super) async fn prepare_secondary<T, F, Fut>(
    configured_timeout: std::time::Duration,
    resumable: bool,
    progress: &AttachProgress,
    prepare: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let scope = if resumable {
        RetryScope::Resume
    } else {
        RetryScope::Legacy
    };
    prepare_candidate_with_stall(
        configured_timeout,
        FIRST_PREAUTH_STALL,
        progress,
        scope,
        prepare,
    )
    .await
}

async fn prepare_candidate_with_stall<T, F, Fut>(
    configured_timeout: std::time::Duration,
    first_stall_budget: std::time::Duration,
    progress: &AttachProgress,
    scope: RetryScope,
    mut prepare: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    use anyhow::Context;
    let timeout = configured_timeout.min(PREPARE_TIMEOUT);
    for attempt in 1..=PREPARE_ATTEMPTS {
        progress.set(Stage::CarrierConnect);
        let started = std::time::Instant::now();
        let preparation = async {
            tokio::select! {
                biased;
                result = prepare() => Some(result),
                _ = wait_first_preauth_stall(progress, first_stall_budget), if attempt == 1 => None,
            }
        };
        match tokio::time::timeout(timeout, preparation).await {
            Ok(Some(result)) => {
                return result.with_context(|| {
                    format!("TCP candidate preparation failed at {}", progress.stage())
                })
            }
            Ok(None) | Err(_) => {
                let stage = progress.stage();
                log::warn!(
                    "TCP candidate preparation timed out at {} after {}ms (attempt {}/{})",
                    stage,
                    started.elapsed().as_millis(),
                    attempt,
                    PREPARE_ATTEMPTS
                );
                if stage == Stage::IdentityVerification {
                    anyhow::bail!("TCP candidate identity verification timed out");
                }
                if !scope.permits(stage) {
                    anyhow::bail!("TCP candidate preparation timed out at {stage}; submitted JOIN/COMMIT is not safe to replay");
                }
                if attempt < PREPARE_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    anyhow::bail!(
        "TCP candidate preparation timed out at {} after {} fresh-socket attempts",
        progress.stage(),
        PREPARE_ATTEMPTS
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
                progress.set(Stage::ServerHelloRead);
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
            progress.set(Stage::IdentityVerification);
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
            progress.set(Stage::IdentityVerification);
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
            progress.set(Stage::ServerHelloRead);
            std::future::pending::<anyhow::Result<()>>()
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.load(Ordering::Relaxed), PREPARE_ATTEMPTS);
        assert!(error.to_string().contains("JOIN ServerHello"));
        // Include the probe and commit budgets, rather than only TCP connect.
        assert!(
            PREPARE_TIMEOUT * PREPARE_ATTEMPTS as u32
                + RETRY_DELAY
                + crate::protocol::tcp_slot_probe::CLIENT_BUDGET
                + PROBE_COMMIT_TIMEOUT
                < crate::protocol::tcp_slot_probe::REQUEST_TTL
        );
    }

    #[tokio::test]
    async fn stalled_first_preauth_retries_before_the_full_prepare_budget() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let started = std::time::Instant::now();
        let value = prepare_candidate_with_stall(
            Duration::from_secs(2),
            Duration::from_millis(20),
            &progress,
            RetryScope::Resume,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                let progress = &progress;
                async move {
                    progress.set(Stage::ServerHelloRead);
                    if attempt == 0 {
                        std::future::pending::<()>().await;
                    }
                    Ok(7)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn first_stall_budget_does_not_interrupt_identity_or_submitted_join() {
        for stage in [Stage::IdentityVerification, Stage::PreparedAckRead] {
            let progress = AttachProgress::default();
            let attempts = AtomicUsize::new(0);
            let value = prepare_candidate_with_stall(
                Duration::from_millis(150),
                Duration::from_millis(5),
                &progress,
                RetryScope::Resume,
                || {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    progress.set(stage);
                    async {
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Ok(9)
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(value, 9);
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn handshake_progress_refreshes_the_first_stall_clock() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let value = prepare_candidate_with_stall(
            Duration::from_secs(1),
            Duration::from_millis(50),
            &progress,
            RetryScope::Resume,
            || {
                attempts.fetch_add(1, Ordering::Relaxed);
                let progress = &progress;
                async move {
                    for stage in [
                        Stage::CarrierConnect,
                        Stage::ServerHelloRead,
                        Stage::AuthProofRead,
                    ] {
                        progress.set(stage);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Ok(11)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 11);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn second_candidate_keeps_the_full_budget_after_a_first_preauth_stall() {
        let progress = AttachProgress::default();
        let attempts = AtomicUsize::new(0);
        let value = prepare_candidate_with_stall(
            Duration::from_millis(150),
            Duration::from_millis(5),
            &progress,
            RetryScope::Resume,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                let progress = &progress;
                async move {
                    progress.set(Stage::ServerHelloRead);
                    if attempt == 0 {
                        std::future::pending::<()>().await;
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(13)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 13);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }
}
