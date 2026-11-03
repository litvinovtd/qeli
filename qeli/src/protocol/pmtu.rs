//! Bounded, directional PMTU confirmation shared by the UDP client and server.
//!
//! This is only challenge correlation and timing. The carrier owner must bind each
//! search to its path and budget revision, and must publish results atomically.
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

pub const CONFIRM_INTERVAL: Duration = Duration::from_secs(10);
pub const GROW_INTERVAL: Duration = Duration::from_secs(10 * 60);
pub const TICK: Duration = Duration::from_millis(250);
pub const INITIAL_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_TIMEOUT: Duration = Duration::from_secs(5);
const SENDS: u8 = 2;
const CONFIRMATIONS: u8 = 3;

#[derive(Clone, Copy, Debug)]
pub struct Challenge {
    pub token: u128,
    pub budget: usize,
    sends: u8,
    sent_at: Instant,
    deadline: Instant,
}

#[derive(Debug)]
pub struct ProbeSearch {
    candidates: VecDeque<usize>,
    pub challenge: Option<Challenge>,
    confirmations: u8,
    timeout: Duration,
}

impl Default for ProbeSearch {
    fn default() -> Self {
        Self {
            candidates: VecDeque::new(),
            challenge: None,
            confirmations: 0,
            timeout: INITIAL_TIMEOUT,
        }
    }
}

impl ProbeSearch {
    pub fn start(&mut self, candidates: impl IntoIterator<Item = usize>) {
        self.clear();
        // A caller cannot accidentally install an unbounded ladder.
        self.candidates = candidates.into_iter().take(32).collect();
    }

    pub fn clear(&mut self) {
        self.candidates.clear();
        self.challenge = None;
        self.confirmations = 0;
    }

    pub fn is_active(&self) -> bool {
        self.challenge.is_some() || !self.candidates.is_empty()
    }

    pub fn next_send(&mut self, now: Instant) -> Option<Challenge> {
        loop {
            if self.challenge.is_none() {
                self.challenge = Some(Challenge {
                    token: rand::random(),
                    budget: self.candidates.pop_front()?,
                    sends: 0,
                    sent_at: now,
                    deadline: now,
                });
            }
            let challenge = self.challenge.as_mut()?;
            if challenge.sends != 0 && now < challenge.deadline {
                return None;
            }
            if challenge.sends >= SENDS {
                self.challenge = None;
                self.confirmations = 0;
                continue;
            }
            challenge.sends += 1;
            challenge.sent_at = now;
            challenge.deadline = now + self.timeout;
            return Some(*challenge);
        }
    }

    /// Three independent exact echoes certify a size. Retransmitted challenges do
    /// not contribute an RTT sample (the returning echo may belong to either send).
    pub fn acknowledge(&mut self, token: u128, budget: usize, now: Instant) -> Option<usize> {
        let challenge = self.challenge?;
        if challenge.token != token || challenge.budget != budget || challenge.sends == 0 {
            return None;
        }
        if challenge.sends == 1 {
            let measured = now.saturating_duration_since(challenge.sent_at);
            let target = measured.saturating_mul(4).clamp(MIN_TIMEOUT, MAX_TIMEOUT);
            // Raise quickly on a slow path; lower gradually after several samples.
            self.timeout = if target > self.timeout {
                target
            } else {
                (self.timeout * 3 + target) / 4
            };
        }
        self.confirmations += 1;
        if self.confirmations >= CONFIRMATIONS {
            self.clear();
            return Some(budget);
        }
        self.challenge = Some(Challenge {
            token: rand::random(),
            sends: 0,
            sent_at: now,
            deadline: now,
            ..challenge
        });
        None
    }
}

/// Confirm the current datagram first. Only after its bounded retries fail does
/// a separately confirmed base establish that a size-selective failure occurred.
pub fn confirmation_budgets(current: usize, base: usize) -> Vec<usize> {
    if current > base {
        vec![current, base]
    } else {
        vec![base]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_failure_requires_a_separately_confirmed_base() {
        let start = Instant::now();
        let mut search = ProbeSearch::default();
        search.start(confirmation_budgets(1460, 548));
        let first = search.next_send(start).unwrap();
        assert_eq!(first.budget, 1460);
        assert!(search.next_send(start + INITIAL_TIMEOUT / 2).is_none());
        let retry = search.next_send(start + INITIAL_TIMEOUT).unwrap();
        assert_eq!(first.token, retry.token);
        let mut now = start + INITIAL_TIMEOUT * 2;
        for index in 0..3 {
            let base = search.next_send(now).unwrap();
            assert_eq!(base.budget, 548);
            assert_ne!(base.token, first.token);
            assert_eq!(search.acknowledge(first.token, 548, now), None);
            now += Duration::from_millis(20);
            assert_eq!(
                search.acknowledge(base.token, 548, now),
                (index == 2).then_some(548)
            );
        }
        assert!(!search.is_active());
    }

    #[test]
    fn complete_outage_has_no_certified_downgrade() {
        let mut search = ProbeSearch::default();
        search.start(confirmation_budgets(1460, 548));
        let start = Instant::now();
        for index in 0..4 {
            assert!(search.next_send(start + INITIAL_TIMEOUT * index).is_some());
        }
        assert!(search.next_send(start + INITIAL_TIMEOUT * 4).is_none());
        assert!(!search.is_active());
    }

    #[test]
    fn clear_invalidates_old_echo_and_rtt_timeout_adapts() {
        let mut search = ProbeSearch::default();
        let start = Instant::now();
        search.start([1460]);
        let old = search.next_send(start).unwrap();
        search.clear();
        search.start([548]);
        let fresh = search.next_send(start).unwrap();
        assert_eq!(search.acknowledge(old.token, old.budget, start), None);
        assert_eq!(
            search.acknowledge(
                fresh.token,
                fresh.budget,
                start + Duration::from_millis(900)
            ),
            None
        );
        assert_eq!(search.timeout, Duration::from_millis(3600));
    }
}
