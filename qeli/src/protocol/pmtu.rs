//! Bounded, directional PMTU confirmation shared by the UDP client and server.
//!
//! This is only challenge correlation and timing. The carrier owner must bind each
//! search to its path and budget revision, and must publish results atomically.
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

pub const CONFIRM_INTERVAL: Duration = Duration::from_secs(30);
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
    discovery: bool,
    lower: Option<usize>,
    upper: Option<usize>,
    previously_certified: Option<usize>,
}

impl Default for ProbeSearch {
    fn default() -> Self {
        Self {
            candidates: VecDeque::new(),
            challenge: None,
            confirmations: 0,
            timeout: INITIAL_TIMEOUT,
            discovery: false,
            lower: None,
            upper: None,
            previously_certified: None,
        }
    }
}

impl ProbeSearch {
    pub fn start(&mut self, candidates: impl IntoIterator<Item = usize>) {
        self.clear();
        // A caller cannot accidentally install an unbounded ladder.
        self.candidates = candidates.into_iter().take(32).collect();
    }

    /// Discovery narrows the successful/failed bracket to one byte. Hints only
    /// guide the search: publishing a new size still requires three exact echoes.
    pub fn start_discovery(&mut self, candidates: impl IntoIterator<Item = usize>) {
        self.start(candidates);
        self.discovery = true;
    }

    /// One fresh echo suffices to recheck an already certified size. Falling back
    /// after its failure still requires three independent base-size confirmations.
    pub fn start_confirmation(&mut self, current: usize, base: usize) {
        self.start(confirmation_budgets(current, base));
        self.previously_certified = Some(current);
    }

    pub fn clear(&mut self) {
        self.candidates.clear();
        self.challenge = None;
        self.confirmations = 0;
        self.discovery = false;
        self.lower = None;
        self.upper = None;
        self.previously_certified = None;
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
                if self.discovery {
                    let failed = challenge.budget;
                    self.upper = Some(self.upper.map_or(failed, |upper| upper.min(failed)));
                    if let Some(lower) = self.lower {
                        if lower >= failed {
                            // A candidate that answered during discovery no longer
                            // confirms: do not publish stale success after a path change.
                            self.lower = None;
                            self.candidates.clear();
                        } else {
                            self.candidates.clear();
                            self.candidates.push_back(lower + (failed - lower) / 2);
                        }
                    }
                }
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
        if self.discovery && self.confirmations == 1 {
            self.lower = Some(budget);
            if let Some(upper) = self.upper.filter(|upper| *upper > budget + 1) {
                self.candidates.clear();
                self.candidates.push_back(budget + (upper - budget) / 2);
                self.challenge = None;
                self.confirmations = 0;
                return None;
            }
        }
        let required = if self.previously_certified == Some(budget) {
            1
        } else {
            CONFIRMATIONS
        };
        if self.confirmations >= required {
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

/// Keep the outer path independent of an intentionally small inner TUN MTU.
/// A kernel route MTU is the best ceiling; platforms without it start at an
/// Ethernet-sized path (or the larger configured inner size), then prove it.
#[cfg(any(feature = "client", test))]
pub(crate) fn probe_ceiling(inner_mtu: i32, outer_overhead: usize, route_mtu: Option<u32>) -> i32 {
    let minimum = crate::config::server::MTU_MIN as i32;
    let maximum = crate::protocol::packet::MAX_TUNNEL_MTU as i32;
    let fallback = 1500usize.max(inner_mtu.max(0) as usize + outer_overhead);
    let path = route_mtu.map_or(fallback, |mtu| mtu as usize);
    i32::try_from(path.saturating_sub(outer_overhead))
        .unwrap_or(maximum)
        .clamp(minimum, maximum)
}

/// Read the connected carrier's kernel PMTU without changing the socket policy.
#[cfg(any(feature = "client", test))]
pub(crate) fn socket_path_mtu(socket: &tokio::net::UdpSocket, ipv6: bool) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let (level, option) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_MTU)
        } else {
            (libc::IPPROTO_IP, libc::IP_MTU)
        };
        let mut value = 0u32;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: both pointers reference live, correctly sized output storage.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&mut value as *mut u32).cast(),
                &mut length,
            )
        };
        (result == 0 && length as usize == std::mem::size_of_val(&value) && value > 0)
            .then_some(value)
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        extern "system" {
            fn getsockopt(
                socket: usize,
                level: i32,
                option: i32,
                value: *mut u8,
                length: *mut i32,
            ) -> i32;
        }
        // Winsock IP_MTU / IPV6_MTU (not Linux's option numbers).
        let (level, option) = if ipv6 { (41, 72) } else { (0, 73) };
        let mut value = 0u32;
        let mut length = std::mem::size_of_val(&value) as i32;
        // SAFETY: the connected socket is borrowed and the output buffers are live.
        let result = unsafe {
            getsockopt(
                socket.as_raw_socket() as usize,
                level,
                option,
                (&mut value as *mut u32).cast(),
                &mut length,
            )
        };
        (result == 0 && length as usize == std::mem::size_of_val(&value) && value > 0)
            .then_some(value)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
    {
        let _ = (socket, ipv6);
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
    fn outer_ceiling_does_not_inherit_small_inner_mtu() {
        let overhead = 48 + 13 + 8 + 20;
        assert_eq!(probe_ceiling(1365, overhead, Some(1492)), 1403);
        assert_eq!(probe_ceiling(1365, overhead, None), 1411);
        assert_eq!(probe_ceiling(9000, overhead, Some(1500)), 1411);
    }

    #[test]
    fn discovery_finds_exact_pppoe_and_asymmetric_path_budgets() {
        for limit in [1464, 1443, 1422, 1421, 1420, 548] {
            let mut search = ProbeSearch::default();
            search.start_discovery([1472, 1421, 1381, 1341, 548]);
            let mut now = Instant::now();
            let mut result = None;
            let mut echoes = Vec::new();
            for _ in 0..120 {
                let Some(probe) = search.next_send(now) else {
                    break;
                };
                if probe.budget <= limit {
                    now += Duration::from_millis(20);
                    echoes.push((probe.budget, probe.token));
                    result = search.acknowledge(probe.token, probe.budget, now);
                    if result.is_some() {
                        break;
                    }
                } else {
                    now += MAX_TIMEOUT;
                }
            }
            assert_eq!(result, Some(limit), "path budget {limit}");
            let final_echoes = &echoes[echoes.len() - 3..];
            assert!(final_echoes.iter().all(|(budget, _)| *budget == limit));
            assert_ne!(final_echoes[0].1, final_echoes[1].1);
            assert_ne!(final_echoes[1].1, final_echoes[2].1);
            assert_ne!(final_echoes[0].1, final_echoes[2].1);
            assert!(!search.is_active());
        }
    }

    #[test]
    fn discovery_does_not_publish_a_hint_that_stops_answering() {
        let mut search = ProbeSearch::default();
        search.start_discovery([1472, 1400]);
        let mut now = Instant::now();
        let mut replied_to_hint = false;
        for _ in 0..80 {
            let Some(probe) = search.next_send(now) else {
                break;
            };
            if probe.budget == 1400 && !replied_to_hint {
                replied_to_hint = true;
                assert_eq!(search.acknowledge(probe.token, probe.budget, now), None);
            }
            now += MAX_TIMEOUT;
        }
        assert!(replied_to_hint);
        assert!(
            !search.is_active(),
            "a stale successful hint is not a certified result"
        );
    }

    #[test]
    fn current_confirmation_is_one_echo_but_downgrade_is_three() {
        let now = Instant::now();
        let mut search = ProbeSearch::default();
        search.start_confirmation(1464, 548);
        let current = search.next_send(now).unwrap();
        assert_eq!(search.acknowledge(current.token, 1464, now), Some(1464));
        search.start_confirmation(1464, 548);
        search.next_send(now).unwrap();
        search.next_send(now + INITIAL_TIMEOUT).unwrap();
        let mut now = now + INITIAL_TIMEOUT * 2;
        for index in 0..3 {
            let base = search.next_send(now).unwrap();
            assert_eq!(base.budget, 548);
            assert_eq!(
                search.acknowledge(base.token, 548, now),
                (index == 2).then_some(548)
            );
            now += Duration::from_millis(20);
        }
    }

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
