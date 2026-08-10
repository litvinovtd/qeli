//! Observable, bounded UDP socket-buffer policy shared by every client and the server.
//!
//! UDP has no receive-window autotuner.  A small kernel queue therefore drops datagrams
//! whenever the userspace receive task is descheduled briefly.  This controller keeps the
//! proven 4 MiB value as the initial floor, measures the actual value granted by the OS and,
//! only for an implicit/default setting, grows in two bounded rungs (8/16 MiB).  It never
//! shrinks a live socket and never reacts to wire sequence gaps: those may be real network
//! loss, which allocating local memory cannot repair.

use std::sync::Arc;
use std::time::{Duration, Instant};

use portable_atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;

pub(crate) const AUTO_INITIAL_RECV_BYTES: u32 = 4 * 1024 * 1024;
pub(crate) const AUTO_MAX_RECV_BYTES: u32 = 16 * 1024 * 1024;
/// Upper bound for an explicit per-socket override. Automatic mode deliberately has the
/// lower cap above; this larger limit only preserves an operator's ability to tune a known
/// high-bandwidth host without allowing a typo to request gigabytes from every worker.
pub(crate) const MAX_CONFIGURED_SOCKET_BUFFER_BYTES: u32 = 64 * 1024 * 1024;
pub(crate) const MIN_AUTO_RECV_BYTES: u32 = 256 * 1024;
const AUTO_MIDDLE_RECV_BYTES: u32 = 8 * 1024 * 1024;
const TUNE_INTERVAL: Duration = Duration::from_secs(1);
// A receive queue should absorb at least this much of the measured wire rate.  This is a
// latency budget, not a fixed byte size: at 100 Mbit/s it is ~625 KiB, at 700 Mbit/s ~4.4 MiB.
const MIN_STALL_BUDGET: Duration = Duration::from_millis(50);

#[derive(Debug, Default)]
pub(crate) struct UdpBufferCounters {
    pub kernel_drops: AtomicU64,
    pub internal_drops: AtomicU64,
    pub grow_events: AtomicU64,
    pub granted_recv_bytes: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UdpBufferSnapshot {
    pub kernel_drops: u64,
    pub internal_drops: u64,
    pub grow_events: u64,
    pub granted_recv_bytes: u64,
}

impl UdpBufferCounters {
    pub(crate) fn snapshot(&self) -> UdpBufferSnapshot {
        UdpBufferSnapshot {
            kernel_drops: self.kernel_drops.load(Ordering::Relaxed),
            internal_drops: self.internal_drops.load(Ordering::Relaxed),
            grow_events: self.grow_events.load(Ordering::Relaxed),
            granted_recv_bytes: self.granted_recv_bytes.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn note_internal_drop(&self) {
        self.internal_drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UdpBufferPolicy {
    pub send_bytes: u32,
    pub receive_bytes: u32,
    /// True only when `recv_buffer_size` was absent.  An explicit number is a fixed manual
    /// override and `0` keeps the OS default exactly as before.
    pub automatic_receive: bool,
    pub max_receive_bytes: u32,
}

/// Process-wide server allocation derived from currently available RAM and the exact number
/// of SO_REUSEPORT sockets. Linux accounts both SO_RCVBUF and SO_SNDBUF at roughly twice the
/// user request, so the planner works in kernel-accounted bytes and leaves 7/8 of available
/// memory to the TUN queues, sessions, crypto and the OS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AggregateUdpBudgetPlan {
    pub auto_initial_recv_bytes: u32,
    pub auto_max_recv_bytes: u32,
    pub budget_bytes: u64,
    pub socket_count: usize,
    pub auto_socket_count: usize,
}

pub(crate) fn plan_aggregate_udp_budget(
    available_memory_bytes: u64,
    socket_count: usize,
    auto_socket_count: usize,
    reserved_kernel_bytes: u64,
) -> Result<AggregateUdpBudgetPlan, String> {
    let budget = available_memory_bytes / 8;
    if socket_count == 0 {
        return Ok(AggregateUdpBudgetPlan {
            budget_bytes: budget,
            ..Default::default()
        });
    }
    if reserved_kernel_bytes > budget {
        return Err(format!(
            "configured UDP socket buffers reserve {} MiB, above the safe aggregate budget {} MiB (12.5% of currently available RAM); lower perf.udp buffers or tun.queues",
            reserved_kernel_bytes / 1024 / 1024,
            budget / 1024 / 1024
        ));
    }
    let per_auto_user_bytes = if auto_socket_count == 0 {
        0
    } else {
        // Linux doubles the value for bookkeeping. Budget the maximum every automatic
        // controller may reach simultaneously, not merely its initial request.
        (budget - reserved_kernel_bytes) / auto_socket_count as u64 / 2
    };
    if auto_socket_count > 0 && per_auto_user_bytes < u64::from(MIN_AUTO_RECV_BYTES) {
        return Err(format!(
            "{} automatic UDP sockets would receive only {} KiB each under the safe aggregate memory budget; lower tun.queues/listener count or set an explicit reviewed buffer size",
            auto_socket_count,
            per_auto_user_bytes / 1024
        ));
    }
    let maximum = per_auto_user_bytes
        .min(u64::from(AUTO_MAX_RECV_BYTES))
        .min(u64::from(u32::MAX)) as u32;
    Ok(AggregateUdpBudgetPlan {
        auto_initial_recv_bytes: AUTO_INITIAL_RECV_BYTES.min(maximum),
        auto_max_recv_bytes: maximum,
        budget_bytes: budget,
        socket_count,
        auto_socket_count,
    })
}

pub(crate) struct UdpBufferController {
    label: String,
    policy: UdpBufferPolicy,
    counters: Arc<UdpBufferCounters>,
    requested_recv_bytes: u32,
    granted_recv_bytes: u32,
    bytes_in_window: u64,
    smoothed_bytes_per_second: u64,
    last_tick: Instant,
    socket_inode: Option<u64>,
    last_kernel_drops: Option<u64>,
}

impl UdpBufferController {
    pub(crate) fn configure(
        socket: &UdpSocket,
        mut policy: UdpBufferPolicy,
        counters: Arc<UdpBufferCounters>,
        label: impl Into<String>,
    ) -> Self {
        let label = label.into();
        policy.max_receive_bytes = policy
            .max_receive_bytes
            .max(policy.receive_bytes)
            .min(AUTO_MAX_RECV_BYTES);
        policy.automatic_receive &= policy.receive_bytes > 0;

        let socket_ref = socket2::SockRef::from(socket);
        if policy.send_bytes > 0 {
            if let Err(error) = socket_ref.set_send_buffer_size(policy.send_bytes as usize) {
                log::warn!(
                    "{label}: could not request UDP SO_SNDBUF={}: {error}; using kernel value",
                    policy.send_bytes
                );
            }
        }
        if policy.receive_bytes > 0 {
            if let Err(error) = socket_ref.set_recv_buffer_size(policy.receive_bytes as usize) {
                log::warn!(
                    "{label}: could not request UDP SO_RCVBUF={}: {error}; using kernel value",
                    policy.receive_bytes
                );
            }
        }

        let granted = effective_receive_bytes(&socket_ref).unwrap_or(0);
        counters
            .granted_recv_bytes
            .fetch_add(granted as u64, Ordering::Relaxed);
        let mode = if policy.automatic_receive {
            "auto"
        } else if policy.receive_bytes == 0 {
            "os-default"
        } else {
            "fixed"
        };
        if granted > 0 {
            log::info!(
                "{label}: UDP receive buffer mode={mode}, requested={} KiB, granted={} KiB{}",
                policy.receive_bytes / 1024,
                granted / 1024,
                if policy.automatic_receive {
                    format!(", auto cap={} KiB", policy.max_receive_bytes / 1024)
                } else {
                    String::new()
                }
            );
            if policy.receive_bytes > 0 && granted < policy.receive_bytes as usize {
                log::warn!(
                    "{label}: UDP receive buffer was capped by the OS (requested {} KiB, granted {} KiB)",
                    policy.receive_bytes / 1024,
                    granted / 1024
                );
            }
        }

        let socket_inode = socket_inode(socket);
        // Establish the baseline before the first one-second sample. Otherwise drops that
        // happen during that first (and often busiest) second become the baseline and vanish
        // from both the counter and the grow decision.
        let last_kernel_drops = socket_inode.and_then(read_udp_socket_drops);

        Self {
            label,
            policy,
            counters,
            requested_recv_bytes: policy.receive_bytes,
            granted_recv_bytes: granted.min(u32::MAX as usize) as u32,
            bytes_in_window: 0,
            smoothed_bytes_per_second: 0,
            last_tick: Instant::now(),
            socket_inode,
            last_kernel_drops,
        }
    }

    pub(crate) fn note_receive(&mut self, bytes: usize) {
        self.bytes_in_window = self.bytes_in_window.saturating_add(bytes as u64);
    }

    pub(crate) fn note_internal_drop(&self) {
        self.counters.note_internal_drop();
    }

    /// Poll local evidence and, if the implicit policy needs it, grow one rung.  This method
    /// is intentionally synchronous and cheap: one getsockopt plus two small `/proc` reads
    /// per second on Linux/Android, and no filesystem work on other platforms.
    pub(crate) fn tick(&mut self, socket: &UdpSocket) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_tick);
        if elapsed < TUNE_INTERVAL {
            return;
        }
        self.last_tick = now;

        let elapsed_ms = elapsed.as_millis().max(1);
        let sample_rate = ((u128::from(self.bytes_in_window) * 1000) / elapsed_ms)
            .min(u128::from(u64::MAX)) as u64;
        self.bytes_in_window = 0;
        self.smoothed_bytes_per_second = if self.smoothed_bytes_per_second == 0 {
            sample_rate
        } else {
            // Fast enough to follow a new speed tier, slow enough not to react to one burst.
            self.smoothed_bytes_per_second
                .saturating_mul(3)
                .saturating_add(sample_rate)
                / 4
        };

        let kernel_drop_delta = self.poll_kernel_drops();
        let scheduler_delay = elapsed.saturating_sub(TUNE_INTERVAL);
        let stall_budget = MIN_STALL_BUDGET.max(scheduler_delay.saturating_mul(2));
        let required =
            (u128::from(self.smoothed_bytes_per_second) * stall_budget.as_millis()) / 1000;
        let required = required.min(u128::from(u32::MAX)) as u32;

        let granted = self.granted_recv_bytes;
        if !growth_needed(
            self.policy.automatic_receive,
            self.requested_recv_bytes,
            self.policy.max_receive_bytes,
            kernel_drop_delta,
            required,
            granted,
        ) {
            return;
        }

        let next = next_rung(self.requested_recv_bytes, self.policy.max_receive_bytes);
        if next <= self.requested_recv_bytes {
            return;
        }
        let socket_ref = socket2::SockRef::from(socket);
        if let Err(error) = socket_ref.set_recv_buffer_size(next as usize) {
            log::warn!(
                "{}: UDP receive-buffer auto-grow {} -> {} KiB failed: {error}",
                self.label,
                self.requested_recv_bytes / 1024,
                next / 1024
            );
            // Do not retry the same forbidden request every second.
            self.requested_recv_bytes = next;
            return;
        }
        self.requested_recv_bytes = next;
        let effective = effective_receive_bytes(&socket_ref).unwrap_or(next as usize);
        self.granted_recv_bytes = effective.min(u32::MAX as usize) as u32;
        if effective >= granted as usize {
            self.counters
                .granted_recv_bytes
                .fetch_add((effective - granted as usize) as u64, Ordering::Relaxed);
        } else {
            self.counters
                .granted_recv_bytes
                .fetch_sub((granted as usize - effective) as u64, Ordering::Relaxed);
        }
        if effective > granted as usize {
            self.counters.grow_events.fetch_add(1, Ordering::Relaxed);
        }
        log::info!(
            "{}: UDP receive-buffer auto-grow requested {} KiB, granted {} KiB (reason: {}, rate={} Mbit/s, local kernel drops +{})",
            self.label,
            next / 1024,
            effective / 1024,
            if kernel_drop_delta > 0 { "kernel overflow" } else { "measured rate/stall budget" },
            self.smoothed_bytes_per_second.saturating_mul(8) / 1_000_000,
            kernel_drop_delta
        );
    }

    fn poll_kernel_drops(&mut self) -> u64 {
        let Some(inode) = self.socket_inode else {
            return 0;
        };
        let Some(total) = read_udp_socket_drops(inode) else {
            return 0;
        };
        let delta = self
            .last_kernel_drops
            .map_or(0, |previous| total.saturating_sub(previous));
        self.last_kernel_drops = Some(total);
        if delta > 0 {
            self.counters
                .kernel_drops
                .fetch_add(delta, Ordering::Relaxed);
            log::warn!(
                "{}: UDP kernel receive queue dropped {} datagram(s) (socket total {})",
                self.label,
                delta,
                total
            );
        }
        delta
    }
}

impl Drop for UdpBufferController {
    fn drop(&mut self) {
        self.counters
            .granted_recv_bytes
            .fetch_sub(self.granted_recv_bytes as u64, Ordering::Relaxed);
    }
}

fn next_rung(current: u32, maximum: u32) -> u32 {
    let candidate = if current < AUTO_MIDDLE_RECV_BYTES {
        AUTO_MIDDLE_RECV_BYTES
    } else {
        AUTO_MAX_RECV_BYTES
    };
    candidate.min(maximum)
}

fn growth_needed(
    automatic: bool,
    requested: u32,
    maximum: u32,
    kernel_drop_delta: u64,
    required: u32,
    granted: u32,
) -> bool {
    automatic
        && requested < maximum
        && (kernel_drop_delta > 0 || required > granted.saturating_mul(3) / 4)
}

fn effective_receive_bytes(socket: &socket2::SockRef<'_>) -> std::io::Result<usize> {
    let raw = socket.recv_buffer_size()?;
    // Linux accounts bookkeeping by reporting twice the user-visible SO_RCVBUF request.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    return Ok(raw / 2);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    return Ok(raw);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_inode(socket: &UdpSocket) -> Option<u64> {
    use std::os::fd::AsRawFd;
    let link = std::fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd())).ok()?;
    let text = link.to_string_lossy();
    text.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn socket_inode(_socket: &UdpSocket) -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_udp_socket_drops(inode: u64) -> Option<u64> {
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(table) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(drops) = parse_proc_udp_drops(&table, inode) {
            return Some(drops);
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_udp_socket_drops(_inode: u64) -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_proc_udp_drops(table: &str, wanted_inode: u64) -> Option<u64> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let inode = fields.get(9)?.parse::<u64>().ok()?;
        if inode != wanted_inode {
            return None;
        }
        fields.last()?.parse::<u64>().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_udp_parser_selects_the_socket_inode_and_drop_column() {
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
  46: 0100007F:20FB 00000000:0000 07 00000000:00000000 00:00000000 00000000  100        0 11111 2 0000000000000000 3\n\
  47: 0100007F:20FC 00000000:0000 07 00000000:00000000 00:00000000 00000000  100        0 22222 2 0000000000000000 17\n";
        assert_eq!(parse_proc_udp_drops(fixture, 22_222), Some(17));
        assert_eq!(parse_proc_udp_drops(fixture, 33_333), None);
    }

    #[test]
    fn auto_growth_is_bounded_to_two_rungs() {
        assert_eq!(
            next_rung(AUTO_INITIAL_RECV_BYTES, AUTO_MAX_RECV_BYTES),
            8 * 1024 * 1024
        );
        assert_eq!(
            next_rung(8 * 1024 * 1024, AUTO_MAX_RECV_BYTES),
            16 * 1024 * 1024
        );
        assert_eq!(
            next_rung(16 * 1024 * 1024, AUTO_MAX_RECV_BYTES),
            16 * 1024 * 1024
        );
        assert_eq!(
            next_rung(AUTO_INITIAL_RECV_BYTES, 6 * 1024 * 1024),
            6 * 1024 * 1024
        );
    }

    #[test]
    fn only_auto_mode_uses_local_overflow_or_rate_pressure() {
        assert!(growth_needed(true, 4, 16, 1, 0, 4));
        assert!(growth_needed(true, 4, 16, 0, 4, 4));
        assert!(!growth_needed(true, 4, 16, 0, 3, 4));
        assert!(!growth_needed(false, 4, 16, 99, 99, 4));
        assert!(!growth_needed(true, 16, 16, 99, 99, 16));
    }

    #[test]
    fn aggregate_budget_scales_with_socket_count_and_counts_linux_doubling() {
        let gib = 1024_u64 * 1024 * 1024;
        let plan = plan_aggregate_udp_budget(8 * gib, 128, 128, 0).unwrap();
        assert_eq!(plan.budget_bytes, gib);
        assert_eq!(plan.auto_max_recv_bytes, 4 * 1024 * 1024);
        assert_eq!(plan.auto_initial_recv_bytes, 4 * 1024 * 1024);

        let plan = plan_aggregate_udp_budget(8 * gib, 32, 32, 0).unwrap();
        assert_eq!(plan.auto_max_recv_bytes, AUTO_MAX_RECV_BYTES);
    }

    #[test]
    fn aggregate_budget_refuses_manual_overcommit_and_unusable_auto_shares() {
        assert!(plan_aggregate_udp_budget(512 * 1024 * 1024, 4, 0, 80 * 1024 * 1024).is_err());
        assert!(plan_aggregate_udp_budget(128 * 1024 * 1024, 128, 128, 0).is_err());
    }
}
