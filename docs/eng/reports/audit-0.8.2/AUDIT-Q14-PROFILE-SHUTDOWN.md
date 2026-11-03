# Q14: profile task and TUN teardown errors during shutdown

Date: 23 September 2026. Baseline commit: `e3fd3c6e`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**. Q14-F027 is **partially** addressed.

## Confirmed problem

The worker outcome already covered DNS/IPv6 sysctl cleanup and usage flush, and the outer
supervisor propagated nonzero exit. However, profile supervisors returned `()` and their
JoinSet results were discarded. Listener/service failures and child-task panics could also
be lost after reaping or cancellation of a shutdown waiter. Profile Drop logged TUN deletion
failure, ignored queue panics and still reported successful teardown.

## Change

`ProfileTasks`, `ProfileServices` and `WorkerServices` return a shutdown result.
Observed failures remain in a bounded accumulator: the first eight causes, up to 256
characters per label and 2048 per detail; additional failures are counted separately.
Cancelling a waiter does not erase consumed errors. Repeated and concurrent callers of
`ProfileTasks::shutdown` receive the retained outcome. Deliberate cancellation of children,
listeners and services during abort is expected; panics and completed errors are retained.
Worker services stop cooperatively, so their unexpected cancellation is an error.

A profile supervisor returns its last generation outcome after a stop request, including
one arriving during post_down. The worker drains every profile supervisor despite an
error, panic or unexpected cancellation. Control-task and worker-service errors join
the same category of the final outcome.

The portable `profile_teardown` module retains Drop failures in a shared report read by
the wrapper after dropping its guard exactly once. Resource cleanup order is preserved.
TUN threads still receive repeated wake-ups and up to three seconds to finish; only
finished threads are joined. Unfinished threads are detached, but timeout, a finished
thread's panic and TUN deletion failure now affect the outcome. No device-deletion retry
is added by this change.

The worker outcome includes `profile/worker task cleanup`. Final known-network lease
verification and usage flush still run after this category fails. Signal-driven shutdown
exits 1; the outer supervisor propagates the failure to its calling CLI.
There are no new INI keys, ABI changes or wire-format changes.

## Validation

13 host regressions were added: four for failure evidence/worker outcome/JoinSet drain,
four for task failures and cancelled waiters, and five for Drop evidence and TUN threads.
They cover concurrent causes, repeated/cancelled waiters, draining remaining tasks after
failure, bounded diagnostics, poisoned mutexes, thread resource release, panic and grace
expiry without blocking join. HTTP/2 and DNS tests now explicitly assert successful
shutdown while retaining their previous ownership and release assertions.

**989 host unit + 52 editor/policy + 7 examples + 12 server INI = 1060 Rust tests PASS.**
Linux all-targets Clippy, client-only, server-only, client without roaming, minimal FFI,
compatibility without features and rustfmt PASS. Clippy retains the existing
`chunks_exact_to_as_chunks` exception; existing feature-specific warnings were not changed.
Portable HTTP/2 and DNS tests ran on the host, including a rerun after stronger shutdown
assertions; Linux worker integration was compiler-checked.

Before application, 53 portable-module tests passed in a separate review copy. They overlap
with the main matrix and are not added to 1060.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/profile-stop-audit-20260923.

## Open boundaries and next pass

Q14-F027 remains open for generic NAT cleanup and complete resource ownership accounting.
A previous generation's failure does not become globally sticky after replacement;
stopping during retry backoff can still return Ok. These cases require tracking unfinished
generation cleanup separately, without turning a recovered transient startup failure into
a permanent error. The outer supervisor respawn policy is unchanged.

The subsequent [sysctl recovery pass](AUDIT-Q14-SYSCTL-RECOVERY.md) fixes false Ok for
unresolved stale entries and ownership loss on failed reacquisition. Partial IPv6 sysctl
acquisition tracking is subsequently fixed by [Q14-F031](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md).
DNS ownership is worker-local memory without persistent journaling. The subsequent
[Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) bounds each server NAT command; an overall
operation-sequence deadline remains open. A successful outcome does not prove that all resources
from earlier generations or processes are absent.

No actual Linux worker, signal delivery, firewall/TUN/DNS, systemd, devices, native release,
SSH/Actions or benchmarks were run.

Previous pass: [final leases and outer supervisor](AUDIT-Q14-OWNED-SHUTDOWN.md).

Follow-up: [Q25-F059–F060](AUDIT-Q25-TUN-LIFETIME.md) removes name-based TUN deletion and retains original descriptors through cleanup. DNS/route identity during external replacement and worker timeout remain open.
