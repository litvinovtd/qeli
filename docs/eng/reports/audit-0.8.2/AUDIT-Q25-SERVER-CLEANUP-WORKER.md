# Q25-F115: server cleanup without blocking the async executor

Date: 25 September 2026. Baseline commit: `db4e8969`. D05/D09: partial closure.

## Confirmed problem

`run_worker` called `nat::cleanup_all` on its async path before starting services.
After joining child tasks, ordinary `run_profile` synchronously dropped
`ProfileTeardown` on that path: it removed DNS INPUT leases and NAT, stopped TUN
threads and released queues. Final NAT sweeps, `finish_owned_cleanup`, and
`usage.flush` also blocked the executor. A component deadline did not keep a
single-thread runtime responsive during the operation.

## Change and limits

`profile_teardown::blocking` runs a synchronous operation on a dedicated thread
and waits without blocking the executor. Its guard joins the worker even if the
waiter is cancelled, before the outer scope can release the network namespace
lease or profile ownership. Ordinary profile shutdown still joins
listeners/services/children, unregisters the generation, and only then moves the
guard to the worker. Spawn/panic failures enter the cleanup result; existing
NAT/TUN failures remain in the shared `Report`. Startup recovery and final
sweeps/flush use the same mechanism. INI, wire/API and routing behavior are unchanged.

This does not move `run_profile_generation`: TUN creation, NAT setup, NDP startup
and some emergency Drops remain synchronous. Cancellation during a forced Drop
can still block its caller; non-preemptible kernel/filesystem syscalls have no
hard deadline. The composed deadline for the entire server setup/cleanup remains
open under D05.

## Validation

Two new regressions: a 120 ms blocking operation leaves a current-thread runtime
heartbeat responsive; cancelling a waiter cannot release a resource before join.
Full host lib: 1602 PASS, 1 previously ignored. Linux cross-check and all-targets
Clippy PASS; 10 targeted Linux tests PASS. Isolated lab `.11`: 8/8 actual
TCP/UDP × IPv6 `off`/`manual`/`route`/`nat66` start/stop cases PASS, including
absence of residual TUN, IPv4/IPv6 NAT and sysctl leases. Tests used private
NET/mount/PID namespaces; installed services were untouched.
Source and logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-cleanup-phase/`.
An additional fault run occupied the TCP/UDP bind port after `post_up`:
**2/2 PASS**. The failed generation removed TUN and NAT while retaining the
worker-lifetime IPv4 forwarding lease and its journal. Releasing the port let
the profile restart; final worker stop restored forwarding and removed the
journal. The first test expectation incorrectly required forwarding to turn off
after a profile failure, contrary to worker-level ownership; the fixture, not
the product, was corrected. Logs and results: `server-bind-failure-v4/`.

No old-code runtime binary was run for this item: the previous synchronous call
was established by direct source comparison. D05 remains IN_PROGRESS.
