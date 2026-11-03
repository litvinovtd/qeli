# Q05 — asynchronous panel firewall-tool discovery

<!-- normative-sync: audit-q05-health-probes-v1 -->

Date: 24 September 2026. Base: `1bfb9920dd812f29484c0d977b8b7660012f5bfe`.
Partial closure of D05/D09 in the [debt register](../../plans/AUDIT-DEBT.md).

## Q05-F008, P2 — diagnostics blocked the async executor

`/api/status` and `/api/transport/health` called synchronous `nat::available()` inside
async handlers. When iptables was absent from standard directories, the fallback ran
`iptables --version` through the synchronous runner. A stalled process/pipe occupied
the Tokio thread for up to 15 seconds plus process termination; a single-thread executor
also delayed neighboring requests. Transport health probed even without NAT profiles.

This was a remaining read-only panel path: the earlier asynchronous config preflight
work did not cover status/health. These calls held no config-write-lock but blocked
the executor.

## Fix

Both handlers use one shared NAT diagnostic and asynchronous discovery. Quick Start
IPv6 discovery uses the same mechanism. Standard tool paths now live in one module,
also reused by existing synchronous server CLI probes. Without an installed candidate,
fallback `--version` uses the common asynchronous process collector.

- Four shared slots bound concurrently admitted async iptables/ip6tables fallback probes.
  Queue time counts toward the request deadline; waiting does not grant a fresh budget.
- Status/health receive 15 seconds for discovery; Quick Start supplies its remaining
  preflight deadline. Expired calls do not accept even an immediately available fast path.
- Stdout/stderr each have a 64 KiB limit; overflow never yields partial accepted output.
- Timeout requests group termination and waits for the child; request cancellation signals
  the owned group and leaves final cancellation reaping to Tokio. No detached blocking task.
- Without NAT profiles these two handlers skip probing. Confirmed tool absence remains
  critical; timeout, permissions, overflow and nonzero exit produce the warning
  `Could not verify iptables availability`. API shape and authentication are unchanged;
  user configs remain INI, with no new parameters or ABI changes.

## Validation

Eight new ordinary Linux tests cover exit/argv, NotFound, overflow, expired/queued budgets
without spawning, shared queue/command time, four-slot admission for eight requests,
real-child cancellation with permit release and reap, task-local probe isolation,
missing/unknown diagnostics and skipping unnecessary checks. The task-local override
replaces only fixture-program discovery; it changes neither PATH nor other requests.
The production collector and child processes remain real.

One new privileged test creates private mount/network namespaces and hides the real
control socket beneath private `/run`. In-process HTTP requests traverse the actual
Axum router, routing and the test configuration's AuthGuard. On current-thread Tokio,
status and transport health each wait for a 1.5-second fixture process while `/system`
responds within its allotted 300 ms, before the probe completes. Host networking and
services remain unchanged. This is not wire-level HTTP/TLS or system supervisor E2E.

A counterfactual restored only synchronous `.output()` with a fresh 15-second command
deadline, preserving the new semaphore/handlers/tests. Two regressions failed as expected
with exit 101: late success after the queue budget and `/status` blocking until child
completion. The source file was then restored byte-for-byte. This compares old behavior
at the same boundary, not a full run of the previous commit.

Final snapshot: **1468 host unit + 71 config integration PASS**; all nine feature/cross/lint
commands PASS. Linux: **1943 ordinary + 30 privileged PASS**, **8 worker lifecycle E2E PASS**
(TCP/UDP × off/manual/route/nat66). Two child helpers are invoked by parent tests rather
than standalone. Process/HTTP-router tests verify the new behavior; server lifecycle
provides the broader regression. Linux Rust 1.97, host Rust 1.98; the previous Clippy
`chunks_exact_to_as_chunks` allowance remains.

Worker SHA256: `e94a95ce5be1b7cdf057b1705e3248c0f2ce4477c248de59d980ddee0b148eef`.
Source archive SHA256: `638e023059e86deb32595eaf38e308fb063427bde150dba3975969c19b056be3` (310 `qeli`/`conformance` files, before commit).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/panel-probes-phase/`,
`panel-probes-clean.log`, `lifecycle-panel-probes-clean/`,
`panel-probes-counterfactual/`. The first `panel-probes-final` run preceded a cancellation
test PID-handshake refinement; final results refer to `clean`. The intermediate
`panel-probes-verified` reused the counterfactual test binary from Cargo cache after tar
restored older source mtimes; its four FAIL results do not qualify the fixed build.
Final `clean` verifies all 310 source hashes before/after and cleans only the qeli package
in its private target before compilation. All work ran on `.11`; the running `.10` server
was unchanged.

## Remaining boundaries

This deadline covers discovery, not entire handlers/HTTP requests. Standard file-path
checks remain synchronous. File I/O, spawn and kill/reap receive no hard upper bound
from a timer. Finding a pathname does not establish firewall functionality, and the
probe admission limit is not panel load certification. NAT/routes/kill-switch sequence
budgets, other lock waits, full HTTP fault/systemd and D13 remain open. D05 and D09 are
not fully closed. Troubleshooting §6.36 also corrects stale preflight wording: its
shared deadline and asynchronous execution had already been implemented.

[Earlier panel phase](AUDIT-Q05-PANEL-TRANSACTIONS.md) ·
[Panel manual](../../manuals/PANEL.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)
