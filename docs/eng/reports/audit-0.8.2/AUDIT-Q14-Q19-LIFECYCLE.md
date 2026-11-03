# Q14/Q19 audit: profile shutdown and DNS listeners

Date: 23 September 2026. Baseline: `7995affd`, following
[EDNS/RDATA](AUDIT-Q19-DNS-EDNS.md). Sections 14 and 19 remain **IN_PROGRESS**.

## Scope

Reviewed generation task ownership, early startup errors, concurrent/cancelled
shutdown waits, actual UDP/TCP DNS listeners, and socket release. Production
`ProfileTasks` moved from `server/mod.rs` to `server/tasks.rs`; host tests now use
the same listeners and task tracker. Removed the unused `Arc<ServerState>` argument
from the UDP listener and both call sites. No new dependencies, INI settings or
client ABI changes.

## Findings

| ID | Priority | Trigger and problem | Fix |
|---|---|---|---|
| Q14-F001 | P2 | NDP or IPv4 DNS has started when a subsequent IPv6 bind, firewall/DHCP setup or another step fails. Local JoinSets were dropped inside `run_profile_generation`, requesting abort without awaiting destructors. The outer wrapper could remove profile resources while services still owned them. | The outer `run_profile` owns both service/listener groups. After every ordinary return from startup, admission closes, services/listeners/children are aborted and joined, then registry/TUN/firewall resources are removed. |
| Q14-F002 | P2 | The first `ProfileTasks::shutdown` took all handles into a local vector. A second call returned immediately; cancelling the first waiter also prevented later callers from waiting for those children. | Pending handles remain in a shared JoinSet. An async mutex serializes waiters, and cancellation-safe polling permits a later waiter to resume joining. |

Q14-F001 follows reachable `?` paths after spawn. Normal shutdown already joined
both groups in the baseline; the gap concerned early returns. Loopback tests
exercise the common cleanup boundary, a subsequent occupied bind, and immediate
port rebinding. Full Linux `run_profile` with TUN/firewall was not executed here.

Two tests reproduced Q14-F002 on the unchanged production tracker after extraction:
both failed with `shutdown returned before its children were dropped`. The normal
supervisor has one shutdown waiter; this fixes the concurrency/cancellation
contract rather than demonstrating a frequent failure of ordinary stop.

JoinSet also replaces scanning every live handle on each spawn and silently
discarding finished task results. Completion notifications drive reaping and
panics are logged. No speedup has been measured.

## Verification

**727 Rust unit + 52 editor/policy + 7 examples + 12 server INI = 798**, PASS.
The unit suite includes 52 resolver, 7 listener and 7 task-ownership tests.
Fourteen tests are new; one existing Linux-only test moved into the host suite.

- Both baseline wait defects: concurrent callers and cancellation of the first waiter.
- Cancelled service-group shutdown can resume; new children are refused.
- Eight producers race shutdown: all 1,024 captured resources are released.
- Completed/panicked children are reaped without retaining old handles.
- IPv4/IPv6 UDP, TCP pipelining and repeated exchanges on one connection.
- Stop cancels 32 queries waiting for a cache lock and a partial TCP body,
  releasing references/ports while a sibling DNS profile continues serving.
- A real query to a silent loopback upstream releases its wildcard UDP port
  at stop without waiting for the 30-second resolver timeout.
- Partial TCP prefixes/bodies expire; a short frame affects only its connection.
- With 512 active TCP connections, the next is closed; disconnecting frees a slot.
  This verifies the bound functionally and is not a load benchmark.

Three Python DNS-fixture tests, minimal client FFI, rustfmt, diff and nine docs
checks pass. Linux all-targets Clippy passes with `clippy::chunks_exact_to_as_chunks`
allowed; a separate strict run records the existing warning at
`qeli/src/server/ndp_proxy.rs:504` on Rust 1.98. That file is unchanged. Cross-compilation does not establish Linux runtime behavior.

The initial new fixture incorrectly used IP:port in `dns.upstream`; production
accepts bare IPs and uses port 53. Fixtures were corrected without changing that
contract. The upstream release assertion now repeats the actual wildcard bind:
on Windows a specific-address bind alongside a wildcard socket does not establish
port ownership. Both intermediate fixture failures are retained separately from
baseline code regressions.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/dns-lifecycle-audit-20260923/`:
`before-regressions.log`, source snapshots, `rust-unit.log`, `rust-integration.log`,
`linux-clippy.log`, `linux-clippy-strict.log`, `verification.json`, `review.diff`.
RU/EN manuals clarify stop ordering and independent listener limits.

## Remaining checks

Linux E2E must cover errors after NDP/IPv4 DNS spawn, actual TUN/firewall rollback,
restart/reload/control/hook failures and sibling isolation. Forced cancellation
or panic of the outer wrapper uses synchronous Drop/abort fallback, without an
async join guarantee; that scenario is not declared complete.

TUN thread shutdown, external interoperability, sustained load/RSS/fd, DNSSEC/RRset
and OS DNS apply/restore remain open. No live OS networking, external SSH lab or
unchanged native clients were used. The next pass covers supervisor, watch/control
shutdown and startup failure recovery in section 14.

Follow-up on 23 September: [Q14-F022/F023](AUDIT-Q14-H2-TASKS.md) adds profile joining
for server H2 drivers/bridges and rejection flushes, retaining pre-auth admission until
a rejected connection is released. Standalone API behavior and other limits remain.
