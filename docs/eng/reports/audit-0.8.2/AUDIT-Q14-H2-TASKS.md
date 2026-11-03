# Q14: server HTTP/2, profile shutdown and pre-auth admission

Date: 23 September 2026. Baseline commit: `a595e898`.
Sections 09, 11, 14 and 22: **IN_PROGRESS**; the full audit remains open.

## Findings

**Q14-F022, P2 — profile shutdown did not join nested H2 drivers/bridges or rejection flushes.**
The profile owned the outer session task, but `h2_carrier::accept` spawned separate Tokio
workers. Carrier Drop requested driver/bridge cancellation without assigning joining to
the profile. Outer-task completion could allow profile cleanup before destruction of the
outer H2 I/O had finished. A separate rejection-response flush was also outside the group.
That flush already had a one-second limit: this was an ordering gap, not an unbounded leak.

**Q14-F023, P2 — pre-auth admission was released before an invalid H2 response finished.**
After accept failed, the REALITY handler returned an error and released its permit while
the flush still owned the connection. Live rejected connections escaped handshake admission
accounting. H2 follows REALITY validation and outer TLS; this pass did not measure resource
exhaustion under load or validate external exploitation.

## Fix

`ProfileTasks` provides a weak `ProfileSpawner` for nested workers. Registration and
admission closure share one mutex; a stopped profile rejects new tasks. Weak references
avoid a registry ownership cycle. A rejected future is destroyed after releasing the mutex,
so its guard can reenter the registry from Drop.

The common H2 carrier supports a client-generation owner, a server-profile owner and the
existing standalone API. The server REALITY path calls `accept_owned`; the normal driver,
bridge and bounded rejection flush enter the profile JoinSet. Individual abort handles
remain with the carrier. Normal `ProfileServices::shutdown` joins these tasks before profile
unregistration and teardown, including later startup failures. Cancelling one shutdown wait
preserves handles and permits another wait.

Rejection transfers the admission guard and connection together into `RejectionFlush`.
Field ordering releases I/O before the permit, including an unpolled task or a spawn rejected
by a stopped profile. Success returns the permit to inner authentication: a successful H2
response does not release admission, and completed AUTH does not charge the established VPN
session against that budget. The existing one-second flush limit and HTTP statuses remain.

Changed sources: `qeli/src/server/tasks.rs`, `qeli/src/server/reality.rs`,
`qeli/src/protocol/h2_carrier.rs`. Shared test I/O fixtures now live in
`qeli/src/protocol/h2_carrier/test_support.rs`; no separate per-client H2 pumps were added.
INI, wire format and ABI 1.16 are unchanged. Release native libraries were not rebuilt.

## Validation

13 new tests: 11 server H2 tests and two weak-spawner tests. Coverage includes:

- joining delayed I/O destruction, two concurrent shutdown waits and cancellation/retry;
- accept cancellation before the preface or first request, and a stopped owner;
- delivery of 405, joining a flush at shutdown, and flush expiry while the peer stays open;
- cancelling a zero-window bridge, half-close with a reverse reply, and later-stream 404;
- retaining pre-auth during flush and destruction, including spawn rejection before polling;
- handing the permit to inner AUTH, absence of ownership cycles, and a reentrant Drop guard.

Two join regressions fail with the original H2 from `a595e898`: a test signature adapter
forwards to the previous accept without task registration. The permit regression separately
fails on an intermediate version with joining fixed but the previous admission lifetime:
a slot becomes available while its connection is still alive. Adapters and logs are retained
alongside the corresponding fixture sources. All three checks pass with the final fix.

**898 host unit + 52 editor/policy + 7 examples + 12 server INI = 969 Rust tests PASS.**
This includes 31 H2 tests. Linux all-targets Clippy, client-only, client without roaming,
server-only, minimal FFI, compatibility without features and rustfmt pass. Existing diagnostics
remain: 23 server-only warnings, terminal_sender without roaming, 33 compatibility dead-code
warnings in unchanged modules and an informational MSVC linker message. The Clippy
chunks_exact_to_as_chunks exception concerns unchanged ndp_proxy.
Nine documentation checks and git diff --check pass.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/server-h2-audit-20260923.

## Limits and next pass

New tests use real H2 over duplex I/O, actual ProfileTasks and semaphores, without running
a Linux worker. Production permit handoff and teardown were reviewed and cross-compiled.
Linux runtime, real TUN/firewall/DNS, SSH/systemd/Actions, platform apps and new benchmarks
were not run.

Public standalone accept/connect retain Drop cancellation without an external async join.
Destroying the entire runtime/owner cannot guarantee joining; there is no overall hard
shutdown deadline. Early platform rollback, forced UDP cancellation, system-command
deadlines, other pre-auth/TLS scenarios and target-device validation remain open.

Previous passes: [profile lifecycle](AUDIT-Q14-Q19-LIFECYCLE.md) and
[client H2 tasks](AUDIT-Q25-H2-TASKS.md).

Follow-up on 23 September: [Q25-F016/F017](AUDIT-Q25-SYSTEM-COMMANDS.md) bounds
TUN/resolvectl commands and tests DNS-marker retention on errors. Route/firewall commands
and an overall shutdown deadline remain open.
