# Q14 audit: supervisor, worker and control events

Date: 23 September 2026. Baseline: `cdee5941`, following
[profile task and DNS lifecycle checks](AUDIT-Q14-Q19-LIFECYCLE.md).
Section 14 remains **IN_PROGRESS**.

## Scope and changes

Reviewed the child data-plane process loop: spawn failures, exit, cancellation,
backoff, Restart/ReloadUsers, channel closure, grace deadlines and watch shutdown.
The production loop now lives in `qeli/src/server/supervisor.rs` and is called by
the same Linux `run_supervisor`. Host tests launch an isolated child test process
that reads stdin, with no networking or privileged operations. Unix signals stay
in the Linux adapter. `WorkerCmd` retains its public path through re-export.
INI settings, JSON APIs, client ABIs and dependencies are unchanged.

## Findings

| ID | Priority | Before | After |
|---|---|---|---|
| Q14-F003 | P2 | A spawn failure caused a 2s sleep and another spawn without observing SIGINT/SIGTERM. Persistent failure could prevent ordinary shutdown indefinitely. | A common retry wait handles stop and commands. An already received stop prevents spawning. Spawn errors use 1, 2, 4, 8, 16, 30 second backoff too. |
| Q14-F004 | P2 | Child moved into a detached wait task while the main loop signalled a saved PID. Cancelling the supervisor did not cancel that waiter; metrics retained exited PIDs. Reaping before a command left a window for signalling a recycled PID. | The loop owns Child. Wait, try_wait and signal use that same object; metrics clear before backoff and on cancellation. Drop requests kill. Wait status/errors are no longer discarded. |
| Q14-F005 | P2 | There was no deadline after SIGTERM: a stuck worker could block stop or an internal restart indefinitely. | Allow 60 seconds for graceful termination, then kill and wait. Repeated Restart does not extend the deadline; the next generation follows the old one's wait. |
| Q14-F006 | P2 | Panel commands were not consumed during crash backoff. Queued Restart/Reload reached the freshly spawned generation, causing redundant restarts and delaying senders. | Restart wakes backoff; old queued commands coalesce before spawn because the new worker reads fresh files. Reload does not signal a terminating process. |
| Q14-F007 | P2 | Signal handlers were installed after panel/client startup in the supervisor and after control/profile tasks in the worker; SIGINT registration happened later through select. Registration failure could also occur after side effects. | Install SIGINT/SIGTERM, plus worker SIGHUP, at the beginning of the respective function before services and networking changes. |

Four regressions failed against the extracted old algorithm: stopping after spawn
failure, stale PID during backoff, supervisor cancellation and ignored graceful
termination. Original source, the pre-fix extracted loop and output are retained.
Tests cover ownership of a real Child, including pipe closure after cancellation.
Linux PID reuse by an unrelated process was deliberately not simulated; closing
that window follows from Child ownership and inspection of installed Tokio source.
F007 is checked by source ordering and Linux cross-compilation, not by signalling
a running Linux server.

## Verification

**741 Rust unit + 52 editor/policy + 7 examples + 12 server INI = 812**, PASS.
The new module has 13 behavioral tests plus one child-fixture entry point, also
counted by libtest. Coverage includes:

- Four original wait/ownership failures.
- Stop before the first spawn; closure of empty and populated channels.
- Closing a live worker's command channel without repeatedly sending stop.
- Reload without replacing the generation; one restart for queued old commands.
- Apply waking a 30-second retry backoff without waiting for its timer.
- Repeated Restart preserving the deadline and preventing overlapping generations.
- Watch: initial true, sender closure, false updates and cancellation before true.

Review found and fixed an intermediate implementation error: a closed channel with
a queued Restart could still permit retry. `review-closed-owner.log` records its
failure before correction; this is separate from baseline findings.

A parallel full run exposed `AddrInUse` in an existing DNS fixture: a free TCP port
is not necessarily available for UDP. One test-only helper now reserves both
sockets, retrying only conflicts and at most 64 times. A separate EDNS response
content test timed out once with a one-second deadline; its headroom is now five
seconds. The cause of that timeout is not established as a production defect.
Deadline tests and production DNS are unchanged; the final normal parallel run passes.

Linux all-targets Clippy passes with the existing
`clippy::chunks_exact_to_as_chunks` exception. A separate strict run records the
warning in unchanged `qeli/src/server/ndp_proxy.rs:504` on Rust 1.98. Minimal FFI,
rustfmt, diff and nine documentation checks pass. Host tests ran on Windows;
this does not establish Linux runtime behavior.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/supervisor-audit-20260923/`:
`before-regressions.log`, `baseline-extracted-supervisor.rs`, `review-closed-owner.log`,
`review-dns-fixtures.log`, final logs, `verification.json`, snapshots and `review.diff`.
RU/EN troubleshooting manuals and the audit registry are updated.

## Limits and next pass

The 60 seconds is a grace period, not a guarantee that a process blocked in an
uninterruptible kernel wait exits. SIGKILL skips post_down and does not confirm
complete firewall rollback; the next worker's stale-rule cleanup is not Linux E2E.
Real Unix signals, systemd/procd, the window before entering the async function,
hooks and startup rollback still need a Linux lab. Forced cancellation of the
profile wrapper remains open from the previous report. No performance measurements
were made.

Next: control.sock ownership and parent-directory permissions, control-handler
shutdown and post_up/post_down pairing. No external SSH scenarios or live OS
networking were used. The full Qeli audit is not declared complete.
