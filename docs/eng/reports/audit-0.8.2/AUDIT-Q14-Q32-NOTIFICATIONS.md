# Q14/Q32: bounded notification delivery and shutdown

Date: 23 September 2026. Baseline: `c19ce7e9`. Sections 14 and 32: **IN_PROGRESS**.

## Findings and fixes

**Q32-F001, P1 — unbounded simultaneous sends.** Per-key cooldown and a ten-second
HTTP timeout did not bound aggregate work across different users/IPs. fire spawned a
separate task for each channel. Connect/disconnect, quota, panel lockout, restore and
startup paths also created wrapper tasks, including with channels disabled. Panel test
requests bypassed any common admission limit.

Each worker and supervisor process now owns one DeliveryQueue. Admission is synchronous
and never waits for network I/O: at most **128 accepted deliveries including active
requests**, with **8 active sends** shared by both channels and panel tests. Queued jobs
are owned tasks waiting for a semaphore, so the task count itself is bounded; there is
no unbounded population waiting to enqueue. Full admission drops new automatic sends
and samples a cumulative warning at rejected counts 1, 2, 4, 8, etc. Panel tests return
an explicit error. Disabled channels/events create no delivery tasks. Configuration
metadata/cache reads remain synchronous on the event path, outside per-packet handling.

Retained message data is bounded too: event detail 2048 UTF-8 bytes, display server name
256 bytes (truncated on character boundaries), webhook JSON body at most 32 KiB, URL
4096 bytes, Telegram token 512 bytes and chat id 128 bytes. Oversized destination fields
are rejected, never truncated. Existing configuration values are preserved; no new INI
keys are introduced. One event sent to both channels consumes two delivery slots.

**Q14-F018, P2 — notification tasks outlived process cleanup.** Their handles were
previously discarded, and signal-driven process exit could abandon sends immediately.
The new scoped owner starts before any producer. The global lookup holds only a Weak
reference, so an ended generation cannot leave a permanently registered runtime task.
All notification wrappers were removed. Worker drain starts after profile cleanup and
final accounting; supervisor drain follows child/client shutdown. Resolving the worker
executable moved ahead of supervisor producers so that startup error cannot skip drain.

Shutdown closes admission and waits up to **10 seconds total**, then aborts and joins
remaining jobs. Cancelling/retrying a shutdown waiter retains both handles and the
original deadline; concurrent waiters serialize. Owner Drop is an emergency abort
fallback and cannot itself await destructors. This is best-effort delivery, not a
persistent queue or delivery acknowledgement guarantee.

Panel probes use the same queue with a separate **10-second end-to-end deadline** that
includes queue wait. A timeout or cancellation of their handler aborts the queued/active
job, preventing unsent probes from starting later. This avoids introducing a long queue
wait as a regression of the previous direct ten-second request. Existing HTTP/TLS and
SSRF validation are retained. HTTP 4xx/5xx automatic delivery results now produce a
channel-specific warning instead of being silently treated as transport success.

## Validation

- **12 new isolated behavioral tests**: queue/active bounds, complete drain, timeout
  resource release, cancellation/retry and concurrent shutdown, panic isolation, owner
  Drop, probe timeout and queued-probe cancellation, disabled events, UTF-8/JSON expansion,
  oversized destination fields, shared panel admission and process-owner recreation.
  Several related assertions share one scenario; there are eight queue and four
  notification tests.
- Four existing notification helper tests now run on Windows too: URL parsing, control
  characters, defaults and SSRF address rules. The permission-stamp test remains Unix-only.
- **793 host unit + 52 editor/policy + 7 examples + 12 server INI = 864 Rust tests PASS.**
  Linux all-targets Clippy PASS with the previous chunks_exact_to_as_chunks exception in
  unchanged ndp_proxy.rs. Minimal FFI, rustfmt, diff and nine docs checks PASS.
- Tests use pending/in-memory fake deliveries. The panel overload fixture uses a numeric
  loopback URL rejected by SSRF even if queue admission regresses. No Telegram/webhook
  request, external SSH, live TUN/firewall or benchmark was run.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/notifications-audit-20260923 contains
baseline, before/after sources, test/check logs, diff and verification metadata.

## Remaining work

Linux signal/systemd/restart and real transport integration still need Linux execution;
cross-compilation is not E2E evidence. Remote receipt cannot be undone when a caller
cancels an already-sent request. Full queues and shutdown deadlines deliberately permit
notification loss; no persistent retry or guaranteed delivery is claimed. Runtime abort
and non-yielding/blocking code cannot be given a synchronous destructor-join guarantee.

The config cache/load trust boundary, URL/HTTP protocol edge cases and cooldown timing
need deeper passes. Supervisor panel/metrics/autostart task ownership also remains open.
Sections 14/32 and the full audit are not complete.
