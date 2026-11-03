# Q25: cancelled shutdown and TUN worker ownership

Date: 23 September 2026. Baseline commit: `2a8a3af3`.
Sections 21, 22, 25 and 27: **IN_PROGRESS**; full platform audits remain open.

## Finding

**Q25-F014, P2 — cancelling started shutdown could destroy the pump before worker joins.**
Unix TUN and Wintun shutdown removed the reader/writer JoinHandles from the pump and moved
those handles into spawn_blocking. If the shutdown future was then destroyed, pump Drop
had no handles left and did not wait for worker termination. Joining continued in a separate
blocking task or remained queued in the pool. Plain Drop without a started shutdown already
joined synchronously; it was not the source of this defect.

Native-runner cancellation can drop run_attempt through this path; finish_generation runs
before Tokio runtime destruction. Runtime destruction later waits for blocking tasks, so
this does not establish a permanent leak or live workers after qeli_client_run returns.
The confirmed defect is early completion of pump destruction and possible generation
completion bookkeeping before joining. This fix does not change ClientCore state publication
or generation-replacement policy.

## Fix

Shared `qeli/src/transport_core/tun_workers.rs` retains joint handle ownership between the
pump and its blocking helper. The mutex remains locked until every join completes. On waiter
cancellation, Drop either waits for the ongoing join or joins the workers itself when the
helper is still queued. This fallback needs no free blocking-pool thread. Normal async
waiting does not block the executor. A worker panic is logged without skipping other joins.

Both pumps signal stop and close the inbound queue, unblocking blocking_send, before joining.
Workers must terminate without async-runtime progress because the Drop fallback is
synchronous. Loop waits are bounded, but this does not impose an overall deadline on
OS/driver calls or whole-client shutdown.

Separate reader/writer ownership fields and duplicated shutdown/Drop joins were removed
from `qeli/src/transport_core/linux_tun.rs` and `qeli/src/transport_core/wintun.rs`. Partial
writer-start failure still stops and joins the existing reader. Linux/Android/macOS use the
shared Unix pump; iOS and the Windows packet seam have no such threads and are unchanged.
INI, wire format and ABI 1.16 are unchanged. Release native libraries were not rebuilt.

## Validation

Six common-owner tests cover normal async joining, cancelling a running join, cancelling
queued joining in a saturated blocking pool, plain Drop, a panicked worker and empty/repeated
shutdown. One Windows test calls the real WintunPump::shutdown with controlled fixture
threads: it checks stop, queue closure and waiting for both workers with the pool occupied.
This test opens neither a driver nor a real adapter.

The Windows test was also run against the original Wintun implementation from `2a8a3af3`:
it fails on early Drop completion. It passes with the fix. An additional Unix test uses socket
pairs to check both descriptors close after cancelled shutdown with an occupied pool. On this
Windows host it was cross-compiled only, not executed.

**876 host unit + 52 editor/policy + 7 examples + 12 server INI = 947 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI and
rustfmt pass. Existing diagnostics remain: the chunks_exact_to_as_chunks exception in
unchanged ndp_proxy, 23 server-only warnings, terminal_sender without roaming and an
informational MSVC linker message. Nine documentation checks and diff checks pass.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/tun-worker-audit-20260923.

Linux validation is cross-compilation. Linux runtime, real TUN/Wintun/firewall/DNS, apps on
devices, SSH/systemd/Actions and new benchmarks were not run.

## Remaining work

Forced cancellation of the entire common TCP/UDP TaskGroup future still does not confirm
async joining or platform rollback. This pass closes native TUN-thread ownership, not all
client tasks. Next checks cover nested H2/transport workers and resource-release ordering,
system-command deadlines and platform fault injection. Release requires fresh native builds
and validation on real target systems.

Follow-up on 23 September: client H2 driver/bridge ownership now spans connect through
generation joining; see [Q25-F015](AUDIT-Q25-H2-TASKS.md). Other limits remain.
