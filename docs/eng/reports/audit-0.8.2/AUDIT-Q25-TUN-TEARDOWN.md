# Q25-F106: asynchronous teardown of an established tunnel

25 September 2026. Base `1bd60ed3`. D05/D09, Linux TCP/UDP.

## Problem

After stopping connection tasks, both transports ran DNS restore, route cleanup and
forwarding restoration synchronously on the async executor. A delayed route-delete
command stopped neighboring tasks on a current-thread runtime. Q25-F105 addressed setup,
not this path. TCP and UDP also duplicated the teardown sequence.

## Fix

Both transports call shared `TunGuard::shutdown`. One fresh thread owns TunGuard from
start to finish, including the original TUN descriptor, DNS lease and RouteOwner.
It inherits and pins the caller's NET/mount context. Ordering is preserved:

1. The worker restores DNS and notifies the waiting async task.
2. The async task closes its sender, stops and joins TUN packet workers.
3. The same network worker cleans owned routes, restores forwarding and destroys the
   guard. DNS failure does not skip subsequent stages. The guard is disarmed only after
   successful explicit cleanup; fallback retries also run on that worker.
4. The client receives the result after Drop completes and the worker is joined.

The resource is never transferred back to the async task between stages. Changing the
waiting thread's namespaces during pump shutdown does not change the final cleanup
context. Attach mode continues to preserve the externally owned interface and routes.

Dropping the waiting future during work first drops the pump-shutdown future (its Drop
stops/joins packet workers), then closes continuation and joins the network worker.
Without continuation the worker executes the existing guard fallback. This can block
the dropping thread synchronously; no detached network mutation remains. Failure to
create a thread or capture context also does not skip pump shutdown.

Thread creation/context/panic errors enter the shared Failures registry under a separate
`network transaction` category. Like DNS/routes/forwarding, it retains the first error,
limited to 2048 Unicode characters. Uncertain cleanup prevents reconnect and release of
an enabled kill-switch. Successful fallback retries do not erase reported failure.
The original connection error, including a typed terminal kick, survives added cleanup errors.

INI, public C ABI and user parameters are unchanged.

## Validation

- 5 new portable tests: responsiveness of both blocking stages, one owning thread and
  Drop ordering, continuation after first-stage error, panic before/after pump shutdown,
  and abandonment during pump shutdown with joined fallback. Two existing Failures tests
  now cover the new category, its size limit and concurrent recording.
- One new privileged test: changing the waiting task's NET/mount namespaces between
  stages does not change the original context of later cleanup and resource Drop.
- Real connections on a current-thread Tokio runtime: **2 baseline reproductions**
  with the previous commit's frozen driver and **4/4 fixed PASS** — TCP/UDP × delayed
  route deletion / delayed command failure. The driver runs the current client library
  with a 100 ms heartbeat; transport is real.
- Before stop, all 6 runs advanced 8 ticks over 800 ms. During held cleanup, baseline
  TCP and UDP advanced **0 ticks**, fixed advanced **7–8 ticks**. While the command
  remained held, the TUN and both families' kill-switch rules remained owned.
- Ordinary fixed TCP/UDP: exit 0, `stopped`, exact restoration of original routes and
  rules, no retained TUN/`*.state`. Injected failure: exit 1, `failed`, original routes
  restored by the guard retry, but the error remained and the kill-switch was retained.
  **2/2 new explicit starts after removing the fault** recovered retained firewall state
  and stopped cleanly. Failed cleanup was not counted as successful stop.
- Fixed exits after barrier release took 0.819–1.133 s. This is only an observation
  on this fixture, not a speedup criterion or a whole-shutdown deadline guarantee.
- Repeated the hostname mixed-firewall matrix: IPv4 nft / IPv6 legacy without firewalld
  and IPv4 legacy / IPv6 nft with firewalld. **38/38 cells**, 34 crash/recovery,
  1220 main assertions and 806 nested checks PASS. All 1088 denied UDP probes had zero
  delivery with verified DROP counters; 656 allowed probes received replies.
- Full snapshot: **1556 host + 71 config; 2111 Linux + 46 privileged + 8 worker lifecycle
  PASS**. All 9 host/cross/feature/lint/format commands passed; the existing Clippy
  `chunks_exact_to_as_chunks` allowance remains. RU/EN documentation and `git diff --check` pass.

## Evidence

Lab: only `10.66.116.11`, Debian / Linux 6.12.105+deb13, Rust 1.97;
local checks used Windows / Rust 1.98. Working server `10.66.116.10` was not used.
New runtime scenarios use private NET/mount/PID namespaces and private `/run`,
`/var/lib`, `/var/log`, `/etc/qeli`, `/tmp`. The matrix uses iptables 1.8.11 nft/legacy,
nft 1.1.3 and private firewalld 2.3.1.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`teardown-task-phase/evidence.json` links results, archives and **348 source files**;
`checks.json` and logs retain exact commands. The **20-scenario** manifest retains raw
and LF-normalized hashes; both matrix fixtures were verified against it. Rust source
was unchanged between unit/privileged, driver, runtime and matrix runs.

Runs: `teardown-task-linux-v1`, `teardown-task-driver-v1`, `teardown-task-repro-v1`,
`teardown-task-matrix-v1`. Evidence retains log/rc, before/active/held/after/recovered
snapshots, command calls and wrapper source, which delays the first route delete and
returns an injected fault before actual deletion. `teardown-task-driver/` retains
Cargo.toml, Cargo.lock and test-driver source. The frozen baseline driver is from
Q25-F105, with SHA below. All final harnesses exited 0; the expected client exit inside
fault scenarios was 1. Baseline's 0 ticks records the responsiveness defect, while its
exit 0 after command release confirms this is not a cleanup-hang/failure test.

Reproduce: `scripts/audit_tunnel_teardown.py --qeli <worker> --driver <fixed-driver>
--baseline-driver <F105-driver> --artifacts <new-dir>`. Requires disposable Linux and root
for private namespaces; the driver is a test fixture, not a shipped client.

| Artifact | SHA-256 |
|---|---|
| `qeli-teardown-task-v1-worker` | `f8be1c82fbeb6a51bf31d886d4abe097aa9fa6cbae66facf642dba5ab732fe1e` |
| `qeli-teardown-task-driver-v1` | `5ff88577bf07542d1b947a36800925d15eb2d74ccabc049377233ce5ded2e87f` |
| `qeli-network-task-driver-v1 (baseline)` | `0eee377bd958626e59b1e9405fb8baab5cea188ab984ad467d3f18593816d511` |
| `linux-source-final.tar.gz` | `f277e5bf76014c60afea230b30626f9d4445e3730dd32912be54586b90eea726` |
| `teardown-task-matrix-v1.tar.gz` | `842fbeff7e20182a6cb7a863a8b2d40bf206db0cae8689ba0cce3d75093baa0a` |
| `teardown-task-repro-v1.tar.gz` | `1782344935943ac3a1403a1bf9dce765b1ae73e1112db1c4ffcb31f1dc624faa` |
| `teardown-task-driver.tar.gz` | `bb5b7fc3a05ba27bc3231f5f285d4a998cd28c7293034ab4536664dd637854bf` |
| `lifecycle-teardown-task-v1.tar.gz` | `242f70548fcdbdc21684c4e9c51d00eabc4866ee6683fae19f46884e4d19b9a6` |
| `teardown-task-scripts.tar.gz` | `ecc8470cc9c064e068447040a6a56713b83733bff00144bfecb7b9a3f70ecd8a` |


## Limits

This addresses the synchronous graceful TunGuard teardown after data-plane completion.
Early `?` returns, unwinding and forced Drop retain synchronous fallback. Kill-switch
setup/refresh/cleanup, other locks/I/O and diagnostic-file publication remain D05 work.
There is still no whole NetworkPlan/shutdown deadline; a started syscall is not interrupted.
Fixture timing is neither a benchmark nor a deadline guarantee.

DNS is disabled in the new runtime scenarios: actual delay/failure is injected at route
deletion. Ordering of both blocking stages, exceptions and context are checked by
unit/privileged tests; earlier tests and the matrix cover DNS and other combinations
within their reports' limits. This is not separate new certification of every DNS backend.

D05 remains **IN_PROGRESS**. D06/D10/D11/D12/D13 and the final benchmark remain open.
Windows VM, Mac/iOS and physical-router runtime remain **SKIPPED by user decision**.
No fresh Android package is tested in this phase. No new full-audit sections were opened.
Debt: **4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO**.
[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/OPERATIONS.md).

Follow-up: [Q25-F107/F108](AUDIT-Q25-FIREWALL-TASK.md) moves firewall operations to joined workers and prevents flushing a chain when hook removal is unconfirmed. Historical results above are retained; overall D05 remains open.
