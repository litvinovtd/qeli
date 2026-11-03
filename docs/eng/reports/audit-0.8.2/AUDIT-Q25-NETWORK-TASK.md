# Q25-F105: applying NetworkPlan outside the async executor

25 September 2026. Base `2b3011b7`. D05/D09, Linux and the shared TUN preparation contract.

## Problem

`ClientPlatform::prepare_tunnel` was synchronous. Linux applied the whole NetworkPlan
on the async executor: TUN, addresses, gateway/sysctl, routes and DNS. Waiting for a
system call or child command delayed neighboring async tasks; a current-thread runtime
could not process stop signals or publish status. The native adapter also waited for
NetworkPlan acknowledgement using `std::thread::sleep` inside its transport runtime.

Simply cancelling `spawn_blocking` does not resolve ownership: work may continue changing
the network after the outer namespace lease is released, while an abandoned result
owning a TUN must first roll back its settings in the original context.

## Fix

TUN preparation is asynchronous in the shared internal TCP/UDP contract. The unused
HandshakeNetwork parameter is removed. The native adapter keeps its existing ACK/cancel
checks and 45-second timeout but waits using async sleep. Public C ABI and INI remain
unchanged; shipped client libraries still need separate D11 rebuilds.

Linux transfers owned config/plan and cleanup owners to a fresh thread. It inherits the
calling thread's context; open fds pin NET/mount namespaces. Context is verified before
work and before adopting the result. No reused thread pool or `setns` is involved.

The worker retains the result until the client decides. Acceptance has no new `await`
between the decision and result transfer through `join`: cancellation cannot lose an
already-created TUN in that interval. On rejection the worker drops the result and
rolls it back in the original namespace; the client asynchronously awaits that rollback,
then joins the thread. Normal stop sets the shared cancel flag and awaits started work.
Checking cancellation before ACK prevents acknowledging an already-observed stopped
session. ACK failure also triggers joined rollback; cleanup errors remain in the shared
Failures registry and prevent a successful restart.

Forcibly dropping the waiting future uses a synchronous Drop fallback: it closes result
admission and joins the worker before releasing outer ownership. This preserves cleanup
ordering but may block the thread calling Drop. It is not hard, prompt cancellation
of a system mutation.

## Validation

- 7 new portable tests cover current-thread runtime responsiveness, cancellation before
  start, joining started work and rollback, forced Drop, single resource transfer,
  worker errors and panics. One additional Linux test checks stop during apply:
  rollback before Running and retained cleanup failure; 4 existing adapter tests became async.
- One new privileged test checks inherited NET/mount namespaces. After the waiting
  thread changes its NET context, adoption is rejected and the result is destroyed in
  the worker's original NET/mount namespaces.
- A control copy restoring synchronous `work()` fails the responsiveness test
  (exit 101); the fixed copy passes (exit 0). This is a helper counterfactual, not
  the previous complete binary; production source files were not modified by this check.
- Real TCP/UDP connections × delay after TUN creation / after `ip link ... up`:
  **4/4 PASS**. Server and test client use current Qeli; the client driver runs the
  library on a current-thread Tokio runtime with a 100 ms heartbeat. Every case
  advanced 7–8 ticks during 800 ms of blocked setup and 8 ticks during 800 ms after
  SIGTERM. The operation retained its TUN until barrier release; `post_up` never ran,
  final state was `stopped`, exit 0, original rules and routes were restored exactly,
  with no TUN or retained `*.state` files.
- Exit after barrier release: TCP create 0.315 s, TCP up 1.868 s, UDP create 0.365 s,
  UDP up 1.868 s. These are four scenario measurements, not a benchmark or deadline promise.
- Repeated the hostname mixed-firewall matrix: IPv4 nft / IPv6 legacy without firewalld
  and IPv4 legacy / IPv6 nft with firewalld. **38/38 cells**, 34 crash/recovery,
  1220 main assertions and 806 nested checks PASS. All 1088 denied UDP attempts had
  zero delivery with verified DROP counters; 656 allowed probes received replies.
- Full snapshot: **1551 host + 71 config; 2106 Linux + 45 privileged + 8 worker lifecycle
  PASS**. All 9 host/cross/feature/lint/format commands passed; Clippy retains the existing
  `chunks_exact_to_as_chunks` allowance for toolchain differences. RU/EN documentation
  checks and `git diff --check` pass. Platform compilation is not runtime certification.

## Evidence and limits

Lab: only `10.66.116.11`, Debian / Linux 6.12.105+deb13, Rust 1.97;
local checks used Windows / Rust 1.98. Working server `10.66.116.10` was not used.
Runtime scenarios ran in separate NET/mount/PID namespaces with private `/run`,
`/var/lib`, `/var/log`, `/etc/qeli` and `/tmp`. Versions: iptables 1.8.11 (nft/legacy),
nft 1.1.3 and private firewalld 2.3.1.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`network-task-phase/evidence.json` links hashes, results and **347 source files**;
`checks.json` and logs in that directory retain exact commands. The 19-scenario manifest
retains raw hashes and hashes after LF normalization. `network-task-driver/` contains
the test driver's source, Cargo.toml and Cargo.lock; it is not a shipped client.

Runs: `network-task-linux-v1`, `network-task-driver-v2`, `network-task-repro-v3`,
`network-task-counterfactual-v1`, `network-task-matrix-v1`; each retains log/rc,
with before/during/after snapshots, commands and results for runtime checks. Repository
scenario: `scripts/audit_network_task.py --qeli <worker> --driver <driver> --artifacts <new-dir>`;
it requires disposable Linux and root for private namespaces.

Failed intermediate attempts are retained separately and not counted as PASS: the first
driver build used the wrong crate name (`qeli_core`); the first repro had no driver.
In the second repro both create cases passed while two up cases exposed a fixture error:
SIGTERM reached the Python launcher wrapper instead of the driver. Final repro-v3 uses
an absolute path to the original `ip` launcher; all four checks passed on the same Rust source.

The matrix used scripts-v1; the final standalone repro used scripts-v2. Comparing both
manifests confirms only `audit_network_task.py` changed, which the matrix does not invoke.
The other 18 files match; each matrix fixture's hashes were verified against its retained
manifest. The final manifest matches repository files.

| Artifact | SHA-256 |
|---|---|
| `qeli-network-task-v1-worker` | `dcbd993f1abee3d24837958501f1344d758947b127547cd62139f8f86b886d7c` |
| `qeli-network-task-driver-v1` | `0eee377bd958626e59b1e9405fb8baab5cea188ab984ad467d3f18593816d511` |
| `linux-source-final.tar.gz` | `66be4506e2429992e4f594c43b5b74cb3acc041a4ca0e6bb6b26a3464ae147cc` |
| `network-task-matrix-v1.tar.gz` | `d927a6354238ebd7ec967d690bfaf5b4724e8470cfb64a3d3a6dff84517e0b60` |
| `network-task-repro-v3.tar.gz` | `189490e0f7c60e4acee22c41839774ec576b70b5e18294f6254f8f9fb717f4b9` |
| `network-task-counterfactual-v1.tar.gz` | `c435e1581be100e10aab9d11321c8b2457269e038edeb62c862cd8fed1dbc1da` |
| `network-task-driver.tar.gz` | `96516fafd9debb2eb48bb2c1c97470e2ab2e1926106021affdf79982354af2ee` |
| `lifecycle-network-task-v1.tar.gz` | `90bc5246cf1951e5c962f3106143c285e331e3e9e6f15aa9b994ad5e76369b68` |
| `network-task-scripts.tar.gz` | `64ef91bc51b90852c86787b88f4d3c342f54573e89c8f070e375d5e9e4033d26` |


D05 stays **IN_PROGRESS**. Ordinary teardown of an established TCP/UDP tunnel,
kill-switch setup/refresh/cleanup, internal locks/I/O and diagnostic-file publication
still contain synchronous sections. Whole NetworkPlan/shutdown has no single deadline.
An already-running syscall is not interrupted: work may finish setup after stop and
then roll it back. Existing command budgets remain; the fixture's timing is not a
guaranteed whole-shutdown duration.

Threads are created sequentially for one client's operations; this is not a new global
limit on client processes. External root changes between checks have no atomicity
guarantee. D06/D10/D13, benchmarks and certification remain open. Windows VM, Mac/iOS
and physical-router runtime remain **SKIPPED by user decision**; this phase does not
certify those runtimes or a fresh Android package.

Debt: **4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO**.
[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/OPERATIONS.md).

Follow-up: [Q25-F106](AUDIT-Q25-TUN-TEARDOWN.md) shares graceful established TCP/UDP tunnel teardown on a joined worker. Early error/Drop fallback and overall D05 remain open; historical results above are retained.
