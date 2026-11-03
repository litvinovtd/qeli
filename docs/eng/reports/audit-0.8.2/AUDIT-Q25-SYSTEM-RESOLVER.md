# Q25-F103: system DNS waiting and client shutdown

24 September 2026. Base `c8b4cccf`. Partial D05/D09 closure; shared transport core and Linux client.

## Defects and fix

Kill-switch called system DNS/NSS synchronously. Its 15-second budget rejected a
late answer but did not bound the call's waiting time or allow stop signals to cancel
it. Connections/UDP diagnostics used `tokio::net::lookup_host`, delegating NSS to the
blocking pool: cancelling the async future did not finish the underlying call, and
runtime destruction could wait indefinitely. The previous `shutdown_timeout(50 ms)`
diagnostic workaround avoided that wait but did not bound accumulated stuck DNS threads.

The new `transport_core/resolver` module serves kill-switch, Linux TCP/UDP, native
adapters' system fallback and UDP diagnostics. One semaphore admits at most four
unfinished NSS calls. Queue waiting consumes the request deadline; each worker
receives its permit before starting and keeps it until actual completion, including
after request cancellation. Late answers are discarded. Numeric IPs bypass the queue
but still reject expired deadlines; platform-supplied addresses remain authoritative.

These are capacity-limited `std::thread` workers outside the runtime blocking pool.
A worker owns only DNS input, its permit and the result channel, with no network
callback or firewall/routes/TUN owner. Linux inherits the spawning thread's context.
Kill-switch pins its context before DNS and verifies it again before mutations.
Setup/refresh budgets and safe firewall-error handling remain intact.

Real comparison exposed another gap: without kill-switch Linux did not check the
stop token until initial carrier connect finished. This phase is now cancellable for
TCP/UDP before NetworkPlan application. Existing TCP/H2 tasks remain owned by
TaskGroup and use ordinary join. Cancellation does not detach/timeout a synchronous
network transaction. Configurations remain INI; the ABI is unchanged.

## Validation

New regressions: **9 ordinary + 1 privileged** cover IP/localhost, neighboring work
on a current-thread runtime, timeout/admission, retained capacity after cancellation,
late-answer rejection, worker error/panic, runtime destruction, cancellation before/
during carrier connect and inherited NET/mount namespaces. Replacing the worker with
`spawn_blocking` reproduces the runtime-destruction test failure (exit 101); the original
resolver passes in a separate control crate. Working source files were not mutated.

`audit_system_resolver.py` delays one selected `getaddrinfo` for 45 seconds through
a test-only LD_PRELOAD shim, only for `qeli-audit-delay.invalid`. Cases cover kill-switch
setup/refresh and initial TCP/UDP without kill-switch. **4/4 baseline processes failed
to stop within 3 seconds** and the fixture killed them with SIGKILL. **4/4 fixed processes
exited with code 0 in 0.003–0.165 seconds**, preserved original operator firewall/routes,
and left no journals or TUN. These are scenario measurements, not a general SLA.

The final matrix resolves `qeli-matrix.test` through real NSS and a private `/etc/hosts`:
IPv4=nft/IPv6=legacy without firewalld and IPv4=legacy/IPv6=nft with real private firewalld.
**38/38 network cells, 34 SIGKILL/recovery cases,
1220 main assertions and 806 nested checks PASS**.
All **1088** direct UDP attempts under protection were blocked, with
EPERM, increasing DROP counters and zero received packets. All **656**
allowed probes received replies. Nested checks are not additional independent tests.
TCP/UDP/QUIC, both carrier/tunnel families, split, TAP, DNS A/AAAA and MTU/PMTU/PTB remain covered.

Host: **1537 unit + 71 config integration**, all 9 feature/cross/lint gates PASS.
Linux: **2089 ordinary + 44 privileged + 8 worker lifecycle PASS**. Python compilation,
bash syntax and 8 matrix contract tests PASS. RU/EN documentation is checked separately.

The first native run remains in evidence: DNS workers were already bounded, but TCP/UDP
without kill-switch did not react to stop; those two FAILs are not counted as PASS.
They prompted the initial-carrier cancellation fix. Matrix v1 passed on the intermediate
binary; the results above refer to the final **v2**.

## Evidence and boundaries

Lab `.11`, isolated NET/mount/PID; working `.10` was unchanged.
All 343 Rust/conformance file hashes and 17 scenario hashes were verified.
Worker SHA256: `effe784cc0bd6a1d40c2feff90eea9aa7c0f6da1bf85aadd74f79d7446b8602a`.
Source archive SHA256: `b0808c29bf5fe336ff5a378689492bda0305bc13be69d51c50785ce3a7e0d6af`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/resolver-budget-phase/`,
`resolver-shutdown-v2/`, `resolver-hostname-matrix-v2/`, `resolver-counterfactual-v1/`,
`lifecycle-resolver-budget-v2/` + `.tar.gz`; logs/exits: `resolver-linux-final-v2`,
`resolver-shutdown-v2`, `resolver-hostname-matrix-v2`, `resolver-counterfactual-v1` (`.log/.rc`).
Commands: `run_checks.py`, `linux-final-v2.sh`, `resolver-repro-v2.sh`,
`hostname-matrix-v2.sh`, `counterfactual.sh`; manifests/results: `evidence.json`,
`linux-source-final-manifest.json`, `scripts-manifest.json`.
Matrix archive SHA256: `706a2fca29117c33545e3e713225fd668bf2d84e060808c2771076aa038108e4`.
Shutdown archive SHA256: `56e5ab1fcfc9eb3983ceae877a7970d6b8f4359ec0e8d0d730b0141e6d3c21a7`.

libc/NSS itself cannot be safely forcibly interrupted. A stuck call retains its
thread, slot and inherited context until completion; four such calls block new
hostname requests until their own deadlines. Numeric addresses continue to work.
This bounds resources and waiting, not successful DNS or whole-connection/shutdown
time. Server notification DNS is a separate path and was not migrated to the
client resolver here.

D05 remains **IN_PROGRESS**: synchronous DNS/routes/gateway/kill-switch mutations,
internal locks/I/O and whole NetworkPlan/shutdown deadlines need separate work with
ownership preserved. This phase does not close D06/D10/D13. Benchmark, certification
and shipped platform binaries were not updated. Windows VM, Mac/iOS and physical-router
runtime remain **SKIPPED by user decision**. Debt totals remain **4/15 DONE (26.7%),
9 IN_PROGRESS, 2 TODO**.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md#kill-switch-kill_switch).

Follow-up: [Q25-F104](AUDIT-Q25-RESOLVER-FILES.md) moves resolver-file reads before firewall setup, shares bounded admission with NSS and unifies the reader/parser with stub detection. Historical results above are unchanged.

Follow-up: [Q25-F105](AUDIT-Q25-NETWORK-TASK.md) moves NetworkPlan application and unadopted-result rollback to a joined worker. Established-tunnel cleanup remains separate D05 work; historical results above are retained.
