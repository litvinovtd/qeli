# Q28: final macOS integration

<!-- normative-sync: q28-macos-integration-v1 -->

**5 October 2026: Q28 DONE within the agreed scope. Plan 28/37 (75.7%), 9 sections remain; next Q29 Android. Actual Mac and Swift compiler/runtime USER SKIPPED by the user.**

| Defect | Change and validation |
|---|---|
| F271 | DNS/PF compared local process start ticks. A timezone change could authorize DNS restore or PF flush against a live owner. New DNS journals use schema 2 UTC ticks; PF uses `clock=utc`. Old DNS v1/untagged PF are legacy: any live recorded PID stays protected regardless of ticks; a missing PID permits recovery. Tagged UTC mismatch distinguishes PID reuse. Equal numeric legacy/UTC identities cannot authorize claim/release/refresh. Out-of-range ticks are rejected. |
| F272 | TCP EOF stopped both directions and could truncate the response after app FIN. App EOF now propagates `SHUT_WR`, preserving server-to-app; remote EOF closes flow write, preserving app-to-server. Both EOF or error/cancellation retire the relay. EOF read source stays suspended until final cancel; only its cancellation handler closes the published fd. State/syscalls use the same serial queue. |

## Current checks

- **1248 managed PASS:** Mac storage54/control83/network **140**/per-app39/forwarding58; Windows325/shared549. Network adds **23** checks using real process probes and production journal/recovery with injected network boundaries. A three-hour recorded offset simulates the old stamp ambiguity; host timezone was not changed.
- **4 expected baseline FAIL** from unchanged preceding DnsJournal/PfRecovery: live PID protection, startup PF sweep, legacy claim rejection and DNS same-numeric identity. Only storage/network boundaries are injected; real host PID probe executes. This is not Darwin runtime.
- Three Release builds, zero warnings/errors; three equal QeliShared DLLs. Unchanged native/Rust digest and 14 actual artifact hashes. Docs/bindings/panel/diff and release qualification checked.
- **8 new Swift cases** exercise production RelayDuplex. **Not executed**. Source review covers both EOF orderings, duplicate EOF, delayed callbacks, backpressure and balanced source cancel/resume. No native baseline or physical TCP response PASS is claimed.

## Whole-section criteria

| Criterion | Evidence and limit |
|---|---|
| Review/dead code | [Storage](AUDIT-Q28-MACOS-STORAGE.md), [daemon/control](AUDIT-Q28-MACOS-CONTROL.md), [network](AUDIT-Q28-MACOS-NETWORK.md), [per-app/build](AUDIT-Q28-MACOS-PERAPP.md), [forwarding](AUDIT-Q28-MACOS-FORWARDING.md), [guardian](AUDIT-Q28-MACOS-GUARDIAN.md), [sockets](AUDIT-Q28-MACOS-SOCKETS.md), current F271/F272. Per-app stage removed duplicate FlowLifetime and unreachable UDP cast. |
| Positive/boundary/negative | Fresh374 Mac managed checks and874 Windows/shared; preceding10 shell fixture PASS on unchanged build.sh. Native Swift cases SOURCE REVIEW, not PASS. |
| Failures/concurrency | Key-provider errors, partial mutations, locks/ownership, retry/checkpoints, real local child/PID and isolated files. Kernel/manager boundaries injected; physical crash recovery excluded. |
| Integration | C#/shared ABI/build contracts, release artifacts/provenance. Windows host qeli.dll serves DTO getters; Darwin dylib was not executed. |
| Fix/retest/evidence | F240–F272 within the previous reports' limits; fresh qualification and immutable raw logs. Historical formal release cases/artifacts/timestamps and physical rows preserved. |

Q28 closure means available criteria complete with explicit user exclusions. Actual GUI/Keychain Unix permissions, utun/PF/networksetup/sysctl/launchd, NE managers/callbacks, Intel/ARM native execution, entitlements/signing/notarization, DNS leaks, crash/roaming/sleep on Mac are **USER SKIPPED**, not PASS. Related managed checks do not execute Swift or prove those properties.

## Upgrade and operation

Stop old Qeli profiles/guardians before upgrading. A new client cannot claim legacy DNS/PF state while the recorded PID exists: timezone and PID reuse are ambiguous in the old format. After process exit, recovery may restore the Qeli-owned snapshot under existing rules; PF is never globally disabled. If another process occupies the PID, inspect it and the network state manually; do not blindly delete journals. Old clients do not understand the new clock/schema and are not a safe downgrade with an active profile. External configurations remain INI; the JSON DNS journal is internal recovery state.

Half-close adds no idle timeout: the remaining direction may legitimately run indefinitely. Error/cancellation/write timeout still retires the relay; arbitrary OS callbacks/syscalls have no guaranteed teardown deadline.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-integration-20261005.
Evidence: release/certification/evidence/q28-macos-integration-20261005.json.
No lab/network/service/profile/timezone changes or push/deploy.

Contracts: [Apple TCP flow EOF](https://developer.apple.com/documentation/networkextension/neappproxytcpflow/readdata%28completionhandler%3A%29), [Apple directional shutdown](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/shutdown.2.html), [.NET Process.StartTime](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.starttime?view=net-10.0).
