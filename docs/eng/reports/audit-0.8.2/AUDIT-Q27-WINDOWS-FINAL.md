# Q27: Windows GUI, service and drivers — DONE/PASS within agreed scope

5 October 2026. Base `39863933`; Windows, .NET SDK 10.0.300.
**27/37 sections DONE/PASS (73.0%), 10 remaining; next Q28.**

<!-- normative-sync: audit-q27-windows-final-v1 -->

## Criteria reconciliation

| Criterion | Evidence and status |
|---|---|
| Review/configuration/dead code | Shared INI/parser/editor contract Q02/Q26; Windows storage, GUI/service transitions/settings, registration/status/log and driver lifecycle reviewed. Removed cached disk-path shortcut, separate LoadLibrary and duplicated filter literal. PASS. |
| Normal/boundary/negative | 325 Windows selftests and 549 shared conformance, no FAIL/SKIP; 52 new Windows and 6 shared checks in this stage. PASS. |
| Faults/concurrency | Partial Open, thread-start/receive fault, joined shutdown timeout/retry, native/interop close refusal, concurrent module loads, retained gate generations, journal order, failed pre-dispose/TUN Dispose and prewarm readiness. PASS on production paths with injected OS adapters. |
| Available integration | Actual embedded DLL/export/FFI, DPAPI/atomic private files, isolated child processes, read-only SCM/Task Scheduler; Release Windows/shared/Mac compile, signatures/checksums/provenance. PASS within these scopes. |
| Target VM runtime | Real Windows adapter/driver open, routes/DNS/firewall/LocalSystem boot/sleep/service reload are **user SKIPPED**, not PASS. Fake adapters do not replace these executions. |
| Fixes/revalidation | Three previous stages plus this batch, 12 expected baseline failures, sealed raw, source/artifact hashes and certification reconciliation. PASS. |

Previous stages: [storage F222–F224](AUDIT-Q27-WINDOWS-STORAGE.md),
[GUI/control F225–F228](AUDIT-Q27-WINDOWS-CONTROL.md),
[registration/status/log F229–F232](AUDIT-Q27-WINDOWS-OBSERVATION.md).
Their intermediate IN_PROGRESS is historical. Q27 closes under the available criteria
and agreed exclusions; it does not certify actual Windows VPN runtime.

## Final batch findings

| Finding | Change |
|---|---|
| Q27-F233: cache trust/unbounded read | Shortcut returned a cached disk path without revalidation; disk hash used arbitrary File.ReadAllBytes. Every extraction now repeats directory/file trust and hash; oversized seekable input refuses before reading, streaming budget is embedded length+sentinel with a64 KiB buffer. Cache trusted embedded images, not trusted disk paths. No new escalation through an intact protected cache is claimed. |
| Q27-F234: growing DLL references | EnsureDriverLoaded called LoadLibrary on every ensure without FreeLibrary. One synchronized process-lifetime module cache retains the DLL for P/Invoke/Rust GetModuleHandle, refuses null and retries failed loads. Intentional lifetime ownership replaces unbounded reference increments. |
| Q27-F235: lost partial adapter | WinDivert cancellation after Open/Wintun ResolveInterface could throw before _tun publication. Publish ownership before throwing stages. Incomplete Wintun prewarm returns its owned object for cleanup and fails readiness; unused-prewarm cleanup errors propagate. |
| Q27-F236: swallowed shared Dispose | CloseTransports/persisted rebuild swallowed BeforeTunDispose/Dispose and forgot TUN. Failure now stops teardown before clear; Stop reports Error, retains adapter for retry and keeps the guard. Same Windows/Mac shared C# behavior. |
| Q27-F237: wrong DROP/lost gates | DROP was0x0001 (SNIFF) rather than0x0002. Correct pinned API contract. Checked close retains failed handles; retired generations remain tracked across replacement. Delete journal/release owner only after every gate closes successfully. |
| Q27-F238: driver lifecycle | WinDivert closed before join and ignored false join/close errors; Wintun marked disposed before successful interop close. Now WinDivert Shutdown(BOTH) → shared2-second join budget → synchronized close, retaining resources after timeout/error. Serialize Open/Dispose and roll back partial Open. Wintun retry retains exact handle/identity. |
| Q27-F239: worker/observer faults | Direct log callbacks could abort Open/packet threads. Isolate observers; worker exceptions complete packet channels and a failed generation cannot become tunnel-up again. Actual managed capture worker with injected receive fault tested, without native driver open. |

DROP/SNIFF, shutdown BOTH=3, network layer, queue/checksum constants and80-byte layout
were checked against the [official WinDivert2.2.2 header](https://github.com/basil00/WinDivert/blob/v2.2.2/include/windivert.h).
F237 follows from source/API: SNIFF was passed instead of kernel DROP; no real VM
transit was measured. Shutdown/queue EOF contract:
[WinDivert documentation](https://reqrypt.org/windivert-doc.html#divert_shutdown).
Repeated loads increment process reference counts:
[Microsoft LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw).

Rust Wintun review: independent adapter/session, packet release before Arc session
Drop, EndSession before CloseAdapter, TunWorkers retains workers through join. Rust/native
source digest and14 artifacts unchanged; prior Q22/Q25 execution scopes retained.
No new native A/B/Linux/JNI/benchmark/soak series is needed or claimed.

## Checks and limits

- **325/325 Windows +549/549 shared PASS**,0 FAIL/SKIP; Release Windows/shared/Mac
  builds:0 warnings/errors. Mac compile-only. All four current Shared DLLs byte-equal.
- Production lifecycle with actual managed threads: start faults, pending workers,
  shutdown/close errors, combined Open/rollback failure, retry/exact handle, receive
  exception, blocked packet channel and rejected reactivation. Fake driver handles
  test ownership protocol, not functioning Windows drivers.
- Real DLL load/export (including WinDivertShutdown), bounded streams,32 concurrent
  module ensures, Wintun collisions/readiness/interop close retry, retained gates and
  journal ordering. DLL probes use normal extraction cache; user profiles/settings/
  service storage and OS networking are unchanged.
- **12/12 expected baseline FAIL**,exit1: original Dispose/CloseTransports bodies
  with injected dependencies, private8 MiB cache allocation, original loader/Open/
  gate decisions. The latter are adapted fault models, not old kernel-path execution.
  Old false join reproduced with an actual managed thread.
- Both Wintun copies passed version/hash/AuthentiCode signer/thumbprint/license;
  WinDivert64.sys Authenticode Valid with thumbprint recorded in raw. This does not
  certify live driver installation/compatibility. PowerShell5 lacked Get-FileHash;
  available PowerShell7.6.5 retry passed, initial failure retained. ExecutionPolicy
  Bypass was child-process-only; system policy unchanged.
- Docs/panel/generated bindings/native provenance/14 checksums/diff PASS.

Deadline covers join, not forced interruption of native Shutdown/Close, Wintun
CreateAdapter, SCM/RPC or OS I/O/locks. Failure requires Stop retry or agreed manual
recovery; successful fake close is not OS cleanup proof. WintunCloseAdapter is void:
observable interop exceptions are retained, not all internal driver errors detected.
Cached embedded bytes/module references live until process exit. Resource SHA does
not attest an already-running foreign service process. Administrator mutation of
protected files/direct uncoordinated storage writes is unsupported. INI configs,
internal JSON API/DTO retained.

Evidence: `release/certification/evidence/q27-windows-final-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-drivers-20261005-r2` (final); initial raw retained separately in the shared workspace.
Human WIP preserved; no installed service/driver open/lab/push/deploy operations.

Pending retirement retries the old close before another native Open and refuses on failure. Retained generations remain bounded; refinement tested separately, initial324 PASS and seal retained.
