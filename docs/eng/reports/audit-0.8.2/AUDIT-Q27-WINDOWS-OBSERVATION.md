# Q27: service registration, status and logs — stage PASS

5 October 2026. Base `741efcb5`; Windows, .NET SDK 10.0.300.
Full Q27 remains **IN_PROGRESS**: **26/37 DONE/PASS (70.3%)**, 11 sections left.

<!-- normative-sync: audit-q27-windows-observation-v1 -->

## Fixes

| Finding | Behavior and change |
|---|---|
| Q27-F229: install-only trust | Start and Apply of an existing service bypassed protected-location validation; Install accepted ERROR_SERVICE_EXISTS unchecked. Now validate the exact quoted current EXE + --service, LocalSystem, separate noninteractive process, service owner/DACL and actual executable/ancestor ACL/owner/reparse before arming intent/starting or changing a profile. Query/trust errors refuse before profile/intent mutation. Stop/Uninstall remain available for recovery. |
| Q27-F230: misleading observation | SCM query failure became Disconnected, numeric Enum.TryParse accepted undefined values, stale Connected remained current. The observer distinguishes pending/unknown and checks Running snapshot freshness (10 seconds, 5 seconds future tolerance), clears traffic on unknown. Decode requires named enum, timestamp, nonnegative counters and ≤2048 detail. Stopped retains terminal Error including incomplete cleanup. Changed Extra updates the GUI without repeating a toast. Installed-query failure prevents a competing GUI tunnel. |
| Q27-F231: log trust and budget | GUI read directly without storage ACL guard/limit; cursor=Length after EOF skipped concurrent append. Reader now uses the same private-storage guard, strict UTF-8 and a complete bounded snapshot ≤256 KiB. GUI replaces the bounded view instead of unbounded AppendText. Partial UTF-8 retries next poll; rotation/truncate+regrow do not trust an old cursor. |
| Q27-F232: oversized writer | Checking length before append let giant lines/crossing appends exceed 256 KiB. Lines are capped at 4096 UTF-16 chars without splitting surrogate pairs, marked truncated; rotate atomically before crossing the byte budget. Reset is atomic and serialized with append within the process. |

Start preserves both the primary failure and failed intent rollback in AggregateException.
Best-effort status/log writing can lose diagnostics on I/O failure; it is not a network
recovery journal. Complete bounded log reads cost at most 256 KiB per one-second poll;
GUI does not promise history preceding rotation. Read failures preserve the last bounded view.

SCM reads use CONNECT, QUERY_CONFIG and READ_CONTROL without write rights. Native
queries/marshalling passed real read-only EventLog and missing-GUID probes; no service
was installed, started or stopped. Contract and 8 KiB maximum buffer:
[Microsoft QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
[QUERY_SERVICE_CONFIGW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw).
QueryServiceConfig describes the next launch configuration, not attestation of a
currently running process. Service-object mutation rights are distinct from filesystem
rights; an unsafe Allow refuses conservatively despite a Deny. Foreign/unsafe registration
is not silently rewritten: disable and reinstall from the protected installed Qeli copy.

## Validation

- **273/273 Windows selftest PASS**, 49 new assertions beyond 224, 0 FAIL/SKIP.
- Production validators/controller/observer and private temp file writer/reader:
  foreign/unquoted/extra-argument command, wrong account/type, filesystem refusal,
  service owner/null DACL/config-write/delete/DACL/owner/generic rights, refusal before
  mutations; real read-only SCM success/absence and unmanaged marshalling.
- Fresh/stale/future/missing/numeric status, negative counters, invalid UTF-8,
  cleanup error after SCM Stopped, pending states and changed error detail.
- Giant Unicode, surrogate boundary, before-overflow rotation, oversized legacy,
  hostile bounded read, append at EOF, partial UTF-8 retry, actual open reader retains
  its old generation across atomic replacement; only GUID temporary files.
- **7/7 expected baseline FAIL**, exit 1: original writer/poll/tail decisions and
  original coordinator with injected dependencies. No native SCM mutation/ProgramData.
  Old tail reproduces skipped append at EOF; old status had no timestamp check and
  the supplied snapshot is stale Connected.
- Release Windows/shared/Mac builds: 0 warnings/errors. **543/543 shared PASS**,
  0 FAIL/SKIP. Mac compile-only. All four current Shared DLLs byte-equal; new Git SHA
  changes InformationalVersion, so the current artifact was tested again.
- RU/EN docs, panel, generated bindings, native provenance, 14 native checksum rows
  and diff PASS. Rust/native inputs unchanged; no new A/B build required.
- Initial harness string-escaping compile errors and subsequent warning retained in
  raw; final builds have zero errors/warnings.

Evidence: `release/certification/evidence/q27-windows-observation-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-observation-20261005` in the shared workspace.

Remaining Q27: final native loader/driver adapter review and available-criteria
reconciliation. Recovery entrypoint reviewed: service refuses startup after failed
kill-switch sweep; SCM Stopped does not prove complete route/DNS/firewall cleanup.
Observer retains a published error but cannot guarantee status delivery on disk fault.
Windows VM network/boot/sleep runtime is **user SKIPPED**, not PASS. GUI clicks and
real SCM registration/reload are not inferred from adapter tests. No installed
services/tasks/native binaries/lab changes. INI configs, internal JSON DTO/storage
retained. No push/deploy.
