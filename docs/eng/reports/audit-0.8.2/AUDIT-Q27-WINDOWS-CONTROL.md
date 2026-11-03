# Q27: service transitions, SCM, autostart and settings — stage PASS

5 October 2026. Base `9b6050ca`; Windows, .NET SDK 10.0.300.
Full Q27 remains **IN_PROGRESS**. Plan: **26/37 (70.3%)**, 11 sections remaining.

<!-- normative-sync: audit-q27-windows-control-v1 -->

## Findings and fixes

| Finding | Confirmed behavior and change |
|---|---|
| Q27-F225: stale profile and lost intent | GUI did SaveProfile → Start; a running worker kept its old tunnel and ordinary Settings Save connected an idle VPN. ServiceProfileTransition validates a DPAPI snapshot before stop, compares stored profiles, stops a changed generation and publishes only after success. Reconnection follows prior intent or explicit enable. An unchanged idle profile stays disconnected. |
| Q27-F226: Stop without confirmation | StartPending/StopPending with CanStop=false returned normally. Stop now waits for transitions within one 20-second budget, verifies Stopped and refuses unsupported states, timeout or concurrent restart after wait. This confirms SCM state, not actual VM network cleanup. |
| Q27-F227: silent scheduler and pipe deadlock | Enable/Disable ignored nonzero exit; Run hid launch errors and read stdout/stderr sequentially without a deadline. Errors now propagate, both pipes drain concurrently, each diagnostic prefix is capped at 4096 characters and the process budget is 10 seconds. Timeout kills the owned process tree; launch errors keep their original type. |
| Q27-F228: settings before durable write | OnSave changed AppSettings.Current before saving; failure left unpersisted live values and escaped as an unhandled UI exception. It now edits a Snapshot and reports write errors without publishing the singleton. External operations follow durable preferences and report their failures separately. |

GUI service/scheduler transitions run off the dispatcher with duplicate-operation and
Settings guards. Moving from GUI tunnel mode calls Stop irrespective of displayed
status, covering retained Error/reconnect generations. Editing the stored service
profile applies that stable Id instead of a different profile from stale preferences;
the logging snapshot does not mutate the original GUI profile. Deleting an installed
service profile is blocked until disabling the service or choosing another profile,
including idle mode. Editing unrelated profiles does not switch the service.

An absent scheduler task permits idempotent disable. COM GetTask checks the exact named
task; only HRESULT `0x80070002` means absence and other errors propagate. On this host
.NET maps it to FileNotFoundException: the first test exposed an overly narrow
COMException catch, corrected and verified with a real read-only GUID probe. Contract:
[Microsoft GetTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-gettask),
[Microsoft scheduler errors](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants).
Preferences remain desired state after an external failure, show the error and retry
on the next Save. There is no cross-system transaction spanning preferences, SCM and
Task Scheduler. A child-command deadline does not promise forced interruption of
COM/RPC, filesystem I/O or CreateProcess itself.

## Checks

- **224/224 Windows selftests PASS**, 0 FAIL/SKIP: **40 new assertions** over 184.
  Production coordinator, real DPAPI snapshots and stateful service/SCM adapters;
  changed/unchanged/live/idle/first install/explicit enable/disable, stop/publish/install/
  start/read failures, malformed previous payload, stable Id and snapshot isolation.
- SCM fake transitions: Stopped/Running/Paused/StartPending/StopPending, cannot-stop,
  timeout and restart after wait. No installed service is controlled by these tests.
- Real private PowerShell child: 128 KiB per stdout/stderr, bounded diagnostics and
  exit 7; stalled child with 400 ms deadline and actual owned-PID termination check;
  missing EXE preserves the Win32 launch error.
- Real atomic settings write in a GUID temp directory: blocked replacement keeps exact
  previous bytes and the original live settings object.
- Baseline: **8/8 expected FAIL**, exit 1. Old bodies are adapted only for service/SCM/
  scheduler dependencies and supplied settings. The real old sequential pipe reader
  deadlocked on its own child; after 1500 ms the harness killed only that child and
  observed its task. No APPDATA/ProgramData/SCM/task mutations.
- Release Windows build: 0 warnings/errors. Initial ambiguous TimeoutException compile
  error and first FileNotFoundException selftest failure remain in raw evidence.
- **543/543 fresh shared conformance PASS**, mandatory fixtures, 0 FAIL/SKIP;
  fresh Release shared/Mac builds have 0 warnings/errors. Mac is compile-only on Windows.
  Shared production inputs are unchanged, but DLL metadata changed after the previous
  commit (InformationalVersion includes its new Git SHA). Conformance was therefore
  rerun; all four current Shared DLL copies match. No exact byte identity with the old
  DLL is claimed. Rust/native inputs and all 14 artifact checksum rows unchanged.
- RU/EN docs, panel, generated bindings, native provenance/checksums and diff checked.

Evidence: `release/certification/evidence/q27-windows-control-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-control-20261005` in the shared workspace.

## Remaining Q27

Next: trust of existing service registration and recovery/status/log/driver adapters,
then reconciliation of available Q27 criteria. GUI modal clicks and real SCM/profile
reload/Task Scheduler registration are not claimed by adapter tests. Windows VM
network/boot/sleep runtime remains **user SKIPPED**, not PASS. Working services/tasks/
native binaries/lab unchanged; no push/deploy. Configs stay INI; internal JSON DTO/storage
remains authorized.
