# Q05: configuration transactions, live reload and restart

Date: 3 October 2026. Status: **PASS for the supported Linux Q05 contract**.

## Result

All five section 05 criteria are complete. Six real HTTP/systemd batches provide
**352 checks PASS** on exact release `8fa8590104ebbceecb78c09d7c146b3ee101719b53820d0d1a1bc3cff664b3b7`. Production Rust is unchanged.
Earlier Q05-F001–F008 fixes have unit regressions in Q04's full Linux run
(2261 PASS, 60 ignored). That run, the 18/327 release matrix, 100 TCP + 100 QUIC/33
soak and native A/B are explicitly reused against unchanged inputs/artifacts;
no fresh execution of those checks is claimed.

## Verified layers

| Batch | Checks | Verified behavior |
| --- | --- | --- |
| Form / INI / history | 75 | Exact shared revision; missing/stale revisions refused, secrets retained, INI 0600 and exact old-byte snapshots. Eight writers yield one success/seven conflicts. Snapshot ENOSPC/read-only, rename refusal and busy sidecar preserve INI; status remains responsive and retry succeeds. |
| Quick Start / hot reload / worker | 207 | Preview/apply/reapply for all ten modes; returned profile matches disk, credentials retained, no implicit restart. New password works immediately, old password/cookie refused; allowlist/trusted proxies apply live. Startup-only saves require full restart. Invalid INI/profile/host overlap preserves worker; successful restart changes worker PID while retaining supervisor/cookie. |
| Detached full restart faults | 15 | Private systemctl shim rejection appears in status; delayed revalidation prevents dispatch after a bad edit. Fifteen-second timeout reports uncertainty and terminates its own child. No actual host-manager calls in this batch. |
| SIGKILL / fsync | 27 | Test-only private-process preload pauses save before/after rename. SIGKILL leaves complete old/new INI and exact rollback snapshot; HTTP cannot report success. Directory fsync failure explicitly reports uncertain durability of the already published file; a fresh revision permits retry. |
| Non-root / EACCES | 17 | Actual UID 65534 panel, working private worker and network capabilities. Save retains ownership/0600. Inaccessible foreign-owned history and parent write refusal preserve INI; removing the fault restores writes. |
| Real systemd | 11 | Two full restarts of an owned transient unit replace supervisor PID, retain cookie, apply new listener and remove old listener. Invalid disk INI refuses restart. The temporary unit is stopped and collected. |

Review covers Form/INI/Quick Start/history, both restart handlers, common preflight,
sidecar leases, atomic publication and live_web reload. Existing units cover secret
masks, trusted sources, stale/external revisions, structure/startup validation, snapshot
freshness, private inodes, partial writes and uncertain directory sync. No unused
production helper was confirmed in these paths.

## Q05-F009: the legacy test managed a running service

`test_web_reload.py` stopped/restarted `qeli-server.service`, used fixed `/etc/qeli`,
`/root`, `/var/log/qeli` paths and the old `/opt/qeli-src/target/release/qeli` binary.
The unsafe scenario was not invoked. It is now a compatibility launcher for the
shared isolated Q05 runtime harness with required `--qeli`, `--sha256`, `--output`.
Missing arguments exit 2 before connecting; `--help` exits 0.

## Isolation, reproduction and boundaries

Shared wrapper: `scripts/audit_web_auth_lab.py`; five scenarios:
`scripts/audit_web_transactions.py`. After setting `QELI_LAB_PASS` in the environment:

```powershell
python scripts/audit_web_auth_lab.py --audit q05 --fixture scripts/audit_web_transactions.py --scenario runtime --qeli /absolute/private/release/qeli --sha256 FULL_SHA256 --output /unique/local/evidence
```

Actual manager E2E: `scripts/audit_web_full_restart_lab.py` with required `--qeli`,
`--sha256`, `--output`; it creates only an owned transient unit. Ordinary batches
use separate NET/mount/PID namespaces. Real systemd uses separate NET/mount namespaces
and an owned systemd cgroup, sharing the host PID namespace for manager-socket
credentials. Network, INI and session state remain private. Full host snapshots,
running `qeli.service` PID/start and working binary SHA match before/after every
batch; temporary unit collected. Running services were not replaced.

Initial capability syntax, inaccessible fixture paths, owner-repairable history modes
and manager-socket/PID-namespace incompatibility remain as fixture diagnostics.
Only final canonical results count as PASS.

SIGKILL does not qualify sudden power loss. SIGKILL before rename may leave a private
temporary inode; the test removes only its exact witnessed owned path after recording
evidence. Automatic crash cleanup is not claimed. Directory fsync failure does not
imply rollback. Filesystem/kernel I/O has no hard deadline from an async timer.
External root writers must follow the sidecar protocol; edits after final validation
are not magically transactional. These boundaries are documented in the
[manual](../../manuals/PANEL.md#server-config-writers-v1).

Archive backup/restore remains Q07; VPN users/revoke remain Q06. Physical qualification,
new benchmarks and the full audit are not claimed complete.
[Final evidence](../../../../release/certification/evidence/q05-transactions-20261003.json).
