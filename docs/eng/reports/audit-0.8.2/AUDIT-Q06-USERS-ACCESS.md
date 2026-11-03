# Q06: users and access revocation — complete

Date: 3 October 2026. **Overall Q06: PASS; four batches complete.**

The fixes were tested on isolated Linux release `fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc`.
**Latest qualification is the fourth batch below: 387 Q06 checks.**
Configurations remain INI. JSON is only the service body of HTTP/control APIs.

## Confirmed defects and fixes

| ID | Defect | Result |
| --- | --- | --- |
| Q06-F001 | Scalar/array/null bodies cleared bandwidth/quota/expiry; wrong enabled/password/bandwidth types reported success. Wrong live bandwidth profile types selected all profiles. | Shared object check and strict field types before hashing, locks and writes. Malformed requests preserve exact previous users INI bytes. |
| Q06-F002 | Deleting a file override restored the inline user or previous group from server.conf. | Deletion of any entry also defined inline is rejected before mutation. Users can be disabled; inline definitions must be removed in server.conf. |
| Q06-F003 | Wrong route.gateway types silently removed the next hop. | Strict nullable string validation; missing/null/empty remain supported. |
| Q06-F004 | Delete, enabled=false through Edit and profile restrictions changed the database while existing TCP/UDP sessions kept working. | Successful SIGHUP applies current rights to open sessions through existing admission/kick/lease teardown. The sweep rechecks current rights, including sessions registered after the initial scan. |
| Q06-F005 | A second persist-command writer after panel bandwidth save replaced explicit burst_mbps with its CLI default. | The panel writes INI once; reload applies effective limit_mbps to existing sessions, including group inheritance. |

The baseline packet run reproduced six tunnels that kept working:
TCP and UDP × Edit disabled / Delete / profile restriction. Tests check both the
session list and ICMP through the client TUN. Private INPUT DROP prevents a false
success through the outer interface after TUN removal. The separate Disable endpoint
and quota/expiry have their own checks.

## Validation

- 119 real HTTP/API checks PASS: strict bodies/types, ACL arrays, u32 boundary, missing group,
  route/gateway families, inline/file precedence, fixed-address collisions,
  nullable clears, quota/expiry, password and limit preservation, share/QR.
- 57 checks PASS with real Linux TCP/UDP clients: 12 revocation scenarios,
  fixed IP, live group bandwidth 2 → 3 Mbps, expiry and seeded exhausted quota.
  Quota uses a private usage sidecar with a known counter, not a new gigabyte benchmark.
- 293 Q04 HTTP checks and 75 Q05 transaction checks PASS on the same new release.
- 2263 Linux unit tests PASS, 60 ignored; pinned full/minimal Clippy and rustfmt PASS;
  116 editor JS groups and panel checks PASS.
- Linux release matrix: 18 cases / 327 assertions PASS, host_restored=true.
  Fresh 100 TCP + 100 QUIC soak / 33 checks PASS; fresh desktop/Android native A/B,
  SHA256SUMS and provenance PASS. All four client libraries are byte-identical to Q04.

Users API confirms persistence and queued reload. It is not a synchronous receipt
of worker authentication readiness. The fixture waits for the user in read-only
worker control before initial authentication, keeping revoke tests separate from a
startup race and brute-force lockout. Historical fixture failures are retained separately
from canonical results.

## Boundaries after the first batch

Q06 remains open: UsersDb filesystem/lock/crash and concurrent writers,
current inline auth in worker control, live ACL/group restriction changes,
multiple devices and replacement of unsafe legacy fixtures. `test_user_reload.py`
and `test_l3_user_limits.py` were not run: they control shared services/fixed paths.
`burst_mbps` remains a legacy stored field; separate data-plane burst enforcement is unconfirmed.
No new benchmark or physical qualification is claimed. Mac, router and Windows VM were excluded by the user.

All new network tests use NET/mount/PID namespaces. Working qeli.service,
PID/start identity and binary were preserved; source and all compilation inputs are hashed.
[Plan](../../plans/FULL-SYSTEM-AUDIT.md#06-users-groups-and-provisioning).

Three legacy firewall/NAT rules appeared on desktop host `.10` during the native build;
raw evidence retains `host_restored=false`. Service PID/start and working executable
were unchanged. The origin is unattributed and no firewall restoration was performed.
This deviation is not reported as unchanged-network PASS; desktop proves A/B artifacts only.

[Final evidence](../../../../release/certification/evidence/q06-users-access-20261003.json).

## Second batch: INI storage and inline auth after SIGHUP

**PASS; overall Q06 remains IN_PROGRESS.** New release `dda3c71f6c51e356d3a123f853f64073570ac17ac9c1a21b805f79141ef91e78`.

**Q06-F006:** SIGHUP installed the new user database, but four persistent control
commands merged users.conf with startup inline users/groups. The real baseline
resurrected a removed inline account through enable-user and failed to disable
an account introduced after reload. The fix retains the last accepted auth
configuration and holds its read lease through the INI transaction and live user
update. Reload replaces auth and users under the same lock order. enable-user,
disable-user, set-limit and set-bandwidth are covered by a regression test.

- New users-storage: 23 checks PASS. Eight concurrent creates lose no accounts;
  disjoint edits of one account preserve both fields. Corrupt INI (unknown key,
  invalid number, invalid UTF-8), read-only storage and rename refusal preserve
  exact bytes; normal saving recovers afterwards.
- API 119 and TCP/UDP live 57 reran successfully on this release: 199 Q06 checks.
- 2264 Linux units, 60 ignored; full/minimal Clippy and rustfmt PASS. Fresh 18/327
  release matrix and 100 TCP + 100 QUIC / 33 soak PASS.
- Fresh native A/B and ABI/provenance PASS; library bytes unchanged. .11 retained network and service. Desktop raw host_restored=false: the first
  default iptables-save dump differs from later ones, while explicit legacy/nft
  dumps and all other inventory fields agree. Read-only repetitions reproduce
  the inconsistent default dump; newly added rules are not established in this
  run. The earlier .10 deviation remains unattributed.

Storage coverage is still partial: ENOSPC/EACCES, lock timeout, crash/durability
and errors after published writes remain. Live ACL/groups, multiple devices and
legacy burst remain as well. These checks do not close Q06.
[Second batch evidence](../../../../release/certification/evidence/q06-users-storage-20261003.json).

## Third batch: live permissions and INI publication failures

**PASS; overall Q06 remains IN_PROGRESS.** Release `25a052afd351324b9fc2924035aac7cb998155d54ff6865a19a6448b99367e5c`.

Five defects reproduced on the previous release: 12 failing live checks and two
storage failures. Corresponding cases now pass.

| ID | Defect | Fix |
| --- | --- | --- |
| Q06-F007 | Narrowed user/group ACL retained old session permissions. | Revoke sessions whose effective packet permissions change. Rule order/duplicates do not matter; own ACL overrides group. |
| Q06-F008 | Removed client_subnets retained source permission and iroute. | Admission-owned teardown releases old ingress, leases and routes. |
| Q06-F009 | Reduced max_sessions retained excess devices. | Keep newest devices per profile within effective cap; session-ID checks protect replacement sessions. |
| Q06-F010 | Held users lock stranded requests indefinitely. | Five-second FileLock contention budget before reading/publishing a candidate. |
| Q06-F011 | Rename plus directory fsync failure falsely reported change NOT applied. | Typed publication error; API/control read back INI. API requests worker reload and reports published/reload_requested while retaining ok=false. |

315 Q06 checks PASS: 72 storage/durability, 67 policy, 119 API and 57 live.
Real TCP/UDP packets cover ACL, delegated sources and three devices; lowering
user/group caps retains the newest. Equivalent ACL and group edits under an own
ACL preserve the session. All eight API mutation paths and four control writers
cover fsync failure, worker readback, actual ENOSPC/EACCES, recovery and crashes
before/after rename.

2265 Linux units PASS, 60 ignored; full/minimal Clippy and rustfmt PASS. Fresh
18/327 matrix, 100 TCP + 100 QUIC / 33 soak and 27 Q05 config-crash checks PASS.
Fresh native A/B, ABI and provenance; canonical and client-consumed libraries
updated. Both labs retained network, service PID/start and working binaries.
The earlier .10 firewall deviation remains historically unattributed.

Legacy test_user_reload.py/test_l3_user_limits.py now launch isolated batches
requiring binary/SHA/output and never stop shared services. The L3 driver checks
live metadata and caps without claiming throughput measurement. CONFIG/PANEL
describe burst_mbps as a stored compatibility field without separate enforcement;
the former CONFIG burst-allowance promise has been corrected.

Storage failures and concurrent writers are closed in Q06. Remaining: actual
bandwidth measurement, same-device/fixed-IP/profile admission lifecycle and
panel presentation of legacy burst. No new benchmark or physical qualification
is claimed.

[Third batch evidence](../../../../release/certification/evidence/q06-users-policy-durability-20261003.json).

## Fourth batch: admission, bandwidth and Q06 completion

**PASS; Q06 complete.** Final release `fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc`.

| ID | Confirmed defect | Fix |
| --- | --- | --- |
| Q06-F012 | Same-device/static-IP replacement and max_sessions eviction closed carriers without a terminal reason; automatic retries evicted the winner again. TCP and UDP duplicated admission logic. | Shared helper selects unique holders and oldest excess devices, delivers `session_superseded` while ownership remains valid, then releases routes, carriers and leases. Modern management clients stop retrying; one four-second budget covers the batch. Legacy peers without ACK are still revoked at deadline but may reconnect. |
| Q06-F013 | Panel zero own bandwidth ignored inherited group limits; legacy burst appeared to be active. | Display effective own/group cap and zero inheritance. Burst is explicitly read-only and unenforced; edit/save preserves its stored value. |
| Q06-F014 | Share password reset after rename/directory-fsync failure missed published INI readback and worker reload. | Ninth API writer uses shared published-write recovery after releasing DB lock; reissuing the share uses persisted credentials without another reset. |

Final release: **387 Q06 checks PASS** — admission 35, bandwidth 33,
durability 76, policy 67, API 119, live 57. TCP/UDP same-device, static IPv4,
cap=1, winner stability for ten seconds, lease release, two-profile scope,
selective revoke and all-profile deletion covered. An intermediate TCP-only fix
failed cap/UDP checks and was replaced by the shared helper. Admission fixtures
raise only their private pre-auth budget for rapid source-IP reuse; production
rate limits remain unchanged.

Actual iperf3 over TCP/UDP uses two parallel flows, three measured seconds after
one warmup second; upload/download have independent buckets. Group=2 yields
1.77–2.10 Mbps, own=1 yields 0.92–1.05; group=3 does not override own=1,
own=0 inherits 3 (2.80), and group=0 restores unlimited. Unlimited headroom
exceeds 5 Mbps; 0.4–1.35 cap tolerance serves this short functional measurement.
This verifies enforcement, not release performance. Stored legacy burst=99
is preserved without separate burst allowance.

2265 Linux units PASS / 60 ignored, full/minimal Clippy and rustfmt PASS;
118 JS groups and static panel PASS. Fresh 18 scenarios / 327 assertions,
aggregate leak and 100 TCP + 100 QUIC / 33 soak checks PASS on the exact release.
All four native cores passed fresh A/B, ABI/provenance and match the previous
batch byte-for-byte; client copies agree. RU/ENG CONFIG/PANEL and plan updated.
Shared services and deployed binaries were not replaced.

Full .11 network/service snapshots match. Desktop .10 SDK A/B passes, but its
default IPv4 firewall dump differs; repeated read-only snapshots also produced
default/legacy dump differences. Final SDK run preserves nft, explicit legacy,
other fields, service PID/start and deployed binary. Full .10 network-preservation
PASS is not claimed; the earlier firewall deviation remains unattributed and
rules were not removed/restored. This is an evidence limitation, not a confirmed
new Qeli defect. Completed debug binaries were losslessly archived with fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc
verification to free space. No physical qualification is claimed.

All five Q06 criteria are closed within accepted scope, with no remaining Q06
items. Q07 follows: archive and transaction checks for backup/restore/history.

[Final evidence](../../../../release/certification/evidence/q06-users-access-complete-20261003.json).
