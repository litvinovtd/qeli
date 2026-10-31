# Full Qeli audit: previous coverage and sequential test plan

> Previously withdrawn 0.8.2 development measurements and comparisons remain retained locally for audit; they are not reinstated as a release benchmark. New dated [Linux snapshots](../reports/LINUX-LAB-0.8.2-2026-10-17.md) and [N04 results](../reports/TUN-N04-0.8.2-2026-10-19.md) are included separately: each retains its measured ELF identity, method and applicability limits. They do not describe every platform or a later binary; engineering-check status alone is not a benchmark.

**Current result, 15 October: all 37/37 audit sections complete within agreed scope (100%). Q29 closed after explicit user acceptance of generic/null DnsResolver ENONET on the measured API34 image as a documented limitation; that FAIL is neither fixed nor relabelled PASS. [Q29 decision](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), [criteria](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q31/Q34 retain their previously qualified completion. Secure VPN, the system kill switch, D06 and physical platform limits are retained. Historical checkpoints below are not the current remaining work.**


**Historical snapshot on 3 October:** [audit debt](AUDIT-DEBT.md) is dispositioned: 14 DONE
and D06 ACCEPTED_LIMITATION by user decision. Full audit resumes; the 37 section
statuses below require criterion-based reconciliation, not automatic PASS.

**Completion workflow from 25 September:** [four batches and test-selection rules](AUDIT-DEBT.md)
replace full-suite repetition after every fix. The levels below remain section coverage
criteria; each small step needs no standalone report. New noncritical hypotheses wait
for the full audit; existing obligations remain.

<!-- normative-sync: full-system-audit-v278 -->

**15 October, Android policy:** the user rejected a separate DNS bypass mode; secure VpnService and the Android system kill switch are retained. [Decision and DNS scope](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md). Generic/null ENONET on the tested API34 is not claimed fixed. The cancelled mode is not new implementation debt; the total remains37/37 (100%).

**Historical checkpoint Q34,14 October,iOS:** finite-number MDM source fix, corrected export/validate roaming test and prepared signed simulator CI with effective Keychain entitlement checks.17 portable methods,32 native DTO requests and5 shell fixtures PASS; fresh Swift/Keychain/Apple CI NOT run. See [report](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md).

**Historical checkpoint Q34,14 October:** Unix service-key helper race fixed and reproduced by the old implementation;28 Windows/Linux checks PASS, daemon/self-test share Mac RENAME_EXCL. Apple/current hosted runtime unqualified; iOS failures and public source pin remain open. See [report](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md).


Inventory date: **22 September 2026**. Baseline: branch `dev`, commit
`fc6f4a5dc8df7f119f2d99a6b72b08916ae7a268`, development **0.8.2**.
The working tree was clean before this documentation. Previous panel and manual/NDP
fixes are committed. This inventory did not modify product code.

The objective is to audit every Qeli system for functional defects, trust-boundary errors,
races, resource/traffic leaks, platform inconsistencies, dead code and documentation drift.
This is an executable plan for a new cycle, not a claim that every system has passed.

## 1. Reconstructed audit history

Sources include this task, relevant tasks titled «аудит» and «ipv6», Qeli project memory,
saved reports, Git and current source structure. Historical notes can refer to removed
implementations. A remembered fix does not close its regression on the current commit.
These records do not establish an independent external cryptographic audit.

| Source | Period and recovered coverage | Evidence and limits |
|---|---|---|
| H01 | 10–12 June: crypto/KDF/replay, handshake/framing, auth/Argon2, users/sessions, Windows storage, DNS/kill switch and INI | [10 June](../archive/audits/AUDIT-2026-06-10.md), [11 June](../archive/audits/AUDIT-2026-06-11.md), [12 June](../archive/audits/AUDIT-2026-06-12.md); historical versions |
| H02 | 18 June–5 July: panel/CSRF, notification SSRF, DNS/DHCP, supervisor/control, NAT cleanup, obfs/WS/AWG and serializers | Qeli memory and [5 July summary](../../archive/audits/AUDIT-FIXES-2026-07-05.md); some historical suspicions were disproved |
| H03 | 11–12 July: hooks/restore/client-save trust boundaries, session teardown, quota/iroute, clients and backups | `project_qeli_audit_2026-07-11.md` memory record; historical fixes/build gates, not fresh E2E |
| H04 | 23–27 July: core/data plane, UDP auth/HOL, pool races, max_clients, NAT tags, routes, parsers, all clients and supply chain | Core/client audit memory from 24/25 July and [27 July summary](../../archive/audits/AUDIT-2026-07-27-FIXES.md); some platform checks were compile-only |
| H05 | 4 August: broad core/client/panel/script audit | `project_qeli_audit_2026-08-04.md`; historical candidate list, not a current defect register |
| H06 | August–September: IPv6/TAP/NetworkPlan/PMTU/DATA_FRAG, roaming/CONTROL_V2 and native/core parity | [IPv6 plan](IPV6-IMPLEMENTATION-PLAN.md), [roaming](ROAMING.md), [transport core](../reference/TRANSPORT-CORE.md), `docs/data/validation/ipv6_lab_matrix_dev.json`; evidence applicability to current SHA must be checked |
| H07 | 26 August–1 September: REALITY/H2 captures, detectability and throughput/CPU/RSS | [DPI](../reports/DPI-AUDIT.md), [comparative benchmark](../reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md); measurements are for 0.8.0, not 0.8.2 |
| H08 | 16 September: broad A01–A14 audit and fixes | Local `audit-vpn-20260916/AUDIT.md` and `FIX-VERIFICATION.md`; Rust/managed builds, probes and Linux tests, not physical platform E2E |
| H09 | 16–17 September: detailed panel/parser A01–A14 audit | Local `audit-panel-20260916/AUDIT.md`, `panel-fixes-20260917/RESULT.md`; Rust/JS probes, saves, ACL fields, secrets, drafts and INI round trips |
| H10 | 22 September: panel follow-up A15–A22 | Local `audit-panel-20260922/AUDIT.md`, `panel-fixes-20260922/RESULT.md`; restart/preflight, staged restore, share transaction, quoting/dev, notification INI; commit `a8c5050b` |
| H11 | 22 September: IPv6 manual/NDP and documentation | Local `ipv6-manual-20260922/RESULT.md`; commit `fc6f4a5d`; 632 portable Rust tests, 25 JS groups, 16 isolated runtime probes; no real Linux NDP/firewall E2E |

H08–H11 local reports are outside the repository; their names identify the working archive.
Secrets and infrastructure addresses are deliberately absent. **A01–A14 were reused in
separate audits:** every finding reference must include H08 or H09. Counts from different
feature/OS suites must not be added or compared as measures of coverage growth.

## 2. Rules for the new cycle

Each section has separate **historical coverage** and **new-run status**. New statuses:
`TODO`, `IN_PROGRESS`, `PASS`, `FAIL`, `BLOCKED`, `N/A`. `BLOCKED` requires a reason and
required environment; `N/A` requires proof of non-applicability. An unavailable runtime
is not a PASS. A fixed finding closes after verification; unresolved findings stay queued.

Every section follows the same levels:

1. **Structure:** inputs/outputs, state owners, dependencies, trust boundaries and callers;
   OS/feature gates, FFI/reflection/generated code and possible dead branches.
2. **Contract:** positive, boundary and malformed-input cases, defaults and semantic
   preservation; differential/round-trip checks with independent implementations.
3. **Failures:** inject acquire/apply/save failures, partial I/O, concurrency, deadlines,
   cancellation/crash/restart, and verify recovery by the resource owner.
4. **Integration:** real process/API/browser/TUN/firewall/OS adapter, then real devices
   wherever behavior depends on drivers, operating systems or mobile networks.
5. **Regression:** reproduce on the original defect, fix, rerun affected checks, update
   documentation and tie results to exact source SHA/features/target.

Each run records ID/date, commit plus dirty diff/hash, tool versions, OS/arch/features,
command, fixtures/seed, expected/actual results, stdout/stderr, exit code, captures/host
state when relevant, finding ID/severity and limitations. Separate hypotheses from
reproduced bugs; accepted risks need justification. Long runs need deadlines and a stop
procedure. Measure leaks instead of inferring them from UI status.

Before invoking an old lab/E2E script, inspect targets, hardcoded endpoints, cleanup,
credential handling and destructive defaults. A listed test is a **harness-review entry
point**, not proof that it is safe or covers all scenarios. Harness unit tests are not E2E.
Network/destructive scenarios use isolated snapshot-backed labs, not production.

## 3. Environments and mandatory matrix

| Environment | Purpose |
|---|---|
| Local portable | Parser/crypto/protocol/KAT, JS state, Python harness and docs; not Linux server runtime |
| Isolated Linux | Server/CLI/API/backup/systemd/TUN/routes/DNS/NAT/NDP; iptables and nft/firewalld, multiprofile and crash recovery |
| Windows VM | GUI/LocalSystem/Wintun/WinDivert/ACL/DPAPI and real networking/recovery |
| macOS Intel + ARM | launchd/utun/pf/Keychain/Network Extension/per-app; build and runtime separately |
| Android device | Release APK/JNI/VpnService, Wi-Fi/LTE/Doze/always-on/lockdown and sleep/wake |
| iOS device | Signed IPA/PacketTunnel/On Demand/NAT64/per-app/MDM; simulator separately |
| OpenWrt/Keenetic | MIPS/ARM and 32-bit ABI, init/UCI/LuCI, real networks and bounded memory |
| Load lab | Controlled bandwidth/RTT/jitter/loss/reorder/MTU, separate traffic generator and observer |

Derive **supported** transport × obfuscation combinations from source; Quick Start is
not the complete protocol capability list. Unsupported combinations must fail clearly,
not be counted as missing positive tests. For every supported mode: connect/auth,
upload/download, DNS, reconnect and stop/cleanup. Additional axes:

- outer IPv4/IPv6 × inner IPv4/IPv6/dual; IPv6-only uplink/NAT64;
- full/split, TUN/TAP, client-to-client/site-to-site/per-app;
- IPv6 `off/manual/route/nat66` × NDP `off/auto/required`, every transition;
- old/new server and client, incompatible ABI/capabilities, off/prefer/required;
- single/multiple profiles, sessions and paths, empty/exhausted pools;
- stop, timeout, revoke, crash, reload/restart, suspend/resume and network changes.

Execute security-critical combinations exhaustively. Other interactions may use explicit
pairwise coverage, not a claim to cover the whole Cartesian product. Leak checks require
tunnel and physical-interface captures; cleanup needs before/after routes/DNS/firewall/
sysctls/fds/tasks.

## 4. Stage 00 — baseline

**DONE: inventory and limited local checks.** This does not complete the product audit.
The next working section is **01: server INI**, followed by 02–07. Linux E2E for recent
administrative and IPv6 changes remains mandatory.

| Check on `fc6f4a5d` | Result | Limit |
|---|---|---|
| `check_panel.py` | PASS: 11 templates, 1142 RU strings | Static |
| `test_panel_editors.cjs` | PASS: 25 groups | Actual JS components in Node, not browser E2E |
| `unittest discover -s scripts -p 'test_native_*.py'` | PASS: 67 tests | Tooling/contracts, not native core rebuilds |
| `sync_version.py` | PASS: dev/planned 0.8.2, released 0.8.1 | Version consistency |
| `native-libs/provenance.py --check` | **FAIL: STALE NATIVE CORES** | Recorded and current source digests differ |
| `release_certification.py --quiet` | **FAIL: manifest missing** | No `release/certification/0.8.2.json` |

**B00-01:** recorded native digest `85f2f17ed9f58e7ad8d0368b936542f2391961bf0a739c7985a93208d6a1cb80`,
actual `3deb3da9d8306e0eaf4fd3d3505a7ad8f4e822b7bd502e8e748f632a852baa52`.
Packaged cores do not validate current Rust. Close in 22/34 through rebuild and provenance
verification; merely updating recorded digests is insufficient.

**B00-02:** a missing manifest does not prove a runtime defect, but means 0.8.2 release
readiness lacks complete evidence. Close in 34 using real matrix results, never a formal
manifest with unexecuted scenarios marked passed.

## 5. Module register: previous audits and the new pass

The following is the complete reconstructed list in execution order. H references point
to section 1 and denote historical review/tests, not current PASS. Cross-cutting work in
35–37 also applies to every section in 01–34.

| ID | Module | Historical checks | New pass |
|---|---|---|---|
| 01 | Server INI and schema | H01, H04, H08–H10 | PASS |
| 02 | Client parsers and qeli:// | H04, H06, H08–H10 | PASS |
| 03 | Panel UI and state | H02, H09–H11 | PASS |
| 04 | Web auth and API protection | H01–H03, H08–H09 | PASS |
| 05 | Config transactions and restart | H08–H10 | PASS |
| 06 | Users, groups and provisioning | H01, H04, H09–H10 | PASS |
| 07 | Backup, restore and history | H03–H04, H08, H10 | PASS |
| 08 | Cryptography, identity and keys | H01, H04, H08 | DONE |
| 09 | Handshake and TCP/UDP pre-auth | H01, H04, H08 | DONE |
| 10 | PacketCodec, replay and control framing | H01, H04, H08 | DONE |
| 11 | REALITY, TLS 1.3 and HTTP/2 | H07–H08 | DONE |
| 12 | Transports and wire camouflage | H02, H07–H08 | PASS |
| 13 | Recordizer, padding and shaping | H02, H07–H08 | PASS |
| 14 | Supervisor, workers and profiles | H02–H03, H08 | PASS |
| 15 | Sessions, IP pools and limits | H01, H03–H04, H08 | PASS |
| 16 | ACL, pushed routes and site-to-site | H03–H04, H06 | PASS |
| 17 | IPv4 NAT, forwarding and sysctls | H02, H04, H08 | PASS |
| 18 | IPv6 off/manual/route/nat66 and NDP | H06, H11 | PASS |
| 19 | Server and client DNS | H01–H02, H05–H06 | PASS |
| 20 | DHCP and lease lifecycle | H02, H05 | PASS |
| 21 | TUN/TAP, IP, MTU/PMTU and fragmentation | H06, H08 | DONE/PASS |
| 22 | Transport core, FFI/JNI and memory | H06, H08 | DONE/PASS |
| 23 | Roaming, resume and CONTROL_V2 | H06, H08 | DONE/PASS |
| 24 | Multipath, bonding and shared budgets | H04, H06, H08 | DONE/PASS |
| 25 | Linux CLI and network recovery | H01, H04, H08 | DONE / PASS |
| 26 | Shared C# and managed/native boundary | H04, H06, H08 | DONE/PASS |
| 27 | Windows GUI, service and drivers | H01, H04, H08 | DONE / PASS |
| 28 | macOS daemon, utun, pf and Network Extension | H04, H08 | DONE/PASS |
| 29 | Android VpnService, JNI and lifecycle | H04, H06, H08 | DONE / ACCEPTED_LIMITATION |
| 30 | iOS PacketTunnel, Swift and MDM | H04, H06, H08 | DONE: SOURCE REVIEW; Apple USER_SKIPPED |
| 31 | OpenWrt, LuCI and Keenetic | H04, H06, H08 | DONE/PASS |
| 32 | Metrics, usage, logs and notifications | H02–H03, H08, H10 | DONE |
| 33 | Installation, updates, file permissions and hooks | H01, H04, H08 | DONE |
| 34 | CI, dependencies, native provenance and release | H04, H06, H08 | DONE/PASS |
| 35 | Fuzzing, concurrency, DoS and soak | H04, H06, H08 | DONE/PASS |
| 36 | Benchmarks and measurement methodology | H07 | DONE |
| 37 | Documentation, test harnesses and dead code | H06, H08–H09, H11 | DONE |

Table reconciled against section21–23,26,28 completion and open29–31,35–36 statuses
on11October. Earlier checkpoint totals below remain historical.

## 6. Scenarios for each section

Order: 01 → 37. If a check needs an unavailable environment, mark only that part BLOCKED;
continue independent analysis of the next section while keeping the blocker queued.
Section PASS requires every mandatory level from section 2.

### 01. Server INI and schema

**Source:** `qeli/src/config`.

Trace every key through parse → validate → runtime → serialize; defaults, ranges, duplicates, unknown keys, quotes/TAB/Unicode. Reject invalid input before writing. Configuration is INI-only; internal JSON API remains.

**Existing harness/fixtures:** `qeli/tests/config_examples.rs`.

- [x] Review and dead code: strict entry points, serde/function-pointer/OS consumers, documented inactive fields; 3 October.
- [x] Parser positive, boundary and negative scenarios: 12 new regressions and the existing suite.
- [x] Failures/concurrency: D07/Q25-F209, 201 unit, 4 privileged and 44 runtime checks.
- [x] Linux integration: check-config/startup/SIGHUP/HTTP save/Quick Start, Q25-F209; final D15 candidate.
- [x] First-pass fixes, retesting and evidence (Q01-F001–F007).

**Status: PASS.**

**First pass, 2026-09-22:** [Q01 report](../reports/audit-0.8.2/AUDIT-Q01-SERVER-INI.md).
Fixed 6 INI processing defects and a fixture coverage gap. 651 portable Rust tests,
25 JS groups and the Linux all-targets check passed. Fixture coverage checks 163 key
names and 3 dynamic families. Diagnostic isolation was exercised across 32 parses.

**3 October reconciliation:** field tracing is covered by [global keys](../reports/audit-0.8.2/AUDIT-Q25-SERVER-GLOBAL-FIELDS.md),
[profile foundation](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md) and [obf](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-OBF.md).
D07/Q25-F209 covers failures/concurrency and Linux save/reload/import; D15 verifies
all 288 Rust hashes unchanged and validates the final release. The no-Linux blocker
is obsolete. [Applicability evidence](../../../release/certification/evidence/q01-reconciliation-20261003.json)
retains the original debug SHA/limits; it does not claim a new run of those 44 checks.
**3 October completion:** targeted review found no new confirmed defects; fixture check rerun. All five section 01 criteria are closed. PASS covers server schema and configuration paths, not networking implementations in later sections.

### 02. Client parsers and qeli://

**Source:** `qeli/src/config/client.rs`, `qeli/src/config/share.rs`, `conformance`.

Verify the current 81-key Rust/C#/Kotlin/Swift contract; INI ↔ forms ↔ URI, foreign fields and secrets. Test malformed pins/ports/IPv6/MTU and prohibit silent fallback to TOFU.

**Existing harness/fixtures:** `scripts/test_native_config_keys.py`.

- [x] Review and dead code: INI/editor/URI callers, projections, C ABI/JNI; 3 October.
- [x] Positive, boundary and negative scenarios: 81 keys / 84 fields, shared URI/INI corpus, prior regressions and fresh DLL audit.
- [x] Failures and concurrency: bounds, preserved errors, 1000 drafts, 128 parallel scenarios; D08 storage coordination.
- [x] Available integration: packaged C ABI, D08 C#/JVM/Android emulator, D15 native A/B; Apple/physical SKIP by user decision.
- [x] Q02-F001–F019, D08/D15 and unchanged-input verification; evidence retains original scope.

**Status: PASS within the agreed scope; Apple/physical SKIP.**

**URI pass, 2026-09-22:** [Q02 report](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md).
Fixed Q02-F001–F006: ambiguous query parameters, scalar/UTF-8/default behavior and skipped
JVM corpus reruns. 651 Rust tests, 438 C# checks and 137 JVM tests passed.
Shared corpus: 21 valid + 29 reject; the 81-key-name contract is preserved.

**Current state, 3 October:** targeted INI/editor review is complete with no new confirmed defects. D08 already exercised available models/stores and the Android emulator; D15 refreshed release native A/B and provenance. Apple and unavailable physical environments were excluded by the user, not given runtime PASS. [Reconciliation](../../../release/certification/evidence/q02-reconciliation-20261003.json): 81 keys, 84 editor fields, 164 adapter + 288 Rust hashes match; six static tests and projection generation passed. Existing runtime results are not claimed as new executions.
**User's architecture proposal:** [shared configuration module](CLIENT-CONFIG-CORE.md)
inside the existing Rust core is implemented in source (ABI 1.16). Local parsers are removed; generated projections/defaults and shared routing/reconnect/version/route-file policies are active. Release A/B is covered by D15; Apple runtime was excluded by the user.

**22 September continuation — configuration boundaries:** eight reproduced INI/URI
scenarios (Q02-F007–F014) were fixed in the core: character/DNS-error loss, invalid overlay names, BOM
validation bypass, secret redaction and misplaced `logging.*` fields. Regressions exercise
client model save paths; details and results are in the
[shared configuration report](CLIENT-CONFIG-CORE.md#configuration-boundary-audit--22-september-2026).
This does not close the full section: Linux E2E and target-device checks remain open.

**Parameters before runtime, 2026-09-22:** Q02-F015–F019 close malformed zero PIN,
invalid host, unsupplied-port repair, old panel validation and automatic dev-insertion defects. Regressions and positive compatibility
cases are recorded in the [Q02 register](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md).

**Runtime follow-up, 2026-09-22:** the same plan records the shared retry-budget/delay policy,
monotonic established-session timing, finite-limit and offline-recovery fixes, and interruptible
Linux backoff. Rust/C ABI/JNI regressions and Linux cross-Clippy passed. This does not close
real-device/network-change, Apple runtime or release-library gates.

**3 October completion:** fresh packaged DLL audit (`653522e6…`), eight groups:
84 explicit field values in runtime text, 21 valid + 29 reject URIs, 15 INI boundaries,
1000 seeded drafts, unrelated edits preserving errors, bounds and 128 parallel
isolation/redaction scenarios. D08 C#/JVM/Android results are reused only after matching
164 adapter + 288 Rust hashes, not claimed as new platform runs. [Result](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md#section-completion--3-october-2026).
PASS covers the configuration contract; OS-parameter effects and actual networking
belong to their platform sections. Apple build/runtime is not claimed.

### 03. Panel UI and state

**Source:** `qeli/src/web/templates`, `qeli/src/web/assets`, `qeli/src/web/pages`.

Loading/error/retry, dirty state, delayed replies, concurrent edits, Form/INI, deletion, secret masks, dates and quotas. Real browser: every page, RU/EN, keyboard and mobile layout; failures must not save defaults.

**Existing harness/fixtures:** `scripts/check_panel.py`, `scripts/test_panel_editors.cjs`.

- [x] Review and dead code: all 11 templates / 10 page wrappers; common Form/INI lifecycle and Rust defaults/Quick Start.
- [x] Positive, boundary and negative scenarios: 116 actual JS groups; secrets, dates, quotas, revisions and Form/INI.
- [x] Failures and concurrency: all-page error/retry, stale replies, modal/draft ownership, duplicate submission, destroy and cancellation.
- [x] Available integration: every page in Edge RU/EN, desktop/mobile and keyboard; shared focus and native beforeunload. API fixtures qualify UI, not backend protection/persistence.
- [x] Q03-F001–F015 fixed/retested; baseline reproductions, raw logs/captures, fresh release matrix and same-artifact soak.

**Status: PASS for panel UI/state.**

**3 October completion:** [Detailed report](../reports/audit-0.8.2/AUDIT-Q03-PANEL-STATE.md) and [final evidence](../../../release/certification/evidence/q03-config-20261003.json). Final batch: 26 new JS groups (116 total), four Config Edge scenarios, reviewed draft/revision, single write, identity/hash/history/remove ownership, Cancel/Tab/Shift+Tab/Escape/focus return and dirty navigation. Fresh release: 18 isolated cases / 327 checks, aggregate leak and 100 TCP + 100 QUIC / 33 checks PASS. Unchanged Rust/native/budget evidence is explicit reuse. User live-users WIP is preserved separately; physical qualification and new benchmarks are not claimed. Q04/Q05/Q07 retain backend auth, transaction and restore obligations.

### 04. Web auth and API protection

**Source:** `qeli/src/web/auth.rs`, `qeli/src/web/mod.rs`, `qeli/src/web/api`.

Inventory routes/guards, Basic/cookie/TOTP, logout/expiry, CSRF, reverse proxies, base_path and allowed_ips. Test concurrent Argon2 budgets/rate limits. Unauthorized requests reveal no secrets and cause no side effects.

**Existing harness/fixtures:** `scripts/check_panel.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: PASS.**

**3 October, completion:** all five Q04 criteria complete for authentication/API boundaries. 2261 Linux units, 116 actual JS groups, 293 real HTTP checks and pinned full/minimal Clippy PASS. Release matrix 18/327 and 100 TCP + 100 QUIC/33 soak PASS; HTTP/matrix reused only after byte-identical release SHA verification. Fresh desktop/Android native A/B and provenance PASS. Web TOTP absent; positive transactions/restore remain Q05/Q07. [Report](../reports/audit-0.8.2/AUDIT-Q04-WEB-AUTH.md), [evidence](../../../release/certification/evidence/q04-web-auth-20261003.json).

### 05. Config transactions and restart

**Source:** `qeli/src/web/api/config.rs`, `qeli/src/web/api/control.rs`, `qeli/src/server/preflight.rs`, `qeli/src/util.rs`.

Common validation/preflight for Form/INI/API/history/Quick Start/worker/full restart. Test stale revisions, concurrent writers, ENOSPC/EACCES and snapshot/rename/restart crashes. Failed preflight preserves the running service and valid configuration.

**Existing harness/fixtures:** `scripts/test_web_reload.py`, `scripts/test_panel_editors.cjs`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: PASS.**

**3 October completion:** 6 batches / 352 actual HTTP/systemd checks PASS: Form/INI/history, 8 concurrent writers, all 10 Quick Start modes, live password/allowlist, worker replacement, detached restart failures, ENOSPC/read-only/EACCES, SIGKILL before/after rename and fsync uncertainty; actual full restart of an owned transient unit. Q05-F009 replaces the live-service test with an isolated launcher. Unchanged Linux 2261 / Clippy / native / matrix / soak explicitly reused; all 322 compilation inputs match. Power loss and uncoordinated external root writes are not certified; backup/restore remains Q07. [Report](../reports/audit-0.8.2/AUDIT-Q05-HTTP-TRANSACTIONS.md), [evidence](../../../release/certification/evidence/q05-transactions-20261003.json).

### 06. Users, groups and provisioning

**Source:** `qeli/src/config/users.rs`, `qeli/src/web/api/users.rs`, `qeli/src/web/api/share.rs`, `qeli/src/web/api/identity.rs`.

Inline + users_file, duplicate precedence, missing groups, invalid types versus restriction removal, static addresses, quota/expiry. Identity failure must not change a password during link creation. Revoke applies to existing TCP/UDP sessions.

**Existing harness/fixtures:** `scripts/test_user_reload.py`, `scripts/test_l3_user_limits.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: PASS.**

**3 October, first batch:** five confirmed defects fixed in API, inline overrides, routes, live revoke and bandwidth writers. 119 API + 57 TCP/UDP checks PASS; fresh Linux units/lint and 293/75 HTTP regressions PASS. Q06 remains open for filesystem/concurrency and additional policies. [Report](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md).

**3 October, second batch:** Q06-F006 removes startup inline users/groups from control mutations after SIGHUP. 23 new storage/control checks, repeated 119 API + 57 live, 2264 Linux units and fresh release/native qualification PASS. Concurrency and read-only/rename/corrupt INI covered; crash/lock/final-fsync, ACL and devices remain open. [Report](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md#second-batch-ini-storage-and-inline-auth-after-sighup).

**3 October, third batch:** fixed live user/group ACL, delegated sources, reduced
device caps, unbounded lock waits and false refusal after INI publication.
315 Q06 checks (72 storage/durability, 67 policy, 119 API, 57 live) and 2265 Linux
units PASS. Real ENOSPC/EACCES, crashes before/after rename and API/control writers
covered. Destructive legacy drivers replaced by isolated batches. Storage faults
and concurrent writers are closed; overall Q06 remains IN_PROGRESS for bandwidth
measurement and remaining admission/access-issuance scenarios.
[Report](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md#third-batch-live-permissions-and-ini-publication-failures).

**3 October, complete:** Q06-F012–F014 fixed: shared TCP/UDP admission, terminal session replacement, effective bandwidth/legacy burst and share-reset recovery. 387 Q06 checks, 2265 Linux units / 60 ignored, 118 JS groups, fresh matrix 18/327 and soak 100 TCP + 100 QUIC/33 PASS. Native A/B matches byte-for-byte; .11 preserved, .10 SDK PASS with explicit firewall-snapshot limitation. No physical qualification claimed. [Final report](../reports/audit-0.8.2/AUDIT-Q06-USERS-ACCESS.md), [evidence](../../../release/certification/evidence/q06-users-access-complete-20261003.json).

### 07. Backup, restore and history

**Source:** `qeli/src/web/api/backup.rs`, `qeli/src/web/api/backup_listing.rs`, `qeli/src/web/api/config.rs` (history), `qeli/src/web/tls.rs`.

Fresh restore with custom paths, mixed user sources, identity and panel secret. Tar bombs, traversal, links, missing files, overlay/exact, staged compatibility and concurrent restore. Snapshots never recursively archive themselves; prove recovery after interrupted publication.

**Existing harness/fixtures:** `scripts/audit_web_auth_lab.py --audit q07 --scenario archives --fixture scripts/audit_web_transactions.py`; shared Q05 `basic` for history/config regression.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: PASS within the agreed available Linux/runtime scope.**

**History, 3 October, first batch:** HTTP reproduction found exact rejection with nested locks, missing identity/TLS validation and archive UID retention. Fixes and current qualification are recorded in the [Q07 report](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md). Overall Q07 remains open: crash/partial publication and recovery, filesystem faults, cross-process users/identity writers, mixed users/panel-secret, operational files/rotation and additional INI trust boundaries (historical list before batch two).

**History, 3 October, second batch:** Q07-F005–F013 cover strict exact, INI command trust, operational snapshots/rotation, old/new users/identity FileLocks, absent-directory lock inode, partial-publication metadata and failure instead of false exact success. 17 baseline checks FAIL; current 176 HTTP/system checks PASS. SIGKILL before/after first rename and manual tar recovery are verified. Mixed inline/external users, panel-secret and direct archive-restore prepare ENOSPC/read-only/HTTP cancellation remain. Overall Q07 is still IN_PROGRESS.

**3 October, Q07 completion:** Q07-F014–F015 fixed: extraction ENOSPC → HTTP 500; only actual FileLock timeout → 409. Mixed users/groups, real restored VPN clients, same/new-host panel-secret, legacy migration, actual archive preparation ENOSPC/read-only and HTTP cancellation pass. Final 226 HTTP/system checks, 2266 units, matrix 18/327, soak 33 and native A/B PASS. Seven-layer review completed; private staging on read-only storage and per-file publication are documented accepted limits. [Final report](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md). Next section: Q08.

### 08. Cryptography, identity and keys

**Source:** `qeli/src/crypto`, `qeli/src/server/reality.rs`, `qeli/src/web/api/identity.rs`.

X25519/ML-KEM/HKDF/AEAD KAT and negative vectors; static binding, proof before credentials, pin/TOFU, RNG, nonce exhaustion, rotation and zeroization. Key ownership/permissions/links/atomic writes. Unit tests do not replace independent cryptanalysis.

**Existing harness/fixtures:** `conformance/hkdf.json`, `conformance/prp-nonce.json`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE.**

**First Q08 batch:** Q08-F001–F003, shared bounded key reads, serialized legacy migration and low-order proof refusal. Previous release reproduces six filesystem failures; first-batch qualification is retained in the [report](../reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).

**3 October, Q08 complete:** Q08-F004–F007, independent NIST/RFC/AEAD/HKDF vectors, seven-area review,31 key/rotation +25 restore/state checks with actual pinned clients,2279 units, matrix18/327, soak33 and native A/B PASS. All mandatory fix checks closed. Accepted limits and conditional REALITY TLS PQ scope are recorded in the [final report](../reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md). Next Q09.

### 09. Handshake and TCP/UDP pre-auth

**Source:** `qeli/src/server/handler.rs`, `qeli/src/server/udp_handler.rs`, `qeli/src/protocol/capabilities.rs`, `qeli/src/client/mod.rs`.

Truncation/replay/reorder/slow peers and invalid PQ/proof/password. Permits before spawn, pending caps, anti-amplification, tarpit and cancellation/deadlines. One login must not block UDP reception; failures release resources without unauthorized downgrade.

**Existing harness/fixtures:** `qeli/fuzz/fuzz_targets/clienthello.rs`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE.**

**Server H2 and pre-auth, 23 September 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): the profile joins nested H2 tasks before
teardown; a rejection flush retains its pre-auth slot until I/O release. 13 new regressions,
969 Rust tests PASS. H2/ProfileTasks/semaphores were exercised on the host; production Linux
was cross-compiled only. Other section scenarios and live Linux E2E remain open.

**3 October, UDP AUTH/PMTU:** [Q09-F001/F002](../reports/audit-0.8.2/AUDIT-Q09-UDP-AUTH.md) fixed/retested: handshake reservation/cancellation/deadline and PMTU only after non-revoked AuthOK. 2283 units, 16 old/new UDP/QUIC + 35 admission checks and fresh matrix/soak/native PASS; Q09 overall remains IN_PROGRESS.

**3 October, TCP/parser:** [Q09-F003–F005](../reports/audit-0.8.2/AUDIT-Q09-TCP-PARSER.md): original AUTH deadline, AUTH OK rollback, strict complete ClientHello and JOIN. 2290 units, 8 real baseline/fixed TCP checks and 256-slot saturation, bounded ASan/libFuzzer, fresh matrix/soak/native PASS. UDP anti-amplification/replay/reordering and negative auth/capabilities contracts remain; Q09 overall IN_PROGRESS.

**3 October, UDP contracts:** [Q09-F006–F009](../reports/audit-0.8.2/AUDIT-Q09-UDP-CONTRACTS.md): publication/revocation, direction/bounds, reaper revalidation and admission/AuthOK deadline+rollback. 2294 units, 74 live UDP/QUIC +16 PMTU +35 admission, fresh matrix/soak/native PASS. Original failures and lab limits retained. Remaining: final review, forged client-proof/capability/contention cases and initial TCP terminal-loss investigation; Q09 IN_PROGRESS.

**3 October, Q09 completion:** [Q09-F010/F011 and final review](../reports/audit-0.8.2/AUDIT-Q09-FINAL.md): KICK survives EOF, pipeline drain and platform delivery errors.2301 units;8 live baseline/fixed +66 decrypted proof/capability/concurrent +35 admission checks;fresh18/327 matrix,100 TCP+100 QUIC/33 soak and four native A/B PASS. All required Q09 fix checks closed; evidence limits explicitly retained. Q10 is next.

### 10. PacketCodec, replay and control framing

**Source:** `qeli/src/protocol/packet.rs`, `qeli/src/protocol/ctrl.rs`, `qeli/src/protocol/control_v2.rs`.

Lengths 0/min/max/overflow, AEAD tags, sequences around 2^63/2^64, replay windows and unknown types/generations. Malformed packets must not panic/abort or allocate without bounds; valid traffic works after rejection.

**Existing harness/fixtures:** `conformance/packet-decode.json`, `conformance/replay-window.json`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE.**

**3 October,Q10 completed:** [PacketCodec/replay/CONTROL_V2](../reports/audit-0.8.2/AUDIT-Q10-CODEC-CONTROL.md): Q10-F001–F003,2307 units,two bounded ASan fuzz campaigns,fresh matrix/terminal/soak/native qualification PASS. Overall plan:10/37 DONE/PASS (27.0%). Next section:Q11.

### 11. REALITY, TLS 1.3 and HTTP/2

**Source:** `qeli/src/protocol/realtls`, `qeli/src/protocol/h2_carrier.rs`, `qeli/src/protocol/h2_carrier`.

Transcripts/replay/decoys and TLS key budgets. H2 zero/small windows, SETTINGS/WINDOW_UPDATE/GOAWAY/RST, partial I/O and backpressure. Stop/timeout releases tasks/sockets/permits. PCAP/active probing is separate from tunnel functionality.

**Existing harness/fixtures:** `qeli/src/protocol/h2_carrier/hardening_tests.rs`, `scripts/roaming_netns_e2e.sh`, `scripts/audit_realtls_wire.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE.**

**Server H2 and pre-auth, 23 September 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): the profile joins nested H2 tasks before
teardown; a rejection flush retains its pre-auth slot until I/O release. 13 new regressions,
969 Rust tests PASS. H2/ProfileTasks/semaphores were exercised on the host; production Linux
was cross-compiled only. Other section scenarios and live Linux E2E remain open.

**3 October, Q11 completion:** [REALITY/TLS/H2](../reports/audit-0.8.2/AUDIT-Q11-REALITY-TLS-H2.md): five common TLS fixes,2317 Linux units,73 REALITY-TLS/H2 checks,3 PCAP/6 wire-probe results,two bounded ASan campaigns,fresh matrix/soak/four native A/B PASS. Overall:11/37 DONE/PASS (29.7%). NextQ12.

### 12. Transports and wire camouflage

**4 October,Q12 DONE/PASS:** Close/controls and wire-matrix review complete;8 baseline FAIL,17 new tests,2352 Linux PASS,13 fresh wire cases,64 probes,two frame/QUIC ASan campaigns,fresh matrix/soak/four native A/B PASS. [Evidence and scope](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md). Overall **12/37 (32.4%)**;next Q13.

**4 October,WS writer batch PASS:** [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md): four shared writer/read fixes,5 baseline FAIL,7 new tests,2325 Linux PASS,10prior +3fresh wire-mode cases,fresh matrix/soak/native A/B PASS. At that batch,HTTP/inbound frame/fuzz remained;Q12 was IN_PROGRESS,overall11/37 (29.7%).

**Source:** `qeli/src/protocol/tls.rs`, `qeli/src/protocol/obfs.rs`, `qeli/src/protocol/quic.rs`, `qeli/src/transport`.

Derive supported runtime/Quick Start combinations: plain/fake-tls/reality/reality-tls/WS/obfs/UDP-QUIC/AWG. Test WS masking/control caps, junk counters, fallback and invalid combinations. Separate protocol compliance, DPI detectability and goodput.

**Existing harness/fixtures:** `conformance/quic.json`, `qeli/fuzz/fuzz_targets/websocket_head.rs`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

### 13. Recordizer, padding and shaping

**4 October, Q13 DONE/PASS: ** removed both disabled UDP stealth branches; TCP-only policy retained. Final 2365 Linux units, 7 live cases, matrix 18/18, soak 33 and four native A/B PASS. Overall **13/37 (35.1%)**, 24 sections remain; next Q14. [Final evidence and limits](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md).

**4 October,morphology batch PASS:** four more padding/normalization/mux corrections,2365 Linux PASS,6 combined TCP/UDP cases,fresh matrix/soak/native A/B. [Evidence and remaining two UDP branches](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md).

**4 October, shaping batch PASS:** [five fixes and measurements](../reports/audit-0.8.2/AUDIT-Q13-MORPHOLOGY.md):5 baseline FAIL,7 new tests,2359 Linux PASS,10 network cases/102 assertions,recordizer campaign,fresh matrix/soak/native A/B. Recordizer/padding/normalization review continues;overall remains12/37 (32.4%).

**Source:** `qeli/src/protocol/recordizer.rs`, `qeli/src/protocol/shaper.rs`, `qeli/src/protocol/obfuscate.rs`.

Off/prefer/required and legacy peers; batch/reassembly caps, flush deadlines, cancellation and aggregate budgets. Junk/heartbeat must not starve payloads. Compare on/off on identical workloads; inspect bounded memory, jitter and periodic PCAP signals.

**Existing harness/fixtures:** `scripts/validate_shaping.py`, `scripts/bench_stealth.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

### 14. Supervisor, workers and profiles

**4 October, Q14 DONE/PASS:** Q14-F039 fixed — supervisor owns background services and stops HTTP/HTTPS panel. 2368 Linux tests, 38 process checks, 4 panel stop/cancel cases, 5 privileged executions, stop during backoff, matrix18/18 and native A/B PASS. [Evidence and limits](../reports/audit-0.8.2/AUDIT-Q14-CURRENT-LIFECYCLE.md).

**4 October, current lifecycle batch PASS: ** 8/8 worker cases, 80 reloads, 22 recovery and14 multiprofile checks on the current release; host/service preserved. [Review and Q14 remaining scope](../reports/audit-0.8.2/AUDIT-Q14-CURRENT-LIFECYCLE.md). Q14 IN_PROGRESS.

**Source:** `qeli/src/server/mod.rs`, `qeli/src/server/tasks.rs`, `qeli/src/server/supervisor.rs`, `qeli/src/server/control.rs`, `qeli/src/server/control_io.rs`, `qeli/src/server/control_socket.rs`, `qeli/src/main.rs`, `qeli/src/hooks.rs`, `qeli/src/hooks/process.rs`.

Start/stop/reload/crash/respawn, occupied bind/TUN, profile deletion/rename, hook failures and dead control clients. Lock ordering, backoff, watchdogs and task ownership. Cleanup is idempotent and isolated between profiles.

**Existing harness/fixtures:** `scripts/test_web_reload.py`, `scripts/test_tun_reclaim.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**Task ownership, 23 September 2026:**
[Q14/Q19 pass](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md) fixes Q14-F001–F002: joining
services after early startup errors and a concurrent/cancelled shutdown barrier.
Seven task-ownership tests include a race over 1,024 resources; actual DNS listeners
are exercised over loopback. Linux TUN/firewall E2E, forced wrapper cancellation,
watch/control, hooks and restart/reload remain open.

**Supervisor and control events, 23 September 2026:**
[Q14 follow-up](../reports/audit-0.8.2/AUDIT-Q14-SUPERVISOR.md) fixes Q14-F003–F007: stop during
spawn failures, Child/PID ownership, a 60-second grace deadline, Restart/Reload
queuing and early signal installation. Thirteen behavioral tests plus a child
fixture; 812 Rust tests overall pass. Tests use real isolated host processes,
not the Linux TUN worker. Control sockets, hooks, Unix signals and Linux rollback
remain open.

**Control socket and hooks, 23 September 2026:**
[Q14-F008–F013 pass](../reports/audit-0.8.2/AUDIT-Q14-CONTROL.md): Unix socket ownership,
safe runtime directory permissions, message bounds, deadlines, handler drain before
profile teardown, and post_down only for ready generations. 819 host Rust tests pass;
12 new Unix tests compiled only. Linux runtime/systemd/hooks and forced cancellation
remain open; next are hook processes/output and startup rollback.

**Hook processes, 23 September 2026:**
[Q14-F014–F015](../reports/audit-0.8.2/AUDIT-Q14-HOOKS.md): shared server/client runner retains
8 KiB per stdout/stderr stream and terminates Linux process groups on timeout/cancellation,
while preserving intentional redirected background services. 828 host Rust tests pass;
four new Linux group tests compiled only. Next: startup rollback, background worker
services and binding trusted config to parsed contents. Linux E2E remains open.

**Worker services and accounting, 23 September 2026:**
[Q14-F016–F017 / Q15-F001](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md): owned and monitored
periodic tasks, draining before profile cleanup, writable accounting only after acquiring
the worker lease, final persistence on both stop paths. Short sessions and final counter
tails now survive registry removal. 848 host Rust tests PASS; Linux cross-check only.
Notification tasks, forced outer cancellation and Linux E2E remain open.

**Notification ownership, 23 September 2026:**
[Q14-F018 / Q32-F001](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md): 128 accepted deliveries,
8 active requests per process, shared panel probe admission, bounded payloads and a
10-second drain after producers stop. No detached notification wrappers remain.
864 host Rust tests PASS; Linux all-targets cross-check only. Supervisor panel/metrics/
autostart ownership, config trust and Linux runtime E2E remain open.

**Config snapshot trust, 23 September 2026:**
[Q14-F019 / Q33-F001](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md): owner/mode and parsed
bytes now come from the same descriptor; immutable startup authorization survives
profile retries without path rechecks. Ready-generation cleanup keeps its command and
environment after config removal/replacement. 874 host Rust tests PASS; four new Unix/
Linux tests cross-checked only. password_command process bounds, startup ownership,
installer/update/restore and Linux runtime integration remain open.

**Credential execution and feature isolation, 23 September 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
asynchronous password_command, 30-second deadline, full stdout up to 16 KiB, discarded
stderr and secret-safe failures. Early SIGINT/SIGTERM cancels and reaps the supplier;
client watchers/sampler have a scoped owner. Server-only TUN gate fixed and both isolated
features checked in CI. 883 host Rust tests PASS; four Linux tests cross-checked only.
Server-only check has 23 existing transport dead-code warnings. password_file bounds,
final client task drain and Linux runtime/release checks remain open.

**File credentials and final status, 23 September 2026:**
[Q25-F002 / Q14-F021](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md): file/command share a 16 KiB
zeroizing buffer; regular-file reads use one owned blocking job, keep symlink support,
reject FIFO and await active I/O on ordinary stop/deadline. The final status follows joined
watchers/sampler, including initialized startup-error paths. 895 host Rust tests PASS;
two Unix tests cross-checked only. Non-interruptible I/O may exceed the 30-second budget.
Startup/network rollback, background fault monitoring and Linux E2E remain open.

**Fail-closed network cleanup, 23 September 2026:**
[Q25-F003](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md): forwarding/NAT cleanup must succeed
before an enabled kill-switch is removed; failures retain the barrier and report why.
899 host Rust tests PASS, including four portable fault-injection scenarios. Linux is
cross-checked only. The early begin_connection follow-up is recorded below; real firewall/E2E remain open.

**Core lifecycle failure handling, 23 September 2026:**
[Q25-F004/F005](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md): core startup errors now reach
cleanup/post_down; core teardown errors terminate with failure and retain the enabled
kill-switch while still attempting forwarding cleanup. Six new host regressions include
real ClientCore queue backpressure. 905 host Rust tests PASS; Linux is cross-checked only.
Live Linux lifecycle/firewall tests and complete route/DNS rollback remain open.

**TUN/route/DNS cleanup propagation, 23 September 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): explicit teardown and rollback guards
share bounded failure evidence with the Linux retry loop. Cleanup errors cannot become a
successful signal stop or release the enabled kill-switch. TunnelSetup owns its guard before
core ACK; terminal kick types survive combined cleanup errors. Eight new host tests pass;
two Linux adapter cases are cross-checked only. 921 host Rust tests PASS. Live Linux E2E,
command deadlines and complete generation-task joining remain open.

**Server H2 and pre-auth, 23 September 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): the profile joins nested H2 tasks before
teardown; a rejection flush retains its pre-auth slot until I/O release. 13 new regressions,
969 Rust tests PASS. H2/ProfileTasks/semaphores were exercised on the host; production Linux
was cross-compiled only. Other section scenarios and live Linux E2E remain open.

**TUN/DNS system commands, 23 September 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 seconds per command, complete
output capped at 16 MiB per stream, child termination and DNS-marker retention on failure.
Diagnostics no longer claim unconfirmed rollback. 986 host Rust tests PASS; two new Linux
process-group tests were cross-compiled only. Route/firewall commands, live Linux and an
overall shutdown deadline remain open; section status stays IN_PROGRESS.

**NAT cleanup, 23 September 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): finite snapshot deletion,
post-delete verification and failure diagnostics while continuing other rules/chains.
13 new host tests, 999 Rust tests PASS; production Linux cross-checked only.
Q14-F026 is fixed in the [next pass](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (teardown error propagation), firewall deadlines and live Linux remain open.

**Shared firewall checks, 23 September 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): server and Linux
kill-switch share presence/absence/error classification; exact DNS cleanup verifies the
1024 boundary and continues TCP after UDP failure. 17 new host tests, 1016 Rust tests
PASS; two new Unix/Linux scenarios cross-checked only. Q14-F027, command deadlines
and actual backend/runtime validation remain open.

**DNS firewall ownership, 23 September 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): a worker registry retains exact rules
after failed Drop/rollback; cleanup and new installation retry pending retirement.
Tokens protect replacements from stale leases; exact retry skips active entries.
12 new host tests, 1028 Rust tests PASS; three adapter regressions compare baseline/fix
separately. Q14-F027, persistent journaling, deadlines and live Linux remain open.

**Worker shutdown outcome, 23 September 2026:**
[Q14-F027, partial fix](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): final retry of known
DNS/IPv6 sysctl leases affects the worker Result and exit status. Accounting flush still
runs after network failure; active DNS leases are reported without deleting their rules.
14 new host tests, 1042 Rust tests PASS; eight separate process-exit scenarios PASS.
A follow-up propagates final worker stop failure through the outer supervisor: nonzero
exit and forced kill no longer return Ok. Five more host tests; that pass totals 1047
Rust tests PASS, plus three separate supervisor regression scenarios PASS.
Next pass: [profile tasks and TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Shutdown JoinSet errors, TUN queue timeout/panic and device deletion failures now reach
the worker outcome; 13 new host tests, current matrix 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): fixed false sysctl recovery
success and loss of existing ownership on failed reacquisition;
1060 Rust tests and 7 separate fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): partial IPv6 acquisition is now
registered before the first attempt; any failure triggers rollback, and failed rollback
retains the scope for final cleanup. 11 new regressions plus one moved Linux-only test:
that pass totals 1072 Rust tests PASS; five separate adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): all five server NAT command launch sites
use the shared runner (15 s; 16 MiB per output stream). Timeout retains DNS ownership;
that pass's matrix of 1073 Rust tests and six separate adapter checks PASS.
Generic NAT outcome, old generations/retry backoff, restart policy, persistent journaling,
overall operation deadlines, remaining system commands and live Linux remain open.

**Preflight, 23 September 2026:** [Q05-F001](../reports/audit-0.8.2/AUDIT-Q05-PREFLIGHT.md):
four host-state probes share the bounded runner (15 seconds, 16 MiB per output stream).
IPv4 fail-open and independent partial IPv6 observations are preserved. The host suite
includes 4 new tests and 20 existing preflight tests; 1097 Rust tests and 21 production-adapter
scenarios PASS. Linux HTTP/restart/restore, transaction-wide deadlines and synchronous
waiting in async handlers remain open.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): unknown sysctl owners are retained and
acquire/recovery reports an error; failed sysctl observation preserves original values
for retry. Eight baseline regressions fixed, 1362 Rust tests PASS. Journal namespace
identity, actual Linux runtime and full section PASS remain open.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 isolates network namespaces,
checks PID/time context and procfs before pruning, and retains nonempty current-boot v1
with an explicit migration error. 24 new tests, 1386 Rust tests PASS. Actual Linux,
namespace identity after object destruction and full section PASS remain open.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): destructive TUN recovery based on partial
PID discovery was removed. The client passively waits for release and refuses
lookup errors/changed ifindex; client and server create the first queue exclusively.
Later queues use its actual name. 20 new tests, 7 baseline failures, 1406 Rust tests
PASS. Linux example-test compilation without the server feature is fixed.
Attach/teardown races and actual Linux runtime remain open.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach and later queues cannot
register a replacement for a vanished TUN; failed TUNSETIFINDEX stops opening.
VNET_HDR/unknown features are refused, supported flags preserved. 18 new host tests
plus an existing parser test; 1425 Rust PASS. Three new Linux ioctl tests compiled
only. Follow-up ownership work is recorded below.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): name-based TUN deletion is removed.
Client and server guards retain original descriptors through host cleanup; setup rollback
borrows the device. 12 extracted-code harness scenarios PASS (baseline 7 FAIL / 5 PASS),
1425 Rust PASS. Three added native Linux tests compiled only. External rename/delete,
DNS-marker/route identity and Q14-F027 remain open.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): only an acquired generation lease
may revert DNS. Namespace/index records and nonblocking ownership locks replace name-only
markers; original-fd checks precede numeric resolver commands. Startup never reverts a
live link solely from a saved marker. 24 new host tests, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace test compiled only. Route identity,
resolver service namespace and post-check index reuse remain open.

### 15. Sessions, IP pools and limits

**4 October, Q15 DONE/PASS:** Q15-F003 bounds IPv4/IPv6 reuse history. 2370 unit, 148 session + 54 actual-TUN data checks, bonding, matrix 18/18 and native A/B PASS. [Evidence and limits](../reports/audit-0.8.2/AUDIT-Q15-CURRENT-SESSIONS.md).

**Source:** `qeli/src/server/pool.rs`, `qeli/src/server/handler.rs`, `qeli/src/server/udp_handler.rs`, `qeli/src/server/usage.rs`.

Concurrent allocate/auth/reconnect/evict/reap/revoke/quota, atomic v4+v6, reservations/exclusions and exhaustion. Shared TCP/UDP/bonding caps. No duplicate IP or leaked lease/token/task/client_subnet after any termination path.

**Existing harness/fixtures:** `scripts/test_udp_reap.py`, `scripts/test_maxsessions.py`, `scripts/test_multidevice.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**Accounting subpass:** [Q15-F001](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md) covers
short TCP/UDP sessions, writer tails, reset baselines and counter retirement. 14 portable
accounting tests pass. The final batch above supplements this historical accounting pass with pool allocation,
concurrent admissions and actual Linux quota/expiry/revoke.

### 16. ACL, pushed routes and site-to-site

**4 October, Q16 DONE/PASS:** Q16-F001 prevents source spoofing through conflicting or
unregistered client_subnet; shared ingress enforces exact/LPM/current-session ownership.
Q16-F002 keeps server tunnel endpoint delivery local with an exit /0.
2374 units, real TCP/UDP/QUIC with IPv4/IPv6, matrix and native A/B — PASS.
[Evidence and limits](../reports/audit-0.8.2/AUDIT-Q16-ACL-ROUTES.md).

**Source:** `qeli/src/server/acl.rs`, `qeli/src/config/users.rs`, `qeli/src/transport_core/network.rs`.

User/group/profile precedence, longest prefixes, client_to_client, spoofed sources, overlaps, /0 and client_subnet return paths. Cover TCP/UDP and v4/v6. Server-side enforcement; revoke/route reassignment removes access from the previous session.

**Existing harness/fixtures:** `scripts/test_push_matrix.py`, `scripts/test_route_push.py`, `scripts/test_l3_user_limits.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

### 17. IPv4 NAT, forwarding and sysctls

**4 October, Q17 DONE/PASS:** 228 fresh current-candidate packet/gateway checks;
319 selected Q16 units plus source/hash-qualified prior backend/recovery evidence.
Q17-F001 replaces the old gateway runner with private isolation. Historical open
statuses below describe earlier snapshots; see [current results and accepted limits](../reports/audit-0.8.2/AUDIT-Q17-IPV4-NETWORK.md).

**Source:** `qeli/src/server/nat.rs`, `qeli/src/client/sysctl.rs`, `qeli/src/client/gateway.rs`.

NAT44/forward_private/gateway_nat/MSS and iptables/nft backend errors. Before/after rules/routes/sysctls with multiple profiles. Exact tags, ownership, crash journals and boot IDs; preserve administrator rules and values.

**Existing harness/fixtures:** `scripts/test_gateway_nat.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**NAT cleanup, 23 September 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): finite snapshot deletion,
post-delete verification and failure diagnostics while continuing other rules/chains.
13 new host tests, 999 Rust tests PASS; production Linux cross-checked only.
Q14-F026 is fixed in the [next pass](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (teardown error propagation), firewall deadlines and live Linux remain open.

**Shared firewall checks, 23 September 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): server and Linux
kill-switch share presence/absence/error classification; exact DNS cleanup verifies the
1024 boundary and continues TCP after UDP failure. 17 new host tests, 1016 Rust tests
PASS; two new Unix/Linux scenarios cross-checked only. Q14-F027, command deadlines
and actual backend/runtime validation remain open.

**DNS firewall ownership, 23 September 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): a worker registry retains exact rules
after failed Drop/rollback; cleanup and new installation retry pending retirement.
Tokens protect replacements from stale leases; exact retry skips active entries.
12 new host tests, 1028 Rust tests PASS; three adapter regressions compare baseline/fix
separately. Q14-F027, persistent journaling, deadlines and live Linux remain open.

**Worker shutdown outcome, 23 September 2026:**
[Q14-F027, partial fix](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): final retry of known
DNS/IPv6 sysctl leases affects the worker Result and exit status. Accounting flush still
runs after network failure; active DNS leases are reported without deleting their rules.
14 new host tests, 1042 Rust tests PASS; eight separate process-exit scenarios PASS.
A follow-up propagates final worker stop failure through the outer supervisor: nonzero
exit and forced kill no longer return Ok. Five more host tests; that pass totals 1047
Rust tests PASS, plus three separate supervisor regression scenarios PASS.
Next pass: [profile tasks and TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Shutdown JoinSet errors, TUN queue timeout/panic and device deletion failures now reach
the worker outcome; 13 new host tests, current matrix 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): fixed false sysctl recovery
success and loss of existing ownership on failed reacquisition;
1060 Rust tests and 7 separate fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): partial IPv6 acquisition is now
registered before the first attempt; any failure triggers rollback, and failed rollback
retains the scope for final cleanup. 11 new regressions plus one moved Linux-only test:
that pass totals 1072 Rust tests PASS; five separate adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): all five server NAT command launch sites
use the shared runner (15 s; 16 MiB per output stream). Timeout retains DNS ownership;
that pass's matrix of 1073 Rust tests and six separate adapter checks PASS.
Generic NAT outcome, old generations/retry backoff, restart policy, persistent journaling,
overall operation deadlines, remaining system commands and live Linux remain open.

**Gateway rollback and protection, 23 September 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): TUN/family/subnet records
replace global flags and config-based undo. Failed families retain retry state;
unknown firewall inspection cannot authorize insertion, and reused permits also
verify kill-switch order. Router operations include sysctl release under the same
process lock. Eight baseline failures → PASS; 25 new tests and five existing tests
newly enabled on host; 1287 Rust tests and nine matrix commands PASS.
Shared exit-node WAN/NAT ownership, multiple kill-switch chains, cross-process
races, overall deadlines and Linux runtime remain open.

**Exit NAT and kill-switch admission, 23 September 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT comments distinguish
TUN/WAN rules; cleanup no longer discovers unowned WAN targets. Public kill-switch
startup checks both families before mutation and rejects other/legacy Qeli chains.
The first carrier remains reachable; concurrent starts in one process admit one
policy. 13 baseline failures → PASS; 30 new tests, two obsolete helper tests removed.
1315 Rust tests and nine matrix commands PASS. Interprocess races, stale TUN identity,
IPv6-protection discovery and Linux runtime remain open.
Follow-up: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
cross-process protected-session ownership and refusal on unknown IPv6.
Linux runtime for the new lease tests remains open; section status is unchanged.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): positive ipv6.disable=1 evidence
permits skipping IPv6 firewall; the shared lease reserves every Linux client's TUN,
including gateway/exit without kill-switch and dev_attach. 17 new host tests,
3 baseline FAIL → PASS. Linux runtime and full section PASS remain open.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): unknown sysctl owners are retained and
acquire/recovery reports an error; failed sysctl observation preserves original values
for retry. Eight baseline regressions fixed, 1362 Rust tests PASS. Journal namespace
identity, actual Linux runtime and full section PASS remain open.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 isolates network namespaces,
checks PID/time context and procfs before pruning, and retains nonempty current-boot v1
with an explicit migration error. 24 new tests, 1386 Rust tests PASS. Actual Linux,
namespace identity after object destruction and full section PASS remain open.

### 18. IPv6 off/manual/route/nat66 and NDP

**4 October, Q18 DONE/PASS:** Q18-F001/F002 fixed; real NS/NA baseline → fix. 184 fresh NDP checks and 446 matrix/transition checks; 2376 unit PASS, Clippy and four native A/B targets PASS. [Results and limits](../reports/audit-0.8.2/AUDIT-Q18-IPV6-NDP.md). Historical open statuses below refer to earlier snapshots.

**Source:** `qeli/src/server/nat.rs`, `qeli/src/server/ndp_proxy.rs`, `qeli/src/config/server.rs`.

All 4×3 egress/NDP combinations for ipv4/dual/ipv6; all 16 stop/restart transitions on dual, with separate retained IPv6-only qualification in its original scope. Linux E2E: off blocks transit; manual adds no IPv6 firewall/DNS/sysctl; route preserves sources; nat66 masquerades. Test RA, exact cleanup, NS validation, session ownership/revoke, required failure, DNS 53/5353 and independent IPv4.

**Existing harness/fixtures:** `scripts/test_panel_ipv6_e2e.py`, `scripts/run_ipv6_release_matrix.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**NAT cleanup, 23 September 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): finite snapshot deletion,
post-delete verification and failure diagnostics while continuing other rules/chains.
13 new host tests, 999 Rust tests PASS; production Linux cross-checked only.
Q14-F026 is fixed in the [next pass](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (teardown error propagation), firewall deadlines and live Linux remain open.

**Shared firewall checks, 23 September 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): server and Linux
kill-switch share presence/absence/error classification; exact DNS cleanup verifies the
1024 boundary and continues TCP after UDP failure. 17 new host tests, 1016 Rust tests
PASS; two new Unix/Linux scenarios cross-checked only. Q14-F027, command deadlines
and actual backend/runtime validation remain open.

**DNS firewall ownership, 23 September 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): a worker registry retains exact rules
after failed Drop/rollback; cleanup and new installation retry pending retirement.
Tokens protect replacements from stale leases; exact retry skips active entries.
12 new host tests, 1028 Rust tests PASS; three adapter regressions compare baseline/fix
separately. Q14-F027, persistent journaling, deadlines and live Linux remain open.

**Worker shutdown outcome, 23 September 2026:**
[Q14-F027, partial fix](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): final retry of known
DNS/IPv6 sysctl leases affects the worker Result and exit status. Accounting flush still
runs after network failure; active DNS leases are reported without deleting their rules.
14 new host tests, 1042 Rust tests PASS; eight separate process-exit scenarios PASS.
A follow-up propagates final worker stop failure through the outer supervisor: nonzero
exit and forced kill no longer return Ok. Five more host tests; that pass totals 1047
Rust tests PASS, plus three separate supervisor regression scenarios PASS.
Next pass: [profile tasks and TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Shutdown JoinSet errors, TUN queue timeout/panic and device deletion failures now reach
the worker outcome; 13 new host tests, current matrix 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): fixed false sysctl recovery
success and loss of existing ownership on failed reacquisition;
1060 Rust tests and 7 separate fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): partial IPv6 acquisition is now
registered before the first attempt; any failure triggers rollback, and failed rollback
retains the scope for final cleanup. 11 new regressions plus one moved Linux-only test:
that pass totals 1072 Rust tests PASS; five separate adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): all five server NAT command launch sites
use the shared runner (15 s; 16 MiB per output stream). Timeout retains DNS ownership;
that pass's matrix of 1073 Rust tests and six separate adapter checks PASS.
Generic NAT outcome, old generations/retry backoff, restart policy, persistent journaling,
overall operation deadlines, remaining system commands and live Linux remain open.

**Gateway rollback and protection, 23 September 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): TUN/family/subnet records
replace global flags and config-based undo. Failed families retain retry state;
unknown firewall inspection cannot authorize insertion, and reused permits also
verify kill-switch order. Router operations include sysctl release under the same
process lock. Eight baseline failures → PASS; 25 new tests and five existing tests
newly enabled on host; 1287 Rust tests and nine matrix commands PASS.
Shared exit-node WAN/NAT ownership, multiple kill-switch chains, cross-process
races, overall deadlines and Linux runtime remain open.

**Exit NAT and kill-switch admission, 23 September 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT comments distinguish
TUN/WAN rules; cleanup no longer discovers unowned WAN targets. Public kill-switch
startup checks both families before mutation and rejects other/legacy Qeli chains.
The first carrier remains reachable; concurrent starts in one process admit one
policy. 13 baseline failures → PASS; 30 new tests, two obsolete helper tests removed.
1315 Rust tests and nine matrix commands PASS. Interprocess races, stale TUN identity,
IPv6-protection discovery and Linux runtime remain open.
Follow-up: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
cross-process protected-session ownership and refusal on unknown IPv6.
Linux runtime for the new lease tests remains open; section status is unchanged.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): positive ipv6.disable=1 evidence
permits skipping IPv6 firewall; the shared lease reserves every Linux client's TUN,
including gateway/exit without kill-switch and dev_attach. 17 new host tests,
3 baseline FAIL → PASS. Linux runtime and full section PASS remain open.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): unknown sysctl owners are retained and
acquire/recovery reports an error; failed sysctl observation preserves original values
for retry. Eight baseline regressions fixed, 1362 Rust tests PASS. Journal namespace
identity, actual Linux runtime and full section PASS remain open.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 isolates network namespaces,
checks PID/time context and procfs before pruning, and retains nonempty current-boot v1
with an explicit migration error. 24 new tests, 1386 Rust tests PASS. Actual Linux,
namespace identity after object destruction and full section PASS remain open.

### 19. Server and client DNS

**4 October, Q19 DONE/PASS:** 105 fresh real DNS/tunnel/resolved/crash checks; Q19-V001 closes the TCP/TC runtime gap. No new production bug; 32 relevant source hashes, 61 raw files and nine archives verified; unchanged Q18 Linux/native qualification reused. [Results and limits](../reports/audit-0.8.2/AUDIT-Q19-DNS-FINAL.md). Historical open statuses below refer to earlier snapshots.

**Source:** `qeli/src/server/dns.rs`, `qeli/src/server/dns/resolver.rs`, `qeli/src/client/dns.rs`, `qeli/src/transport_core/network.rs`.

UDP/TCP upstreams, truncation fallback, timeouts, malformed packets, caching/eviction/blocklists. Full/split, resolved/resolv.conf and OS resolvers, v4/v6 leaks, failed apply before Connected and crash recovery. Custom ports/manual IPv6; rejected DoT is not implemented DoT.

**Existing harness/fixtures:** `scripts/test_dns_test_server.py`, `scripts/test_panel_route_dns.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**Shared network-plan pass, 22–23 September 2026:**
[Q19/Q22 report](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md). Fixed legacy/v2 DNS differences
and order-dependent route-budget failures; removed obsolete Linux DNS test code.
This validates the shared planner, not the entire module. DNS proxy/cache, actual
OS apply/rollback and concurrent lifecycle checks remain open.

**Server DNS, 23 September 2026:** [Q19 report](../reports/audit-0.8.2/AUDIT-Q19-DNS-PROXY.md).
Fixed Q19-F004–F006: NODATA TTL after CNAME, compressed-name validation and failover
after TCP TC. One production engine is tested locally: 22 DNS tests with UDP/TCP,
754 Rust tests overall — PASS. Linux lifecycle, advanced DNS types and load checks
remain open; the overall section is not complete.

**Cache and signed exchanges, 23 September 2026:**
[Q19 follow-up](../reports/audit-0.8.2/AUDIT-Q19-DNS-CACHE.md) closes Q19-F007–F010: a 16 MiB
per-profile packet budget, byte-preserving uncached TSIG/SIG(0) relay, and request
header/opcode checks. The legacy panel lab script no longer opens SSH on import. 36 DNS tests, 768 Rust tests overall — PASS. Real Linux
lifecycle, sustained concurrent load/RSS, advanced EDNS/RDATA and external signed
interoperability remain open; section 19 stays **IN_PROGRESS**.

**EDNS/RDATA, 23 September 2026:**
[Next Q19 pass](../reports/audit-0.8.2/AUDIT-Q19-DNS-EDNS.md) fixes Q19-F011–F015: TTL across
all replayed sections, common RDATA framing, OPT/TLV validation and BADVERS,
extended RCODE during truncation, and uncached EDNS options with fresh OPT on
ordinary cache hits. 51 DNS tests including IPv6 loopback UDP/TCP; 783 Rust tests
in total — PASS. Linux lifecycle, sustained load/RSS, DNSSEC/RRset semantics,
external interoperability and OS DNS apply/rollback remain open.

**DNS listeners and cleanup, 23 September 2026:**
[Q14/Q19 pass](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md): production UDP/TCP listeners
are host-testable and no longer take an unused ServerState. Seven listener plus
52 resolver tests cover IPv4/IPv6, persistent/pipelined TCP, deadlines, the
512-connection limit, cancellation and port rebinding. 798 Rust tests overall
pass. Shared lifecycle fixes are Q14-F001–F002; real Linux runtime and sustained
load remain open.

**Legacy resolver recovery, 23 September 2026:**
[Q25-F006](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md): failed unlink/chmod and invalid snapshot
payloads no longer count as successful recovery and cannot retire the recovery record.
Eight new Windows host tests pass; three Unix-specific cases are cross-checked only.
913 host Rust tests PASS. Live Linux DNS and propagation of lower-level cleanup errors remain open.

**TUN/route/DNS cleanup propagation, 23 September 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): explicit teardown and rollback guards
share bounded failure evidence with the Linux retry loop. Cleanup errors cannot become a
successful signal stop or release the enabled kill-switch. TunnelSetup owns its guard before
core ACK; terminal kick types survive combined cleanup errors. Eight new host tests pass;
two Linux adapter cases are cross-checked only. 921 host Rust tests PASS. Live Linux E2E,
command deadlines and complete generation-task joining remain open.

**TUN/DNS system commands, 23 September 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 seconds per command, complete
output capped at 16 MiB per stream, child termination and DNS-marker retention on failure.
Diagnostics no longer claim unconfirmed rollback. 986 host Rust tests PASS; two new Linux
process-group tests were cross-compiled only. Route/firewall commands, live Linux and an
overall shutdown deadline remain open; section status stays IN_PROGRESS.

**NAT cleanup, 23 September 2026:**
[Q14-F024/F025](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md): finite snapshot deletion,
post-delete verification and failure diagnostics while continuing other rules/chains.
13 new host tests, 999 Rust tests PASS; production Linux cross-checked only.
Q14-F026 is fixed in the [next pass](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Q14-F027 (teardown error propagation), firewall deadlines and live Linux remain open.

**Shared firewall checks, 23 September 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): server and Linux
kill-switch share presence/absence/error classification; exact DNS cleanup verifies the
1024 boundary and continues TCP after UDP failure. 17 new host tests, 1016 Rust tests
PASS; two new Unix/Linux scenarios cross-checked only. Q14-F027, command deadlines
and actual backend/runtime validation remain open.

**DNS firewall ownership, 23 September 2026:**
[Q14-F028](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md): a worker registry retains exact rules
after failed Drop/rollback; cleanup and new installation retry pending retirement.
Tokens protect replacements from stale leases; exact retry skips active entries.
12 new host tests, 1028 Rust tests PASS; three adapter regressions compare baseline/fix
separately. Q14-F027, persistent journaling, deadlines and live Linux remain open.

**Worker shutdown outcome, 23 September 2026:**
[Q14-F027, partial fix](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md): final retry of known
DNS/IPv6 sysctl leases affects the worker Result and exit status. Accounting flush still
runs after network failure; active DNS leases are reported without deleting their rules.
14 new host tests, 1042 Rust tests PASS; eight separate process-exit scenarios PASS.
A follow-up propagates final worker stop failure through the outer supervisor: nonzero
exit and forced kill no longer return Ok. Five more host tests; that pass totals 1047
Rust tests PASS, plus three separate supervisor regression scenarios PASS.
Next pass: [profile tasks and TUN teardown](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).
Shutdown JoinSet errors, TUN queue timeout/panic and device deletion failures now reach
the worker outcome; 13 new host tests, current matrix 1060 Rust tests PASS.
[Q14-F029/F030](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md): fixed false sysctl recovery
success and loss of existing ownership on failed reacquisition;
1060 Rust tests and 7 separate fixture checks PASS.
[Q14-F031](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md): partial IPv6 acquisition is now
registered before the first attempt; any failure triggers rollback, and failed rollback
retains the scope for final cleanup. 11 new regressions plus one moved Linux-only test:
that pass totals 1072 Rust tests PASS; five separate adapter checks PASS.
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): all five server NAT command launch sites
use the shared runner (15 s; 16 MiB per output stream). Timeout retains DNS ownership;
that pass's matrix of 1073 Rust tests and six separate adapter checks PASS.
Generic NAT outcome, old generations/retry backoff, restart policy, persistent journaling,
overall operation deadlines, remaining system commands and live Linux remain open.

### 20. DHCP and lease lifecycle

**Source:** `qeli/src/server/dhcp.rs`, `qeli/src/config/server.rs`.

DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE, invalid requested_ip, duplicate xid/MAC, expiry and malformed options. NAK consumes no lease; empty pools do not underflow. Supported TAP/IPv4 only; verify panel round trips.

**Existing harness/fixtures:** `qeli/tests/config_examples.rs`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**4 October, Q20 complete:** [DHCP report](../reports/audit-0.8.2/AUDIT-Q20-DHCP-FINAL.md). Five fixes;2383 Linux unit PASS/60 ignored;35 semantic DHCP checks plus60 rate primers,13 fresh VPN smoke checks;four native A/B targets. TAP injection verifies actual worker DHCP, not VPN AUTH or device E2E. Old malformed OFFER and64-DNS admission reproduced;INI boundaries documented.

### 21. TUN/TAP, IP, MTU/PMTU and fragmentation

**4 October, Q21 complete:** [TUN/TAP, IP and MTU/PMTU](../reports/audit-0.8.2/AUDIT-Q21-PACKETS-FINAL.md). No new production defect; seven boundary properties,61 actual-module tests,70 real network checks,3 portable checks and two independently parsed carrier PCAPs PASS. Current Q20 full units/Clippy/release/native and earlier privileged TUN evidence are reconciled within their exact scope. Overall: 21/37 (56.8%), 16 remain; next Q22.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway binds RouteOwner;
firewall operations check namespace/TUN internally, and cleanup precedes TUN release.
Lost TUN permits rule cleanup in the original namespace while retaining the sysctl scope.
13 new host tests, 1485 Rust PASS; 9 baseline regressions reproduced. Internal sysctl
journal/stale recovery and independent kill-switch operations remain open.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
verify the original TUN through Weak and its held namespace; physical rollback is independent.
Identity loss is terminal, including callback and final FIB query. 13 new host tests,
1472 Rust PASS; four new native tests compiled only. Gateway/firewall/sysctl callback
internals, physical uplinks and post-check races remain open.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup checks a held
namespace and original TUN before each command; rename/delete/unknown retain reservations,
while physical bypass cleanup remains independent. 13 new host tests, 1459 Rust PASS;
three native route tests compiled only. Post-check races, setup/roaming TUN identity
and physical uplinks remain open.

**Source:** `qeli/src/tun`, `qeli/src/protocol/ip.rs`, `qeli/src/protocol/icmp.rs`, `qeli/src/protocol/data_frag.rs`, `qeli/src/protocol/udp_frag.rs`.

TUN host prefixes, TAP ARP/NDP/RA/DAD and unsupported EtherType/VLAN/multicast. IPv6 MTU 1280, small outer PMTU, spoofed PTB and path changes. Reassembly duplicates/overlaps/gaps/order/expiry/ID reuse and memory caps; inspect unwanted outer fragmentation.

**Existing harness/fixtures:** `scripts/test_tap_ipv6_control_probe.py`, `qeli/fuzz/fuzz_targets/data_frag.rs`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**Cancelled TUN shutdown, 23 September 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Shared TunWorkers retains Unix TUN/Wintun thread ownership through joining, including
cancelled shutdown and a saturated blocking pool. Seven new host regressions; 947 Rust
tests PASS. The Unix descriptor test was cross-compiled only. Real devices/drivers and
other section scenarios remain unverified; the full audit is still open.

**TUN/DNS system commands, 23 September 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 seconds per command, complete
output capped at 16 MiB per stream, child termination and DNS-marker retention on failure.
Diagnostics no longer claim unconfirmed rollback. 986 host Rust tests PASS; two new Linux
process-group tests were cross-compiled only. Route/firewall commands, live Linux and an
overall shutdown deadline remain open; section status stays IN_PROGRESS.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): destructive TUN recovery based on partial
PID discovery was removed. The client passively waits for release and refuses
lookup errors/changed ifindex; client and server create the first queue exclusively.
Later queues use its actual name. 20 new tests, 7 baseline failures, 1406 Rust tests
PASS. Linux example-test compilation without the server feature is fixed.
Attach/teardown races and actual Linux runtime remain open.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach and later queues cannot
register a replacement for a vanished TUN; failed TUNSETIFINDEX stops opening.
VNET_HDR/unknown features are refused, supported flags preserved. 18 new host tests
plus an existing parser test; 1425 Rust PASS. Three new Linux ioctl tests compiled
only. Follow-up ownership work is recorded below.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): name-based TUN deletion is removed.
Client and server guards retain original descriptors through host cleanup; setup rollback
borrows the device. 12 extracted-code harness scenarios PASS (baseline 7 FAIL / 5 PASS),
1425 Rust PASS. Three added native Linux tests compiled only. External rename/delete,
DNS-marker/route identity and Q14-F027 remain open.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): only an acquired generation lease
may revert DNS. Namespace/index records and nonblocking ownership locks replace name-only
markers; original-fd checks precede numeric resolver commands. Startup never reverts a
live link solely from a saved marker. 24 new host tests, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace test compiled only. Route identity,
resolver service namespace and post-check index reuse remain open.

### 22. Transport core, FFI/JNI and memory

**4 October, Q22 complete:** [transport core, FFI/JNI and memory](../reports/audit-0.8.2/AUDIT-Q22-CORE-FFI-FINAL.md). Q22-F001/F002 fix queued access after panic and cancel leased runners before handle retirement. Two baseline failures reproduced; 2402 full-feature units, strict Clippy, 22 Windows C ABI checks, 23 actual Android JNI checks, C11/C++11 headers and four native A/B PASS. Linux CLI bytes unchanged; prior network executions retain their scope. Overall: 22/37 (59.5%), 15 remain; next Q23.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway binds RouteOwner;
firewall operations check namespace/TUN internally, and cleanup precedes TUN release.
Lost TUN permits rule cleanup in the original namespace while retaining the sysctl scope.
13 new host tests, 1485 Rust PASS; 9 baseline regressions reproduced. Internal sysctl
journal/stale recovery and independent kill-switch operations remain open.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
verify the original TUN through Weak and its held namespace; physical rollback is independent.
Identity loss is terminal, including callback and final FIB query. 13 new host tests,
1472 Rust PASS; four new native tests compiled only. Gateway/firewall/sysctl callback
internals, physical uplinks and post-check races remain open.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup checks a held
namespace and original TUN before each command; rename/delete/unknown retain reservations,
while physical bypass cleanup remains independent. 13 new host tests, 1459 Rust PASS;
three native route tests compiled only. Post-check races, setup/roaming TUN identity
and physical uplinks remain open.

**Source:** `qeli/src/transport_core`, `qeli/include/qeli_transport_core.h`, `native-libs`.

Create/start/PREPARE/APPLY/COMMIT/stop/free, callbacks, buffers, queues and generation/cancellation. Stale handles, double free, callbacks after disposal, partial failure and ABI/feature mismatches. Packaged cores must match source, not merely load successfully.

**Existing harness/fixtures:** `scripts/test_native_repro.py`, `native-libs/provenance.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**Shared network-plan pass, 22–23 September 2026:**
[Q19/Q22 report](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md). Fixed legacy/v2 DNS differences
and order-dependent route-budget failures; removed obsolete Linux DNS test code.
This validates the shared planner, not the entire module. DNS proxy/cache, actual
OS apply/rollback and concurrent lifecycle checks remain open.

**TCP and Linux path-monitor ownership, 23 September 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): the common owner closes admission before
abort/join. TCP reader/writer/pipeline and producers finish before network cleanup;
management-event errors also follow teardown. Linux monitor blocking jobs are tracked for
TCP and UDP. 931 host Rust tests PASS; Linux is cross-checked only. Other UDP tasks, nested
transport workers, forced cancellation and command deadlines remain open.

**UDP ownership and rollback ordering, 23 September 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect and the Linux monitor share one group. Management-event errors follow
normal cleanup; the group finishes before platform-candidate inspection/rollback. TaskHandle
preserves join ownership across cancelled waits and path transfer. Nine new regressions;
940 host Rust tests PASS, Linux is cross-checked only. Nested transport workers, forced
cancellation, command deadlines and platform fault injection remain open.

**Cancelled TUN shutdown, 23 September 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Shared TunWorkers retains Unix TUN/Wintun thread ownership through joining, including
cancelled shutdown and a saturated blocking pool. Seven new host regressions; 947 Rust
tests PASS. The Unix descriptor test was cross-compiled only. Real devices/drivers and
other section scenarios remain unverified; the full audit is still open.

**Nested H2 tasks, 23 September 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
The TCP group starts before connect and joins drivers/bridges; the native runner retains
it across attempt cancellation. Nine new regressions, 956 Rust tests PASS; Linux is
cross-checked only. Server H2 is covered by the subsequent [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, early platform rollback, UDP cancellation and deadlines remain open.

**Server H2 and pre-auth, 23 September 2026:**
[Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md): the profile joins nested H2 tasks before
teardown; a rejection flush retains its pre-auth slot until I/O release. 13 new regressions,
969 Rust tests PASS. H2/ProfileTasks/semaphores were exercised on the host; production Linux
was cross-compiled only. Other section scenarios and live Linux E2E remain open.

**Linux monitor commands, 23 September 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
three read-only route/address queries use the shared runner with a 15-second deadline
and output limits. TaskGroup retains the blocking command during stop; failed samples
do not publish PathUpdate. 1098 Rust tests and 23 production-adapter scenarios PASS.
Route mutations, overall shutdown deadlines and actual Linux handover remain open.

**Gateway WAN, 23 September 2026:** [Q25-F021/F022](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md):
IPv4/IPv6 default-route and fallback queries use the shared bounded runner; cleanup
discovers a WAN only without remembered family targets. Seven new portable regressions,
1105 Rust tests and 33 separate adapter scenarios PASS. Actual Linux firewall and
uncertain mutation ownership remain open.

**Failed route mutations, 23 September 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): a failed add/replace/retirement
is reversible only after the failed destination is confirmed unchanged; unavailable,
changed or multi-line snapshots produce unknown state. Fifteen new regressions plus
eight existing route tests now run on host; 1128 Rust tests PASS. Baseline reproduction
has 10 expected failures and 5 controls. Pending ownership/recovery of uncertain routes,
command deadlines and live Linux remain open.

**Route ownership and cleanup, 23 September 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): the journal retains supplied
delete selectors; stale identity no longer authorizes replace/retirement/rollback.
Cleanup verifies absence and keeps failed entries for retry. Sixteen new regressions;
1144 Rust tests PASS. The same adapter tests reproduce 15 baseline failures and one
control. Process-global ownership, pending unknown mutations, atomic identity, command
deadlines and live Linux remain open.

**Scoped route ownership, 23 September 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): setup, guards and roaming receive a
unique owner; cleanup closes admission and handles only that owner's records.
Other Qeli owners cannot borrow the route; interface reuse waits for the old lease.
17 new regressions, 1161 Rust tests PASS; two targeted baseline failures reproduced.
Attach mode does not advertise managed roaming. Cross-process isolation, orphan/pending
operations, TUN workers, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — retirement/restore outcomes:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): deletion requires
confirmed absence; restoration requires the complete previous snapshot. Lost completion
does not negate a confirmed action, and apparent success cannot prove rollback.
16 new baseline failures → 16 PASS; 1177 Rust tests total and nine matrix commands PASS.
Linux runtime was not run. Pending unknown/orphan recovery, cross-process races and
command deadlines remain open; the section status is unchanged.

**2026-09-23 follow-up — pending and orphan records:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): unknown roaming operations retain
reservations without delete authority; every unknown commit closes admission.
Cleanup/reconnect releases pending/orphan entries only after confirmed absence, with
separate final-lease and interface-flush conditions. 17 new regressions/controls;
1194 Rust tests and nine matrix commands PASS. Initial setup mutations, flush postconditions,
durable crash recovery, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — initial setup and flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole share
exact pre/post checks and pending tracking for unknown outcomes. Both interface-flush
families require confirmed empty state or a missing interface verified by link inventory.
8 baseline failures → PASS plus 13 controls; 1214 Rust tests and nine matrix commands
PASS. Linux runtime, command deadlines, other route paths, durable crash recovery
and Q14-F027 workers/FD remain open.

**2026-09-23 follow-up — bounded route/firewall commands:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): routes and kill-switch use the
shared runner: 15 seconds per command, 16 MiB each for stdout/stderr. Gateway inherits
bounds through the iptables helper. Unknown outcomes preserve pending/verification;
unknown IPv4 default routes require protection unless allow_ipv4_leak is explicit.
20 new tests; 1234 Rust tests and nine matrix commands PASS. Overall transaction
deadlines, other route ownership paths, gateway rollback and Linux runtime remain open.

**2026-09-23 follow-up — TUN/TAP, pushed and local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): the active NetworkPlan installer
shares exact pre/post checks, metric verification and ownership/pending tracking.
Unused pushed/local implementations and the second parser were removed.
Malformed route_local inventory prevents mutations. Pending is reconciled after the
independent flush of the Qeli-owned interface. 10 reproducing regressions and 13 controls;
1257 Rust tests and nine matrix commands PASS. Gateway rollback, globals, overall
deadlines, crash recovery and Linux runtime remain open.

### 23. Roaming, resume and CONTROL_V2

**4 October, Q23 complete:** [roaming, resume and CONTROL_V2](../reports/audit-0.8.2/AUDIT-Q23-ROAMING-FINAL.md). Q23-F001 rearms the original orphan deadline after aborted prepared resume. 2405 units, strict Clippy, 24 focused tests, 12 fresh Linux cases/281 checks and four native A/B PASS. Overall: 23/37 (62.2%), 14 remain; next Q24.

**Source:** `qeli/src/protocol/roaming.rs`, `qeli/src/protocol/control_v2.rs`, `qeli/src/transport_core`.

TCP make-before-break/UDP migration: proof/path validation, anti-amplification, grace expiry, replay/revoke and candidate races. NAT rebinding, family changes, Wi-Fi/LTE, sleep/wake, server restart/APPLY rollback and PMTU reset. Verify cross-server boundaries; a PUSH_CONFIG constant is not an implementation.

**Existing harness/fixtures:** `scripts/roaming_tcp_all_modes_netns_e2e.sh`, `scripts/roaming_udp_all_modes_netns_e2e.sh`, `scripts/roaming_mixed_version_netns_e2e.sh`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**TCP and Linux path-monitor ownership, 23 September 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): the common owner closes admission before
abort/join. TCP reader/writer/pipeline and producers finish before network cleanup;
management-event errors also follow teardown. Linux monitor blocking jobs are tracked for
TCP and UDP. 931 host Rust tests PASS; Linux is cross-checked only. Other UDP tasks, nested
transport workers, forced cancellation and command deadlines remain open.

**UDP ownership and rollback ordering, 23 September 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect and the Linux monitor share one group. Management-event errors follow
normal cleanup; the group finishes before platform-candidate inspection/rollback. TaskHandle
preserves join ownership across cancelled waits and path transfer. Nine new regressions;
940 host Rust tests PASS, Linux is cross-checked only. Nested transport workers, forced
cancellation, command deadlines and platform fault injection remain open.

**Nested H2 tasks, 23 September 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
The TCP group starts before connect and joins drivers/bridges; the native runner retains
it across attempt cancellation. Nine new regressions, 956 Rust tests PASS; Linux is
cross-checked only. Server H2 is covered by the subsequent [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, early platform rollback, UDP cancellation and deadlines remain open.

**Linux monitor commands, 23 September 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
three read-only route/address queries use the shared runner with a 15-second deadline
and output limits. TaskGroup retains the blocking command during stop; failed samples
do not publish PathUpdate. 1098 Rust tests and 23 production-adapter scenarios PASS.
Route mutations, overall shutdown deadlines and actual Linux handover remain open.

**Failed route mutations, 23 September 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): a failed add/replace/retirement
is reversible only after the failed destination is confirmed unchanged; unavailable,
changed or multi-line snapshots produce unknown state. Fifteen new regressions plus
eight existing route tests now run on host; 1128 Rust tests PASS. Baseline reproduction
has 10 expected failures and 5 controls. Pending ownership/recovery of uncertain routes,
command deadlines and live Linux remain open.

**Route ownership and cleanup, 23 September 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): the journal retains supplied
delete selectors; stale identity no longer authorizes replace/retirement/rollback.
Cleanup verifies absence and keeps failed entries for retry. Sixteen new regressions;
1144 Rust tests PASS. The same adapter tests reproduce 15 baseline failures and one
control. Process-global ownership, pending unknown mutations, atomic identity, command
deadlines and live Linux remain open.

**Scoped route ownership, 23 September 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): setup, guards and roaming receive a
unique owner; cleanup closes admission and handles only that owner's records.
Other Qeli owners cannot borrow the route; interface reuse waits for the old lease.
17 new regressions, 1161 Rust tests PASS; two targeted baseline failures reproduced.
Attach mode does not advertise managed roaming. Cross-process isolation, orphan/pending
operations, TUN workers, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — retirement/restore outcomes:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): deletion requires
confirmed absence; restoration requires the complete previous snapshot. Lost completion
does not negate a confirmed action, and apparent success cannot prove rollback.
16 new baseline failures → 16 PASS; 1177 Rust tests total and nine matrix commands PASS.
Linux runtime was not run. Pending unknown/orphan recovery, cross-process races and
command deadlines remain open; the section status is unchanged.

**2026-09-23 follow-up — pending and orphan records:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): unknown roaming operations retain
reservations without delete authority; every unknown commit closes admission.
Cleanup/reconnect releases pending/orphan entries only after confirmed absence, with
separate final-lease and interface-flush conditions. 17 new regressions/controls;
1194 Rust tests and nine matrix commands PASS. Initial setup mutations, flush postconditions,
durable crash recovery, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — initial setup and flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole share
exact pre/post checks and pending tracking for unknown outcomes. Both interface-flush
families require confirmed empty state or a missing interface verified by link inventory.
8 baseline failures → PASS plus 13 controls; 1214 Rust tests and nine matrix commands
PASS. Linux runtime, command deadlines, other route paths, durable crash recovery
and Q14-F027 workers/FD remain open.

**2026-09-23 follow-up — bounded route/firewall commands:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): routes and kill-switch use the
shared runner: 15 seconds per command, 16 MiB each for stdout/stderr. Gateway inherits
bounds through the iptables helper. Unknown outcomes preserve pending/verification;
unknown IPv4 default routes require protection unless allow_ipv4_leak is explicit.
20 new tests; 1234 Rust tests and nine matrix commands PASS. Overall transaction
deadlines, other route ownership paths, gateway rollback and Linux runtime remain open.

**2026-09-23 follow-up — TUN/TAP, pushed and local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): the active NetworkPlan installer
shares exact pre/post checks, metric verification and ownership/pending tracking.
Unused pushed/local implementations and the second parser were removed.
Malformed route_local inventory prevents mutations. Pending is reconciled after the
independent flush of the Qeli-owned interface. 10 reproducing regressions and 13 controls;
1257 Rust tests and nine matrix commands PASS. Gateway rollback, globals, overall
deadlines, crash recovery and Linux runtime remain open.

### 24. Multipath, bonding and shared budgets

**Source:** `qeli/src/client/mod.rs`, `qeli/src/transport_core/buffer_pool.rs`, `qeli/src/transport_core/carrier.rs`, `qeli/src/transport_core/session.rs`, `qeli/src/server/handler.rs`.

JOIN proof, stream caps, asymmetric RTT/loss, one/all path failures and ordering/starvation. Bandwidth/quota/buffer caps must not multiply by stream count. Resume/reconnect/stream close preserve valid sessions and release obsolete carriers.

**Existing harness/fixtures:** `scripts/roaming_netns_e2e.sh`, `scripts/roaming_tcp_bonding_netns_case.sh`, `scripts/roaming_tcp_starvation_netns_case.sh`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS.**

**4 October — Q24 complete:** [report](../reports/audit-0.8.2/AUDIT-Q24-BONDING.md). Q24-F001
fixes shared-pool starvation on both peers. 2407 units/60 ignored, strict Clippy,
release, 12 Linux scenarios/283 checks, 4 native A/B, 22 Windows ABI and 23 JNI
checks PASS. Historical throughput is not rerun. Overall: 24/37 (64.9%); next Q25.

**TCP and Linux path-monitor ownership, 23 September 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): the common owner closes admission before
abort/join. TCP reader/writer/pipeline and producers finish before network cleanup;
management-event errors also follow teardown. Linux monitor blocking jobs are tracked for
TCP and UDP. 931 host Rust tests PASS; Linux is cross-checked only. Other UDP tasks, nested
transport workers, forced cancellation and command deadlines remain open.

**UDP ownership and rollback ordering, 23 September 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect and the Linux monitor share one group. Management-event errors follow
normal cleanup; the group finishes before platform-candidate inspection/rollback. TaskHandle
preserves join ownership across cancelled waits and path transfer. Nine new regressions;
940 host Rust tests PASS, Linux is cross-checked only. Nested transport workers, forced
cancellation, command deadlines and platform fault injection remain open.

**Nested H2 tasks, 23 September 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
The TCP group starts before connect and joins drivers/bridges; the native runner retains
it across attempt cancellation. Nine new regressions, 956 Rust tests PASS; Linux is
cross-checked only. Server H2 is covered by the subsequent [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, early platform rollback, UDP cancellation and deadlines remain open.

### 25. Linux CLI and network recovery

**Reconciliation on 4 October:** [Q25 final](../reports/audit-0.8.2/AUDIT-Q25-LINUX-CLI-FINAL.md). F216/F217 fixed; 2414 units, 26 CLI/68 checks, 2 connected/32 checks and four fresh A/B pairs PASS. Unchanged network implementations reconciled by SHA/exact shared prefix; earlier recovery/soak scopes and D06 accepted limitation retained. Historical open wording below describes earlier snapshots.

[Q25-F067–F068](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md): gateway binds RouteOwner;
firewall operations check namespace/TUN internally, and cleanup precedes TUN release.
Lost TUN permits rule cleanup in the original namespace while retaining the sysctl scope.
13 new host tests, 1485 Rust PASS; 9 baseline regressions reproduced. Internal sysctl
journal/stale recovery and independent kill-switch operations remain open.

[Q25-F065–F066](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md): setup/roaming route commands
verify the original TUN through Weak and its held namespace; physical rollback is independent.
Identity loss is terminal, including callback and final FIB query. 13 new host tests,
1472 Rust PASS; four new native tests compiled only. Gateway/firewall/sysctl callback
internals, physical uplinks and post-check races remain open.

[Q25-F063–F064](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md): route cleanup checks a held
namespace and original TUN before each command; rename/delete/unknown retain reservations,
while physical bypass cleanup remains independent. 13 new host tests, 1459 Rust PASS;
three native route tests compiled only. Post-check races, setup/roaming TUN identity
and physical uplinks remain open.

**Source:** `qeli/src/client`, `qeli/src/client_main.rs`, `qeli/src/hooks.rs`.

Endpoint route pinning/same-LAN, full/split, includes/excludes, leak policies/kill switch. Stop/SIGTERM/SIGKILL/reconnect/failed setup: before/after routes/DNS/firewall preserve foreign state. Trusted hooks/password_command, deadlines and honest cleanup status.

**Existing harness/fixtures:** `scripts/test_gateway_nat.py`, `scripts/test_tun_reclaim.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE / PASS.**

**Credential execution and feature isolation, 23 September 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
asynchronous password_command, 30-second deadline, full stdout up to 16 KiB, discarded
stderr and secret-safe failures. Early SIGINT/SIGTERM cancels and reaps the supplier;
client watchers/sampler have a scoped owner. Server-only TUN gate fixed and both isolated
features checked in CI. 883 host Rust tests PASS; four Linux tests cross-checked only.
Server-only check has 23 existing transport dead-code warnings. password_file bounds,
final client task drain and Linux runtime/release checks remain open.

**File credentials and final status, 23 September 2026:**
[Q25-F002 / Q14-F021](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md): file/command share a 16 KiB
zeroizing buffer; regular-file reads use one owned blocking job, keep symlink support,
reject FIFO and await active I/O on ordinary stop/deadline. The final status follows joined
watchers/sampler, including initialized startup-error paths. 895 host Rust tests PASS;
two Unix tests cross-checked only. Non-interruptible I/O may exceed the 30-second budget.
Startup/network rollback, background fault monitoring and Linux E2E remain open.

**Fail-closed network cleanup, 23 September 2026:**
[Q25-F003](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md): forwarding/NAT cleanup must succeed
before an enabled kill-switch is removed; failures retain the barrier and report why.
899 host Rust tests PASS, including four portable fault-injection scenarios. Linux is
cross-checked only. The early begin_connection follow-up is recorded below; real firewall/E2E remain open.

**Core lifecycle failure handling, 23 September 2026:**
[Q25-F004/F005](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md): core startup errors now reach
cleanup/post_down; core teardown errors terminate with failure and retain the enabled
kill-switch while still attempting forwarding cleanup. Six new host regressions include
real ClientCore queue backpressure. 905 host Rust tests PASS; Linux is cross-checked only.
Live Linux lifecycle/firewall tests and complete route/DNS rollback remain open.

**Legacy resolver recovery, 23 September 2026:**
[Q25-F006](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md): failed unlink/chmod and invalid snapshot
payloads no longer count as successful recovery and cannot retire the recovery record.
Eight new Windows host tests pass; three Unix-specific cases are cross-checked only.
913 host Rust tests PASS. Live Linux DNS and propagation of lower-level cleanup errors remain open.

**TUN/route/DNS cleanup propagation, 23 September 2026:**
[Q25-F007–F009](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md): explicit teardown and rollback guards
share bounded failure evidence with the Linux retry loop. Cleanup errors cannot become a
successful signal stop or release the enabled kill-switch. TunnelSetup owns its guard before
core ACK; terminal kick types survive combined cleanup errors. Eight new host tests pass;
two Linux adapter cases are cross-checked only. 921 host Rust tests PASS. Live Linux E2E,
command deadlines and complete generation-task joining remain open.

**TCP and Linux path-monitor ownership, 23 September 2026:**
[Q25-F010/F011](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md): the common owner closes admission before
abort/join. TCP reader/writer/pipeline and producers finish before network cleanup;
management-event errors also follow teardown. Linux monitor blocking jobs are tracked for
TCP and UDP. 931 host Rust tests PASS; Linux is cross-checked only. Other UDP tasks, nested
transport workers, forced cancellation and command deadlines remain open.

**UDP ownership and rollback ordering, 23 September 2026:**
[Q25-F012/F013](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md): active/candidate/draining receive,
candidate-connect and the Linux monitor share one group. Management-event errors follow
normal cleanup; the group finishes before platform-candidate inspection/rollback. TaskHandle
preserves join ownership across cancelled waits and path transfer. Nine new regressions;
940 host Rust tests PASS, Linux is cross-checked only. Nested transport workers, forced
cancellation, command deadlines and platform fault injection remain open.

**Cancelled TUN shutdown, 23 September 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Shared TunWorkers retains Unix TUN/Wintun thread ownership through joining, including
cancelled shutdown and a saturated blocking pool. Seven new host regressions; 947 Rust
tests PASS. The Unix descriptor test was cross-compiled only. Real devices/drivers and
other section scenarios remain unverified; the full audit is still open.

**Nested H2 tasks, 23 September 2026:** [Q25-F015](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
The TCP group starts before connect and joins drivers/bridges; the native runner retains
it across attempt cancellation. Nine new regressions, 956 Rust tests PASS; Linux is
cross-checked only. Server H2 is covered by the subsequent [Q14-F022/F023](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).
Standalone H2, early platform rollback, UDP cancellation and deadlines remain open.

**TUN/DNS system commands, 23 September 2026:**
[Q25-F016/F017](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md): 15 seconds per command, complete
output capped at 16 MiB per stream, child termination and DNS-marker retention on failure.
Diagnostics no longer claim unconfirmed rollback. 986 host Rust tests PASS; two new Linux
process-group tests were cross-compiled only. Route/firewall commands, live Linux and an
overall shutdown deadline remain open; section status stays IN_PROGRESS.

**Shared firewall checks, 23 September 2026:**
[Q14-F026 / Q25-F018/F019](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md): server and Linux
kill-switch share presence/absence/error classification; exact DNS cleanup verifies the
1024 boundary and continues TCP after UDP failure. 17 new host tests, 1016 Rust tests
PASS; two new Unix/Linux scenarios cross-checked only. Q14-F027, command deadlines
and actual backend/runtime validation remain open.

**Server command follow-up:**
[Q14-F032](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md): all five server NAT command launch sites
use the shared runner (15 s; 16 MiB per output stream). Timeout retains DNS ownership;
that pass's matrix of 1073 Rust tests and six separate adapter checks PASS.
Generic NAT outcome, old generations/retry backoff, restart policy, persistent journaling,
overall operation deadlines, remaining system commands and live Linux remain open.

**Linux monitor commands, 23 September 2026:** [Q25-F020](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md):
three read-only route/address queries use the shared runner with a 15-second deadline
and output limits. TaskGroup retains the blocking command during stop; failed samples
do not publish PathUpdate. 1098 Rust tests and 23 production-adapter scenarios PASS.
Route mutations, overall shutdown deadlines and actual Linux handover remain open.

**Gateway WAN, 23 September 2026:** [Q25-F021/F022](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md):
IPv4/IPv6 default-route and fallback queries use the shared bounded runner; cleanup
discovers a WAN only without remembered family targets. Seven new portable regressions,
1105 Rust tests and 33 separate adapter scenarios PASS. Actual Linux firewall and
uncertain mutation ownership remain open.

**Failed route mutations, 23 September 2026:**
[Q25-F023/F024](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md): a failed add/replace/retirement
is reversible only after the failed destination is confirmed unchanged; unavailable,
changed or multi-line snapshots produce unknown state. Fifteen new regressions plus
eight existing route tests now run on host; 1128 Rust tests PASS. Baseline reproduction
has 10 expected failures and 5 controls. Pending ownership/recovery of uncertain routes,
command deadlines and live Linux remain open.

**Route ownership and cleanup, 23 September 2026:**
[Q25-F025/F026](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md): the journal retains supplied
delete selectors; stale identity no longer authorizes replace/retirement/rollback.
Cleanup verifies absence and keeps failed entries for retry. Sixteen new regressions;
1144 Rust tests PASS. The same adapter tests reproduce 15 baseline failures and one
control. Process-global ownership, pending unknown mutations, atomic identity, command
deadlines and live Linux remain open.

**Scoped route ownership, 23 September 2026:**
[Q25-F027/F028](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md): setup, guards and roaming receive a
unique owner; cleanup closes admission and handles only that owner's records.
Other Qeli owners cannot borrow the route; interface reuse waits for the old lease.
17 new regressions, 1161 Rust tests PASS; two targeted baseline failures reproduced.
Attach mode does not advertise managed roaming. Cross-process isolation, orphan/pending
operations, TUN workers, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — retirement/restore outcomes:**
[Q25-F029/F030](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md): deletion requires
confirmed absence; restoration requires the complete previous snapshot. Lost completion
does not negate a confirmed action, and apparent success cannot prove rollback.
16 new baseline failures → 16 PASS; 1177 Rust tests total and nine matrix commands PASS.
Linux runtime was not run. Pending unknown/orphan recovery, cross-process races and
command deadlines remain open; the section status is unchanged.

**2026-09-23 follow-up — pending and orphan records:**
[Q25-F031/F032](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md): unknown roaming operations retain
reservations without delete authority; every unknown commit closes admission.
Cleanup/reconnect releases pending/orphan entries only after confirmed absence, with
separate final-lease and interface-flush conditions. 17 new regressions/controls;
1194 Rust tests and nine matrix commands PASS. Initial setup mutations, flush postconditions,
durable crash recovery, deadlines and Linux runtime remain open.

**2026-09-23 follow-up — initial setup and flush:**
[Q25-F033/F034](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md): carrier/exclude/blackhole share
exact pre/post checks and pending tracking for unknown outcomes. Both interface-flush
families require confirmed empty state or a missing interface verified by link inventory.
8 baseline failures → PASS plus 13 controls; 1214 Rust tests and nine matrix commands
PASS. Linux runtime, command deadlines, other route paths, durable crash recovery
and Q14-F027 workers/FD remain open.

**2026-09-23 follow-up — bounded route/firewall commands:**
[Q25-F035/F036](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md): routes and kill-switch use the
shared runner: 15 seconds per command, 16 MiB each for stdout/stderr. Gateway inherits
bounds through the iptables helper. Unknown outcomes preserve pending/verification;
unknown IPv4 default routes require protection unless allow_ipv4_leak is explicit.
20 new tests; 1234 Rust tests and nine matrix commands PASS. Overall transaction
deadlines, other route ownership paths, gateway rollback and Linux runtime remain open.

**2026-09-23 follow-up — TUN/TAP, pushed and local routes:**
[Q25-F037–F039](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md): the active NetworkPlan installer
shares exact pre/post checks, metric verification and ownership/pending tracking.
Unused pushed/local implementations and the second parser were removed.
Malformed route_local inventory prevents mutations. Pending is reconciled after the
independent flush of the Qeli-owned interface. 10 reproducing regressions and 13 controls;
1257 Rust tests and nine matrix commands PASS. Gateway rollback, globals, overall
deadlines, crash recovery and Linux runtime remain open.

**Gateway rollback and protection, 23 September 2026:**
[Q25-F040–F042](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md): TUN/family/subnet records
replace global flags and config-based undo. Failed families retain retry state;
unknown firewall inspection cannot authorize insertion, and reused permits also
verify kill-switch order. Router operations include sysctl release under the same
process lock. Eight baseline failures → PASS; 25 new tests and five existing tests
newly enabled on host; 1287 Rust tests and nine matrix commands PASS.
Shared exit-node WAN/NAT ownership, multiple kill-switch chains, cross-process
races, overall deadlines and Linux runtime remain open.

**Exit NAT and kill-switch admission, 23 September 2026:**
[Q25-F043–F045](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md): NAT comments distinguish
TUN/WAN rules; cleanup no longer discovers unowned WAN targets. Public kill-switch
startup checks both families before mutation and rejects other/legacy Qeli chains.
The first carrier remains reachable; concurrent starts in one process admit one
policy. 13 baseline failures → PASS; 30 new tests, two obsolete helper tests removed.
1315 Rust tests and nine matrix commands PASS. Interprocess races, stale TUN identity,
IPv6-protection discovery and Linux runtime remain open.
Follow-up: [Q25-F046–F047](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md) —
cross-process protected-session ownership and refusal on unknown IPv6.
Linux runtime for the new lease tests remains open; section status is unchanged.

[Q25-F048–F049](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md): positive ipv6.disable=1 evidence
permits skipping IPv6 firewall; the shared lease reserves every Linux client's TUN,
including gateway/exit without kill-switch and dev_attach. 17 new host tests,
3 baseline FAIL → PASS. Linux runtime and full section PASS remain open.

[Q25-F050–F051](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md): unknown sysctl owners are retained and
acquire/recovery reports an error; failed sysctl observation preserves original values
for retry. Eight baseline regressions fixed, 1362 Rust tests PASS. Journal namespace
identity, actual Linux runtime and full section PASS remain open.

[Q25-F052–F053](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md): sysctl journal v2 isolates network namespaces,
checks PID/time context and procfs before pruning, and retains nonempty current-boot v1
with an explicit migration error. 24 new tests, 1386 Rust tests PASS. Actual Linux,
namespace identity after object destruction and full section PASS remain open.

[Q25-F054–F056](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md): destructive TUN recovery based on partial
PID discovery was removed. The client passively waits for release and refuses
lookup errors/changed ifindex; client and server create the first queue exclusively.
Later queues use its actual name. 20 new tests, 7 baseline failures, 1406 Rust tests
PASS. Linux example-test compilation without the server feature is fixed.
Attach/teardown races and actual Linux runtime remain open.

[Q25-F057–F058](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md): attach and later queues cannot
register a replacement for a vanished TUN; failed TUNSETIFINDEX stops opening.
VNET_HDR/unknown features are refused, supported flags preserved. 18 new host tests
plus an existing parser test; 1425 Rust PASS. Three new Linux ioctl tests compiled
only. Follow-up ownership work is recorded below.

[Q25-F059–F060](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md): name-based TUN deletion is removed.
Client and server guards retain original descriptors through host cleanup; setup rollback
borrows the device. 12 extracted-code harness scenarios PASS (baseline 7 FAIL / 5 PASS),
1425 Rust PASS. Three added native Linux tests compiled only. External rename/delete,
DNS-marker/route identity and Q14-F027 remain open.

[Q25-F061–F062](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md): only an acquired generation lease
may revert DNS. Namespace/index records and nonblocking ownership locks replace name-only
markers; original-fd checks precede numeric resolver commands. Startup never reverts a
live link solely from a saved marker. 24 new host tests, 1446 Rust PASS; guard harness
baseline 3 FAIL / 3 PASS, fixed 6 PASS. Native namespace test compiled only. Route identity,
resolver service namespace and post-check index reuse remain open.

### 26. Shared C# and managed/native boundary

**Source:** `qeli-shared/QeliShared`, `qeli-shared/QeliConformance`.

Rust validation parity, import/export/storage and handle/callback lifetimes. Mandatory-fixture conformance and platform selftests. Check OS/features/reflection before deleting legacy codecs; builds/selftests do not replace live client connections.

**Existing harness/fixtures:** `conformance/README.md`, `.github/workflows/ci.yml`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS** within available scope; user-excluded platform runtime is SKIPPED.

[Q26 final](../reports/audit-0.8.2/AUDIT-Q26-MANAGED-FINAL.md): four observer/pump-ownership/update-body/route-reader fixes; 543 shared conformance, 143 Windows selftest, Release builds and three negative fixture gates. Actual DLL: 32 handle generations; real Stop timeout/cleanup retry with fake TUN. Native/Rust inputs unchanged. Selftests do not claim a desktop VPN connection with real TUN/firewall or Mac runtime; user exclusions retained.

### 27. Windows GUI, service and drivers

**Source:** `qeli-win/QeliWin`, `qeli/src/transport_core/wintun.rs`.

LocalSystem IPC/ACL/SIDs, DPAPI, protected directories, atomic service profiles and DLL loading. Windows VM: Wintun/WinDivert/per-app, routes/DNS/firewall, stop during connect, sleep/wake and boot service. Cleanup errors remain visible; prevent UAF/double close.

**Existing harness/fixtures:** `scripts/e2e_windows_native.py`, `scripts/verify_windows_drivers.ps1`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE / PASS within agreed scope; VM runtime user SKIPPED.**

**Cancelled TUN shutdown, 23 September 2026:** [Q25-F014](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
Shared TunWorkers retains Unix TUN/Wintun thread ownership through joining, including
cancelled shutdown and a saturated blocking pool. Seven new host regressions; 947 Rust
tests PASS. The Unix descriptor test was cross-compiled only. Real devices/drivers and
other section scenarios remain unverified; the full audit is still open.

**5 October, storage stage:** [Q27-F222–F224](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-STORAGE.md):
DPAPI `.bak` recovery, consistent bounded service files, strict UTF-8 and required-null
validation. 41 new Windows assertions; 184/184 platform + 543/543 shared PASS;
5 old production failures reproduced, Wintun signatures/hash/licenses PASS.
Q27 remains IN_PROGRESS: GUI/SCM/autostart and remaining adapters next;
Windows VM network/sleep/boot runtime remains user SKIPPED.

**5 October, GUI/control stage:** [Q27-F225–F228](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-CONTROL.md):
profile stop/publish/restart preserving intent, SCM pending-state refusal,
scheduler exit/deadline/pipe drains and settings snapshots. 40 new assertions,
224 Windows + fresh543 shared PASS; baseline 8 FAIL. Shared/native inputs unchanged;
managed Git-SHA metadata changed, so the current DLL was tested again. Q27 IN_PROGRESS: existing registration
trust and recovery/status/log/driver adapters next; user runtime SKIPPED retained.

**5 October, service observation:** [Q27-F229–F232](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-OBSERVATION.md): Registration command/account/type/owner/DACL and filesystem recheck before changes; stale/unknown status and terminal cleanup Error, bounded trusted log snapshots/atomic rotation. 273 Windows + 543 shared PASS,49 new assertions,7 baseline FAIL. Q27 IN_PROGRESS; next native loader/driver adapters and final reconciliation. Plan26/37 (70.3%).

**5 October, Q27 complete:** [Windows final](../reports/audit-0.8.2/AUDIT-Q27-WINDOWS-FINAL.md): F233–F239,325 Windows +549 shared PASS,52+6 new checks,12 baseline FAIL. Actual VM driver/network/LocalSystem boot/sleep/service reload user-excluded,not PASS. Available criteria reconciled with the three previous stages. Plan27/37 (73.0%); next Q28.

### 28. macOS daemon, utun, pf and Network Extension

**Source:** `qeli-mac/QeliMac`, `qeli-mac/per-app`.

Daemon IPC/ownership/modes, Keychain, selected profiles, Intel/ARM ABI and DNS journals. Real Mac: preserve foreign pf/nat/rdr anchors; test per-app entitlements, DNS leaks, reconnect, crashes and sleep/wake. Separate GUI/daemon/Network Extension execution.

**Existing harness/fixtures:** `qeli-mac/README.md`, `.github/workflows/ci.yml`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE — available scope PASS; Mac/Xcode/runtime USER SKIPPED.**

**5 October: storage stage PASS.** [F240–F242](../reports/audit-0.8.2/AUDIT-Q28-MACOS-STORAGE.md):54 storage PASS,5 baseline FAIL; Keychain errors/duplicate/key creation races,strict key files/growth budgets,no quarantine on key-provider failures. Actual Mac USER SKIPPED. Next daemon/helper/selected profile/utun/pf/Swift; section remains open. Plan27/37(73.0%).

**5 October: daemon/control stage PASS.** [F243–F248](../reports/audit-0.8.2/AUDIT-Q28-MACOS-CONTROL.md):83 control +54 storage +325 Windows +549 shared PASS;5 baseline expected FAIL. Actual Mac USER SKIPPED. Next utun/pf/DNS/Swift. Plan27/37(73.0%).

**5 October: network cleanup stage PASS.** [F249–F255](../reports/audit-0.8.2/AUDIT-Q28-MACOS-NETWORK.md):117 network +83 control +54 storage +325 Windows +549 shared PASS;10 baseline expected FAIL. Actual Mac USER SKIPPED. Remaining Swift/per-app/build contracts, forwarding ownership/crash recovery and final integration review. Q28 IN_PROGRESS;27/37.

**5 October, final:** [integration F271/F272](../reports/audit-0.8.2/AUDIT-Q28-MACOS-INTEGRATION.md):1248 managed PASS,23 new network checks,4 baseline FAIL;8 new Swift cases not executed. Available criteria reconciled with prior stages; actual Mac/Swift exclusions remain not PASS. Plan28/37(75.7%),9 remain;next Q29.

### 29. Android VpnService, JNI and lifecycle

**5 October, Q29 lifecycle:** [F277 and checks](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LIFECYCLE.md). TUN apply and teardown serialized; join outside monitor. Q29 remains IN_PROGRESS, full VPN/lifecycle not yet qualified. Full plan28/37(75.7%). **167 JVM +23 Android PASS;2 expected baseline FAIL.**

**5 October, Q29 framework service:** [F278 and checks](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SERVICE.md): rejected config preserves current status; five actual lifecycle cases before Auth.167 JVM +28 Android PASS;1baseline FAIL. Q29 IN_PROGRESS,plan28/37(75.7%).

**5 October, Q29 data plane:** [three modes anddual-stack](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):3freshintegrationPASS,48TUN replies;1post-authF278baselineFAIL. ProductAPK/JNI unchanged;167JVM/28Android/1248.NET reused,not fresh. ExplicitVPNNetwork +kernel-source preflight;ordinary default-network selection still open. Q29IN_PROGRESS,28/37(75.7%).

**Source:** `qeli-android/app`.

Protect/TUN retention/generations during reconnect/cancel/stop. Keystore, INI migration, encrypted backups/lost-key recovery; manifest exports/deep links/boot. Device: Wi-Fi/LTE, always-on/lockdown, Doze, process kill, IPv6-only/NAT64 and Release/R8.

**Existing harness/fixtures:** `scripts/roaming_android_sleep_wake_gate.py`, `scripts/roaming_android_udp_grace_expiry_gate.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE within agreed scope; scoped API34 DNS — ACCEPTED_LIMITATION.**

**5 October, storage/package:** [F273–F276](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md):167 JVM/18debug instrumentation PASS;2baseline failures;Release/R8 build andlint(0errors,55warnings),API28 exactness/legacy recovery/backup exclusions. Temporary read-only AVD;host/service/userdata preserved. R8 production UI smoke separately;debug-test APK onminified target unqualified. Q29 IN_PROGRESS;plan28/37(75.7%).

### Q29 closure ledger — 6 October

This ledger selects remaining work; previous completed matrices do not require repetition
without a relevant change. Results remain limited to their exact inputs and tested fixture.
The section checklist is not a statement that every scenario below has passed.

| Layer | Available evidence | Disposition |
| --- | --- | --- |
| INI, Keystore, migration, lost-key/backup, profile editor/export and manifest/package | [F273–F276, F284–F285](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md) | Scoped PASS; physical OEM/D2D and older APIs not executed |
| TUN/plan/protect/observer ownership | [F277](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LIFECYCLE.md), [F282–F283](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md) | Adapter boundaries qualified; no universal OS scheduling claim |
| Actual service commands and Activity permission request ownership | [F278](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SERVICE.md), [F280](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-PERMISSIONS.md) | Scoped PASS; permission waiting/result injection is distinct from OS dialog automation |
| Data, ordinary UID, dual stack, handover, NAT64, per-app/DoT, bounded Doze/flapping and stop blocking | [Release](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md), [NAT64](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-NAT64.md), [per-app](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md), [power/flapping](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-ENDURANCE.md), [trusted DoT](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md) | Scoped PASS; source/readiness publication fixed by [F279](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONNECTED-GATE.md); physical long sessions not qualified |
| R8 instrumentation | [matching runner](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNNER.md) | Opt-in matching runner PASS; default production UI smoke separately qualified; earlier runner FAIL retained |
| External process death | [actual Qeli recovery](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md), [historical independent control](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md) | Actual ordinary R8 Qeli recovered its authenticated NetworkPlan in2.985s after SIGKILL in the13 October run; blocking/manual recovery PASS. The previous automatic recovery FAIL remains historical; this is not new current-APK runtime |
| Generic auto/null DnsResolver | [API diagnostic](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) | User accepted the documented limitation of this API34 image. Original ENONET remains FAIL; independent VPN reproduces it, typed A/AAAA and explicit VPN work. Q29 complete within agreed scope. |
| Whole-section source/dead-code and lifetime reconciliation | [F286–F288](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SOURCE.md),31 Kotlin files, Manifest/resources/R8/22 JNI | Review criterion complete; [F289 fixed](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SETTINGS.md), scoped pre-auth/UI and fresh Release checks. Reference screen alone is not liveness proof. |

Q29 is complete within agreed scope after explicit user acceptance of the documented API34 DNS limitation. Original FAIL results and platform coverage limits are retained; the known ENONET is not claimed fixed. Previous platform skips and D06 are unchanged.

### 30. iOS PacketTunnel, Swift and MDM

**Source:** `qeli-ios/QeliCore`, `qeli-ios/QeliPacketTunnel`, `qeli-ios/QeliIOS`, `qeli-ios/MDM`, `qeli-ios/QeliIOSTests`.

Exactly-once start/stop completion, generation/cancellation, Keychain/app groups and extension memory. Device: On Demand, sleep/wake, captive portals, NAT64/DNS, per-app/MDM and settings rollback. Simulator builds, signed IPA and physical evidence are distinct.

**Existing harness/fixtures:** `docs/eng/reference/IOS-ANDROID-PARITY.md`, `scripts/test_verify_ios_ipa.py`.

- [x] Review and dead code.
- [ ] Positive, boundary and negative scenarios. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Failures and concurrency. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Integration and target platform. — USER_SKIPPED (Swift/Xcode/Apple runtime).
- [ ] Fixes, retesting and evidence. — USER_SKIPPED (Swift/Xcode/Apple runtime).

**Status: DONE within agreed scope: SOURCE REVIEW and portable checks. Swift/Xcode/Apple runtime USER_SKIPPED; XCTest, signed IPA, callbacks, RSS/leaks and network scenarios remain NOT_RUN.**
**12 October reconciliation:** current92 Swift inputs are covered by the source review;91 are byte-identical. Only the `exit_node` test fixture changed to include required `gateway=false`; project.yml adds LICENSE/notices resources. Production Swift/MDM/header inputs are unchanged. Fresh6 Python IPA fixtures,10 plist parses and bindings PASS. The four remaining platform criteria are excluded by the direct user decision about the Mac/iOS lab. Earlier IN_PROGRESS/NOT_RUN entries below are historical checkpoints; they do not establish Swift execution. [Current reconciliation](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md).

[Scoped F290/F291 source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-POLICY-SNAPSHOT.md):
exact MDM numbers and stale provider-reply ownership. Six IPA-verifier fixture
regressions PASS; six added Swift XCTest and Xcode/runtime NOT_RUN (user-excluded
Apple runtime). Whole-section review remains open; no checklist item is closed yet.
Q29 open observations retained; overall28/37(75.7%),9 remain.

[Storage F292/F293 source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-KEYCHAIN.md): Keychain
first-writer identity/TOFU arbitration, no silent ID rotation, explicit key sizes and
removal of the now-unreferenced update API. Seven new Keychain XCTest NOT_RUN;
six IPA fixture regressions/documentation/bindings PASS. Engine/provider shutdown,
read/settings callback lifetime and platform qualification remain open.

Explicit malformed/stale profile options now fail without launching the configured
profile (F294); four selector XCTest NOT_RUN,11 new XCTest in this batch.

[F295–F297 lifecycle source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-LIFECYCLE.md): terminal
monitor Stop, current-engine effects and provider-wide OS leases; shared15s settings
budget, cache invalidation and original completion outcomes.13 new XCTest NOT_RUN;
actual callback draining/lifetime/native joins not runtime-qualified. App/UI/settings
source review remains.6 IPA fixture/docs/bindings PASS; runtime matrices reused only
for unchanged implementations. Q30 IN_PROGRESS,28/37; no checklist item closed.

[F298/F299 app preference source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-APP-PREFERENCES.md):
five status preassignment bypasses removed; full managed reconciliation serialized,
latest settings read at admission and obsolete/cancelled preference work rejected.
Three gate XCTest NOT_RUN;6 IPA fixture/docs/bindings PASS. Provider-message/backup
UI and final memory/dead-code source review remain. Q30 IN_PROGRESS,28/37.

[F300–F302 messages/backup source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-MESSAGES-BACKUP.md):
20s cancellable settings-message wait with session/generation/epoch ownership;
one unfinished snapshot poll per epoch; captured backup passwords and byte-derived
filename.11 new XCTest NOT_RUN;6 IPA fixture/docs/bindings PASS. Actual OS operations
remain callback-owned; final memory/dead-code inventory review remains. Q30IN_PROGRESS.

Wire-crypto membership cleanup F302 excludes remaining Swift cipher/HKDF helpers
from production and includes them in XCTest; unreferenced X25519/auth helpers removed.
Source membership verified, Xcode build NOT_RUN; native binary behavior unchanged.

### Q30 source closure ledger — 6 October

[Current F303–F306 source/memory reconciliation](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md)
completes the Review/dead-code criterion:92 Swift inputs classified;12 single-reference
framework entry points retained; duplicate probe owners removed. Probe start/completion,
profile ping ownership, actual encoded log1MiB/message4KiB and update collector1MiB
are bounded/fenced in source.11 new XCTest NOT_RUN;6 IPA fixtures/docs/bindings PASS.
This latest source disposition supersedes earlier notes that source review remained open;
original execution evidence is unchanged. Actual Swift/Apple runtime/RSS/leaks/callback
and native joins remain unqualified; the other four checklist criteria remain open.
Q30 IN_PROGRESS,overall28/37(75.7%); no platform observation reclassified PASS.

### 31. OpenWrt, LuCI and Keenetic

**Source:** `qeli-openwrt`, `scripts/build_keenetic.py`.

UCI → INI escaping/shell injection, LuCI ACLs, flash secrets, init/procd and upgrade/rollback. ARM/MIPS/mipsel, endian/32-bit ABI and client-only features. Real router: WAN renewal/reboot, DNS/firewall/hooks and memory/throughput; cross-build is not device testing.

**Existing harness/fixtures:** `scripts/keenetic_verify.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE within agreed scope.**

**6 October, F307–F310:** [control/render/firewall packet](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md):7 Node fixtures and10 real-shell fixtures in each BusyBox/dash PASS;37 recipe checks PASS after preexisting stale Android assertion correction. Commit-confirmed UCI intent, serialized controls, atomic0600 INI and checked firewall retry. Scoped fixtures only; full review/install/upgrade/build qualification remain open; actual router runtime USER_EXCLUDED. Overall28/37(75.7%) unchanged.

**F311–F313 continuation, 6 October:** same [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md),14 router-helper fault tests,10 JS caller/adapter fixtures and11 shell fixtures per interpreter PASS. Toolchain failure/false artifact PASS/connection leaks fixed; init-visible status bypasses form cache. Actual ucode/rpcd/rc.common and cross-build NOT_RUN; installation/upgrade and full review still OPEN. No section promoted.

**F314–F315 continuation, 6 October:** [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): retryable owned installation defaults and start guard; shared managed-source replacement with incomplete-sync build guard. Baseline ignored failures/stale inputs reproduced.21 shell tests per BusyBox/dash,7 filesystem source-sync tests,14 router-helper tests,12 shared lab tests,37 native recipes and10 JS fixtures PASS. Real libuci/fw4/procd/package/cross-build NOT_RUN,router USER_EXCLUDED; full upgrade/concurrency/provenance/review remain OPEN. Q31 IN_PROGRESS,28/37 unchanged.

**F316–F319 continuation, 6 October:** [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): checked secret deletion, retryable legacy scrub, failed UCI/duplicate-zone admission, callback status through standard rc.common hooks. Baseline/isolated pre-hooks dispatcher false success reproduced.37 shell/saved-dispatcher cases per BusyBox/dash,11 JS fixtures/37 recipes/docs/bindings PASS. Saved rc.common uses fake lib/UCI/procd; real daemon/ubus/opkg/flock lifecycle unqualified. Q31 IN_PROGRESS,28/37 unchanged; full upgrade/concurrency/build review OPEN.

**F320–F321 continuation, 6 October:** [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): Keenetic canonical bundle names, checked required dependencies, prepared per-file publication and preserved INI; checked ndm mutations, strict OpkgTun suffix and single plan snapshot.20 shell cases per BusyBox/dash,37 recipes/docs/bindings PASS; old name/dependency/false-up/mixed-plan behavior reproduced. Actual opkg/ndm/ELF/cross-build NOT_RUN,router USER_EXCLUDED. Template process/legacy state/idempotence/concurrency and broader review OPEN; Q31 IN_PROGRESS,28/37 unchanged.

**F322–F323 continuation, 6 October:** [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): checked atomic forwarding snapshots, touched-family/interface checkpoints, tagged legacy firewall ownership and failure/retry gates in both Keenetic templates.64 shell model tests per BusyBox/dash (44 new),37 recipes/docs/bindings PASS. Original bad snapshot, forgotten restoration, lost matching admin rules, hidden firewall failures, mode-change and restart gating reproduced. Old untagged checkpoints require manual review; actual router/kernel/comment capability/cross-build NOT_RUN and router USER_EXCLUDED. PID/join/launch/INI parity/OpkgTun concurrency/broader review OPEN; Q31 IN_PROGRESS,28/37 unchanged.

**F324–F325 continuation, 6 October:** [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): verified PID/start ticks/executable, atomic private process record, joined TERM before wrapper cleanup, retained timeout/error state and checked startup/upgrade admission.108 BusyBox/dash cases (43 actual native helper process checks,44 state models,21 installer/hook) and37 recipes/docs/bindings PASS. Safe old/new comparisons reproduce foreign/group PID, early cleanup, ignored TERM and false launch success. No atomic pidfd/interprocess or actual router/core network qualification; shortened polling, old PID upgrade review documented. INI parity/OpkgTun generations/concurrency/packaging/broader source/build review OPEN; Q31 IN_PROGRESS,28/37 unchanged.

**October7, Q31-V003:** actual SDK packaging of a retained musl binary and offline opkg:7PASS without skips; signed release feeds, nft/legacy resolver, install/upgrade/remove and conffile0600. Full SDK Rust compile/source release-cut OPEN; live router USER_EXCLUDED. [Q31 report](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).28/37(75.7%) unchanged.

**October7, F358/Q31-V004:** Rust1.89 client-bin GNU check/full musl compile/link actual SDK macro + GCC13.3 PASS. Unused SDK FFI outputs removed; baseline1FAIL/fixed5real-Cargo methods PASS, SDK3 and18 executable smoke cases PASS. Prebuilt Rust/std, no full SDK bootstrap/release pipeline/router. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).28/37(75.7%) unchanged.

**7 October, F359–F360:** actual procd reproduced stale repeated start and removal of the live client after rejected preparation. INI/password file comparison and rejection of empty set/add fix both; baseline 5 failures in 3 methods, fixed 11 native methods and 55 shell methods on ash/dash PASS without skips. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md). Inert adapter, no VPN/fw/firmware; core generation/ABA/rollback OPEN. 28/37 (75.7%) unchanged.

**7 October,F361:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): runtime NetworkPlan records the existing authenticated generation, distinguishing same-address new generations and within-adapter ABA. Derived baseline2 assertion FAIL/1 PASS; fixed11 Rust units/GNU check/production Clippy/fmt PASS;194 Keenetic methods on each ash/dash without skips(2 new),37 recipes/14 LuCI/docs9/bindings PASS. Writer/lock,counter reset and atomic ndm remain OPEN; no fresh SDK/FFI/cross/firmware claim. Q31 IN_PROGRESS,28/37(75.7%),9 remain;Q29/Q30/D06 retained.

**7 October,F362–F363:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): recheck plan/marker after show, receipt mv and pending rm; fresh OpkgTun init launch invalidates the old process receipt, repeated live start preserves it. Baseline8 failures in4 of5 new methods on each ash/dash; fixed199 methods/interpreter without skips,37 recipes/14 LuCI/docs9/bindings PASS. Real process, modelled ndmc/plan publication;Rust/FFI/SDK/cross unchanged. Writer/lock/after-final-check/atomic ndm/direct launch OPEN. Q31 IN_PROGRESS,28/37(75.7%);Q29/Q30/D06 retained.

**7 October,F364:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): shared router/host/CI exporter pins five Cargo.toml release fields against ambient FFI/environment/home/ancestor overrides. Real-Cargo baseline9assertion FAIL in12cells;fixed8methods/12cells and72Linux helper/gate methods without skips PASS. Actual pinned Zig/cargo-zigbuild x86_64-musl mini baseline unwind|0/fixed abort|3;staticELF validator/execution PASS.37recipes/14LuCI/docs9/bindings PASS. Not current Qeli/clean A-B/4targets/SDK/FFI/CI run;full hermetic/pipeline OPEN. Q31 IN_PROGRESS28/37(75.7%);Q29/Q30/D06 retained.

**7 October,F365/Q31-V005:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): full independent x86_64-musl baseline A/B differed; shared helper remaps owned source paths. Two fresh fixed full Qeli builds byte-identical;9actual-Cargo/72Linux model methods and48INI metadata cases PASS without skips. Verified existing offline registry seed, no network/VPN or published-binary replacement. Other-ISA A/B/full hermetic/SDK pipeline OPEN;Q31 IN_PROGRESS28/37(75.7%);Q29/Q30/D06 unchanged.

**7 October, Q31-V006/F366–F367:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): six fresh full AArch64/ARMv7/MIPS builds yield three byte-identical pairs. Together with SHA-matched sealed F365 x86_64 evidence, all four standalone A/B targets qualify. 72 actual QEMU INI cases/12 CLI calls;15 new release-gate/72 related Linux methods PASS without skips. Gate 2 now uses a private exact committed Git archive and common pins/locked recipe/SHA/ELF admission, rejects dirty inputs, fails configured errors and closes SSH; CI adds its tests. Full live preflight/CI dispatch, SDK bootstrap/source release-cut, full hermetic policy and remaining Q31 source review OPEN; firmware USER_EXCLUDED. Q31 IN_PROGRESS,28/37(75.7%),9 remain;Q29/Q30/D06 retained. No push/deploy.

**7 October, F368–F369/Q31-V007:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md):28-file source review reconciled;first criterion complete. Shared SSH helper fixes stderr receive-window timeout reproduced in four callers;connection/probe failure close and installed-pin diagnostics fixed.16actual SSH checks,8actual probe commands,125Linux methods without skips,78local native contract/docs/bindings PASS. Native provenance was already STALE and remains release-blocking Q34;digest/artifacts not substituted. SDK/pipeline/concurrency limits retained. Q31 IN_PROGRESS,28/37(75.7%),9remain;Q29/Q30/D06 retained.

**7 October, F372:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): exact-commit CI admission fails closed for missing Git/CI identity, bad queries and stale workflows.77router+18CI Linux methods without skips; actual read-only preflight aggregate refusal verified. Positive/boundary/negative criterion complete,2/5criteria; Q31 IN_PROGRESS28/37(75.7%),9remain. Native current/debt14/15+D06 accepted unchanged; SDK/release-cut/ndm boundaries and firmware exclusions retained. No push/release.

**7 October,F373–F375:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): retire saved/partial OpkgTun addresses, preserve ownership across stop/start and stale-plan failure, check current local IPv4 for cached no-op/clearing.218methods per dash/ash without skips;14nonroot CI methods and old hook/init baseline regressions. Cooperative failure/concurrency criterion complete;3/5criteria,Q31IN_PROGRESS,28/37overall. Remaining cross-component/SDK/release integration and exclusions retained; no push/deploy.
**7 October,F376–F378:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): immutable/unique source metadata, committed TOML version and actual SDK mirror checksum admission.25 unprivileged Linux source methods,18CI/15router gates PASS; exact old4fail-open cases reproduced. CI24+1explicit baseline skip. No SDK bootstrap/release-cut/Actions claim; Q31 remains3/5criteria IN_PROGRESS,28/37overall.

**7 October,F379/Q31-V008:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK source archive/check-FIXUP/prepare integration passes on exact candidate crate; old bad mirror download/prepare0 reproduced. Shared prepare/compile verifier stops bad hash before unpack/Cargo,9dash/9ash+25source methods uid65534 PASS;7integration stages with inert Cargo boundary. Full SDK Rust/bootstrap/release-cut/CI separate;3/5criteria IN_PROGRESS,28/37overall.

**October7,Q31-V009:** [live release gate](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): real ARMv7/MIPS release builds through current Gate2 helper,SHA/static ELF PASS;32actual QEMU CLI/INI executions uid65534 PASS,317exact compile inputs. Named tools/defaults and qeli745/901 preserved,own roots cleaned. No new product fix/native refresh/firmware/full preflight/Actions;SDK bootstrap/release-cut/writer-lock/atomic ndm remain. Q31 IN_PROGRESS3/5,28/37overall.

**14 October: cold Rust Host/Compile now attempted.** Prepare/configure and actual bootstrap79s compilation PASS; pinned LLVM CI download returned4HTTP404. Host/Compile FAIL retained; Host/Install/stage2/dist not executed, budget guards did not fire. All6226200078owned bytes removed, host/accounts/staged preserved. Full compiler/cold graph remains OPEN; prebuilt SDK/IPK scope unchanged.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 October: LLVM CI404 remedy executed.** One private-feed flag, prepare/configure/bootstrap and actual source LLVM C++ compilation verified; last Ninja indicator548/3710. Owned guard stopped partial attempt (time); full compiler/SDK graph still open. Root/cache/archive/unit removed, host preserved, original404 retained.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 October: long source compiler stopped by OOM.** LLVM1690/3710; kernel CONSTRAINT_MEMCG/llvm-tblgen, cgroup1152MiB RAM/512MiB swap. Archive/cleanup qualified, host preserved, no SDK build started. Q31 remains IN_PROGRESS; no identical resource retry.33/37,NO_PUSH_DEPLOY_RELEASE.

**14 October: Q36 socket-buffer causal tests.** Two6session/12window series without kernel tracing: tiny send worsened unlimited ACK in all3pairs; separately tested stock/auto receive with held stock send. Actual tb/rb, single INI delta, workload/ACK/topology/host/SHA cleanup qualified; RU/EN CONFIG clarifies explicit0 versus absent key. Product defaults unchanged. Q36 IN_PROGRESS;33/37 (89.2%), NO_PUSH_DEPLOY_RELEASE.

**14 October: Q36 client writer priority.** Fresh6sessions/12windows,nice0/-10 only own writer; actual TID/weight/policy/affinity/config/PID/ACK/host/SHA cleanup qualified. No consistent delay removal; no production adoption. Next direct per-packet stage timing with separate diagnostic build/observer controls.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 October: Q36 direct ACK stage pilot.** Private diagnostic build and2 isolated selector tests,3sessions/6windows stock/OFF/ON, unique exact-header seven-stage identity/cleanup qualified. Distinct ThinLTO artifact and one ordered observer pilot; original shipping cause and observer neutrality still open.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 October: Q36 sampled server handoffs.** Nine exact-header stages, three reversed same-artifact OFF/ON pairs /12windows, deterministic1/16 subset and actual cleanup qualified. Server TUN/forwarding/stream queue times separated; observer ratios and sampling limitations retained.33/37 (89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

**14 October: Q36 recordizer FIFO control.** Three same-diagnostic-artifact policy off/required pairs/12windows; probes ON both, actual one-carrier negotiation and six common exact-header stage identities/cleanup qualified. MUX per-ACK crypto stamps unavailable; observer/batching/deadline/morphology limits explicit.33/37(89.2%),Q36 IN_PROGRESS,NO_PUSH_DEPLOY_RELEASE.

### 32. Metrics, usage, logs and notifications

**Source:** `qeli/src/server/metrics.rs`, `qeli/src/server/usage.rs`, `qeli/src/server/notify.rs`, `qeli/src/server/roaming_metrics.rs`, `qeli/src/trace.rs`, `qeli/src/web/api/logs.rs`.

Counters/quota/session accounting across reconnect/reap/crash, corrupt stores and bounded logs/SSE/backpressure. Notification INI/tokens/load races, SSRF/DNS rebinding/redirects/deadlines/rate limits. Logs reveal no credentials; disabled tracing leaves the hot path unchanged.

**Existing harness/fixtures:** `scripts/test_roaming_control_stats.py`, `scripts/test_blocked_settings.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE/PASS within documented scope.**

**Notification ownership, 23 September 2026:**
[Q14-F018 / Q32-F001](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md): 128 accepted deliveries,
8 active requests per process, shared panel probe admission, bounded payloads and a
10-second drain after producers stop. No detached notification wrappers remain.
864 host Rust tests PASS; Linux all-targets cross-check only. Supervisor panel/metrics/
autostart ownership, config trust and Linux runtime E2E remain open.

**October8,F380–F383:** [Q32 metrics](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md): missing-RPC baseline,guest/CPU resets and PID/starttime fixed;three old metric failures and PID42 collision reproduced;8metrics/36namespace at PID42 and2424library PASS(60ignored),Clippy/daemon PASS.Native/ABI in report evidence.Usage/logs/notify remain open;Q32 IN_PROGRESS,28/37 overall.

**8 October, F384:** [Q32 usage](../reports/audit-0.8.2/AUDIT-Q32-USAGE.md): post-rename fsync failure reproduced; memory retains the published reset, typed cause is preserved and control reports uncertain durability. 16 harness/2426 Linux tests PASS (60ignored), strictClippy/daemon,A-B four cores,WindowsABI22/AndroidJNI23 PASS; report evidence. Store and registration/quota/shutdown reviewed; logs/trace/roaming/notify remain open. Q32 IN_PROGRESS,28/37 overall.

**8 October, F385–F388:** [Q32 logs and trace](../reports/audit-0.8.2/AUDIT-Q32-LOGS-TRACE.md): descriptor-pinned log reads reject raced symlinks/FIFOs, four I/O slots survive caller cancellation, tail preserves complete boundary lines and trace uses atomic0600 publication outside Tokio workers with one admitted dump. Three baseline failures reproduced; extracted harness11/UID65534, real SIGUSR1 twice with65536 ordered rows,2434 library tests (60ignored), strictClippy/daemon and118 Node VM groups PASS. Four current native A/B, WindowsABI22/AndroidJNI23 and final gates in report evidence. Failed preparations/known legacy firewall drift retained; no wholehost claim for initial .10 baseline. Capture/HTTP/disk/physical scope limits retained. Q32 remains IN_PROGRESS; roaming, notification trust/secret-redaction and full integration remain open. Overall28/37(75.7%), nine remain.

**8 October, F389–F394:** [notification INI and delivery](../reports/audit-0.8.2/AUDIT-Q32-NOTIFICATIONS.md): trust enforced before read/save, complete bounded HTTP status and 2xx-only success, query/fragment parsing, conservative special-address guard, post-save cache invalidation and symlink-entry stamps. Three old helper failures plus two actual-library cache failures reproduced; six helper tests, 12 isolated HTTP checks and cache trust/recovery qualify the corrected source. Final library/native counts and guards are in machine evidence. Q32 and Q29/Q30/Q31 scopes remain open; 28/37 overall, nine remain; old debt14 DONE plus D06 accepted.

**8 October, Q32 complete:** all five criteria reconciled across metrics/usage/logs/trace/notifications and unchanged roaming observations; final2439 library, strictClippy/daemon, actual HTTP12/cache, native A/B/ABI22/JNI23 and docs/provenance PASS. Source16 comparisons preserve prior execution scope; physical/TLS/Telegram/browser limits remain documented. Full plan29/37(78.4%),eight remain;Q29/Q30/Q31 and D06 retained.

### 33. Installation, updates, file permissions and hooks

**Source:** `qeli/debian`, `qeli/src/server/update.rs`, `qeli/src/util.rs`, `qeli/src/hooks.rs`, `qeli/src/config_source.rs`, `release/docker`.

Install/upgrade/downgrade/remove, systemd sandbox, identity/user preservation, checksums/attestation and atomic replacement. Docker digest/recreation/health/rollback. File locks/links/owners/ENOSPC, PATH hijacking, panel/restore command injection and SSH deadlines.

**Existing harness/fixtures:** `scripts/test_ssh_run.ps1`, `scripts/release_preflight.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE.**

**Config snapshot trust, 23 September 2026:**
[Q14-F019 / Q33-F001](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md): owner/mode and parsed
bytes now come from the same descriptor; immutable startup authorization survives
profile retries without path rechecks. Ready-generation cleanup keeps its command and
environment after config removal/replacement. 874 host Rust tests PASS; four new Unix/
Linux tests cross-checked only. password_command process bounds, startup ownership,
installer/update/restore and Linux runtime integration remain open.

**Credential execution and feature isolation, 23 September 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
asynchronous password_command, 30-second deadline, full stdout up to 16 KiB, discarded
stderr and secret-safe failures. Early SIGINT/SIGTERM cancels and reaps the supplier;
client watchers/sampler have a scoped owner. Server-only TUN gate fixed and both isolated
features checked in CI. 883 host Rust tests PASS; four Linux tests cross-checked only.
Server-only check has 23 existing transport dead-code warnings. password_file bounds,
final client task drain and Linux runtime/release checks remain open.

**8 October,F400–F403:** [Q33 Docker entrypoint](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): four baseline defects reproduce per dash/ash; default argv, explicit CLI config and owner-only/no-replace first-run files fixed.34 scenarios/46 actual chroot invocations PASS without skips; deterministic creator and copy/link failures covered. Docker image/daemon, Debian updater/install and full Q33 remain OPEN. Q31 SDK bootstrap deferred on measured2GB RAM/~9GB disk, below upstream8GB/30GB recommendation; no compiler FAIL/PASS claimed.29/37(78.4%),eight remain; exclusions unchanged.

**8 October,F404–F411:** [Q33 server updater](../reports/audit-0.8.2/AUDIT-Q33-SERVER-UPDATER.md): invalid local input, package admission, CRLF/cleanup, full transaction lock, exact install/downgrade identity, restart/PID health and unsafe legacy cache fixed.14 old regression scenarios FAIL;21 final methods/24 updater+1 installer invocations PASS with genuine dpkg fixtures. Exact CI command, ShellCheck and guarded cleanup PASS; production maintainer scripts/systemd/VPN/Docker remain OPEN. Q33 IN_PROGRESS;29/37(78.4%),eight remain; old debt14DONE+D06accepted, Q29/Q30/Q31/exclusions retained. No push/deploy/release.

**8 October,F412–F416:** [Q33 Debian lifecycle](../reports/audit-0.8.2/AUDIT-Q33-DEBIAN-LIFECYCLE.md): private no-replace users creation, pre-unpack state guards, explicit service-user/debconf failure handling, stop-failure removal guard and adduser dependency fixed.10 baseline methods/12 expected failures;16 final methods/24 genuine lifecycle dpkg invocations PASS, exact CI command/lint PASS. Production make/scripts with inert binary/dependencies and account/debconf/systemctl seams; full installer/daemon/Docker OPEN. Own root SHA-backed-up and guarded-cleaned; service777/845 unchanged. Q33IN_PROGRESS,29/37(78.4%),eight remain; old debt14DONE+D06accepted,Q29/Q30/Q31/exclusions retained. No push/deploy/release.

**8 October,F417–F421:** [Q33 binary installer](../reports/audit-0.8.2/AUDIT-Q33-BINARY-INSTALLER.md): copy-failure propagation, exclusive source/full staging, safe state/users, signal exit and remote architecture/metadata/required attestation fixed.14 baseline methods19 expected failures;18 final methods23 invocations(21prefix+2earlywhole) PASS, exact CI and updater21 regressions/lint PASS. Explicit HTTP/account/systemctl/qeli/gh seams; no full installation/VPN/OIDC PASS. Full installer dependency/publication/tuning/health and Docker OPEN. Own root backed-up/guarded-cleaned; service777/845 unchanged. Q33IN_PROGRESS,29/37(78.4%),8remain; old debt14DONE+D06accepted,Q29/Q30/Q31/exclusions retained. No push/deploy/release.

**8 October,F422–F426:** [Q33 installer admission](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-ADMISSION.md): conditional/rechecked dependency setup, qeli/arch/version metadata, exact installed state, required gh and removal of dead QELI_DEB URL branch.12 baseline methods14 failures;18 final methods22 calls(20helpers+2earlywhole) PASS; exact CI/binary18/updater21 regressions/lint PASS. Recipe38/native14 SHA+provenance PASS. Full positive installer/publication/tuning/health/disconnected host/Docker OPEN. Own root backed-up/guarded-cleaned;777/845 unchanged. Q33IN_PROGRESS;29/37DONE78.4%,8remain; Q31 3/5 and all historical open/excluded/accepted items retained. No push/deploy/release.

**8 October,F427–F431:** [Q33 secret/config publication](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-SECRETS.md): static unsafe secret targets, private rename/kept-link copy, staged summary/pending-password recovery, atomic web rewrite/owner600, unique private backups and accurate retained-user notice fixed.14 baseline methods15 expected assertions; final21 methods22 runs(20helpers+1earlywhole+1positivewhole with seams) PASS. Exact CI/admission18/binary18/updater21 regressions/lint/recipes38/native14 PASS. Full actual CLI/parser/identity/users/panel/kernel/service/VPN/Docker and initial config transaction remain OPEN; no automatic rollback/durability/race-pinned-dir claim. Both roots backed-up/guarded-cleaned;777/845 unchanged. Q33IN_PROGRESS,29/37DONE78.4%,8remain; Q31 3/5 and historical open/excluded/accepted items retained. No push/deploy/release.

**8 October,F432–F436:** [Q33 preflight/staged INI](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): explicit host/panel/boolean checks before changes; auto-host before config/identity; exact-one profile header/explicit awk errors; complete private INI stage through CLI/web/final validation, root helper after validation, backup/rename publication. Baseline17methods22expected assertions; fixed21methods28whole(3positive/25refusals), exact CI21/28,78regressions/lint/recipes38/native14/docs9(676Markdown) PASS. Filesystem genuine; CLI/systemctl/kernel seams, actual parser/auth/daemon/VPN/Docker OPEN. Config retained before commit; users/identity/links/tuning/bin/deps/drop-in may change, restart-after-publish not rolled back, prior root override OPEN. Own .11 root backed-up/cleaned;777/845 unchanged. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%,8remain,historical OPEN/USER_EXCLUDED/D06ACCEPTED retained. No push/deploy/release.

**8 October,F437–F438:** [Actual CLI/version](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CLI.md): --version for old binary compatibility, strict fixture argv and unique stage-lock cleanup. Version baseline2fail→2PASS; realCLI initial4lockfail→5PASS, repeatedCI2+5;99regressions/lint/recipes38/native14/docs9(678Markdown)PASS. Genuine debug artifact85ea/SHA37a6 reused for unchanged CLI/parser/trust paths;4laterclient/notify differences, not fullcurrentRust/releaseABI qualification. Real three-profile keys/Argon2/users/panel/INI/link/custom-dropin flows;systemctl/daemon/kernel/preflight-ip seams,VPN/Docker/default-unit-rootrevertOPEN. Package CI added,not executed Actions. Own root backed-up/cleaned,777/845 unchanged. Raw334files41695825bytesSEALED. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%8remain,history/exclusions/D06accepted retained;no push/deploy/release.

**8 October,F439–F441:** [Service user/ownership](../reports/audit-0.8.2/AUDIT-Q33-SERVICE-USER.md): preserve client-links/backups ownership, root0700 receipt directory; validate real state and retain existing override on repair failure; explicitly apply installer default qeli after validation. Baseline ownership2/CLI3 failures;fixed2+10 and117regressions PASS;CI2+10+2,lint3scripts,Rustbin5/Clippy/fmt PASS. Current CLI rebuilt0e01;native A/B evidence refreshed. Real systemd/startup/kernel/VPN/Docker remain OPEN;Q33 IN_PROGRESS,29/37DONE78.4%,8remain. Historical debt/exclusions retained;local dev only.

**8 October, F442–F444 / Q33-F045–F047:** [Systemd](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md): stable nft diagnostics boundary; supervisor SIGHUP with managed shutdown and preserved panel lockouts; bounded root filesystem capabilities. Current CLI a36d/SHA6161 built Rust1.97 offline/locked; bin5 + SIGHUP4 + supervisor23 + Clippy PASS; installer/CLI129 + exact localCI14 + lint PASS. Real manager257 sandbox/reload/restart/root-qeli/invalid-INI recovery qualified in an owned network namespace; root config trust refusal retained. Native A/B/ABI and sealed evidence in report. This closes that scoped manager gate, not whole Q33: actual package/update rollback pipeline, VPN traffic and Docker image runtime remain OPEN. Q33 IN_PROGRESS, 29/37 DONE (78.4%),8 remain; previous exclusions/deferred items/history unchanged; no push/deploy/release.

**8 October:** [DEB/update/remove](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md): actual portable release/jemalloc and production package; genuine apt/dpkg/debconf/CLI/systemd with private DB and explicit unit mapping, final 24 PASS. Successful update, package rollback after broken unit and corrupt ELF, exact configured DB, preserved bytes/UID/mode of config/users/identity/receipts/backups, remove/purge. Three fixture FAIL runs retained; audit helpers repaired, product unchanged. This scoped gate closes; whole binary/kernel installer, release VPN roundtrip, Docker and Actions remain OPEN. Q33 IN_PROGRESS; 29/37 DONE (78.4%), 8 remain; previous status/exclusions retained.

**8 October:** release VPN and package→systemd→VPN: [Q33 DEB](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md). Extracted production release ELF matrix:18 scenarios/376 PASS (TCP/UDP, outer/inner4/6, split, leak, TAP, DNS, MTU, legacy0.7.16). Genuine pinned H-1 client through packaged service:36 PASS, fresh/upgrade/both rollbacks, exact TUN route and clean stop. Original fixture trust FAIL retained; show-identity runs as qeli. Product/native unchanged; host restored, roots SHA-archived/guard-cleaned. Release data-plane and package/service/VPN gates close; full binary/kernel installer and Docker/Actions remain OPEN. Q33 IN_PROGRESS;29/37 DONE78.4%,8remain; previous limits retained.

**8 October,F445 / Q33-F048:** [Full installer/kernel](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): reproduced/repaired false sysctl success; private per-run snapshots/prior files/restore instructions, readback and early tuning path guards. Full QELI_BIN+QELI_SRC and production QELI_DEB:24PASS each with actual manager/CLI/Argon2/MSS/pinned VPN; probing0→1→0 and persistent files restoration. Linux136 regressions without skips/lint PASS, tuning CI added. Initial FAIL retained; host777/845/network/kernel unchanged. Full positive installer/partial kernel recovery gate closes, without global ten-key writes/BBR loading/reboot/empty-OS bootstrap claims; Docker/Actions and previous limits remainOPEN. Q33IN_PROGRESS29/37DONE78.4%,8remain; no push/deploy/release.

**Q33 complete 8 October:** [final reconciliation](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md) maps all five criteria to evidence. F450 closes retained hooks and exact deletion; source/runtime limits remain.

### 34. CI, dependencies, native provenance and release

**Source:** `qeli/Cargo.toml`, `qeli/Cargo.lock`, `.github/workflows`, `native-libs`, `release/certification`.

Feature/debug/release/jemalloc matrices, lockfiles, current advisories/licenses and pinned Actions/SDKs. Independent A/B core rebuilds, hashes/ABI/provenance and driver/APK/IPA signatures. Certification requires real evidence tied to the source SHA, never edited digest/status substitutes.

**Existing harness/fixtures:** `scripts/test_native_recipes.py`, `scripts/test_native_repro.py`, `scripts/test_release_certification.py`, `scripts/release_certification.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE within agreed scope.**

**Credential execution and feature isolation, 23 September 2026:**
[Q25-F001 / Q33-F002 / Q14-F020 / Q34-F001](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md):
asynchronous password_command, 30-second deadline, full stdout up to 16 KiB, discarded
stderr and secret-safe failures. Early SIGINT/SIGTERM cancels and reaps the supplier;
client watchers/sampler have a scoped owner. Server-only TUN gate fixed and both isolated
features checked in CI. 883 host Rust tests PASS; four Linux tests cross-checked only.
Server-only check has 23 existing transport dead-code warnings. password_file bounds,
final client task drain and Linux runtime/release checks remain open.

### 35. Fuzzing, concurrency, DoS and soak

**Source:** `qeli/fuzz`, `scripts/stability_gate.py`.

Fuzz INI/hello/packet/WS/realtls/QUIC/IP/fragments/roaming with retained corpora. Inject acquire/apply/save failures and stop/auth/reload/reap races. Run 30–60 minute smoke and ≥8-hour release soaks measuring RSS/fds/tasks/leases/rules with predefined growth thresholds.

**Existing harness/fixtures:** `qeli/fuzz/README.md`, `scripts/roaming_udp_resource_soak_netns_gate.sh`, `scripts/linux_roaming_release_soak.sh`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: DONE within the verified bounded scope.**

**10 October,F504–F505:** [Stability gate](../reports/BENCHMARK.md): fixed false admission from incomplete/rounded/invalid measurements and removed host-wide cleanup.89Windows/19Linux methods,4workflow lint and actual read-only .11 refusal PASS;service777/845/CLI75bc preserved. No new throughput/soak or wholeQ34/Q35/Q36 completion.30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,Q35-V001:** [Actual bounded soak](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
current isolated runners executed100TCP+100QUIC over440.95s;33assertions PASS,
one session/original workers/TUN, stable fd and sampled RSS<32MiB. Actual
compiled ELF reused after318 compiler-input byte checks; no new compilation.
Logs retained, exact owned root cleaned, lab service/config preserved. Bounded
integration is complete;30–60min/8h,10k, tasks churn and other Q35 levels remain
open. Whole section IN_PROGRESS, overall30/37(81.1%),7remain.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F509/Q35-F006:** [Short control sockets and fault matrix](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
actual deep-TMPDIR SUN_LEN fixed with private /run paths;TCP/UDP/bonding/secondary
consumers migrated.14case executions/320assertions,7liveconcurrent snapshots,
35Linuxscript+7kernelmethods PASS;initial familyFAIL and TCP-only observer
failure retained. Whole Q35 IN_PROGRESS,30/37DONE81.1%,7remain.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**13 October, Q35 final:** [five-criterion mapping](../reports/audit-0.8.2/AUDIT-Q35-FINAL.md) combines actual fuzz, owning-module fault/limits audits, concurrency and current full endurance; original dates, failures and limitations are preserved. Q36 stage observation was executed separately and does not qualify its original cause. The plan is33/37 (89.2%), four sections remain open.

### 36. Benchmarks and measurement methodology

**Source:** `scripts/benchmark.py`, `qeli/src/packet_bench_main.rs`, `test`, `docs/data/benchmarks/benchmark_results.json`.

Pin source/binaries, CPU/governor/affinity/VM contention, MTU/modes and background load. P=1/P=4, up/down/bidirectional, inner/outer v4/v6, TCP/UDP goodput, latency percentiles, loss/jitter, CPU/RSS/auth rate. ≥3 independent runs, median/spread/raw results; 0.8.0 numbers do not represent current development.

**Existing harness/fixtures:** `scripts/bench_bonding.py` (historical, explicitly guarded).

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**Status: IN_PROGRESS.**

### 37. Documentation, test harnesses and dead code

**Source:** `docs`, `qeli/config`, `scripts`, `conformance`, `site`.

Compare keys/defaults/errors with runtime, execute complete examples, verify RU/EN, stable/dev and ABI/benchmark dates. Inspect legacy JSON config, unused dependencies/helpers/routes/flags and disconnected tests. Prove dead code across OS/features/FFI/reflection/generators; regressions must fail on the original defect.

**Existing harness/fixtures:** `scripts/check_docs.py`, `scripts/check_panel.py`, `scripts/test_site_docs.js`, `scripts/sync_version.py`.

- [x] Review and dead code.
- [x] Positive, boundary and negative scenarios.
- [x] Failures and concurrency.
- [x] Integration and target platform.
- [x] Fixes, retesting and evidence.

**11 October, Q37-F001/F002:** [baseline and fixes](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md): restored RU/EN versioned attestation examples; private website selected explicitly with `--site-root PATH`, missing inputs still refuse. Actual website, five negative site scenarios, five RU/EN version methods, 97 native harness/18 certification gate tests PASS. Native provenance STALE and release certification 21 problems remain OPEN; actual current builds and final Linux matrix required. Full Q37 remains open, overall 30/37 DONE81.1%.

**11 October, Q37-F003:** removed6320 unreachable lines from41 retired Python/shell files and an unused legacy JSON config. Refusal stubs retained;42 actual Python refusals/3 shell guards, generated bindings and38 recipe methods PASS. Strengthened existing regression test refused the original dead body. [Evidence](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Runtime/native/benchmark inputs preserved; full Q37 IN_PROGRESS, overall30/37 DONE81.1%.

**11 October,Q37-F004:** [client config parity](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md):84 defaults/81 profile keys+3 logging, REALITY/AWG/shaping/gateway/TOFU/Android docs corrected;8 contract methods/4 old-source negatives/9docs PASS. Factory CLI39 actual admissions:37 accepted+2 expected original refusals. First harness FAIL and full host firewall delta FAIL retained; owned fixture SHA/inactive cleanup complete. Native inputs unchanged/Q35 RUNNING; full Q37 and30/37 DONE81.1% unchanged.

**11 October,Q37-F005:** server134 scalar defaults /268 RU+EN comparisons;68 corrected+66 original INI admissions,126accepted+8refused. Inline comments/section mixing/overlapping listeners fixed;11methods/old-doc negatives/docs/workflows PASS. First/third/fourth host FAIL retained; only nine affected-case invocations repeated, owned SHA/inactive cleanup complete. Native inputs unchanged/Q35 RUNNING; full Q37 IN_PROGRESS,30/37 DONE81.1%.

**11 October,Q37-F006:** all176 consumed INI keys reconciled:134+41 defaults,1 obsolete. Fixed list/option/group/listen/REALITY descriptions;82 actual admission decisions (30accepted/52refused),11 original diagnostic FAIL retained. Shared users.conf error formatting preserves the cause; source Rust probe0/3 before→3/3 after, full CLI rebuild still required. Host gates PASS/FAIL/FAIL, archive and owned-root cleanup verified. [Report](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native digest317e722b stale, Q35 frozen/RUNNING; Q37 IN_PROGRESS,30/37 DONE81.1%.

**11 October, Q37-F007:** reviewed 297 Rust files and 306 edges; OS/features/FFI API retained. Removed direct mio and production tower; actual Cargo locks, 4 Linux graphs and 235 legal packages checked. CI includes 24 Python modules and 14 LuCI scenarios; portable 104 on Windows, Linux 149 and changed import methods PASS without skips. Added suite admission guard and made 23 manual scripts import-inert with unchanged body/literal AST. Router tests use temporary output. Main/fuzz fmt checked. Three host FAIL retained; owned roots SHA-archived and removed. [Report](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native 3538e06c STALE, Q35 frozen RUNNING; Q37 IN_PROGRESS, 30/37 DONE (81.1%).

**11 October, Q37-F008:** local ci-check uses the shared Rust pin and explicit +toolchain, locked tests/Clippy and minimal server/client/FFI checks. Five actual Linux shell fixtures passed and the original runner was rejected; no Rust compilation occurred. Two owned roots SHA-archived/removed; host PASS/FAIL retained. [Report](../reports/audit-0.8.2/AUDIT-Q37-DOCUMENTATION.md). Native 3538e06c STALE, Q35 TCP5300 RUNNING; Q37 IN_PROGRESS, 30/37 DONE (81.1%).

**Q37 DONE: 12 October; agreed scope.**
## 7. Baseline and subsequent commands

Run from the checkout root using the project toolchain; retain one log per invocation.
These commands do not imply permission to run arbitrary network/deployment scripts
mentioned earlier.

```text
python scripts/check_docs.py
python scripts/check_panel.py
node scripts/test_panel_editors.cjs
python -m unittest discover -s scripts -p "test_native_*.py"
python scripts/sync_version.py
python native-libs/provenance.py --check
python scripts/release_certification.py --quiet
```

`site/` is intentionally absent from Git. With the private website available, separately run `node scripts/test_site_docs.js --site-root PATH` and retain hashes of all five checked inputs plus its log. If inputs are unavailable, the website check remains OPEN; other baseline checks run independently.

Run the complete server suite **on Linux**. The same command on Windows has different
cfg coverage. Record the exact target and features:

```text
cargo test --locked --manifest-path qeli/Cargo.toml --workspace -- --test-threads=1
cargo clippy --locked --manifest-path qeli/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path qeli/Cargo.toml --features transport-core-ffi transport_core -- --test-threads=1
cargo run --locked --manifest-path qeli/Cargo.toml --features conformance-gen --bin gen-conformance -- --check
```

Use current [CI](../../../.github/workflows/ci.yml) commands for Windows/macOS/Android/iOS
builds/selftests, preserving environment and fixture guards. Do not automatically carry
forward old Clippy exceptions: record the toolchain and justify each exception. A cross
check is not Linux runtime execution.

## 8. Closing sections and the full cycle

Name new findings `Q<section>-F<number>`, for example `Q01-F001`, avoiding reused
historical A-identifiers. Record impact, preconditions, reachable path, reproduction,
fix and regression evidence. P0/P1 block the affected release until fixed or explicitly
resolved; P2/P3 remain concrete tracked tasks despite successful builds.

After each section, update its register row, attach results and identify the next section.
A changed contract reopens regression checks for its consumers. Final PASS requires all
mandatory sections closed, resolved blockers, justified N/A cases, matching native/source
SHA, physical scenario evidence, reproducible benchmarks and accurate support limits.

**Current queue, 11 October:** finish the remaining Q36 cells and
[methodology checks](../reports/BENCHMARK.md); separate Q35 soak obligations and
Q37 final reconciliation remain open. Sections29–31 and34 close against their
own remaining criteria; user-excluded platforms do not re-enter the queue.

**Historical queue on 24 September:** the [debt register](AUDIT-DEBT.md) below
was dispositioned on3October:14 DONE,D06 ACCEPTED_LIMITATION. The next paragraph
preserves that checkpoint's original obligations, rather than the current queue.

D02 still needs durable namespace identity for global entries after crashes;
then D04 crash recovery and remaining D05/D06 network budgets/resource context.
Lock/I/O, directory-trust, standalone kill-switch and Linux route/TUN checks have
already run within the boundaries documented below. Runtime contracts, the full
integration matrix, other platforms, release A/B, soak and a current benchmark
remain open. Full section statuses are unchanged.

**24 September, D05:** [Q05-F002–F004](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md): async preflight before config locking, shared probe budget, stale-snapshot refusal, owned guard for cancelled backup/restore and bounded restart dispatch. Sections remain IN_PROGRESS; archive operations and full HTTP/systemd E2E remain open.

**D05/D09, backup/restore:** [Q05-F005–F007](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md): shared preparation budget, bounded stdin/output, complete pre-restore snapshot, immediate duplicate refusal and private API-handler roundtrip. Crash/ENOSPC/systemd and other network budgets remain open.

**D02, Q25-F077:** [context inside sysctl transactions](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md) is checked around PID/sysctl I/O and persistence; a transaction cannot continue writing after observed context loss. Other D02 criteria remain open.

D02/D05/D09: [atomic state publication](../reports/audit-0.8.2/AUDIT-Q25-ATOMIC-STATE.md) cleans partial temporary files and syncs the directory on Unix; actual partial-write/fsync fault probes PASS. Other criteria of these groups remain open.

D02/D05/D09: [state-directory and lock identity](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md). Parent trust is closed within the stated boundaries; durable namespace identity and original-interface generation remain D02. The groups are not yet fully closed.

D08/D11/D12: [Android JNI and emulator runtime](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-RUNTIME.md): fixed cargo-ndk cwd/API flag, removed the obsolete JSON-config harness; 154 JVM + 6 instrumentation tests PASS. The fresh dev x86_64 APK is SHA-verified. Release A/B, the full config/runtime contract and other platforms remain open.

D02: [namespace pins](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-PIN.md) retain open fds from admission through the end of the transaction; 1922 Linux + 29 privileged + 8 worker E2E PASS. Durable generation between transactions and after crashes remains open, as does original-interface generation.

D02: [Q25-F083 — original interface sysctl](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md): journal v3 retains fds and refuses when evidence is lost; 3 baseline defects reproduced, 5 additional worker E2E PASS. Unsafe name-based restoration and loss of originals are closed. Durable namespace generation after crashes remains open for global journals; automatic per-interface crash recovery is not promised.

D05: [Q25-F084 — shared DNS deadline](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md): dns/domain share 15 seconds from admission, retaining a partial lease for separate rollback. 3 new Linux regressions PASS. Kill-switch is addressed by the following phases below; NAT/routes and other lock waits remain open.

D05/D09: [Q05-F008 — async health probes](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md): Status/Transport health do not block the executor waiting for `--version`; four shared async slots and a deadline including queue time. 8 new ordinary + 1 privileged HTTP-router test PASS; 2 counterfactual old-behavior checks fail as expected. Whole network mutation budgets and full HTTP/systemd/fault coverage remain open.

D05/D09: [Q25-F085 — shared kill-switch cleanup deadline](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md): 15 seconds include the operation mutex and both families; partial outcomes retain ownership for verified retry. 5 regressions PASS, 2 counterfactual old-behavior FAIL. Engage/refresh are addressed by the following phases below; NAT/routes/gateway and other lock waits remain open.

D05/D09: [Q25-F086/F087 — kill-switch refresh](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md): shared admission/command deadline accounts for resolver time; unknown cannot authorize insertion. 6 new regressions and 5 cleanup reruns PASS; 3 counterfactual old-behavior FAIL. DNS/NSS remains synchronous; the following phase below addresses the engage command budget, while NAT/routes/gateway and other waits remain open.

D05/D09: [Q25-F088/F089 — kill-switch setup and rollback](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md): shared 15-second setup deadline plus a separate shared 15-second rollback deadline; leak overrides cannot accept incomplete rollback. 8 new regressions PASS; 2 counterfactual FAIL, then 8 setup + 6 refresh + 5 cleanup PASS. Full snapshot: 1962 Linux + 30 privileged + 8 worker E2E PASS. Engage/refresh/disengage command budgets are addressed within the stated limits; synchronous DNS/NSS, NAT/routes/gateway, other waits and full D04/D05/D09 remain open.

D05/D09: [Q14-F034 — shared NAT cleanup deadline](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md): profile/startup/final cleanup each share 15 seconds across admission, IPv4/IPv6, exact rules and retired DNS UDP/TCP. Late results cannot succeed; unverified records remain owned. 8 new Linux regressions PASS; 4 counterfactual FAIL, then 8 regressions + 1 privileged exact-rule PASS. Full snapshot: 1970 Linux + 30 privileged + 8 worker E2E PASS. NAT setup/rollback, DNS lease Drop/setup admission, routes/gateway, internal sysctl/I/O and full D04/D05/D09 remain open.

D05/D09: [Q14-F035 — DNS INPUT lease deadlines and retirement](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md): setup and cleanup each receive 15 seconds including queue/UDP/TCP; separate rollback after setup, retirement without lock admission and retained pending evidence. 4 new portable + 7 Linux + 1 privileged regressions PASS; 5 negative controls, then 20 domain + 7 DNS + 8 NAT + 2 native PASS. Full snapshot: 1981 Linux + 31 privileged + 8 worker E2E PASS. NAT setup/rollback, DNS REDIRECT, routes/gateway, internal sysctl/I/O and full D04/D05/D09 remain open.

D05/D09: [Q14-F036 — NAT/forwarding and DNS REDIRECT setup](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md): shared setup and exact rollback deadlines; 10 new regressions, 7 negative controls, 1991 Linux + 31 privileged + 8 E2E PASS. Client routes/gateway, scheduler isolation and full D05 remain open.

D02 closed: [Q25-F090 — namespace generation and journal v4](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md). D04/D05 and other criteria remain. Windows VM, Mac/iOS and router tests are excluded from current scope by user decision, not declared PASS.

D09/D10: [17/17 Linux packet matrix PASS](../reports/audit-0.8.2/AUDIT-Q34-LINUX-MATRIX.md). D13: 100 TCP handovers preserved session/fd but exceeded the RSS criterion; failure retained, debt open.

D05/D09: [Q25-F091 — shared gateway/exit-node deadline](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md): 6 regressions, 6 counterfactual failures, 107 restored gateway and full Linux 2001 + 32 privileged + 8 E2E PASS. Route sequences, internal locks/I/O and scheduler isolation remain open.

D13: [100 release TCP/UDP handovers each](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): 30/30 assertions PASS, RSS growth within the unchanged 32 MiB limit; debug FAIL retained. Full resource/fault coverage and final-source measurements remain open.

D05/D09: [Q25-F092 — shared route transaction deadline](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md): 8 regressions, 6 counterfactual FAILs, 196 restored route tests and full Linux 2009 + 32 privileged + 8 E2E PASS. Executor isolation and internal I/O remain open.

D06/D09: [Q25-F093 — strict resolver configuration check](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md): 3 new tests, 2 counterfactual FAILs, 18 restored DNS, full Linux 2012 + 32 privileged + 8 E2E PASS. A separate probe confirmed cross-netns mutation through a shared D-Bus; bus/service identity still needs a fix.

D06/D09/D10: [Q25-F094/F095 — resolved/D-Bus context and DNS ports](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md): direct unique-owner calls with AUTH GUID, 2023 Linux + 33 privileged + 8 E2E, 17/17 packet matrix (301 assertions), 4 counterfactual FAILs and restored 29 DNS + 1 privileged PASS. Real resolved/custom ports/foreign netns and PID namespace checked. The previous open bus/service identity item is closed within these boundaries; other D06 and D10 criteria remain open.

D04/D06/D09: [Q14-F037 — worker network lease](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md): different control/state paths can no longer bypass admission; baseline deleted 9 live-worker rules. 2027 Linux + 34 privileged + 8 lifecycle and 22 crash/admission/recovery checks PASS. D04 IN_PROGRESS: persistent exact firewall/routes and mixed nft remain open.

D04/D09/D10: [Q14-F038 — persistent server firewall](../reports/audit-0.8.2/AUDIT-Q14-FIREWALL-JOURNAL.md): exact NAT/routing/DNS INPUT/REDIRECT specifications are written before mutation and recovered after SIGKILL/deleted profiles without listing. Backend/namespace/file errors abort startup and retain evidence. 2044 Linux + 35 privileged + 8 lifecycle; 27 recovery checks; 17/17 cases, 301 assertions PASS. D04 remains IN_PROGRESS: client route/DNS/kill-switch and the full mixed nft/firewalld matrix remain open.

D04/D06/D09: [Q25-F096/F097 — DNS state v2](../reports/audit-0.8.2/AUDIT-Q25-DNS-MARKER-STORAGE.md): trusted held directory, validated files and SO_NETNS_COOKIE; v1 remains without automatic migration. Three file defects reproduced on baseline. 2055 Linux + 37 privileged + 8 lifecycle; 17/17 cases, 323 assertions PASS. Client route/kill-switch recovery, legacy global DNS, live persistent TUN, mixed nft/firewalld and sidecar accumulation remain open; D04 IN_PROGRESS.

D04/D09/D10: [Q25-F098 — kill-switch after crash](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REBUILD.md): exact temporary DROP guards retain the prior barrier during setup/rollback and repeated SIGKILL. Real-client baseline passed 14 IPv4 + 13 IPv6 UDP probes; fixed passed 0. 2057 Linux + 39 privileged + 8 lifecycle; 14 runtime checks; 17/17 cases, 339 assertions PASS. D04 IN_PROGRESS: routes, legacy global DNS/persistent TUN and the full mixed firewall matrix remain open.

D04/D09: [Q25-F099 — route ownership attributes](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-ATTRIBUTES.md): usability is separate from delete/replace authority; implicit protocol/metric/source and extra attributes are checked. Baseline deleted 10 operator replacements on the kernel and a real client static bypass. 2068 Linux + 40 privileged + 8 lifecycle; 17/17 cases, 384 assertions PASS. At that stage persistent client route journaling was not implemented; see Q25-F100 below. D04 IN_PROGRESS.

D04/D09: [Q25-F100 — durable physical route journal](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-JOURNAL.md): intent/confirmed ownership, boot/cookie/TUN scope, shared lock and terminal roaming on I/O failure. Baseline left bypass/blackhole after SIGKILL → reconnect → stop (3 FAIL). 2087 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Physical client route recovery is closed within the stated scope; legacy global DNS, live persistent TUN and mixed firewall keep D04 IN_PROGRESS.

D04/D05/D09: [Q25-F101 — legacy global DNS](../reports/audit-0.8.2/AUDIT-Q25-LEGACY-DNS.md): unsafe automatic replay and PID refcount removed; snapshot/holders require manual recovery without reading contents or waiting on locks. Baseline changed the resolver in 4 cases; new contract 47/47 PASS. 2078 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Legacy global recovery closed by safe refusal; live persistent TUN and mixed firewall keep D04 IN_PROGRESS.

D04/D09: [persistent TUN/TAP after SIGKILL](../reports/audit-0.8.2/AUDIT-Q25-PERSISTENT-TUN.md): safe refusal preserves interface/routes/DNS/firewall; recovery succeeds after explicit removal of a verified orphan. 17/17 rows, 506 main assertions; 17 persistent scenarios with 199 detailed checks PASS. No new defect; Rust unchanged. This portion of D04 is closed within the stated boundary; D04 IN_PROGRESS for the full mixed firewall matrix.

D04/D09/D10: [server mixed nft/legacy/firewalld recovery](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md): 16/16 scenarios, 476 checks PASS. Actual per-family backend switches, native nft parse errors, firewalld reload, partial cleanup and manual recovery verified. Unknown absence retains evidence; the lost WAN sysctl witness remains the D02 manual boundary. Rust unchanged. D04 IN_PROGRESS: mixed firewall client kill-switch/DNS/routes packet recovery is still required.

D04 closed: [Q25-F102 and client mixed firewall matrix](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md): 152/152 network cells, 136 SIGKILL/recovery cases, 4880 main assertions and 3224 nested checks PASS. All 4352 direct UDP attempts under protection were blocked; 2624 allowed probes received replies. The shared classifier now handles exact legacy advice; server 16/16, 476 checks reran PASS. Persistent TUN/sysctl/legacy DNS manual boundaries remain. **Debt total: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.** This does not complete full-audit sections; D05/D06 and D09/D10/D13 remain open.

D05/D09: [Q25-F103 — shared DNS/NSS and shutdown](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md): four unfinished calls, queue-inclusive deadline, retained capacity after cancellation and no blocking-pool shutdown wait. 4 baseline failures and 4 fixed PASS; 38/38 hostname cells, 34 crash/recovery, 1220 main and 806 nested checks PASS. 1537 host + 71 config; 2089 Linux + 44 privileged + 8 lifecycle PASS. D05 stays IN_PROGRESS: network-mutation scheduler isolation, internal locks/I/O and whole NetworkPlan/shutdown. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F104 — resolver files before firewall](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md): one bounded snapshot, shared reader/parser with stub checks, exact keyword, comments and retained scope. 7 baseline/fixed pairs; 2 old hangs, all 7 fixed runs clean. 38/38 cells, 34 crash/recovery, 1220 main and 806 nested checks PASS. 1544 host + 71 config; 2098 Linux + 44 privileged + 8 lifecycle PASS. D05 stays IN_PROGRESS: network mutations, internal locks/I/O and whole NetworkPlan/shutdown. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F105 — applying NetworkPlan outside the async executor](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md): a fresh thread retains ownership and the original NET/mount context until adoption or completed rollback; native ACK uses async sleep. 7 new portable + 1 Linux + 1 privileged regressions; synchronous helper counterfactual FAIL, fixed PASS. Real TCP/UDP × TUN-create/ip-up: 4/4 PASS with a responsive current-thread runtime, joined rollback and exact network restoration. 38/38 cells, 34 crash/recovery, 1220 main and 806 nested checks; 1551 host + 71 config; 2106 Linux + 45 privileged + 8 lifecycle PASS. D05 remains IN_PROGRESS: established-tunnel teardown, kill-switch mutations, locks/I/O/diagnostics and whole NetworkPlan/shutdown deadlines. Forced Drop may block until join. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F106 — graceful teardown of established tunnels](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md): shared TCP/UDP TunGuard shutdown preserves DNS → pump join → routes/forwarding and runs network cleanup on one joined worker. Worker failures enter sticky Failures. 5 new portable + 1 privileged test; baseline TCP/UDP produced 0 heartbeat ticks during held cleanup, fixed produced 7–8. 4/4 fixed scenarios and 2/2 explicit restarts after faults PASS; kill-switch retained on failure. 38/38 cells, 34 crash/recovery, 1220 main and 806 nested checks; 1556 host + 71 config; 2111 Linux + 46 privileged + 8 lifecycle PASS. D05 remains IN_PROGRESS: early error/Drop paths, kill-switch mutations, locks/I/O/diagnostics and whole NetworkPlan/shutdown deadlines. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F107/F108 — firewall workers and retained DROP](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md): setup/refresh and all six terminal cleanup paths await owned workers; unconfirmed unhook forbids chain flushing. 8 new regressions, 8 baseline + 12 fixed runtime scenarios; baseline passed 6 UDP probes after cleanup failure, fixed passed 0. 38/38 cells, 34 crash/recovery, 1220 main + 806 nested checks; 1564 host + 71 config; 2119 Linux + 46 privileged + 8 lifecycle PASS. Original wildcard UDP recovery FAIL retained: explicit-bind rerun passed; multi-IP wildcard remains D06/D10. D05 remains open for startup recovery, early Drop, locks/I/O/diagnostics and whole deadlines. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D06/D09/D10: [Q15-F002 — wildcard UDP reply address](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md): pktinfo survives receive through immutable reply/roaming/PMTU paths. Baseline secondary IPv4 connections fail with 96 wrong-source replies; fixed has 8/8 IPv4/IPv6 × plain/obfs connections, 256/256 inner UDP echoes and original refresh-fault recovery PASS. 6 new Linux + 1 privileged regression; 1564 host + 71 config; 2125 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. Wildcard defect closed within report boundaries; overall D06/D10 and D05 remain open. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F109 — startup recovery on a joined worker](../reports/audit-0.8.2/AUDIT-Q25-STARTUP-RECOVERY-TASK.md): lease → routes → DNS, stop awaits the real result/error; successful stop starts no connection. 3 new Linux regressions, 2 baseline + 6 fixed runtime scenarios; baseline heartbeat 0, fixed 7–8, competing claims excluded; stale DNS marker retired, live/busy/foreign/legacy preserved. 1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. D05 remains open: early error/Drop, locks/I/O/diagnostics and the overall deadline. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F110 — pump startup and early rollback](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md): one Linux worker owns guard/fds on fcntl/thread failure; partial-reader join precedes TUN release; recordizer/budget checks precede platform apply. 4 baseline + 8 fixed runtime, 4 cleanup faults + 4 recovery PASS; heartbeat 0 → 7–8. 1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. D05 remains open: other early paths, Drop fallback, locks/I/O/diagnostics and the overall deadline. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F111 — ordered diagnostics writer](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md): one thread, one pending snapshot, joined final write; file I/O outside the async executor. 5 new portable + 1 privileged test; 2 baseline + 4 fixed fsync cases, 2 baseline + 4 fixed TCP/UDP teardown and 2 recoveries PASS. 1569 host + 71 config; 2133 Linux + 48 privileged + 8 lifecycle PASS. D05 remains open: other locks/I/O, early Drop and the overall deadline. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F112/F113 — identity files](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md): ID loads once on a joined worker and temporary identity survives reconnect; TOFU is capped at 1 MiB, corrupt/conflicting pins reject new trust, writes are atomic. 15 new tests; 8 baseline + 8 fixed identity cases, 6 teardown cases and 2 recoveries PASS. 1575 host + 71 config; 2148 Linux + 48 privileged + 8 lifecycle PASS. D05 remains open: synchronous TOFU, other startup I/O/Drop and overall deadlines. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F114 — TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md): one joined thread owns trust-file I/O; stop and timeout retain admitted writes and late errors until terminal result. 9 portable regressions; 16 worker cases + 16 file cases + 6 teardown and 2 recoveries PASS. 1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS. Overall deadlines and other startup I/O/Drop remain D05. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

**4 October, HTTP/WS read batch PASS:** [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md):6 fixes,9 baseline FAIL,11 new tests,2335 Linux PASS,40 live probes+63 transport assertions,request-head ASan/libFuzzer,fresh matrix/soak/four native A/B PASS. At the read batch,Close/control lifecycle and wire-matrix review remained open;Q12 was IN_PROGRESS,overall11/37 (29.7%).

**5 October, Q28 per-app:** [bridge, Swift and build paths](../reports/audit-0.8.2/AUDIT-Q28-MACOS-PERAPP.md): F256–F261;22 managed +10 shell PASS,6 old bridge and5 old shell failures. Swift source review;10 new native cases USER SKIPPED. Q28 IN_PROGRESS; forwarding/guardian/native socket lifetime remain. Plan27/37.

**5 October, Q28 forwarding:** [ownership and recovery](../reports/audit-0.8.2/AUDIT-Q28-MACOS-FORWARDING.md): F262–F264;58 new checks,1208 managed PASS,6 expected baseline FAIL. One Qeli owner per Mac,durable snapshot before sysctl,independent restore/checkpoint/retry. Actual Mac USER SKIPPED. Q28 IN_PROGRESS;guardian/native socket lifetime and integration remain. Plan27/37.

**5 October, Q28 guardian:** [readiness and generation ownership](../reports/audit-0.8.2/AUDIT-Q28-MACOS-GUARDIAN.md): F265–F267;39 per-app (17 new),1225 managed PASS,9 expected old C# FAIL. Swift ownership/10 new cases SOURCE REVIEW / USER SKIPPED. Schema v5,bundle upgrade after joining old guardians;no legacy-state takeover. Q28 IN_PROGRESS;native sockets and integration remain. Plan27/37.

**5 October, Q28 sockets:** [fd lifetime and I/O budgets](../reports/audit-0.8.2/AUDIT-Q28-MACOS-SOCKETS.md): F268–F270,18 new Swift cases SOURCE REVIEW / USER SKIPPED. Serial queue + cancel-handler release,nonblocking deadlines,atomic framework-write watchdog,zero UDP datagrams.1225 related managed PASS do not execute Swift. Q28 IN_PROGRESS;final integration/DNS-PF owner stamps remain. Plan27/37.

**5 October, ordinary Android sockets:** [split/full × three transports](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):6freshPASS,72replies.5/6initialIPv4sources physical after observedCONNECTED;TUNready1–111ms,payload guarded bypreflight. Immediate first-packet andexternal/default routes unqualified;DNS/kill-switch/lifecycle next. ProductAPK/JNI unchanged,Q29IN_PROGRESS,28/37(75.7%).

**5 October,Q29 off-pool/DNS:** [seven cases](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-DATA.md):7newPASS,72off-poolreplies and12systemDNS A/AAAA replies;full without includeRoutes,split without defaults. Valid full kill-switch rejected without OSlockdown. Initial wildcardUDPsink caused6timeouts,pcap confirms fixture wrongsource,fixedsinkPASS. ProductAPK/JNI unchanged;positive lockdown/systemlifecycle open,Q29IN_PROGRESS,28/37(75.7%).

**5 October,Q29 system lifecycle(partial):** [Always-on/lockdown and external process death](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md):actual OS policy,separate UID,blocking after SIGKILL/force-stop, manual recovery and system revoke confirmed. Automatic SIGKILL redelivery FAIL (issue OPEN) despite startCommandResult=3;complete system gate is not PASS. Q29 IN_PROGRESS,28/37(75.7%).

**5 October,Q29 independent Android control:** [minimal Java VpnService](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md):without TUN,restarted after17.40s with flags=1;with TUN,no new PID within45s at both lockdown=0 and lockdown=1. Failure reproduces without Qeli JNI/core;only TUN creation differs at the same lockdown=0. Exact framework implementation/other devices remain unqualified.Product recovery gate remains FAIL,Q29 IN_PROGRESS,28/37(75.7%).

**5 October, Q29 power/TCP recovery:** [three fresh scenarios](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-POWER.md): screen5s, forced IDLE20s and TCP reset/reconnect PASS with identical PID/TUN; both wakes without fresh Auth/NetworkPlan. One bootstrap PASS,10 receipts including delayed fault UDP through TUN after recovery Auth (+0.207s),not permanent discard. Revoke/cleanup and host/service/userdata/power restoration PASS. APK/JNI unchanged;only README changed among296 inputs,295 identical. Long/physical Doze,handover,UDP/QUIC remain;SIGKILL recovery still FAIL.Q29 IN_PROGRESS,28/37(75.7%).

**5 October,Q29 UDP/QUIC recovery:** [four fresh scenarios](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-UDP-RECOVERY.md):2bootstrap PASS,UDP/QUIC×soft/grace-expiry4/4PASS.Soft:new outer port/epoch1 without fresh Auth/plan;full:ordered fallback and exactly1 fresh Auth/plan;PID/TUN/addresses retained.18receipts including2delayed faultUDP through TUN after recoveryAUTH,0receipts in negative windows.Revoke/cleanup/host/service/userdata PASS.1test source changed,295inputs/productAPK/JNI/managed identical;new testAPK.Same-network does not qualify carrier handover;SIGKILLFAIL remains.Q29IN_PROGRESS,28/37(75.7%).

**5 October,Q29 carrier handover:** [actual AVD Network switching](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-HANDOVER.md):UDP/QUIC×Wi-Fi↔Cellular4/4targetPASS,2bootstrap in successful runs,16receipts.New systemhandle/outerport/epoch,Auth/plan2/2,TUNretained.InitialUDPFAIL preserved:incorrect exact-one-commit predicate on LinkProperties update;fixed gate verifies alltargethandles,UDPrepeatPASS,initial strictQUICPASS not repeated.3readonlyattempts,host/service/userdata/cleanup unchanged.296inputs/2APK/JNI/managed identical.AVD/privatebackend;TCPhandover,post-switchIPv6/TCP,NAT64/Release remain,SIGKILLFAIL open.Q29IN_PROGRESS,28/37(75.7%).

**5 October,Q29 TCP handover:** [Wi-Fi↔Cellular](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TCP-HANDOVER.md):2/2PASS,1bootstrap/8receipts. Fresh Auth/NetworkPlan and outerports,PID/TUN/addresses retained,ordinary UID payload after recovery;UDPpathcommit0. Revoke/settings/host/service/userdata/cleanup PASS;296inputs/2APK/JNI/managed unchanged. Harness only,no rebuild. Post-switchIPv6/TCP,NAT64/Release,longpower/flapping,SIGKILLFAIL remain.Q29IN_PROGRESS,28/37(75.7%).

**5 October,Q29 post-switch payload:** [full dual-stack matrix](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md):TCP/UDP/QUIC×Wi-Fi↔Cellular×IPv4/IPv6TCP/UDP24/24PASS,6transitions,3bootstrap/42receipts.IndependentUID,allreplybytes/SHA,sink+TUNpcap;TCPfreshAuth/plan,TUNretained;UDPsoftcommits/Authunchanged. Revoke/settings/host/service/userdata/cleanupPASS.295inputs/productAPK/JNI/managed identical,1testreceiverchange,newtestAPK.AvailableAVDpost-switchpayloadcovered;IPv6only/NAT64,Release,longpower/flapping,SIGKILLFAILremain,Q29IN_PROGRESS,28/37(75.7%).

**5 October, Q29 Release runtime:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md): 24/24 payload probes, six Wi-Fi ↔ Cellular transitions, three UI INI imports, 30 receipts. TCP/UDP/QUIC × IPv4/IPv6 TCP/UDP, independent UID, full replies/SHA and TUN pcap. PID/TUN retained; revoke/cleanup and lab state PASS. Release/testRelease R8, nondebuggable target, lab signing; production rules not relaxed. Matching instrumentation Trace FAIL and four failed attempts retained; UI success does not close them. IPv6-only/NAT64, full Release fault suite, leak matrix, long power/flapping and SIGKILL FAIL remain. Q29 IN_PROGRESS; 28/37 (75.7%).

**5 October, Q29 Release faults:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-FAULTS.md): seven scenarios PASS (screen-off, forced Doze, TCP reset, UDP/QUIC × soft/grace-expiry), three UI imports, twelve initial dual-stack payload probes. PID/TUN retained, wake without fresh Auth/plan, full recovery with fresh Auth/plan; revoke/cleanup and lab state PASS. Same Release pair and all 296 inputs, no rebuild. Two harness failures retained; DEX explains original Trace references without a definition, runner FAIL not called PASS. NAT64, leak matrix, long power/flapping, remaining lifecycle and SIGKILL FAIL remain. Q29 IN_PROGRESS; 28/37 (75.7%).

**5 October, Q29 IPv6-only/NAT64:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-NAT64.md): TCP/UDP/QUIC masking, three Release UI imports, 12 dual-stack TCP/UDP payload probes and 18 receipts PASS. SLAAC/RDNSS WLAN without IPv4, A-only server, DNS64 and actual bidirectional translation confirmed in pcap; revoke/cleanup and fixture state PASS. All 296 inputs and APK/JNI/managed unchanged. Three fixture failures retained; NAT64 handover on fixed-IPv4 Cellular not qualified. Leak matrix, long power/flapping, remaining lifecycle and SIGKILL FAIL remain. Q29 IN_PROGRESS; 28/37 (75.7%).

**5 October, Q29 transition/stop leak probes:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-LEAK-BURSTS.md): four Release runs, 1,056 probes, six handovers and four force-stops. All four physical outgoing paths positively calibrated in sink/pcap; short baseline timeouts not called blocking. No new physical SYN/data/UDP in the qualified window; post-baseline marked requests only through TUN, 192 post-stop probes without reply/receipt/capture. Manual recovery 16 payload probes and revoke/cleanup PASS. Product APK/native/managed unchanged; one test receiver changed, fresh test R8 build. DNS/cold-start/split/per-app, long scenarios and SIGKILL FAIL remain. Q29 IN_PROGRESS; 28/37 (75.7%).

**5 October, Q29 DNS/cold start:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STARTUP-DNS.md): TCP/UDP/QUIC, 864 socket samples, 21 unique-name DNS operations, A/AAAA through TUN; six DNS operations and 144 socket samples without VPN blocked. Twelve manual recovery payloads/revoke/cleanup PASS, eight attempts/538 echo receipts. Immediate delivery after APPLIED FAIL on all three transports (27–247 ms); follow-up 48/48 does not close readiness. Generic DnsResolver ENONET and five failed attempts retained; QUIC test-only journal removes dependence on a missing logcat record, TCP/UDP not repeated. Product APK/native/managed unchanged, fresh test APKs; each run exact pair/source pinned. Cold publication, split/per-app/Private DNS, long scenarios and SIGKILL FAIL remain. Q29 IN_PROGRESS; 28/37 (75.7%).

**October5,Q29 DNS APIs:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md):7diagnostic variants,8no-payload checks,288socket samples/48blocked,4manual recovery/revoke/cleanupPASS. Errors and4failed attempts retained;productAPK/JNI/managed unchanged,newtestAPK. ENONET localized to auto/null;reference points to secureVPN app_netid. Priorreadiness/SIGKILL/runnerFAIL open;Q29IN_PROGRESS,28/37(75.7%).

**October5,Q29 startup state:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STARTUP-STATE.md):336socket/96network samples,callbacktimeline;postAPPLIED56,activeVPN/tun0/dual48,errorsingroup4. ExactCONNECTEDnotmeasured,priorFAILretained.UI XMLmovedto/data/local/tmpafterpreservedFAIL,sameAPK,bothcleanupPASS;48blocked/4manualrecovery/revokePASS.Q29IN_PROGRESS28/37(75.7%).

**5 October,Q29 F279:** [CONNECTED gate](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONNECTED-GATE.md):172unit/5new PASS,lint0errors;3finalRelease runs,960samples,80freshpostCONNECTED/0errors,TCPinclude retainedTUN2transitions. ImmediateACK,UIwaitsforAndroidcallback;historicalAPPLIED/SIGKILL/runnerFAILretained.Q29IN_PROGRESS28/37(75.7%).

**5 October, Q29 Release runner:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNNER.md):7/7 instrumentation PASS,TCP/UDP/QUIC×split/full,72receipts/12DNS. Opt-in R8 ABI rules inferred from pre-R8 references;default production rules unchanged. Trace/LazyKt and Kotlin access FAIL retained;3attempts cleanup/host/userdata PASS. PrivateDNS/per-app/longlifecycle/SIGKILL remain;Q29IN_PROGRESS28/37(75.7%).

**5 October, Q29 per-app/Private DNS:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md):include/TCP and exclude/QUIC on productionR8,112socket/80reply/32expectedblocked,52DNSops/48answers,7states×2UID. No selected-UID physical DNS/fallback after strict-negative;2PCAP/drop0,cleanup/settings/host/userdata PASS. Strict trustedDoT/longpower/flapping/SIGKILL/ENONET remain;Q29IN_PROGRESS28/37(75.7%).

**5 October, Q29 bounded Doze/flapping:** [report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-ENDURANCE.md):TCP/UDP/QUIC,9power phases(30s+2×120s),18WiFiCellulartransitions,36wake/72posthandover payloads,1440burst samples/144poststopblocked,45DNSops/72answers;3PCAP/protectedphysical0/drop0. PID/TUN retained;settings/host/userdata/recovery/revoke PASS. Historical commit false-positive fixed in harness,5regression tests. Bounded AVD matrix covered;physical/OEM longsoak,strict trustedDoT/SIGKILLFAIL/ENONET remain,Q29IN_PROGRESS28/37(75.7%).

**5 October, Q29 trusted DoT:** [Report](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md): TCP/UDP/QUIC strict untrusted/trusted/mismatch/recovery PASS;39DNS/12authenticated answers,36payloads,576bursts/144poststopblocked;3PCAP physicalleaks0/drop0. Temporary labCA/settings/host/userdata cleanup5attempts PASS;2harnessFAIL preserved;dynamicUID fixed/12helper3CLI fresh,product/native/managed unchanged. SIGKILLFAIL/ENONET/otherAPI-OEM-arm64 open;Q29 IN_PROGRESS28/37(75.7%).

**6 October, Q29 F280:** [permission ownership](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-PERMISSIONS.md): same valid-profile adapter suite old3FAIL/fixed3PASS; cancel/profile snapshot/Activity recreation fixed. Fresh179JVM(7new), lint0errors55warnings; defaultR8 TCP real UI connect/reconnect,16payloads/192bursts/13DNS/strictDoT/capturephysical0drop0 PASS. Pending permission phase/result injected; Release instrumentation NOT RUN; four preliminary attempts unqualified, all seven cleanupPASS. Native/server/managed unchanged; SIGKILL/ENONET/otherAPI-OEM-arm64 remain,Q29IN_PROGRESS28/37(75.7%).

**6 October, Q29 trusted Wi-Fi:** [service runtime](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-WIFI.md):3new instrumented PASS,realSSID/background1.2s/WiFiCellularcycle/livepause/250msresume cancellation/kill-switch refusal,16full IPv4IPv6TCPUDP payload receipts. Product/native/managed unchanged;JVM/lint/R8 prior scope retained. 2harnessFAIL preserved,3runtime cleanup/host/userdata PASS;4helper/4CLI fresh. Active-lockdown trustedSSID handover/remaining lifecycle/SIGKILL/ENONET/otherAPI-OEM-arm64 open,Q29IN_PROGRESS28/37(75.7%).

**6 October, Q29 F281:** [trusted Wi-Fi with lockdown](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-LOCKDOWN.md): old Release return misses proactive reconnect and falls back after a transport error; four callback predicates fixed. Fresh182JVM(3new)/lint0errors55warnings/defaultR8; TCP/UDP/QUIC6handover transitions,36ordinary-UID full payloads,864bursts/144poststopblocked,3capture physical0/drop0 PASS. Freshdebug3normal-pause tests/16payloads PASS;15helper4CLI/docs/bindings. Three preliminary harnessFAIL and one pre-runtime SFTP interruption preserved;8runtime cleanup/host/userdata PASS. Native/server/managed unchanged;Release instrumentationNOT_RUN. SIGKILL/ENONET/remaining lifecycle/protect/otherAPI-OEM-arm64 open;Q29IN_PROGRESS28/37(75.7%).

**6 October, Q29 F282:** [socket-protection ownership and trusted-Wi-Fi failures](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md): stale polled requests rejected before carrier/bind/protect side effects under service monitor; sleeps/JNI ACK outside. Same fresh test APK old8/3expected FAIL, fixed8PASS (five new cases), 28 debug full payloads. Fresh182JVM/lint0errors55warnings/defaultR8; TCP/UDP/QUIC6transitions/36ordinary-UID full payloads,864socket samples/144poststopblocked,independent capture physical0/drop0 PASS. All five attempts cleanup/host/service/userdata/address PASS;15helper4CLI/docs/bindings. Three protect cases are Context-attached service adapter fixtures with real JNI sockets; location-switch redaction and queued disconnect exercise actual framework, without claiming permission revoke or a native-join barrier. Native/server/managed unchanged;Release instrumentationNOT_RUN. SIGKILLFAIL/auto-nullENONET and unqualified platform/lifecycle coverage preserved;Q29IN_PROGRESS28/37(75.7%).

**6 October, Q29 F283:** [retired network observer ownership](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md): callbacks check owner/stopping under lifecycle monitor, registration/removal serialized; intentional trusted pause retains its observer. Actual Android registration/real carrier with controlled late delivery on Context-attached service adapter: same fresh test APK old13/5expected FAIL, fixed13PASS; actual framework trusted suite retains28full payloads. Fresh182JVM/lint0errors55warnings/defaultR8 UDP2transitions/12ordinaryUID full payloads/288socket samples/48poststopblocked;independent capture physical0/drop0 PASS. Three runtime cleanup/host/service/userdata/address PASS;15helper4CLI/docs/bindings. Initial module-style helper import failures retained, direct script calls PASS; stale removed-code comments corrected. Native/server/managed unchanged,Release instrumentationNOT_RUN; prior TCP/QUIC matrix retained within old scope. Closure ledger added; SIGKILLFAIL/auto-nullENONET retained;Q29IN_PROGRESS28/37(75.7%).

**6 October, Q29 F284–F285:** [profile editor/export](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md): early Save and missing-package/mode state corrected; unreadable store export reports failure, encryption/write/close moved to IO, failed sink cannot report success. Same corrected test APK old5/4expected FAIL,fixed5PASS; initial3FAIL/premature listener-read diagnostic preserved. Fresh188JVM(6new),lint0errors54warnings/defaultR8 TCP2handover/12full payloads/288socket samples/48poststopblocked,capturephysical0/drop0;5attempts host/userdata/address/server cleanupPASS;15helper6CLI. Private file exports qualified, external SAF/cloud providers not executed. Q29IN_PROGRESS28/37(75.7%);SIGKILLFAIL/ENONET/skips/D06 unchanged.

**F326–F327 continuation, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): exact saved-plan receipt for OpkgTun no-op/MTU changes, literal address matching; matching-zombie recheck after failed exe lookup.120 cases each BusyBox/dash (47 owned native-process,44 state,29 installer/hook),12 new;37 recipes/docs/bindings PASS. Old/current hook and deterministic zombie failures reproduced; initial dash FAIL and orphan NOT_REPRODUCED retained. No actual router/core network or generation/concurrency qualification; INI parity/package/build/source review OPEN. Q31 IN_PROGRESS,28/37 unchanged.

**F328–F329, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): isolated per-run verification checkout/target; shared source sync, no service operations; checked locked single-job host gate, forward normal/build graph, mandatory ELF/hash and meaningful exit/SSH-finally.19 gate tests Windows/Linux,7 real temp-file shared-sync,37 recipes/docs/bindings PASS; actual offline Cargo local-fixture positive/negative graphs PASS. Original forced-service calls, stale sync, false PASS/exit0 and connection leak reproduced with models/temp files. No Qeli build/router qualification; INI parity/OpkgTun concurrency/package/build provenance OPEN.Q31 IN_PROGRESS,28/37 unchanged.

**F330–F331, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): removed both shell INI parsers; client-bin-only core metadata inspection uses bounded loader/strict common parser. Quoted/case/BOM/on parity and exit_node ownership; cached validated preflight, unknown/error reply fails before launch. Fresh Rust1.97 client-bin host debug build/8unit/Clippy/fmt PASS;155cases each BusyBox/dash,16new owners with22actual inspector subcases;16old/current records each shell.37recipes/docs/bindings PASS. Default core outside gated addition unchanged; no FFI/release/cross rebuild or real router networking. Binary/template upgrade together; configuration path is reloaded, generation/concurrency not closed. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37.

**F332–F334, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): shared lifecycle.sh for both init variants, wan.d and installer; atomic mkdir exclusion across whole restart/internal cleanup, under-lock marker recheck, shared library delivery0600. Observed core plan replacement stops L3/save/receipt and retains retry; directory publication targets rejected.165cases per BusyBox/dash,8new concurrent lifecycle and2installer; three old hook/stop/save assertions and old directory publication reproduced.37recipes/docs/bindings PASS. Network/ndm/opkg modeled; owned shell/native helpers real; core/native inputs/artifacts unchanged. Busy events require retry; SIGKILL stale lock needs manual owner review, no auto deletion. Atomic core/config generations/ABA/firmware/build provenance remain OPEN. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37.

**F335–F337, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): private0700 per-run source/target, always upload, no shared manifest restore; --sync compatible, retained owned dirs. Shared SHA-bound ELF class/machine/static admission before atomic publication, ARM EABI5 hard-float; SDK lockfile/metadata guard and one compiler job.45 Linux router methods,20 old/current records,5 actual offline tiny-crate make/Cargo cases,real static ELF positive/GNU debug negative,37recipes/docs/bindings PASS. Initial harness FAIL retained. No fresh Qeli cross/firmware build or full ABI/musl/ISA/toolchain pin/reproducibility claim; native/core/binaries unchanged. Generation/ABA/rollback/firmware remain OPEN; Q29/Q30/D06 retained.Q31 IN_PROGRESS28/37(75.7%),9remain.

**F338–F339, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): one shared target/setup/build policy, Rust1.97.0/MIPS nightly-2026-06-10/Zig0.13.0/cargo-zigbuild0.23.0, checked identities/std/rust-src/installer result. Encoded/ambient compiler flags isolated; dead helper definitions/duplicate build_std removed.52Linux tests/12old-current models/actual offline host Rust1.96ambient→1.97recipe fixture/37recipes/docs/bindings PASS. Initial CLI probe and transient BIN failures retained/repaired; final exact-source rerun. .10 inventory read-only,.11 owned execution,global tools/services unchanged. No Qeli/cross/firmware/SDK/A-B build;hermeticity/config/PATH/sharedcache/uploadrace/fullABI/generation/rollback OPEN. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37(75.7%).

**F340–F341, 6 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): installer backs up binary/init/helper,recovers old bytes/modes on ordinary rename failure/TERM,retains pending/backups on failed restore; updated init/hook/retry admission guarded. Symlink/FIFO targets and linked config directory rejected before package updates.176tests per ash/dash(11new),10old/current records each,37recipes/docs/bindings PASS. Initial read-only arch call assertion FAIL retained/repaired/fullrerun. Native/core/recipes/artifacts unchanged,reused inspector/helper hashes verified. Existing INI preserved;late example/mode600/opkg not rolled back. Older init may ignore guard;manual recovery for SIGKILL/powerloss/root-admin races,full-bundle transaction/generation/firmware/cross remain OPEN. Q29/Q30/D06 retained,Q31 IN_PROGRESS28/37(75.7%).

**F342, October6:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): one shell writer correctly serializes literal quotes/backslashes/edge spaces/Unicode for the shared Rust INI parser; user/volatile obfs_key no longer change during render.4new tests/40 round-trip operations,baseline13mismatches per shell;41full OpenWrt tests ash/dash,11Node/37recipes/docs/bindings PASS.Actual exact-source GNU parser+owned files,UCI/procd/fw models,router USER_EXCLUDED;no VPN handshake/cross/FFI build claim.Initial missing-log compile failure retained,qualified inspector links existing GNU rlib.Core/native/recipes/artifacts unchanged;generation/ABA/firmware/cross and Q29/Q30/D06 limits retained.Q31 IN_PROGRESS28/37(75.7%),9remain.

**F343, October6:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): shared bounded/strict core inspector checks template TUN against dev/device_type=tun/dev_attach even with GATEWAY=no;OpkgTun requires external gateway ownership.20baseline false-admission mismatches per interpreter,8new shell methods/34actual cells;184tests ash/dash,fresh GNU client-bin build/12units/strictClippy/fmt,37recipes/docs/bindings PASS.Initial old C-helper arity timeout retained,new metadata-only adapter fixed,owned process/temp cleanup done;not a product failure.317compile/17fixture Git inputs checked,private manifest rlib-only.Linux client-bin metadata-only change;no FFI/release/cross/firmware/runtime claim.Preflight→launch/config generation/ABA OPEN;Q29/Q30/D06 retained.Q31 IN_PROGRESS28/37(75.7%),9remain.

**F344–F346, 6 October:** [Q31 actual cross matrix](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): all4baseline musl compile FAIL; fixed4real release builds/ELF PASS. Fixed signed statfs magic comparison/MIPS stdAtomicU64 lease counter;CI named pins/jobs1/flag isolation/commonELF. GNU build/strictClippy/fmt,79sysctl+1private native descriptor,52Linux helpers without skips,24static gateway tests each ash/dash,37recipes/docs/bindings;CI YAML/16shell/8actualELF cells PASS.Initial cast/missing-conformance/zero-filter harness records retained. .10owned builds/namedtool additions,services/defaults unchanged;.11owned GNU/netns,repo artifacts unchanged. SDK/ucode/rpcd/configgeneration/ABA/firmware/A-B remain;current completion table in report.Q29/Q30/D06 retained,Q31IN_PROGRESS28/37(75.7%),9remain.

**F347–F349, 6 October:** [Q31 actual ucode/fs](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): pinned OpenWrt24.10/25.12 native interpreters reproduce regex/array-popen failures; literal stdin commands/byte checks now work. Directory false-success and linked runtime write/delete/status admission fixed.14 new methods PASS in all4version/shell combinations; full55OpenWrt tests on ash/dash with24.10,11Node/37recipes/docs/bindings PASS. Initial loader/cleanup harness errors retained separately; old status/link gives7independent failures per version. Private dependency extraction/single-job builds only,.10 unchanged,no services/firewall/network changed. Rust/native inputs/artifacts unchanged. ucode/fs scoped PASS; actual rpcd/UCI/procd/SDK/firmware,configgeneration/ABA and cleanA/B still OPEN. Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F350–F351, 6 October:** [Q31 native RPC/UCI/ACL](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): explicit luci-base/ucode-mod-fs deps; actual missing-fs registration failure reproduced. Shared LuCI validator rejects C0/DEL/oversize/invalid Unicode before ubus NUL truncation; direct callers must exclude unsupported NUL.7 actual chroot rpcd/ubusd/libuci/session ACL tests no skips,11 real UCI→render→common INI values,14 Node tests(3new)/37recipes/docs/bindings PASS. Immutable24.10 stack/private DESTDIR/singlejob,source/artifact/template/Git hashes saved. Setup/nodev/header/global-CLI-vs-session assumptions retained separately; no host services/network/.10 changes or residual owned processes. Rust/native/router inputs unchanged; no new Qeli/FFI/cross build. Real native API scope updates older NOT_RUN; procd/SDK/HTTP/firmware,configgeneration/ABA/A-B remain. Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F352, 6 October:** [Q31 actual procd](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): real official OpenWrt24.10.4 x86 rootfs/non-PID1 procd/ubus/UCI/rc.common supervision; init now preserves service set/add/delete exit status and failed-stop restart gate.7new integration methods PASS,8old false-success failures for missing supervisor/socket reproduced. Full69OpenWrt tests PASS on ash/dash without skips;14Node/37recipes/docs/bindings PASS. Client is inert receipt/sleep, TUN existence marker only, no actual firewall/VPN/host services/network/.10 mutation; owned cleanup verified. SDK remains OPEN (1.7GB free .11); firmware USER_EXCLUDED, HTTP/configgeneration/coreABA/A-B separate. Qeli Rust/native artifacts unchanged; Q29/Q30/D06 preserved,Q31IN_PROGRESS28/37(75.7%),9remain.

**F353–F354, 7 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK24.10.4 exposed recursive ip6tables dependency and wrong LuCI IPK owner/URL; conditional +IPV6:ip6tables and LUCI_MAINTAINER/LUCI_URL fixed.3 SDK/3 actual IPK methods without skips,14 packaged minified JS/14 source JS/37recipes/docs/bindings PASS. Stock IPv6=y and private default-n Kconfig profile qualified; no firmware IPv4-only claim. Offline opkg in an empty root FAIL due to missing dependencies; full install/Rust build/source release-cut/MSRV compatibility/clean A/B OPEN. SDK/feed/IPK/raw retained; only owned completed compiler cache recoverably archived.41historic cases/acceptance/core/ABI/binaries unchanged,.10 untouched,no push. Q31 IN_PROGRESS28/37(75.7%),9remain;Q29/Q30/D06 retained.

**Q31-V002, 7 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual official musl uhttpd24.10.4→native GNU rpcd/ucode/fs/UCI over private socket, mount/net namespaces.6 HTTP methods without skips: login/reader-writer/denials/secrets/5service verbs/UCI apply-confirm/embedded-session rejection/revoke-idle-expiry/packaged JS/malformed recovery PASS. Service process inert; no browser/TLS/firmware/VPN qualification.959 official rootfs files/215links,28rpcd files/19links,7Git inputs verified,cleanup PASS;14JS/37recipes/docs/bindings PASS. Initial fixture FAIL retained; Qeli permissions/code/core/ABI/binaries unchanged. SDK build/install/compiler compatibility,preflight/core generation/ABA,clean A/B OPEN;41historic cases/acceptance preserved.Q31 IN_PROGRESS28/37(75.7%),9remain,Q29/Q30/D06 retained.

**F355, 7 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): Keenetic now inspects and launches one private INI copy, preserving source owner/mode; original edits apply on restart. Installer admits root-owned config directory/tools; links/unsafe paths/copy failures refuse launch, failed join retains recovery. Same actual core/native fixture reproduced baseline atomic rotation in both variants;8new methods, full192 on dash and ash without skips PASS;37recipes/14LuCI/docs9/bindings PASS. Initial global-mv fault fixture failures retained and narrowed to PID publication. Product core/ABI/binaries unchanged;315/317 exact compile inputs, two known portability-only diffs and retained inspector verified, no fresh Rust/cross build. Only owned .11 files/processes, cleanup verified,.10 untouched.41historic cases/acceptance preserved. Root/admin replacement,core plan/ABA,OpenWrt config generation,SDK build/install/compiler/source release-cut,clean A/B OPEN;firmware USER_EXCLUDED. Q31 IN_PROGRESS28/37(75.7%),9remain;Q29/Q30/D06 retained. No push/deploy.

**F356–F357, 7 October:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): real Cargo reproduces compiler-config and intermediate-directory overrides (same baseline4methods/9expected subtestFAIL). Shared pinned rustc lookup/output policy now covers both router helpers, host verification with Rust1.97.0/Clippy and router CI.59router methods(7real-Cargo)/19hostgate model methods without skips PASS; actual tiny test/Clippy/graph,16rendered bash-n steps,37recipes/14LuCI/docs9/bindings PASS.17Git/lab inputs,cleanup verified; private home only,.10/host services/network unchanged. No full Qeli/Zig/cross/SDK/GitHub Actions qualification; project core/ABI/artifacts unchanged. Full hermetic configs/profile/source/PATH/cache/A-B and existing Q31 remainder OPEN.41historic cases/acceptance preserved;Q31 IN_PROGRESS28/37(75.7%),9remain,Q29/Q30/D06 retained. No push/deploy.

**October7,F370–F371:** [native preflight](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): real low-space baseline removes retained A/B fixture;fixed preserves it;36Linux/80local PASS. Isolated source roots,Cargo jobs1,installed pins inventory PASS. Native refresh blocked by disk;two local backups verified,auto-review rejected cleanup and no removal occurred. Native provenance STALE/Q34 OPEN;28/37(75.7%),9remain,Q31/Q29/Q30/D06 scopes retained.

**October7, native/D11/D15:** [current-package reconciliation](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md): four independent A/B,14 SHA/provenance,22 Windows ABI/325 platform/549 .NET/201 JVM/23 Android JNI,2417 Linux library and12 CLI tests/Clippy/debug builds PASS. Preparation failures retained;peak benchmark/VPN matrix/soak not rerun. Debt14/15 DONE+D06 ACCEPTED;full audit28/37(75.7%),9 remain;Q29/Q30/Q31 and exclusions retained.

**October8,F395:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): separate core/hook publication lock eliminates cooperative check-to-command race without lifecycle/startup deadlock. Three expected old-hook failures; four Rust/shell cases per dash/ash,196 existing methods per shell without skips,2444 Linux(60preexisting ignored),strictClippy/client PASS. Native refresh/ABI and raw guards are in scoped packet evidence. Mixed bundles/admin writes, sequential NDM/power loss, firmware exclusions and full SDK/release pipeline remain outside closure; Q31 remains3/5IN_PROGRESS. Full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED;Q29/Q30 unchanged.

**8 October,F396:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): whole preflight requires one clean commit between gates; three old mixed-commit false-PASS cases reproduced.12 whole-program methods,56 Linux related methods uid65534 without skips PASS; Windows78PASS/3pre-existing skips. Snapshot/report identity and120-second certification timeout qualified; optional lab build and production pin/hash unchanged. Current native inputs/artifacts unchanged, SHA/provenance retained; owned Python fixture removed after verified backup. Full SDK/bootstrap/release-cut/successful Actions/preflight remain OPEN; Q31 remains3/5,full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED,Q29/Q30/exclusions retained.

**8 October,F397–F398:** [Q31 CI diagnostics](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): macOS CI output matches guarded per-app-arm64 leaf; old command fails,11 Windows/12 Linux path cases PASS (Windows symlink unavailable). iOS exit-node known-key fixture now uses valid gateway=false shared split mode; seven actual configuration-ABI checks PASS. Swift XCTest/Keychain status(-34018) runtime remains OPEN; old native CI failure reconciled to current PASS provenance, not new Actions success. Source/runtime exclusions and all plan/debt counts retained.

**8 October,F399/Q31-V010:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK nested make broke sed before Cargo; exact admission plus dollar-free substitution fixes it. Official24.10.4 x86/64 Git download/hash/prepare, Rust1.89 prebuilt client compile/link, SDK install/dependency/strip/IPK PASS.6 real-Cargo,7 offline opkg and9 fresh SDK-client OpenWrt userspace cases PASS without skips. Stock toolchain tables repaired a fixture packaging prerequisite; no dependency bypass. Initial rootfs prep/autoremove backup-selection failures retained. SHA-verified backup and guarded own-root cleanup; service unchanged, native14SHA/provenance PASS. Upstream Rust bootstrap/cold-hermetic build, production source-cut and successful current Actions/preflight remain OPEN; firmware USER_EXCLUDED. Q31 remains3/5, full29/37(78.4%),8remain; old debt14DONE+D06accepted,Q29/Q30 retained. No push/deploy/release.

**8 October,Q31-V011:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): previous32-bit builds predated F395; current6c2225cd ARMv7/MIPS full client builds/SHA/static ELF PASS,318exact transferred inputs.32QEMU CLI/INI and14exact production PublicationLock/budget release behavior checks PASS on cortex-a7/24Kc uid65534. No new product regression/ABI/source change;14nativeSHA/provenance PASS. .11 rustup inventory auto-installed a missing named nightly; only that own addition removed with guards/default preserved,probe compiled sequentially on .10. Verified backups,three own roots cleaned,unrelated old root/services retained. Old four-target A/B keeps original source/date;no cfg(test)/firmware/fullVPN/SDK bootstrap/source-cut/current CI success claim. Q31 remains3/5;29/37(78.4%),8remain;Q29/Q30/D06/exclusions retained. No push/deploy/release.

**8 October,F446–F448:** [Docker runtime](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): fixed branch latest publication, Cargo --locked, removed four destructive/status-ignoring legacy harnesses. Real Docker image/runtime26PASS: pinned H1 VPN fresh/recreation/known-image rollback, root0600/readonly volumes, protected-login readiness, bytes/UID/mode preservation, six exit0 without OOM/SIGKILL. Harness FAIL retained; host snapshots/AppArmor/PID777-845 restored, owned root SHA-backed-up/guard-cleaned. Runtime gate closed; compiler multiarch/registry/currentActions and final Q33 command/hook reconciliation OPEN.29/37DONE78.4%,8remain; historical debt14DONE+D06accepted/exclusions preserved; local dev without push/deploy/release.

**8 October,F449/Q33-F052:** [Q33 final reconciliation](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): fixed restore hook-file protection bypass through `..`, quotes and symlink aliases; unknown top-level managed literal variables/globs refuse publication. Exact original Linux collector expected FAIL;14 targeted production helper/gate checks PASS. Full server/native qualification PASS:CLI5/backup49/IO2/Clippy,freshA-B/14SHA/provenance/WindowsABI22. Retained hook snapshot SOURCE REVIEW OPEN;Q33IN_PROGRESS;overall29/37DONE78.4%,8remain. Previous runtime gates reused only for unchanged paths;Q29/Q30/Q31/USER_EXCLUDED/D06ACCEPTED retained. No push/deploy/release.

**8 October,F450/Q33-F053:** [Q33 complete](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): actual two-HTTP-restore baseline executes a replaced harmless marker; fix retains startup/later worker hooks until supervisor exit and refuses exact deletion. Fixed8+later10 runtime, CLI5/backup50/lifecycle1/post_down3/privateIO2/Clippy PASS; fresh native/ABI qualification and raw seal are in the report. Q33 5/5 DONE;30/37(81.1%),7remain. Q29/Q30/Q31/Q34/D06 historical limits preserved; no push/deploy/release.

**8 October, F451–F454 / Q34-F005–F008:** [Rust dependency policy and TLS](../reports/audit-0.8.2/AUDIT-Q34-DEPENDENCY-POLICY.md): removed archived PEM wrapper,der0.8.0 updated to0.8.1;licenses/all-features/locked and audit warnings are hard gates,pinned tools/toolchain. Fresh RustSec DB5701a6d2: baseline0CVE+2warnings/current0CVE0warnings;real license refusals retained. TLS10/unit2445+60ignored/CLI5/14HTTPS/feature+release-checks/Clippy/fmt and Wintun file signatures PASS. Initial fmt/FD/harness failures retained,process fd budget4096;host services preserved. Fresh native qualification and raw seal in report. Q34 IN_PROGRESS,30/37DONE81.1%,7remain;exact-SHA Actions/package/platform/release coverage is not replaced by local checks. NO_PUSH_DEPLOY_RELEASE.

**8 October, F455–F459 / Q34-F009–F013:** [Client supply chain](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): two npm advisories fixed with byte-identical CSS; official Gradle checksum qualified by real positive/corrupt-wrapper checks; NuGet all/transitive/low audit errors and explicit advisory source, actual vulnerable/unavailable-source refusals; WinDivert official archive match/signature/hash/notices positive+4negative PASS. Three Release managed builds, required conformance, Windows selftest and local codec benchmark PASS. braces advisory remains OPEN (no published patch); SDK/locks/other graphs/currentCI/release coverage pending. Native inputs/copies14SHA unchanged; no lab changes. Q34 IN_PROGRESS,30/37DONE81.1%,7remain; established Q29/Q30/Q31/D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F460–F462/Q34-F014–F016:** [SDK/locks](../reports/audit-0.8.2/AUDIT-Q34-SDK-LOCKS.md): exact official SHA512-qualifiedSDK10.0.401/runtime10.0.12;CIglobal-json-file/build_appcwd corrected;35reviewed perRID/config/tools/Linux/singlefile locks with root/referenced missinglock guard.18Windowsgenerate-lockedpairs/7builds/conformance/adapters/codec and exact2Windows+2MacpublishPASS;realoldSDK/drift/hash/missingrefusalsPASS;Linux12graphs24restore/builds2MacpublishPASS,ownedSHAarchive/proc-mountguardcleanup/service745901preserved. Native/CSS/protectedfiles unchanged;standaloneinvokerselftest only,normalrequireAdministrator740 retained. Android locks/remainingpackages/currentCI/sourcecut and bracesOPEN remain;Q34IN_PROGRESS30-37DONE81.1percent7remain;historical debt/Q29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F463–F465/Q34-F017–F019:** [Android dependencies](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-DEPENDENCIES.md): strict transitive project/early-plugin locks, three real lockfiles, SHA256 artifacts+metadata and missing-policy guards. 747 independent HTTPS files match; Windows/macOS AAPT2 checksum admission only. Actual debug/defaultR8/debug-release instrumentation assemblies, locked/offline/lint and fresh201productionJNI JVM PASS; five real default-mode refusals PASS. Initial partial-lock, harness Metaspace and alias404 trials retained; separate lint/in-process Kotlin/oneworker privateVM overrides. SHA-backup/proc-mountguard owned cleanup,777845 preserved; nativee3fb/14SHA/protected unchanged. No device VPN/currentJava17CI/otherOS builds claimed. Q34IN_PROGRESS30-37DONE81.1percent7remain;braces/packages-licenses/currentCI/sourcecut-release and historicalQ29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F466–F468/Q34-F020–F022:** [Maven security](../reports/audit-0.8.2/AUDIT-Q34-MAVEN-SECURITY.md): shared early-plugin/project security versions, KGP2.4.21/Netty4.1.137/BC1.85 and remaining targeted fixes; all318 locked package/version records freshOSV0affected (initial326/19affected/50distinctadvisories). CI Maven fail-closed gate8fixtures/actualJDOMnegative-positive PASS; wrong-password test now AEADBadTagException, nullable reflection checked. Java17 officialSHA private qualification: debug/defaultR8/debug-release instrumentation assemblies/201JVMproductionJNI/lint0errors53warnings/offline-strict PASS;2actualoffline policy/driftrefusals+restoredpositive.104freshHTTPS checksums/626exactinheritedsealed records,obsolete admission removed. First unit compileFAIL and harness/API diagnostics preserved. SHA32720631byte backup/proc-mountguardcleanup777845 preserved; nativee3fb/14SHA/protectedfiles unchanged. License metadata318 obtained, actualNOTICE/native copyleft/source-cut/device runtime/currentActions remain OPEN; freshestCI37765333335 is anotherSHAf84a78d9. Q34IN_PROGRESS30-37DONE81.1percent7remain;F459braces/Q29SIGKILLFAIL-ENONET/Q30/Q31/D06accepted/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F469/Q34-F023:** [Android licenses/NOTICE packaging](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-NOTICES.md): per-variant canonical project AGPL/MPL,Apache2,Maven runtime inventory,original archive identities and preserved JAR/AAR/nested notices; dedicated original-archive ArtifactView,identical variant visit deduplication. Independent extraction current-checksum-admitted63archives/44AAR/24resources PASS;76license declarations inherited sealed review. CI APK index/hash/coordinate/origin gate12negative fixtures. APK qualification/evidence in linked report; native dependency/upstream-source notices,matching source publication/signatures/currentActions/fullrelease remain OPEN. Native e3fb/protected files unchanged; no new nativeAB/JVM/deviceVPN claim. Q34IN_PROGRESS30/37DONE81.1percent7remain; historical Q29/Q30/Q31/F459/D06/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October, F470/Q34-F024:** [Common Cargo legal resources](../reports/audit-0.8.2/AUDIT-Q34-NATIVE-NOTICES.md): 235 checksum-locked packages,458 upstream resources, six exact-VCS supplements; one common bundle and packaging/CI checks. Actual qualification and limitations in linked report. Rust std/toolchain/.NET/upstream-source notices, source publication, OpenWrt immutable source cut and current Actions remain OPEN. Q34 IN_PROGRESS;30/37 DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/USER_EXCLUDED unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F471–F472/Q34-F025–F026:** [Managed notices and Inter font](../reports/audit-0.8.2/AUDIT-Q34-MANAGED-NOTICES.md):67 actual SDK-content-hash/official-catalog checked NuGet/runtime packages,187 shared resources; original upstream bytes and separate SIL OFL1.1/copyright for6 exact embedded fonts.35-lock/globalSDK/runtime binding,offline generator/checker,desktop/CI/app gates.19fixtures/final-source regeneration/four actual publishes/published negative/restored and shell gates PASS; scope and raw qualification in report. Toolchain notices,MicroCom exact source binding/sourcepublication/OpenWrt cut/finalActions/release OPEN. Nativee3fb/14SHA/protected unchanged,labs untouched;no new nativeAB/JVM/device claim. Q34 IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F473/Q34-F027:** [Toolchain runtime/stdlib notices](../reports/audit-0.8.2/AUDIT-Q34-TOOLCHAIN-NOTICES.md):65 original reviewed Rust/Zig/NDK/GCC-MinGW resources,69 embedded files;533 common native files. Offline policy/version/SHA binding,Gradle source InputFile,common CI and all packaging paths. Qualification and exact scope in report. Source publication,old GCC minor linkage/NDK whole archive/OpenWrt immutable source cut/final Actions-signatures-release remain OPEN. Nativee3fb/14SHA/protected preserved;Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F474–F477/Q34-F028–F031:** [Release publication gates](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md):actual tag/clean-source/exact-commit CI admission beforebuild,shared Rust pin,Docker reviewed base digests/common notices,extractedDEB notices gate,allworkflow CI filters.86methods/baselineactualGit/CLI/YAMLparse PASS;official metadata and401/currentCIabsence limits in report. Fullsourcepublication/OpenWrt immutablecut/wholeDockerbuild/currentActions/signatures/release OPEN;nativee3fb/14SHA/protected unchanged,labs untouched. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F478–F479/Q34-F032–F033:** [Attestation/checksums](../reports/audit-0.8.2/AUDIT-Q34-ATTESTATION-CHECKSUMS.md): removed unsupported build provenance for downloaded foreign assets; only actual CI-built DEB remains a subject. Atomic SHA256SUMS publication with consumer-compatible filename/regular-file admission and retained old manifest on failure. Linux11 no-skips/real GNU verify/baseline defect PASS;Windows7+4POSIXskips,release18,recipes38,YAML parse PASS (67distinct methods). SHA-backed-up/guard-cleaned own Python fixture;777845/service/network/native14SHA/protected unchanged. No Docker/native rebuild or hosted signing. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F480/Q34-F034:** [Full Docker build](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-BUILD.md): tag/Cargo/exact-commitCI gate before publication tools/login,fullref/history/actionsread;actual classifier mismatch baseline/refusal and64focusedmethods/YAML PASS. Full fresh amd64 defaultfatLTO/jemalloc pinnedRust/Debian build826.546s/no binaryoverride,exact533image notices/CLI/dependencies and26pinnedVPN/recreation/invalidimage rollback checks PASS. Originalhost restored,own image/source/fixtures archiveSHA-qualified before guarded cleanup;public cache/tools exclusion explicit. Harness refusals/profile restoration retained;explicitunconfined runtime is not defaultAppArmor qualification. Multiarch/currentActions/signatures/sourcepublication remainOPEN;Q34IN_PROGRESS30/37DONE81.1percent7remain;native14SHA/protected/historicalQ29Q30Q31F459D06exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F481/Q34-F035:** [Immutable Docker inputs](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-INPUTS.md): reviewed frontend digest matches previous whole build;fresh registry index/manifest/config SHA checked. Single signed Debian/security snapshot20261008T000000Z,live sources removed,source-scoped expiry only,archive authentication preserved. Actual SHA-pinned amd64 Debian rootfs APT3signatures/62new150total packages/13commands/check/repeat and4signature negatives PASS;66focused methods/2priorrecipe refusals. SHA-backed-up full installedrootfs/guardedcleanup/original777845/network/profiles preserved;initial harness failures retained. No fresh wholeimage/compiler/ARM/hostedActions/release;remaining Q34/historical limits preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F482/Q34-F036:** [OpenWrt source Git flags](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md): actualGit10hidden-input false-PASS reproduced on exactprior gate;scoped ls-files refuses assume-unchanged/skip-worktree on5inputs before pin/hash. Unrelatedflags keep existingboundary.37methodsPASS(25source/12preflight),3existingPOSIX-oldbaseline skips unchanged;sourcecut actualpin/tree mismatch OPEN,pin/hash/SDK untouched. Docs/native14/protected unchanged scope,no lab/network/newcompiler/runtime. Q34IN_PROGRESS30/37DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F483/Q34-F037:** [OpenWrt exact local source cut](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md): stalepin/actual qelitree baseline refused;exact full local dev f4b80a9 pinned,actualSDK24.10.4 download+prepare and second emptyDL/differentURL samearchiveSHA PASS. All 3131 trackedfiles match originalcommit incllicenses/notices;no syntheticcommit. PublicURL unchanged,actualGitHubHTTP422 means publication prerequisite OPEN. Sourcegate/native14/protected/doc checks and scoped evidence in report;no newcompiler/bootstrap/IPK/router/nativeAB/hostedCI claims. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29SIGKILLFAIL-ENONET/Q30/Q31/F459braces/D06accepted/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F484/Q34-F038:** [Fuzz CI inventory](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-INVENTORY.md): actualCargo15targets butoldsmoke/nightly11 omitcontrol_v2/quic_envelope/realtls_client/websocket_frame. Sharedmanifesthelper drives bothconsumers,earlymetadatafailure blocks instead ofemptysmoke;nightlydynamicneeds/output matrix.69localmethodsPASS+10repeatLinuxunits+10actualCI Bash scenarios with controlledcargo receipts inclbaselinegap,15calls/early23failure/malformed/missing/outputpreservation/new16thtarget/externalsymlink refusal. ActualRust/libFuzzer/hostedActions and pinnedfuzztools remainseparate OPEN;no core/native/tree changes,previousOpenWrtcut retainsqelitree. SHA-backed-up fullownedfixture/procmountguards/service777845 preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q35TODO andhistoricalQ29/Q30/Q31/F459/D06/exclusions retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F485–F486/Q34-F039–F040:** [Reproducible fuzz CI](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): pinned nightly/cargo-fuzz,independent146-package lock,locked-fetch/offline/SHA and strict audit. All15 real ASan targets:85,930,590 executions,no crash artifacts;72 Windows+13 Linux methods and actual missing/stale/drift refusals PASS. Exact SDK source recut/prepare3140files/second emptyDL identicalSHA PASS;pin/hash updated. Scope and retained harness failures in report.Q34IN_PROGRESS30/37DONE81.1%,7remain;Q35TODO/historical limits preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F487/Q34-F041:** [Fuzz Actions context correction](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): official SHA-qualified actionlint1.7.12 reproduces two invalid job-env references introduced in previous patch;export single pinned RUSTUP_TOOLCHAIN through GITHUB_ENV instead. Final semantic lint13 regressions/exact Bash export PASS. Previous real85,930,590-case ASan smoke recipe/environment unchanged,not rerun;sealed history preserved. Q34IN_PROGRESS30/37DONE81.1%,7remain;Q35TODO/hostedCI/historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October, F488/Q34-F042:** [Permanent Actions lint](../reports/audit-0.8.2/AUDIT-Q34-WORKFLOW-LINT.md): new CI gate checks every .yml/.yaml with official SHA-pinned actionlint1.7.12. All four baseline workflows already valid; persistent coverage gap closed. Each Windows/Linux:11 unit+8 actual scenarios PASS, including invalid env/new yaml/tampered binary refusal. Owned .11 backed up and removed;777/845 preserved. Core/native/source cut unchanged; hosted CI and other boundaries retained in report. Q34 IN_PROGRESS;30/37 DONE81.1%,7remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9October,F489/Q34-F043:** [MicroCom source binding](../reports/audit-0.8.2/AUDIT-Q34-SOURCE-BINDING.md): compatible0.11.2 retains52API and exact DLL/nuspec commit; full76-file upstream SHA verified,publisher-only exception removed.24actualWindows/Linuxgraphpairs,baseline/fixedCOMconsumer12assertions,187-file bundle regeneration/builds/publishes/conformancePASS. Later incompatible candidates not applied. Scope/cleanup evidence in report;native/qeli tree unchanged. Q34IN_PROGRESS30/37DONE81.1%,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October, F490/Q34-F044:** [Docker latest](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): reproduced old stable tag rollback of latest; separate numeric highest-version admission and shared concurrency group.16 Windows +16 Linux methods,59 related Windows methods and official lint of4workflows PASS. Inputs/output recovered,owned Linux fixture removed,service777/845 preserved. Git-tag inventory/queue/old-ref boundaries and other obligations remain in report. Q34 IN_PROGRESS;30/37 DONE81.1%,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F491/Q34-F045:** [APK builder](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): removed global GradleDaemon SIGKILL/shared cache journal deletion; import-safe main/finally close SSH/SFTP on failures.63 Windows/Linux methods and official lint4workflows PASS; separate PID/mount probe reproduces baseline SIGKILL while fixed orchestration preserves foreign worker/cache. Evidence recovered,owned root removed,service777/845 preserved. No new APK; shared source workspace/expected release signer and previous limits remain open. Q34 IN_PROGRESS;30/37 DONE81.1%,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F492/Q34-F046:** [Private APK snapshot](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): complete committed inputs replace shared source directories/extension filter; locks/legal/Java/conformance retained, owned Cargo/Gradle/output paths. Real APK/JVM and separate-root mutation refusal PASS;71 Windows+22 Linux methods,lint/docs PASS. APK/source SHA-recovered,2owned roots removed,original777/845 retained. Offline/SDK/ENOSPC refusals and release/runtime limits in report;Q34IN_PROGRESS30/37DONE81.1%,7remain;historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F493/Q34-F047:** [Explicit E2E APK](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): four installers require source/size/SHA/native-bound BUILD.json; private transfer,remoteSHA/ADB status and refusal before canonical server restoration.89Windows+18Linux methods,5real transfer/refusal cases with controlledADB,lint/docs PASS; own inputs SHA-recovered/cleaned,original777/845 retained. No real emulator/VPN/release runtime. Q34IN_PROGRESS30/37DONE81.1%,7remain;historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F494/Q34-F048:** [Common release source admission](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): preflight/certification/tag reject hidden Git flags; certification pins and rechecks commit. New certification evidence compatibility retained.165Windows+33Linux methods PASS,own fixture removed,original .11 service retained;no CI dispatch/Rust/APK rebuild.Q34IN_PROGRESS30/37DONE81.1%,7remain;historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F495/Q34-F049:** [Actual publisher certification](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): baseline admitted a failed required case; both release workflows now require --require-certification before DEB build/Docker login.132Windows+41Linux methods and semantic workflow lint PASS; own SHA fixture cleaned,original .11 service retained.No current Actions/OIDC/publication/Rust/APK rebuild.Q34IN_PROGRESS30/37DONE81.1%,7remain;historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October, F496/Q34-F050:** [Refuse packaging without a signer](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): confirmed unsigned archive/Done; build_app.sh now refuses before native/publish and retains old outputs.57 Windows +8 Linux methods,Bash syntax and workflow lint PASS. Signers controlled; actual Mac signature/runtime not tested. Own Linux fixture cleaned,service retained; only SDK copy removed after complete retained-ZIP comparison.Q34 IN_PROGRESS,30/37DONE81.1%,7remain; other limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October, F497–F498/Q34-F051–F052:** [Universal2 and retired resign](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): removed arm64 fallback on lipo failure/missing Intel; full Mach-O graph and every output admitted. Retired unused unchecked SSH-resign helper.58Windows/11Linux methods including2actualLLVM PASS,workflow lint/docs PASS. Synthetic headers,no full payload/signature/Mac runtime; originalservice retained,ownroot cleaned.Q34IN_PROGRESS30/37DONE81.1%,7remain;previous limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, F499–F500/Q34-F053–F054:** [Packager inputs/resources](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): all SSH/SFTP exit paths closed, private workspaces, safe TAR/core before SSH and 4 upload SHA gates.72 Windows/23 Linux methods +3 actual main trials PASS; corruption retains prior ZIP. Controlled signer/synthetic headers,no Mac/signature PASS.48 owned lab files cleaned,service unchanged. NuGet/HTTP duplicates removed after SHA,archives/SEALED retained. Q34 IN_PROGRESS;30/37 DONE81.1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, F501/Q34-F055:** [CI compiler pins](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): removed implicit stable in7jobs,compiler1.97.0 matches reviewed policy; other matrix/nightly choices retained. Actual YAML/exactaction default proof,65methods/actionlint4/docs PASS. Source qualification without hosted Actions/rebuild; native/qeli execution inherited. Q34IN_PROGRESS30/37DONE81.1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F502–F503/Q34-F056–F057:** [CI event/coverage](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): release gate requires push event/exact SHA; green PR merge cannot replace source CI. Paths filters removed, all root policy changes run CI.132Windows/67Linux methods/actionlint4/docs PASS. Actual Git/controlled gh,not hosted Actions.25ownedlabfiles cleaned,service unchanged. Developer docs1.97/locked updated;F459 latest3.0.3/no patch OPEN.Q34IN_PROGRESS30/37DONE81.1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10October,F506–F507:** [Soak admission](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): reproduced zero-loop TCP and downgraded endurance labels; common decimal validation before network actions, smoke/full markers and10k/1k minimum only for full endurance wrapper. Mandatory bounded100 unchanged.28Linux/57Windows methods,4workflow lint PASS;no newVPNsoak/native rebuild.Q34/Q35IN_PROGRESS,30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10October,F508/Q35-F005:** [Runner isolation](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
closed competing TCP/UDP namespace cleanup and shared family-switch hosts.
7 real kernel +35 Linux script methods PASS; SIGINT/TERM/KILL remove descendants,
neighboring processes/config preserved. Only live NAT counters normalized for
structural comparison, raw retained. No new VPN soak claim;
Q34/Q35IN_PROGRESS,30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, Q35 fragment fuzz:** [report](../reports/audit-0.8.2/AUDIT-Q35-FRAGMENT-FUZZ.md): two targets strengthened, 246,813 actual ASan runs PASS; original harness failures retained. Q35 IN_PROGRESS, 30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, Q35 extended roaming:** [report](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): TCP fake-TLS and UDP QUIC ran concurrently for 900 switches each, with 1850.9 seconds elapsed and 1835.9 seconds of verified simultaneous live activity across 368 full process samples. Both scenarios passed without failures; RSS/threads/fds/sockets stayed within predeclared budgets. Service and host firewall structure were preserved; the owned test root was deleted after SHA backup. Full release endurance/eight hours/other adapters remain open. Q35 IN_PROGRESS,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F511/Q35-F009:** [Client INI and qeli:// fuzz](../reports/audit-0.8.2/AUDIT-Q35-CLIENT-CONFIG-FUZZ.md): added canonical reparse invariants for successful inputs and structured IPv4/IPv6/roaming/password-link cases. Pinned ASan:18,494 runs/61s, seven seeds, zero new crash artifacts;701 corpus files and723 evidence files SHA preserved. Initial local harness error retained; own root cleaned, service777/845 unchanged. One target, not complete nightly/DoS. Q35 IN_PROGRESS,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F512/Q35-F010:** [Release-soak admission](../reports/audit-0.8.2/AUDIT-Q35-RELEASE-ADMISSION.md): old gate falsely passed in0.064s with eight silent children. It now requires eight phase results, final TCP10k/UDP10k+3×1k checkpoints and28800s on a monotonic clock. Seven Linux contract tests and Bash syntax PASS; silent child/missing checkpoint/eight hours minus1ns refuse. Actual eight-hour VPN soak remains OPEN,Q35IN_PROGRESS30/37DONE.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**12 October, tested candidate adoption:** [wire pool and actual results](../reports/BENCHMARK.md): 916 inputs matched the qualified build at adoption; two explicitly verified spacing/line-break edits in one file then satisfied rustfmt without changing logic. Four strict feature profiles and 8+1 tests PASS. Twenty-four one-minute AUTH runs /34644 authentications, peak RSS 336320 KiB against the unchanged 524288 limit; composite20+4 evidence preserves the original file-budget refusal and host differences. Twelve fresh native sessions /48 functional IPv4 TCP/UDP P1/P4 windows. Source and CI warning gate adopted. [Q35 endurance](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): five resource scenarios completed; upload6.8627%>5% FAIL, cross-node phase NOT_RUN. Android:23 JNI +2 packaged INI tests verified with the previous x86_64 native; original harness/signature/wlan0 refusals retained, no full VPN runtime claim. Q30 DONE in agreed scope;31/37 (83.8%), Q29/Q31/Q34/Q35/Q36/Q37 remain. Native refresh, hosted CI, performance/cross-node and the remaining criteria of these six sections stay open. `NO_PUSH_DEPLOY_RELEASE`.

<!-- normative-sync: current-pool-native-20261012 -->

### October 12: platform libraries after the pool fix

[Build and runtime results](../../../release/certification/evidence/current-pool-native-20261012.json).
Two independent builds of each of four libraries used source `c0aad62a`:
Android arm64/x86_64, Windows x64 and macOS universal2. Every A/B pair is
byte-identical; both copies of each artifact were updated and provenance/SHA256
checked. Exact export sets passed: 55 per Android ABI and 33 C exports on
Windows and each macOS architecture. The current Windows library passed 22
C ABI checks; Android API34 x86_64 passed 23 JNI checks and 2 packaged INI tests.

Fresh instrumented Release/test APKs and an ordinary unsigned Release contain
both current Android ABIs. R8 and package checks passed. Prior 201 JVM tests
and lint were reused after comparing all 679 input files with the already
qualified repaired projection; this is not a new JVM run through the fresh
native library. The original wlan0 guard refusal is retained. The fresh
fixture waited for carrier (LOWER_UP/state UP) and interface startup and passed strict before/after network
equality. Original AVD, SDK and production services were preserved; owned
runtime/build roots and temporary swap were removed.

The original desktop worker FAIL is retained: the final inventory found only
an empty `.intentionally-empty-file.o`; all 327 inputs matched. Artifacts,
API and C ABI were qualified from the complete SHA-verified archive without
recompilation. The .10 iptables4/legacy4 host-gate FAIL remains; production
process identities and binaries were preserved. Whole-host PASS is not claimed.

The plan remains 31/37 complete (83.8%); Q29/Q31/Q34/Q35/Q36/Q37 are open.
These results close the native-artifact refresh required by the pool change.
Full Android VPN data plane, load limits, TCP asymmetry cause, the Q35 upload
regression and cross-node step are not covered by this PASS. Physical
Mac/Xcode/iOS, router and Windows VM runtime were excluded by the user.
Whole-release and hosted CI gates remain open. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: separate performance and cross-node verification

<!-- normative-sync: q35-bounded-performance-crossnode-20261012 -->

[Qualified results](../../../release/certification/evidence/q35-bounded-performance-crossnode-20261012.json).
Lab .11 ran four predeclared independent checks: performance and cross-node
for the previous CLI `35da83fd` and current pool-fixed CLI `52511ceb`. Both
performance runs retained three 20-second rounds, the 5% threshold, the 2-CPU
limit and the upload/download/combined-CPU assertions. Receiver rates were
checked against raw iperf3 output separately by policy and direction, and medians
were independently recalculated. No measurement was excluded or replaced by a retry.

| Binary | Upload off / required, Mbps | Upload decrease | Download off / required, Mbps | CPU off / required, % | Performance: failed criteria | Cross-node |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Previous CLI | 515 / 518 | -0.5825% | 626 / 620 | 159.921 / 160.140 | PASS: — | 28 PASS / 0 FAIL |
| CLI with pool fix | 515 / 538 | -4.4660% | 615 / 624 | 160.560 / 163.601 | PASS: — | 28 PASS / 0 FAIL |

Cross-node here means two independent server processes and registries in separate
network namespaces on one VM. Checks cover foreign-locator JOIN rejection,
primary-carrier loss, fallback to full AUTH, a new address and traffic through
the secondary process. This does not certify physical-server failover.

The original 13-hour release gate remains FAIL: upload decreased 6.8627%
against a 5% limit. Comparing off/required on one binary does not measure a
regression between software versions. The old failure's cause is not established;
these checks do not prove an effect from the pool fix or background load. The five
completed resource scenarios were not repeated and belong to the previous SHA.
This packet does not certify a full 8-hour release gate on the current CLI.

Every input and retained file was SHA-verified; observed processes ran in private
mount/net/PID namespaces. Services, PID/start ticks/binaries and staged CLI were
preserved. The owned root, remote archive and transient unit were cleaned.
Full structural comparison across all host backends passed.
Q35 remains IN_PROGRESS; the ledger remains 31/37 (83.8%), six sections open.
Full release and hosted CI are not certified. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: 20 Linux criteria on the pool-fixed CLI

<!-- normative-sync: current-pool-linux-certification-20261012 -->

[New results and source binding](../../../release/certification/evidence/current-pool-linux-matrix-20261012.json).
Lab .11 freshly executed every required automated Linux scenario on CLI
`52511ceb`: 19 separate executions, 409 successful assertions and no failures;
the twentieth leak criterion is derived from actual probes in 14 full/split
cases. Elapsed time: 595.0 seconds. Previous executions on a different
binary and their timestamps were not rewritten.

Coverage includes 12 outer/inner IPv4/IPv6 combinations with TCP/UDP fake-TLS/UDP
QUIC, two dual-stack split tunnels, TAP with local NDP/RA, real systemd-resolved
and DNS over IPv4/IPv6/forced TCP, DATA_FRAG/PMTU on MTU 1280 and ICMPv6 PTB,
both directions of Qeli 0.7.16 compatibility, 100 TCP switches and 100 QUIC switches.
Commands, raw logs, result assertions, SHA, separate mount/net/PID namespaces
and the required functional markers were independently checked for each case.

No recompilation was needed: 915 of the existing qualified build's 916 inputs
match exactly. The only two previously declared whitespace replacements in
buffer_pool.rs were reverified without changing logic, strings or comments.
All 453 fixture inputs match. ELF and legacy-client SHA are pinned. DNS tools,
dependencies and the resolver account already existed on .11; no installation
or service change was needed.

Every retained file was SHA-verified. Structural comparisons across all host
backends passed before/after/after cleanup. Production PID/start ticks/binaries,
staged CLI, DNS tools/dependencies and passwd/group were preserved. The owned
root, remote archive and transient unit were removed. Linux certification binds
these new results and the verified applicability of later documentation-only
changes; this execution's original source/time/raw remains a separate immutable fact.

This closes the stale binding of 20 Linux criteria after the pool change.
The bounded 100+100 soak does not replace the eight-hour Q35 release gate.
The old Q35 performance FAIL, Android SIGKILL/ENONET, full Android VPN data plane,
hosted CI and other open criteria remain outside this PASS. The ledger remains
31/37 (83.8%), with Q29/Q31/Q34/Q35/Q36/Q37 open. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: Q35 performance measurement order

<!-- normative-sync: q35-performance-order-20261012 -->

[Raw results and independent qualification](../../../release/certification/evidence/q35-performance-order-20261012.json).
Lab .11 executed four predeclared measurements on previous CLI `35da83fd`,
ordered off → required → required → off. Each policy retains three 20-second
rounds, the unchanged 5% budget and CPUQuota 200%. All four functional cases
passed (44 assertions). These are order diagnostics, not a new full release gate.

| Order | Policy | Upload Mbps | Download Mbps | CPU % | Host steal % |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | off | 511 | 633 | 159.861 | 0.004 |
| 2 | required | 513 | 635 | 159.519 | 0.008 |
| 3 | required | 527 | 630 | 161.851 | 0.008 |
| 4 | off | 524 | 632 | 161.849 | 0.004 |

- off-first / required-second: upload -0.3914%, download -0.3160%; gates {"upload": true, "download": true, "cpu": true}; PASS.
- off-last / required-third: upload -0.5725%, download 0.3165%; gates {"upload": true, "download": true, "cpu": true}; PASS.

All 24 iperf3 receiver results were independently checked, and medians and both
comparisons recalculated. Observations retain host CPU steal, PSI, memory and
cgroup with available raw counters. The private sysfs mount does not expose a
cgroup filesystem: all cgroup observations are empty. Quota throttling and memory
cgroup events were not measured. Every input and retained file was SHA-verified;
private namespaces were confirmed. Full host comparisons passed before/after/after
cleanup; production services and staged CLI remained intact. The owned root,
remote archive and transient unit were removed.

In the original 13-hour run, both performance policies used fresh process pairs;
their PID/start ticks do not overlap the resource prefix in 9395 snapshots.
The performance helpers are unchanged. Thus the 6.8627% FAIL does not demonstrate
degradation of the same long-lived VPN session. The original observer retained no
host CPU steal/PSI/cgroup telemetry; this short diagnostic cannot reconstruct those
conditions. Even different forward/reverse comparisons cannot establish the
historical failure's cause. The budget and original failure remain intact;
root cause is NOT_ESTABLISHED. The 13-hour resource prefix was not replayed.

Q35 remains IN_PROGRESS; the current CLI's full eight-hour gate is not certified.
The ledger stays 31/37 (83.8%), with six sections open. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: Q37 complete against five criteria

<!-- normative-sync: q37-five-criteria-closure-20261012 -->

[Criterion matrix and verifiable evidence](../../../release/certification/evidence/q37-closure-20261012.json).

| Criterion | Completion basis |
| --- | --- |
| Review and dead code | 297 Rust modules / 306 edges; 59 diagnostics in four Linux profiles, 73 reviewed suppressions. 41 retired bodies and unused direct dependencies removed; external API, JNI/C/Swift and RAII retained. Subsequent changes covered by current strict profiles and native A/B. |
| Positive, boundary and negative cases | 84 client fields, 134 server defaults and 176 reader keys reconciled; actual INI admissions and original negatives retained. Eight current schema/docs/generated-adapter methods PASS. |
| Failures and concurrency | Four current admission methods and two safe-import methods for 24 scenarios PASS; five real Linux CI-fixture methods remain applicable after exact unchanged runner/test SHA. Empty/incomplete/skipped/expected-failure suites never qualify; child failures remain visible. |
| Integration and target platform | Current four native A/B, exports/provenance, 22 Windows C ABI, 23 Android JNI and two packaged INI checks; fresh 20 Linux criteria / 409 assertions. User-skipped physical platforms are not described as tested. |
| Fixes, retesting and evidence | Original F001–F013 and maintenance failures retained; 915/916 current CLI inputs match, with the sole formatter delta separately proved. Current provenance/docs/version/source gates PASS; owned cleanup and historical host failures retained. |

Final targeted checks: 14 methods without failures/errors/skips; provenance,
documentation, version and strict Linux certification passed. The initial wrapper
expected one import method rather than two: its count refusal is retained; both
actual successful methods were qualified from their original log without a replay.
Previous full Rust suites, 149 Linux fixtures, native/JNI and network executions
retain their actual timestamps and SHA; they are not presented as new executions.

Q37 covers documentation, reachability, test connection/admission and the qualified
integration of changed harnesses. Full Android VPN data plane, SIGKILL recovery and
ENONET belong to Q29; hosted CI and publication to Q34; SDK/bootstrap to Q31;
historical performance failure/full endurance to Q35; TCP asymmetry cause/capacity
to Q36. These remain open without duplicating them as an undefined Q37 remainder.
This does not claim semantic reachability for every possible execution or public API.

**Q37 DONE within agreed scope. Total: 32/37 (86.5%), five sections remain:**
Q29/Q31/Q34/Q35/Q36. The whole audit and release remain incomplete.
Network runs and large builds were not replayed; no new compiler caches were created.
`NO_PUSH_DEPLOY_RELEASE`.

<!-- q31-current-portable-20261012 -->

**12 October, Q31-V013:** current ARM/MIPS and client-only SDK compile/packaging qualified; fixed0664 license permissions and stale SDK/opkg assertions.54 scoped methods PASS,533 license files checked. The ELF was unchanged during corrected Install/repackaging. Owned roots removed, about3.6GiB released, original services preserved. [Full scope and remainder](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md). Q31:3/5 IN_PROGRESS; bootstrap resource-deferred, physical router USER_EXCLUDED. Total32/37 (86.5%),5 open sections.

<!-- q29-current-vpn-20261012 -->

**12 October:** [Q29: current VPN integrations/fixture reliability](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md). Fixed RAM admission, post-CONNECTED sampling, Profiles transition and ANR handling.23 helper methods/7 matching-R8 routed cases PASS,72 exact receipts/6 DNS names. Six cold attempts FAIL retained;last stopped at unpublished storage. SIGKILL/ENONET remain open;ordinary production-rules/current independent UID cold gate not qualified. Q29 IN_PROGRESS;32/37(86.5%),5 sections remain.

<!-- q34-current-source-cut-20261012 -->

**12 October:** Production OpenWrt pin/hash refreshed: two SDK downloads and prepare qualified,all 3272 tracked files matched Git. Actual source gate and25 methods PASS;3 previous skips preserved. Public pin/CI absent; no bootstrap/IPK executed. Q34 IN_PROGRESS;32/37(86.5%),5 sections open. [Q34](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md). NO_PUSH_DEPLOY_RELEASE.

<!-- q29-storage-startup-20261012 -->

**12 October:** Q29 scoped current independent-UID cold UI/startup/lockdown/manual recovery gate qualified.8 fixture methods PASS,336 probes,241 correlated receipts,80/80 post-CONNECTED replies,stopped lockdown48/0. Storage readiness before APK/push fixes premature INI upload. DNS/null ENONET,SIGKILL and ordinary production-rules APK remain open;32/37(86.5%),5 sections. [Отчёт](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).NO_PUSH_DEPLOY_RELEASE.

<!-- q29-production-runtime-20261012 -->

**12 October:** Ordinary production R8 APK qualified via UI/SAF and independent UID without instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts,stopped lockdown48/0 and manual recovery/DNS PASS. APK payload unchanged by lab signing;real release signing and physical platforms unqualified. DNS/null ENONET,first-post-APPLIED blocking and historical SIGKILL retained. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-dns-selection-control-20261012 -->

**12 October:** Q29 generic/null ENONET cause localized on the current API34 image. Authenticated dnsproxyd selection and independent platform TUN owner UID reproduce failure;bypassable control returns A+AAAA. Typed/null and explicit VPN DNS traverse TUN. Product APK/JNI/default kill-switch unchanged;compatibility failure retained,SIGKILL and first-post-APPLIED remain open. [Q29 DNS](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-current-sigkill-20261012 -->

Current production R8 SIGKILL recovery:FAIL;whole runtime FAIL. Plain/TUN platform controls ran once,45s window retained. Manual recovery/revoke and dead/force-stopped blocking PASS. Product APK/JNI and byte-identical restart policy unchanged;SIGKILL failure not overwritten. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

<!-- q29-publication-contract-20261012 -->

APPLIED/CONNECTED boundary reviewed: first sampled sockets after APPLIED started before CONNECTED;8 interval refusals and80/80 post-CONNECTED PASS in each retained run. Interpretation question closed, original FAIL_POST_PLAN_BLOCKING retained. The helper already gates post-CONNECTED;6 methods PASS. No new runtime/builds. SIGKILL/DNS compatibility FAIL and Q29 IN_PROGRESS remain. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.

### 13 October: native copy and full endurance debt closed

<!-- normative-sync: adopted-native-endurance-checkpoint-20261013 -->

[Q34: adopted fixes and fresh natives](../reports/audit-0.8.2/AUDIT-Q34-ADOPTED-NATIVE.md):
factory panel build, two assets tests and 131 HTTP checks PASS. Adopted
commit da776fb8 was rebuilt A/B for four libraries; 22 Windows ABI checks,
23 Android JNI checks and two packaged INI tests PASS. All eight local copies,
SHA256SUMS and PROVENANCE were updated and verified. Independent archive
qualification and cleanup of both build roots, temporary swap and emulator
are complete.

[Q35: complete current endurance](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md):
13 h 4 min, all eight phases, 10k TCP/10k QUIC/1k per additional UDP adapter,
performance and 28 cross-node checks PASS with the unchanged 5% threshold.
The old -6.8627% upload FAIL and its unestablished cause remain separately
recorded. Q35 needs final mapping of the other criteria; Q34 needs global
source applicability/certification, a public source cut and hosted CI.
Q29 platform scope, Q31 bootstrap and Q36 diagnostics remain open.
The overall count remains 32/37 (86.5%) without inferred module completion.
`NO_PUSH_DEPLOY_RELEASE`.

### 13 October: actual Q36 TUN diagnostics

<!-- normative-sync: q35-final-q36-stage-checkpoint-20261013 -->

### 13 October: current Q36 statistical population

Qeli SIGKILL recovery qualified on the ordinary production R8 APK; disconnect/revoke prevent service resurrection in 30-second windows. DNS/null remains open. [Q29 recovery](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md). Plan: 33/37 (89.2%); Q29 IN_PROGRESS.

**14 October: current ARMv7/MIPS after F030 qualified.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md):2fresh client-only builds/907Git inputs/staticELF/SHA +32QEMU CLI/INI PASS;allownresourcesarchived/cleaned,productionpreserved. Original preparation/importFAIL retained;SDK/IPK-current-core refresh andbootstrap remainopen,physicalrouterUSER_EXCLUDED;33/37 unchanged,NO_PUSH_DEPLOY_RELEASE.

**14 October: current SDK/IPK after F030 qualified.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): stock SDK 24.10.4 with private official Rust 1.89; client-only Compile/Install/BuildPackage, 7 opkg, 9 CLI/INI and 533 notices PASS. Child cleanup and partial logging on timeout fixed and verified with a real negative test. Owned resources cleaned, production preserved. Full feed rustc/std/cargo bootstrap remains unexecuted; physical router USER_EXCLUDED, public CI/release open. 33/37, NO_PUSH_DEPLOY_RELEASE.

**14 October: F459 / Q34-F013 closed for the current panel graph.** [Client supply](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): adopted Tailwind 4 compiler API removes braces/CLI/watcher chain. Fresh npm audit: old graph exit 1 / five affected entries; current exit 0 / zero. CSS/build/watch/template inputs and previous 29 Linux / 29 Windows, 36 variants / 96 states, 131 HTTP checks checked without rerunning. Cache removed; whole Q34 remains open, 33/37 unchanged, NO_PUSH_DEPLOY_RELEASE.

**14 October: complete Rust feed preparation qualified.** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): six SDK-pinned files, official source SHA, stock patch, host-prepare/host-configure and GNU-host/musl-target semantics PASS. Fixture feed omissions and host exports corrected; all owned resources removed. Compiler bootstrap/cold graph NOT_RUN, Q31 open,33/37 unchanged,NO_PUSH_DEPLOY_RELEASE.

**14 October: actual public CI reviewed.** [Q34](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): three failed published-e7 jobs;source pin404,current core unpublished. Keenetic fixture fixed and verified44/root +44/non-root, production owner guards intact. Mac/iOS diagnosis and exact-source hosted gate remain open;physical stands USER_EXCLUDED,33/37 unchanged,NO_PUSH_DEPLOY_RELEASE.
