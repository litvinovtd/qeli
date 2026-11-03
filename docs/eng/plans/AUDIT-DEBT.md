# Technical debt from started audits

> Previously withdrawn 0.8.2 development measurements and comparisons remain retained locally for audit; they are not reinstated as a release benchmark. New dated [Linux snapshots](../reports/LINUX-LAB-0.8.2-2026-10-17.md) and [N04 results](../reports/TUN-N04-0.8.2-2026-10-19.md) are included separately: each retains its measured ELF identity, method and applicability limits. They do not describe every platform or a later binary; engineering-check status alone is not a benchmark.

<!-- normative-sync: audit-debt-v144 -->

**19 October, N04 — final distribution qualification:** after the Linux UDP reader
fix, the next cross-thread boundary was removed: the `qeli client` / `qeli-client`
transport loop and I/O driver use `current_thread`. Server and `_worker` retain
`multi_thread`; native FFI runtime policy is unchanged. The queue default is 1000.

The ready Linux ELF `e4cb6e05…`, qualified on `dev` at
[`9ab788e5`](https://github.com/litvinovtd/qeli/commit/9ab788e5d5e7aaddb3d82220bb6ebdb9da8cacd2),
passed **20 required runtime cases / 409 assertions** and **7 load windows** of
FakeTLS/QUIC, including a separate one-minute QUIC950 window. With client/server
queues 1000/1000, all seven windows recorded **0 TUN drops at both endpoints**.
The one-minute window delivered 949.76 Mbps with 0.00267535% end-to-end UDP loss;
zero TUN drops does not mean zero total loss. [Ready-ELF results](../../../release/certification/evidence/n04-cli-packaged-udp-20261019.json)
remain separate from [diagnostic A/B and its limits](../reports/TUN-N04-0.8.2-2026-10-19.md).
Earlier residual reader-fix drops and separate queue2000 checks retain their own
ELF identities; the default was not raised and loaded RTT was not qualified.

Native A/B, provenance, SDK source, 16 distribution files,
[20/20 CI](https://github.com/litvinovtd/qeli/actions/runs/39232066191) on exact
`9ab788e5` and release preflight passed. The [release qualification](../../../release/certification/0.8.2.json)
records their identities and applicability. Documentation-only changes do not mean
these tests were rerun; the new revision receives separate documentation, CI and
preflight checks. The previous 37/37 scope, accepted unfixed API34 ENONET / D06,
original FAILs and excluded platforms are retained. The distribution remains in a
private draft; no release publication was performed.

Original full-audit reconciliation: 15 October 2026. The full audit is complete within agreed scope: 37/37 (100%). Q29 closed by explicit user decision with the documented generic/null DnsResolver API34 limitation; the original ENONET remains FAIL and no fix is claimed. The original 15 obligation groups remain 14 DONE and D06 ACCEPTED_LIMITATION; previous platform coverage limits are retained. Historical OPEN entries and counts below refer to their stated dates. [Q29 decision and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).

`DONE` requires a fix/justification and the required verification. `BLOCKED` denotes an
unavailable external prerequisite, never success. The user supplied Linux and an Android
emulator on 24 September; the historical “no Linux environment” limitation is obsolete.
Connections to both Linux VMs were verified; the running server and its files were not replaced.

[Full plan](FULL-SYSTEM-AUDIT.md) · [Shared configuration core](CLIENT-CONFIG-CORE.md)

`ACCEPTED_LIMITATION` records an explicit user decision to retain a known remainder;
it is neither a fix nor PASS.

**Historical snapshot, October7:** 14/15 DONE, D06 ACCEPTED_LIMITATION.
D11/D15 are closed for the current package after fresh A/B, exports/signatures,
14 SHA entries, provenance, Windows/Android ABI and managed checks, Linux
2417 library/12 CLI units, strict Clippy and debug client/daemon builds.
[Current reconciliation](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md) retains initial
preparation failures and original measurement limits. Eight agreed old roots
were removed after rechecking backups/identity/guards; both local archives
remain. Q29 SIGKILL/ENONET, Q30 callback drain/Apple and Q31 SDK/release pipeline
remain incomplete full-audit work, not PASS. Full plan:28/37, nine sections
remain. Future source/recipe changes can invalidate native evidence again.
October8 [Q32 update](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md):2424 library PASS,
60preexisting ignored,strictClippy/daemon PASS and36namespace PASS atPID42;
WindowsABI22/AndroidJNI23 qualify the new binaries.Final nativeA/B/provenance
are in this packet evidence.Managed sources/ABI declarations are unchanged;
prior12CLI and platform limitations retain their original scope.
The [Q32 metrics packet](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md) separately refreshes native
evidence after the server edit; its qualification and limits are recorded in the
report, without closing remaining Q29/Q30/Q31 scopes.
Historical OPEN below does not require repeating closed unchanged checks.

| ID | Sections | Status | Debt | Closure criteria / current evidence |
|---|---|---|---|---|
| D01 | 14/17/18/25 | DONE | NAT and retired-generation failures | Retain exact rules before mutation; retry and final failure; prevent restart after incomplete cleanup; release IPv4 forwarding. Unit/cross, 18 native and 8 worker E2E PASS; baseline IPv4 leak reproduced. [Report](../reports/audit-0.8.2/AUDIT-Q14-RETAINED-CLEANUP.md). |
| D02 | 14/25 | DONE | Internal sysctl boundaries | Lock/I/O/context, trusted directory, namespace fd pins, original per-interface fd/witness and v4 network_cookie verified. 1995 Linux + 32 privileged + 8 lifecycle and SIGKILL/mismatch worker E2E PASS. Lost interface witness stays for manual recovery; general persistent firewall/DNS/routes remains D04. [Report](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md). |
| D03 | 22/25 | DONE | Standalone kill switch | Pinned namespace, retained exact-family owner, fail-closed reconnect and safe address rotation. 11 portable + 2 native regressions; actual IPv4/IPv6 filter counters and 2 baseline failures. [Report](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md). |
| D04 | 14/19/22/25 | DONE | Crash recovery | Persistent server firewall, DNS v2, kill-switch and physical routes verified; legacy global DNS, persistent TUN and lost sysctl witnesses have explicit safe manual boundaries. [Client mixed matrix](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md): 152/152 cells, 136 crash/recovery; [server](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md): 16/16, 476 checks rerun PASS. Additional multiprofile/public-policy reload is closed by D10/Q25-F213; state accumulation is covered by D13. Arbitrary policies/root rewrites are not certified. |
| D05 | 05/14/25 | DONE | Whole-operation deadlines and blocking | Panel preflight/health/backup, DNS/NSS, resolver files, startup INI/identity, TOFU/status writers and network workers checked. Batch A below closes command composition: 15 seconds for NetworkPlan and separate shared 15 seconds for cleanup through Drop and terminal firewall. Linux early-Drop/internal waits reconciled; hook/backup file preparation is closed by the continuation below; ordinary server startup/final cleanup and profile teardown now use joined workers; profile TUN/NAT and DNS firewall setup now also use joined workers; NDP bind now also runs on a worker, with AsyncFd registration in the original runtime; setup through readiness of every listener now has a shared 120-second budget; replacement admission after cancellation is closed by [Q25-F130](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md); async joining on forced Drop is closed by Q25-F206 below; Q25-F208 closes total CLI shutdown and concurrent notification drain: 45-second worker budget, forced exit 124, recovery, 136 unit and 8 lifecycle PASS. Library/kernel boundaries are justified. [Server setup](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-WORKER.md), [DNS firewall](../reports/audit-0.8.2/AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md), [NDP bind](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NDP-BIND-WORKER.md), [readiness and budget](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md). Arbitrary kernel/fs I/O and forced joins are not preempted. [Server cleanup](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CLEANUP-WORKER.md). [Worker ownership](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md). |
| D06 | 15/21/22/23/25 | ACCEPTED_LIMITATION | External network resource context | Multi-IP UDP endpoint, WAN presence/ECMP/auto-detection, NAT44/NAT66 off-WAN guard, DNS/bus/sysfs/attach/process context and late IPv4/IPv6 validated; Q25-F214: 73 portable + 23 privileged, Q25-F215: 4 mixed cells/204 packet checks PASS. [Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) remains a known P2: name selectors and the client monitor do not provide continuous identity. DEVMAP prototype: 156 checks, not a production fix. On 3 October the user declined its integration and corresponding monitor changes. Stop the profile and confirm cleanup before replacing its selected WAN. Remainder accepted as a limitation, not PASS; decision and rollback are recorded at the end. |
| D07 | 01/05/09/11 | DONE | Server configuration at runtime | Trace field → parse/validate/runtime/serialize; malformed/oversized input; check-config/startup/SIGHUP/HTTP save/Quick Start preserving active state on failure. [Q25-F137](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SIGHUP-AUTH.md) through [Q25-F149](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-PATH-TRUST.md) cover targeted SIGHUP, size, live web state, private INI publication, admission parity, file-path trust, coordinated panel/CLI/restore writes, bounded TLS PEM intake, check-config TLS parity, explicit TLS path trust, and Let's Encrypt panel saves. [Q25-F150](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PANEL-SNAPSHOT-TRUST.md) closes panel identity/Share/users trust bypasses after manual INI edits. [Q25-F151](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PANEL-SAVE-TRUST.md) blocks trust promotion through panel saves, history, and archive commands. [Q25-F152](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FIELD-MATRIX-LOGGING.md) checks parse/serialize coverage of 150 fixed INI keys and requires a full restart for three active logging fields. [Q25-F153](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-AUTH-SAVE.md) rejects an enabled panel without a password or explicit insecure_no_auth in both editors and history restore. [Q25-F154](../reports/audit-0.8.2/AUDIT-Q25-SERVER-QUICKSTART-BF-SAVE.md) extends the guard to Quick Start and lockout-policy saves, validates the complete BF candidate before SIGHUP, and reports INI read failures or a pending worker reload. [Q25-F155](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SIGHUP-RESTART-HINTS.md) removes false warnings for disabled profiles and reports unapplied SIGHUP changes to live profiles, two auth flags, and three logging fields. [Q25-F156](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-HASH-VALIDATION.md) validates a nonempty admin hash at check-config/startup and preserves working login after an invalid live reload. [Q25-F157](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-RELOAD-RESULT.md) separates INI publication from successful panel application and prevents a partial lockout-policy swap when reload is cancelled. [Q25-F158](../reports/audit-0.8.2/AUDIT-Q25-SERVER-BLOCKED-LIVE.md) applies the panel lockout policy through live web reload, exposes saved/active divergence, and avoids a false password rejection for a disabled panel. [Q25-F159](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-ORDER.md) stabilizes INI ordering of groups, IPv4/IPv6 reservations, and user metadata. The 2026-10-01 batch rejects empty profile sets through the shared validator and checks panel authentication and existing TLS PEM files before a full restart; 74 tests and strict Clippy passed on `.11` (2 namespace tests ignored). The second batch aligns `check-config` and startup with panel refusal when `web.enabled = true` has no password; 152 server/panel tests and strict Clippy passed on `.11` (2 namespace tests ignored). The next batch requires `expected_revision` for Quick Start, form, INI and history restore; older API scripts were updated, with 37 editor tests, formatting and strict Clippy passing on `.11`. The [global field matrix](../reports/audit-0.8.2/AUDIT-Q25-SERVER-GLOBAL-FIELDS.md) traces parse/validate/runtime/apply for 34 auth/web/logging keys; the fixture generator confirms 163 names and three dynamic families. The [foundational profile matrix](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md) traces 63 non-obf.* entries and fixes the silent cap on explicit tun.queues above 256. The [obf.* matrix](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-OBF.md) traces the other 59 keys and fixes REALITY share-link SNI. [Q25-F160](../reports/audit-0.8.2/AUDIT-Q25-SERVER-BLOCKED-REVISION.md) also requires an INI revision for lockout-policy saves. [Q25-F161](../reports/audit-0.8.2/AUDIT-Q25-SERVER-ARCHIVE-SCAN.md) stops silently skipping directory-entry errors during archive restore. [Q25-F162](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NOTIFY-INI.md) removes notification JSON migration and bounds notify.ini reads/writes. [Q25-F163](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NOTIFY-REVISION.md) guards notify.ini saves against stale tabs. Q25-F209 below closes mixed save/reload/import: 201 unit, 4 privileged executions and 44 runtime checks PASS; external writers ignoring the shared lock are explicitly unsupported, with rationale in the manual. [Q25-F190](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-HISTORY.md) makes INI history listing and rotation report I/O failures; Windows rustfmt and 1551 portable tests PASS, with targeted server tests and mixed Linux runtime rechecked in Q25-F209. |
| D08 | 02/24/27 | DONE | Shared client configuration | Verify the complete 81+3 field contract, INI/import/URI/QR/form/store/reconnect through real adapters; fuzz/budget and concurrent edits. [Q25-F164](../../ru/reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-REVISION.md) protects panel INI against stale tabs, manual edits and name collisions on import; [Q25-F165](../../ru/reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-BOUNDS.md) bounds autostart/status reads and serializes Connect/Delete with saves. [Q25-F166](../../ru/reports/audit-0.8.2/AUDIT-Q25-CLIENT-DELETE-REVISION.md) requires a revision before Delete and reports when a saved running client needs reconnect. [Q25-F167](../../ru/reports/audit-0.8.2/AUDIT-Q25-ANDROID-FILE-IMPORT.md) keeps Android file imports byte-faithful and rejects malformed UTF-8. [Q25-F168](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-CONFIG-FILES.md) shares strict bounded INI file loading across Windows/macOS CLI. [Q25-F169](../../ru/reports/audit-0.8.2/AUDIT-Q25-CLIENT-UI-INI-INPUT.md) passes untrimmed INI from Windows/macOS/Android/iOS UI to the shared parser. [Q25-F170](../../ru/reports/audit-0.8.2/AUDIT-Q25-MOBILE-CONFIG-BUDGET.md) aligns early Android/iOS file and store budgets with the shared core’s 256 KiB limit. [Q25-F171](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-UTF8.md) rejects malformed UTF-8 in Windows/macOS profile stores. [Q25-F172](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-RECOVERY.md) prevents overwriting an unreadable store that could not be preserved and avoids misclassifying migration write failures. [Q25-F173](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-PROFILE-TRANSACTIONS.md) persists proposed desktop profile changes before updating the visible list. [Q25-F174](../../ru/reports/audit-0.8.2/AUDIT-Q25-ANDROID-PROFILE-TRANSACTIONS.md) commits Android profile changes and backup restore before UI updates, and verifies encrypted migration before erasing plaintext. [Q25-F175](../../ru/reports/audit-0.8.2/AUDIT-Q25-MOBILE-STORE-LOAD-FAILURE.md) prevents ordinary Android/iOS writes after a store load failure while allowing explicit backup restore. [Q25-F176](../../ru/reports/audit-0.8.2/AUDIT-Q25-ANDROID-STORE-DECODING.md) rejects malformed Android store structure and UTF-8 without changing credentials. [Q25-F177](../../ru/reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-UI-REVISION.md) rejects stale Android/desktop UI operations and reports when Android needs reconnect after editing the active INI. [Q25-F178](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-CONCURRENCY.md) protects the desktop profile store from stale cross-process writes and quarantine. [Q25-F179](../../ru/reports/audit-0.8.2/AUDIT-Q25-ANDROID-STORE-VERSION.md) rejects stale Android Activity and restore writes. [Q25-F180](../../ru/reports/audit-0.8.2/AUDIT-Q25-IOS-EMPTY-ARCHIVE.md) rejects an empty iOS store before normalization. [Q25-F181](../../ru/reports/audit-0.8.2/AUDIT-Q25-IOS-ACTIVE-PROFILE-RECONNECT.md) tells iOS users to reconnect after editing the active INI. [Q25-F182](../../ru/reports/audit-0.8.2/AUDIT-Q25-IOS-PROFILE-SNAPSHOT.md) rejects stale iOS Edit/Delete actions within the app. [Q25-F183](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-BOUNDS.md) bounds desktop store and macOS .bak I/O at 16 MiB. [Q25-F184](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-LOCK-WAIT.md) allows bounded one-second waiting for brief desktop sidecar-lock contention. [Q25-F185](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-STRUCTURE.md) rejects a null desktop store root or row while preserving a genuine empty array. [Q25-F186](../../ru/reports/audit-0.8.2/AUDIT-Q25-ANDROID-ACTIVE-INDEX.md) rejects malformed Android active-profile indexes on all three paths and bounds direct service reads. [Q25-F187](../../ru/reports/audit-0.8.2/AUDIT-Q25-IOS-ACTIVE-INDEX.md) rejects malformed iOS restore active indexes, pending XCTest on Mac/Xcode. [Q25-F188](../../ru/reports/audit-0.8.2/AUDIT-Q25-MOBILE-STORE-BOUNDS.md) bounds Android encrypted store and backup before decoding/crypto, rejects malformed UTF-8, and documents distinct portable-backup and internal desktop-store budgets. [Q25-F189](../../ru/reports/audit-0.8.2/AUDIT-Q25-DESKTOP-PROFILE-IDENTITY.md) migrates a missing Id in mixed desktop stores and rejects empty/duplicate explicit IDs on read and write. [Q25-F191](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-NULL-FIELDS.md) rejects null in required desktop-profile fields and collections on read and write; conformance and both desktop builds PASS. [Q25-F192](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-SETTINGS-STORE.md) shares Windows/macOS settings storage, bounds reads and writes to 1 MiB, and preserves corrupt originals before fallback; seven file conformance cases and both builds PASS. [Q25-F193](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-APPS-INI.md) keeps apps_mode/apps in the qeli section when editing a profile with a logging section; 167 JVM tests and a debug APK PASS. [Q25-F194](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-PASSWORD.md) refuses share links without a portable inline password; 52 shared-editor integration tests PASS on Windows. [Q25-F195](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-UI.md) shows the refusal in Windows/macOS/iOS UI; desktop builds PASS, iOS XCTest pending. [Q25-F196](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-PARITY.md) aligns Android/.NET/iOS tests for passwordless-link import versus refused re-export; 167 Android JVM tests and .NET conformance PASS against fresh debug host DLL. [Q25-F197](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-INI-MATRIX.md) pins all 84 schema fields through runtime and 1000 deterministic INI export/reimport mutations; 54 editor tests PASS. Q25-F210 below closes the available remainder: arbitrary external writers are explicitly unsupported and the iOS provider is read-only; 511 .NET, 167 JVM and 12 Android instrumentation PASS. Preceding VPN/reconnect E2E is reconciled with D12; Apple runtime is SKIPPED by user decision, not PASS. [Q25-F198](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-URI-BUDGET.md) caps direct panel URI imports at 256 KiB before query parsing; 1552 portable and 54 integration tests PASS. |
| D09 | 14/15/25/32/33 | DONE | Linux lifecycle and system failures | [Closure evidence](../reports/audit-0.8.2/AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md): source `4eaf551a`: 2175 Linux unit, 8 control, 15 hook-process and 8/8 live worker lifecycle PASS, with exit/SHA and before/after network snapshots. Earlier 48 privileged and real DNS/route/firewall matrices still apply to unchanged paths. Full install/upgrade and network combinations remain D11/D10; whole shutdown remains D05. |
| D10 | 17/18/19/21/22/23 | DONE | Network integration matrix | Supported Linux contract closed by Q25-F211/F212/F213 below: 118 four-profile IPv6/DNS checks, 8 NDP packet cells/248 checks, 4 mixed IPv4/IPv6 backends with public firewalld zone/policy reload/restart/416 checks and 19 targeted tests PASS. Foreign resources restored; crash/recovery — D04, TCP/UDP multiprofile SIGKILL/churn — D13. Arbitrary root rewrites/automatic backend migration are not certified. [Evidence](../../../release/certification/evidence/firewalld-profiles-20261002.json). |
| D11 | 00/24/27/34 | DONE | Current native cores and provenance | [Q25-F202](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md): clean source `27db1a22`, one digest, independent A/B release builds of Windows x64, macOS universal2 and Android arm64/x86_64 with matching SHA; ABI/exports, 14 manifest copies and provenance PASS. Windows selftest 143/0, Android APK embeds verified libraries. After Q25-F204, [the A/B refresh](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md#refresh-after-q25-f204-1-october-2026) verified source digest `d39a3343`, four ABI 1.16 libraries, 14/14 SHA pairs and provenance; Windows selftest 143/143, Android JVM 167/167 and a new APK with exact `.so` files. Mac app/runtime are excluded under D12 by user decision.  Current October7 package: see native/Linux reconciliation above. |
| D12 | 24/25/27/34 | DONE | Platform evidence within available scope | [Q25-F203](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md): Android 0.8.2 APK/JNI, 167 JVM, 11 instrumentation, bidirectional ICMP, WebView HTTP 200 from VPN address, reconnect and Wi-Fi toggle PASS. The physical inner source was localized to system Private DNS `netd`; server anti-spoofing held. Windows VM, Mac/Xcode/iOS and router runtime are **SKIPPED by user decision**, not PASS. After the new native A/B and APK, [instrumentation 11/11](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md#refresh-after-q25-f204-1-october-2026) was repeated; full VPN traffic for this new APK was not. Physical Android/LTE/Doze/always-on and a release APK remain part of full audit section 29, not certified here. |
| D13 | 14/19/22/25 | DONE | Resource retention under load | [Q25-F204](../reports/audit-0.8.2/AUDIT-Q25-WORKER-RESOURCE-CHURN.md): 8/8 worker TCP/UDP × IPv6-mode, 80 reloads, fd/socket/task delta zero; exact release SHA `a526c03b` completed 100 TCP handovers (16/16), 100 UDP QUIC handovers (17/17), and three UDP adapters ×20 (17/17 each), retaining session/processes/TUN and restoring sysctl leases. Concurrent TCP/UDP profiles: 14/14 stop/reload/SIGKILL/recovery, fd/socket/tasks 26/11/7→26/11/7, network/journal restored after stop. RSS peaks were sampled; unavailable platform runtime is not certified. |
| D14 | 00/34 | DONE | Historical final regression and certification | Engineering checks belong to snapshot `a526c03b`: automated certification 20/20, network scenarios and host-state restoration. [Measurement method and publication status](../reports/BENCHMARK.md). Numerical 0.8.2 measurements are withdrawn and are not a public version comparison. Physical advisories are not PASS; source changes require evidence-applicability review. |
| D15 | All started sections | DONE | Final reconciliation | [Q25-F200](../reports/audit-0.8.2/AUDIT-Q25-DOC-PARITY.md)/[Q25-F201](../reports/audit-0.8.2/AUDIT-Q25-PATCH-RECONCILIATION.md): docs and 625 archived patches reconciled. Final 3 October: native A/B/ABI/provenance, Windows 143; unchanged 164 adapter + 288 Rust hashes; release `09af8fb0`, Linux 2257 unit, fmt/Clippy, 18/327 runtime, 100 TCP + 100 QUIC/33 checks, 45.02s shutdown/recovery, certification 20/20 automated. [Evidence](../../../release/certification/evidence/final-candidate-20261003.json). 21 physical advisories not PASS; D06 accepted limitation.  Current October7 package: see native/Linux reconciliation above. |

Historical debt-register state on 3 October: **14/15 DONE, D06 ACCEPTED_LIMITATION**.
**15/15 groups (100%) are dispositioned**: 14 closed with evidence; the user
waived the D06 remainder. Q25-A125 is not fixed: stop the profile and confirm
cleanup before selected WAN replacement. At that date only debt was closed; the remaining audit
sections were reviewed later. The current result is stated at the top of this document. Historical counts retain their original scope.

## Debt completion: workflow from 25 September

At the user's request, work proceeds in batches with tests selected by change risk.
The verified reference snapshot is `a8aba986`: 1584 host, 71 config, 2157 Linux,
48 privileged, 8 lifecycle, 38 native cases and 2 recoveries; see
[TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md). These results belong to that
snapshot and do not automatically certify subsequent changes.

| Batch | Groups | Remaining work and completion condition |
|---|---|---|
| A. Startup, shutdown and system context | D05/D06/D09 | Review startup config_source::load/metadata/canonicalize, composed NetworkPlan/cleanup budgets and remaining early Drop paths in one pass; complete the WAN/resolved/attach/dynamic IPv6 table. Record each path as fixed and tested, already covered by referenced evidence, or a justified limitation. Finish with targeted Linux tests of affected boundaries. |
| B. Configuration and remaining network compatibility | D07/D08/D10 | Complete the server field → parse/validate/runtime/serialize table and the 81+3 client contract; cover save/reload/import, malformed input and concurrent edits. Run only uncovered IPv6/NDP, DNS, multiprofile and firewall combinations, grouping related fixes. |
| C. Builds, Android and resources | D11/D12/D13 | Rebuild affected cores at an agreed clean commit, verify A/B/ABI/provenance and Android. Run one bounded churn/reconnect/fault campaign with cycles and fd/tasks/threads/RSS/network-object growth criteria recorded before execution. Retain platform SKIPPED decisions. |
| D. Final regression and measurements | D14/D15 | Run one overall regression campaign on the final candidate, a current benchmark and package/documentation reconciliation. Give every obligation evidence or an explicit unresolved remainder; unverified work cannot be declared closed. |

Batches specify completion order, not a promise of four runs or a calendar deadline.
Fixes and short checks happen inside a batch; advancing does not require another
permission request.

### Test selection

- Each change gets its defect regression, affected module tests and necessary build.
  Docs-only changes get docs/link/diff checks, without Rust or lab runs.
- Related fixes share one test campaign. Run full Linux/host suites at batch boundaries;
  run the full feature/platform matrix on the final candidate, or earlier when
  cfg/features/ABI/dependencies change.
- New native fault/cancel/crash scenarios remain required for changes to ownership of
  networking, keys or persisted state. Unchanged transport and firewall matrices do
  not need to run after every local fix.
- Reproduce against the old binary once. Reuse that baseline with its SHA; repeat it
  only when its scenario, assumptions or an ambiguity changes.
- Reuse evidence only after checking affected code/dependencies and lab conditions,
  recording the original SHA and applicability reason. A newly built binary does not
  invalidate every independent check. The final candidate still gets overall validation.
- Run independent builds/tests concurrently; operations sharing mutable sources,
  target directories or network resources stay sequential. Do not repeat successful
  checks without a relevant subsequent change.

### Scope and reporting

Existing D01–D15 obligations remain. Record new noncritical improvements and unproven
hypotheses in the later full-audit queue without expanding this batch. Include confirmed
security, data/traffic loss or core functional defects with a specific reproducer.

Uninterruptible syscalls and forced Drop require a supported-boundary and ownership
explanation; they do not by themselves restart the audit cycle. Ordinary hangs, lost
errors and ownerless mutations remain mandatory defects. Relabelling a defect as a
limitation does not close it.

Use one batch result entry in this register; small fixes need no separate report.
Preserve logs, commands and hashes as machine artifacts. User-facing results state
behavior changes, closed criteria and a finite remainder. The 4/15 figure counts fully
closed groups; it is not a time or work-completion estimate. Rescheduling alone changes
no completion status.

Initial batch A reconciliation at `a8aba986`: config_source already rejects special
files with NONBLOCK + fstat and validates one opened snapshot. Do not re-audit those
properties unless they change. Remaining checks are synchronous loading before signal
registration, no overall size cap in the loader itself, and startup metadata/canonicalize.
These are concrete review targets. Individual DNS/route/gateway/kill-switch budgets and
joined workers already have evidence; inspect their composition and early exits instead
of repeating every previous scenario.

Privileged external mutation between a check and a write has no atomic protection
guarantee; this is an OS-interface limitation, not automatically a new feature defect.
However, identity loss, command errors and unknown outcomes must retain recovery evidence
and must not produce false success.

### Batch A — verified startup result, September 25

The startup part of D05/D09 is closed: stop handlers precede INI reads, the 256 KiB
client cap precedes content reads/allocation, and loading, capability probes and hook
canonicalization run on a joined worker. The permission warning uses the same opened
snapshot. Stop waits for admitted work; late failures remain errors, with no credential
command or connection started.

Targeted checks: 12 host + 32 Linux tests (15 config source, 8 lifecycle,
9 prepared worker), Linux Clippy and standalone client build. Frozen baseline
`a8aba986` reproduced runtime blocking, SIGTERM exit before handler registration, and
oversized-file reads. Three fixed startup cases and TCP/UDP startup → post_up → stop
passed in separate NET/mount/PID namespaces, preserving routes and operator firewall.
The first stop fixture incorrectly used `pass_cmd`: its strict-parser rejection was
retained and the corrected `password_command` fixture was rerun. Regression retained as
[scripts/audit_client_startup.py](../../../scripts/audit_client_startup.py) and
[test shim](../../../scripts/audit_client_startup_shim.c). Commands, manifests, SHA and logs:
`audit-debt-20260924/batch-a-startup/` under the `qeli` artifact directory.

The server at `a8aba986` (SHA256 `c53dec6b…83c97`) and unchanged teardown fixture are reused;
this change does not affect server behavior. Earlier broad matrices are not claimed as
new runs. D05/D06/D09 remain IN_PROGRESS: composed NetworkPlan/cleanup budget, system
context table and early Drop paths remain. Established boundary: arbitrary kernel/
filesystem I/O cannot safely be interrupted; forced Drop retains its join. This limit
does not close the remaining shared command-budget obligation.

**Shared command budget (batch A continuation).** TUN/gateway/routes/DNS setup shares
15 seconds. Rollback/cleanup receives a separate shared deadline, retained across pump
join, worker threads, fallback Drop and terminal firewall cleanup. Errors remain sticky;
a new attempt after previous owners finish receives a fresh budget. Ownership selectors,
namespace guards and kill-switch release prerequisites are not weakened.

Validated: 1594 host tests, 471 targeted Linux tests and 18 privileged; Linux Clippy,
client-only and server-only builds. Eight native baseline/fixed TCP/UDP cases inject
successive 9+9 second delays: old `efc9f949` takes 19–20 seconds. Fixed setup expires
commands at the shared deadline and finishes rollback about 15.9 seconds after the first
marker; cleanup takes about 14.8 seconds from its first mutation marker (its budget began
earlier). Setup leaves clean networking; failed cleanup retains both DROP families and
`failed`, preserving operator rules/routes. Four ordinary TCP/UDP clean/fault shutdown
cases and two explicit recovery runs also PASS. Fixture:
[audit_network_budget.py](../../../scripts/audit_network_budget.py). Evidence:
`audit-debt-20260924/batch-a-budget/`, 359-file source manifest, driver SHA256
`ef126a15…934a4f7`. Server `a8aba986` is reused; its runtime is not claimed as a new build.

A separate restart after **gateway timeout** confirmed the D02 boundary: a lost
per-interface sysctl witness prevents automatic cleanup completion. The initial automatic
recovery expectation produced 2 FAIL retained in `ab3`; this is not successful recovery.
Validation checks preservation of the original record, absence of TUN/routes and both
DROP families; follow [§6.64](../manuals/TROUBLESHOOTING.md) for manual recovery.
The two successful recovery cases above refer to the earlier route-fault scenario without
lost witnesses.

Command composition is closed within these limits; no hard arbitrary-kernel-I/O timeout
is promised. D05 remains IN_PROGRESS pending the final early-Drop/internal-wait inventory;
D06 remains open for the checks below. Group totals remain 4/15 DONE.

D06 reconciliation against current code (no new runtime PASS claim):

| Boundary | Existing evidence / remainder |
|---|---|
| resolved / system bus | GUID/unique owner/network/PID context already exercised in [resolver context](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md); DNS v2 markers/crash are D04. |
| procfs / sysfs | Namespace pins, cookie and sysctl witnesses are D02/D04. IPv6 module-disabled evidence uses bounded strict reads; it does not guarantee absence of future IPv6. |
| TUN attach / names | [Attach](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md), leases and route/TUN identity have dedicated checks. `dev_attach` reads `tun_flags` through `/sys/class/net`, which may belong to an inherited network namespace. The [kernel netlink snapshot](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c) omits some `TUN_FEATURES`, and the first `TUNSETIFF` may rewrite them; a simple netlink substitution is unsafe. [Q25-F123](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH-CONTEXT.md) adds a native same-name/different-netns test and rejects a proven `ifindex` mismatch before `TUNSETIFF`. Matching indexes do not prove namespace identity; this combination remains uncertified until full namespace-aware flag observation is available. |
| Physical WAN | `gateway/wan.rs` returns a route's device name; firewall records name selectors. [Q25-F120](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IPV6-ROAM.md) rechecks the IPv6 default route after the roaming COMMIT rule batch. [Q25-F124](../reports/audit-0.8.2/AUDIT-Q25-EXIT-POLICY-ROUTING.md) reproduces un-NATed off-WAN egress under policy routing and adds a fail-closed DROP before MARK/NAT plus cleanup lockdown. [Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) confirms that a distinct new name is blocked, but a new device reusing the old name inherits MARK/NAT without refresh. [Q25-F126](../reports/audit-0.8.2/AUDIT-Q25-WAN-METRIC.md) selects the lowest-metric main-table default; a separate exit-WAN change without VPN COMMIT is now handled by the [Q25-F127](../reports/audit-0.8.2/AUDIT-Q25-EXIT-WAN-MONITOR.md) monitor, verified on TCP/UDP through cleanup. Active-WAN rename/reuse is unsupported until an identity-bound backend exists; migration and mixed-backend packet/recovery remain D06/D10. [Q25-F128](../reports/audit-0.8.2/AUDIT-Q25-EXIT-SELF-WAN.md) rejects the exit TUN itself as a WAN before installing rules. [Q25-F129](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md) rejects ECMP and equal-priority defaults on different WANs instead of selecting one destination hash bucket; the client IPv6 gateway also refuses before changing forwarding/RA. |
| DNS / carrier globals | DNS is per-link; process-global carrier/cycle state is protected by one run_client per process through terminal cleanup. Forced Drop closes readmission until process restart; verification below. |
| Dynamic IPv4 | [Q25-F122](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV4.md) disallows admission without `iptables` based on a currently empty default-route list; a late route cannot bypass a missing firewall. Other WAN/route scenarios remain D06/D10. |
| Dynamic IPv6 | [Q25-F121](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md) disallows unprotected admission based on a currently empty address list; late IPv6 cannot bypass a missing firewall. The native address-arrival matrix and other dynamic paths remain D06/D10. |

**Linux runtime admission and early-exit reconciliation (batch A continuation).**
Concurrent `run_client` calls no longer overlap process-global carrier/cycle state:
the second call fails before config/signals, and admission lasts through cleanup and
final writer completion. A returned error permits another invocation with the usual
resource checks. Forced Drop of the whole future closes admission until process restart:
nested TaskGroups cannot guarantee async join in Drop. This is an explicit cancellation
boundary, not a claim of successful network cleanup.
[Contract](../manuals/OPERATIONS.md#one-linux-client-per-process).

Against the original `b307c913` entry point, the rejection-before-missing-INI check
produced the expected FAIL: the old invocation reached file open while the process gate
was occupied. The fixed entry point, simultaneous admission, terminal ownership,
cancellation with an in-flight child and panic passed: 7 host + 85 Linux tests, Linux
Clippy. Three privileged tests of unchanged namespace workers remain ignored in this
targeted run; no new privileged PASS is claimed. Final commands/exit codes/manifest: `audit-debt-20260925/batch-a-instance/`.

Linux client early-path reconciliation against current code and previous evidence:

| Path / wait | Outcome and boundary |
|---|---|
| Startup/NetworkPlan before adoption | `network_task::Job::Drop` rejects the result and joins the original thread; partial guards roll back there. [Network worker](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md), startup and budget above. |
| Pump start / partial plan | Writer failure stops and joins the reader; rejected `(pump, guard)` drops in that order. [Pump start](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md). |
| Established TUN / ordinary error | `TunGuard::shutdown` awaits DNS → pump → routes/gateway; fallback Drop retains the TUN fd and shared cleanup deadline. [Teardown](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md), budget above. |
| TCP/H2/UDP child tasks | Ordinary exits finish TaskGroups before terminal cleanup; Drop only closes admission/requests abort. Forced cancellation of the entire run_client now prohibits reuse in that process. [TCP](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md), [H2](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md), [UDP](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md). |
| TOFU/status / file I/O | finish awaits the worker; fallback Drop joins synchronously. Sender/queue mutexes are not held during file operations. [TOFU](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md), [status](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md). |
| Internal locks / waits | Carrier/core/diagnostic state changes under short mutexes without await; writer queues release their mutex before external I/O. TunWorkers deliberately holds its join lock through all threads so cancellation cannot abandon fd ownership. [TUN workers](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md). Non-preemptible kernel/fs I/O and forced join remain a documented boundary, not a 15-second process-exit guarantee. |

This closes reconciliation of the listed Linux early-Drop paths and process-global
admission. D05/D06/D09 were not closed at that stage: hook/backup file preparation
needed runtime reproduction. The following batch continuation closes that part;
server setup/cleanup still requires checking. WAN/dynamic IPv6 remain in D06. No new platform or network packet PASS is claimed.

**Hook and backup file I/O (batch A continuation).** Executor stalls during hook context
write/removal and active backup INI reading were reproduced and fixed. One joined thread
owns hook preparation, command runtime and cleanup; cancellation before spawn skips the
command, while cancellation of a running shell waits for termination/reaping before
context removal. Backup preflight uses the existing blocking worker with its config
lease; HTTP cancellation cannot release it before the operation ends. The shared loader
rejects FIFO and checks a stable source file. Hook authorization and INI/API formats
are unchanged.

Validation: **37 host + 77 Linux tests, 8 native scenarios PASS**, Linux Clippy and separate
client/server builds. The reproducer delays actual write/unlink/read by 2 seconds:
original `0645a8b0` handlers deliver 0/0/2 heartbeat ticks (3 expected FAIL), fixed handlers
178/178/179. Cancelled preparation leaves no command-start marker; cancellation of a live
hook verifies reaping/process absence and context removal. Cancelled backup retains the
config lease, preserves config and delivers 178 ticks. Backup → overlay/exact restore and
incomplete rollback-snapshot rejection ran in private NET/mount/PID namespaces and tmpfs
`/etc/qeli`, `/tmp`. Shim: [audit_hook_backup_io_shim.c](../../../scripts/audit_hook_backup_io_shim.c).
Logs/commands/362-file source manifest: `audit-debt-20260925/batch-a-file-io/`;
fixed test binary SHA256 `208e91b7…500bba`. Baseline combines the original handlers with
the new test harness; it is not an old released binary.

This hook/backup item is closed; D05 remains IN_PROGRESS. Server code review specifies
the next batch: `run_worker` invokes synchronous `nat::cleanup_all`;
`run_profile_generation` performs TUN/NAT setup, and ordinary `run_profile` calls
`drop(ProfileTeardown)` with NAT cleanup/worker joins on its async path. NAT component
budgets already have coverage; scheduler isolation and a composed profile deadline
still need checking. Non-preemptible kernel/fs calls and forced joins are not claimed
to have a hard timer bound. D06 WAN/dynamic IPv6 and other groups remain; **4/15 DONE**.

### Q25-F115 — server cleanup off the async executor

Synchronous `nat::cleanup_all`, ordinary `ProfileTeardown::drop`, final NAT
sweep/ownership checks and `usage.flush` run on joined workers. Cancelling an async
waiter joins its worker, so the network namespace lease and profile resources cannot
be released before accepted cleanup finishes. Child-task shutdown, registry removal,
NAT and TUN cleanup keep their order; a worker failure enters `Outcome`.
[Report](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CLEANUP-WORKER.md).

Host: 1602 tests PASS, 1 pre-existing ignored; Linux cross-check and all-targets
Clippy PASS. Lab `.11`: 10 targeted Linux tests and eight real TCP/UDP ×
`off`/`manual`/`route`/`nat66` lifecycle cases and 2 bind-failure/rollback/retry cases PASS in private NET/mount/PID
namespaces. Exact source manifest and logs:
`audit-debt-20260925/server-cleanup-phase/`. D05 remains IN_PROGRESS:
synchronous TUN/NAT setup, emergency Drop, a composed profile deadline and
non-preemptible system calls still need separate resolution. Register total:
**4/15 DONE**.

### Q25-F116 — server profile TUN/NAT setup off the executor

The first joined worker creates and configures TUN: until its result is adopted,
the non-persistent device belongs to its original fds. After adoption,
`ProfileTeardown` owns the queues; only then does a second worker install
NAT/IPv6 routing. Cancelling a waiter joins its running worker before dropping
the outer guard. [Report](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-WORKER.md).

1603 host tests PASS, 1 previously ignored; 11 targeted Linux tests, Linux
all-targets Clippy and 8 ordinary plus 2 bind-failure/retry cases in private
namespaces on `.11` PASS. Source/logs:
`audit-debt-20260925/server-setup-phase/`. D05 remains IN_PROGRESS: DNS INPUT
firewall, NDP bind, emergency Drop and the composed deadline for all operations
remain. Register: **4/15 DONE**.

### Q25-F117 — server profile DNS firewall setup off the executor

Both DNS INPUT/REDIRECT installs run on joined workers. Cancelling a waiter
closes adoption; an unadopted `DnsInputLease` is destroyed in its original
namespace before the outer guard drops. An adopted lease moves into
`ProfileTeardown`. [Report](../reports/audit-0.8.2/AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md).

1603 host tests PASS, 1 previously ignored; 11/11 targeted Linux tests,
22/22 recovery/ownership/SIGKILL checks, 4/4 TCP/UDP × IPv6 `manual`/`route`
DNS cases in private namespaces on `.11` PASS. Logs and manifest:
`audit-debt-20260925/server-dns-setup-phase/`. D05 stays IN_PROGRESS:
NDP bind, emergency Drop and whole-setup deadline remain. Register: **4/15 DONE**.

### Q25-F118 — NDP bind off the executor

`AF_PACKET` bind and socket-local multicast membership run on a joined
worker; the adopted `OwnedFd` is registered as `AsyncFd` on the original
Tokio runtime. Cancellation closes an unadopted fd before the outer guard
is destroyed. [Report](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NDP-BIND-WORKER.md).

On `.11`: 5 NDP unit, 1 privileged namespace, 8 lifecycle and 22 recovery
checks PASS; Linux Clippy for library/binary and rustfmt PASS. Source and logs:
`audit-debt-20260925/server-ndp-bind-phase/`. D05 stays IN_PROGRESS:
whole deadline, forced Drop and arbitrary kernel/fs I/O. Register:
**4/15 DONE**.

### Q25-F119 — shared server setup deadline and all-listener readiness

A 120-second budget runs from generation start until primary and every extra
listener confirms bind; after readiness, service has no such timer. UDP reports
readiness after its complete SO_REUSEPORT group. Bind errors belong to setup,
not cleanup. [Report](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md).

On `.11`: 2 new + 11 worker tests, 8 lifecycle, 4 occupied-bind
rollback/retry/stop and 22 recovery checks PASS; Linux Clippy library/binary,
rustfmt and docs checks PASS. Failed first run and corrected rerun are in
`audit-debt-20260925/server-setup-budget-phase/`. D05 stays IN_PROGRESS:
forced Drop, whole-shutdown deadline and non-preemptible kernel/fs I/O.
Register: **4/15 DONE**.

### D09 — final Linux lifecycle reconciliation, 25 September

The [report](../reports/audit-0.8.2/AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md) ties the current
Linux suite (2175 PASS), 8 control and 15 hook-process tests to eight live
worker cases. Raw before/after firewall/routes/links/forwarding snapshots, binary
and harness SHA, stdout and exit codes are retained. An initial snapshot assertion
falsely flagged empty xtables-nft built-in tables; raw dumps remain and the comparison
was corrected. The first full suite hit EMFILE at nofile=1024 in a 512-connection
TCP test; unchanged code passed with nofile=4096. Prior privileged/DNS/route/crash
evidence was checked against the unchanged paths.
**D09 DONE; register: 5/15 DONE (33.3%), 8 IN_PROGRESS, 2 TODO.**
Install/upgrade and systemd runtime remain separate full-audit and D11 work;
D05/D06/D10 retain their status.

### Q25-F130 — server worker admission after cancellation

After the first network mutation, forced Drop or an unconfirmed terminal result
retains the network-namespace lease until process exit. Early rejection and
successful ordinary shutdown release it; a replacement worker cannot overlap
an unfinished generation. [Report and checks](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md).
This partially closes D05: async child joining on forced Drop and the whole
shutdown deadline remain open. Register: **5/15 DONE**.

### Q25-F131 — WAN presence during server setup

The selected IPv4 NAT or managed IPv6 uplink is now checked with an ioctl in the
worker network namespace before enabling forwarding or adding rules.
[Report and 1 unit + 8 ordinary + 2 negative Linux runs](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WAN-PRESENCE.md).
Active-WAN name reuse, atomic binding of rules to device identity and mixed-backend
recovery remain open. D06 stays IN_PROGRESS; register **5/15 DONE**.

### Q25-F132 — ambiguous server auto-WAN

The shared client/server default-route parser detects ECMP and equal best metrics
on different WANs. Server auto mode refuses before forwarding and new rules;
[report: 11 parser + 1 WAN unit, 8 ordinary and 2 negative Linux cases](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WAN-ECMP.md).
Explicit WAN, policy routes and runtime changes remain D06/D10;
register **5/15 DONE**.

### Q25-F133 — client core build without the roaming feature

The exit WAN monitor runs on Linux regardless of experimental-roaming, but TCP
and UDP declared the TUN name only under that feature. The client-only build
failed with two E0425 errors; the declaration is now Linux-scoped.
[Report, baseline FAIL and fixed feature builds](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-ONLY-BUILD.md).
The router client binary built and ran with --help; platform runtime and
provenance remain D11/D12. Register **5/15 DONE**.

## Sources

- [AUDIT-Q01-SERVER-INI](../reports/audit-0.8.2/AUDIT-Q01-SERVER-INI.md)
- [AUDIT-Q02-CLIENT-PARSERS](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md)
- [AUDIT-Q05-PREFLIGHT](../reports/audit-0.8.2/AUDIT-Q05-PREFLIGHT.md)
- [AUDIT-Q14-CONTROL](../reports/audit-0.8.2/AUDIT-Q14-CONTROL.md)
- [AUDIT-Q14-DNS-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md)
- [AUDIT-Q14-H2-TASKS](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md)
- [AUDIT-Q14-HOOKS](../reports/audit-0.8.2/AUDIT-Q14-HOOKS.md)
- [AUDIT-Q14-IPV6-PARTIAL-ACQUIRE](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md)
- [AUDIT-Q14-NAT-CLEANUP](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md)
- [AUDIT-Q14-NAT-COMMANDS](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md)
- [AUDIT-Q14-OWNED-SHUTDOWN](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md)
- [AUDIT-Q14-PROFILE-SHUTDOWN](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md)
- [AUDIT-Q14-Q15-WORKER-USAGE](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md)
- [AUDIT-Q14-Q19-LIFECYCLE](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md)
- [AUDIT-Q14-Q25-FIREWALL-CHECKS](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md)
- [AUDIT-Q14-Q32-NOTIFICATIONS](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md)
- [AUDIT-Q14-Q33-CONFIG-TRUST](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md)
- [AUDIT-Q14-SUPERVISOR](../reports/audit-0.8.2/AUDIT-Q14-SUPERVISOR.md)
- [AUDIT-Q14-SYSCTL-RECOVERY](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md)
- [AUDIT-Q19-DNS-CACHE](../reports/audit-0.8.2/AUDIT-Q19-DNS-CACHE.md)
- [AUDIT-Q19-DNS-EDNS](../reports/audit-0.8.2/AUDIT-Q19-DNS-EDNS.md)
- [AUDIT-Q19-DNS-PROXY](../reports/audit-0.8.2/AUDIT-Q19-DNS-PROXY.md)
- [AUDIT-Q19-Q22-NETWORK-PLAN](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md)
- [AUDIT-Q25-CLIENT-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md)
- [AUDIT-Q25-CLIENT-NAMESPACE](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md)
- [AUDIT-Q25-CORE-LIFECYCLE](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md)
- [AUDIT-Q25-CREDENTIAL-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md)
- [AUDIT-Q25-DNS-LEASES](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md)
- [AUDIT-Q25-DNS-RECOVERY](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md)
- [AUDIT-Q25-EXIT-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md)
- [AUDIT-Q25-GATEWAY-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md)
- [AUDIT-Q25-GATEWAY-ROLLBACK](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md)
- [AUDIT-Q25-GATEWAY-WAN](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md)
- [AUDIT-Q25-H2-TASKS](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md)
- [AUDIT-Q25-KILL-SWITCH-LIFETIME](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md)
- [AUDIT-Q25-NETWORK-CLEANUP](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md)
- [AUDIT-Q25-PASSWORD-FILES](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md)
- [AUDIT-Q25-PATH-MONITOR](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md)
- [AUDIT-Q25-ROUTE-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md)
- [AUDIT-Q25-ROUTE-OUTCOME](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md)
- [AUDIT-Q25-ROUTE-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md)
- [AUDIT-Q25-ROUTE-PENDING](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md)
- [AUDIT-Q25-ROUTE-POSTCONDITIONS](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md)
- [AUDIT-Q25-ROUTE-SCOPE](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md)
- [AUDIT-Q25-SETUP-FLUSH](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md)
- [AUDIT-Q25-SETUP-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md)
- [AUDIT-Q25-SYSCTL-NAMESPACE](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md)
- [AUDIT-Q25-SYSCTL-OWNER-EVIDENCE](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md)
- [AUDIT-Q25-SYSTEM-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md)
- [AUDIT-Q25-TCP-TASKS](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md)
- [AUDIT-Q25-TUN-ADMISSION](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md)
- [AUDIT-Q25-TUN-ATTACH](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md)
- [AUDIT-Q25-TUN-CLEANUP](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md)
- [AUDIT-Q25-TUN-LIFETIME](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md)
- [AUDIT-Q25-TUN-WORKERS](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md)
- [AUDIT-Q25-TUNNEL-ROUTES](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md)
- [AUDIT-Q25-UDP-TASKS](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md)

D02/D05: [sysctl journal reads and lock waits](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-JOURNAL-IO.md) are fixed within the stated scope; remaining row criteria are open.

D03: [kill-switch namespace / reconnect](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md).

D02/D06: [namespace-aware link observation](../reports/audit-0.8.2/AUDIT-Q25-LINK-OBSERVATION.md).

D05: [async preflight and panel transaction lifetime](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md). The following phase closed the backup/restore budget; other network sequence budgets remain open.

D05/D09 update: [backup/restore budget and snapshot completeness](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md). Other network sequences and filesystem fault E2E remain open.

D02: [internal sysctl boundary guard](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md); durable namespace identity and original-interface ownership remain open; a later phase closed parent trust.

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

D05/D09: [Q25-F111 — ordered diagnostics writer](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md): one thread, one pending snapshot, joined final write; file I/O outside the async executor. 5 new portable + 1 privileged test; 2 baseline + 4 fixed fsync cases, 2 baseline + 4 fixed TCP/UDP teardown and 2 recoveries PASS. 1569 host + 71 config; 2133 Linux + 48 privileged + 8 lifecycle PASS. D05 remains open: other locks/I/O, early Drop and the overall deadline. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F112/F113 — identity files](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md): ID loads once on a joined worker and temporary identity survives reconnect; TOFU is capped at 1 MiB, corrupt/conflicting pins reject new trust, writes are atomic. 15 new tests; 8 baseline + 8 fixed identity cases, 6 teardown cases and 2 recoveries PASS. 1575 host + 71 config; 2148 Linux + 48 privileged + 8 lifecycle PASS. D05 remains open: synchronous TOFU, other startup I/O/Drop and overall deadlines. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F114 — TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md): one joined thread owns trust-file I/O; stop and timeout retain admitted writes and late errors until terminal result. 9 portable regressions; 16 worker cases + 16 file cases + 6 teardown and 2 recoveries PASS. 1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS. Overall deadlines and other startup I/O/Drop remain D05. **Debt: 4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO.**

### Q25-F205 — panel client shutdown, 1 October 2026

A concrete D05 remainder is resolved: outbound-client shutdown no longer adds
five seconds per profile. Every manager-owned process receives SIGTERM concurrently
and shares the original five-second grace, including registry admission.
The first shutdown request closes Connect/autostart admission; repeated or cancelled
waiters do not reset the deadline. Forced kill, unsuccessful exit and signal/wait errors
reach the supervisor terminal result together with the main worker failure.

Disconnect retains the original Child until reaping even when its HTTP waiter is
cancelled. A per-profile lock prevents replacement while that process is still cleaning
up; status checks for other profiles do not wait for it. Shutdown creates no detached
handle owners, and observed failures survive waiter cancellation. Five new process
regressions plus existing autostart: **6/6**; related supervisor **19/19**, shutdown
**10/10**, profile tasks **19/19**, total **54 PASS**. Rustfmt PASS. Rust 1.97 Clippy
passed with `-D warnings -A clippy::useless_conversion`; without that exception it
failed on two unchanged portable UDP conversions. Both outcomes are retained.

[Machine evidence](../../../release/certification/evidence/client-shutdown-20261001.json)
contains hashes of all 287 tested Rust files, the test binary SHA, outputs and raw hashes.
The lab's working PID 845, listener 443 and release SHA `a526c03b` were preserved.
Tests use real child processes without network mutations; no new release VPN/E2E or
benchmark was run. The original sequence was established by production-source review;
the old release binary was not executed for this finding.

D05 remains IN_PROGRESS: async joining before resource destruction during forced Drop
and the total worker/supervisor shutdown wall-clock bound. Five seconds bounds only
outbound-client grace; kernel reaping/fs I/O is not promised to be interruptible.
D11/D14 evidence and **9/15** above describe tested candidate `62c84fc4`.
This server change modifies the native source digest and release tree; old provenance
and certification do not certify the new HEAD. Build evidence and certification refresh
belong to final D15 package assembly, rather than rerunning unchanged transport/firewall
matrices after every local fix.

### Q25-F206 — profile resources after forced cancellation, 2 October 2026

The D05 async-join/host-cleanup ordering item is closed. Previously Drop requested
task cancellation and immediately released TUN/DNS/NAT while a descendant could
still be running its destructor. ProfileScope now transfers both generation resources
and joinable task sets to the worker. The worker joins them before resource deletion,
the global NAT sweep and terminal hooks. Cancelling the drain requeues the entire
generation; no detached cleanup owner is created. Forced cancellation remains a
terminal failure even after successful cleanup. If the worker future itself is
destroyed, unfinished resources and its network lease remain retained until process
exit; a replacement in-process worker is rejected.

A regression with real TUN and DNS INPUT rules delays a descendant Drop. Its control
invokes the unchanged production ProfileTeardown destructor directly: **expected FAIL**,
resources disappear too early. This exercises the previous ordering with the same
test binary, rather than executing an old release. The fixed guard: **1/1 PASS**,
including cancelled initial drain, retained resources and repeated joining.
Ordinary teardown **13/13**, profile tasks **19/19**, shutdown **10/10**,
supervisor **19/19**, panel clients **6/6**, totaling **67 unit PASS**.
The current debug binary passes **8/8** live worker TCP/UDP × off/manual/route/nat66
with reload, second-worker rejection, SIGTERM and network-state restoration.
Full parent-host snapshots match; the working listener 443/PID 845 is preserved.

[Machine evidence](../../../release/certification/evidence/deferred-profile-20261001.json):
287 verified Rust source SHA pairs, test/debug binary SHA, commands, results,
raw hashes and host snapshots. Rustfmt PASS; Rust 1.97 Clippy PASS with the existing
exception for two portable UDP conversions: `-D warnings -A clippy::useless_conversion`.
The first compilation failed on mutability and the first build command on a driver
path; corrected runs succeeded and the initial logs are retained.

**D05 remains IN_PROGRESS for the overall shutdown budget within the stated limits**:
this fix adds no single wall-clock deadline and cannot interrupt kernel/fs I/O.
Historical **9/15 DONE (60%)** and D11/D14 apply to candidate `62c84fc4`;
the new HEAD requires final native/provenance/certification refresh under D15.

### Q25-F207 — concurrent worker and panel-client stop, 2 October 2026

Sequential supervisor shutdown composition is fixed. Previously outbound-client stop
began only after supervise returned, potentially 60 seconds after the signal.
Connect/autostart remained open until then, and the client grace was added after
worker waiting. Handling SIGTERM/SIGINT now synchronously closes client admission
before the worker's SIGTERM. One coordinator polls both supervisor-owned waits
concurrently and returns both results; it creates no detached tasks. Supervise
completion without a separate stop signal also starts client cleanup. Cancelling
the coordinator preserves existing guards and the manager's original deadline;
neither path's failure is discarded.

Targeted shutdown **13/13**, panel clients **7/7**, supervisor **19/19**,
notifications **8/8**: **47 PASS**, including four new regressions.
Live checks launch real supervisor/worker/client processes in separate NET/mount/PID
namespaces. The retained Q25-F206 debug binary reproduces sequential waiting:
with an eight-second post_down the client is still alive at 6.20 seconds,
and the total stop takes 13.24 seconds. The current debug binary reaps the client
at 5.02 seconds while the worker hook is still running; total stop takes 8.25 seconds.
Both supervisors return expected exit 1: the TCP peer deliberately leaves handshake
unanswered, forcing client kill and leaving its VPN cleanup unconfirmed.
This verifies delay/reaping and failure reporting, rather than a successful VPN handshake.

Both runs remove worker TUN/tagged NAT, restore the original forwarding value and
reap every child. Full parent-host snapshots match; listener 443/PID 845 and the
working release SHA are preserved. Rustfmt PASS; Rust 1.97 Clippy PASS with the existing
`-D warnings -A clippy::useless_conversion` exception. Evidence retains SHA for 287
sources, both debug binaries and the test binary, initial compile/fixture failures and
corrected runs. Full transport/benchmark matrices were not repeated.

Checks and exact SHA are recorded in
[machine evidence](../../../release/certification/evidence/stop-composition-20261002.json).
This fixes composition of existing grace periods rather than adding a single worker
shutdown deadline. Notification waiting, async joins, blocking host cleanup and kernel
reaping retain their documented limits. **D05 remains IN_PROGRESS**; final native
rebuild and release certification after server changes remain D15. Historical
**9/15 DONE (60%)** apply to the verified candidate `62c84fc4`.

### Q25-F208 — total CLI shutdown and notifications, 2 October 2026

The final D05 criterion is closed within its declared boundaries. CLI workers start
an OS-thread **45-second** clock, independent of Tokio, on the first observed stop/fatal
event before stop diagnostics. It remains armed through control handlers, services,
profile/deferred joins, NAT/sysctl, hooks, counter persistence, control-socket removal
and final logging. Repeated arm does not refresh it; cancelling the owning future does
not revoke an armed timer. Normal completion disarms and joins its thread. Late
completion cannot win merely because the monitor was scheduled late.

On expiry the worker closes command admission, kills tracked groups of owned commands
whose leaders remain unreaped, and calls `_exit(124)` without Rust Drop, logging or C
atexit. Spawn/reap/group signalling share one registry to prevent signalling a recycled
PGID. The supervisor classifies 124 as a deadline failure with cleanup unconfirmed.
Normally detached background services with closed pipes retain their existing contract.
Worker and supervisor notifications close admission and retain their original ten-second
grace from stop; draining runs concurrently with cleanup. The supervisor retains sixty
seconds for its worker and five for clients, polling all owned waits concurrently.

**136 targeted unit PASS**: process budget 6, notifications 9, supervisor 20,
shutdown 13, teardown 13, profile tasks 19, hook process 15, credential supplier 13,
system commands 21, panel clients 7. Eight new regressions include real child processes
with a stalled Tokio executor, timer-owner cancellation and exit 124. This is a targeted
set, not a new execution of all 2317 unit tests.

In isolated NET/mount/PID namespaces the retained Q25-F207 debug binary remains alive
48 seconds after stop when one post_down metadata call is delayed for sixty seconds.
Only the harness terminates it. The new worker exits itself after forty-five seconds
with code 124; another post_down starts a shell and sleep after thirty-five seconds of
preparation. The controller reaps the owned group leader and sleep with SIGKILL and
checks that every observed member has disappeared from `/proc`. TUN/tagged NAT are gone;
the unfinished sysctl journal remains. The next ordinary worker recovers forwarding and
exits normally with zero. Foreign INPUT rules, routes and other settings are preserved.
**8/8** ordinary TCP/UDP × off/manual/route/nat66 lifecycle cases with reload, refusal
of a second worker and stop PASS. Full outer-host snapshots match; the working listener,
PID and release SHA are preserved.

[Evidence](../../../release/certification/evidence/worker-budget-20261002.json) retains
288 verified Rust SHA values, test/debug SHA, commands, the initial Clippy failure and
correction, and the first fixture failure and corrected child-reaping assertion. The
outer shell could reap its script child before dying itself; requiring that child's
wait status again was a harness error. The corrected assertion requires SIGKILL for
the group leader and sleep and disappearance of every observed PID. Rustfmt, all nine
docs checks and diff PASS; Rust 1.97 Clippy PASS with the existing
`-D warnings -A clippy::useless_conversion` exception.

The limitation is justified: this is a CLI process boundary after an observed stop,
not an absolute guarantee from OS signal delivery. Preparation before shutdown, library
`run_worker`, arbitrary kernel exit/reaping and stalled spawn under the registry are not
safely preempted; library cancellation retains resources/namespace quarantine. Kernel
failure has no exact wall-clock guarantee. An application filesystem worker and an active
hook group are verified with real process exit and recovery. These limits are not reported
as PASS for arbitrary kernel failures. **D05 DONE; register: 10/15 DONE (66.7%),
5 IN_PROGRESS**. Final native/provenance/certification refresh remains D15; the historical
candidate `62c84fc4` certificate does not certify current HEAD.

### Q25-F209 — mixed configuration lifecycle, 2 October 2026

The remaining D07 scope is closed after the global and profile field matrices.
A new reproducible [harness](../../../scripts/audit_panel_config_lifecycle.py) exercises
the real HTTP panel, supervisor and TCP/UDP worker in private NET/mount/PID namespaces.
Rust code is unchanged: no new production defect was found in these scenarios.
The generator again confirms 163 parser names, three dynamic families and a current
165-entry fixture; this is parser coverage, not 165 separate network E2E cases.

**201 targeted unit tests PASS**: server 78, INI 22, config_source 16, panel config 38,
control 7, backup 32, status 4, preflight 4. All three privileged backup tests ignored
by the ordinary suite ran separately in isolation: exact/overlay roundtrip, rollback
refusal for an unreadable file, and ownership during slow backup I/O. The last also
ran with cancellation: **4 executions PASS**. Initial `server::web::api::*` filters
selected zero tests and are not counted; corrected `web::api::*` runs require a
nonempty selection for every group.

**44/44 HTTP/runtime checks PASS**: invalid INI/form/privileged-hook refusal;
mandatory revisions, stale tabs and exactly one concurrent-write winner; waiting
for an external process holding the shared lock and preserving its bytes on conflict;
live web versus saved profile versus startup-only web; refusing restart before
stopping a healthy worker; explicit restart applying a new TCP bind; Quick Start/
check-config/history rollback; malformed archive and exact restore preserving the
lock inode and identity; password rotation revoking the old cookie without restart;
normal stop restoring forwarding, TUN and foreign firewall rules. Identity survives
all operations. The first intermediate run had 43 checks; the final harness adds an
end-to-end identity comparison and reports PASS only after completing the scenario.

The [panel manual](../manuals/PANEL.md#server-config-writers-v1) defines the boundary:
every cooperative external writer must flock the canonical `<config>.lock` from
read through publication. Revision and the second check detect a completed manual
edit or changes during preparation. An arbitrary root writer ignoring that lock
between the final check and rename cannot be made atomically coordinated. This is
an explicitly unsupported writer protocol, not a PASS. Such editing requires stopping
Qeli, finishing competing panel/CLI writes, validating INI and starting again.

All 288 Rust inputs and debug/test SHA match the preceding exact-build evidence.
No new build, Clippy or full benchmark matrix ran in this batch. Full external `.11`
host snapshots match before/after both sets; the running release and listener
443/PID 845 are preserved; `.10` is untouched. Commands, SHA, results and raw manifest:
[machine evidence](../../../release/certification/evidence/config-mixed-20261002.json).
Network combinations remain D10 and final native/certificate refresh remains D15;
this is not certification of current HEAD or completion of the whole 37-step audit.
**D07 DONE; registry: 11/15 DONE (73.3%), 4 IN_PROGRESS — D06/D08/D10/D15.**

### Q25-F210 — client store ownership and D08 closure, 2 October 2026

D08 is closed within the available scope, retaining the agreed D12 exclusions.
Q25-F197 covers all 84 shared INI editor fields and 1000 deterministic mutations.
Its Rust code is unchanged; no new coverage-guided fuzzing is claimed. External
writers are bounded by the protocol below. Automatic reconnect and Wi-Fi transition
are covered by preceding Android VPN E2E Q25-F203, not by a new traffic run here.
Unavailable Mac/iOS/Windows VM/router checks remain **SKIPPED by user decision**,
not PASS; full mobile lifecycle and release delivery remain the full audit.

A second iOS writer was found and removed: when the archive was absent,
`ProfileStore.load()` saved a template in PacketTunnel as well as in the app.
During first publication the extension could overwrite the app's profiles with its
template. Only initial AppModel now explicitly allows missing-store initialization;
PacketTunnel and ordinary load are read-only and fail for an absent archive.
Reading existing ciphertext no longer creates a missing master key: it preserves
the encrypted original and requests backup recovery. Two XCTest regressions and
EN/RU messages were added. XCTest and iOS compilation **did not run** because the
Apple lab is excluded; call sites, guard ordering and absence of write/key-create
in the reader branch were reviewed. A single `@StateObject AppModel` serves the
WindowGroup on MainActor; PacketTunnel reads and widgets cannot access profiles
or keys. There is no second app-owned profile writer among these processes;
arbitrary external-process UserDefaults transactions are not promised atomic.

A new desktop conformance regression launches **two independent OS processes**:
both read one initial version, exactly one publishes, the other refuses; winner
bytes and `.bak` survive and a fresh reader writes after both exit. Full .NET
selftest: **511 PASS, 0 FAIL**, exact Windows DLL SHA `653522e6`. The first run placed
build artifacts outside the tree, could not find boundary corpus and reported one
FAIL. Corrected ordinary project output executes that corpus, including 19 additional
checks. The initial refusal is retained and not counted as PASS.

Android: **167 JVM, 0 failures/errors/skipped**; debug and androidTest APKs built.
**12/12 instrumentation PASS** on Android 14/API 34 x86_64 AVD, including real
INI → packaged JNI → AES-GCM/Keystore → re-read after a port edit → stale-write refusal.
This tests storage/adapters, not a new VPN handshake or UI editing during active VPN.
Both APK `.so` files equal committed A/B libraries. No native rebuild ran here;
final refresh remains D15. The read-only AVD exits without saving; userdata hashes
and the full external host snapshot match; working release/listener 443/PID 845
are preserved and `.10` is untouched.

Supported writing: desktop instances use shared ProfileStoreFile, sidecar and
observed revision; Android Activities share one process/SharedPreferences with an
encrypted version; iOS uses the single app writer. Edit/import INI through the app,
not by changing the encrypted store. Arbitrary external writers bypassing coordination
are unsupported: hash/revision does not close the final check-to-rename gap. Store
maintenance requires finishing all writers and using supported backup restoration.
Editing saved active INI does not rewrite an existing session; reconnect explicitly
when the app requests it. Previous reconnect E2E is not counted as a new execution.

[Checks and SHA](../../../release/certification/evidence/client-store-20261002.json).
**D08 DONE; registry: 12/15 DONE (80%), 3 IN_PROGRESS — D06/D10/D15.** This is not full
audit completion, iOS runtime PASS or certification of current HEAD.

### Q25-F211 — combined IPv6/DNS/NDP matrix, 2 October 2026

Added a reproducible [isolated runtime scenario](../../../scripts/audit_worker_ipv6_multiprofile.py):
four real dual-stack `off/manual/route/nat66` profiles, two TCP and two UDP, a shared
WAN, independent DNS listeners and required NDP responders on `manual`/`route`.
Real **iptables-nft and iptables-legacy: 59 checks each, 118 PASS total**.
Checks cover off DROP, no manual IPv6 rules, source-preserving route, nat66 MASQUERADE
and off-WAN guard, protective DROP ordering, shared forwarding/RA leases, invalid
SIGHUP refusal and unchanged network generation on valid reload.

Each backend executed **32 DNS queries** across four profiles: IPv4/IPv6 × UDP/TCP ×
A/AAAA. Upstream received only eight queries: cache is shared between frontend
transports within one profile and independent between profiles. Standalone `manual`
returned two additional IPv6 DNS answers with initial `forwarding=0` and unchanged
RA/IPv6 firewall. DNS originated on the server: this tests the real proxy/listeners,
not encrypted VPN traffic or TUN INPUT/port 53 redirection packet paths. Both NDP
responders actually bound; upstream NS/NA replies for active session leases are not
validated by this batch.

With a missing required `ndp_proxy_interface`, the profile admits no clients and
never runs post_up. The worker remains alive and retries the profile: required NDP
does not mean termination of other profiles. After SIGTERM the test compares exact
foreign rules/policies, routes, link flags (including ALLMULTI), sysctl values and
removal of the control socket/sysctl journal. Four-profile stop, manual-only stop
and stop following NDP refusal restore baseline on both backends.

Three intermediate fixture failures are retained and not counted as PASS: the first
two compared a baseline without yet-created empty nat/mangle tables; nft `-S` reads
do not instantiate them. The fixture now creates/removes an empty private chain
before taking baseline. The third incorrectly expected worker termination instead
of supported rejected-profile retry. No production Rust changes were required.
All 288 local/remote source SHA and debug SHA match previous exact build evidence;
no fresh build/Clippy/benchmark was run. External host snapshots match across all
four attempts, working release/listener is preserved, `.10` was untouched.
[Commands, SHA and raw manifest](../../../release/certification/evidence/ipv6-multiprofile-20261002.json).

**D10 stays IN_PROGRESS:** upstream NDP packet tests for active/inactive leases and
remaining mixed firewall/firewalld and lifecycle combinations are still required.
WAN changes/identity stay D06; final native/certificate refresh stays D15.
**Registry: 12/15 DONE (80%), 3 IN_PROGRESS — D06/D10/D15.** This fraction concerns
technical-debt groups, not the entire 37-step audit.

### Q25-F212 — NDP for active sessions and prefixes, 2 October 2026

Closed the D10 packet-level NDP component for `required` in `route` and `manual`:
**8/8 `route/manual × TCP/UDP × nft/legacy` cells, 31 checks each, 248 PASS total**.
The new [scenario](../../../scripts/audit_ndp_session_packet.py) launches a real worker
and authenticated CLI client in separate client/router/server namespaces. Upstream
considers the pool and delegated prefix on-link and sends NS to the server WAN;
no SessionMap injection or simulated firewall response is used.

Executed **128 packet probes, 384 Ethernet NS**. Each cell has a positive control:
kernel NDP on the WAN. Before connection, no NA covers the reserved `/128` or
`client_subnet`; after handshake, both addresses receive correct proxy NAs, while a
free pool address and unowned prefix receive none. Checks validate Ethernet MAC,
IPv6 source/destination, hop limit, ICMPv6 checksum, target/TLLA and Solicited/Override
flags. DAD receives all-nodes NA with both flags clear; wrong hop limit/checksum and
DAD with SLLA are rejected. Hex of every sent NS and received NA is retained.

The external router actually pings the assigned address and a client-side
`client_subnet` address through the encrypted VPN; no NAT66 is present. On normal
client stop the test waits for control registry removal (including UDP idle expiry/
maintenance), then fresh NS receives no NA for either lease or delegated prefix.
The prefix kernel route is retired. A new handshake restores ownership and both
addresses' NAs. Stopping the worker ends replies and restores exact foreign firewall
rules/policies, routes, link flags and IPv6 sysctl; control socket/sysctl journal are
removed. For `manual`, forwarding and permits are administrator-provided beforehand
and preserved; Qeli does not acquire their ownership.

Corrected the [IPv6 guide](../manuals/IPV6.md): stopping a client process does not
always mean immediate server session removal. While a UDP session remains until
idle/liveness timeout/cleanup, or a roaming grace period applies, NDP can still
reply for it. Test reply retirement after session removal/revoke; an old upstream
neighbor cache entry alone does not prove a fresh responder reply.

Two intermediate fixture failures are not counted as PASS: check-config correctly
rejected a 1000ms interval with default 5000ms jitter; the next initial snapshot
preceded WAN link-local DAD completion. Preparation now sets jitter=0 and waits for
the original link-local address; strict restoration comparison remains. Production
Rust is unchanged. All 288 local/remote source SHA and debug SHA match previous exact
build evidence; no fresh build/Clippy/benchmark. External host snapshots match across
all three attempts, working release/listener is preserved, `.10` was untouched.
[Results, commands, SHA and raw manifest](../../../release/certification/evidence/ndp-packets-20261002.json).

This is not a new packet test of `/0`, rate saturation, VLAN, admin revoke/active owner
replacement or SIGKILL NDP. Multiple-profile mixed firewall/firewalld reload/policy
combinations stay D10; WAN identity stays D06, final certification stays D15.
**Registry: 12/15 DONE (80%), D06/D10/D15 IN_PROGRESS.** NDP packet lifecycle is
validated; the entire D10 and full 37-step audit are not closed by this batch.

### Q25-F213 — multiprofile, mixed backends and firewalld policies, 2 October 2026

Closed the remaining D10 integration component: **4/4 IPv4/IPv6 pairs nft/nft,
nft/legacy, legacy/nft, legacy/legacy, 104 checks each — 416 PASS**.
The [four-profile scenario](../../../scripts/audit_worker_ipv6_multiprofile.py) now
uses an [isolated firewalld fixture](../../../scripts/audit_firewalld_profiles.py).
Real `off/manual/route/nat66` TCP/UDP profiles, manual/route required NDP and firewalld
2.3.1 public zone with a public → HOST priority -500 policy run together. Real copied
xtables multicall binaries are selected independently for IPv4/IPv6; command output
and rules are not mocked. SHA of all 17 original Debian packages was verified.

An external veth peer tests permitted UDP 49000 and policy-denied 49001: **96 packet
probes, 288 datagrams, 168 validated echo replies**; 120 denied sends receive no reply
within 250ms per packet. Removing the rich DROP actually opens 49001, restoring it
blocks IPv4 and IPv6 again. Firewalld reload with active profiles, after stop and after
restart preserves exact Qeli/foreign rules. A new generation may reorder independent
profiles while preserving each profile/table/chain order and mandatory DROP before
ACCEPT. Reload within one generation compares the full snapshot.

Each cell validates 42 DNS answers: initial 32 IPv4/IPv6 × UDP/TCP × A/AAAA, four after
policy changes, four after restart and two manual-only; **168 total**. Profile caches
are independent and policy changes retain cache. Invalid SIGHUP preserves active
state; valid SIGHUP retains the network generation. Manual-only preserves original
administrator forwarding/RA and IPv6 firewall; a missing required NDP interface
refuses admission/post_up while supported worker retry continues. All four stop
phases restore both backends, native nft, routes, sysctl/link flags, control socket
and journal to baseline.

Targeted suite: **18 portable PASS and one separately executed privileged PASS** on
the exact test-binary SHA. Coverage includes IPv6/NDP combinations, INI round-trip,
interface selection, lease/prefix/session ownership, malformed NS/DAD/NA, rate bound
and namespace bind; the `ndp` substring filter also selects several endpoint tests.
The initial wrong native module path was caught at listing before execution and is
not counted as PASS. Two early runtime failures were fixture defects: INPUT DROP
blocked IPv6 ND, then baseline contained synthetic iptables-save headers without six
empty native nft hooks. Preparation now permits ICMPv6 only on the control veth and
adds/deletes a temporary rule before baseline. Strict comparison remains; production
Rust is unchanged. All 288 local/remote source SHA and debug/test artifacts were
verified, so prior exact build evidence applies. No new build/Clippy/benchmark.
External host snapshots match for final and earlier attempts; working release/service
is preserved and `.10` was untouched.
[Commands, SHA, results, initial failures and raw manifest](../../../release/certification/evidence/firewalld-profiles-20261002.json).

D10 closure uses the following independent evidence:

| Criterion | Confirmation |
|---|---|
| off/manual/route/nat66, DNS/NDP, rollback/stop | Q25-F211: 118 checks; this batch repeats composition on four mixed backend pairs |
| Active/inactive NDP leases and delegated prefix, real VPN | Q25-F212: 8 packet cells/248 checks; this batch's targeted NDP tests |
| Foreign resources and mixed crash/recovery | D04: server 16-cell/476-check and client 152-cell matrices |
| Concurrent TCP/UDP, reload/stop/SIGKILL/recovery, churn | D13: 14 multiprofile lifecycle checks and prior same-SHA churn |
| Multiple IPv6 profiles with firewalld reload/policy | This batch: 4 mixed cells/416 checks, real positive and negative policy probes |

Validation boundaries remain: DNS originates on the server toward a real proxy port,
and control firewall traffic targets an independent echo listener. This is not a new
VPN forwarding packet test through every public zone/policy or TUN INPUT/port-53.
Arbitrary root rewrites, automatic backend migration and every possible firewall
policy are not certified; Qeli preserves foreign restrictions and the administrator
provides topology permissions. `/0` and rate bounds have unit coverage, but no new
packet saturation/VLAN/admin-revoke/SIGKILL NDP tests were run. Physical provider
networks and user-excluded platforms are not reported as PASS.

**D10 DONE within this Linux scope. Registry: 13/15 DONE (86.7%), 2 IN_PROGRESS —
D06 and D15.** WAN identity/runtime route changes and final native/certificate refresh
remain open. This fraction covers technical-debt groups, not the entire 37-step audit.
The next batch addresses D06's remaining external network context table.

### Q25-F214 — external network context and late addresses, 2 October 2026

Executed one targeted D06 batch on the exact current test binary:
**73 portable + 23 privileged executions PASS**. The new
[runner](../../../scripts/audit_external_context.py) uses existing Rust regressions
and real independently selected xtables backends for IPv4/IPv6. Production Rust is
unchanged; no new build, Clippy, full benchmark or native refresh. All 288 local/remote
source SHA and test/release SHA match the
[exact build evidence](../../../release/certification/evidence/config-mixed-20261002.json).

On **4/4 nft/nft, nft/legacy, legacy/nft, legacy/legacy pairs**, three native scenarios
run: late IPv4 default route, late global IPv6 plus default route, and refresh/cleanup/
restart after moving to a foreign network namespace. Total **12 native executions**,
eight covering dynamic addresses/routes. Protection is installed before the route/
address appears; real ICMP then increases the existing kill-switch DROP counter.
The namespace scenario preserves a foreign sentinel and refuses mutations in the
wrong context. This is packet counter proof, not an external receiver response test:
there is no external receiver on the dummy WAN.

The remaining suite runs once: 11 WAN-discovery, 23 exit-policy, 11 resolver-context,
18 attach-policy, 3 terminal-writer, 5 process-admission and 2 interface portable
tests; eight real TUN ioctl and three native context tests. Coverage includes missing/
borrowed/multiqueue TUN, fd cleanup after rename/replacement, foreign namespaces and
same-name/different-index sysfs rejection; interface MAC/index and TAP/hooks use the
calling namespace. Resolver refuses a foreign network before mutation. Admission
lasts through terminal completion, refuses overlap before reading configuration and
remains closed after forced Drop. Portable filters temporarily ignore three native
fixtures: two execute separately; the real-resolved child was not run or counted as
PASS here. Its previous packet/PID/bus checks retain separate evidence.

| D06 boundary | Reconciliation and current contract |
|---|---|
| DNS / D-Bus / procfs | Context guards rerun PASS; real resolved, AUTH GUID/unique owner, PID/network and marker recovery — prior Q25-F094/F095/F096/F097. Supported shared network/PID context and trusted resolver are required; no service fixture rerun here. |
| sysfs / link observation | Native interface/TAP/hooks PASS without sysfs remount; sysctl namespace pins/cookie/witness are closed by D02. Observation is not atomic protection against another root. |
| TUN attach / name / features | 18 policy + 8 native PASS. External manager holds device/format stable. `dev_attach` requires matching namespace sysfs; equal numeric ifindex in separate namespaces does not prove identity. This unsupported combination is not reported fixed. |
| DNS/carrier globals | 3 writer + 5 admission PASS; one Linux run_client per process through cleanup, forced Drop requires process restart. Independent clients use separate processes. |
| Late IPv4/IPv6 | 8/8 native executions on four mixed backend pairs PASS; prior missing-firewall refusals Q25-F121/F122 still apply. DHCP/RA daemon rollout and every dynamic route are not certified. |
| Client default WAN | 11 discovery + 23 exit-policy models PASS; real TCP/UDP monitor previously checked in Q25-F127. No new mixed monitor packet test here. |
| Server WAN / identity / policy routes | Q25-F131–F136 retain presence, ECMP/auto-failure and NAT44/NAT66 off-WAN guards. Same-name replacement lacks continuous identity protection; server runtime route/policy composition remains D06 work. |

All fixture changes occur in private NET/mount/PID namespaces; native Rust tests
also create disposable thread namespaces. Full outer snapshot of both backends/nft,
routes, addresses, listener, resolver and named namespaces matches before/after.
Working release/service is preserved; `.10` was untouched.
[Commands, exact selectors/counts, SHA and raw manifest](../../../release/certification/evidence/external-context-20261002.json).

**D06 stays IN_PROGRESS**, but the mixed-backend late-address/route coverage gap is
closed and DNS/sysfs/attach/process-global components need no repeated broad sweep.
Next: WAN identity, server runtime route changes and policy/RFC1918 contract with
packet checks. Unsupported privileged replacements are not relabelled as fixes.
**Registry: 13/15 DONE (86.7%), D06/D15 IN_PROGRESS**.

### Q25-F215 — server default/policy routes and LAN, 2 October 2026

Closed D06's documented server runtime-route/address-plan component: **4/4 pairs
nft/nft, nft/legacy, legacy/nft, legacy/legacy, 51 checks each, 204 PASS total**.
The new [packet runner](../../../scripts/audit_server_route_policy.py) launches a real
worker with concurrent dual-stack TCP NAT44/NAT66 and IPv6-only UDP route profiles,
two real authenticated clients, two WANs and a separate LAN. Qeli installs its rules;
no SessionMap injection or simulated network responses.

Receivers observe IPv4/IPv6 source after decryption, forwarding and NAT in each cell.
Executed **116 packet probes, 348 UDP datagrams, 252 validated echo replies**.
276 sends traverse real VPN; 72 are direct receiver positive controls. 96 sends
correctly receive no reply within 350ms each. For 84, the exact Qeli off-WAN DROP
counter increases (28 checks, delta=3 each); administrator `FORWARD DROP` blocks
the remaining 12.

| State | Observed behavior |
|---|---|
| Selected WAN A | NAT44/NAT66 use WAN A source; route preserves client IPv6 source |
| RFC1918 LAN off-WAN | 10/8, 172.16/12, 192.168/16 reached without NAT under administrator ACCEPT |
| CGNAT/public LAN off-WAN | NAT44 guard blocks 100.64.0.1 and 192.0.2.1; direct controls prove receivers healthy |
| IPv6 LAN off-WAN | NAT66 blocks; route reaches it with original source |
| Administrator FORWARD DROP | RFC1918 LAN closes; selected WAN remains reachable through Qeli's own permit |
| Default A → B | NAT44/NAT66 retain their rule generation and block off-WAN; route follows B without NAT |
| Source policy table100 → A with default B | NAT resumes through A; independent route client continues through B |
| Default restored A | NAT and route work through A without reconnect |
| Source policy → B with default A | NAT44/NAT66 guards block; peer B has positive controls |

After removing policy rules and restoring routes, the exact live snapshot matches:
both family/backend firewall saves/native nft, IPv4/IPv6 route tables and RPDB, link
flags and sysctl. Each of eight client-process logs has exactly one connection
attempt and one successful AUTH throughout the final scenario. Normal client/worker
stop restores initial state and removes the control socket/sysctl journal. Full
outer lab host snapshot matches before/after; working release/service is preserved,
`.10` was untouched.

The guide now explains that server auto-WAN selection occurs at profile installation
and does not automatically move NAT to a new default route. Select a new WAN by
restarting the profile, or provide administrator routing toward its original WAN.
The client exit-node monitor is separate. RFC1918 NAT44 exceptions exclude CGNAT/
public LAN. The initial fixture failure is retained: IPv6-only client mistakenly
received IPv4 includes and correctly refused them after AUTH; its route list was
corrected. Intermediate r2's 160 PASS remain separate: final r3 adds positive
controls, DROP counters and exact RPDB comparison; these are not added to the 204.
Production Rust is unchanged; 288 local/remote source SHA and debug/release SHA match
exact build evidence. No new build/Clippy/benchmark.
[Commands, results, SHA, initial failure and raw manifest](../../../release/certification/evidence/server-route-policy-20261002.json).

These are four selected topology/backend cells retaining devices, not every possible
policy table, obfuscation or physical network. Delegated client_subnet has separate
route/NDP evidence and does not traverse this NAT packet scenario. No new firewalld
daemon run: public-policy/multiprofile proof remains Q25-F213. IPv4 forward_private/
manual runtime paths were not rerun here.

**D06 IN_PROGRESS:** continuous selected-WAN identity across rename/delete/recreate
[Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) is not fixed; the client WAN monitor
requires separate reconciliation of that remaining issue. This batch does not turn
name-based limitations into identity protection.
**Registry: 13/15 DONE (86.7%), D06/D15 IN_PROGRESS**.

### Q25-A125 continuation — WAN identity guard selection, 2 October 2026

Kernel candidates were qualified on four mixed backends: **168 expected-outcome
checks**, 88 probes / 264 datagrams / 168 echo replies / 96 blocked sends. These
are synthetic exit-shaped rules, with no worker/VPN or production fix. A native
ifindex selector admits a replacement with the former index/name/MAC. A per-device
devgroup token blocks it, but assigning it disables a foreign group0 DROP; root can
copy the token onto a new device. A simple switch to ifindex or silent device-group
mutation is therefore rejected as a complete fix.

[Report and concrete implementation requirements](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md)
and [full evidence](../../../release/certification/evidence/wan-identity-candidates-20261002.json).
The client monitor is reconciled against current source: ExitWanSnapshot stores
names only, compared every five seconds; existing Q25-F127 evidence covers name
changes, not identity. No new monitor E2E, real firewalld or crash/group recovery is
claimed. Outer firewall/routes/link groups/RPDB and kernel module sets are preserved.

**D06 IN_PROGRESS:** a kernel guard with an explicit ownership contract, shared lease,
journal and packet/recovery checks remains. Other D06 components have evidence;
general suites need not be repeated before code changes. **13/15 DONE (86.7%)**;
D15 is final build/certification after the production fix.

### Q25-A125 continuation — DEVMAP guard selected, 3 October 2026

A working prototype preserves routing/NAT while blocking WAN replacement: frozen
DEVMAP removes its entry on unregister; a mangle/POSTROUTING socket-filter compares
actual out index. Both a different index with the renamed original still alive and
name/index/MAC reuse after deletion are checked, alongside pin/reopen and no refill.
**4/4 mixed cells, 156 checks, 72 probes / 216 sends / 168 replies / 48 DROP**.
Two separate setpriv checks show refusal under stock unit capabilities and success
with CAP_BPF when bpffs is prepared beforehand.

[Exact mechanism, limits and integration](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) ·
[evidence](../../../release/certification/evidence/wan-devmap-20261003.json).
This is synthetic veth proof, not Qeli worker/TUN, SIGKILL or systemd startup. Outer
network snapshots match; xt_bpf was autoloaded once and left loaded. Rust, working
unit/service and `.10` are unchanged.

**D06 IN_PROGRESS:** implement the selected guard in a shared Rust helper, trusted
pins / persistent journal / bootstrap / service capabilities / client monitor, then
target real VPN/multiprofile/conntrack/policy/recovery checks. General identity
candidate search need not continue. **13/15 DONE (86.7%)**, D15 follows the final
production candidate.

### Q25-A125 disposition — 3 October 2026

The user declined BPF integration as unnecessary complexity. The prototype worked;
production integration was still incomplete. This decision concerns the production
change, not the reproduced finding. Q25-A125 remains a known P2: WAN rules select
by name, and another device reusing that name may inherit NAT admission.

**D06 ACCEPTED_LIMITATION:** other components have the evidence listed above;
continuous device identity and the corresponding client-monitor changes are
excluded from mandatory implementation by user decision. [Operations contract](../manuals/OPERATIONS.md):
stop the profile and confirm cleanup before selected-WAN rename/delete/recreate,
then change the device and restart the profile. Default-route changes with devices
retained have separate successful checks.

The unfinished Rust helper/server-journal draft was archived outside the repository
and removed from both working and lab source trees. CAP_BPF, bpffs bootstrap and
service-unit changes were not applied: automatic approval review rejected the
privilege change before execution, then the user cancelled the implementation.
Working release SHA `a526c03b` and .11 service (MainPID 777) are retained. `.10` was
untouched. The draft build is not PASS and its test artifacts are not certified.
[Machine-readable decision and rollback](../../../release/certification/evidence/wan-identity-disposition-20261003.json).

**D15 remains:** reconcile one final candidate, native/provenance/build/benchmark
evidence against exact source/artifact SHA and reuse applicable previous results.
BPF integration and further WAN-identity candidate searches are not required.

### Final native D15 checkpoint — 3 October

Fresh A/B and ABI checks pass for all four native libraries; bytes match the
previous artifacts and provenance now binds digest `1bcee8e9…`. Windows
read-only selftest passes 143/143. Unchanged 164 adapter + 288 Rust input hashes
preserve D08 applicability; seven Linux reports match all 288 Rust files.
The unrelated vpn-nat service on .10 changes three legacy rules: the FAILED
host wrapper is retained and journal-qualified; byte reproducibility is
independent of that drift. [Details](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md).
D15 remains IN_PROGRESS for fresh Linux release/runtime/soak/benchmark and
certification; 13/15 DONE + D06 ACCEPTED_LIMITATION remain unchanged.

### Final D15 closure — 3 October

Candidate validated; benchmark and automated certification refreshed. Initial
harness failures retained: missing compile-time conformance fixtures and SSH
NOFILE 1024 for 512 TCP pairs. Complete inputs plus process-local 4096 yield
2257 PASS, zero failed, 60 normally ignored. Working service limit 65536 and
PID unchanged. Soak bounds fd/socket counts and sampled RSS within 32 MiB over
100 cycles; no indefinite soak claimed. Old reports stay historical; unchanged
module evidence is reused by SHA within original limits. No repeated common
campaign without relevant changes. Full release preflight/publication and
physical exclusions are not PASS.

**8 October, F384:** [Q32 usage](../reports/audit-0.8.2/AUDIT-Q32-USAGE.md) distinguishes pre-publication failure from uncertain durability after rename. Baseline memory700/file0 reproduced; patched harness16/uid65534,2426library (60ignored),strictClippy/daemon,A-B four cores,WindowsABI22/AndroidJNI23 PASS; details in evidence. Initial host firewall drift and failed preparations retained. Aggregate remains14/15 DONE plusD06 ACCEPTED_LIMITATION.

**8 October, F385–F388:** [Q32 log/trace I/O](../reports/audit-0.8.2/AUDIT-Q32-LOGS-TRACE.md) is qualified: three baseline failures, harness11/UID65534, real signal dumps,2434 library (60ignored), strictClippy/daemon,118 Node VM groups and four native A/B/WindowsABI22/AndroidJNI23 PASS. Failure logs/input corrections and initial legacy firewall drift retained; scoped source/input/host/physical limits in evidence. Aggregate14/15 DONE plusD06 ACCEPTED_LIMITATION; Q32 and other unfinished full-audit sections remain open.

**8 October, F389–F394:** [notification INI and delivery](../reports/audit-0.8.2/AUDIT-Q32-NOTIFICATIONS.md): trust enforced before read/save, complete bounded HTTP status and 2xx-only success, query/fragment parsing, conservative special-address guard, post-save cache invalidation and symlink-entry stamps. Three old helper failures plus two actual-library cache failures reproduced; six helper tests, 12 isolated HTTP checks and cache trust/recovery qualify the corrected source. Final library/native counts and guards are in machine evidence. Q32 and Q29/Q30/Q31 scopes remain open; 28/37 overall, nine remain; old debt14 DONE plus D06 accepted.

**8 October, Q32 complete:** all five criteria reconciled across metrics/usage/logs/trace/notifications and unchanged roaming observations; final2439 library, strictClippy/daemon, actual HTTP12/cache, native A/B/ABI22/JNI23 and docs/provenance PASS. Source16 comparisons preserve prior execution scope; physical/TLS/Telegram/browser limits remain documented. Full plan29/37(78.4%),eight remain;Q29/Q30/Q31 and D06 retained.

**October8,F395:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): separate core/hook publication lock eliminates cooperative check-to-command race without lifecycle/startup deadlock. Three expected old-hook failures; four Rust/shell cases per dash/ash,196 existing methods per shell without skips,2444 Linux(60preexisting ignored),strictClippy/client PASS. Native refresh/ABI and raw guards are in scoped packet evidence. Mixed bundles/admin writes, sequential NDM/power loss, firmware exclusions and full SDK/release pipeline remain outside closure; Q31 remains3/5IN_PROGRESS. Full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED;Q29/Q30 unchanged.

**8 October,F396:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): whole preflight requires one clean commit between gates; three old mixed-commit false-PASS cases reproduced.12 whole-program methods,56 Linux related methods uid65534 without skips PASS; Windows78PASS/3pre-existing skips. Snapshot/report identity and120-second certification timeout qualified; optional lab build and production pin/hash unchanged. Current native inputs/artifacts unchanged, SHA/provenance retained; owned Python fixture removed after verified backup. Full SDK/bootstrap/release-cut/successful Actions/preflight remain OPEN; Q31 remains3/5,full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED,Q29/Q30/exclusions retained.

**8 October,F397–F398:** [Q31 CI diagnostics](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): macOS CI output matches guarded per-app-arm64 leaf; old command fails,11 Windows/12 Linux path cases PASS (Windows symlink unavailable). iOS exit-node known-key fixture now uses valid gateway=false shared split mode; seven actual configuration-ABI checks PASS. Swift XCTest/Keychain status(-34018) runtime remains OPEN; old native CI failure reconciled to current PASS provenance, not new Actions success. Source/runtime exclusions and all plan/debt counts retained.

**8 October,F399/Q31-V010:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK nested make broke sed before Cargo; exact admission plus dollar-free substitution fixes it. Official24.10.4 x86/64 Git download/hash/prepare, Rust1.89 prebuilt client compile/link, SDK install/dependency/strip/IPK PASS.6 real-Cargo,7 offline opkg and9 fresh SDK-client OpenWrt userspace cases PASS without skips. Stock toolchain tables repaired a fixture packaging prerequisite; no dependency bypass. Initial rootfs prep/autoremove backup-selection failures retained. SHA-verified backup and guarded own-root cleanup; service unchanged, native14SHA/provenance PASS. Upstream Rust bootstrap/cold-hermetic build, production source-cut and successful current Actions/preflight remain OPEN; firmware USER_EXCLUDED. Q31 remains3/5, full29/37(78.4%),8remain; old debt14DONE+D06accepted,Q29/Q30 retained. No push/deploy/release.

**8 October,Q31-V011:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): previous32-bit builds predated F395; current6c2225cd ARMv7/MIPS full client builds/SHA/static ELF PASS,318exact transferred inputs.32QEMU CLI/INI and14exact production PublicationLock/budget release behavior checks PASS on cortex-a7/24Kc uid65534. No new product regression/ABI/source change;14nativeSHA/provenance PASS. .11 rustup inventory auto-installed a missing named nightly; only that own addition removed with guards/default preserved,probe compiled sequentially on .10. Verified backups,three own roots cleaned,unrelated old root/services retained. Old four-target A/B keeps original source/date;no cfg(test)/firmware/fullVPN/SDK bootstrap/source-cut/current CI success claim. Q31 remains3/5;29/37(78.4%),8remain;Q29/Q30/D06/exclusions retained. No push/deploy/release.

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

**8 October,F446–F448:** [Docker runtime](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): fixed branch latest publication, Cargo --locked, removed four destructive/status-ignoring legacy harnesses. Real Docker image/runtime26PASS: pinned H1 VPN fresh/recreation/known-image rollback, root0600/readonly volumes, protected-login readiness, bytes/UID/mode preservation, six exit0 without OOM/SIGKILL. Harness FAIL retained; host snapshots/AppArmor/PID777-845 restored, owned root SHA-backed-up/guard-cleaned. Runtime gate closed; compiler multiarch/registry/currentActions and final Q33 command/hook reconciliation OPEN.29/37DONE78.4%,8remain; historical debt14DONE+D06accepted/exclusions preserved; local dev without push/deploy/release.

**8 October,F449/Q33-F052:** [Q33 final reconciliation](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): fixed restore hook-file protection bypass through `..`, quotes and symlink aliases; unknown top-level managed literal variables/globs refuse publication. Exact original Linux collector expected FAIL;14 targeted production helper/gate checks PASS. Full server/native qualification PASS:CLI5/backup49/IO2/Clippy,freshA-B/14SHA/provenance/WindowsABI22. Retained hook snapshot SOURCE REVIEW OPEN;Q33IN_PROGRESS;overall29/37DONE78.4%,8remain. Previous runtime gates reused only for unchanged paths;Q29/Q30/Q31/USER_EXCLUDED/D06ACCEPTED retained. No push/deploy/release.

**8 October,F450/Q33-F053:** [Q33 complete](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): actual two-HTTP-restore baseline executes a replaced harmless marker; fix retains startup/later worker hooks until supervisor exit and refuses exact deletion. Fixed8+later10 runtime, CLI5/backup50/lifecycle1/post_down3/privateIO2/Clippy PASS; fresh native/ABI qualification and raw seal are in the report. Q33 5/5 DONE;30/37(81.1%),7remain. Q29/Q30/Q31/Q34/D06 historical limits preserved; no push/deploy/release.

**Q34 dependency packet,8 October:** [F451–F454](../reports/audit-0.8.2/AUDIT-Q34-DEPENDENCY-POLICY.md) closed within Rust dependency policy/PEM migration/formatter gate with actual negative/positive checks. Old14DONE and D06accepted preserved;full Q34/current Actions and established Q29/Q30/Q31/platform limits remain separate criteria. No new D-item list or qualification of untested release payloads.

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
**10 October,F504–F505:** [Stability gate](../reports/BENCHMARK.md): fixed false admission from incomplete/rounded/invalid measurements and removed host-wide cleanup.89Windows/19Linux methods,4workflow lint and actual read-only .11 refusal PASS;service777/845/CLI75bc preserved. No new throughput/soak or wholeQ34/Q35/Q36 completion.30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10October,F506–F507:** [Soak admission](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): reproduced zero-loop TCP and downgraded endurance labels; common decimal validation before network actions, smoke/full markers and10k/1k minimum only for full endurance wrapper. Mandatory bounded100 unchanged.28Linux/57Windows methods,4workflow lint PASS;no newVPNsoak/native rebuild.Q34/Q35IN_PROGRESS,30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10October,F508/Q35-F005:** [Runner isolation](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
closed competing TCP/UDP namespace cleanup and shared family-switch hosts.
7 real kernel +35 Linux script methods PASS; SIGINT/TERM/KILL remove descendants,
neighboring processes/config preserved. Only live NAT counters normalized for
structural comparison, raw retained. No new VPN soak claim;
Q34/Q35IN_PROGRESS,30/37DONE81.1percent,7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F509/Q35-F006:** [Short control sockets and fault matrix](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
actual deep-TMPDIR SUN_LEN fixed with private /run paths;TCP/UDP/bonding/secondary
consumers migrated.14case executions/320assertions,7liveconcurrent snapshots,
35Linuxscript+7kernelmethods PASS;initial familyFAIL and TCP-only observer
failure retained. Whole Q35 IN_PROGRESS,30/37DONE81.1%,7remain.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, Q35 fragment fuzz:** [report](../reports/audit-0.8.2/AUDIT-Q35-FRAGMENT-FUZZ.md): two targets strengthened, 246,813 actual ASan runs PASS; original harness failures retained. Q35 IN_PROGRESS, 30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October, Q35 extended roaming:** [report](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): concurrent real TCP/UDP VPN runs of 900 cycles each; 1835.9 seconds of verified simultaneous activity, 368 full process samples, all resource budgets PASS. Complete host snapshots retained and owned root removed after SHA backup. This is local qualification; full release endurance/eight hours remain open. Q35 IN_PROGRESS;30/37 DONE,7 remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F511/Q35-F009:** [Client INI/qeli:// fuzz](../reports/audit-0.8.2/AUDIT-Q35-CLIENT-CONFIG-FUZZ.md): stable serialization invariants;18,494 ASan runs PASS,701 final corpus files,723 SHA-verified evidence files; first local collector refusal retained. Owned root removed,service/host preserved. Whole Q35 remains open,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 October,F512/Q35-F010:** [Release-soak false PASS](../reports/audit-0.8.2/AUDIT-Q35-RELEASE-ADMISSION.md): silent children previously produced PASS in0.064s; eight verified results, final10k/10k+3×1k checkpoints and28800s now required. Seven Linux/Bash checks PASS; owned root removed,service preserved. Actual eight-hour run remains open,Q35IN_PROGRESS30/37DONE.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

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

<!-- q29-publication-contract-20261012 -->

APPLIED/CONNECTED boundary reviewed: first sampled sockets after APPLIED started before CONNECTED;8 interval refusals and80/80 post-CONNECTED PASS in each retained run. Interpretation question closed, original FAIL_POST_PLAN_BLOCKING retained. The helper already gates post-CONNECTED;6 methods PASS. No new runtime/builds. SIGKILL/DNS compatibility FAIL and Q29 IN_PROGRESS remain. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.
