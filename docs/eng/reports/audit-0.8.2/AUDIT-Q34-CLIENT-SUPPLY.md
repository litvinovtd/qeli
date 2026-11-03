# Q34: client build dependencies and Windows signatures

<!-- normative-sync: q34-client-supply-v9 -->

**Current October 15 result: DONE within agreed scope; criteria and limits are in the final section below.**

**Current status, 14 October:** F459 / Q34-F013 is closed for the current source tree: the adopted Tailwind 4 graph contains no braces and fresh npm audit returns 0. Dated results below retain their original failures; final qualification is recorded at the end. Q34 remains IN_PROGRESS; full plan 34/37 (91.9%).

8 October 2026. F455–F458 / Q34-F009–F012 are closed in the scope below. F459 / Q34-F013 remains OPEN. Full Q34 remains IN_PROGRESS; full audit 30/37 DONE (81.1%), 7 remain. Local changes only; no push, deployment or release.

## Findings and fixes

| Finding | Result |
|---|---|
| F455 / Q34-F009 | Actual npm audit found selector-parser GHSA-rj75-hqrm-r3gf and source-map-js GHSA-68fv-2mgg-jv7q. Exact overrides 7.1.6 and 1.2.2 replace only those two lock records. Clean npm ci --ignore-scripts and CSS build PASS; embedded CSS byte-identical. |
| F456 / Q34-F010 | Gradle wrapper version was pinned, but its downloaded archive lacked a checksum. Added official Gradle9.7.1 SHA256 acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a. Real wrapper accepts the verified official ZIP and refuses a byte-modified ZIP before running Gradle. Existing wrapper-JAR CI validation retained. |
| F457 / Q34-F011 | NuGet audit warnings did not stop normal restore/build. Repository Directory.Build.props audits all direct/transitive packages from low severity; NU1900–NU1905 are errors. NuGet.Config fixes an explicit official advisory source without overriding package sources. Three actual Release restores/builds PASS; known vulnerable fixture and unavailable advisory source both refuse restore. |
| F458 / Q34-F012 | Windows signature gate covered only Wintun. Extended existing gate to both official WinDivert2.2.2-A copies: pinned DLL/driver/license/per-path notices, driver file version2.2, Valid Authenticode and signer thumbprint043589F75FCE2795E7F2CC3E526D46784D5DDAB3. Positive and four real corrupt/missing-file refusals PASS. |
| F459 / Q34-F013 OPEN | braces GHSA-vfj7-8cjw-p6xm has no published patched version as of this check; npm latest3.0.3 and Tailwind v3-lts3.4.19 still depend on it. Current npm audit returns1: five affected graph entries from this one advisory. No suppression or claim of zero vulnerabilities; npm hard gate remains pending. |

These npm packages build trusted repository CSS/templates; they do not ship as the VPN/panel runtime parser. No client INI format changes. A Tailwind4 migration would change the build/configuration contract and requires separate CSS compatibility qualification. A speculative braces3.0.4 trial was refused by npm and never entered the repository. Open finding must be revisited when an upstream fix or qualified replacement is available.

## Actual checks and boundaries

NuGet fresh package/audit cache, SDK10.0.300: Release Windows, managed macOS cross-build and QeliConformance build/restore PASS. The three Release graphs have no reported known vulnerabilities, including transitive packages. This does not qualify Debug/headless/Linux-specific graphs, SDK freshness, or absence of undisclosed defects. Mandatory shared conformance with the full tracked corpus PASS; Windows adapters selftest PASS. PacketCodec conformance benchmark:1400bytes,20000iterations,260.953ms,102.328MiB/s; this is a local codec gate, not VPN throughput. Initial incomplete scratch copy failed eight required fixture checks; complete corpus rerun retained the required checks.

NuGet real System.Text.Json8.0.0 fixture refuses with NU1903. Deliberately unavailable child-only audit source refuses with NU1900/NU1905. No global NuGet source or OS networking configuration was edited. The initial SDK first-use log reports a development HTTPS certificate setup. Audit settings apply to projects built inside this repository; stripped standalone source copies must retain these root build-policy files. .NET package locks and SDK policy remain separate Q34 work.

Official [WinDivert2.2.2-A release](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) ZIP downloaded independently; both bundled x64 files exactly match upstream SHA256. Official ZIP contains an unsigned user-space DLL and a Valid signed SYS; gate authenticates SYS and pins DLL bytes. Notices intentionally differ by path and are checked individually. No driver installation, WinDivert filter, VPN routing or Windows network VM qualification. Wrapper positive run executes only Gradle --version in private GRADLE_USER_HOME; no APK/runtime claim.

Scratch data/caches and outputs are owned local paths. No SSH/lab changes or secrets used. Rust/native source digest remains e3fb04a80fc8c2e7334fa5187dacb497ca47b2a79954fcddae45b5d5a533052c; committed four-target A/B, copies and 14 SHAs remain valid without rebuilding unchanged Rust inputs. app.css, CHANGELOG and users.html remain byte-identical. Initial fixture/encoding/notice assumptions are recorded as harness failures rather than product regressions.

`q34-client-supply-20261008`: SEALED 88 files / 404870232 bytes; manifest SHA256 `049420ad624cd500958d4b0a9dacefa18e4142f32ece4d814259da8e36e0e66a`.

SDK policy, .NET/Android dependency locking/verification, other dependency graphs and release payload/current exact-SHA Actions admission remain open Q34 coverage. Old14 debtDONE+D06accepted; Q29SIGKILLFAIL/ENONET, Q30Apple/callbackOPEN, Q31capacity/source-cut/currentActions and USER_EXCLUDED Mac/iOS/router/Windows network VM are preserved. No fresh Android runtime/soak or physical Mac claim.

Policy references: [Gradle wrapper checksums](https://docs.gradle.org/current/userguide/gradle_wrapper.html#sec:verification), [NuGet audit](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages), [selector-parser advisory](https://github.com/postcss/postcss-selector-parser/security/advisories/GHSA-rj75-hqrm-r3gf), [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).

## 9 October: F491 / Q34-F045 — APK builder must not kill another Gradle build

`scripts/rebuild_apk.py` ran global `pkill -9 -f GradleDaemon` and removed
`/root/.gradle/caches/journal-1` before building, despite its Gradle invocation
already using `--no-daemon`. A process name does not identify build ownership;
this could terminate another task and damage its cache. Both global operations
are removed. Gradle owns its locks. Rust/Gradle commands, offline mode, one worker,
source mirroring, release-signature verification and SHA-qualified APK download
are preserved.

Execution now lives in `build`/`main`: import does not connect to the lab,
invalid arguments refuse before SSH, and `finally` closes SFTP/SSH after open,
build or close failures. The CLI retains default debug and `--release` modes;
compilation/signature failure still exits unsuccessfully. New tests run in CI.

Inside owned .11 PID/mount namespaces, the exact baseline command killed a
controlled foreign-named `GradleDaemon` and its own shell, both returncode -9.
The shared-cache path was covered by a private bind mount; host processes and
the real cache were inaccessible to the probe. Baseline journal deletion is
not claimed because the shell died first. The actual fixed orchestration
invoked a controlled failing `gradlew`, correctly refused compile failure7,
and preserved the foreign worker and byte-identical cache marker. This is
process/failure qualification, not actual Gradle/compiler/APK execution.

Windows:7 new lifecycle/orchestration methods,38 native recipe methods and11
workflow methods PASS. Linux: the same7 new methods and the separate actual
concurrency probe PASS. Official SHA-verified actionlint1.7.12 accepted four
workflows. Inputs/full Linux output were recovered with SHA, and the owned root
was removed using an exact file list after process/fd/mount guards. The .11
service,PID777/845 and installed CLI75bc were preserved; .10 was unused.
Core/native recipe inputs,14 native SHA,protected files and the existing OpenWrt
source cut are unchanged; no new APK was built.

Scope: this removes global process termination and shared-cache damage.
The builder retains its fixed source directories; concurrent APK builds from
different sources using those same directories are not qualified by this packet.
Release `apksigner` verification proves a valid signature, not the expected
publisher; current signed release payload and publisher qualification remain
open requirements. F459 braces remains OPEN without suppression. Q34 IN_PROGRESS;
30/37 DONE81.1%,seven sections remain;Q29 SIGKILL FAIL/ENONET,Q30/Q31,D06
ACCEPTED_LIMITATION and USER_EXCLUDED are preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F491 evidence: `q34-apk-builder-20261009`; SEALED 36 files / 1205550 bytes; manifest SHA256 `bf6a65063b2ee57f87813097cb2601d15d075dffa25ebf0a9007139abcaa8bf9`.


## 9 October: F492 / Q34-F046 — one complete private snapshot per APK build

Closed shared-source contamination in the APK builder: independent calls wrote
into `/root/android-project` and `/root/qeli-src`, allowing their inputs/outputs to
mix. The old extension filter also omitted11 tracked Android inputs, including
Gradle lockfiles, a Java instrumentation receiver and legal files; conformance was
placed inside the Android project instead of its sibling directory.

Before SSH the builder requires a clean committed Git tree without hidden trust
flags, validates native provenance and snapshots all tracked `qeli`, `qeli-android`,
`conformance`, `LICENSE`, `LICENSING.md` inputs. Exact inventory and Git blobs are
checked; symlinks/unsafe members and Git export transformations are refused.
Each .11 invocation owns `/var/tmp/qeli-apk-build.XXXXXXXX`, its Cargo target and
Gradle project state. Full input SHA checks run after upload and after build.
The JNI input directory is explicit. APK and `BUILD.json` are published into
`qeli-android/dist/<commit>-<run>/` without overwriting another invocation.
Failed remote checkouts remain available for diagnosis; no automatic cleanup.

CLI defaults to debug; `--release` selects release. Gradle defaults to offline;
`--online` explicitly permits missing downloads under unchanged strict locks/checksums.
`--gradle-user-home` and `--android-sdk` require absolute paths on the remote lab.
`--signing-properties` is also a remote path and requires `--release`; the legacy
`/root/android-project/keystore.properties` default is only a signing input source.
Java Properties handles escapes and relative `storeFile`; the private umask077 copy
is removed in finally. `apksigner` comes from the selected SDK. Synthetic fixtures
cover this behavior; production release signing was not performed.

Real snapshot:1046 files,25896960 bytes; artifact source commit
`40c644229eb3f91429d6ead272e2428e2ebd320a`. Qualified builder commit
`82d31cb3bd8567c386236f45668f7f0c6159a890` uses identical selected source files.
Two real independent roots were deployed: a settings mutation in the second was
refused by SHA, while the first built a real debug APK. No second concurrent compiler.
Fresh host Rust JNI took97.89s; final ownership verification reused its cache.
JVM: 201 tests,0 failures/errors,0 skipped. APK SHA256
`1525e14c4098bca83e3f1557f29c5c9a1d1c85878042c1ea90ef97815b4027ee`; both JNI payloads match the snapshot, the existing
full legal packaging gate passes and the debug signature is valid.

71 Windows and22 final Linux regression methods PASS; official actionlint accepts
4workflow; docs724Markdown/9checks PASS. Initial offline missing-AGP, incomplete
harness SDK and local duplicate-cache ENOSPC failures are retained. Strict locks and
verification were never disabled. The final build used explicit online mode and
private cache/wrapper/SDK from verified sources; required Build Tools36.0/licenses
were copied read-only from the existing lab SDK. Gradle additionally downloaded
Platform Tools37.0.1 into the private SDK. Serial host JNI transfer was interrupted
after successful build/publication and resumed with bounded16-request prefetch
and independent SHA checks, without recompilation. Only the incomplete new archive
and owned regenerable publish directories were removed, after2619SHA checks and
confirmation that unique Qeli outputs remain recovered elsewhere.

APK, host JNI, JUnit XML and all retained source/log inputs were SHA-recovered;
both owned remote roots were removed after process/fd/mount guards. Regenerable
compiler/dependency/SDK caches are excluded from the recovery archive; their input
origin and hashes are recorded separately. Original .11 service,PID777/845 and CLI75bc
remain unchanged; .10 unused. Core,14nativeSHA,protected files/OpenWrt cut unchanged.
No APK install, emulator/VPN runtime, release/expected-publisher or hosted Actions
qualification. Expected release publisher and F459 braces remain OPEN.
Q34 IN_PROGRESS;30/37 DONE81.1%,7 remain;Q29 SIGKILL FAIL/ENONET,Q30/Q31,
D06 ACCEPTED_LIMITATION,USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F492 evidence: `q34-apk-snapshot-20261009`; SEALED 127 files / 180541943 bytes; manifest SHA256 `5db226ad94b5c7e764973618383df4955b4b845abd36254b1d9d544907ee3f28`.


## 9 October: F493 / Q34-F047 — explicit verified E2E APK

Four installers e2e_android_faketls.py, e2e_android_udpquic.py,
e2e_android_bonding.py and e2e_final.py selected shared /root/android-project APK.
Read-only .11 inventory found SHA324e19e8…, different from the newly qualified
APK1525e14c…. Three scripts ignored exit status: exact baseline csh/a/install
expressions continued after controlled Failure/rc7. Installation failure in
e2e_final entered finally and restarted the canonical server.

Common android_apk_input.py requires --apk-receipt before SSH and the optional
SSH library import. An explicit BUILD.json selects sibling app-debug.apk.
Debug variant, size/SHA, existing source commit, identical selected Git source
trees at clean HEAD and native provenance are required. Bytes are frozen before
connection; moving the whole publication directory works, stale absolute
local_artifact metadata does not select the input. No automatic shared/latest
APK; release refused because these tests use debug/run-as. Fake-TLS --kill-switch retained.

The installer uploads into a private mktemp root and verifies remote SHA before
ADB. A180s process deadline, rc0, standalone Success and absence of Failure are
required. Finally removes the exact private blob/root via rm/rmdir. Refusal
precedes server/tunnel setup; e2e_final prepares before server restoration and
closes both connections on refusal. Shared source/cache unchanged.

Run scripts/rebuild_apk.py first, then the selected E2E with --apk-receipt
"qeli-android/dist/COMMIT-RUN/BUILD.json", replacing COMMIT-RUN with the printed
build directory. Clean repository and identical selected source/native inputs
are required. Both benchmark manual commands are updated.

89 Windows and18 final Linux methods PASS; new suite in CI, official actionlint
accepts4workflow; docs724Markdown/9checks PASS. The actual common installer on .11
transferred the prior qualified30MB APK in five cases: success, Success/rc7,
Failure/rc0, Success+Failure/rc0 and actual byte mutation before remote SHA.
Private controlled ADB recorded four calls with original SHA and no call on
mutation. Five install roots and two fixture roots removed after SHA recovery
of inputs/events/logs and guards. Original777/845 service and CLI75bc retained;
.10 unused. Generator/cleanup harness errors retained separately: refused before
connection or deletion; final cleanup confirmed.

This qualifies selection/transfer/status/early refusal, without real emulator
installation, VPN transport matrix or production server restart. Two REALITY
scripts and production lifecycle using an already installed client without this
installer path are not claimed newly runtime-qualified. Prior201JVM/debug APK/
legal/signature evidence inherited, no rebuild. Receipt binds selected inputs,
not independent publisher attestation. Native14/source cut/protected files unchanged;
Q34IN_PROGRESS30/37DONE81.1%,7remain;F459/Q29/Q30/Q31/D06accepted/USER_EXCLUDED
and expected release publisher OPEN retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F493 evidence: `q34-apk-consumers-20261009`; SEALED 90 files / 1637228 bytes; manifest SHA256 `c6888dfc8edc8712f6f92d98fa9165c5e93e350830c1a2f8b0d9c994e349ac84`.

## 14 October: F459 closed after adopting the CSS compiler replacement

Current commit `67b418ddd5cc8a00f495eb744e77fd18cc73302c` was checked. Tailwind 3 CLI was replaced by the public Tailwind 4.3.3 compiler API (`@tailwindcss/node` and `@tailwindcss/oxide`) with a local watcher. All 45 lockfile package entries, including optional platform packages, contain no braces, micromatch, chokidar or `@tailwindcss/cli`; dependency and optionalDependency edges were checked too. This replacement was already adopted at `da776fb892bd6c02b34194a8e772770744832a77`; no dependencies were updated in this pass.

Fresh `npm audit --package-lock-only --ignore-scripts --json --audit-level=low` against the official registry ran on two unchanged Git snapshots. The old graph at `3638b43c145ae2dc9ca609c0811d0b56175548b3` returned exit 1 and five high entries from GHSA-vfj7-8cjw-p6xm. The current graph returned exit 0 and zero known vulnerabilities at every severity. Node v24.14.0, npm 11.9.0; no suppression, audit=false or audit fix. This checks known advisories for that lockfile at request time, not undisclosed defects. The [upstream advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) still has no patched version; this finding is closed by removing the vulnerable chain, not by claiming an upstream patch.

Exact CSS/build/watch/template inputs match the previously executed 29 Linux and 29 Windows checks. Embedded CSS matches the Linux build and the final 36 browser variants / 96 paired states by SHA, with zero observed JS/geometry/font/spacing/text/aria differences. Both `qeli/web-assets` and `qeli/src/web` are unchanged since adoption. The previous 131 HTTP asset/auth/CSP/CSRF/INI checks retain their dates and CLI SHA; no new build, browser or HTTP runtime ran here. Historical F459_closed=false fields in candidate packets were not rewritten.

The initial sandbox request hit network restrictions; its error JSON is retained separately. The permitted request to the same official endpoint succeeded. The owned npm cache (5458196 bytes) was removed, no node_modules were created, and global caches and source were unchanged.

F459 / Q34-F013 CLOSED in the current local source. Whole Q34 remains open: hosted exact-source CI, public pin/source publication and full release admission are not certified here. Current SDK/IPK/native/Linux20 have separate evidence; full feed compiler bootstrap belongs to Q31 and remains open. 33/37 (89.2%), NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q34-f459-current-graph-20261014.json`; local raw: `audit-debt-20260924/q34-f459-current-graph-r2-20261014`.

## 14 October: public CI and Keenetic fixture ownership

Read-only GitHub inspection confirmed public dev e7a90130f0bd206e549d0757819c92dbd0e8e135 and its immutable tree. Its qeli/ differs from the local candidate in24 files; public source pin ee2b74aafb2a57a2613541223c5522908cb71f71 returns404. Adjacent successful runs are Dependabot jobs; the [main CI](https://github.com/litvinovtd/qeli/actions/runs/38231547743) contains21 jobs and three failures. This is the existing published-e7 run, not a fresh test of the current local candidate.

Eight native-libs Keenetic fixture failures involve root ownership on an unprivileged runner. The old test was reproduced under UID65534. Only scripts/test_keenetic_templates.py changed: stat models ownership within the fixture prefix, retains real modes/missing-file errors and delegates other paths to actual stat. Production templates and root-owner checks remain intact. New cases reject a foreign config owner before publication and check model mode/missing/outside-path behavior.

Qualified44 root cases and44 UID65534 cases:43 successful unprivileged cases retained from r2 plus the one remaining case in r3; the overall missing-input r2 FAIL remains. Both initial projection missing-file errors are preserved. Installer/rollback/hooks and both new cases pass. Own roots/remote archives removed; host/service/firewall/routes/resolver preserved. No physical router, Qeli/native/APK rebuild or complete Linux20 replay.

Existing CI remainder: macos-build racing key creators disagree; ios-build reports Keychain -34018, accepts -Infinity as numeric managed policy and misses two expected roaming/source-pin rejections. iOS tests ran with CODE_SIGNING_ALLOWED=NO. These need separate diagnosis/fixes and exact-source hosted validation; neither all iOS root causes nor their resolution is established here. User-excluded physical Mac/iOS stands were not used.

The local Linux fixture defect is fixed and checked. Public source pin, current hosted CI and full release admission remain open; no source publication. Additional Q29 supported-network API candidates are recorded separately, with no safe generic/null workaround found. Q34 IN_PROGRESS;33/37(89.2%),NO_PUSH_DEPLOY_RELEASE. Evidence: release/certification/evidence/q34-ci-owner-20261014.json. Raw: q34-public-state-20261014 and q34-keenetic-ci-owner-r2/r3-20261014.

## 14 October: atomic Mac service-key publication

Localized the racing-key-creator failure in the existing macos-build CI. `ServiceKeySelection.PublishExclusiveFile` used File.Move with overwrite:false; the Unix .NET implementation can check destination absence before an ordinary rename, allowing another creator's key to be overwritten. The original implementation actually failed on Linux during32 repeated four-way races. [The .NET10 source](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/IO/FileSystem.Unix.cs) confirms that path; Windows baseline passed.

The real Mac daemon already used renameatx_np(RENAME_EXCL) with validated directory descriptors; the CI failure does not establish a race in that production path. Daemon and helper now share PublishExclusiveMac. Directory descriptors, root/type/mode checks, no-follow, complete private temp files, flush/fsync and cleanup remain. The Linux helper atomically links the completed file; Windows retains its platform File.Move. EEXIST means lost publication, including a dangling symlink; other Unix failures remain observable, with no unsafe copy/rename fallback.

Added32 four-way races checking exactly one publisher and identical observed keys, no leftover temp files,0600 permissions and dangling-symlink refusal. SDK10.0.401 compiled whole ServiceState/ServiceProfileCodec and the real shared model library; eight Windows checks passed on runtime10.0.12. On Linux the old implementation failed, the fix passed10 checks as root and10 as UID65534. Total28 checks using pinned SDK/runtime; separate SDK10.0.300 checks are supplemental, not fresh macOS qualification. Initial incomplete compile fixture missing BoundedStorage and SDK cleanup blocked by its own compiler server remain recorded preparation failures; the actual dependency was added and the owned server stopped.

Own Windows SDK and Linux runtime/root/archive removed with verification; original archives retained, lab services/firewall/routes/resolver preserved. No Apple syscall runtime, complete UI build or current hosted CI execution; physical Mac is user-excluded. iOS Keychain/numeric-policy/roaming failures, public source pin and hosted admission remain separate Q34 obligations.33/37(89.2%),NO_PUSH_DEPLOY_RELEASE. Evidence: release/certification/evidence/q34-key-publication-20261014.json. Raw: q34-key-publication-20261014.

## 14 October: three iOS failures and corrected CI preparation

Git blob comparison confirmed that ManagedConfiguration, KeychainStore, ConfigCore, VPNConfig/Projection and Rust editor/client in the existing public e7 CI match local baseline212456f7. Historical failures apply to these same components; no new current-candidate CI run occurred.

The MDM reader accepted negative infinity as false in existing Apple CI. It now checks number.doubleValue.isFinite before NSDecimalNumber conversion, rejecting NaN and both infinities while retaining exact integer and legacy boolean0/1 handling. The version test also covers negative infinity. This is a source fix backed by the historical reproducible CI failure: fresh Swift compile/tests were NOT run. Local Swift/Xcode and lab Swift are unavailable; the official1122730813-byte toolchain was not downloaded. Apple runtime is user-excluded; numeric tests cannot be reported as passing.

RoamingPolicyTests incorrectly expected toINI to reject required+local/lport. Shared export intentionally preserves invalid INI drafts for editing; validate/runtime/URI enforce validity. The test now checks IPv4/IPv6 local and lport export/import preservation, ineligible roaming, rejection by validate/runtime/validating init and acceptance of lport0. Actual current Windows native ABI with platform=ios passed32 DTO requests: export preserves pins, required+pins fails validate/runtime/URI, auto+pins retains reconnect fallback. These requests did not execute the Swift bridge or Apple runtime; the Rust parser is unchanged.

Keychain -34018 denotes an unavailable access group; Apple recommends checking [the built application's effective entitlements](https://developer.apple.com/forums/thread/114456). Existing CI disabled test-host signing. The test step now performs an ad-hoc Debug simulator build-for-testing, checks actual codesign signature and effective shared-Keychain group of built Qeli.app, then uses test-without-building in the same derivedDataPath. Device signing/provisioning policy and production KeychainStore are unchanged. Simulator preflight reuses the IPA signed-entitlement reader; codesign dump is bounded to30 seconds and fails observably on timeout/launch failure. Simulator inventory uses RUNNER_TEMP. This is prepared CI correction, not proven real Keychain PASS.

11 new portable signing-admission methods and6 existing IPA methods PASS. Real pinned actionlint accepted all workflows; five exact CI shell fixtures proved success order and refusal on selector/build/entitlement-check/test failures. Apple commands are explicit stand-ins in these fixtures. Initial wrapper quoting and Windows-CRLF projection failures remain recorded; both lab roots were cleaned with host/service/firewall/routes/resolver preserved. No new SDK/native/CLI/VPN build, real Apple signing or hosted dispatch.

Q34 remains IN_PROGRESS: actual signed simulator Keychain, changed Swift tests, current Mac CI and public source pin remain unqualified. Q29/Q31/Q36 obligations are unchanged.33/37(89.2%),NO_PUSH_DEPLOY_RELEASE. Evidence: release/certification/evidence/q34-ios-ci-contracts-20261014.json. Raw: q34-ios-ci-contracts-20261014 and q34-ios-ci-shell-r2-20261014.

## 15 October: qualified native atomic cleanup integrated

Fix 7df0ce1fc6daae6565cc1325d064956c82ef6189 records the temporary path before write/flush/fsync and publishes evidence through the shared atomic helper. Failure preserves the previous destination and removes its own temporary. Fourteen project test methods passed on Windows and fourteen on Linux; successful serialization is unchanged.

The changed build input required fresh libraries: independent A/B builds matched for Android arm64/x86_64, Windows x64 and universal macOS. Qualification includes 22 Windows ABI cases, 23 JNI and 2 packaged INI tests on Android14/API34/x86_64, exact exports and eight canonical/consumer copies. macOS runtime is not claimed. Owned roots/unit and temporary swap were removed. Native digest `f89a6526de575a292d600cd77e4b3dae6ca8cfd6fd5a9d34001a959268edcfa3`. [Evidence](../../../../release/certification/evidence/q31-native-atomic-cleanup-20261015.json).

The existing 20 Linux results remain applicable because the Rust product tree and 50 matrix dependencies are unchanged; no new Linux runtime is claimed. Q29 DNS, the source-built SDK consumer and public/hosted qualification remain open. 34/37 (91.9%); no full release PASS.


## October 15: Q34 completed on dev

**Q34 DONE within agreed scope.** All 19 required CI jobs passed on exact commit
`9fa0903a191aea54019a2ba293c709d740c661de`; two scheduled fuzz jobs did not
run under workflow conditions. This confirmed strict dependency gates,
Windows/macOS/Android builds, actual signed iOS simulator/Keychain tests,
Android API29/API35, four router targets and packages. These results supplement
the previous locking/checksum/license/source-binding and negative fixtures.

Intermediate API29 CI exposed a race in the lifecycle test itself: a live callback
could publish a carrier between the sentinel write and the retired-callback
assertion. The assertion now holds the same lifecycle monitor as the service.
Production callback ownership checks are unchanged and the test was not disabled.
The corrected API29 job passed; the original FAIL and log are retained. Skipped
live-VPN tests in hosted jobs are not counted as executed Q29 scenarios.

After rustls0.23.46, fresh native A/B, ABI/JNI/INI/APK and SDK/IPK checks passed.
A new factory release CLI with jemalloc, `dbf16592…`, passed 20 Linux certification
cases: 19 actual executions, 409 assertions, IPv4/IPv6, DNS, MTU/PTB, TAP/NDP/RA,
a legacy peer and 100 TCP/UDP roaming flips each. Previous binaries, dates and
results were not renamed. This is a bounded functional matrix, not a new
eight-hour soak.

| Criterion | Result |
| --- | --- |
| Review and dead code | Dependency/SDK/locks/notices/source/workflow/native/release reports and targeted fixes completed |
| Normal, boundary and negative cases | All 19 current required CI jobs, feature/package gates and fresh Linux20 PASS |
| Failures and concurrency | Retained baseline/CI FAIL, atomic writer/publication checks and corrected API29 fixture |
| Integration and target platform | Hosted Windows/Mac/iOS/Android/router, current SDK/IPK and native A/B; physical exclusions retained |
| Fixes, rechecks and evidence | Public dev/source history, fresh runtime receipts, provenance and certification binding |

[Criterion mapping](../../../../release/certification/evidence/q31-q34-dev-closure-20261015.json)
and [fresh Linux matrix](../../../../release/certification/evidence/q34-dev-linux-runtime-20261015.json)
retain exact hashes, dates, limits and cleanup. A redundant stop of an already
unloaded systemd unit failed after the successful CLI build and owned root removal;
separate read-only verification confirmed the result without recompiling. Local
matrix preparation failures are retained as well.

Physical Mac/iOS/router/Windows network VM remain USER_EXCLUDED; the 21 physical
certification rows were not turned into PASS. No tags, releases or deployments
were created. The current total is 36/37 (97.3%); Q29 generic/null API34 ENONET
remains open. The cancelled VPN bypass was not restored. Historical OPEN entries
and counts above are not the current remaining work.
