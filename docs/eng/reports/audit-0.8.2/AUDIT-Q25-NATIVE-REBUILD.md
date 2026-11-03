# Q25-F202 — reproducible native cores and Android runtime

<!-- normative-sync: audit-q25-native-rebuild-v4 -->

A later [F203 check](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md) explained
the background packets and closed D12 within the agreed available scope.

Date: 1 October 2026. A/B source: `27db1a22`, digest
`dce152196ab7b13ba42f9808a571ba95ac494c7ccbbd1c69578bd0de90c1979c`.
Verified artifacts were brought to `dev` in commit `08a1823d`.

## Resolved blockers

The native recipe put release output in the client VM's `/tmp`, a tmpfs with
less than 1 GiB available. It now uses disk-backed `/var/tmp` and requires
8 GiB free before building. The old space failure was reproduced on .10;
only regenerable Cargo incremental caches on .10 and .11 were removed.
Running services and binaries were not replaced.

Android `libc::in6_pktinfo.ipi6_ifindex` is signed, whereas Linux uses an
unsigned type. Checked conversions on receive and send fixed cross-compilation;
`Control::send` now propagates errors and batch scratch clears pointers on
failure. Six Linux UDP unit tests and one privileged IPv6 wildcard test passed.
The Android JVM recipe now builds host JNI from the same synchronized source
and provides its path to Gradle; the former 88 `UnsatisfiedLinkError` failures
are gone.

## Artifacts and verification

Two independent release builds, A and B, yielded identical SHA-256 for each target:

| Target | SHA-256 |
|---|---|
| Windows x64 DLL | `c601cffa1ab922552276358ed977445fc6bb1258c37b3c925c06eb437cb84d13` |
| macOS universal2 dylib | `1f5037414c5c19e040094bfb7d3bb2f6064a4e0781718f83e4ead267a3c2034d` |
| Android arm64-v8a so | `d3ccc2389600c9559d612c9deea4f03eeda73963dd5af2aea07a835f8a18bbca` |
| Android x86_64 so | `6c4db7c9ac12c482c6d62fe74347e9abec891042acd0daaca44ed3135b53077e` |

Windows/macOS export six REALITY and 22 client symbols; Android also exports
21 TransportCore JNI symbols. The universal2 library contains both Mach-O
architectures. All canonical and consumed copies were refreshed.
`native-libs/verify.sh` (14 entries) and `provenance.py --check` pass after
cherry-picking the artifact commit. The 71 local native-recipe tests pass.

The Windows .NET build passed without errors or warnings; selftest with the
fresh DLL reported 143 PASS, 0 FAIL. Android Gradle built a debug APK and
167 JVM tests passed without errors. The APK is version 0.8.2 (code 722),
SHA-256 `9ec9967bc691bd7b575572a85c7fd28d6478728d6395f89b47e5bbb678eb9968`.
Both embedded `.so` files match the A/B artifacts byte for byte.

On a read-only Android 14/API 34 x86_64 AVD, direct
`adb shell am instrument` yielded **11/11 PASS**: INI/JNI, JSON config and
forged-link rejection, diagnostic journal, encrypted store/version/bounds, and
TUN builder. The temporary emulator was stopped. Gradle
`connectedDebugAndroidTest --offline` could not resolve UTP 32.2.1, absent
from its cache; that was a Gradle launch failure, not a test failure. The
first emulator hung while Gradle ran concurrently; the tests passed separately
on a memory-limited instance.

## Bounded two-VM Android VPN E2E

An existing dedicated `e2e` profile (`tcp://0.0.0.0:8503`, `e2e0`,
REALITY) ran on .10 separately from the normal service under a 240-second
`timeout`; after it expired, it was restarted for 180 seconds solely to
check reverse ICMP. On .11, the same APK was installed on a read-only
Android 14 AVD; a test **INI** was imported through the supported legacy
store migration and Connect was tapped in the UI. The service JSON store
container is not the config format.

Android logcat recorded `Auth OK`, assigned `10.60.0.2`,
`Native NetworkPlan 1 APPLIED`, and `Rust owns the TUN payload`; the UI
showed `Connected`/`Tunnel active`. Server → client over `e2e0`:
**4/4 ICMP, 0% loss**. After the bounded server stopped, the client
automatically reconnected: a second `Auth OK` and
`NetworkPlan 2 APPLIED`. Client → server after reconnect:
**4/4 ICMP** with the default source and **2/2** with explicit
`10.60.0.2`. A 0/3 probe performed after the first server had already
expired is retained as a timing control, not counted as a tunnel failure.

After app `force-stop` and AVD shutdown, the owned test process ended;
`:8503` and `e2e0` were gone. The regular `qeli-server.service` stayed
active and kept listening on `:443`; its files and service were untouched.

The server log also contained rejected inner packets with the emulator's
physical address `10.0.2.16` rather than assigned `10.60.0.2`.
The tested Android shell ICMP used the correct source and passed. The
source of the background packets is unknown; server anti-spoofing
correctly rejected them. Targeted checks of another Android UID,
background traffic, and VPN lifecycle across network changes remain
under D12. This is not proof of a main-tunnel defect.

## Scope

D11 is complete for current native cores, A/B, ABI, copies, provenance, and
available packages. D12 remains open for the background inner-packet anomaly and untested
lifecycle scenarios; basic Android VPN handshake and bidirectional ICMP pass. Windows VM, Mac/Xcode/iOS, and router runtime were
excluded by user decision; the macOS dylib was structurally checked but the
Mac app and its behavior were not validated. This APK is a debug build, not a
published release.

## Refresh after Q25-F204: 1 October 2026

The Linux-only candidate `rp_filter` fix changed the shared source digest,
so the native cores were rebuilt instead of leaving stale provenance.
Two independent A/B passes from clean commit `f638d957` (source digest
`d39a334335d8a0110a59683bbdf354dfbfb4bd8e5919bdc5981a4b08278f43a5`)
reproduced all four ABI 1.16 libraries:

| Target | New SHA-256, identical in A/B |
|---|---|
| Windows x64 DLL | `653522e6bade8fce705a12ec1566c4c119d49b27d55cb7ba088c018b2bd1dd92` |
| macOS universal2 dylib | `61292c140318590e7441ba891d1ca39266a22f3ee72c6f31fb2d6b39ed474e6a` |
| Android arm64-v8a so | `0255a5d8f60114301761031331c7fdf3ce7a6d6895790f93ad9b760a445c1522` |
| Android x86_64 so | `4ae6eb05b0a498e6fb9aab6014fbc1f0d50552dd48c6f49541c94b90f561ba30` |

Six Reality and 22 client exports, `qeli_config_request`, 21 Android
JNI exports, and both Mach-O architectures were checked. All four
canonical/consumed pairs, 14 `SHA256SUMS` entries, both JSON A/B evidence
files, and `provenance.py --check` pass. Windows Release build had zero
errors/warnings; selftest **143/143** passed. Android JVM XML reports
**167/167** with zero failures/errors/skips. The new 0.8.2/code 722 debug
APK has SHA-256
`324e19e8460ec4f81956bb7931ff305643e538a6b288873460d0d18e1e55d1ca`;
both embedded `.so` files match their A/B artifacts byte for byte.
The refreshed app and test APKs installed on the read-only Android 14/API 34
x86_64 AVD; direct `am instrument` passed **11/11**. The emulator was stopped.
Full VPN traffic was not rerun with this new APK: the E2E above belongs to
the previous APK, while F204's fix is compiled only on Linux.
The older hashes and runtime results above describe the previous revision.
Windows VM, Mac/Xcode/iOS, and router runtime remain excluded by the
user's decision. D11 remains DONE for the refreshed source.

[Debt register](../../plans/AUDIT-DEBT.md) · [Native recipes](../../../../native-libs/README.md)

## Final native reconciliation for D15: 3 October 2026

Fresh independent A/B builds from clean `93cb845d` cover Windows x64,
macOS universal2 and both Android ABIs. Source/recipe digest:
`1bcee8e99b5a365e28821122b19fe190adce0277a6a6cba5fcb1a14c600f48d9`.
All four libraries are byte-identical to the 1 October results in the table
above: the later changes concern Linux process ownership and shutdown.
ABI/exports, both Mach-O architectures, canonical/consumed pairs, 14
SHA256SUMS entries and refreshed provenance pass. Windows Release has zero
errors/warnings; a fresh read-only selftest passes **143/143**.

D08 applicability compares **164 adapter input and 288 Rust input hashes**,
with no changes; the DLL and both packaged Android libraries are unchanged.
The previous **511 .NET, 167 JVM and 12 instrumentation** results therefore
remain applicable within their original limits; these are not new executions
or a new VPN traffic test. Seven recent Linux reports also match all 288
Rust source hashes.

Android host networking and the working service PID are unchanged. Desktop
A/B and ABI pass, but the host wrapper returned FAILED: three legacy
FORWARD/MASQUERADE rules disappeared on .10. Journal and the exact
`vpn-nat.sh`/`vpn-nat-stop.sh` scripts establish that the unrelated `vpn-nat`
service adds/removes them while its `vpn-obfuscated` dependency repeatedly
fails (missing `/etc/vpn-obfuscated`). The working Qeli PID stayed unchanged;
build commands made no firewall/service mutations. The original FAILED is
retained; whole-host firewall invariance is not claimed. No lab service or
privilege settings were changed. The initial Android disk preflight failure
is retained too; only verified compiler caches were removed and the 8 GiB
floor was not reduced.

[Machine evidence](../../../../release/certification/evidence/final-native-refresh-20261003.json)
and raw `audit-debt-20260924/d15-final-20261003/` record commands, hashes and limits.
D15 remains IN_PROGRESS pending a fresh Linux release, common runtime matrix,
soak, benchmark and current certification reconciliation. User platform
exclusions remain; BPF integration is cancelled and Q25-A125 is not fixed.

## Native and current Linux reconciliation — 7 October 2026

Clean source `2b2c1565`, native source/recipe digest `c2ac10e0f41c826129a7b10918db88e84a77e55109eb4537783b34f99abd2a8b`. Two independent builds reproduce each of the four ABI 1.16 libraries. Complete exports, both Mach-O architectures, UUID/indirect-symbol normalization and two ad-hoc signatures pass; all seven canonical/consumed pairs and 14 SHA entries match. PROVENANCE now passes for the current tree. Builds used pinned installed tools, isolated sources, private offline caches, one Cargo worker and bounded compiler processes. macOS cross-build warnings about the unavailable Xcode SDK are retained; no Apple runtime qualification.

| Target | A/B SHA-256 |
|---|---|
| Windows x64 | `a32aff872e5a57bfb24e1d6eca066f0580e86485bd09910eb95407de9b855ed9` |
| macOS universal2 | `dda6c2b1a1a094af4487133217b74325de30913530deeb3d38d738c7d6097c38` |
| Android arm64-v8a | `b3b195c4ee3d62a441d6d0d1cfe0a73b85f4d276c3d24c0cac22903aaadc58f9` |
| Android x86_64 | `49c9eccc21f822c805364edb10adb45208519957554ba89c21696d1edc2c6a04` |

Fresh Windows C ABI: 22 PASS; Windows platform selftest: 325 PASS; shared .NET conformance: 549 PASS. Both Release builds report zero errors/warnings. Android JVM: 201 PASS, zero failures/errors/skips; actual Android 14/API34/x86_64 JNI: 23 PASS. The debug APK contains exact copies of both rebuilt libraries; app and test APK hashes are retained. JNI runs through private app_process without installing an APK or applying a VPN/TUN.

Current exact Git Linux inputs: 383 files including seven release INI fixtures. Fresh library units: 2417 PASS, 60 normally ignored; standalone CLI units: 12 PASS, zero ignored. Strict Rust 1.97.0 all-target Clippy and current debug client/daemon builds pass. Tests run in private network/mount/PID namespaces; service PID and host snapshots are preserved. This is not a fresh common VPN matrix, release daemon, peak benchmark or soak. Earlier results retain their original artifacts/dates and relevant source limits.

Initial JNI wrapper FAIL (emulator Wi-Fi boot transition and nft stderr placement) and first Clippy preparation FAIL (missing include_str release fixtures) remain in raw evidence. The retry waits for WLAN readiness, retains nft stderr separately and compares full rule stdout; source/fixtures are SHA-verified. Unit2417 was not rerun after a fixture-only repair. Original AVD userdata hashes remain unchanged.

The user's explicit continuation authorized the eight listed old roots after verified recoverable backups, file identity and mount/process checks. Both local archives remain. A new 1.37 GB generated Linux compiler cache was removed only after preserving current debug binaries by SHA; source/logs/native A/B artifacts remain. No working services, network policy, global toolchain configuration or releases were changed.

D11/D15 current-package reconciliation is closed: **14/15 DONE plus D06 ACCEPTED_LIMITATION**. Full audit remains **28/37 (75.7%), nine sections pending**. Q29 SIGKILL/auto-null ENONET observations, Q30 callback drain/Apple exclusions and Q31 SDK/release pipeline are not promoted to PASS. No push/deploy. [Machine evidence](../../../../release/certification/evidence/native-current-20261007.json); raw `audit-debt-20260924/native-refresh-build-20261007/`.
