# Q29: minified Release and Android network runtime

<!-- normative-sync: q29-android-release-runtime-v1 -->

**5 October 2026. Release/R8 passed 24/24 post-switch payload checks: TCP/UDP/QUIC × two Wi-Fi/Cellular transitions × IPv4/IPv6 TCP/UDP. Six transitions, three INI imports through the product UI, 30 sink receipts. Q29 remains IN_PROGRESS; overall plan: 28/37 (75.7%).**

## Environment and method

Three sequential Android 14/API 34 x86_64 AVD runs on .11, in private NET/MNT/PID namespaces with readonly userdata. The outer backend is isolated and offline. Server .10 is untouched. The actual file-picker imports INI through Release Activity; Android Always-on + lockdown starts the saved profile. No instrumentation or private-preference injection is used to prepare the profile.

`svc wifi disable/enable` actually switches Current Networks between WIFI (`wlan0`) and CELLULAR (`eth0`); Android netid/handle changes are confirmed. After each transition, independent UID 10148, distinct from Qeli UID 10149, opens ordinary Java sockets to an off-pool sink: IPv4/IPv6 × TCP 16 KiB/UDP 257 bytes. Client sockets use no bind, protect, root or JNI. The standalone receiver runs from the ReleaseAndroidTest APK without AndroidJUnitRunner.

The TCP reply contains the complete reversed payload; UDP returns the `Q29:` prefix and complete payload. The receiver compares every byte and request/reply SHA-256; the harness checks sink receipts and the TUN source address. CONNECTED status alone is not a passing result.

## Results

| Outer transport | Wi-Fi → Cellular | Cellular → Wi-Fi | Payload | Entire run |
| --- | --- | --- | --- | --- |
| tcp | 5.64 s | 10.26 s | 8/8 PASS | 196.03 s |
| udp | 5.19 s | 9.65 s | 8/8 PASS | 183.96 s |
| quic | 5.21 s | 9.24 s | 8/8 PASS | 179.99 s |

Stage time includes ADB and four probes, so it is not pure outage duration. Every run retains PID, `tun0`, ifindex and addresses. TCP performs fresh Auth and NetworkPlan: 1/1 → 2/2 → 3/3, with new outer ports and reuse of Android TUN. No UDP path commits occur for TCP. UDP/QUIC retain Auth/NetworkPlan 1/1; every new commit token matches the confirmed target network, and the server records a new port and epoch.

Pcap confirms eight post-switch requests per transport, with IPv4/IPv6 TUN source addresses, after the corresponding server AUTH/PATH_COMMIT. TCP requests are fully reassembled by sequence; repeated/overlapping bytes and all 16 KiB SHA are verified. Reassembly reuses the prior stage algorithm; the clock anchor is updated for UI startup without an instrumentation bootstrap. Each run has ten receipts: a physical baseline probe, a connected VPN probe and eight target payload probes.

Actual Settings revoke and cleanup pass in all three runs: `desired=false`, consent `ignore`, service and TUN absent. Final preferences are only read through private AVD root; there are no writes. Wi-Fi/mobile-data settings are restored. Host/service and userdata SHA/size/mtime remain unchanged; server exit code is 0 and namespace addresses are restored.

## Builds, changes and retained failures

```sh
./gradlew :app:assembleRelease :app:assembleReleaseAndroidTest \
  -PqeliTestBuildType=release -PqeliLabReleaseSigning=true \
  --offline --no-daemon --max-workers=2
```

Both Release builds pass R8; the test build uses product `-applymapping`. APKs use a debug test certificate for the lab only; the target is not debuggable, checked by package flags and `run-as` denial. Without the new flags, debug test variant and ordinary production signing or unsigned Release remain. R8/shrinking/proguard are not relaxed. Of 296 product input files, 295 are identical; only `app/build.gradle.kts` changes for opt-in test variant/lab signing. Kotlin, receiver, proguard rules, JNI/Linux CLI and seven managed artifacts are unchanged; eleven auxiliary files are pinned by hashes.

The first matching Release instrumentation run fails before the test body: `NoClassDefFoundError: androidx/tracing/Trace`. A shared optimized classpath issue is inferred from stack and mapping; the precise root cause is unproven. Stack, original harness and zero bootstrap/receipts are retained. UI verification does not close this failure. [Official R8 troubleshooting](https://developer.android.com/topic/performance/app-optimization/troubleshoot-the-optimization).

Three other failed harness attempts are retained: System UI ANR; premature selection of a background Downloads label while the picker loads; forbidden Debug `run-as` XML read after revoke on a nondebuggable target. The last attempt already passed eight TCP payload probes, but failed its final gate and is excluded from 24/24. The final harness uses bounded waits for actual Wait/file rows and, when needed, the observed unique storage root. System UI ANR also occurs during each successful run and is dismissed through the actual Wait button; the OS failure is not hidden.

Fresh Release/testRelease and default Debug builds, Python/CLI, nine docs checks, panel and generated bindings pass. Previous JVM/Android/.NET/integration results remain historical scopes, not a fresh full suite.

Raw: `audit-debt-20260924/q29-android-release-runtime-20261005`. Evidence: `release/certification/evidence/q29-android-release-runtime-20261005.json`.

## Limits and remaining scope

The available AVD Release/R8 UI post-switch IPv4/IPv6 TCP/UDP payload matrix is covered for TCP/UDP/QUIC outer transports. Each TCP probe opens a new connection; continuity of an already open long stream is untested. The shared private offline backend does not qualify physical Wi-Fi/LTE/Internet. IPv6 inside the VPN does not imply IPv6-only outer/NAT64.

IPv6-only/NAT64, first packets during transitions and the full leak matrix, long/physical Doze/flapping, the full Release lifecycle fault suite, matching AndroidJUnitRunner FAIL and other API/OEM/arm64 remain. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) stays open. Previous [UDP/QUIC](AUDIT-Q29-ANDROID-HANDOVER.md), [TCP](AUDIT-Q29-ANDROID-TCP-HANDOVER.md) and [payload](AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md) scopes are preserved. USER_SKIPPED and D06 without BPF are unchanged; Q29 IN_PROGRESS.
