# Q29: Android Release sleep and transport recovery

<!-- normative-sync: q29-android-release-faults-v1 -->

**5 October 2026. Seven Release/R8 scenarios PASS: screen-off, forced Doze, TCP reset/reconnect, UDP/QUIC × soft/grace-expiry. Three UI starts, twelve initial IPv4/IPv6 TCP/UDP payload probes; 28 sink receipts. Q29 IN_PROGRESS; overall plan 28/37 (75.7%).**

## Method and artifacts

Three sequential readonly Android 14/API 34 x86_64 AVD runs on .11, in private NET/MNT/PID namespaces. The Release/testRelease APK pair is byte-identical to the [prior Release qualification](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md). All 296 product source inputs, JNI/Linux CLI and seven managed artifacts match. No rebuild, product change or production proguard rule change is needed; only the Python harness changes. Server .10 is untouched.

Actual INI file-picker and OS Always-on + lockdown start the profile. The target is not debuggable; `run-as` is denied. A debug test certificate is used only for the lab. No AndroidJUnitRunner or private-preference injection is used. Independent UID 10148, distinct from Qeli UID 10149, performs ordinary Java socket probes without bind/protect/root/JNI. Before faults, IPv4/IPv6 × TCP 16 KiB/UDP 257 bytes are checked: complete response comparison, request/reply SHA and TUN source in receipts. After sleep and recovery, separate UDP probes confirm working data transfer.

## Scenarios

| Transport | Scenario | Auth/NetworkPlan | Result |
| --- | --- | --- | --- |
| TCP | screen-off 5 s → wake | 1/1 → 1/1 | PASS |
| TCP | forced deep IDLE 20 s → wake | 1/1 → 1/1 | PASS |
| TCP | TCP reset → reconnect | 1/1 → 2/2 | PASS |
| UDP | soft path recovery | 1/1 → 1/1; PATH_COMMIT epoch 1 | PASS |
| UDP | grace expiry 15 s → full reconnect | 1/1 → 2/2 | PASS |
| QUIC | soft path recovery | 1/1 → 1/1; PATH_COMMIT epoch 1 | PASS |
| QUIC | grace expiry 15 s → full reconnect | 1/1 → 2/2 | PASS |

Every scenario retains PID, TUN, ifindex and addresses. Sleep is confirmed by dumpsys power; forced Doze reaches actual IDLE with no permanent battery exemption. Wake creates no fresh Auth/NetworkPlan. Reset causes a native transport error, then a new successful Auth/NetworkPlan and Android TUN reuse. Soft UDP/QUIC changes the outer source port without fresh Auth; grace expiry follows NAT recovery → error → Auth → NetworkPlan. DROP/REJECT rules exist only in the private namespace; UDP rule ownership is restored by exact comparison.

## Negative window and recovery

During faults, the independent receiver times out and the sink receives no request within that probe window. This does not imply perpetual packet discard: a queued request may forward through TUN after recovery Auth succeeds. Pcap analysis checks complete UDP bytes, source and order against server AUTH on shared clocks. Actual delays after Auth: tcp 0.047 s, udp 0.048 s, quic 0.092 s. This delivery is not presented as a physical leak or proof of the full leak matrix.

Actual Settings revoke passes in all three qualified runs: `desired=false`, consent `ignore`, service/TUN absent. Preferences are only read through private AVD root after revoke. Power/battery settings are restored, server exit code is 0, and host/service and userdata SHA/size/mtime remain unchanged across all five attempts.

## Harness and Release runner review

The first attempt passes three power scenarios and revoke, but its final gate fails: it expects four dual-stack receipts from the former Debug bootstrap, absent with UI import. Four independent initial payload probes are added. The second attempt stops before faults: the new `Q29READY` marker is rejected by the receiver allowlist. The final version uses existing `Q29PROTECTED`, with payload length distinguishing initial payloads from short state probes. The test APK is unchanged; both failed attempts, XML, logs and source versions are retained and excluded from seven PASS. System UI ANR/Wait is also retained in run evidence.

DEX analysis of the prior APK pair confirms that neither APK defines `androidx.tracing.Trace`, but test DEX references original `beginSection/endSection/forceEnableAppTracing`. This agrees with the prior runner failure stack. Fresh dependencyInsight confirms the same resolved tracing 1.2.0 for app and tests: there is no resolved-version mismatch. R8 moves/removes APIs used only by tests; the [official minified instrumentation issue](https://issuetracker.google.com/issues/126429384) describes this boundary. The precise AGP dependency exclusion mechanism is unqualified here. No broad keep rules or Trace copy are added; the prior instrumentation FAIL is not called PASS or masked by UI checks.

## Checks and limits

Python/CLI, nine docs checks, panel, generated bindings and certification validation pass. No rebuild or repeated JVM/.NET suites: the relevant product inputs are byte-identical. Raw: `audit-debt-20260924/q29-android-release-faults-20261005`; evidence: `release/certification/evidence/q29-android-release-faults-20261005.json`.

This is short forced Doze in an AVD, not physical suspend/long Doze; temporary battery exemptions are not fully classified. The backend is offline; physical LTE/Internet is untested. The [prior carrier matrix](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md) remains a separate scope. NAT64/IPv6-only outer, immediate packets/full leak matrix, long flapping/power, other API/OEM/arm64 and remaining Release lifecycle scenarios stay open. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) is not repeated or closed. USER_SKIPPED and D06 without BPF remain unchanged; Q29 IN_PROGRESS.
