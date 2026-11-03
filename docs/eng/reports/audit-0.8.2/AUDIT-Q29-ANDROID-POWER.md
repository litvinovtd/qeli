# Q29: Android screen, deep idle and TCP recovery

<!-- normative-sync: q29-android-power-v1 -->

**5 October 2026. Three new runtime scenarios PASS; Q29 IN_PROGRESS. Plan: 28/37 (75.7%), 9 sections remain.**

## Environment and scope

One readonly Android 14/API34 x86_64 AVD, `UE1A.230829.036.A1/11228894`, in private NET/MNT/PID namespaces on .11. Debug APK/JNI exactly reused from the qualified prior stage. The normal INI parser saved a TCP full-tunnel profile with reconnect=true, roaming=off, DNS=off and IPv6 required. Actual Settings enable Always-on/lockdown. Ordinary UDP probes originate from independent test UID10148, distinct from Qeli UID10149; shell/root traffic does not replace application probes.

## Fresh results

| Scenario | Observation and result |
| --- | --- |
| Bootstrap | 1 instrumented PASS in 2.105s; four off-pool TCP/UDP IPv4/IPv6 replies |
| Screen off for 5s | PASS: screen actually not Awake; PID/TUN/ifindex/all addresses retained; post-wake UDP reply through TUN |
| Forced deep idle for 20s | PASS: IDLE verified before/after dwell; same PID/TUN; post-wake UDP reply through TUN |
| TCP reset and automatic reconnect | PASS: actual native transport error; TUN retained during fault; fresh Auth/NetworkPlan and reply through TUN without manual launch |
| System revoke and cleanup | PASS: service/TUN absent, desired=false, VPN consent revoked; server exit0, namespace addresses and power settings restored |

Both wakes log “same network, keeping the tunnel”: Auth=2 and NetworkPlan=2 remain unchanged. PID2155, tun0/ifindex19, 10.86.0.2/32 and fd86:29:1::2/128 persist. TCP recovery raises both counters 2→3 while retaining the same TUN, with a reuse marker. The first attempt passes in 183.92s. Host/service and userdata SHA/size/mtime unchanged; .10 untouched.

No permanent user battery exemption for Qeli is present; the UI request was denied. Temporary framework exemptions are not fully classified. Doze restricts network/CPU and can ignore wake locks; foreground service alone does not prove absence of power restrictions. [Official Android documentation](https://developer.android.com/training/monitoring-device-state/doze-standby).

## Packet sent during the fault

The negative Q29BLOCKED probe receives SocketTimeoutException and **zero sink receipts within its observation window**. After removing the private INPUT TCP REJECT, the retained TUN forwards that packet: pcap source10.86.0.2, arriving 0.207s after fresh server Auth. This is delayed VPN delivery after recovery; “never delivered” would be incorrect. Analysis uses server AUTH timestamps and pcap sharing host clocks, without directly comparing AVD and host clocks.

The sink records **10 packets**: four bootstrap, one physical baseline, four positive Q29PROTECTED through TUN, and one delayed Q29BLOCKED through TUN. Zero receipts during the fault probe is not a complete packet-discard or leak guarantee. The firewall fault targets only private namespace port24966; finally removes the exact rule.

## Changes and reproducibility

Added `--suite power` in scripts/audit_android_data_plane_lab.py and helper scripts/audit_android_power_lifecycle.py. Repeated tagged probes wait for a fresh COMPLETE log entry rather than accepting an existing response. Shared UI/UDP helpers and only pure state parsers from scripts/roaming_android_sleep_wake_gate.py comprise five executed inputs. The old sleep gate using shell ping does not provide application network evidence.

qeli-android/README.md now clarifies wake locks and user battery exemption. Only that document changed among 296 previously qualified source inputs; the other 295, product/test APKs, 14 native and 7 managed artifacts are identical. No core/JNI/product Kotlin changes were needed. Fresh docs/panel/bindings checks are separate from historical 167 JVM/28 Android/1248 .NET, Release R8/lint and 3+6+7 integration scopes; there is no fresh combined run.

Raw: `audit-debt-20260924/q29-android-power-20261005`, including runtime-initial, pcap, late-delivery-analysis.json, source-proof and raw-seal. Evidence: `release/certification/evidence/q29-android-power-20261005.json`.

## Remaining scope

No payload probe runs inside IDLE, since launching the receiver could alter power state. This verifies retention and post-wake traffic, not uninterrupted Doze delivery. Physical CPU suspend, long sleep/wake-lock lease renewal, actual Wi-Fi/LTE handover, UDP/QUIC fault grace, Release runtime and other API/OEM remain unqualified. [The prior SIGKILL restart failure](AUDIT-Q29-ANDROID-SYSTEM.md) remains FAIL; this batch does not repeat or close it. Mac/iOS/router/Windows VM remain USER_SKIPPED; D06 without BPF is an accepted boundary. Next Q29 batch: actual default-network changes and UDP/QUIC recovery.
