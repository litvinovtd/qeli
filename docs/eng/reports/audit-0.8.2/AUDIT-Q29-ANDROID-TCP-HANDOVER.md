# Q29: TCP across Android Wi-Fi/Cellular switching

<!-- normative-sync: q29-android-tcp-handover-v1 -->

**5 October 2026. TCP × Wi-Fi→Cellular/Cellular→Wi-Fi: 2/2 PASS; bootstrap PASS; 8 sink receipts. Q29 IN_PROGRESS, plan 28/37 (75.7%).**

One readonly Android14/API34 x86_64 AVD on .11 in private NET/MNT/PID namespaces. Product/test APK, JNI, Linux CLI and all296 source inputs match the previous stage. Harness only: --suite handover supports --transport tcp, bootstrap selects roaming=off, checks TCP full reconnect instead of UDP soft path commit. Recovery suite rejects TCP before namespace mutation.

Actual OS Always-on+lockdown starts the saved INI profile after instrumentation ends. svc wifi disable/enable switches the actual default Current Networks between WIFI(wlan0) and CELLULAR(eth0); dumpsys confirms new netids/handles. Independent UID10148, distinct from Qeli10149, sends ordinary IPv4 UDP to an off-pool sink without bind/protect/root.

| Transition | Gate time | netid | Auth / NetworkPlan |
| --- | --- | --- | --- |
| WIFI→CELLULAR | 3.29s | 101→102 | 2/2→3/3 |
| CELLULAR→WIFI | 4.35s | 102→105 | 3/3→4/4 |

TCP correctly repeats Auth and applies a fresh NetworkPlan. Both transitions retain PID, TUN, ifindex and all addresses; logs confirm Android TUN reused. Roaming commits=0: UDP path migration is not used. Server AUTH/new outer source ports match pcap; each post-switch probe traverses source10.86.0.2 after the corresponding fresh Auth on shared host clocks. Gate time includes ADB/assertions and is not pure outage latency.

8receipts:4dual-stack bootstrap (IPv4/IPv6 TCP16KiB and UDP257),1physical baseline,1connected,2post-switch IPv4UDP. Settings revoke PASS: desired=false, consent ignore, no service/TUN. Wi-Fi/mobile-data settings restored; host/service and userdata SHA/size/mtime unchanged, serverexit0, namespace addresses restored. .10 untouched. Entire run 153.03s.

Python/CLI, docs (9checks), panel and generated bindings checks PASS.296source inputs,14native,7managed,2APK rechecked;10aux inputs pinned. Previous JVM/Android/.NET/Release/integration results remain historical scopes, not a fresh full suite. Raw: audit-debt-20260924/q29-android-tcp-handover-20261005; evidence: release/certification/evidence/q29-android-tcp-handover-20261005.json.

## Limits and remaining scope

Actual AVD system Networks share a private offline backend; physical Wi-Fi/LTE/Internet are untested. Post-switch payload is IPv4UDP only: IPv6/TCP after switching, first packets during transitions, the full leak matrix, IPv6-only/NAT64, Release runtime and long/physical Doze/flapping remain. [UDP/QUIC handover](AUDIT-Q29-ANDROID-HANDOVER.md) has a separate scope. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) remains open; Q29 IN_PROGRESS. USER_SKIPPED devices/D06 without BPF unchanged.
