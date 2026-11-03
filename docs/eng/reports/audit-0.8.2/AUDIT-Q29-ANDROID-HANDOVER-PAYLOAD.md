# Q29: IPv4/IPv6 TCP/UDP after Android network switching

<!-- normative-sync: q29-android-handover-payload-v1 -->

**5 October 2026. Three outer transports × two Wi-Fi/Cellular transitions × four payload probes:24/24PASS.6carrier transitions,3bootstrapPASS,42sink receipts. Q29 IN_PROGRESS;plan28/37(75.7%).**

Three sequential readonly Android14/API34 x86_64 AVD runs on .11 in private NET/MNT/PID namespaces. Actual OS Always-on+lockdown starts the saved INI profile after instrumentation. svc wifi disable/enable switches actual Current Networks between WIFI(wlan0) and CELLULAR(eth0); new netids/handles confirmed. .10 untouched.

After each transition independent UID10148, distinct from Qeli10149, opens ordinary Java sockets to an off-pool sink:IPv4/IPv6 × TCP16KiB/UDP257. No bind/protect/root, JNI or target APK dependency. TCP reply is the full reversed payload, UDP is Q29:prefix+payload; receiver compares every byte and request/reply SHA256, harness verifies sink receipts and TUN source. Result is not based only on CONNECTED status.

| Outer transport | Wi-Fi→Cellular | Cellular→Wi-Fi | Payload | Entire run |
| --- | --- | --- | --- | --- |
| tcp | 5.79s | 10.38s | 8/8PASS | 163.02s |
| udp | 4.91s | 24.51s | 8/8PASS | 165.02s |
| quic | 5.05s | 27.45s | 8/8PASS | 174.97s |

Gate time includes ADB and four probes; not pure outage latency. All runs retain PID,tun0,ifindex19 and every address. TCP:Auth/NetworkPlan2/2→3/3→4/4,new outer ports,Android TUN reused,0UDPcommits. UDP/QUIC:Auth/plan2/2unchanged,PATH_COMMIT with new outer ports/epochs; every new Android commit token matches the confirmed target carrier.

Pcap confirms8post-switch requests per transport with IPv4/IPv6 TUN source after the corresponding server AUTH/PATH_COMMIT on shared host clocks. TCP requests fully reassembled by sequence with matching overlap/retransmission bytes; all16KiB SHA matches receiver/sink. Initial offline parser wrongly expected frame length and payload in one IP packet; failure/correction preserved separately,no runtime rerun. Each run14receipts:4dual-stack bootstrap,1physical baseline,1connected,8post-switch.42total receipts,including24new target payloads.

Settings revoke and cleanupPASS in all3runs:desired=false,consent ignore,no service/TUN. Wi-Fi/mobile-data settings restored,host/service anduserdata SHA/size/mtime unchanged,serverexit0,namespace addresses restored. Product APK/JNI/LinuxCLI/managed unchanged;295of296source inputs match,only test receiver changed. TestAPK rebuilt offline;10aux inputs pinned. Harness changes do not mean historical suites executed again on the new testAPK.

Fresh build/Python/CLI,docs9checks,panel and generated bindingsPASS. Raw:audit-debt-20260924/q29-android-handover-payload-20261005;evidence:release/certification/evidence/q29-android-handover-payload-20261005.json. Previous JVM/Android/.NET/Release/integration results remain historical scopes,not a fresh full suite.

## Limits and remaining scope

Available AVD post-switch IPv4/IPv6 TCP/UDP payload covered for TCP/UDP/QUIC outer. Each TCP probe opens a new connection; continuity of an already open long stream untested. System AVD carriers share a private offline backend;physical Wi-Fi/LTE/Internet untested. IPv6 inner does not imply IPv6-only outer/NAT64. First packets during transitions,full leak matrix,IPv6-only/NAT64,Release runtime and long/physicalDoze/flapping remain. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) open. Previous [UDP/QUIC](AUDIT-Q29-ANDROID-HANDOVER.md) and [TCP](AUDIT-Q29-ANDROID-TCP-HANDOVER.md) scopes preserved;USER_SKIPPED/D06withoutBPFunchanged,Q29IN_PROGRESS.
