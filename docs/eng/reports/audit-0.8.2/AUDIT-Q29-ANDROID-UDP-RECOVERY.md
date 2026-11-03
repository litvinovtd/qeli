# Q29: Android UDP and QUIC masking recovery

<!-- normative-sync: q29-android-udp-recovery-v1 -->

**5 October 2026. UDP/QUIC × soft recovery/grace expiry: 4/4 fresh runtime PASS. Two bootstrap PASS. Q29 IN_PROGRESS; plan28/37 (75.7%).**

## Scope

Two sequential readonly Android14/API34 x86_64 AVD runs on .11, each in private NET/MNT/PID namespaces. Product debug APK,JNI and Linux CLI exactly reused;only test APK rebuilt. Normal encrypted ProfileStore saves INI:UDP,fake-tls,roaming=required,full tunnel,IPv6 required,reconnect=true,DNS off;second run enables QUIC masking. Server advertises experimental roaming and heartbeat5000ms,grace15s;both endpoints remain running during faults. Actual Settings enable Always-on/lockdown.

Independent test application uses an ordinary DatagramSocket,no bind/protect/root. Bootstrap checks TCP16KiB/UDP257 over IPv4/IPv6 to off-pool targets. After instrumentation ends,the system starts the saved profile;recovery is not simulated by calling client methods.

## Fresh results

| Transport | Soft recovery | Sustained fault | Whole run |
| --- | --- | --- | --- |
| UDP | PASS;NAT request31.78s,DROP removed32.08s | PASS;NAT request32.40s,DROP removed49.85s | 226.94s |
| UDP + QUIC masking | PASS;NAT request32.22s,DROP removed32.63s | PASS;NAT request31.27s,DROP removed54.16s | 247.33s |

The soft scenario restores transport shortly after a new-path request,within its grace;this is not a five-second outage test. Each run retains Auth/NetworkPlan2/2,commit rises0→1,and payload again arrives through TUN. Server PATH_CHALLENGE/PATH_COMMIT confirms a real new outer source port and epoch1;the physical Android Network remains unchanged.

Sustained fault retains bidirectional UDP DROP until native transport error and a negative application probe. Sequence:NAT recovery request → transport error → fresh Auth → NetworkPlan. Auth/plan2→3,commit remains1;one successful full Auth/plan,without manual reconnect. PID,tun0,ifindex19 and all IPv4/IPv6 addresses match before/after recovery;TUN reuse marker observed. Actual Settings revoke PASS after both scenarios. Services/TUN absent,desired=false,consent ignore;serverexit0,rules/namespace addresses restored,host/service/userdata unchanged..10 untouched.

## Negative probe and delayed delivery

Each Q29BLOCKED ends in SocketTimeoutException with zero sink receipts within its observation window. After reconnect,that packet forwards **through TUN**,source10.87.0.2. UDP:0.179s,QUIC masking:0.257s after fresh server Auth;exact timings are in capture-analysis.json. Server timestamps and pcap share host clocks;AVD clock is not directly compared. Permanent discard is not claimed.

Each sink records9 receipts:four dual-stack bootstrap,physical baseline,connected positive probe,soft/full recovery replies and a delayed fault packet. Total18 deliveries:16 correspond to successful probes,2 are delayed. This is a limited IPv4 UDP fault probe,not a complete TCP/IPv6 leak matrix.

## Changes and evidence

scripts/audit_android_data_plane_lab.py adds recovery suite/transport selection;scripts/audit_android_udp_recovery.py implements both faults with exact own-rule removal in finally. VpnSystemLifecycleInstrumentedTest accepts validated private UDP/QUIC/roaming fixture arguments and selects the correct pin/port/IPv6 prefix. Java receiver and product Kotlin unchanged.External configuration remains INI.

New test APK built locally offline:remote /root/android-project was stale,and its APK/sources were not used. Only one instrumented test changed among296 prior source inputs;295 identical. Product APK,14native and7managed artifacts unchanged;test APK fresh. Historical167JVM/28Android/1248.NET,ReleaseR8lint and3+6+7integration remain separate scopes,not a fresh combined run. Fresh docs/panel/bindings/Python checks run separately.

Raw:audit-debt-20260924/q29-android-udp-recovery-20261005:runtime-udp/runtime-quic,executed sources,new test APK,server INI,source-proof,capture-analysis/raw-seal. Evidence:release/certification/evidence/q29-android-udp-recovery-20261005.json.

## Remaining Q29 scope

This verifies same-network UDP recovery/fallback,not a default physical-network switch. Next batch:actual available AVD carrier-network switching.Long/physical Doze,IPv6-only/NAT64,Release runtime and other API/OEM remain unqualified. [Prior SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) remains open;[power/TCP batch](AUDIT-Q29-ANDROID-POWER.md) retains its separate scope.Mac/iOS/router/Windows VM USER_SKIPPED and accepted D06 without BPF unchanged.
