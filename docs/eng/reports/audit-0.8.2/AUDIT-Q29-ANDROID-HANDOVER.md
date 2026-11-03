# Q29: Android carrier-network handover

<!-- normative-sync: q29-android-handover-v1 -->

**5 October 2026. UDP/QUIC masking × Wi-Fi→Cellular/Cellular→Wi-Fi:4/4 target transitions PASS. Q29 IN_PROGRESS;plan28/37(75.7%).**

## Environment and method

Three sequential readonly Android14/API34 x86_64 AVD runs on .11 in private NET/MNT/PID namespaces. Initial UDP/QUIC runs use the strict helper;only failed UDP is repeated after correcting the harness criterion. Product/test APK,JNI,Linux CLI and296 prior source inputs identical.No new build. Server INI enables heartbeat/experimental roaming;saved profile:full tunnel,UDP/fake-tls,roaming=required,IPv6 required,reconnect=true,DNS off;second mode enables QUIC masking.

After dual-stack TCP/UDP bootstrap,instrumentation ends.Actual Always-on/lockdown starts the saved profile.Then svc wifi disable/enable changes the real Android carrier,without calling application methods or fabricating NetworkCallback.Independent UID10148 uses ordinary UDP to an off-pool sink;Qeli UID10149.No bind/protect/root payload.

System dumpsys connectivity records active default network and Current Networks:netid,handle,transport,interface.Historical event logs do not supply current facts.Shape checked against [AOSP ConnectivityService](https://android.googlesource.com/platform/frameworks/base/+/8230b03102fd3de01986fed7f1a7e660e366d859/services/core/java/com/android/server/ConnectivityService.java);reference only,not an exact-image framework commit claim.Qeli's actual best-matching NOT_VPN callback processes new Networks;its commit token and recovered traffic are checked.

## Qualified results

| Transport | Wi-Fi→Cellular | Cellular→Wi-Fi | Whole successful run |
| --- | --- | --- | --- |
| UDP,corrected-gate repeat | 2.45s;net100→101;commit0→1 | 4.40s;net101→104;commit1→3 | 151.04s |
| UDP+QUIC masking,initial strict gate | 2.24s;net100→101;commit0→1 | 4.18s;net101→104;commit1→2 | 148.92s |

Each new handle differs from the old;committed android token matches the new default carrier.Wi-Fi is wlan0/10.0.2.16,Cellular eth0/10.0.2.15 in this AVD.Server PATH_COMMIT confirms new outer source ports and increasing epochs:UDP1/2/3,QUIC1/2.No additional Auth:only bootstrap and system launch occur;Auth/NetworkPlan2/2 unchanged.Process,tun0,ifindex19 and all TUN addresses retained.

Two successful bootstraps check IPv4/IPv6 TCP16KiB/UDP257;each transition is followed by an independent IPv4 UDP reply through TUN.Successful runs have16 sink receipts:8 each(4bootstrap,1physical baseline,1connected,2post-switch).Pcap shows source10.87.0.2 and tagged packets following server PATH_COMMIT on shared host clocks.AVD time is not directly compared with host.

Actual Settings revoke PASS;service/TUN absent,desired=false,consent ignore.Wi-Fi/mobile-data settings restored;serverexit0,namespace addresses restored,host/service and userdata SHA/size/mtime unchanged in all3 attempts..10 untouched.All evidence transferred as verified complete tar bundles,including pcap/UI XML.

## Harness correction and retained FAIL

Initial UDP gate FAIL in128.95s on Wi-Fi return:Auth/plan2/2,payload/TUN passed,but commits1→3 rather than expected1→2.Log shows Network changed followed by Network link properties changed;both commits target the same new Wi-Fi handle.Address/routes/DNS changes can require another path update,so exactly-one-commit is not the tested contract.

Helper now requires at least one fresh commit,**every fresh commit must target the confirmed new handle**;no-new-Auth/plan,TUN retention and application reply checks remain.Interface delimiter parsing hardened.Repeated UDP again produces two Wi-Fi commits and passes.QUIC already passed the stronger initial counter;its token/snapshot/pcap independently rechecked without rerunning runtime.Both executed helper variants and their delta retained;QUIC is not claimed to execute the new helper.Initial failed attempt also has bootstrap PASS and8receipts,but its overall gate remains FAIL and is excluded from4/4.System revoke was not reached in this attempt;only final namespace/AVD cleanup is confirmed.

Added scripts/audit_android_network_handover.py and --suite handover in scripts/audit_android_data_plane_lab.py.No product Kotlin/JNI/core changes.All296source inputs,14native,7managed and2APKs identical to prior stage;10aux inputs checked.Historical167JVM/28Android/1248.NET,ReleaseR8lint and3+6+7integration remain separate scopes,not a fresh aggregate.Fresh docs/panel/bindings/Python checks separate.

Raw:audit-debt-20260924/q29-android-handover-20261005:runtime-udp(FAIL),runtime-quic(PASS),runtime-r2-udp(PASS),both executed source variants,source-proof/source-review,capture-analysis,raw-seal.Evidence:release/certification/evidence/q29-android-handover-20261005.json.

## Remaining scope and limits

These are actual AVD system Networks,both sharing one private offline host backend;physical Wi-Fi/LTE/Internet not tested.Post-switch payload is IPv4 UDP;post-switch IPv6/TCP,TCP outer transport,long loss/flapping,IPv6-only/NAT64 and Release runtime remain.Immediate packets during transition and complete leak matrix unqualified.[SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) remains open;[same-network UDP/grace](AUDIT-Q29-ANDROID-UDP-RECOVERY.md) and[power/TCP](AUDIT-Q29-ANDROID-POWER.md) retain separate scopes.Next Q29:TCP handover and remaining available platform checks.USER_SKIPPED devices/D06 without BPF unchanged.
