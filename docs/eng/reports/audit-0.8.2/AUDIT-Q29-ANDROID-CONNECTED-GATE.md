# Q29: CONNECTED after Android VPN publication

<!-- normative-sync: q29-android-connected-gate-v1 -->

5 October2026. F279 fixed in the measured API34 x86_64 Release scope;Q29 IN_PROGRESS. Plan28/37(75.7%),9 sections remain.

F279:TUN establishment/coreACK immediately published CONNECTED before Android app routing. The [previous run](AUDIT-Q29-ANDROID-STARTUP-STATE.md) reproduced EACCES/pending-connect even with an active VPN snapshot. ACK still immediately starts the native packet pump;UI stays CONNECTING until passive VPN NetworkCallback supplies AVAILABLE,VPN capabilities and LinkProperties matching plan addresses and,from API29,MTU. Facts from different networks are never combined;LOST discards facts. INTERNET/VALIDATED are not required for private/split VPNs.

Fresh observer per plan,including retained TUN. Core/generation/descriptor ownership,coroutine activity and status checked under service monitor before CONNECTED;stop/revoke/reconnect cannot resurrect an old generation. Transport exit/teardown cancel the wait. Profile timeout bounded1–30s;failure stops native generation,retaining TUN/system lockdown for retry. No failed ACK after successful ACK;failure to start the observer after ACK also stops core. Observer unregisters in finally. Timeout/cancel immediately before callback source-reviewed,without dedicated runtime injection.

An owner can observe its VPN even when excluded from UID ranges:[AOSP NetworkCapabilities](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android14-release/framework/src/android/net/NetworkCapabilities.java). Include INI captures only com.qeli.test;Qeli skips itself in addAllowedApplication. Independent ordinary-UID traffic sockets unbound/unprotected. AOSP branch is reference,not verified exact image revision.

| Final APK check | Result |
| --- | --- |
| TCP cold start,include/test UID |CONNECTED after ACK 557.0ms;34fresh post-CONNECTED samples,0errors |
| UDP cold start,all |CONNECTED after ACK 724.0ms;46fresh post-CONNECTED samples,0errors |
| TCP include,Wi-Fi ↔ Cellular |2transitions,freshACK/CONNECTED each generation,samePID/TUN/addresses,8dual-stackTCP/UDP payload checks |
| Unit/lint |172/172,5new publication tests;0lint errors/55prior warnings |
| Harness |4startup helper tests,2resolver regressions,4CLI rejection guards |

Three final Release/R8 runs:960burst socket samples,660echo receipts. Cold post-CONNECTED:80/80PASS;first fresh family/protocol sample required per cold run,missing coverage rejected. Product log timestamps liveStatus publication;Activity broadcast receipt not separately measured. Sampled API34 PASS is not a guarantee for every first packet/OEM. Post-APPLIED/pre-CONNECTED errors and historical FAIL retained.

Independent nonce/request/replySHA,sink/private-hostpcap:four physical outgoing paths positively calibrated before lockdown,fresh delivered tagged post-plan requests through TUN. No new physical SYN/data/UDP in protected steady/stop window,0kernel capture drops. 144post-stop samples without response/receipt/capture,14DNS operations/14answered questions,12manual recovery payload checks,Settings revoke/cleanupPASS. Include/retainedTUN covered,not full include/exclude/split/Private DNS matrix.

Initial exploratory include/TCP:36post-CONNECTED PASS,460ms,336samples/216receipts;separate APK/mapping/executed helpers retained. Full lint then found2NewApi errors,getMtuAPI29/clearCapabilitiesAPI30. Fixed without suppression/minSdk bump:API28 does not read MTU,API28–29 remove default capabilities through compatible calls. Final build/172tests/lintPASS;initial lintFAIL retained.API28/29 runtime not executed. Local driver/report preparation assertion/missing-file/quotingSyntaxError fixed before their stages;not remote runtime failures.

Native digest,14JNI/native hashes/7managed artifacts unchanged;no Rust rebuild. Service/README changed,2source files added;298source/14auxiliary inputs pinned. Lab signing only,non-debuggable product,productionR8/security unchanged,INI-only configs. Four sequential .11 runs in private NET/MNT/PID/readonlyAVD;host/service/firewall/routes/userdata unchanged,namespacecleanup/serverexit0,.10untouched.

RemainingQ29:split/per-app exclusions/PrivateDNS,longpower/flapping/further lifecycle/races;SIGKILL recoveryFAIL,genericDnsResolverauto/nullENONET,matchingR8runnerTraceFAIL remain. QUIC cold gate not run on newAPK.USER_SKIPPED/D06 unchanged.

Raw:audit-debt-20260924/q29-android-connected-gate-20261005;evidence:release/certification/evidence/q29-android-connected-gate-20261005.json.
