# Q29: Android VPN payload and post-auth lifecycle

<!-- normative-sync: q29-android-data-v9 -->

**5 October 2026. Stage PASS; Q29 IN_PROGRESS. Plan28/37(75.7%),9 sections remain.**

## Qualified behavior

Three new instrumented cases start actual VpnService/JNI:TCP fake-tls,UDP fake-tls,UDP QUIC. Client verifies a pinned identity with bind_static_to_session;server requires client key proof. Each establishes dual-stack TUN and sends a16KiB TCP stream and32/257/1024byte UDP payloads both ways overIPv4/IPv6. The independent sink reverses TCP payload or prefixes UDP replies;exact bytes,server-side source addresses andSHA256 are recorded. This is not a benchmark.

After traffic,invalid ACTION_CONNECT must preserve CONNECTED,negotiated properties,foreground andconnection_desired;further traffic verifies continuity. Manual disconnect removes service/TUN. TCP also completes a second authenticated start after preceding teardown finishes.

**Fresh3/3 PASS**,48 sink replies for the fixedAPK. OldAPK:1test,1expectedFAIL after successfulIPv4/IPv6traffic replaces CONNECTED withERROR;additional coverage of already fixedF278,no new product patch. ServerTCP-TUN pcap retained. Final tests explicitly bind AndroidVPNNetwork and wait for kernel source selection from assignedTUN addresses.

## Fixture and provenance

scripts/audit_android_data_plane_lab.py runs Qeli andreadonlyAVD in freshNET/MNT/PID namespaces on.11,without external uplink orproduction profiles. TwoINI profiles useNAT=false andIPv6manual;traffic targets the server's own tunnel addresses,no external routing orDNS. Android14/API34 x86_64,requested memory768MiB/1core; retained runtime-final/emulator.log reports an increase to2560MB. LinuxCLI matches a previously qualifiedSHA256,no freshRust build.

ProductAPK matches preceding stage byte-for-byte.289 prior inputs,JNI and7managedDLLs unchanged;prior167JVM,28Android,1248.NET andRelease/R8/lint(0errors55warnings) reused only within their original scopes. These are **not** fresh runs. No fresh combined31Android run. Without private fixture arguments the three integration tests skip;ordinary emulator CI does not qualify this stage.

Earlier attempts retained:invalidINI heartbeat/jitter combination;differentADB ports;early Java sockets selecting physical source/read timeouts;TCP sink terminating onEOF;initial sink-count assertion racing worker completion. They are not presented as a proven transport-core regression. Harness waits for actual kernel source before sending and keeps accepting afterEOF. Independent IPv4/IPv6 EOF → fresh-request check passes. Ordinary apps' immediate default-network selection afterCONNECTED remains unqualified andnext inQ29:LinkProperties/CONNECTED alone do not prove kernel-route readiness.

All five namespace executions and the initial config-only failure preserveAVDuserdata SHA256/mtime/size;working.11 hostnetwork/qeli.service match before/after. Final server exits0,private namespace addresses restored;no app service/TUN afterforce-stop,noAndroidRuntimeFATAL. .10 untouched. Arm64 packaged bytes checked,not executed.

## Remaining scope

Ordinary apps' automaticVPNselection,full-tunnel/lockdown,DNS/external routes,Wi-Fi/LTEroaming/protect,revoke/processdeath/redelivery/always-on/Doze,Release runtime andolderAPIs. No new physicalLTE/OEMbackup evidence. WholeQ29 remains open. Earlier [framework lifecycle](AUDIT-Q29-ANDROID-SERVICE.md) and[TUN/JNI](AUDIT-Q29-ANDROID-LIFECYCLE.md) retain their own scope.

Raw:C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-data-20261005.
Evidence:release/certification/evidence/q29-android-data-20261005.json.

## Additional stage: ordinary sockets

Six new cases (TCP fake-tls, UDP fake-tls, UDP QUIC × split/full) use ordinary Socket/DatagramSocket without Network.bindSocket/socketFactory or process binding. **6/6 PASS,72 server replies**: IPv4/IPv6,TCP16KiB,UDP32/257/1024,rejected CONNECT after traffic and manual stop. Native NetworkPlan confirms three mode=full and three mode=split. Destinations are the server's own TUN addresses: exercising full configuration does not yet prove external/default traffic capture.

A readiness window was observed: in **5/6 starts the first IPv4 socket after observed CONNECTED selected physical source10.0.2.16**. TUN source selection appeared1–111ms after observing the status; subsequent IPv6 probes already selected TUN. Measurements include25ms polling,two successful predicate evaluations and checking overhead; they are not exact netd application timing. Diagnostic UDP sockets send no data. Payload is sent only after bounded source preflight. Thus six PASS results confirm delivery after readiness, **not immediate first-packet success after CONNECTED or leak safety with kill_switch=false**. Root cause and any status-publication adjustment remain open; no new Rust regression is established.

Product APK/JNI unchanged,no product fix. Fresh test APK build and six debug cases; preceding results are reused only within original scopes,no fresh combined37Android run. New six cases skip without private fixture arguments. scripts/audit_android_data_plane_lab.py adds --suite ordinary; default explicit selects only the original three methods.

One run took109.19s,tests18.913s. Readonly API34x86_64,fresh NET/MNT/PID on.11,serverexit0,namespace addresses restored,userdata SHA/mtime/size and working network/service unchanged,no app service/TUN,no AndroidRuntimeFATAL. .10 untouched. Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-default-20261005; evidence: release/certification/evidence/q29-android-default-20261005.json. Q29 remains IN_PROGRESS; next external routes/DNS/kill-switch,early first-packet readiness and system lifecycle.

## Off-pool routes, system DNS and kill-switch rejection

Next batch: **7/7 new debug instrumented cases PASS**. Six cover TCP fake-tls,UDP fake-tls and UDP QUIC in split/full; the seventh rejects full-tunnel kill_switch=true without system lockdown. No fresh combined44Android suite was run; prior results retain their original scopes.

Destinations198.19.0.1 and2001:db8:29::1 are outside both VPN pools. Full profiles have no includeRoutes: delivery requires default routes0.0.0.0/0 and::/0,both checked in LinkProperties. Split profiles have explicit /32,/128 and no defaults. Ordinary unbound Socket/DatagramSocket carry TCP16KiB andUDP32/257/1024; the server records72 replies with TUN sources and payload hashes. This proves client off-pool capture. Targets belong to private server loopback: no external Internet,serverFORWARD/NAT/NAT66 or production connectivity test.

Each profile installs tunnel DNS198.19.0.53; its /32 route is checked independently from user includeRoutes. Ordinary InetAddress.getAllByName resolves six unique q29-*.test names. The client receives A andAAAA in all six cases; the independent DNS sink records12 answered questions from TUN sources and pcap confirms the path. Other Android queries get NXDOMAIN; no external uplink. Private DNS/DoT and resolver restoration after system process-death are outside scope.

The negative kill-switch case uses a valid profile: without OS lockdown Qeli publishes ERROR,finishes the foreground service and leaves no TUN/connection properties. Positive Always-on+lockdown and process-death packet blocking are **not yet qualified**. Editing secure settings alone does not count as enabling system policy.

Initial attempt retained:1negativePASS,6UDP receive timeouts. Pcap shows request198.19.0.1:26000 and reply10.86.0.1:26000: the fixture wildcard UDP socket selected the wrong source,so connected DatagramSocket rejected replies. Binding the sink to each destination address yields7PASS. IPv6 default assertion was additionally changed from text to address family; original::/0 formatting worked and did not cause those six failures. No new product defect or APK/JNI change in this stage.

Final run105.94s,tests21.149s; Android14/API34x86_64,readonly AVD and server in fresh NET/MNT/PID on.11. Both runs preserve userdata SHA/mtime/size and working hostnetwork/qeli.service;serverexit0,namespace addresses restored,no app service/TUN after stop,no AndroidRuntimeFATAL. Product APK,289priorinputs,14nativehashes and7managedDLL unchanged. Fresh test APK build only; prior167JVM/28Android/1248NET/Release-lint reused in original scope. New seven cases skip without private fixture arguments; gate --suite routed.

The gap between observed CONNECTED and actual source selection persists in route-readiness.json; payload still waits for bounded unsent preflight. Qeli publishes CONNECTED after native ACK without waiting for framework default network. [AOSP Vpn source](https://android.googlesource.com/platform/frameworks/base/+/b8e604452076/services/core/java/com/android/server/connectivity/Vpn.java) establish creates/registers NetworkAgent and returns TUN. This supports a hypothesis of separate state publication; this source is not the emulator's exact build source and does not prove netd timing. Early-status semantic decision remains open.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-routes-dns-20261005. Evidence: release/certification/evidence/q29-android-routes-dns-20261005.json. Q29IN_PROGRESS,plan28/37(75.7%). Next positive lockdown,revoke/process-death/redelivery/always-on/Doze,Release and remaining platform scenarios.


The subsequent [system lifecycle stage](AUDIT-Q29-ANDROID-SYSTEM.md) confirms positive lockdown and tested blocking after process death;automatic SIGKILL redelivery remains FAIL (issue OPEN). This is a separate partial qualification;Q29 stays open.


<!-- q29-storage-startup-20261012 -->

**12 October:** A new current matching-R8 cold UI/SAF run with independent UID passed after bounded storage admission. All80 post-CONNECTED sockets passed; established stopped lockdown48/0,manual recovery/system+raw DNS PASS.241 receipts correlated to UID journal. Generic DNS/null ENONET and historical SIGKILL FAIL remain open;ordinary production APK unqualified. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-production-runtime-20261012 -->

**12 October:** Ordinary production R8 APK qualified via UI/SAF and independent UID without instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts,stopped lockdown48/0 and manual recovery/DNS PASS. APK payload unchanged by lab signing;real release signing and physical platforms unqualified. DNS/null ENONET,first-post-APPLIED blocking and historical SIGKILL retained. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md).Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-dns-selection-control-20261012 -->

**12 October:** Q29 generic/null ENONET cause localized on the current API34 image. Authenticated dnsproxyd selection and independent platform TUN owner UID reproduce failure;bypassable control returns A+AAAA. Typed/null and explicit VPN DNS traverse TUN. Product APK/JNI/default kill-switch unchanged;compatibility failure retained,SIGKILL and first-post-APPLIED remain open. [DNS comparison](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-current-sigkill-20261012 -->

Current production R8 SIGKILL recovery:FAIL;whole runtime FAIL. Plain/TUN platform controls ran once,45s window retained. Manual recovery/revoke and dead/force-stopped blocking PASS. Product APK/JNI and byte-identical restart policy unchanged;SIGKILL failure not overwritten. [System scope](AUDIT-Q29-ANDROID-SYSTEM.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-publication-contract-20261012 -->

APPLIED/CONNECTED boundary reviewed: first sampled sockets after APPLIED started before CONNECTED;8 interval refusals and80/80 post-CONNECTED PASS in each retained run. Interpretation question closed, original FAIL_POST_PLAN_BLOCKING retained. The helper already gates post-CONNECTED;6 methods PASS. No new runtime/builds. SIGKILL/DNS compatibility FAIL and Q29 IN_PROGRESS remain. [Current contract](AUDIT-Q29-ANDROID-CURRENT-VPN.md).
