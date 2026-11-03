# Q29: current VPN integrations and Android fixture reliability

<!-- normative-sync: q29-current-vpn-v7 -->

**Current October 15 result: Q29 completed within agreed scope. The user accepted the documented generic/null DNS limitation of the measured API34 image. ENONET is not fixed and the original FAIL is retained; secure VPN and the system kill switch remain. Full audit: 37/37.**

12 October2026. Q29 IN_PROGRESS;32/37 (86.5%),5 sections open.

Seven current matching-R8 instrumented VPN integrations PASS on Android14/API34
x86_64. CLI52511ceb…, APK77c12051…/JNI01da54a3… used;126 canonical Android build
inputs match. Non-debuggable target and native bytes match qualified current
builds. Unchanged JVM/native A/B not replayed; no new large compiler caches.

| Scenario | Fresh result |
| --- | --- |
| TCP, UDP fake-TLS, QUIC × split/full | 6 actual instrumented PASS |
| IPv4/IPv6 × TCP/UDP sockets | 72 independent server echo receipts, exact size/SHA; TCP16384B and UDP32/257/1024B |
| System DNS through VPN | 6 unique names, A/AAAA question/answer receipts with TUN source |
| Full kill-switch without system lockdown | 1 actual refusal PASS; not qualification of enabled lockdown |
| Final service/TUN/AndroidRuntime | No service/TUN; no FATAL EXCEPTION |
| Guest memory | Requested1536MiB/explicit lowram, MemTotal=1505648KiB |

Final gate duration:130.93s. Ordinary sockets without process binding
or explicit Network.bindSocket in routed cases retain source/readiness preflight.
Instrumentation uses target-app context: this does not qualify a separate
non-VPN-owner UID or the first socket after CONNECTED. Instrumentation creates
profiles instead of UI/SAF. The signed R8 pair uses matching-runner rules;
ordinary production-rules APK, arm64/OEM and long physical sessions are not
qualified by this execution.

## Harness fixes

1. Emulator36.6.11 raised requested768MiB to2560MB. On the2GiB VM, owned
   cgroups1400MiB RAM/512MiB swap then1400MiB/1536MiB exhausted capacity before
   APK install and during UI import. Now1536MiB/explicit `-lowram` plus mandatory
   guest MemTotal admission before APK install. Four focused methods PASS.
   [AOSP](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android/android-emu/android/main-common.c) explains removal of the RAM lower bound; this branch is not proven
   to be the exact installed build source.
2. The24-sample cold burst finished0.854s before CONNECTED. The helper now waits
   boundedly for CONNECTED before the existing fresh follow-up. All observed
   post-CONNECTED samples in both bursts must pass; missing cold coverage stays
   explicit without continuous-coverage PASS. Two new methods cover late
   publication and failed follow-up refusal.
3. Profiles tap had not finished transitioning when Import was declared absent.
   Up to30s/5 fresh observations require the button; retap only an unselected
   Profiles tab. Three methods reject selected-only false PASS/delayed transitions.
4. A system ANR during Always-on was misclassified as unknown VPN confirmation.
   Shared UI helper preserves original XML, selects only system Wait and requires
   a fresh ordinary screen within3 attempts. Two methods cover preservation and
   refusal on repeated ANR.

Together with prior DNS/startup fixtures:23 helper methods PASS. Memory admission
ran in current Android. The fully repaired cold UI scenario **did not pass**:
the last cold attempt stopped at unpublished `/sdcard`, with remote secure_mkdirs
failed on INI push. Previous ANR/UI/timing failures remain. One failed attempt
received actual VPN replies before aborting, without full acceptance PASS. The
seventh routed gate has its own successful scope and does not close those failures.

Historical system/data descriptions now distinguish requested768MiB from measured
RAM. Retained data/runtime-final, restart-control/r4 and resolver-diagnostic logs
report2560MB. Original packets, dates/results remain unchanged.

## Remainder

Prior SIGKILL automatic recovery also failed in minimal independent TUN control;
this step neither repeats nor closes it. Generic auto/null DnsResolver ENONET
remains: ordinary system lookup in the routed gate is a different API operation.
Current cold UI startup/lockdown/recovery remains FAIL/uncovered. Do not repeat
identical cold attempts without external-storage admission and adequate system
stability. Lowram is not standard physical-platform qualification. Historical
positive matrices retain original inputs; USER_SKIPPED/D06 unchanged. Q29 and
the whole audit remain incomplete.

All7 attempts preserved host firewall/routes/resolver, production service and
original AVD userdata. Seven owned roots removed after SHA-verified full recovery
archives and process/fd/mount/host snapshot checks. Raw:
`audit-debt-20260924/q29-current-vpn-20261012`, `q29-current-vpn-r2-20261012`…
`q29-current-vpn-r7-20261012`. [Scoped evidence](../../../../release/certification/evidence/q29-current-vpn-20261012.json).
`NO_PUSH_DEPLOY_RELEASE`.


## 12 October: cold UI and independent UID after storage admission

One corrected current matching-R8 run PASS in256.91s. The app is not debuggable;
actual UI/SAF imported INI without instrumentation or private prefs injection.
126 canonical Android build inputs,CLI52511ceb…,APK77c12051… and native01da54a3…
retain the qualified current bytes. Ordinary production-rules APK and physical
devices remain outside this scope.

After boot_completed,`/sdcard` was absent: readlink pointed to
`/storage/self/primary`,df reported No such file. One10s ADB timeout was observed.
At16.995s,the real `/dev/fuse` mounted at `/storage/emulated`,resolved
`/storage/emulated/0` and shell write access were observed. This is one boot
measurement,not a universal deadline. A shared helper now waits at most60s and
retains every observation before APK install and immediately before INI push.
`Download` is created only after admission; uploaded INI SHA256 is checked before
the file picker opens. A writable underlying directory without FUSE is refused.
[AOSP](https://source.android.com/docs/core/storage/scoped) describes modern FUSE
emulated storage; exact path/filesystem guards apply to this API34 AVD.

Five new storage and three UI transition methods PASS with no skips. Negative
cases include underlying directories,wrong/ambiguous user paths,transport errors,
shared budget expiry without extension,timeouts and unknown phase. The full
corrected cold scenario ran once; all six prior failures retain their results.
Guest MemTotal1505652KiB for requested1536MiB passed the existing reserved-kernel
memory admission. An initial local qualifier incorrectly demanded the previous
1505648KiB;4KiB difference is not a product failure. Only metadata qualification
was corrected; the runtime was not replayed.

| Ordinary UID10149,VPN owner10148 | Fresh samples / replies |
| --- | --- |
| Physical baseline |48/48|
| Cold lockdown start |96/64|
| Startup follow-up |48/48|
| Connected steady |48/48|
| Force-stop transition |48/23 — before transition completed|
| Established stopped lockdown |48/0 — all blocked|

336 burst probes yielded231 successful replies;10 additional socket probes
succeeded. All241 server echo receipts independently matched protocol/family/
payloadSHA from the non-VPN-owner journal. Connected/manual recovery IPv4/IPv6
TCP16384B and UDP257B passed. Physical baseline and pre-transition replies are
not described as VPN leakage. Established stopped state had no socket or DNS replies.

The first sockets after Native NetworkPlan APPLIED still had EACCES/Pending
connect failure;FAIL_POST_PLAN_BLOCKING is retained. Android CONNECTED was
published535ms after APPLIED. All80 observed post-CONNECTED sockets passed:32
cold-burst and 48 follow-up samples,all four family/protocol combinations.
Coverage=COLD_AND_FOLLOWUP;finite sampling does not prove uninterrupted delivery
or the first possible socket exactly at publication.

Seven DNS cases PASS:raw physical baseline;system/raw connected;two blocked
refusals;system/raw after manual recovery. Generic DnsResolver with explicit
active VPN now returns A+AAAA;typed A/AAAA with null/active network also pass.
Generic `network=null` still returns ENONET while VPN is active. Diagnostic
observation does not turn this failure into a complete DNS qualification.

The current independent-UID cold UI/startup/lockdown/force-stop/manual recovery
gate is qualified in this scope. Automatic SIGKILL recovery is another lifecycle:
historical FAIL remains,not executed here. Q29 IN_PROGRESS;32/37(86.5%).
Original readonly AVD userdata,PID777/845/service and all host firewall backends/
routes/resolver preserved. Results SHA-qualified;owned root removed after
verified recovery and inode/path/process/fd/mount guards. No Rust/JVM/native
builds or large compiler caches were created.
[Evidence](../../../../release/certification/evidence/q29-storage-startup-20261012.json).
Raw:`audit-debt-20260924/q29-storage-startup-20261012`.NO_PUSH_DEPLOY_RELEASE.


## 12 October: ordinary production R8 APK, independent UID

The ordinary `assembleRelease` APK passed runtime in 252.94s on Android14/API34/x86_64. This build uses neither `instrumentation-abi.pro` nor `qeliTestBuildType=release`. No Gradle/Rust/JVM builds were repeated: the existing production-unsigned APK `ec05ed9330ca3db7cca6f296569e68b24f172f5c9d2a5d65667e80e717da288c` was signed with the Android Debug certificate for this isolated AVD. Signature,16KiB ZIP alignment and all 1091 non-signature ZIP entries were verified, including unchanged DEX/resources/manifest and both JNI. Signed SHA256 `3d8496b42251fd90109a4b87532acf8a1c8b16a1a07d85267ce6c08b2db7f2a7`. Real release signing and physical/OEM/arm64 execution are not qualified here.

The app is not debuggable. Actual UI/SAF imported INI without instrumentation or private prefs injection. The test APK served only as a standalone broadcast receiver, UID 10149, separate from VPN owner UID 10148. Ordinary TCP/UDP sockets do not bind/protect; explicit Network binding occurs only in separately labelled diagnostics. All 126 canonical Android build inputs are unchanged. x86_64 JNI `01da54a3d1b24fdbfc4d305697df582a6b8bec2e04985b0c7ce64a6277d0ea82`; arm64 bytes are build-qualified, not runtime-qualified.

| Phase | Samples / replies |
| --- | --- |
| physical-baseline | 48/48 |
| cold-lockdown-start | 96/68 |
| startup-followup | 48/48 |
| connected-steady | 48/48 |
| force-stop | 48/8 |
| stopped-lockdown | 48/0 |

All 230 echo receipts independently matched protocol/family/payloadSHA to the separate UID: 220 burst replies and10 single sockets. Established stopped lockdown blocked all48 sockets with no DNS answers. Manual force-stop/re-enable recovery passed IPv4/IPv6 TCP/UDP and system/raw DNS. Replies before the force-stop transition completes are not described as leakage.

All 80/80 observed post-CONNECTED sockets passed: 32 cold and 48 follow-up,coverage=COLD_AND_FOLLOWUP. This is finite sampling. First sampled sockets after Native NetworkPlan APPLIED: `FAIL_POST_PLAN_BLOCKING`; prior refusals remain recorded. Generic DnsResolver `network=null` still returns ENONET;explicit active VPN and typed A/AAAA null/active pass. Automatic SIGKILL recovery was not executed here; its historical failure remains open.

The ordinary production R8 runtime gate is qualified in this scope alongside previous matching-R8 results. Q29 IN_PROGRESS;32/37(86.5%),five sections open. Original AVD userdata,working service/PID and host firewall/routes/resolver are preserved. The owned runtime root was removed after SHA-qualified backup and inode/path/process/fd/mount checks. [Evidence](../../../../release/certification/evidence/q29-production-runtime-20261012.json). Raw:`audit-debt-20260924/q29-production-runtime-20261012`.NO_PUSH_DEPLOY_RELEASE.


<!-- q29-dns-selection-control-20261012 -->

**12 October:** Q29 generic/null ENONET cause localized on the current API34 image. Authenticated dnsproxyd selection and independent platform TUN owner UID reproduce failure;bypassable control returns A+AAAA. Typed/null and explicit VPN DNS traverse TUN. Product APK/JNI/default kill-switch unchanged;compatibility failure retained,SIGKILL and first-post-APPLIED remain open. [DNS comparison](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-current-sigkill-20261012 -->

Current production R8 SIGKILL recovery:FAIL;whole runtime FAIL. Plain/TUN platform controls ran once,45s window retained. Manual recovery/revoke and dead/force-stopped blocking PASS. Product APK/JNI and byte-identical restart policy unchanged;SIGKILL failure not overwritten. [System scope](AUDIT-Q29-ANDROID-SYSTEM.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-publication-contract-20261012 -->

## 12 October: APPLIED and CONNECTED boundary

Current source and two retained cold-start runs were reviewed without new runtime. `APPLIED` is logged after `setTunFd` and positive `networkPlanResult`: Rust permits Running and packet pumping for that generation. This internal plan step does not confirm Android VPN publication for application sockets.

The service remains CONNECTING until `awaitAndroidVpnPublication`. One Network must provide callback availability, VPN capabilities and LinkProperties matching the plan addresses, interface and MTU (public MTU is unavailable on API28). Facts from different Networks are never combined; onLost discards old facts. Before `announceConnected`, the service checks the live job, stopping, core, generation, identical TUN and CONNECTING state. Timeout stops the generation without CONNECTED; system lockdown remains. Native Running and user-visible Android CONNECTED are distinct states. The 5 October publication fix already implements this order; no new product fix is required.

| Retained run | APPLIED → CONNECTED | Failed probes in that interval | After CONNECTED |
| --- | --- | --- | --- |
| matching-R8/storage admission | 535ms | 8 | 80/80,0 errors |
| ordinary production R8 | 455ms | 8 | 80/80,0 errors |

For all four family/protocol combinations, the first sampled socket after APPLIED started before CONNECTED. Each run has 32 successful post-CONNECTED cold-burst sockets and 48 follow-up sockets. Independent-UID journal start times are compared with publication device_ms, rather than ADB return or socket completion times. All 126 canonical Android inputs from each execution match current source. Previously qualified server receipts retain their original qualification.

`FAIL_POST_PLAN_BLOCKING` remains unchanged in original result/qualification and new evidence: the observed refusal is not relabeled PASS. The helper already separately requires `published_start.status == PASS` and rejects post-CONNECTED errors, absent publication and failed follow-up. Its 6 existing unit methods passed without skips. No helper change or repetition of qualified runtime is needed.

The first-post-APPLIED interpretation question is closed in this scope: early blocking during CONNECTING/lockdown does not establish a regression of an announced connected session. Delivery acceptance uses fresh sockets started after CONNECTED; failures after it remain FAIL. Sampled PASS does not prove the first possible socket, continuous zero loss, all UIDs, no leakage without lockdown, or physical/OEM behavior. The earlier historical CONNECTED publication without callback waiting had a separate defect and is not justified by this conclusion.

Automatic SIGKILL recovery FAIL and generic/null DNS compatibility FAIL remain with platform localization. Q29 stays IN_PROGRESS;32/37(86.5%), five sections remain open. Product, fixtures, APK/JNI and original raw logs are unchanged; no lab execution or large builds/caches. [Evidence](../../../../release/certification/evidence/q29-publication-contract-20261012.json). Raw: `audit-debt-20260924/q29-publication-contract-20261012`. NO_PUSH_DEPLOY_RELEASE.


## October 15: Q29 completed with accepted DNS limitation

The user accepted the known generic/null DnsResolver ENONET on the measured
API34 image and authorized closing Q29 within agreed scope. This does not
fix the error: the original FAIL, independent TUN control and image limits
are retained. Secure VpnService and the system kill switch remain without
a bypass mode.

| Criterion | Result |
| --- | --- |
| Review and dead code | Source/lifetime review, subsequent settings/recovery fixes and current 33 production files reconciled |
| Normal, boundary and negative cases | INI/Keystore/migration/backup/permissions/NetworkPlan/protect/publication and hosted API29/35 have scoped evidence |
| Failures and concurrency | Stale owners/observers, teardown, storage failures and current SIGKILL recovery verified; original FAIL retained |
| Integration and target platform | Bounded API34/R8/ordinary UID, dual stack/NAT64/per-app/DoT/power and ABI/JNI/INI; physical/OEM limits retained |
| Fixes, rechecks and evidence | Published fixes and receipts; the only remaining scoped DNS FAIL explicitly accepted as a limitation |

[Decision and evidence](../../../../release/certification/evidence/q29-dns-final-review-20261015.json),
[DNS reproduction](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md). Historical statuses
and counts above refer to their execution dates. No new VPN/runtime runs were
performed for this decision. The full plan is complete: 37/37 within agreed
scope; D06 and previous platform limits remain.
