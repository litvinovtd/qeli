# Q29: Android system Always-on, lockdown and process death

<!-- normative-sync: q29-android-system-v8 -->

**5 October 2026. Partial result; Q29 IN_PROGRESS. Plan28/37(75.7%),9 sections remain. The complete system gate is FAIL: automatic redelivery after external SIGKILL is unqualified.**

## Boundaries exercised

One new debug instrumented bootstrap saves the active INI profile through the real encrypted ProfileStore, verifies TCP16KiB/UDP257 over IPv4/IPv6 to off-pool targets, then ends. Android finishes instrumentation by force-stopping its target package: separate am instrument calls cannot leave the VPN running between them. Subsequent actions therefore run in the external driver; UDP probes run in a standalone Java test-APK receiver,UID10148,distinct from Qeli UID10149. It uses ordinary DatagramSocket without Network binding,process binding,protect or root. The receiver is absent from the product APK. Platform Java avoids Kotlin runtime dependencies available from the target only during instrumentation.

The actual Android Settings UI enables Always-on VPN and Block connections without VPN; UI XML is retained. The OS launches the saved kill_switch=true full-tunnel/reconnect profile with pinned identity/client key proof; Auth and native NetworkPlan are observed. Reading secure settings adds evidence; writing those settings does not substitute for enabling the policy.

## Results

| Scenario | Result |
| --- | --- |
| Bootstrap,dual-stack TCP/UDP payload | 1 new instrumented PASS,4 replies |
| Ordinary app probe without VPN | PASS: target reachable over the physical path |
| Actual Always-on+lockdown | PASS:TUN-sourced reply |
| External kill -9 of Qeli | FAIL (issue OPEN):no new process/NetworkPlan within45s |
| Probe after SIGKILL | PASS:socket error,0 sink deliveries |
| User force-stop | PASS:no TUN,probe blocked,0 deliveries |
| Explicit relaunch/system policy toggles | PASS:new Auth/NetworkPlan,foreground,TUN reply |
| Disable policy/Forget VPN in Settings | PASS:service/TUN absent,connection_desired=false,ACTIVATE_VPN=ignore |

A physically reachable baseline distinguishes blocking from an unreachable endpoint. Tagged UDP payloads have independent sink SHA256 receipts. Negative probes attempt to send; they have no source-readiness preflight. These negative cases cover IPv4 UDP to one off-pool target,not a complete TCP/IPv6 leak matrix or physical Internet.

## Open SIGKILL result

Before kill,dumpsys reports isForeground=true,startRequested=true,startCommandResult=3 and a delivered android.net.VpnService intent. Exit info records SIGNALED/status9,rather than force-stop. TUN disappearance triggers Vpn.interfaceRemoved unbinding the dead service and DeadObjectException before ActivityManager processes app death. A stale app=null ServiceRecord remains without a scheduled restart. Several independent readonly runs reproduce the failure. Tested traffic remains blocked under lockdown;manual recovery works.

The [START_REDELIVER_INTENT contract](https://developer.android.com/reference/android/app/Service#START_REDELIVER_INTENT) provides redelivery after process death. [Android14 r1 ActiveServices](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-14.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java) calls serviceProcessGoneLocked on an unbind exception;killServicesLocked walks running-service records to schedule restart. This supports a framework bookkeeping race hypothesis;this source is **not established as the exact emulator image source**. No causal product defect is proven. REDELIVER was not arbitrarily replaced by STICKY;no resurrection watchdog was added. The independent minimal VpnService control is completed below;another system process-death mechanism and a different image remain separate scenarios. The failure remains open,not PASS/USER_SKIPPED.

## Independent platform control

The separate com.qeli.audit.restartcontrol APK contains two Java classes and Android APIs only. A receiver saves the mode;a foreground VpnService returns START_REDELIVER_INTENT and optionally creates a TUN. No JNI,Rust,transport,parsers,Qeli profiles,timers or watchdog. Real Always-on Settings starts both services;external root kill -9 terminates the process. The control is stopped,policy disabled and VPN consent revoked before Qeli in the same disposable AVD.

| Control | Observation |
| --- | --- |
| Foreground VpnService without TUN,Always-on,lockdown=0 | Final control:restart after17.40s;new PID,flags=1,same intent,result=3 |
| Same service with TUN,Always-on,lockdown=0 | No new PID within45.19s;TUN absent |
| Same service with TUN,Always-on,lockdown=1 | No new PID within45.08s;TUN absent |

The analogous failure reproduces without product code. This separates the observed platform VPN lifecycle issue from a causal JNI/transport defect in Qeli. The final comparison changes only TUN creation at the same lockdown=0:the failure appears with a TUN. Lockdown is not necessary for reproduction on this image. System unbind DeadObjectException before process-death handling and stale app=null match the Qeli trace. The exact framework commit and universality across Android14 devices are not established. Product automatic recovery on this fixture remains FAIL;safety blocking and manual recovery retain separate results. No START_* change or watchdog was added.

Fingerprint:Android/sdk_phone64_x86_64/emu64x:14/UE1A.230829.036.A1/11228894:userdebug/test-keys. javac --release8 + aapt2/D8/zipalign/apksigner build the control;source/APK SHA256 and commands are retained. The first attempt stopped before the control cells:a SystemUI ANR appeared after tapping the gear. The second attempt completed both control cells and product SIGKILL/blocking,but a battery exemption dialog obscured manual recovery;the third uiautomator returned without XML before measurements. The shared UI helper waits for the intended provider,handles Wait after navigation,selects DENY for the battery exemption and retains a separate fresh XML with bounded dump retry. The fourth attempt completed all three control cells and repeated product blocking,but navigation to manual recovery mistakenly selected Qeli own Settings. UI selection is now restricted to the system com.android.settings package;DENY explicitly reopens system Settings. The final harness verification runs only product --suite system in a separate fresh AVD,without repeating completed controls. The earlier two-mode control remains separate:16.22s/45.06s;it still changed TUN and lockdown together.

Raw:C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-restart-control-20261005. Reproduce with scripts/build_android_restart_control.py,then scripts/audit_android_data_plane_lab.py --suite system --restart-control using SHA-qualified APK/CLI. The remote runner also requires android_lab_ui.py,audit_android_restart_control.py,audit_udp_handshake_contracts.py. Control observations are diagnostic and do not replace the product acceptance gate.

## Harness and reproducibility

Only tests/driver changed:singular instrumentation output;bounded timeout instead of nc -w misuse;real separate UID instead of shell/su sockets;platform Java for standalone probes;instrumentation force-stop separation;bounded Wait for SystemUI ANR;already-open management-screen detection;FORGET text selection instead of button1,which is DISMISS here. Failed attempts remain separate and are not called core regressions.

Android14/API34 x86_64,readonly AVD requested768MiB/1core (launch argument, not measured guest RAM;12 October correction below) and Linux Qeli in fresh NET/MNT/PID namespaces on.11,no external uplink. Product APK9af9789d…/JNI are unchanged;no Rust/product fix.290 previous source inputs,14 native hashes and7 managed DLLs match;293 current inputs,fresh test-APK build only. Prior167JVM/28Android/1248.NET/Release-R8-lint and3+6+7 integration stages retain their original scopes,not a fresh combined45Android run. Every attempt checks host network/qeli.service and userdata SHA/mtime/size;.10 untouched;arm64 not executed.

Raw:C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-system-20261005. Evidence:release/certification/evidence/q29-android-system-20261005.json. Driver --suite system. Previous [off-pool/DNS and data plane](AUDIT-Q29-ANDROID-DATA.md) remain distinct qualifications. Q29 stays open:SIGKILL recovery,Doze,roam/protect,Release runtime,olderAPI,physical/OEM scenarios. Early CONNECTED/source readiness stays open in the earlier report.


Previous qualified run(r13)213.97s,bootstrap2.421s. The complete gate correctly returned FAIL solely for SIGKILL recovery;all other listed criteria completed. Seven receipts:4 bootstrap,1 physical baseline,1 protected,1 manual recovery;two blocked probes had no delivery. Final service/TUN absent,AndroidRuntime without FATAL. All13 attempts preserve host/service/userdata,serverexit0,namespace addresses restored. Consent is proven revoked after named FORGET and waiting for ACTIVATE_VPN=ignore;onRevoke was observed during the disable-policy/Forget sequence,not an artificial method call.


New final product-only run(r5):219.07s,bootstrap2.668s,1 fresh PASS and7 receipts;no harness error. Complete gate FAIL solely for SIGKILL recovery. Both negative probes blocked,manual recovery and Settings revoke PASS;final service/TUN absent,AndroidRuntime without FATAL. Three-mode control(r4) completed in a separate preceding AVD;its product portion reached SIGKILL/blocking,but manual recovery there remained unqualified due to UI. All5 new attempts preserve host/service/userdata,serverexit0,namespace addresses restored. Product/test APKs,14 native and7managed unchanged;296 source inputs and6 auxiliary verified. Evidence:release/certification/evidence/q29-android-restart-control-20261005.json. Old results are not aggregated into a fresh suite.


12 October:768MiB above was a launch request, not measured RAM. Control/r4 log reports an increase to2560MB. [Fix and current scoped gate](AUDIT-Q29-ANDROID-CURRENT-VPN.md);SIGKILL FAIL retained.


<!-- q29-storage-startup-20261012 -->

**12 October:** A new current matching-R8 cold UI/SAF run with independent UID passed after bounded storage admission. All80 post-CONNECTED sockets passed; established stopped lockdown48/0,manual recovery/system+raw DNS PASS.241 receipts correlated to UID journal. Generic DNS/null ENONET and historical SIGKILL FAIL remain open;ordinary production APK unqualified. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md). Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-production-runtime-20261012 -->

**12 October:** Ordinary production R8 APK qualified via UI/SAF and independent UID without instrumentation: 80 post-CONNECTED sockets PASS,230 correlated receipts,stopped lockdown48/0 and manual recovery/DNS PASS. APK payload unchanged by lab signing;real release signing and physical platforms unqualified. DNS/null ENONET,first-post-APPLIED blocking and historical SIGKILL retained. [Current scope](AUDIT-Q29-ANDROID-CURRENT-VPN.md).Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-dns-selection-control-20261012 -->

**12 October:** Q29 generic/null ENONET cause localized on the current API34 image. Authenticated dnsproxyd selection and independent platform TUN owner UID reproduce failure;bypassable control returns A+AAAA. Typed/null and explicit VPN DNS traverse TUN. Product APK/JNI/default kill-switch unchanged;compatibility failure retained,SIGKILL and first-post-APPLIED remain open. [DNS comparison](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


## 12 October: current production SIGKILL and platform TUN control

One current ordinary-R8 run took 401.05s on readonly Android14/API34 x86_64. Whole runtime `FAIL`,automatic authenticated recovery `FAIL`. Actual UI/SAF imported INI without instrumentation/private-prefs injection;126 canonical Android inputs unchanged. CLI/APK/JNI were not rebuilt. Only the standalone platform Java restart control APK was built;plain and TUN+lockdown ran,prior TUN without lockdown was not repeated.

| Control | Result | Observation,s | PID |
| --- | --- | --- | --- |
| plain | RESTART_OBSERVED | 18.95 | 1889 → 2329 |
| vpn | NO_RESTART_OBSERVED | 45.49 | 2494 → none |

The current plain foreground control restarts;TUN control and Qeli reproduce unbind/DeadObjectException before process death and no restart scheduling during45s. Failure is localized to Android framework TUN teardown,not an exact framework revision or an assertion that restart can never occur.

Before SIGKILL services have isForeground=true,startRequested=true,startCommandResult=3. Exit-info confirms SIGNALED/status9;the live PID is captured before kill. System logs check exact component/PID unbind exception,DeadObjectException,process death and restart scheduling. START_REDELIVER/desired policy is byte-identical to historical source;actual redelivery requires new PID/READY flags1. START_STICKY was not tested as a fix. [AOSP Android14 reference](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-14.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java) removes the service/process association after an unbind exception before the subsequent service traversal. This explains reference code;it does not identify the exact AVD build.

A separate ordinary UID confirmed dead/force-stopped blocking:0 server receipts. Manual recovery/revoke PASS;these do not qualify automatic recovery. Guest1536MiB/lowram,actual MemTotal=1505648KiB;prior2560MB attempts retain their results. Whole runtime failure/error remain in original result. Broad platform-health conclusions are limited to one AVD.

Local manifest read failed before runtime dispatch. One owned staging root was resumed only after all existing payload SHA values matched;metadata completed without reuploading APK/core. Service/PID,host firewall/routes/resolver and original userdata preserved. Owned root removed after verified recovery and inode/process/fd/mount guards. [Evidence](../../../../release/certification/evidence/q29-current-sigkill-20261012.json). Raw:`audit-debt-20260924/q29-current-sigkill-20261012`. Q29 IN_PROGRESS;32/37(86.5%).NO_PUSH_DEPLOY_RELEASE.


<!-- q29-publication-contract-20261012 -->

APPLIED/CONNECTED boundary reviewed: first sampled sockets after APPLIED started before CONNECTED;8 interval refusals and80/80 post-CONNECTED PASS in each retained run. Interpretation question closed, original FAIL_POST_PLAN_BLOCKING retained. The helper already gates post-CONNECTED;6 methods PASS. No new runtime/builds. SIGKILL/DNS compatibility FAIL and Q29 IN_PROGRESS remain. [Current contract](AUDIT-Q29-ANDROID-CURRENT-VPN.md).


Qeli SIGKILL recovery qualified on the ordinary production R8 APK; disconnect/revoke prevent service resurrection in 30-second windows. DNS/null remains open. [Q29 recovery](AUDIT-Q29-ANDROID-RECOVERY.md).
