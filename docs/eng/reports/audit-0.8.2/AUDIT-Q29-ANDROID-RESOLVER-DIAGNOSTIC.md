# Q29: comparing Android DNS APIs

<!-- normative-sync: q29-android-resolver-diagnostic-v4 -->

**Current October 15 result: Q29 completed within agreed scope. The user accepted the documented generic/null DNS limitation of the measured API34 image. ENONET is not fixed and the original FAIL is retained; secure VPN and the system kill switch remain. Full audit: 37/37.**

October5,2026. Q29 IN_PROGRESS;plan28/37(75.7%). One successful readonly API34 x86_64 Release/TCP run on .11 in private NET/MNT/PID;four preserved failed attempts. .10 untouched.

Independent test APK UID10148,Qeli UID10149. Real INI UI import,Always-on/lockdown,dns=tunnel,dns_servers=198.19.0.53. Product APK/JNI/managed unchanged;test receiver/manifest and Python helpers changed. Matching instrumentation not executed;prior Trace FAIL open.

| Variant | Actual result |
| --- | --- |
| `connectivity` | 8 no-payload connectivity checks |
| `auto` | ExecutionException:android.net.DnsResolver$DnsException: android.system.ErrnoException: resNetworkQuery failed: ENONET (Machine is not on the network) |
| `a` | 198.19.0.1 |
| `aaaa` | 2001:db8:29::1 |
| `auto-active` | 198.19.0.1,2001:db8:29::1 |
| `a-active` | 198.19.0.1 |
| `aaaa-active` | 2001:db8:29::1 |

`auto`:automatic-family DnsResolver.query with implicit network;`a`/`aaaa`:typed overload. `-active` passes ConnectivityManager.getActiveNetwork. Fresh unique name per call,cache-bypass flags,7-second wait,CancellationSignal. Errors retained independently of successful ordinary InetAddress.getAllByName.

`connectivity`:8no-payload Os.socket → optional Network.bindSocket → Os.connect(port0) checks,null/active VPN × 8.8.8.8/2000::/two fixture targets. Error phases and ordinary-UID capabilities/LinkProperties retained. Local socket checks,not delivery proof.

Continuous private-host pcap verifies unique questions/answers,TTL0,exact A198.19.0.1/AAAA2001:db8:29::1,sink receipts. All delivered diagnostic questions require TUN source10.86.0.2. API errors without packets do not demonstrate broad DNS compatibility.

288socket samples across6phases,48post-force-stop without reply/receipt/capture,7ordinary DNS operations,4manual recovery payloads,revoke/cleanupPASS;174echo receipts. Immediate first-socket status:`NOT_SAMPLED_AFTER_PLAN`. Diagnostic opt-in records NOT_SAMPLED_AFTER_PLAN if the short burst ends before APPLIED;ordinary startup gate strict. Missing coverage is not readiness PASS;prior failure open.

Four preserved failed attempts:two missing-wait_until NameErrors (first edit did not match;final import verified before run),one burst ended before APPLIED,one uninitialized-list KeyError. Two local mixed-answer/error and wrong-UID checks PASS. Exact executed helpers,same APK pair and cleanup retained. All5host/service/userdata/namespace restoration unchanged,serverexit0;no product preferences injection.

Primary AOSP android14-release DnsResolver/DnsUtils/Network/NetworkUtils/JNI retained,not proven exact image revision. Reference automatic-family overload checks family sockets before DNS;typed overload skips this. Hidden getDnsNetwork selection not directly observed;null/explicit-active differences do not themselves prove a Qeli routing defect.

Localization: auto/null ENONET without questions/receipts;typed/null A/AAAA and auto/active VPN answer. In AOSP getDnsNetwork obtains app_netid via getdnsnetid;getNetworkForConnectLocked chooses physical/unreachable network for secure VPN. Automatic-family overload explicitly binds family-check sockets there,conflicting with lockdown;DNS context separately selects dns_netid. This reference-based explanation matches runtime;the current image's hidden selected network was not directly measured. No justification to alter Qeli routes or weaken lockdown.

Broad DNS API compatibility,immediate startup publication,split/per-app/Private DNS,long power/flapping,SIGKILL recovery FAIL remain. One AVD does not qualify OEM/arm64/otherAPI versions. USER_SKIPPED/D06 unchanged.

Raw:`audit-debt-20260924/q29-android-resolver-diagnostic-20261005`;evidence:`release/certification/evidence/q29-android-resolver-diagnostic-20261005.json`.


## 12 October: measured DNS network selection and independent TUN control

Six completed DNS comparisons are independently qualified;the remaining control-only run took 189.99s on Android14/API34/x86_64. Production R8 APK/JNI unchanged;126 canonical Android inputs match. Whole cold/startup and native/Gradle/JVM suites were not repeated. The final pair consists of two small standalone platform Java APKs: a sender and minimal TUN/local DNS responder, with no Qeli code or `.so`.

Sender UID 10150,control TUN owner UID 10151,Qeli UID 10148. Every cell observed an unbound process. The same UID directly read dnsproxyd `getdnsnetid 0`:code222 plus big-endian netId,the selection operation used by reference AOSP getDnsNetwork. Selected/active networks,capabilities/LinkProperties,IPv4/IPv6 bind/connect phases,five overload/network variants,unique names and uncached flags were retained.

| Cell | Active netId | Selected app netId | Selected family checks | Generic/null |
| --- | --- | --- | --- | --- |
| physical-baseline | 100 | 100 | 8.8.8.8:True,2000:::True | 198.19.0.1,2001:db8:29::1 |
| qeli-secure-open | 101 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| qeli-secure-lockdown | 102 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-secure-open | 101 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-secure-lockdown | 102 | 100 | 8.8.8.8:False,2000:::False | ENONET |
| control-bypass-open | 104 | 104 | 8.8.8.8:True,2000:::True | 198.19.0.1,2001:db8:29::1 |

NetIds are local to each AVD boot;equal numbers across boots do not identify the same Network object. EPERM also occurs without lockdown. Under lockdown both providers select a network different from the active VPN;both family checks fail,generic/null and generic/selected return ENONET without DNS questions. Typed/null A/AAAA and generic/active return answers. Changing only `allowBypass()` on the same minimal TUN with lockdown disabled selects the VPN network and passes family checks and generic/null A+AAAA. Scoped ENONET is therefore localized to Android network selection/checks before DNS,not Qeli Rust DNS packet processing. The actual ENONET remains recorded:this is cause qualification on one image,not universal DNS API compatibility PASS.

[AOSP DnsResolver](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android14-release/framework/src/android/net/DnsResolver.java) performs family checks in the generic overload;the typed overload skips them. [Netd DNS context](https://android.googlesource.com/platform/system/netd/+/refs/heads/android14-release/server/NetworkController.cpp) separates app_netid from dns_netid;secure and bypassable VPN app-network selection differ. The retained reference branch is not asserted to be the exact AVD revision. The conclusion uses current authenticated dnsproxyd responses and causal secure/bypassable comparison,not reference code alone.

DNS delivery matches unique name/qtype/source in host receipts and local control logs. Qeli typed/null and explicit-active answers traverse TUN10.86.0.2;the control handles those queries locally at TUN10.88.29.2. Physical baseline uses its original host peer. Secure/open generic-selected emits no DNS packets;the pre-DNS refusal remains recorded instead of a tunneled PASS. Additional Qeli socket probes are unqualified:their optional tag was outside the receiver whitelist. The prior complete production transport gate retains separate evidence and was not repeated here.

Production Qeli Java/Kotlin has no DnsResolver or allowBypass calls. Server hostname resolution already uses the explicitly selected network (`selected.getAllByName(config.serverAddress)`);source files were verified unchanged. This failure concerns the ordinary third-party UID generic DNS API.

Private INI explicitly uses `kill_switch=false` to compare OS lockdown off/on. Production defaults and the previously qualified fail-closed profile are unchanged. The initial211.94s attempt is unqualified:LocalSocket timeout before connect,DNS name outside whitelist,and correct Qeli rejection of `kill_switch=true` without lockdown. Raw FAIL remains;its owned root was removed after verified recovery before the corrected attempt. Sender/TUN owner UIDs are separate in the corrected fixture;the local DNS TUN uses a blocking FD.

Three Qeli/baseline DNS cells retain their second195.93s attempt,whose overall optional-socket-tag FAIL is not overwritten. The third run executes only the three remaining controls,without repeating Qeli DNS,UI import or production runtime. The third whole runtime is also FAIL:AndroidRuntime records only `com.android.systemui` crashing with `subscriptionId 1 is not in the list of valid subscriptions`. All six DNS cells completed with verified answers/UID/policy;whole AVD stability/runtime is unqualified. The original FAIL is not overwritten or rerun to obtain a green status. Host/service/firewall/routes/resolver and original userdata preserved;all three owned roots removed after SHA/inode/process/fd/mount guards. UI/SAF INI import without instrumentation/private-prefs injection. ENONET cause investigation is qualified in this scope. Historical automatic SIGKILL recovery FAIL,first-post-APPLIED blocking and full release/platform qualification remain. Q29 IN_PROGRESS;32/37(86.5%). [Evidence](../../../../release/certification/evidence/q29-dns-selection-control-20261012.json). Raw:`audit-debt-20260924/q29-dns-selection-control-r2-20261012` + `q29-dns-selection-control-r3-20261012`;initial attempt:`q29-dns-selection-control-20261012`.NO_PUSH_DEPLOY_RELEASE.


13 October: additional upstream source review confirms getdnsnetid still returns app_netid in the Android16 reference. No newer Android runtime was tested and changing DNS addresses/upgrading OS is not claimed to fix it. No safe transparent third-party workaround found; Q29 stays open, user has not accepted the limitation. [Primary source](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp).

## 14 October: actual allowBypass together with lockdown

One previously unexecuted cell used an independent minimal VpnService and a separate DNS sender UID, without building, installing or starting Qeli. The original six cells were not replayed. On the same Android14/API34/x86_64 `UE1A.230829.036.A1/11228894`, the control Builder's `allowBypass=true` with OS lockdown=1 produced actual `bypassable=false`: active VPN network102, getdnsnetid selected network100. Both selected-network IPv4/IPv6 socket binds returned EPERM; generic/null and generic/selected returned ENONET before DNS questions. Typed/null A/AAAA and generic/active returned the expected answers. Six family-check sockets and five DNS calls were checked. This workaround candidate is rejected; Q29 stays open, no safe transparent workaround for foreign apps was found and the user has not accepted the limitation.

Two initial attempts retain their outcomes: absent physical default network caused NETID_UNSET, then the readiness guard refused before a DNS cell. The log localized the missing carrier to modem ::1 address resolution. The next private NET namespace restored loopback addresses from the previously qualified fixture and checked AI_ADDRCONFIG. The corrected cell completed while preserving original AVD config/userdata. Archives and outcomes were verified; all three owned roots/units were removed and host state preserved. Production allowBypass was not enabled. This qualifies observations on this image, not other Android/OEM versions or the whole release matrix.

[Evidence](../../../../release/certification/evidence/q29-bypass-lockdown-20261014.json). Raw: `audit-debt-20260924/q29-bypass-lockdown-20261014`, `q29-bypass-lockdown-r2-20261014`, `q29-bypass-lockdown-r3-20261014`. NO_PUSH_DEPLOY_RELEASE.

## 15 October: ordinary secure VPN and Android system kill switch retained

The user rejected a separate compatibility mode that permits VPN bypass. The production Android client retains the ordinary secure VpnService without allowBypass. INI/URI, defaults, the settings UI and native libraries are unchanged. A full-tunnel profile with kill_switch=true still requires Android Always-on VPN and “Block connections without VPN”; Qeli verifies this policy and does not switch it itself.

A bypass compatibility mode is no longer an audit obligation; no additional builds or runtime of that cancelled mode are required. This choice does not fix the observed generic/null DnsResolver ENONET or turn it into PASS: the pre-query failure remains a scoped observation on this API34 image. Typed A/AAAA, an explicit VPN network, ordinary DNS cases and bypass blocking retain their separate positive evidence above.

This policy decision supersedes the earlier pending user preference. The platform DNS observation remains explicit; Q29 is not automatically closed. No new Android/DNS runtime was executed here. Full audit:34/37 (91.9%); NO_PUSH_DEPLOY_RELEASE.


## October 15: safe-candidate outcome and practical boundary

On tested Android14/API34 the failure affects the generic overload
`DnsResolver.query(network=null, …)` in a separate caller application. It fails
before issuing DNS: Android selects a network different from the active VPN,
and both family-check socket binds to the selected network return EPERM.
An independent minimal VpnService with local DNS reproduces it without Qeli
code. This is not a claim about other Android versions or OEMs.

On the same image, ordinary DNS, typed/null A/AAAA and generic queries with an
explicit VPN network have positive evidence. Qeli's 33 current production
Java/Kotlin files contain no DnsResolver or allowBypass calls; VPN server names
already resolve through an explicitly selected carrier. The same process-local
API in Qeli cannot change a DNS call inside another application's process.

The retained reviews cover allowFamily/addresses/routes, DNS addresses,
underlying networks, HTTP proxy, process/native resolver binding, physical
default, foreign-UID protect/permissions and TUN DNS interception. No new
actionable candidate preserving secure VPN and the system kill switch was
identified. This is a bounded source/API/runtime review, not proof against
every possible future solution. The user-cancelled bypass is not restored.

On API29+, the affected application's developer can pass the intended VPN
Network explicitly to DnsResolver.query or use the typed A/AAAA overloads;
these variants were qualified for the measured sender. This changes the caller
application. No INI switch in Qeli was identified that repairs its call. The
network parameter and overloads are documented by the
[official DnsResolver API](https://developer.android.com/reference/android/net/DnsResolver).
User-facing steps are in
[ENONET troubleshooting](../../manuals/TROUBLESHOOTING.md#android-enonet-in-one-application).

[Consolidated evidence](../../../../release/certification/evidence/q29-dns-final-review-20261015.json)
binds eight retained review/runtime receipts and the current source snapshot.
A local draft Android report includes the minimal reproduction arrangement
and retained control-source references; it has not been submitted. No new
build, runtime execution or platform change was performed.

The user explicitly chose to accept the limitation and close Q29. Q29 is
complete within agreed scope with this documented API34 fixture limitation.
ENONET is neither fixed nor relabelled PASS; original results, secure VPN
policy and coverage limits are retained. The full audit is 37/37 (100%)
within agreed scope. No new executions were performed.
