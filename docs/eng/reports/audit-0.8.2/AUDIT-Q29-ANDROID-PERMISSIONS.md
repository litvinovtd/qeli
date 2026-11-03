# Q29: Android connection permission ownership

<!-- normative-sync: q29-android-permission-flow-v1 -->

F280 fixes three Activity permission-flow defects: granting a delayed permission
could start VPN after cancellation, connect with an edited/switched profile, or
lose the request after Activity recreation. Q29 remains IN_PROGRESS; overall
28/37 sections (75.7%). This report qualifies this fix, not the full Android gate.

## Behavior and fix

MainActivity retains the originally parsed and validated VpnConfig in a ViewModel.
Notification and VPN permission callbacks must belong to the pending stage before
starting the service. Disconnect cancels the configuration; an outstanding callback
is drained before another request can use its launcher. Denial and failed launches
release the request. The service consumes the configuration once.

Configuration changes retain this in-memory request. It is not saved in Bundle or
preferences: process death drops it and a new explicit connect is required. This
does not change existing service recovery or Android always-on behavior.

## Verification

The same final test APK and valid encrypted INI profile archive were used with the
old and fixed debug app on the isolated .11 API34 x86_64 AVD. Three tests exercise
real ActivityScenario, ActivityResultRegistry callbacks, service and JNI. The pending
notification-permission stage and result are injected; OS dialog presentation and
rotation while a system dialog is open are not qualified by this adapter suite.

| Scenario | Old app | Fixed app |
|---|---|---|
| Cancel, await stopped service, then deliver late grant | FAIL: cancelled VPN starts | PASS |
| Edit profile during permission wait | FAIL: replacement peer receives ClientHello | PASS: original peer |
| Recreate Activity with pending request | FAIL: request lost | PASS |

Fresh JVM: 179 PASS, including seven ownership tests; lint: zero errors, 55 warnings.
Default production R8 Release was rebuilt and signed with the lab key. Actual INI
import and Android lockdown bootstrap precede a real Activity disconnect/connect
button cycle. The disconnected ordinary UID probe is blocked; four full IPv4/IPv6
TCP/UDP replies after reconnect pass byte-count/SHA and TUN-source checks.

The same TCP run also covers strict DoT untrusted CA, trusted CA, mismatched SAN and
recovery; 16 full payload probes, 192 burst samples (48 post-stop blocked), 13 DNS
operations/answers including four authenticated A/AAAA answers. Independent capture:
zero new physical requests in the qualified protected window, zero kernel drops.
The UI-disconnected check is one IPv4 UDP probe, not a full boundary leak matrix.
No universal immediate first-packet guarantee is claimed. Four helper tests and
two invalid-CLI guards pass before mutation.

The Release app is nondebuggable. The unchanged standalone framework Java probe APK
from the prior DoT packet is reused, with the same lab certificate; matching Release
instrumentation is NOT RUN. Product JNI/server/managed artifacts are unchanged;
prior all-transport qualifications are retained, not freshly rerun on this new APK.

## Evidence and limits

Four preliminary attempts remain unqualified: target-permission revocation during
instrumentation crashed that attempt; a modal dialog delayed the injected result;
three subsequent preliminary fixtures used the wrong archive field. Final A/B uses
`cfg`, matching ProfileStore. These fixture failures do not become product regressions
or PASS totals. All seven attempts restore host/service, settings and persistent AVD
userdata; Release also restores temporary CA stores. .10 is untouched.

Raw: `audit-debt-20260924/q29-android-permission-flow-20261005`.
Evidence: `release/certification/evidence/q29-android-permission-flow-20261005.json`.
302 source inputs, 22 auxiliary inputs; three new source files, MainActivity/README
and one lab helper changed. Native/server/managed provenance remains pinned.

[Prior SIGKILL redelivery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md),
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), other Android
API/OEM/arm64 runtime coverage and remaining lifecycle criteria stay open.
