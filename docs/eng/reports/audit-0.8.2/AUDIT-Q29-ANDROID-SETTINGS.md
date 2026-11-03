# Q29 F289: apply LAN settings to an active connection

<!-- normative-sync: q29-android-settings-v1 -->

6 October 2026. FIXED, scoped verification below. The previous source-review packet
identified this independently of F286–F288; its original results and raw seal are retained.
Q29 remains IN_PROGRESS.

Settings Save persisted global `allow_lan` and displayed a reconnect toast, but called the
ordinary `connect()` path, whose connected/connecting guard immediately returned. The
current TUN kept its previous routing policy until a later independent reconnection.

Save now requests explicit reconfiguration. Ordinary Connect retains its existing state
guard; reconfiguration can replace a connected/connecting attempt. Both paths retain strict
saved-INI parsing, notification/VPN consent and the same `VpnConnectRequest` ownership.
Disconnecting and outstanding permission-result states cannot start another request;
`begin` still refuses an owned configuration. A pending initial request uses the updated
preference when the service establishes its TUN after permission completion.
The Activity carries explicit reconfiguration in the retained permission request.
The service validates both commands, queues the replacement configuration, joins the
old native runner/TUN through existing teardown, then starts the replacement in the same
foreground controller. Disconnect/revoke/destroy clear the queue; ordinary Connect retains
the active-generation rejection. A queued settings intent remains redelivery-eligible,
without claiming SIGKILL recovery PASS. Its existing fingerprint includes global LAN policy,
so a changed policy does not reuse the old TUN after Auth. Configurations remain INI.

## Checks and limits

Same final three-case test APK: old product3/1 expected restart FAIL+2 controls PASS,
fixed3 PASS. Initial old2/1FAIL and UI-only fix2/1FAIL retained separately; final tests
add explicit Disconnect cancellation. The initial failure exposed the service guard.

Fresh default production R8 Release TCP PASS: actual UI INI import/OS lockdown,
two Wi-Fi→Cellular→Wi-Fi transitions,12 ordinary-UID IPv4/IPv6 TCP/UDP full payloads
with independent size/SHA/TUN-source checks,288 sampled sockets including transient
handover/force-stop loss,48 post-stop blocked. Protected physical request leaks0 and
capture drop0. Five attempts preserve host service/routes/firewall/resolver and original
AVD userdata SHA/size/mtime; namespace/server cleanup PASS. Successful final runs leave
no Qeli service/TUN. Initial failed runs retain their own abort diagnostics; their skipped
final Android cleanup guards are not relabelled PASS. .10 untouched.

Fresh201 JVM PASS (two new request-mode lifecycle cases), lint0 errors/54 warnings and debug/test/default R8/resource-shrunk
Release builds PASS. No JVM case mirrors the private UI dispatcher. Three new actual
Activity/settings/Keystore/service/native pre-auth tests use a local stall peer:

- Save the LAN checkbox while an actual native Auth attempt is active and the connected
  Activity state is injected; the peer must receive a second native hello. The test
  exercises the real posted AlertDialog Save listener and records the persisted LAN flag.
- Save, then Disconnect; the service must finish and not resurrect the cancelled request.
- Seed a pending notification request, Save the same setting, and prove no service starts,
  the outstanding callback is still owned and returns the original configuration.

Test-only dialog roots/delegate reflection are used. Connected UI and pending permission
phase are injections, not real published CONNECTED or an OS permission-dialog test. The
stall peer publishes no Auth/TUN; no LAN route reachability/physical-network matrix
is claimed here. Because command/teardown dispatch changed,
one fresh default Release TCP handover/stop check is qualified below; UDP/QUIC matrices
are not repeated. Matching Release instrumentation NOT_RUN.
Initial UI-only fix failed the same native-restart test: service rejected Connect while
an old generation was active. This retained diagnostic led to the queued teardown fix.
One new-test compile diagnostic (wrong Kotlin constructor names) is retained, then repaired
by using the shared strict INI parser. Native/server/managed inputs remain hash-identical.
Fifteen helper tests and eight CLI invalid-mode guards cover the settings-ui fixture;
RU/EN docs and generated bindings checked.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-settings-20261006.
Evidence: release/certification/evidence/q29-android-settings-20261006.json.

[Source review](AUDIT-Q29-ANDROID-SOURCE.md) complete. No confirmed product fix remains
from that source-review batch. [SIGKILL automatic recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md)
and [auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) remain open;
no causal JNI defect proven. Other API/OEM/arm64 coverage limits, user skips and D06
unchanged. Q29 IN_PROGRESS; total28/37(75.7%),9 remain.
