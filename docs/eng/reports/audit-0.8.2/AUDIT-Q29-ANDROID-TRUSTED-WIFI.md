# Q29: trusted Wi-Fi service runtime

<!-- normative-sync: q29-android-trusted-wifi-v1 -->

Three new instrumented scenarios pass on the isolated .11 API34 x86_64 readonly AVD.
This qualifies bounded trusted-network controller behavior. Product code is unchanged;
Q29 stays IN_PROGRESS, overall 28/37 sections (75.7%).

## What ran

The test reads the real emulator Wi-Fi SSID after opening MainActivity. Location and
nearby-Wi-Fi permissions are granted externally before instrumentation; trusted SSIDs
are set through the same device-local preferences used by the UI. Service actions are
actual framework starts. No reflected service, fake Network callback or fake transport.
These are adapter tests, not automation of the settings editor/permission prompts.

- Cold start on a trusted SSID: foreground WAITING with no TUN, desired connection
  retained. The Activity moves to CREATED; waiting remains after 1.2 seconds.
  Actual `svc wifi disable` switches to the available emulator Cellular carrier;
  native authentication and a new dual-stack TUN complete. Re-enabling Wi-Fi pauses
  again and joins teardown. Disabling trusted-network policy restores the tunnel.
- Enable trusted policy while an authenticated tunnel is live: pause closes TUN
  and clears live IP; policy disable arms the real 250ms resume job. A framework
  disconnect leaves no service/TUN or desired intent after an additional 1.2 seconds.
  A fresh explicit start works.
- Trusted SSID with `kill_switch=true` and no OS lockdown: connection is rejected
  with ERROR and no TUN, rather than entering trusted waiting.

Four restored/active stages each verify complete IPv4/IPv6 TCP16KiB and UDP257 replies:
16 payload probes, byte-for-byte assertions and 16 independent server receipts with
matching SHA and assigned TUN sources. Test sockets explicitly use the active VPN
Network; this is not a new ordinary-UID default-socket or leak matrix.

## Qualification and harness failures

The final complete runner passes all three tests and cleanup. The previous run also
passed these same three tests, but its runner incorrectly demanded UDP-transport
receipts from a TCP-only suite; it remains an overall FAIL. An earlier fixture failed
before starting Android because sink addresses were not installed. Both attempts
are preserved. A duplicate-root preparation was rejected before another runtime.

The helper now accepts `--suite trusted-wifi --variant debug --transport tcp`, requires
pinned fixed APKs/manifest and private NET/MNT/PID namespaces, installs off-pool sinks,
and qualifies the correct TCP-only matrix. Four helper tests and four invalid-CLI
checks pass. All three runtime attempts preserve host/service/firewall/routes and
persistent userdata SHA/mtime/size; server exit and namespace address restoration pass.
The final Android service/TUN is absent, AndroidRuntime contains no FATAL EXCEPTION. The global dumpsys header retains a SystemUI Keyguard Last ANR; the filtered live Qeli service list is empty.
.10 is untouched.

Only a test APK was rebuilt. Product debug APK and both JNI ABI hashes exactly match
F280; native/server/managed inputs are unchanged. The prior 179 JVM/lint/default-R8
qualifications retain their scope; these are not fresh JVM or Release runtime runs.
303 source inputs (README changed, one test added), 22 auxiliary inputs (one helper
changed), 14 native and seven managed artifacts pinned.

Raw: `audit-debt-20260924/q29-android-trusted-wifi-20261006`.
Evidence: `release/certification/evidence/q29-android-trusted-wifi-20261006.json`.

## Remaining boundaries

Background waiting here is 1.2 seconds, not physical suspend or a long OEM session.
Permissions were granted before instrumentation; actual revocation, redacted SSID,
observer-registration failures, disconnect during an unfinished native pause, and
trusted-SSID handover with active OS lockdown are not qualified by this suite.
SSID exposure is permission-dependent: [Android WifiInfo contract](https://developer.android.com/reference/android/net/wifi/WifiInfo).
An SSID name alone does not authenticate an access point; trusted pause remains an
explicit user opt-in without either lockdown form.

[Prior SIGKILL FAIL](AUDIT-Q29-ANDROID-SYSTEM.md),
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), remaining
lifecycle/protect races and other API/OEM/arm64 runtime coverage stay open.
