# Q29: per-app UID and Private DNS

<!-- normative-sync: q29-android-app-policy-v1 -->

5 October 2026. **Two Release runtime runs PASS**: include/TCP and exclude/QUIC,
API34 x86_64 readonly AVD on .11 in separate NET/MNT/PID namespaces. 112 socket
probes: 80 replies and 32 expected blocks. 52 DNS operations, 48 A/AAAA/raw answers.
Q29 remains IN_PROGRESS; overall plan 28/37 (75.7%).

Earlier runs covered the selected UID, while the excluded Settings package had no
network probe. The new framework-only `com.qeli.auditprobe` package is built from
the existing `SystemNetworkProbeReceiver.java`: separate UID, no duplicate sender
implementation, JNI, Instrumentation, bindSocket or protect. The selected sender is
`com.qeli.test`. Package manager confirms three distinct app/sender UIDs.

| State | Selected UID | Unselected/excluded UID |
|---|---|---|
| Before VPN | Physical path | Physical path |
| VPN, lockdown disabled | TUN | Physical path |
| VPN, lockdown enabled | TUN | Blocked |
| Force-stop, lockdown enabled | Blocked | Blocked |
| Manual recovery, lockdown enabled | TUN | Blocked |
| Lockdown disabled again | TUN | Physical path |
| System revoke | Physical path | Physical path |

Each state exercises IPv4/IPv6 TCP/UDP and raw DNS. Full reply bytes/SHA are
matched with independent sinks; source addresses confirm TUN/physical routing.
INI is imported through the actual UI. `kill_switch=false` permits testing both
OS lockdown settings; these runs do not replace earlier `kill_switch=true` gates.

Private DNS `off`/`opportunistic` are tested with both lockdown settings:
system `InetAddress` and raw UDP return answers to the selected UID through TUN.
With `hostname=q29-unreachable.invalid`, VPN LinkProperties show
`UsePrivateDns:true`, the provider name and `PrivateDnsBroken`; four system lookups
fail while raw DNS still works through TUN. This is a negative test of an
unresolvable provider name: **successful DoT with a trusted certificate was not
executed**. Raw DNS deliberately does not use system Private DNS.

Independent analysis of both PCAPs: 52 unique names, 48 plaintext query packets,
no selected-UID physical queries or clear fallback after expected blocking/strict
failure; kernel drops 0. Excluded-UID blocking under lockdown is expected OS policy.
Private DNS settings, namespace addresses, host/service/firewall/routes and
persistent userdata restored; server exit 0. .10 untouched. Manual recovery is
not claimed as automatic recovery.

The earlier production-R8 pair from CONNECTED-gate is reused: app SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`,
non-debuggable, lab signed; the instrumented ABI variant from runner does not
replace this APK. Product Kotlin/manifest/resources/native and production ProGuard
rules unchanged. Fresh checks: six helper tests, three CLI guards, two runtime runs
and PCAPs. Earlier JVM/lint/native/managed gates are reused for unchanged inputs.
The initial CLI rejection before lab startup is retained, not a runtime FAIL.

Available-AVD active per-app/lockdown transitions are covered. Trusted strict DoT,
long power/flapping, remaining lifecycle, SIGKILL recovery FAIL and auto/null
DnsResolver ENONET remain open. API28/29, arm64/OEM not executed; USER_SKIPPED/D06
unchanged. [Configuration](../../manuals/CONFIG.md) and
[troubleshooting](../../manuals/TROUBLESHOOTING.md) updated. Android recommends that
the Private DNS provider be reachable both outside and inside the VPN:
[DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager).

Evidence: `release/certification/evidence/q29-android-app-policy-20261005.json`.
Raw: `audit-debt-20260924/q29-android-app-policy-20261005` (outside Git), with APKs,
mappings, full logs, captures, source proof and the initial preparation failure.
