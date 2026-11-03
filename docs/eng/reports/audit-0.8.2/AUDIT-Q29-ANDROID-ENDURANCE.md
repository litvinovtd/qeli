# Q29: bounded Doze and repeated carrier switching

<!-- normative-sync: q29-android-endurance-v1 -->

5 October 2026. **Three Release runtime runs PASS**: TCP, UDP and QUIC. Nine power
phases, 18 Wi-Fi ↔ Cellular transitions, 36 wake payload probes and 72 post-transition
payload probes. 1,440 socket burst samples including 144 expected post-force-stop
blocks; 45 DNS operations, 72 A/AAAA/raw answers. Q29 IN_PROGRESS; plan28/37 (75.7%).

## Matrix and result

| Check | On each transport |
|---|---|
| Screen off | 30 seconds, not Awake; service and TUN state retained |
| Forced deep Doze | Two 120-second periods; IDLE/not Awake observed every 15 seconds |
| After three wakes | IPv4/IPv6 × TCP/UDP, system A/AAAA; no fresh Auth/NetworkPlan |
| Wi-Fi ↔ Cellular | Three full cycles, six transitions; changed actual Network handles |
| After each transition | Four full-payload/SHA socket probes and system A/AAAA |
| TCP reconnect | Fresh Auth/NetworkPlan/CONNECTED, same PID/TUN/ifindex/addresses |
| UDP/QUIC roaming | Fresh target-handle commits without fresh Auth/NetworkPlan, retained TUN |
| Stop/lockdown | 48 socket samples and two DNS operations, no reply or PCAP request |
| Recovery/revoke | Manual four-payload/DNS recovery; actual system revoke |

An ordinary UID in separate `com.qeli.test` performs probes without bindSocket/protect
or Instrumentation; `com.qeli` has a different UID. Actual UI imports INI: apps_mode=all,
full tunnel, kill_switch=true; Settings enable Always-on/lockdown. No user battery
exemption. No receiver runs during IDLE: state retention and delivery after wake are
qualified, not continuous traffic during sleep. Total requested power holds:810 seconds.

Three independent PCAPs confirm positive physical calibration for all four socket
kinds before VPN, complete marked payload/SHA through TUN after baseline, no fresh
physical SYN/data/UDP in the protected window, and DNS A/AAAA only through TUN.
TCP payloads are reassembled from segments and sink receipts matched to capture.
The analyzer separates a reused TCP tuple by fresh SYN/sequence space only after
FIN/RST of its previous session; the old analyzer failure is retained.
The previous device started_ms versus host action epoch comparison did not confirm
fresh starts after END for 1 transitions; discrepancy cause unqualified.
That stronger check is not PASS. Separately, PCAP requests cross every handover
on shared host clocks, and four fresh socket probes follow each completed switch.
This is not a first-socket-immediately-after-END guarantee; both timing records retained.
Kernel drops 0. Short burst timeouts are not permanent packet-discard claims:
transitions may delay/drop traffic; delivery is required after each completed switch.

## Harness correction

Returning to a previously used Network could satisfy the roaming wait with a historical
commit. `audit_android_network_handover.py` now requires a higher exact-handle commit
count than before the action; handle12 does not match handle123. Missing log evidence
cannot prove success. Five regression tests cover historical/fresh repeated records,
other/similar handles and truncated logs. The old predicate returns a false positive
on an unchanged historical buffer.

New `--suite endurance` requires Release and --leak-bursts, runs three power phases
and three handover cycles; existing short power/handover suites remain supported.
CLI rejects unsupported combinations before namespace/AVD startup.

## Artifacts and limits

API34 x86_64 readonly AVD .11 in private NET/MNT/PID namespaces. Exact default
production-R8 APK/test APK and matching mapping reused from CONNECTED-gate; app SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`, non-debuggable,
lab signing. The opt-in instrumented ABI variant does not replace this APK.
Product Kotlin/manifest/resources/native and production ProGuard unchanged.
Power/carrier settings, namespace addresses, host/service/firewall/routes and persistent
userdata restored; server exit0. .10 untouched.
Initial UDP attempt FAIL before VPN startup: physical IPv4 Pending connect failure,
no IPv4 requests captured. Root cause unqualified; failed raw retained,
cleanup/host/userdata PASS. Fresh AVD repeat with identical APK/helpers passed the matrix.
Four attempts total; failed attempt excluded from PASS counts.

299 source inputs: README only changed;19 auxiliary inputs:three changed helpers,
one new regression test.14 native/7 managed artifacts unchanged. Fresh11 helper tests,
3 CLI guards and3 runtime/PCAP; prior172 JVM/lint checks reused through matching inputs,
no rebuild required.

Raw: `audit-debt-20260924/q29-android-endurance-20261005`.
Evidence: `release/certification/evidence/q29-android-endurance-20261005.json`.

Bounded Doze/flapping on available AVD covered. Physical CPU suspend, lease renewal
after hours asleep, other APIs/OEMs/arm64 and real LTE unqualified. Trusted strict DoT,
[SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) and
[generic auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md)
remain open. Mac/iOS/router/Windows VM USER_SKIPPED; D06 without BPF preserved.
