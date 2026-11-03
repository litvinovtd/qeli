# Q29 F281: trusted Wi-Fi with active lockdown

<!-- normative-sync: q29-android-trusted-lockdown-v1 -->

A trusted SSID must suppress carrier handover only when a VPN pause is allowed.
`kill_switch` or Android's system lockdown forbids that pause. F281 removes the
unconditional trusted-SSID shortcuts from available/capabilities/lost/late-replacement
callbacks, using the current connection configuration and actual system lockdown state.
The ordinary trusted pause policy is unchanged.

## Finding and verification

The old callbacks classified a carrier as trusted and skipped roaming, while the pause
controller independently refused to pause. This could leave the transport on its
previous carrier after a return to trusted Wi-Fi. The fix shares the pause-eligibility
predicate across all four callbacks. The old production Release reproduces the missed proactive reconnect on
Cellular в†’ trusted Wi-Fi: the outward transition passes, the return has no new carrier
reconnect request, then transport error `rc=-10` causes a passive retry after the transport fails. The unchanged handover gate fails on the missing proactive-reconnect marker;
this is delayed recovery, not an assertion that the VPN never recovers. Three preliminary
runs fail in the harness before this check (external-storage import, SSID editor selector,
foreground-type parser) and are not product reproductions.

Three new JVM tests cover both lockdown forms,
the available and replacement decisions, and unknown/non-Wi-Fi networks.

Runtime results and scope are recorded in the paired evidence packet:
`release/certification/evidence/q29-android-trusted-lockdown-20261006.json`.
The runner imports an INI through the actual production Release file picker, enables
Always-on and lockdown through Android Settings, and enters the observed SSID in Qeli's
settings editor, then saves and reads it back. Permissions are externally granted;
permission-dialog automation is not part of this check. The active service location
foreground type is observed. No preference injection or fake carrier callback is used.

`audit_android_data_plane_lab.py --suite handover --variant release --apps-mode all
--trusted-lockdown-handover --leak-bursts --transport tcp` requires pinned APK/manifest
and the qualified server in private NET/MNT/PID namespaces and a disposable readonly AVD.
UDP/QUIC use the same opt-in. Incompatible variants/suites/per-app combinations fail
before filesystem or lab mutation. The standalone probe runs as an independent UID;
matching Release instrumentation is NOT RUN. Production R8 rules are unchanged.

Fresh JVM, lint, default-R8 build, packet analysis and runtime outcomes must be read
with their explicit source/APK hashes; a harness failure is not a product reproduction.
The packet preserves preliminary fixture failures and their cleanup evidence.

## Qualified results on 6 October

| Fresh check | Result |
|---|---|
| JVM / lint / default production R8 | 182 PASS (3 new); 0 lint errors, 55 warnings; Release/debug build PASS |
| Release TCP / UDP / QUIC masking | 3 complete runs PASS; 6 actual Wi-Fi ↔ Cellular transitions |
| Independent ordinary-UID full payload | 36 PASS: IPv4/IPv6 TCP16KiB and UDP257 after transitions and manual recovery; reply bytes/SHA, sink receipts and reassembled TUN pcap agree |
| Release transition/stop bursts | 864 samples; 144 post-stop samples blocked; protected physical requests 0, capture drops 0 |
| Normal trusted pause on the fresh debug APK | 3 instrumented tests PASS; 16 full payloads with explicit VPN-bound sockets and independent sink SHA/TUN-source receipts |
| Helpers / CLI / documentation / bindings | 15 helper tests, 4 pre-mutation CLI rejection checks, docs and bindings PASS |

TCP performs fresh Auth/NetworkPlan on both transitions while retaining PID/TUN/addresses.
UDP/QUIC commit the new actual carrier and retain authentication/session/TUN; all commits
in each transition target that carrier. The source/reply SHA is reconstructed independently
from the tagged payload for all 36 Release probes. Four physical socket kinds are positively
calibrated in capture/receipts before lockdown. Short baseline and transition timeouts are
preserved: outward burst replies are TCP36/48, UDP36/48, QUIC40/48; return48/48 each.
The result does not claim lossless transitions or universal first-packet readiness.

The debug counterpart repeats cold trusted waiting, real Wi-Fi/Cellular pause/resume,
live-tunnel pause, cancellation of the pending resume, explicit restart and kill-switch
refusal without OS lockdown. It retains the adapter boundary of the prior suite: SSID
preferences injected locally, permissions granted externally, explicit VPN-bound sockets.

All eight runtime attempts (three preliminary harness failures, the old-product reproduction,
three fixed Release runs and debug regression) pass host/service/firewall/routes, persistent
userdata hash/mtime/size and server/address cleanup checks. A later SFTP disconnect before
QUIC dispatch is preserved separately: no runtime began in that partial upload directory.
SSH recovered without a reboot; host state matched, and QUIC ran in a fresh directory.
No .10 changes. No matching Release instrumentation or new native/server/managed build.
303 source inputs (4 changed), 23 auxiliary inputs (1 changed, 1 added), 5 regression inputs,
14 native rows, 7 managed artifacts and all 6 APK files are pinned. The reused standalone
Release probe and debug test APK are distinguished from the freshly built product APKs.

## Boundaries

The bounded API34 x86_64 AVD matrix cannot establish physical/OEM/other-API/arm64 behavior
or a long session. The normal trusted-pause adapter uses explicit VPN-bound sockets and
local settings injection; it does not replace the Release independent-UID checks.
[Prior SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md),
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), remaining
lifecycle/protect races and other Android platform coverage remain open.
Q29 remains IN_PROGRESS; overall 28/37 sections (75.7%), nine remain.

Raw packet: `audit-debt-20260924/q29-android-trusted-lockdown-20261006`.
