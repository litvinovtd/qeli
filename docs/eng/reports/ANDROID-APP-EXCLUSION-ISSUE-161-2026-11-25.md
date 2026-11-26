# Qeli on Android: RKNHardering and app exclusion tests

[Русская версия](../../ru/reports/ANDROID-APP-EXCLUSION-ISSUE-161-2026-11-25.md)

On Android 14, **RKNHardering 2.11.0 could still see the system's `tun0` interface even when excluded from Qeli**. Interface visibility is not evidence that an excluded app's traffic uses the VPN. With distinct public IPv4 addresses at each exit, an ordinary HTTPS request from the excluded app used the direct exit with Android lockdown off and was blocked with lockdown on. The included app used the VPN server's exit in both states. [Qeli issue #161](https://github.com/litvinovtd/qeli/issues/161#issuecomment-7159527650) · [RKNHardering 2.11.0](https://github.com/xtclovver/RKNHardering/releases/tag/v2.11.0)

## Passive detector

The Android 14/API 34 emulator used the unchanged upstream RKNHardering APK, SHA-256 `77d64f300534f9068fb8441fc62d8baa97698d2cf5e7b04e5133f0736399fc59`. It ran with an ordinary application UID. Only Android's active-transport indicator and interface enumeration were enabled. Active probes, scanning, external IP detection and extra permissions were off. On-screen values were compared with the UI XML, lockdown settings and the VPN's UID ranges. [Upstream source](https://github.com/xtclovver/RKNHardering/tree/v2.11.0)

| State | Active-network indicator | Interface enumeration |
| --- | --- | --- |
| Qeli disconnected | `TRANSPORT_VPN: not detected` | No VPN interface |
| App included, lockdown off | `TRANSPORT_VPN: detected` | `VPN interface detected: tun0` |
| App included, lockdown on | `TRANSPORT_VPN: detected` | `VPN interface detected: tun0` |
| App excluded, lockdown off | `TRANSPORT_VPN: not detected` | `VPN interface detected: tun0` |
| App excluded, lockdown on | `No active network found` | `VPN interface detected: tun0` |

The initial UI collector did not scroll to the interface row. The corrected collector captured it and the transport flag. The included repeat retained an overall `FAIL` because Android `SystemUI` failed while the emulator was initializing, before Qeli connected; the recorded observations were independently checked. The excluded run exited `0`. Each of those two runs also made 32 ordinary control-app socket checks: 20 direct, eight via VPN and four blocked.

RKNHardering displayed `Bypass detected` with the app included and `No bypass detected` with it excluded, regardless of lockdown. These are the detector's labels, not a routing verdict. The passive phase did not test public egress, arbitrary interface selection or HyperOS. [Related v2rayNG discussion](https://github.com/2dust/v2rayNG/issues/6465)

## HTTPS egress with a shared public IPv4

RKNHardering's built-in IP Comparison made one ordinary HTTPS request to ipify. A lab relay logged the source address without terminating TLS; the application validated the certificate. The direct and VPN lab exits shared a public IPv4, so the number shown by ipify could not distinguish the routes. The relay's source address did. [IP Comparison implementation](https://github.com/xtclovver/RKNHardering/blob/v2.11.0/app/src/main/java/com/notcvnt/rknhardering/checker/IpComparisonChecker.kt)

| App state | Android lockdown | Result |
| --- | --- | --- |
| Qeli disconnected | Off | Shared public IP, direct source `198.19.0.1` |
| Included | Off or on | Shared public IP, tunnel source `10.86.0.2` |
| Excluded | Off | Shared public IP, direct source `198.19.0.1` |
| Excluded | On | DNS/connection error; no HTTPS connection at the relay |

The first attempt stopped on a direct IPv6 precheck timeout. The included control later exited `0`; the excluded repeat retained an overall `FAIL` for an emulator `SystemUI` failure before connection. Its planned observations were collected and corroborated by the relay and Android's VPN UID ranges. Each tested series also recorded 20 ordinary control requests: 10 direct, eight via VPN and two blocked. The relay reported a `Broken pipe` for one included HTTPS connection after capturing the source and bidirectional bytes; RKNHardering displayed the public IP.

## External Qeli server with two different public IPv4 addresses

The Android 14 emulator used Qeli 0.8.5 over TCP/fake-tls. Before testing, independent measurements confirmed that direct address `A` and VPN exit `B` differed. The HTTPS request now went directly to ipify, without the lab relay.

| State | IP Comparison |
| --- | --- |
| VPN disconnected before and after | `A` |
| Included, lockdown off or on | `B` |
| Excluded, lockdown off | `A` |
| Excluded, lockdown on | DNS/connection error, no IP |

Both completed runs exited `0`. Initial ADB and VPN authorization failures were preserved separately. The temporary VPN test account was removed; the user-file SHA-256 and the live service PID were unchanged.

## Ordinary sockets

The separate socket matrix used the Android 14/API 34 emulator and candidate `74312bf858430ca5318611f49e977c1cd409ea6e`. A lab key signed the APK; 1,095 source entries were byte-identical after signing. The tested APK SHA-256 was `ca0c6d827822d148e2312915f02cd04f71d073e86538f9a09abcab09aac233d8`. Two ordinary app UIDs exercised IPv4 TCP, IPv4 UDP, IPv6 TCP and IPv6 UDP under `apps_mode = exclude`. Source addresses and data hashes were checked at the receiver. [Candidate CI](https://github.com/litvinovtd/qeli/actions/runs/45595561765) · [Test harness](https://github.com/litvinovtd/qeli/blob/74312bf858430ca5318611f49e977c1cd409ea6e/scripts/audit_android_app_policy.py)

| State | Included app | Excluded app |
| --- | --- | --- |
| Before VPN | 4/4 direct | 4/4 direct |
| VPN active, lockdown off | 4/4 via VPN | 4/4 direct |
| VPN active, lockdown on | 4/4 via VPN | 0/4 reached server |
| VPN stopped, lockdown on | 0/4 reached server | 0/4 reached server |
| VPN restored, lockdown on | 4/4 via VPN | 0/4 reached server |
| Lockdown off again | 4/4 via VPN | 4/4 direct |
| Android revoked VPN authorization | 4/4 direct | 4/4 direct |

The successful repeat exited `0`. Of 56 probes, 40 reached the server as expected (16 via VPN and 24 direct); all 16 expected blockers produced a socket error and no packet at the receiver. Dedicated DNS checks were not part of this repeat. Early control-route errors, a DNS precheck timeout and an incomplete final harness check remain in the run history; the Russian report lists each run and the corresponding raw receipt.

## Limits and a possible defensive follow-up

These results do not qualify forced interface selection, exposure of the VPN ingress address to other apps, public IPv6, a complete DNS matrix, Android work profiles, Ozon on HyperOS or the UI Ping feature. The Android app list is enforced by Android; the IP packet read from TUN has no UID attached. A possible additional defense would check TCP/UDP connection ownership on Android API 29+, starting with diagnostic counters. `INVALID_UID` is ambiguous, so a stricter blocking policy needs its own evaluation. The available API does not cover ICMP or API 28; no new filter or fix is claimed in this report. [Android API](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,java.net.InetSocketAddress,java.net.InetSocketAddress)) · [AOSP ConnectivityService](https://android.googlesource.com/platform/packages/modules/Connectivity/+/75cd08977dce9f5a9bb24846743860e1ed8f0b01/service/src/com/android/server/ConnectivityService.java)
