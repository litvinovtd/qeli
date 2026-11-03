# Q25-F203 — Android Private DNS, VPN traffic, and Wi-Fi change

<!-- normative-sync: audit-q25-android-network-identity-v1 -->

Date: 1 October 2026. Source `3b54c342`; the same debug APK
0.8.2/code 722 was tested, SHA-256
`9ec9967bc691bd7b575572a85c7fd28d6478728d6395f89b47e5bbb678eb9968`.
The lab used a read-only Android 14/API 34 x86_64 AVD on .11 and a dedicated
REALITY profile on .10 (`:8503`, `e2e0`), leaving the regular `:443` service up.

## Cause of rejected inner packets

After VPN Auth and NetworkPlan application, the server recorded 13 packets
sourced from `10.0.2.16` instead of assigned `10.60.0.2`, and correctly
rejected them with its source guard. Android `ss -tpne` showed separate sockets:

| Process | Local address | Destination |
|---|---|---|
| Qeli, UID 10147 | `10.0.2.16` | `10.66.116.10:8503` (protected carrier) |
| `netd`, UID 1051 | `10.0.2.16` | `1.1.1.1:853` (Private DNS/TLS) |

With the VPN active, `ip route get 1.1.1.1 from 10.0.2.16` chose
`tun0`: the physical-address DNS socket entered the tunnel. Temporarily
setting `private_dns_mode=off` on the disposable AVD closed the `netd`
socket; the rejection count stayed **13** over the next 20 seconds.
Restoring the original value (`null`) opened a new `netd` socket from
`10.60.0.2`; the count remained **13**. This localizes the observation
to an Android system DNS socket. Server anti-spoofing works as intended;
there is no basis to weaken it or rewrite client addresses. The original
socket's creation time was not measured, so its existence before VPN
activation is an inference from its address and controlled reopening,
not a directly timestamped fact.

## App traffic and network change

After Wi-Fi was disabled for eight seconds and re-enabled, Android again
reported `Auth OK` and `Native NetworkPlan 4 APPLIED`; client → server
over VPN: **3/3 ICMP, 0% loss**. The rejected-source count stayed **13**.

A separate `org.chromium.webview_shell` app opened
`http://10.60.0.1:18080/`. An HTTP responder bound only to the test
TUN address logged `10.60.0.2 GET / HTTP/1.1 200`. This verifies
traffic from another app UID, beyond `adb shell`; its favicon request
received an expected 404.

After app `force-stop` and AVD shutdown, both bounded test processes
ended; ports `:8503`/`:18080` and `e2e0` were gone. The regular
`qeli-server.service` remained active on `:443`.

## Status and limits

D12 is complete **within the agreed available scope**: current Android
APK/JNI, 167 JVM tests, 11 instrumentation tests, bidirectional ICMP,
WebView, reconnect, and Wi-Fi toggle are verified; the Private DNS anomaly
has a controlled explanation. Windows VM, Mac/Xcode/iOS, and router runtime
were excluded by user decision — neither PASS nor certification.
A physical Android device, LTE/Doze/always-on, a release APK, and full
audit section 29 remain separate untested scenarios.

[Debt register](../../plans/AUDIT-DEBT.md) ·
[Earlier Android E2E](AUDIT-Q25-NATIVE-REBUILD.md)
