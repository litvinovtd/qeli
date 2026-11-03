# Q29: VPN publication during cold startup

<!-- normative-sync: q29-android-startup-state-v1 -->

October5,2026. Q29 IN_PROGRESS;plan28/37(75.7%). One successful readonly API34 x86_64 Release/TCP private NET/MNT/PID run on .11;one preserved UI FAIL attempt. .10 untouched.

Ordinary independent UID10148,Qeli UID10149. Real INI UI import,Always-on/lockdown,tunnel DNS. Product Release APK/JNI/managed unchanged;one test Java receiver changed,newmatchedR8testAPK. No Kotlin/core change,lockdown weakening or traffic socket bind/protect.

336socket samples:96cold,48each across5other phases. Immediately before each cold socket,record active Network,VPN transport,interface,IPv4/IPv6 presence and metadata-read time bounds. Default NetworkCallback registered before TURN ON. This is publication observation,not atomic kernel-policy state. APPLIED device log measured;exact Activity CONNECTED receive not measured. Unchanged QeliService calls announceConnected after APPLIED following TUN fd/ACK.

| First sample after APPLIED | Delay,ms | Payload success | Network/VPN/interface | Detail |
| --- | --- | --- | --- | --- |
| ipv4/tcp | 9.0 | False | null/False/null | error=ConnectException:failed to connect to /198.19.0.1 (port 26000) from /:: (port 0) after 250ms: connect failed: EACCES (Permission denied) |
| ipv4/udp | 16.0 | False | null/False/null | error=SocketException:Pending connect failure |
| ipv6/tcp | 19.0 | False | null/False/null | error=ConnectException:failed to connect to /2001:db8:29::1 (port 26000) from /:: (port 0) after 250ms: connect failed: EACCES (Permission denied) |
| ipv6/udp | 7.0 | False | null/False/null | error=SocketException:Pending connect failure |

Localization:first4sockets fail7–19ms afterAPPLIED with null activeNetwork;4failures311–321ms have VPN/tun0/dual snapshots but precede VPN AVAILABLE. Callback419ms afterAPPLIED;44/44subsequent samples pass,firstsuccessfulsample481ms afterAPPLIED. getActiveNetwork/LinkProperties alone is not a readiness barrier. Oneimage/run observation,not universal callback guarantee or exact CONNECTED receive time. Product status-publication fix not applied:owner-UID observer needs per-app/reusedTUN verification.

56post-plan samples,48with activeVPN/tun0/IPv4/IPv6 snapshot,4payload errors in that group. Immediate status:`FAIL_POST_PLAN_BLOCKING`. NOT_SAMPLED is not PASS;later success does not rewrite historical FAIL.

Device-clock callback events:

- `BURST_NETWORK run=2 uid=10148 event=AVAILABLE network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_false network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=LINKS_wlan0 network=100 device_ms=1791219354498`
- `BURST_NETWORK run=2 uid=10148 event=AVAILABLE network=102 device_ms=1791219357266`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_true network=102 device_ms=1791219357267`
- `BURST_NETWORK run=2 uid=10148 event=LINKS_tun0 network=102 device_ms=1791219357267`
- `BURST_NETWORK run=2 uid=10148 event=CAPABILITIES_vpn_true network=102 device_ms=1791219357587`

All nonce/request/replySHA verified by receiver,sink,continuous private-host pcap and TCP reassembly. Fresh delivered post-plan taggedrequests through TUN;pre-lockdown physical calibration retained. No newphysicalSYN/data/UDP in protectedsteady/stopwindow.48poststop samples and2DNSoperations without reply/receipt/capture;7DNSoperations/7answeredquestions,4manualrecoverypayloads,revoke/cleanupPASS. 224echo receipts,213.91s.

Cold-only24samplesperkind uses background broadcast,bounded socket deadlines plus sleeps15.6s maximum. Other phases preserve12samples/foregrounddeadline. Payload/socketdeadlines unchanged;metadata adds latency and can affect races. Callback ordering retained;no synchronous ConnectivityManager queries inside callbacks.

First attempt failed before networking:uiautomator reported /sdcard XML creation but cat returned No such file3times. UI artifacts moved to shell /data/local/tmp;exact missing-file cause unknown. Same APKpair. Failed bundle/executedhelpers/cleanup retained;both host/service/userdata/namespace restoration unchanged,serverexit0.2helper contracttests/4CLIguards/docs/generatedbindingsPASS.

Historical auto/null ENONET,matchingrunnerTraceFAIL,SIGKILLrecoveryFAIL retained. Split/per-app/PrivateDNS,longpower/flapping,otherAPI/OEM/arm64 remain;USER_SKIPPED/D06unchanged.

Raw:`audit-debt-20260924/q29-android-startup-state-20261005`;evidence:`release/certification/evidence/q29-android-startup-state-20261005.json`.
