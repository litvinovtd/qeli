# Q29: packets crossing carrier transitions and force-stop

<!-- normative-sync: q29-android-leak-bursts-v1 -->

**5 October 2026. Four Release runs PASS: 1,056 probes, six Wi-Fi ↔ Cellular transitions and four force-stops. No physical leaks observed in the qualified windows; 192 post-stop probes blocked. Q29 IN_PROGRESS; overall plan 28/37 (75.7%).**

## Method and scope

Four sequential readonly Android 14/API 34 x86_64 AVDs on .11 in private NET/MNT/PID namespaces. Three use the previous offline SLIRP backend with actual Android Network handle changes; the fourth uses [IPv6-only/DNS64/NAT64](AUDIT-Q29-ANDROID-NAT64.md), including observed CLAT. These are emulated carrier networks, not physical LTE/Internet.

Product Release APK, JNI/Linux CLI and seven managed artifacts are unchanged byte for byte. Of 296 source inputs, only the test APK Java receiver changed; 295 are identical. Fresh releaseAndroidTest/R8 build PASS in 17 s, using the same product mapping and lab certificate. Production proguard rules unchanged. Non-debuggable Release imports INI through the file picker and starts through actual Always-on + lockdown. No AndroidJUnitRunner or private preference injection; the previous runner FAIL was not repeated or called PASS.

Independent receiver UID 10148 (Qeli UID 10149) starts four concurrent ordinary Java socket streams: IPv4/IPv6 × TCP/UDP. No bind/protect/root/JNI. Each stream creates 12 new sockets with 257-byte payloads containing run/sample IDs. Inter-probe delay 150 ms, connect/read timeout 250 ms. This is a bounded series, not continuous traffic every millisecond. Probe start/end times, host/device action markers, complete replies and SHA are retained. Each action burst starts before the action and opens more sockets after completion. The harness verifies both sides of the interval rather than accepting only a final recovered reply.

Before VPN startup, all four outbound request kinds are positively calibrated by complete payloads at the physical sink and in pcap. SLIRP's short reply budget produced only 8 replies out of 48 in each baseline, but the sink received 46/48/44 complete requests in TCP/UDP/QUIC runs, covering both families and protocols. These timeouts are retained and not treated as successful blocking. NAT64 baseline has 48/48 replies and requests. Calibration establishes outbound reachability, not a delay-free return path.

## Results

| Carrier / transport | Burst probes | Carrier switches | Connected-steady replies | Post-force-stop replies under lockdown | Whole-run sink receipts |
| --- | --- | --- | --- | --- | --- |
| SLIRP / TCP | 288 | 2 PASS | 48/48 | 0/48 | 208 |
| SLIRP / UDP | 288 | 2 PASS | 48/48 | 0/48 | 208 |
| SLIRP / QUIC masking | 288 | 2 PASS | 48/48 | 0/48 | 206 |
| IPv6-only NAT64 / TCP | 192 | Not exercised | 48/48 | 0/48 | 114 |

Total 736 sink receipts include baseline, burst and ordinary control probes; they are not the count of successful burst replies. Wi-Fi departure bursts receive 44/42/44 replies; return bursts receive 48 each. Delivered requests use TUN source. TCP performs fresh Auth/NetworkPlan; UDP/QUIC commit paths without a new Auth before force-stop. PID/TUN/ifindex/addresses remain unchanged across each run's two handovers. TUN retention across force-stop is not asserted.

Each burst crossing force-stop receives eight replies in a series that began before stopping; the number eight alone is not labeled a leak. Every delivered request uses TUN source. After force-stop completes, the harness verifies absent PID/TUN and retained OS lockdown. Separate 48 new sockets per run produce no reply, sink receipt or captured request: 192 negative probes with prior positive calibration of all four outgoing paths.

## Independent packet checks

A new private Linux namespace `any` capture covers plaintext TUN, SLIRP proxy/loopback and NAT64/TAP paths to the target port. Zero kernel capture drops. The parser handles IPv4/IPv6, reassembles complete framed TCP requests by sequence and verifies identical overlap/retransmission bytes; UDP is checked in full. Run/sample payload SHA links pcap, receiver and sink. A translated IPv6 destination for an IPv4 literal is attributed to its original IPv4 probe, not mislabeled as an IPv6 probe.

From connected-steady through stopped-lockdown completion, no new physical SYN/data/UDP reaches the target. Delayed physical baseline connections are identified by an earlier SYN and not mislabeled as new leaks. Every marked post-baseline request uses a TUN source. Even after a receiver timeout, late delivery is checked against the entire capture and sink. These findings apply to the fixture targets and bounded series. Arbitrary traffic, other ports, DNS, split/per-app, cold startup and every interval between samples are not qualified.

## Recovery, validation and remaining work

User force-stop intentionally marks the package stopped. The harness explicitly reopens the app and resets OS policy; this does not test automatic SIGKILL restart. All 16 post-manual-recovery IPv4/IPv6 TCP 16 KiB/UDP 257 probes PASS with complete bytes/SHA and TUN source.

Actual Settings revoke PASS: desired=false, consent ignore, no service/TUN. All four runs preserve host/service and persistent userdata SHA/size/mtime; server exit 0 and namespace cleanup PASS; .10 untouched. Python/CLI guards, all nine docs checks, panel, generated bindings and certification PASS. JVM/.NET/native suites were not repeated with unchanged product inputs; the fresh test build and new runtime were executed.

Raw: `audit-debt-20260924/q29-android-leak-bursts-20261005`; evidence: `release/certification/evidence/q29-android-leak-bursts-20261005.json`. Full capture analysis is in sealed raw; evidence contains aggregates. No new product code defect established by this batch. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md), prior matching instrumentation Trace FAIL, DNS/cold-start/split/per-app leak cases, long power/flapping and other API/OEM/arm64 remain. Q29 IN_PROGRESS; USER_SKIPPED and D06 without BPF unchanged.
