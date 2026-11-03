# Q29: Android Release on an IPv6-only DNS64/NAT64 network

<!-- normative-sync: q29-android-nat64-v1 -->

**5 October 2026. TCP, UDP and QUIC masking over NAT64: three Release/R8 runs PASS, 12 IPv4/IPv6 TCP/UDP payload probes and 18 sink receipts. Q29 IN_PROGRESS; overall plan 28/37 (75.7%).**

## Qualified behavior

Three sequential readonly Android 14/API 34 x86_64 AVDs on .11, inside private NET/MNT/PID namespaces. The selected WLAN interface has no IPv4 address: Android obtains IPv6 through SLAAC, a route through RA and DNS through RDNSS. The server listens on fixture IPv4 `192.0.2.10`; `q29-v4-only.test` has an upstream A record and no upstream AAAA. DNS64 synthesizes `2001:db8:29:ffff::c000:20a`; TAYGA translates actual packets to IPv4 and replies back to IPv6.

The normal file picker imports INI into a non-debuggable Release app. Actual Always-on + lockdown starts a profile with `kill_switch = true`, `ipv6 = required`, `dns = off`. APKs, JNI/Linux CLI, all 296 product inputs and seven managed artifacts exactly match the [previous Release qualification](AUDIT-Q29-ANDROID-RELEASE-FAULTS.md). No rebuild or production proguard change. Signing remains a lab test certificate; no instrumentation or private preference injection.

| Outer transport | Inner IPv4 TCP / UDP | Inner IPv6 TCP / UDP | Auth / NetworkPlan | Revoke and cleanup |
| --- | --- | --- | --- | --- |
| TCP/fake-tls | PASS / PASS | PASS / PASS | 1 / 1 | PASS |
| UDP/fake-tls | PASS / PASS | PASS / PASS | 1 / 1 | PASS |
| UDP/fake-tls + QUIC masking | PASS / PASS | PASS / PASS | 1 / 1 | PASS |

An independent app UID 10148 uses ordinary Java sockets without bind/protect/root/JNI; Qeli UID is 10149. Each TCP probe sends 16 KiB, UDP 257 bytes. Complete response bytes, request/reply SHA and TUN source in sink receipts are verified. An independent pcap parser reassembles TCP requests by sequence, including framing and identical retransmitted bytes. A separate pre-connection IPv6 probe verifies off-pool physical reachability; connected probes use the TUN source. These are 12 target matrix probes plus six short baseline/connected probes, not 18 full matrix scenarios.

Outer bridge and NAT64 TUN captures confirm the DNS64 IPv6 destination, server IPv4 destination, translator pool source and both directions. Matching L4 records are compared after clearing TCP/UDP checksums that change during translation; matching counts are retained in evidence. Server AUTH peer tuples occur in the capture. No IPv4 outer connection to the profile port appears on the bridge. This is the bounded capture for these runs, not the complete leak matrix.

Android also automatically started CLAT: virtual `v4-wlan0` has `192.0.0.4/32`, while base `wlan0` remains without IPv4. Connectivity and address snapshots retain this observation; a separate outer IPv4-literal path through CLAT was not exercised.

## Fixture repairs and retained failures

TAYGA and radvd were unpacked into a private folder from Debian packages; executable SHA is pinned. No package installation or host service startup. A real bidirectional TCP exchange exercises the translator before AVD boot, avoiding a long Android run when the translator immediately rejects traffic.

Three FAIL attempts retain executed helpers, logs and pcap; none contributes to the PASS matrix:

1. TAYGA 0.9.2 rejected `64:ff9b:1::/96` with the fixture IPv4 destination. Capture shows Qeli's outgoing SYN followed by ICMP unreachable from TAYGA. Its [address mapping source](https://github.com/openthread/tayga/blob/master/addrmap.c) checks the first 32 WKP bits when rejecting private/documentation IPv4. The fixture now uses a separate `2001:db8:29:ffff::/96` outside the on-link SLAAC `/64`.
2. After successful NAT64 Auth/NetworkPlan, switching to Cellular failed to reconnect. The emulator publishes fixed IPv4/DNS modem settings; that interface does not receive this TAP fixture's IPv6-only settings and cannot reach the test DNS64. This is not a qualified NAT64 handover. The [previous ordinary carrier transition matrix](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md) remains separate.
3. The new `nat64` suite was missing from two off-pool address/sink provisioning conditions. Before product startup, its baseline received ICMP unreachable from the fixture. Suite membership was repaired; the failure is retained.

The harness has a dedicated NAT64 suite. Invalid suite/carrier/build combinations fail before network namespace mutation. Product code was unchanged: these failures demonstrate fixture problems, not established client defects.

## Completion and limits

Actual Settings revoke PASS: `desired=false`, consent `ignore`, no service/TUN. All six attempts retained host/service and persistent userdata SHA/size/mtime; server exit 0, private namespace addresses and sysctl restored. .10 untouched. Python/CLI guards, all nine docs checks, panel, generated bindings and certification PASS. JVM/.NET/build suites were not repeated with unchanged inputs.

Raw: `audit-debt-20260924/q29-android-nat64-20261005`; evidence: `release/certification/evidence/q29-android-nat64-20261005.json`. This qualifies IPv6-only/DNS64/NAT64 data transfer in the available AVD for three transports. Real Internet/LTE, CLAT, NAT64 handover, immediate transition packets and full leak matrix, long power/flapping, other API/OEM/arm64 and remaining lifecycle scenarios are not qualified. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) and the prior matching instrumentation Trace FAIL remain open. Q29 IN_PROGRESS; USER_SKIPPED and D06 without BPF unchanged.
