# C → A → B: Linux chain qualification, 30 October 2026

Status: verification complete. All 168 main r08 checks passed, including 20 fault
cycles, real A/B reboots and 30 minutes of mixed traffic. VM300/301 were restored.
The original strict cleanup FAIL for a reboot-reset qdisc was not overwritten:
exact restoration and a fresh comparison are separate records. This is a dated
engineering check, not a release publication.

Practical instructions: [server chain in four actions](../scenarios/CHAINED-SERVERS.md),
including prerequisites and a startup section. This report tested a separate lab
watcher. Moving network actions into INI was checked in a
[separate series](CHAINED-SERVERS-HOOKS-2026-10-30.md); the results are not conflated.

## Lab and reproducibility

| Role | VM | Resources | Placement |
| --- | --- | --- | --- |
| A, ingress server and separate upstream client | 300 | 2 vCPU / 2048 MiB | qcf-a, separate VLAN 102 |
| B, exit server | 301 | 2 vCPU / 2048 MiB | qcf-b, VLAN 103 |
| C and second user C2 | 304 | 1 vCPU / 1024 MiB | qcf-c/qcf-c2, VLAN 101 |
| T and independent underlay router | 305 | 1 vCPU / 1024 MiB | qcf-t/qcf-r; VLAN 101–103 and veth to T |

A/B: Debian 13, kernel 6.12.111+deb13-amd64; C/T: 6.12.113+deb13-cloud-amd64.
Management is outside namespaces.
Proxmox manages VMs only; tests and helper processes run in guests. VM302 was not
used and no builds occurred. A/B RAM, CPU and queues were not tuned.

Existing Linux amd64 **0.8.3** binary, SHA-256:

```text
9cc1dfb84ccdee3bc0fb23aa3b0745882b0d520a325134112be2575512b62a1d
```

This is not current dev/0.8.4 or Android. Both outer hops use TCP FakeTLS,
Recordizer required with actual active PACKET_MUX_V1; inner TCP/UDP is IPv4.
MTU 1400; heartbeat 1000±100 ms; this build's default padding 32–512 and timed
batching, shaping disabled. Both identities are pinned and client key proof is enabled.

A-in: 10.80.1.1/24; C/C2: .10/.11; A-out: 10.80.2.2; B-tun: 10.80.2.1/24.
No NAT on A. B's upstream user delegates 10.80.1.0/24 through client_subnet;
explicit B MASQUERADE covers that network except private destination 198.19.0.0/24.
Public test T: 198.18.0.10; IPv6 control: fd42:230:4::10.

## Evidence design

- A genuinely reaches T directly; C has working routed external ULA IPv6 before
  VPN. An explicit /128 route reaches T's loopback; NDP is not assumed.
- External header-only observers on T/router watch A and C WAN. Positive controls
  record direct packets; observers do not restart during A/B reboot.
- A has an early iptables/ip6tables mangle/FORWARD guard and policy table 208 with
  a permanent blackhole; a watcher repairs routes for recreated TUN interfaces.
- C's native kill-switch is supplemented by namespace platform OUTPUT protection.
  DNS uses namespace resolv.conf **and** NSS hosts files/dns, not host resolved sockets.
- HTTP peer, 2 MiB file SHA, UDP/TCP DNS, ordinary getent, C/C2, private no-NAT
  routing and A-in/A-out/B-tun/T header-only captures are independent checks.

Stock iptables/ip6tables v1.8.11 use the default nf_tables backend. There are no
direct nft commands in r06–r08 and no alternatives changes. Backend naming does
not mean invoking nft.

## Three functional repetitions

Five-second windows, offered 20 Mbps, TCP P1; UDP payload 1200. These verify paced
delivery, **not maximum throughput**. Upload is C→T; download is T→C.

| Repetition | TCP up / down, Mbps | TCP retrans up / down | UDP up / down, Mbps | UDP loss up / down |
| --- | --- | --- | --- | --- |
| 1 | 20.03 / 20.13 | 7 / 4 | 19.92 / 20.02 | 0% / 0% |
| 2 | 20.05 / 20.13 | 1 / 5 | 19.90 / 20.02 | 0% / 0% |
| 3 | 20.03 / 20.13 | 1 / 0 | 19.91 / 20.01 | 0% / 0% |

All repetitions: HTTP sees B WAN; private T sees original C; both DNS forms and
getent pass; file SHA matches; both users receive correct replies. Captures show
C source on A's two TUNs and B TUN, B source on T WAN. Capture drops are zero on
these four observers. External IPv6 is blocked after connection; inner IPv6
forwarding was not tested. TCP retransmits are nonzero; this functional test
does not localize their causes or TUN drops.

## Faults and reboots

Four cycles of each kind, 20 total. Every failure leaves the first C→A ping alive
but makes T inaccessible. Clearing the failure restores connectivity without manual route add.

| Failure | Cycles | Fault injection to successful HTTP, seconds |
| --- | --- | --- |
| Block A→B transport | 4 | 1.43–2.46 |
| Stop A upstream | 4 | 3.22–6.77 |
| Delete working route while watcher is suspended | 4 | 1.49–1.52 |
| SIGKILL A upstream | 4 | 5.56–6.91 |
| Stop/start B server | 4 | 4.31–4.35 |

Stop/crash/B restart produce a verified new qeli-out ifindex. Separate checks stop
the watcher then delete the route, and delete the policy rule itself: the firewall
blocks main-table fallback. These prove independent protection layers, not just a failed curl.

Real reboot recovery: **23.78 seconds for A**, **24.93 seconds for B**; both boot
IDs changed. C/T were not rebooted and T observers remained active. Times include
failure injection, imposed pauses, service restart and HTTP checks; they are not
pure handshake times or a guaranteed SLA.

## Long phase and restoration

Both long connections completed; full raw iperf JSON and systemd journals confirm
their actual durations:

| Workload | Duration, seconds | Receiver goodput, Mbps | Loss / retransmits |
| --- | --- | --- | --- |
| C TCP upload, offered 20 Mbps | 1800.017 | 20.000 | 237 TCP retransmits |
| C2 UDP download, offered 10 Mbps | 1800.001 | 10.000 | Receiver reports 0%, 0 lost out of 1,874,988 |

Final iperf UDP jitter is 1.436 ms: an iperf aggregate, **not** latency p95/p99.
Sender/receiver windows ended at different times; their packet totals must not be
treated as one common loss counter. Maximum throughput was not measured.

The steady long phase has **8,024** new HTTP observations, all successful and all
seeing B; every UDP/TCP DNS probe in that phase passed. Full log: 8,509 HTTP
observations, 8,393 successes and 116 failures during deliberately injected faults
and reboots, retained in raw. Both external observers covered approximately
**2013.9 seconds**, including fault/reboot intervals: **zero direct T packets and
zero capture drops** on each. Earlier positive controls were nonzero. This supports
the finding of no measured bypass to T.

systemd garbage-collects successful transient units. A later `ExecMainStatus=0`
was therefore not the sole completion evidence: complete JSON, actual 1800-second
durations and successful-exit journal entries were checked as well.

B reboot reset its runtime-only eth1 `fq` to boot default `fq_codel`. That was the
only strict initial-cleanup difference, preserved as FAIL. A full retained tc
snapshot from a previous experiment with the same original boot ID allowed exact
restoration of **fq handle 8001:, limit 10000, flow_limit 100** and every other
option; the resulting tc JSON matched fully. This was restoration **after** the
test, not speed tuning. The post-reboot long phase used boot-default qdisc and
must not be interpreted as a clean throughput A/B.

Fresh comparisons on all four VMs match original addresses/interfaces, IPv4/IPv6
routes, rules, iptables/ip6tables, forwarding/rp_filter and native service states
(except expected boot IDs and dynamic lifetimes/ifindex). No test namespaces,
lease locks or installed qcf units remain. SHA of A/B/C raw binaries and original
dist is unchanged; old binaries and results were not overwritten.

The original lab variant's helpers were also checked in disposable C namespaces: repeated
installation, readiness refusal without a policy rule, foreign-chain refusal,
targeted rollback and NAT start/stop preserving an unrelated sentinel rule.
systemd syntax/dependencies passed on copies with existing executable paths
(not a separate production deployment/reboot of those templates). Five portable
[helper unit tests](../../../scripts/test_qeli_chain_helpers.py) and nine docs checks passed.

## Initial failures retained

Before r08, preparation/collector failures were preserved rather than overwritten:

| Attempt | Cause and correction |
| --- | --- |
| sandbox 01/02 | Incorrect runner path; then missing underlay IPv6 /128 route before Qeli |
| r01/r02 | Syntax errors in the early firewall variant; subsequent runs use iptables/ip6tables only as requested |
| r03 | Insufficiently private control socket parent and premature readiness check |
| r04 | Managed DNS unsuitable for a namespace without its own system resolver; platform-managed DNS selected |
| r05 | iproute JSON returns table as a string, helper compared a number; failure was fail-closed |
| r06 | Wildcard-bound UDP DNS fixture replied from the wrong source; exact bind fixed, iperf explicitly bound too |
| r07 | NSS used host resolved through a Unix socket; namespace nsswitch hosts files/dns added |

Each attempt's raw and cleanup result remain separate; earlier FAIL records were
not replaced. None of these errors alone establishes a binary regression.

## Raw and limits

Current raw on each A/B/C/T: `/opt/qeli-chain-e2e-20261030-r08`, containing exact
binary copies on A/B/C, controller/helper source and SHA, private configs, runtime
logs, raw iperf JSON, header-only PCAP/counters, HTTP/DNS probe log, before/after
snapshots and systemd journals. r01–r07 are in separate neighboring directories.
Private configs/identities and large raw are not copied into public documentation.

Raw also contains qualification-result.json, final-evidence.json and a separate
restoration-followup.json; example validation is under manual-validation on C.
[Compact data](../../data/chained_servers_2026-10-30.json) retain measurements,
168 checks and original FAIL provenance without private configs.

Results cover controlled T targets, one outer transport and root commands in
isolated namespaces. Not qualified: arbitrary host DNS/IPC APIs, non-root apps,
C reboot, the actual Internet, all 12 profiles or maximum throughput. Lab systemd
templates remain experiment artifacts, not dependencies of the current manual.
Its startup section links 17 separate INI-hook startup/recovery scenarios without duplicates.
External firewalls/network managers need separate acceptance. Editing instructions
did not change this report's measured data.
