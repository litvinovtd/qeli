# Q34/Q25 — Linux packet matrix and roaming soak

<!-- normative-sync: audit-q34-linux-matrix-v1 -->

24 September 2026. Core: `86242da6` (verified D02 source snapshot), executable SHA256:
`96f96c31d42b501773bd0eeb223f923da966a3d5d6b5420862962c679d03183d`. Rust 1.97.0 debug binary: developer integration,
not release certification or a throughput benchmark.

## Q34-F004, P2 — network harnesses used outdated runtime assumptions

`ipv6_netns_case.sh`, `roaming_netns_e2e.sh` and `roaming_udp_netns_e2e.sh` now create
unpredictable 0700 work directories with `mktemp -d`. Control-socket admission correctly
rejected the former predictable 0755 directory. Each independent case gets its own
`STATE_DIRECTORY`; newly created namespaces must not inherit the journal of a destroyed
network from another case. Participants within each case share a directory with separate
namespace groups.

IPv4/IPv6 route-get now waits up to five seconds for route installation: TUN/address
creation precedes complete NetworkPlan setup. A one-shot assertion could fail while real
tunnel traffic succeeded. DNS assertions use the observed numeric ifindex and verify the
exact `dns-link-v1` marker exists before checking its removal. The former assertion against
an absent legacy file did not establish cleanup.

## Results

**17/17 matrix rows, 297 assertions PASS**: outer IPv4/IPv6 × inner IPv4/IPv6 × TCP
fake-tls / UDP fake-tls / UDP quic-shape; TCP/UDP dual-stack split; TAP NDP/RA; DNS A/AAAA
via both listener families and IPv4/IPv6 upstreams; PMTU, DATA_FRAG, explicit MTU 1280
and ICMPv6 Packet Too Big. Clean client stop removes TUN and restores direct IPv4/IPv6
connectivity. DNS packets are real; resolvectl is a controlled stub, so this does not verify
a live resolved D-Bus service. 8 Python matrix contract tests PASS.

Earlier failed runs are retained: control-socket admission, route-get timing, cross-case
journal reuse and obsolete DNS assertions. The first lab bundle also omitted the TAP
helper; this packaging error was corrected before the final run. Matrix criteria were
not weakened.

**100-flip TCP soak: RSS FAIL**. All 100 handovers committed exactly once on both ends,
with one session and the original processes/TUN, orphan=0. Maximum fd counts: client 15,
worker 18; socket fd: 5/6. Last sampled RSS: 41184/101028 KiB. The 32768 KiB growth
threshold was exceeded. The original script does not print baseline values, so the exact
delta cannot be recovered from this log; further measurement is required. Wrapper stopped
on TCP failure, so UDP did not run. The threshold stays unchanged; D13 remains open.

## Provenance and limits

Private net/mount/PID namespaces on lab `.11`, isolated `/run`, `/var/lib`, `/var/log`,
`/tmp` and `/etc/qeli`; live `.10` unchanged. D02 source archive SHA256:
`0908e9bc9fd9aa140470a6cf1e7dfb0b08b58cdf4b3a69750263dac8ee634de4`.
LF-normalized scripts have a separate SHA manifest. Evidence:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/packet-matrix-phase/`,
`packet-matrix-full-v4/`, `packet-matrix-full-v4.log`, `roaming-soak-100/` and its log.

Full D09/D10/D13/D14 remain open: off/manual/route/nat66 × NDP, real resolved/firewalld/
mixed nft, multiprofile/fault/crash recovery, full resource measurements and current
release A/B/benchmark. The next gateway phase is not in this binary. Windows VM,
Mac/iOS and router checks are excluded by user decision, not declared PASS.

[Debt register](../../plans/AUDIT-DEBT.md) · [Full plan](../../plans/FULL-SYSTEM-AUDIT.md)

D13: [100 release TCP/UDP handovers each](AUDIT-Q34-RELEASE-SOAK.md): 30/30 assertions PASS, RSS growth within the unchanged 32 MiB limit; debug FAIL retained. Full resource/fault coverage and final-source measurements remain open.

Follow-up: [Q25-F096/F097](AUDIT-Q25-DNS-MARKER-STORAGE.md) moves DNS markers to v2 with SO_NETNS_COOKIE and a trusted held directory, testing SIGKILL/restart with real resolved. Counts and the v1 contract above describe the historical snapshot; current operations are in TROUBLESHOOTING §6.50.
