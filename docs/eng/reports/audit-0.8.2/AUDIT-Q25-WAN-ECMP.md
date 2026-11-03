# Q25-F129: ambiguous ECMP default WAN

Date: 25 September 2026. Base: `79004b0f`. D06 remains **IN_PROGRESS**.

In a private Linux network namespace, `ip route show default` for dual-uplink ECMP printed a `default` header without `dev` and two indented `nexthop` lines for `wan0` and `wan1`. The previous parser found no `dev` in the header and fell back to `route get 1.1.1.1`, which chose `wan0`. Across 64 other destinations the kernel chose `wan0` 36 times and `wan1` 28 times. The exit node could report readiness with rules for only one WAN; its guard would block some client flows. This is an availability and diagnostic defect, not an observed address leak.
A separate IPv6 probe printed `default metric 1024 pref medium` with the same
indented nexthops: fixed `route get` chose `wan0`, while 64 destinations split
**36/28** between the two WANs. Script and log: `wan-ecmp-ipv6-probe.sh` and
`wanecmpipv6c.log` in the same artifact directory.

The parser now collects devices from every nexthop of each default route and compares candidates at the lowest metric. If the preferred route has multiple interface names or tied preferred routes use different names, selection is ambiguous. It does not fall back to `route get` in this case because that represents only one destination hash bucket. A lower-metric single WAN still wins over a more expensive ECMP route; multiple nexthops on the **same** interface remain supported. Setup, monitor and refresh errors now say there is no unique default WAN.

The shared IPv6 gateway also uses this parser to preserve `accept_ra` before enabling forwarding. Collapsing ambiguity into "no route" would skip RA setup and the native IPv6 preservation check. WAN selection therefore exposes a distinct `Ambiguous` state: the gateway rejects it before recording ownership or changing sysctl/firewall, and also distinguishes ambiguity from a missing route after enabling forwarding. The LAN-only path without a default route remains supported.

Four new unit tests cover both IPv4 and IPv6: ECMP, tied metrics on different WANs, a lower-metric single WAN, and tied routes on the same interface. A further regression verifies that the
IPv6 gateway refuses ambiguity before sysctl/firewall changes or ownership. Final Linux `.11` checks: **11/11** WAN parser tests and **103/103**
gateway rollback tests, plus `cargo fmt --check` and
`cargo clippy --lib -- -D warnings` passed. All four tested source files
match the local worktree byte for byte. Log:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wanecmpfinal2.log`.
IPv4/IPv6 kernel probe logs and scripts (`wanecmpprobe.log`,
`wanecmpipv6c.log`, `wan-ecmp-probe.sh`, `wan-ecmp-ipv6-probe.sh`) are in
the same artifact directory. Installed services and server `.10` were untouched.

Boundary: this is an explicit refusal of automatic selection, not full ECMP support across interfaces. An already active profile retains its old rules until cleanup; flows over the old authorized WAN may work while flows over a new WAN are blocked by the guard. A failed `route show` command still permits the `route get` fallback; per-packet policy routes and WAN name reuse remain separate D06/D10 boundaries.
