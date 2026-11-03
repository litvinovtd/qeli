# Q25-F126: select the default WAN by route metric

Date: 25 September 2026. Base: `f35631c6`. D06 remains **IN_PROGRESS**.

`gateway/wan.rs` took the first `dev` printed by `ip route show default`.
With several defaults, output order could put exit-node MARK/NAT/FORWARD on a
backup WAN. [ip-route(8)](https://man7.org/linux/man-pages/man8/ip-route.8.html)
defines lower metric as higher priority. The parser now picks the lowest metric
among `default` lines with `dev`. An absent metric means zero; a malformed
metric discards the record. IPv4 and IPv6 share the selection; `route get`
remains the fallback when no usable default exists.

Regression cases cover reversed output order, an absent metric, and an invalid
metric. In an isolated packet test on lab `.11`, the kernel selected the WAN
with metric 50 over metric 600. Rules for metric 600 alone caused the exit
guard to block the packet (counter 1). After MARK/NAT/FORWARD for the selected
WAN were added, the sink saw NAT source `192.0.2.2`, not client `10.0.0.2`.
Script and logs:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wan-metric-packet.sh`,
`wanmetricpacket.log`, `wanmetric.log`. The check used private network/mount/PID
namespaces only; installed services were unchanged.


Code checks on `.11`: 7/7 focused WAN tests, 113/113 gateway tests,
and `cargo fmt --check` — PASS. Bilingual `scripts/check_docs.py`: 9/9 PASS.

The subsequent [Q25-F127](AUDIT-Q25-EXIT-WAN-MONITOR.md) added a dedicated
exit-WAN monitor and verified refresh without VPN path COMMIT on TCP/UDP.
The subsequent [Q25-F129](AUDIT-Q25-WAN-ECMP.md) rejects ECMP and equal
best metrics across interfaces.
D06 remains open for rename/name reuse
[Q25-A125](AUDIT-Q25-WAN-NAME-REUSE.md) and other physical boundaries;
policy routing is covered by [Q25-F124](AUDIT-Q25-EXIT-POLICY-ROUTING.md).
