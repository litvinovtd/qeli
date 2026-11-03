# Q25-F132: ambiguous auto-WAN for server profiles

25 September 2026. Base: `280c4d93`. D06 remains **IN_PROGRESS**.

## Defect and fix

Server `detect_wan_until` selected a WAN only through
`ip route get 1.1.1.1` or one fixed IPv6 destination. Under ECMP, that
answer represents one hash bucket while other destinations can use another
interface. Qeli then installed NAT/FORWARD rules for only one WAN name.
The client gateway already had an `ip route show default` parser that
accounts for all nexthops and metrics.

`preferred_default_device` and `DefaultDevice` now live in shared
`network_default_route`. The client retains the same algorithm. For auto
selection, the server first reads all default routes, chooses the unique WAN
at the lowest metric, and rejects ECMP or equal-best routes on different
devices. It fails before enabling forwarding or adding new rules. At this
historical revision, an unusable/failed listing still fell back to `route get`;
[Q25-F135](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md) later removed that fallback
for NAT44/NAT66.

## Verification

On isolated Linux `.11`, Rustfmt, **11/11** shared-parser tests, 1/1 WAN
presence test, strict Clippy and the build passed. The resulting binary
passed **8/8** ordinary TCP/UDP × off/manual/route/nat66 worker lifecycle
cases with **automatic** IPv4 and IPv6 WAN and before/after network snapshots.

Separate NET/mount/PID namespaces contained two WANs with real IPv4/IPv6
ECMP default routes. `route get` chose `wan0` for both fixed destinations,
while `route show default` listed `wan0` and `wan1`. Automatic IPv4 NAT
and IPv6 route refused with `ambiguous default WAN`: **2/2 PASS**;
forwarding/firewall did not change and the TUN was removed on stop.
Installed `.11` services and server `.10` were untouched.

Binary SHA256: `0a67306e187e21edb9dfd693cc9b9d64b82eb219ca34a1bca8b0a57021c98646`.
Shared parser SHA256: `0c1cb45dca572ad3a21d3db3cfafd160d1af458b09f372041be0b41cc6bbaa3c`.
Logs, exit codes, routes, network snapshots and scripts:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-ecmp-phase/`.

## Remaining boundary

This rejects only **auto** selection when an ambiguous default route is
observed. An explicit WAN, separate policy tables, failure to read the
default-route list and route changes after setup were outside this original
fix. [Q25-F135](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md) later closed the
failed-listing fallback for NAT44/NAT66.
Server NAT44/NAT66 rules match egress by name; if a packet actually exits
through another interface, MASQUERADE might not match. The
[NAT66 off-WAN guard](AUDIT-Q25-SERVER-NAT66-EGRESS.md) closes that packet-level
path for NAT66. IPv4 NAT44, mixed-backend recovery and
[name reuse](AUDIT-Q25-WAN-NAME-REUSE.md) remain D06/D10 boundaries.
