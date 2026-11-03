# Q25-F136: NAT44 off-WAN boundary with private LAN access

25 September 2026. Base: `2fd8bea4`. D06 remains **IN_PROGRESS**.

## Defect and fix

With a permissive host `FORWARD` chain, MASQUERADE applies only on the
selected WAN. A route through another interface could forward a client
packet without NAT. A packet test reproduced this for
`10.73.0.2 → 192.0.2.1`. A blanket `-i TUN ! -o WAN` drop also broke
access to private server-side LAN `10.50.0.0/24`.

NAT44 now installs an essential `FORWARD DROP` for packets from the TUN
that leave through a different interface **and have destinations outside
RFC1918**. The rule precedes host permits, is verified with `iptables -C`
and is journaled for exact removal. It matches the TUN rather than just
the pool, covering authenticated `client_subnet` traffic too. RFC1918
destinations (`10/8`, `172.16/12`, `192.168/16`) keep the administrator's
existing firewall policy; Qeli grants no new permission for those routes
and applies no off-WAN MASQUERADE. If the guard cannot be installed,
NAT44 startup fails.

## Verification

In fresh NET/mount/PID namespaces on isolated Linux lab `.11`, both
`iptables-nft` and `iptables-legacy` blocked the client's packet to an
off-WAN non-RFC1918 destination, delivered it to RFC1918 LAN with the original
source, and masqueraded traffic on the selected WAN. Both backends
accepted repeated negated `iprange --dst-range` matches; `-C` and exact
`-D` succeeded. Installed lab services and server `.10` were untouched.

Rustfmt, **19/19** `server::nat` tests, **11/11**
`nat_firewall_journal` tests, strict Clippy and the Linux build passed. The
first live-worker run exposed that the durable firewall journal rejected
the new `iprange` module before rule installation. Its validator now
accepts only the exact emitted IPv4 `filter/FORWARD` guard: three negated
RFC1918 ranges, the owned comment and `DROP`. Changed ranges or negation
and IPv6 are rejected. An interface literally named `iprange` is not
mistaken for the module.

The repeated live worker (`tcp`, IPv6 `off`) passed: `iptables-save` showed
the rule, a second process was refused, a rejected config reload preserved
the running generation, and graceful stop removed TUN, rules, forwarding
lease and socket. Network state before/after matched. Final binary SHA256:
`d3cf473f75af6eb2f60e017864a33a3de59522c9e864cbbb467206501b4a5b17`.
`nat.rs`: `5017508c81c38b03867ee23d1ccb4d3aada7d64dd550f9df80bdb8a2b26ccb8c`.
`firewall_journal.rs`: `9a0362dee8affc7fa129cf1eef02023066669020f0d7e762cca13640c421e3f1`.

## Boundary

The guard covers destinations **outside RFC1918**. If another network
behind the server uses public, CGNAT or other non-RFC1918 addressing,
this transit on an unselected interface is blocked. It needs separate
source-preserving routing without NAT or the selected WAN. RFC1918
traffic on another interface still follows the host firewall policy;
this is not a strict physical WAN identity binding. Explicit/policy
WANs, same-name device replacement, live route changes and mixed-backend
recovery remain D06/D10 work.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/`.

Follow-up, 2 October 2026 — Q25-F215 in the [current register](../../plans/AUDIT-DEBT.md): 4 mixed IPv4/IPv6 backend pairs, real TCP NAT44/NAT66 and UDP route with default/policy route and RFC1918/CGNAT/public-LAN changes gave 204 checks PASS. [Packet evidence](../../../../release/certification/evidence/server-route-policy-20261002.json). Runtime routing with retained devices is checked within this scope; continuous WAN identity under name reuse remains D06. Historical open statuses above describe the earlier snapshot.
