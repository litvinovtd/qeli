# Q25-F134: NAT66 blocks transit through another WAN

25 September 2026. Base: `3a79c47a`. D06 remains **IN_PROGRESS**.

## Defect and fix

NAT66 MASQUERADE and its FORWARD permit matched the selected WAN, but there
was no prohibition on another egress interface. With a host `FORWARD ACCEPT`
policy or an external permit, a TUN packet could leave another WAN without
MASQUERADE, exposing the client's ULA address. Startup WAN presence and
ambiguous-auto-WAN checks did not cover a later route change.

NAT66 now installs an essential, owned `ip6tables -I FORWARD 1 -i <tun>
! -o <wan> -j DROP` before host permits. Matching the TUN also covers
operator-authorized `client_subnet` sources outside the allocation pool.
Failure to install and verify the guard refuses profile startup and retains
exact rollback ownership. `route` and `manual` keep their LAN/site-to-site
routing contracts.

## Verification

On Linux `.11`, Rustfmt, 16/16 `server::nat` tests, strict Clippy and the
binary build passed. In a fresh NET/mount/PID namespace with `FORWARD ACCEPT`,
a UDP packet from `fd42::2` reached off-WAN `wan1` without MASQUERADE before
the guard. With the guard it timed out and its DROP counter reached 1; via
the selected `wan0` it arrived as `2001:db8:1::2` after NAT66.

A real TCP worker in a separate namespace installed the guard above both
FORWARD permits. Startup, second-worker refusal, rejected reload and stop
passed. Exact IPv4/IPv6 rules, forwarding, TUN and routes returned to their
before snapshots. Installed services on `.11` and server `.10` were untouched.

Binary SHA256: `baa6371daccd37c39ca8e299bbb0898887671590b9d82033d5b1b52eb6186add`.
`nat.rs` SHA256: `98fe215261a2f03a79fefa79a54c0244840c4445bdb70f0c515173072132da6e`.
Scripts, logs, return codes and snapshots:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat66-egress-phase/`.

## Remaining boundary

The rule matches the WAN **name**, not an immutable ifindex. Device removal
and name reuse, mixed iptables/nft backends, and actions by another root remain
D06/D10 boundaries. IPv4 NAT44 has a similar off-WAN gap, but it can also
route to server-side networks. An unconditional DROP could break existing
site-to-site configurations, so that contract needs a separate resolution
under D06.

Follow-up, 2 October 2026 — Q25-F215 in the [current register](../../plans/AUDIT-DEBT.md): 4 mixed IPv4/IPv6 backend pairs, real TCP NAT44/NAT66 and UDP route with default/policy route and RFC1918/CGNAT/public-LAN changes gave 204 checks PASS. [Packet evidence](../../../../release/certification/evidence/server-route-policy-20261002.json). Runtime routing with retained devices is checked within this scope; continuous WAN identity under name reuse remains D06. Historical open statuses above describe the earlier snapshot.
