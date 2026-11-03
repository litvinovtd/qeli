# Q25-F135: refuse NAT auto-WAN without a usable default-route listing

25 September 2026. Base: `fcdc7f72`. D06 remains **IN_PROGRESS**.

## Defect and fix

After Q25-F132, the server rejected visible ECMP but fell back to one
fixed-destination `ip route get` when `ip route show default` failed or
produced no usable result. That answer represents only one ECMP hash bucket.
NAT44/NAT66 could start with MASQUERADE for one WAN while other destinations
used another interface.

Automatic WAN discovery for **NAT44 and NAT66** now requires successful
`route show default` and one usable selected interface. Command failure,
an empty/unusable listing and observed ambiguity refuse startup before
forwarding or rules change. IPv6 `route` and `manual` retain their
`route get` fallback for LAN-only and policy-routed configurations. An
explicit WAN remains administrator-managed. The historical IPv4 `eth0`
value denotes auto even when written in INI, so it cannot serve as an
explicit override.

## Verification

On isolated Linux `.11`, Rustfmt, **18/18** `server::nat` tests, strict
Clippy and a binary build passed. Two new unit tests cover empty, malformed
and unavailable listings without calling `route get`, and retain the IPv6
`route` fallback.

Separate NET/mount/PID namespaces had real IPv4/IPv6 ECMP default routes.
A test `ip` shim failed only `route show default`, leaving `route get`
working. The old binary started NAT44/NAT66 through one hash bucket in
**2/2** cases; the fixed binary refused **2/2** with
`cannot verify a unique default WAN` before forwarding or new rules.
TUN and rules were absent after stop. Installed `.11` services and server
`.10` were untouched.

Old binary SHA256: `baa6371daccd37c39ca8e299bbb0898887671590b9d82033d5b1b52eb6186add`.
Fixed binary SHA256: `23ccf5f97811a760cc3a326f300f9b45d1b6f0f02a4b1537827b27cb4ac3d341`.
`nat.rs` SHA256: `d00bb79043fb98f277c73094a8d7f0932ce42ec503d9b1ae20b6629ffad7ea9c`.
Logs, commands, exit codes and packet snapshots:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/`.

## Separately confirmed NAT44 boundary

With `FORWARD ACCEPT` and two egress networks, a packet from `10.73.0.2`
reached an off-WAN public address **without MASQUERADE**. The same source
also legitimately reached server-side LAN `10.50.0.0/24`. A trial blanket
`-i <tun> ! -o <wan> -j DROP` blocked **both** paths, while the selected
WAN still performed NAT44. The NAT66 guard therefore cannot be copied to
NAT44 without defining server-LAN exceptions. This remains open. Explicit
and policy WANs, runtime route changes, name reuse and mixed backends also
remain D06/D10 boundaries.
