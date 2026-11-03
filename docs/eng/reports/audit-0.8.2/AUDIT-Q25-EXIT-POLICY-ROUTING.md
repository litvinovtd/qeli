# Q25-F124: exit-node under off-WAN policy routing

Date: 25 September 2026. Base: `eab70d71`. Priority: P1. D06 remains **IN_PROGRESS**.

The exit node selected its NAT interface from the main default route. Its
MARK rule matched only `-i <tun> -o <selected-WAN>`, while MASQUERADE
required both the selected WAN and that mark. Policy routing for forwarded
packets can choose another interface even while the main default and a local
`ip route get` point at the original one. With an accepting FORWARD chain,
the packet left without NAT and exposed the client's original address.

The isolated .11 lab reproduced this across three network namespaces.
The main default selected `wan-main`, while `iif qeli-in lookup 100`
routed a forwarded packet through `wan-policy`. Before the change, tcpdump
on that WAN saw `10.0.0.2 > 203.0.113.9`; Qeli's MARK and MASQUERADE
counters were both zero.

The exit node now records WAN ownership and installs a filter/FORWARD DROP
for packets from its TUN without reserved mark `0x51/0x51`. It takes priority in FORWARD; with multiple exit profiles it can follow
their safe rules but always precedes its own permits. An existing
kill-switch FORWARD hook for the same TUN causes a refusal because its
chain could ACCEPT the packet before this DROP. NAT is
installed before MARK, so partial setup cannot admit marked but un-NATed
traffic. New roaming permits remain behind the guard. An empty-chain
ACCEPT policy is no longer an exit-node fallback.
Qeli brings an owned TUN up only after guards for all negotiated families
are installed. `dev_attach = true` is rejected because an external live
interface would leave a pre-guard window. A plan without an authenticated
IPv4 or IPv6 address is rejected as well.

Cleanup first installs a separate DROP for *all* output from that TUN,
including packets already marked before NAT removal. A failed removal
retains lockdown for retry. `exit_node` with `gateway_nat` or `forward`
in one profile is rejected because they require incompatible handling
of traffic arriving from the TUN.

With the same policy route, the guarded packet was dropped (DROP counter
1; tcpdump received none). After `wan-policy` was added as an allowed
WAN, tcpdump saw the NAT address `198.51.100.2 > 203.0.113.9`; MARK and
MASQUERADE each matched once. Artifacts:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wanpacket.log`
and `wanpacketfixed.log` in the same directory.

Final validation: `cargo fmt`, 111 focused gateway tests, INI regressions,
and the full Linux lib suite: 2182 PASS, 0 FAIL, 59 ignored. The full
suite used a 4096-open-file soft limit (up from 1024): a separate DNS
TCP test holds 512 client and server sockets in one process. Logs:
`wanfinal.log` and `wanfullfinal.log` in the artifact directory above.

Boundary: Qeli reserves the mark bits; external mangle rules must not set
them, and external firewall rules must not place ACCEPT ahead of the guard.
Traffic on a new WAN remains blocked until a successful refresh. Physical
interface rename/reuse and a full live-Qeli matrix remain open in D06.
