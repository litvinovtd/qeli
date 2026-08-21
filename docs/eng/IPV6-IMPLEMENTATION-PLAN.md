# Full IPv6 support — implementation plan

Status: source implementation complete; release certification is still in progress. Updated:
2026-08-21.

The development runtime gate and authenticated capability negotiation are enabled. This is
not yet a release-readiness claim: the physical/native and Linux network-namespace matrix in
section 14 must still pass with freshly rebuilt native cores before a release is promoted.

This document defines **full**, not partial, IPv6 support in Qeli. The work may be split
into internal development stages, but no intermediate stage may be advertised as IPv6
support. The feature is release-ready only after the complete server, client, transport,
routing, installation, and upgrade matrix passes.

Qeli user and installed configuration remains flat INI (`.conf`) only. JSON is not and must
not become a configuration format. Internal structured wire/FFI/API serialization may use
its own representation, but it is not user configuration and documentation must not call it
one.

## 1. Definition of full support

The release must support all of the following together:

- inner IPv4, dual-stack, and inner IPv6-only;
- an IPv4 or IPv6 server endpoint independently of the inner tunnel family;
- TCP, UDP, and QUIC, every obfuscation variant, and every built-in Quick Start mode;
- full and split tunnel, include/exclude routes, DNS, ACL, client isolation,
  site-to-site/`client_subnet`, kill switch, and leak protection for both families;
- Linux CLI, OpenWrt, Keenetic/OpkgTun, Android, iOS, Windows, and macOS;
- system-wide and Windows/macOS per-app modes;
- TUN and the advertised TAP mode, including IPv6 EtherType and NDP/RA;
- installer, `.deb`, Docker, panel, Quick Start, multiprofile configuration, and every
  shipped example;
- explicit old/new client/server compatibility without silent partial operation;
- correct MTU, ICMPv6 Packet Too Big, and transport-level UDP record fragmentation.

Full IPv6 does not mean that an IPv6-only tunnel can reach IPv4-only destinations. That
requires NAT64/DNS64 or another family-translation proxy and is a separate feature. `dual`
is the recommended universal mode. NAT64/DNS64 is outside the first native-IPv6 delivery
and must not be imitated by a hidden IPv4 leak.

## 2. Mode and leak semantics

The server persists a concrete profile mode:

| `tun.ip_mode` | Inner addresses | Full tunnel | Split tunnel |
|---|---|---|---|
| `ipv4` | IPv4 only | IPv4 through Qeli; IPv6 blocked unless leakage is explicitly allowed | only selected IPv4 routes; ordinary IPv6 may remain direct, an explicit IPv6 include is rejected |
| `dual` | IPv4 and IPv6 atomically | both families through Qeli | selected routes of both families through Qeli |
| `ipv6` | IPv6 only | IPv6 through Qeli; IPv4 blocked unless leakage is explicitly allowed | only selected IPv6 routes; ordinary IPv4 may remain direct |

Therefore, with `tun.ip_mode = ipv4`, IPv6 traffic does **not** travel inside the tunnel.
In full-tunnel mode its safe default is blocking, not VPN bypass.

The client `ipv6` setting is a server-capability acceptance policy, not the server mode:

- `auto` — use IPv6 when the server and platform negotiate the complete capability;
- `required` — reject the connection unless full inner IPv6 is available;
- `off` — do not request inner IPv6.

Symmetric protection requires `allow_ipv6_leak = false` and a new
`allow_ipv4_leak = false`. A full-tunnel leak is always explicit. In split mode, traffic
outside selected routes remains direct and exclusions take precedence over inclusions.

## 3. Flat-INI schema

The absence of new keys preserves the current IPv4 behavior. Proposed server schema:

```ini
[profile:reality-tls]
tun.ip_mode = dual
tun.address = 10.9.0.1
pool.cidr = 10.9.0.0/24
pool.exclude =
pool.reservation.alice = 10.9.0.50

tun.ipv6_address = fd71:e1:1234:1::1
pool.ipv6.cidr = fd71:e1:1234:1::/64
pool.ipv6.exclude =
pool.ipv6.reservation.alice = fd71:e1:1234:1::50

routing.ipv6.mode = nat66
routing.ipv6.interface =
dns.listen_ipv6 = fd71:e1:1234:1::1
dns.push_servers = 10.9.0.1, fd71:e1:1234:1::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

Allowed values:

- `tun.ip_mode = ipv4|dual|ipv6`, defaulting to `ipv4`;
- `routing.ipv6.mode = off|route|nat66`;
- `ipv6 = auto|required|off` in the client `[qeli]` section.

The panel and installer may offer `auto`, but must inspect the environment once and persist
a concrete `tun.ip_mode`. A restart must not change family because of a temporary uplink
failure.

The users file needs IPv6 counterparts:

```ini
[user:alice]
static_ip = 10.9.0.50
static_ipv6 = fd71:e1:1234:1::50
allowed_networks = 10.0.0.0/8, 2001:db8:100::/48
client_subnet = 192.168.50.0/24, 2001:db8:200::/56
route = 2001:db8:300::/48 gateway=fd71:e1:1234:1::50 metric=100
```

The parser, serializer, and validator must:

- use `IpAddr`/`IpNet` where both families are valid;
- reject a family mismatch in gateways, reservations, and pools;
- detect overlaps with pools, server addresses, exclusions, and reservations;
- reject meaningless unspecified, multicast, loopback, and IPv4-mapped IPv6 client values;
- scope DHCP settings explicitly to DHCPv4 and report them clearly in IPv6-only mode;
- preserve every consumed key and reject unknown/unread keys during strict validation;
- pass parse → serialize → parse without semantic changes.

## 4. Capability negotiation and compatibility

IPv6 cannot be inferred from the application version alone: support depends on both the
Rust core and the platform adapter. Before address allocation, peers negotiate at least:

- `INNER_IPV6` — IPv6 packets in the data plane;
- `NETWORK_PLAN_V2` — a two-family network plan;
- `UDP_DATA_FRAG_V1` — transport-level UDP record fragmentation;
- family-specific adapter support for IPv6 TUN, routes, DNS, kill switch, and per-app
  routing.

Negotiation must be backward compatible. The server may append a compact authenticated
capability trailer after the current proof, containing magic, version, length, and bits. The
proof-only form plus trailer must remain shorter than 64 bytes so an old client cannot
mistake it for a full proof. A new client sends an extended auth request only after the
server advertises the feature; otherwise it preserves the legacy byte layout exactly.

Required matrix:

| Server | Client | Result |
|---|---|---|
| new | old | IPv4 in `ipv4`/`dual`; clear rejection in IPv6-only |
| old | new | legacy IPv4; clear rejection for `ipv6=required` |
| new | new, capable platform | negotiated `ipv4`, `dual`, or `ipv6` |
| new | new, incomplete adapter | IPv4 or rejection; never a false IPv6 plan |

In `dual`, a new IPv6-capable client receives both addresses atomically or the connection
fails. An old client may receive legacy IPv4 only. IPv6-only must reject an incapable client
before allocating an address. A client with `ipv6=off` uses the IPv4 side of a dual profile
and receives a clear rejection from an IPv6-only profile.

## 5. AuthOK, NetworkPlan, and ABI

The current singular IPv4 fields in
[transport_core/session.rs](../../qeli/src/transport_core/session.rs) and
[transport_core/mod.rs](../../qeli/src/transport_core/mod.rs) become a typed model such as:

- `family_mode`;
- `addresses[]`: family, address, prefix length, gateway;
- `routes[]`: family, destination, optional gateway, metric/exclude;
- `dns_servers[]`;
- `inner_mtu`;
- every active outer carrier endpoint/family, including multipath;
- monotonic network-plan `generation`.

Keep the legacy IPv4 projection for one ABI transition cycle. Additive fields and
capability bits require minor ABI 1.10 → 1.11, not a major bump while old fields retain
their semantics. A server only sends the IPv4 plan to an old adapter.

`persist_tun` must compare a canonical fingerprint of the **entire semantic** NetworkPlan:
mode, both-family addresses, normalized routes, ordered DNS, MTU, and the complete set of
carrier/bypass endpoints. The
monotonic delivery `generation` rejects stale events but is excluded from the fingerprint;
otherwise an identical plan could not be reused after reconnect. TUN reuse is allowed only
on a full semantic match; otherwise rebuild network state atomically. The physical-network
signature includes IPv4/IPv6 addresses, gateways, and resolvers, not only the client IPv4
address
([VpnTunnelBase.cs](../../qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs)).

## 6. Shared IP data plane

A single safe IPv4/IPv6 parser with normalized metadata must replace isolated first-nibble
checks. It must:

- validate IPv4 total length and IPv6 payload length and explicitly reject jumbograms;
- parse Hop-by-Hop, Routing, Destination Options, Fragment, and AH with bounds;
- cap extension-header count and total bytes;
- expose L4 ports only when they are actually present;
- retain source/destination/protocol/fragment id for source guard, ACL, and flow hash;
- apply policy equally to first and later fragments;
- pin all fragments of one IPv6 datagram to the same flow/worker;
- use a bounded fragment-policy cache keyed by source/destination/id/next-header: apply the
  first fragment's L4 ACL decision to later fragments, and drop or very briefly queue a
  non-first-before-first fragment under a strict limit;
- safely reject malformed, overlapping, and ambiguous chains.

Generalize SessionMap, source guard, ACL, isolation, route lookup, and flow hash that are
currently coupled to `Ipv4Addr`, `u32`, and `/32` in
[server/mod.rs](../../qeli/src/server/mod.rs),
[server/acl.rs](../../qeli/src/server/acl.rs), and
[protocol/mod.rs](../../qeli/src/protocol/mod.rs).

Traffic normalization must not append random bytes to a completed IP datagram. Reach the
target size with existing AEAD padding so the declared IP length always matches the packet
([protocol/obfuscate.rs](../../qeli/src/protocol/obfuscate.rs)).

## 7. MTU, PMTU, framing, and encapsulation

This is a blocking dependency before inner IPv6 can be enabled:

- `inner_mtu` is the interface/inner-IP MTU and is at least 1280 whenever IPv6 is active;
- `outer_udp_datagram_budget` is the local maximum Qeli UDP datagram for one outer path;
  multipath stores a separate budget for every active path;
- these values must not be conflated or derived by merely subtracting overhead;
- budget is directional: the client measures uplink and the server independently measures
  downlink;
- both senders start with a conservative **family-specific** budget and probe again after
  carrier/network/roaming changes: outer IPv6 uses no more than 1232 bytes at its minimum
  MTU 1280, while the supported outer IPv4 minimum is specified separately (for example a
  548-byte UDP payload on a 576-byte path), never borrowed from IPv6;
- TCP uses stream framing but still applies the correct `inner_mtu`.

Existing handshake fragmentation in
[protocol/udp_frag.rs](../../qeli/src/protocol/udp_frag.rs) is not a data-plane solution.
UDP/QUIC needs `DATA_FRAG_V1`:

1. Encrypt one complete inner IP packet as one ordinary AEAD record.
2. Split the completed ciphertext record below AEAD into envelopes carrying record id,
   offset/index, count, total length, and payload.
3. Authenticate each fragment with a separate keyed MAC derived from a dedicated session
   KDF key; verify it before allocating a large buffer.
4. Give every QUIC-wrapped fragment a unique packet number.
5. Bound reassembly by record count, bytes, record size, and time; handle duplicates,
   conflicts, and overflow safely.
6. After exact reassembly, run the normal PacketCodec decrypt/replay check.

The new envelope is enabled only after capability negotiation and is never sent to an old
peer.

An IPv6 router does not fragment a transit packet. If an inner packet cannot be sent, the
client or server creates a correct ICMPv6 Packet Too Big with the right source and checksum.
IPv4 retains its IPv4 fragmentation/ICMP behavior. Tests cover loss, reorder, duplicate and
conflicting fragments, timeout, memory DoS, directional MTU differences, and absence of
outer IP fragmentation.

## 8. Pools, sessions, and atomicity

The pool model becomes an optional IPv4 pool plus an optional IPv6 pool under one
transactional lock. An IPv6 `/64` cannot be enumerated in memory: the allocator tracks only
used/reserved addresses and uses a bounded `u128` counter or keyed hash with collision
probing.

Reserve the subnet-router anycast (all-zero host), server gateway, exclusions, and
reservations. IPv6 has no broadcast. The plan distinguishes assigned prefix from pool/on-link
prefix. An L3 TUN client receives a `/128` host route and sends selected routes directly to
the point-to-point interface without an NDP-dependent on-link gateway. TAP uses an address
inside the L2 `/64` and reaches its gateway through NDP. One `prefix_len` must not accidentally
force TUN semantics onto TAP or vice versa.

Sessions are indexed by session id, optional IPv4, and optional IPv6; token maps to session
id. `max_clients` counts sessions, not addresses. Allocate, insert, rollback, reaping,
eviction, and release must update both families atomically.

Routes and ACL use `IpNet` longest-prefix matching. Never install `client_subnet = ::/0` as
a host default route through a client: an exit-node default belongs to an internal routing
table/explicit mechanism or it will hijack the server's uplink.

## 9. Server IPv6 forwarding, DNS, and egress

`routing.ipv6.mode` has strict semantics:

- `off` — IPv6 only inside the profile/LAN, no Internet egress;
- `route` — a bidirectionally routed GUA/prefix without NAT;
- `nat66` — ULA/GUA through an explicit IPv6 uplink and stateful NAT66.

All three modes require `ip6tables`. `off` is not an absence of policy: it inserts and
verifies profile-tagged non-TUN drops in both directions so the profile cannot inherit
forwarding from another active profile or a host-wide administrator setting. `route` follows
the profile's connected and authenticated dynamic kernel routes bidirectionally, including
server LAN and IPv6 `client_subnet` transit; `nat66` admits only related/established WAN replies.

Linux setup enables IPv6 forwarding, family-correct FORWARD/NAT rules, MSS clamp, and
mandatory ICMPv6 including Packet Too Big. If the uplink learns its route through RA/SLAAC,
enabling forwarding must not disable RA reception: apply `accept_ra=2` narrowly to that
uplink and restore its previous value later. Original values are journaled atomically before
the `/proc` writes and recovered on the same kernel boot after an unclean worker exit; a
different boot ID discards the stale journal instead of overwriting freshly loaded host policy.
nftables or ip6tables may be used, but sysctl and
firewall cleanup, rollback, and multiprofile behavior must be symmetric with IPv4.

Without a working IPv6 default route/uplink, the panel and installer must not claim Internet
IPv6. An isolated/LAN `off` profile, a valid routed prefix, or a clear failure is acceptable.
A ULA alone does not create Internet reachability.

The DNS proxy listens on reachable UDP and TCP addresses of both families, picks a
family-correct local bind for each upstream, and handles bracketed `SocketAddr`. It must not
push an unreachable-family resolver. IPv6-only full tunnel needs a reachable in-tunnel IPv6
resolver; A answers are not translated without DNS64.

## 10. Outer IPv6 carrier

Outer and inner families are independent: outer4/inner6 and outer6/inner4 must work.
Resolver and transport sockets move from `Ipv4Addr` to `IpAddr`/`SocketAddr`, resolve A and
AAAA, and create a socket for each candidate family.

TCP uses family-aware sequential failover with one bounded overall deadline divided fairly
among the remaining candidates, so one dead A/AAAA record cannot consume the OS SYN timeout.
UDP `connect()` does not prove reachability: a failed authenticated first flight advances
the candidate rotation for the next bounded reconnect generation, so stable DNS ordering
cannot trap the client on one black-holed address. `local_address` must match the candidate
family; the primary carrier uses a fixed `local_port`, while bonded TCP members retain the
local address with ephemeral ports. Android protects every candidate
socket from the VPN loop before connect.

The selected literal carrier is authenticated in NetworkPlan; the generation also retains
the complete resolved A/AAAA set supplied to the transport. Every usable candidate is
narrowly bypassed by full-tunnel routes and the kill switch before capture is installed.
Bonded streams remain inside that pinned generation set, and `persist_tun` fingerprints the
order-independent set so a DNS-set change forces an atomic network-plan rebuild; a broad
port or whole-IPv6 bypass is forbidden. Reject link-local endpoints without a scope id until
scope id becomes part of the configuration model.

The server opens deterministic, separate IPv4 and IPv6 listeners. The IPv6 listener uses
V6ONLY so IPv4-mapped addresses cannot collide with the IPv4 socket. IPv6 hosts in links and
socket strings are always bracketed.

## 11. Platform adapters

Every adapter needs real IPv6 address/routes/DNS, exact outer bypass, two-family kill switch,
atomic apply/rollback, and a full NetworkPlan fingerprint.

- **Linux CLI:** generic address/route setup, IPv6 DNS and firewall. The attach-existing
  exchange must carry both addresses instead of one IPv4 value; version it or use one
  family-tagged line per address. Router/exit sysctls require a cross-process owner journal:
  acquire even an already-correct value, key owners by PID start-time plus TUN/profile, restore
  only after the last live owner, and discard stale state after a kernel reboot.
- **OpenWrt:** UCI/LuCI render new INI keys; fw4 uses the correct family, routed IPv6 or
  `masq6`; rollback removes all IPv6 route/firewall state.
- **Keenetic/OpkgTun:** hooks and `ndmc` stop parsing address/routes with IPv4-only regular
  expressions and apply both families.
- **Android:** replace the dummy `fd00:71e1::1/128` plus `::/0` leak blocker with real plan
  address/routes/DNS. Remove the dummy when IPv6 is active; `allowFamily()` remains an
  explicit leak policy only.
- **iOS:** real `NEIPv6Settings`, routes, and DNS; uplink/downlink packet protocol follows IP
  version; resolver uses AF_UNSPEC.
- **macOS utun:** the four-byte family header is AF_INET for IPv4 and AF_INET6 for IPv6.
- **Windows global:** Wintun receives IPv6 address/routes/DNS and a v4/v6 kill switch.
- **Windows per-app:** selected WinDivert IPv6 is tunneled instead of bypassed/dropped;
  rewrite the physical source to tunnel IPv6 and reverse replies, update TCP/UDP/ICMPv6
  checksum/pseudo-header, and handle fragments safely.
- **macOS per-app:** the transparent proxy tunnels selected IPv6 with family-correct
  source/destination/interface binds and an A+AAAA tunnel-DNS relay that retries usable family
  candidates; split ordinary traffic bypasses while explicit routes fail closed without their
  negotiated family. It does not copy Windows raw-NAT design.

## 12. TUN, TAP, NDP, and RA

An L3 TUN obtains its address through AuthOK/NetworkPlan and does not require DHCPv6. This is
separate from Ethernet mode.

Advertised TAP support requires:

- accepting and producing EtherType `0x86DD`, not only `0x0800`;
- selecting an Ethernet header from the inner IP version;
- correct IPv6 multicast MAC mapping;
- NDP (Neighbor Solicitation/Advertisement), Router Solicitation/Advertisement, and required
  link-local/multicast packets;
- the AuthOK-assigned address in the L2 `/64` and RA for parameters/default router; keep the
  Autonomous flag off until allocator/source guard can register arbitrary SLAAC/privacy
  addresses;
- DAD for the assigned address and correct NDP replies without accepting another session's
  address;
- no MAC derivation from four IPv4 address bytes;
- separate TUN and TAP tests on every platform where they are advertised.

Stateful DHCPv6 may be a separate feature and is not required for native IPv6 over L3 TUN.
The existing `dhcp.enabled` remains explicitly DHCPv4 and must not silently imply DHCPv6.

## 13. Panel, Quick Start, installers, and examples

Quick Start must not silently migrate an existing IPv4 profile on repeated execution. Add
an explicit Enable/Configure IPv6 action and `auto|off|dual|ipv6` choice. `auto` verifies
global IPv6, a default route, and real egress, then persists a concrete mode.
The independent outer `[::]` listener is added only when the host snapshot proves IPv6 socket
availability; an IPv4 profile must still launch on a kernel with IPv6 completely disabled.
Repeated Quick Start preserves an existing profile's manually configured listener set.

ULA creation generates a stable RFC 4193 prefix (random `/48`, per-profile `/64`), checks it
against host addresses and other profiles, and persists it. Never regenerate it on restart
or repeated Quick Start.

Update and test:

- all ten built-in `QUICKSTART_SPECS`, repeated application, and explicit IPv4→dual/IPv6
  upgrade;
- the multiprofile configuration;
- configs actually installed by `.deb` under `/etc/qeli`: server, multiprofile, users,
  client, and client-reality examples;
- every other repository example including max-obfuscation;
- installer-generated config, Docker seed config, OpenWrt UCI/LuCI, and Keenetic hooks;
- bracketed IPv6 in public host, share link, and panel API;
- every availability/latency probe in panels and applications: A+AAAA, the same
  transport-aware handshake for UDP/QUIC instead of substituting TCP/ICMP, and no requests at
  all when polling is disabled;
- Docker IPv6 forwarding/sysctls/network prerequisites.

Every generated `.conf` passes strict parsing, runtime validation/preflight, and
parse → serialize → parse. Test the actual file list in the built `.deb`, not only a similar
source-tree copy.

## 14. Mandatory tests and release gates

### Unit, property, and fuzz

- INI defaults, invalid family/mode/prefix, unknown keys, and round-trip;
- capability trailer, auth compatibility, and corrupt lengths;
- NetworkPlan v2 and legacy projection;
- IPv6 extension headers, lengths, fragments, flow hash, ACL, and source guard;
- non-enumerating `/64` pool, reservations, and atomic dual-allocation rollback;
- ICMPv6 Packet Too Big and checksums;
- DATA_FRAG reorder/loss/duplicate/conflict/timeout/memory limits/packet-number uniqueness;
- DNS A/AAAA and IPv4/IPv6 upstream combinations;
- persist-TUN fingerprint when only one IPv6 route, DNS value, or MTU changes.

### Linux network namespaces

The matrix contains outer4/inner4, outer4/inner6, outer6/inner4, outer6/inner6, dual and
IPv6-only physical networks; TCP/UDP/QUIC; every obfuscation/Quick Start mode; full/split;
AAAA and IPv6 upstream DNS; ACL/isolation/`client_subnet`; routed/NAT66; MTU 1280;
outer IPv4 MTU 576; asymmetric PMTU; reconnect/persist/roaming; kill switch and leak tests.

Packet captures must prove no outer IP fragmentation of Qeli UDP data, no IPv4/IPv6/DNS
leak, and correct ICMPv6 PTB.

### Native platforms and compatibility

Native/physical tests are mandatory on Android, iOS, Windows, and macOS including both
per-app modes, plus OpenWrt and Keenetic. Test old-server/new-client, new-server/old-client,
and new/new. Rebuild all native libraries before release and automatically verify matching
application/core ABI and capability versions.

Enabling the development runtime gate means the source path is testable end to end; it does
not make the release IPv6-certified. Release documentation may call IPv6 ready only after
the whole matrix, including IPv6-only, TAP, and per-app, is green. A known exception cannot
be branded as “full”.

## 15. Implementation order and dependencies

1. ✅ Add flat-INI schema, parser/serializer/validation, and round-trip tests.
2. ✅ Add ABI/platform capabilities and backward-compatible auth negotiation.
3. ✅ Introduce typed dual AuthOK/NetworkPlan v2 with legacy IPv4 projection.
4. ✅ Introduce a shared IPv4/IPv6 parser and flow hash; move normalization into AEAD padding.
5. ✅ Separate inner MTU and bidirectional local UDP budgets.
6. ✅ Implement `DATA_FRAG_V1` and its dedicated `data_frag` fuzz target.
7. ✅ Implement atomic IPv4/IPv6 pools and session indexes.
8. ✅ Generalize server forwarding, source guard, ACL, isolation, and client routes.
9. ✅ Implement ICMPv6 PTB, DNS, routed IPv6/NAT66, and rollback.
10. ✅ Complete Linux/OpenWrt/Keenetic and attach-existing support.
11. ✅ Add the outer IPv6 carrier and dual server listeners.
12. ✅ Complete Android and iOS source adapters.
13. ✅ Complete Windows/macOS global mode source adapters.
14. ✅ Complete Windows/macOS per-app mode source adapters.
15. ✅ Complete TAP/NDP/RA.
16. ✅ Update panel, Quick Start, installer, `.deb`, Docker, examples, and documentation.
17. ⏳ Pass the physical release matrix and rebuild/verify every native core.

Stages 1–6 previously blocked inner IPv6 even in an experimental profile: without
negotiation, correct MTU, and data fragmentation the result risked incompatibility, black
holes, and violation of the IPv6 minimum MTU. They are now complete and the development
runtime gate is enabled. Stage 17 still blocks release promotion.

## 16. Former IPv4-only sites covered by the implementation

The implementation replaced or generalized the original IPv4-only paths at these sites:

- inner-packet filter in [client/mod.rs](../../qeli/src/client/mod.rs);
- singular IPv4 AuthOK/NetworkPlan in
  [transport_core/session.rs](../../qeli/src/transport_core/session.rs),
  [transport_core/network.rs](../../qeli/src/transport_core/network.rs), and
  [transport_core/mod.rs](../../qeli/src/transport_core/mod.rs);
- IPv4 resolver/socket carrier in
  [transport_core/carrier.rs](../../qeli/src/transport_core/carrier.rs) and
  [transport_core/runtime.rs](../../qeli/src/transport_core/runtime.rs);
- IPv4 pool/session/ACL/preflight in [server/pool.rs](../../qeli/src/server/pool.rs),
  [server/mod.rs](../../qeli/src/server/mod.rs),
  [server/acl.rs](../../qeli/src/server/acl.rs), and
  [server/preflight.rs](../../qeli/src/server/preflight.rs);
- IPv4-only flow hash in [protocol/mod.rs](../../qeli/src/protocol/mod.rs);
- handshake-only UDP fragmentation in
  [protocol/udp_frag.rs](../../qeli/src/protocol/udp_frag.rs);
- IPv4 TUN/TAP assumptions in [tun/iface.rs](../../qeli/src/tun/iface.rs),
  [tun/tap.rs](../../qeli/src/tun/tap.rs), and
  [transport_core/linux_tun.rs](../../qeli/src/transport_core/linux_tun.rs);
- IPv4 defaults/pool/MTU validation in [config/server.rs](../../qeli/src/config/server.rs);
- Quick Start IPv4 pool generation in [web/api/config.rs](../../qeli/src/web/api/config.rs).

These source sites are covered by unit/cross-build gates. The remaining release work is the
physical end-to-end proof from flat INI and negotiation through platform configuration, live
traffic, PMTU behavior, and rule cleanup.
