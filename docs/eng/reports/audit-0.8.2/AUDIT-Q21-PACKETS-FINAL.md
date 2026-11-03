# Q21: TUN/TAP, IP and MTU/PMTU

<!-- normative-sync: audit-q21-final-v1 -->

**DONE/PASS. Plan: 21/37 (56.8%), 16 remaining.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q21-packets-20261004.json).
Linux candidate: `36a0e491f9437773b73b3e29f9c7ab0b7f624142e782dd78777f0c6168e6cef1`.

## Result and layers

No additional production defect was confirmed in this pass. Seven new boundary
properties and an actual carrier packet capture close verification gaps. The
production core and native compilation inputs are unchanged from qualified Q20.

| Layer | Reviewed behavior and evidence |
|---|---|
| TUN admission | The first multiqueue descriptor creates exclusively. Later queues bind to its actual name/index; attach cannot silently create a replacement. Unknown flags and VNET_HDR fail. Current full-core tests include 28 open/admission checks. |
| Ownership and namespaces | Original descriptors survive worker teardown and network cleanup; closing them cannot delete an unrelated persistent same-name replacement. Held namespaces and descriptor identity prevent host lookup from resolving another link. Eight earlier privileged Linux tests are retained with their original executable/date: production inputs match, and one fixture's C-string syntax change is proven equivalent. |
| Authenticated addressing | Existing TUN host-prefix checks retain their scoped matrix evidence. Fresh real TAP authenticates IPv4 /24 and IPv6 /64, passes both families' traffic and cleanly removes the device. This tests the native Linux path, not an installed mobile app. |
| TAP control | ARP and NDP answer only the supported owned address/prefix scope. DAD gets no proxy answer. Router Advertisement has router lifetime zero and PIO L=1/A=0: it is not an implicit default-router or SLAAC service. Unit checks cover EtherType/length mismatch, Ethernet padding, multicast MAC mapping, ARP/NDP/RS and DAD; actual TAP NDP/RA checksum probes pass. |
| IP metadata | Declared IPv4/IPv6 length must match the L3 record. IPv4 IHL/flags/fragment limits and IPv6 extension chains/fragment alignment are bounded. Nonfirst fragments do not expose fictitious transport ports. Metadata parsing is not a complete ingress checksum/firewall policy; authenticated source ownership and the host IP stack are separate layers. |
| ICMP and IPv4 fragmentation | DF packets get bounded Fragmentation Needed; non-DF packets are split on aligned offsets, preserving ID, payload and appropriate copied options. IPv6 PTB stays within 1280 bytes and advertises at least 1280. Invalid endpoints and ICMP error recursion are rejected. A 17-combination fragmentation sweep checks MTU, offsets/MF and byte-for-byte payload reconstruction. |
| Encrypted DATA_FRAG | HMAC is checked before allocating reassembly state. Limits are 64 fragments, 32 records per peer, 512 KiB buffered payload and a 16645-byte encrypted record. Overlaps, gaps, inconsistent metadata and conflicting duplicates fail; reordered valid fragments reconstruct exactly. New tests exercise count/byte exhaustion and recovery, malformed MAC floods, maximum boundaries and record-ID reuse. |
| Handshake fragments and PMTU | The older control reassembler remains a separate bounded wire format. Shared vectors, shape/size parsers and wrapper budgets pass. Carrier PMTU responses must match a fresh random 128-bit token and exact size; reverse certification also checks peer/path epoch. A new path starts with a conservative budget. Full-core tests retain wrong/stale-path and concurrent egress checks. |
| Dead code | Reviewed helpers are called by real packet, TAP or transport paths. The minimal audit crate emits two unused-item warnings because it does not link the full client; they do not identify production dead code. Qualified full-core all-target Clippy remains clean. |

## Executed qualification

- **61 packet tests PASS**, including seven new properties, importing the actual
  production IP/ICMP/DATA_FRAG/control-fragment/TAP modules into a small private
  offline Cargo crate. Referenced constants are extracted verbatim from source;
  every imported input matches the current Linux build inventory. A deterministic
  8192-buffer corpus exercises untrusted metadata paths; this is not a new ASan
  or continuous fuzz campaign.
- **70 checks PASS across three final Linux scenarios**: MTU/PMTU/PTB 38,
  IPv6 TAP/NDP/RA 15 and dual-stack TAP 17. Auto inner MTU 1400 crosses an outer
  MTU 1280 with DATA_FRAG; explicit inner MTU 1280 returns actual downlink PTB
  for oversize traffic and succeeds at the advertised size.
- Two actual carrier PCAPs are independently parsed and reconciled with observer
  output: both directions are present, zero MF/nonzero-offset IPv4 fragments,
  zero packets above the 1280-byte link bound. This supplements application logs;
  the saved capture is encrypted carrier traffic from private namespaces.
- **Three portable TAP-probe tests PASS.** The prior current-source **2383 full
  Linux unit PASS/60 ignored**, strict Clippy, release build and four native A/B
  artifacts are reused after checking all 347 build inputs. They were not rerun
  or represented as new executions. Native provenance still matches.

The two lab services, active executable hashes and working source-tree release
are preserved. Network runs restore host addresses, routes, firewall, resolver,
listeners and named namespaces. No new benchmark or working binary replacement.

## Accepted boundaries

TAP is an L3 facade; general Ethernet/VLAN bridging and IPv6 jumbograms are not
supported. This pass does not add configuration values or revive JSON configs.

Carrier PMTU ACKs precede PacketCodec decryption; their random challenge prevents
blind forgery but does not hide the challenge from an on-path observer. Kernel
ICMP PMTU reduction and a hostile path can still deny service. No general PTB
spoof-immunity claim or new raw ICMP ingress filter is made. Generation of ICMP
errors, malformed probe parsing, stale-path rejection and actual small-path
behavior are qualified at their respective layers.

DATA_FRAG expiry is five seconds from first receipt, checked on subsequent pushes;
idle entries can remain allocated until another push or session teardown, within
the fixed caps. Reusing a record ID is legal; PacketCodec's authenticated counter
and replay checks remain mandatory after assembly.

PCAP scope is the tested outer IPv4 UDP QUIC path, not every Internet path. Older
platform/backend rows keep their actual dates/artifacts. User-excluded Mac,
router and Windows VM runtime, 60 ignored tests and accepted Q25-A125 WAN
same-name replacement limits retain their existing scope.

Next: **Q22 transport core, FFI/JNI and memory**.
