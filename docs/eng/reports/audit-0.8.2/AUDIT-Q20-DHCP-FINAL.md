# Q20: DHCP and lease lifecycle

<!-- normative-sync: audit-q20-final-v1 -->

**DONE/PASS. Plan: 20/37 (54.1%), 17 remaining.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q20-dhcp-20261004.json).
Linux candidate: `36a0e491f9437773b73b3e29f9c7ab0b7f624142e782dd78777f0c6168e6cef1`.

## Defects and changes

| ID | Before | Fixed behavior |
|---|---|---|
| Q20-F001 | A valid message-type prefix could allocate an address despite invalid hardware fields, control-option lengths, duplicates or a malformed later TLV. A 1500-byte receive buffer concealed longer tails. | Validate complete BOOTREQUEST, Ethernet type/length, nonzero unicast MAC, cookie and option streams before rate accounting or allocation. Require END and exact fixed-option lengths; receive the full UDP datagram. |
| Q20-F002 | Only four MAC bytes identified a limiter bucket. Neighboring VM/NIC addresses shared the same limit. | All six bytes identify the client. The 61st packet from one MAC is dropped; another MAC with the same prefix remains eligible. |
| Q20-F003 | Saturating `lease * 3` made T2 incorrect for long leases and could put it before T1. | Multiply in u64, divide, then narrow. Ordinary and upper u32 boundaries preserve the configured 3/4 policy. |
| Q20-F004 | 64 IPv4 DNS addresses wrapped option 6's length byte and corrupted the reply. | With DHCP enabled and proxy DNS disabled, admission allows at most 63 IPv4 push resolvers. The encoder also refuses overflow. DHCP-disabled and proxy-enabled configurations retain their separate rules. |
| Q20-F005 | Requested addresses or server identifiers in overloaded BOOTP fields were invisible to the parser. | Option 52 selects bounded `file`/`sname` streams in wire order. Truncation, nested overload and duplicate fixed control options fail before allocation. |

`server/dhcp.rs` owns the wire parser and lease operations; `server/mod.rs` shares
the new DNS bound across check-config, panel validation and worker startup. No
new configuration format was added: configuration remains INI.

## Layers reviewed

| Layer | Contract and result |
|---|---|
| INI and panel | DHCP fields survive the exhaustive server serializer fixture; all 163 parser key names and three dynamic families are covered. IPv6-only DHCP, invalid pool bounds, zero lease, oversized domain and invalid binds fail shared validation. Direct DNS 63/64 boundaries also run through the actual CLI. |
| Listener | Linux receives initial broadcasts on INADDR_ANY with SO_BINDTODEVICE on the actual profile interface, not WAN. Bind completes before admission; ProfileTasks owns cancellation. The actual worker's TAP/UDP listener disappears on clean stop. |
| Wire | DISCOVER, REQUEST, DECLINE and RELEASE dispatch; OFFER/ACK/NAK framing, xid, MAC, address, gateway, mask, DNS, domain and timers. Main and overloaded streams are bounded. Padding and unknown valid TLVs remain legal. Duplicate xid/MAC reuses the same offer. |
| Ownership | Shared IpPool is authoritative: fixed requests cannot evict VPN allocations. Rejected REQUEST does not reserve fallback space. RELEASE/DECLINE require the exact owning MAC and address; another server's selected REQUEST remains silent. |
| Lifetime | Monotonic expiry; OFFER holds 30 seconds, REQUEST commits the configured lease; later DISCOVER cannot shorten a committed lease. Periodic reaping and allocation-time reaping release the shared reservation. DECLINE quarantine lasts 600 seconds and is excluded from allocation. |
| Exhaustion and locking | Empty/exhausted windows do not underflow or evict active VPN owners. Lease/decline/shared-pool lock order is consistent; allocation holds exclusive lease access through pool commitment. Unit and real-packet checks cover reuse after expiry and release. |
| Dead code | Production helpers are used by dispatch, allocation, reaping or response encoding. The option lookup wrapper is test-only; it is not an alternative production implementation. |

Wire-field references: [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html)
and [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html). This audit qualifies
Qeli's supported Ethernet DHCPv4 subset; it does not claim full DHCP compliance.

## Qualification

- Four behavioral tests fail on the old production implementation: malformed
  allocation, MAC collision, long-lease T2 and DNS-length overflow. Ten old DHCP
  tests still pass in that counterfactual run.
- **2383 Linux unit tests PASS, 60 ignored**, strict all-target Clippy and release
  build PASS. Seven tests were added, including overloaded options, pool exhaustion
  with a live VPN allocation and shared configuration admission. The DHCP module
  has 16 passing tests; serializer and panel API tests run in the same full suite.
- **35 semantic DHCP checks PASS**, plus 60 deliberate rate primers, recorded as
  95 checks. The fixture starts a real server worker, opens an additional queue
  of its real multiqueue TAP, injects Ethernet/IPv4/UDP frames, and observes actual
  outgoing packets with AF_PACKET. It checks zero-source broadcast acquisition,
  duplicate xid/MAC, ACK/renewal, NAK, wrong-owner RELEASE, DECLINE, quarantine,
  exhaustion, expiry, malformed input including a tail beyond 1500 bytes, overloaded
  options, independent rate buckets, INI admission and clean shutdown.
- The old binary actually emits OFFER for the malformed packet and accepts a
  64-resolver DHCP configuration; the fixed candidate rejects both. Earlier
  fixture calibration runs are retained and are not presented as successful
  negative-packet coverage.
- **13 fresh authenticated IPv4 TCP VPN checks PASS** on this candidate. Four
  native targets pass independent A/B builds: Windows x86_64, macOS universal2,
  Android arm64-v8a and x86_64. Canonical and consumer copies match; provenance
  reflects current Rust inputs. Native compilation is separate from device E2E.

Both lab services and working executable hashes remain unchanged. The Android
build initially refused insufficient headroom; only verified inactive private
unit/Clippy cache files were removed. Desktop preserves the previously accepted
ambient three-rule legacy firewall delta. No working binary replacement, push,
new benchmark or physical-platform execution occurred.

## Scope limits

Lease state is process-local and does not persist across profile restart. Client
identifiers do not replace MAC lease keys; DHCPINFORM and external-LAN conflict
probes are not implemented. MAC ownership is spoofable, so the profile interface
scope matters. DHCP address allocation is separate from VPN AUTH address assignment.
The TAP test qualifies the actual DHCP service, not a client DHCP daemon or mobile
installed-app flow. User-excluded Mac/router/Windows VM runtime, 60 ignored tests
and accepted Q25-A125 WAN replacement limitations remain explicitly scoped.

Next: **Q21 TUN/TAP, IP and MTU/PMTU**.
