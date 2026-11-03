# Q19: server and client DNS

<!-- normative-sync: audit-q19-final-v1 -->

**DONE/PASS. Plan: 19/37 (51.4%), 18 remaining.** 4 October 2026.
Linux candidate: `4c70a6595b6f5a9a9b2809c7975f12212895347fdabc9e05d4135f5a69a8a2f3`.
Production Rust is unchanged since Q18; this is a fresh DNS run on the same binary SHA.
[Evidence](../../../../release/certification/evidence/q19-dns-20261004.json).

## Review outcome

No new confirmed production DNS defect was found. **Q19-V001** closes a runtime
coverage gap: the previous tunnel DNS fixture sent UDP queries to a UDP-only upstream.
It now exercises TCP listeners, TC → TCP retry and forced TCP upstream over a real VPN.
This adds checks, not a product configuration feature. Configs remain INI; internal
JSON API/evidence remain supported.

| Layer | Reviewed contract |
|---|---|
| Configuration | UDP/TCP upstream; unknown protocols including TLS/DoT refused. At most 16 upstreams, 10000 cache/blocklist entries, timeout up to 300 seconds. IPv4/IPv6 listeners and ports remain independent of IPv4 NAT. |
| DNS wire | Bounded name/RR walk, backward compression pointers, expanded names ≤255, common RDATA/framing validation. Malformed packets and multiple questions do not enter the ordinary cache. QR/txid/question/upstream socket must match. |
| Upstream | Random unsigned txid; one query deadline divided between upstreams. UDP TC/exact buffer fill retries TCP with remaining time. TCP connect/write/prefix/body share a deadline. Error/incomplete TCP answers allow the next upstream. |
| Cache | Whole query key without txid; reply ID restored and TTLs aged. Minimum RR lifetime across sections, negative SOA bound, high-bit TTL=0. At most 16 MiB query+response payload per profile plus entry cap; expired/pressure eviction preserves accounting. |
| EDNS/signatures | OPT/TLV validation and BADVERS/FORMERR/NXDOMAIN/TC metadata. Nonempty options and TSIG/SIG(0) bypass ordinary caching. Oversized signed UDP replies are dropped; TCP/sufficient EDNS space is required. Proxy does not verify DNSSEC signatures itself. |
| Listener lifecycle | Both UDP/TCP sockets bind before admission; permits precede task spawn. At most 512 UDP tasks/TCP connections per listener. Persistent TCP reads separate framed messages with idle/body/write deadlines. ProfileTasks owns task cancellation. |
| Client NetworkPlan | Shared config/push/fallback priority; protected DNS host routes in full/split. Failed apply cannot ACK/Connected. Linux supports custom ports through SetLinkDNSEx; mobile/desktop adapters refuse unsupported ports. |
| Linux resolver | Verified stub/resolved only; numeric ifindex/original TUN descriptor, namespace cookie, bus AUTH GUID/GetId and unique owner. Lease transferred before writes; separate shared 15-second setup/cleanup budgets. Legacy global resolv.conf snapshots retained for administrator recovery. |
| NSS/files | Four read-only workers; timeout/cancel retains a slot until libc/NSS finishes. Resolver files: regular ≤64 KiB, stable descriptor stamp, at most 64 addresses. NUL/invalid/scoped entries cannot broaden firewall allowances. |

No dead production helper was confirmed. Test wrappers are cfg(test); compatibility/
recovery paths retain old markers and fail closed. Android applies canonical DNS before
NetworkPlan ACK. Windows tracks partial family application; macOS journals physical-service
DNS. Their actual OS/device qualification retains its own scope, distinct from Linux.

## Qualification

**105 fresh checks PASS:** three dual-stack full TCP tunnel cases — UDP IPv4 upstream,
UDP IPv6 upstream, forced TCP IPv6 upstream. Each uses a real systemd-resolved stub,
A/AAAA over both tunnel DNS families, downstream TCP, stop/reconnect, SIGKILL and markers.
Each UDP upstream log confirms two TC replies and two TCP retries. All 13 exchanges
in the forced TCP case use TCP, with no UDP. Complete host snapshot restored.

Retained Q18 full Linux run: **2376 unit PASS, 60 ignored**, including 52 resolver,
7 listener, 23 client DNS, 37 DNS lease, 7 legacy DNS and 16 system-resolver tests.
These are original runs on the same production source, not repeated execution. Q18
Clippy/release and four native A/B targets remain qualified; provenance matches current
inputs. Three runtime fixture changes do not require Rust/native rebuilds.

Q18 four-profile matrix additionally covers DNS UDP/TCP A/AAAA on both families,
custom listener ports and manual/off/route/nat66 coexistence. Prior NSS stalls, FIFO/
slow/oversized/drift/scoped resolver files and service/PID/network mismatch results
retain original SHAs/times. 32 relevant unchanged source hashes, 61 raw files and nine
archives are verified. Older manifests match only part of the shared dependencies;
changed/absent entries are recorded separately, not declared exact qualification of
the current whole tree. Current composition is covered by Linux unit and fresh real
resolved/tunnel/SIGKILL execution. Historical baseline repro FAILs remain recorded.

Local: three DNS helper and eight matrix contract tests PASS; docs/panel/certification PASS.
Reproduce with scripts/audit_release_matrix_lab.py --cases linux.dns.ipv4-ipv6,
mandatory candidate path/SHA and fresh output. Password comes from QELI_LAB_PASS. Raw:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q19-dns-20261004.

## Limits

Real Linux kernel, private NET/mount/PID and actual resolved. This is not new Android
installed-app or physical Wi-Fi/cellular DNS leak qualification. [Earlier Android runtime](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md)
retains its APK/date and Private DNS socket caveat. Mac/router/Windows VM runtime is
user-excluded; complete Android/desktop audits remain in their own plan sections.

NSS cannot be forcibly cancelled: four stuck calls retain four slots and new lookups
expire by deadline. Context observation is not atomic against arbitrary privileged
service movement. Proxy does not perform full DNSSEC/RRset coherence validation;
unknown RDATA remains opaque, EDNS option cache bypass can reduce hit rate. No new
benchmark/throughput claim. Q25-A125 WAN replacement limitation remains; no blanket
execution claim for 60 ignored tests. Next Q20 DHCP/leases.
