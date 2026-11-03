# Q19 audit: cache memory, signed exchanges and query headers

Date: 23 September 2026. Baseline: `c68be853`, following the
[DNS proxy pass](AUDIT-Q19-DNS-PROXY.md). Section 19 remains **IN_PROGRESS**.

## Scope

Reviewed retained cache memory, replacement/expiry/eviction, TSIG and SIG(0),
request headers and the panel's cache setting. The production engine remains
`qeli/src/server/dns/resolver.rs`, shared by Linux UDP/TCP listeners and host tests.
Configuration remains INI; no new configuration key or client ABI was introduced.

## Findings and fixes

| ID | Priority | Before | After |
|---|---|---|---|
| Q19-F007 | P2 | The cache limited entry count only. 1000 entries with 40000-byte answers retained 40004000 packet bytes; large query keys add more memory. | A shared per-profile store caps retained query + response payloads at 16 MiB and still respects `dns.cache_size`/10000 entries. Boxed slices avoid unaccounted vector capacity. Expired entries go first, then batch eviction without copying victim keys. Disabled caching bypasses reads as well as writes. |
| Q19-F008 | P2 | TSIG/SIG(0) requests had their transaction ID changed, and signed answers entered the ordinary cache with TTL rewriting. | Preserve signed upstream exchanges byte for byte and bypass both cache paths. Signed responses cannot be locally truncated; oversized UDP replies are dropped. Reject signed replies to unsigned queries and try another upstream, because ordinary queries retain randomized upstream IDs. |
| Q19-F009 | P2 | An incoming response could be processed as a query. Multiple questions reached upstream while blocklist inspected only the first; matching ignored opcode. | Ignore QR=1, return FORMERR for QUERY with QDCOUNT>1, NOTIMP for unsupported opcodes, and require the response opcode to match. QDCOUNT=0 remains valid, including COOKIE exchanges. |
| Q19-F010 | P2 | Importing `scripts/test_panel_route_dns.py` opened SSH and ran a remote mutation scenario. Ordinary unittest discovery unexpectedly attempted authentication. | Put the existing scenario behind `__main__`. An offline regression forbids socket creation and stdout side effects during import. AST comparison confirms the CLI body and embedded remote scripts are unchanged. |

The cache budget measures retained packet lengths, **not process RSS**. Map and
allocator overhead, active-query buffers and the number of profiles are separate.
Expiry is lazy; under insertion pressure the store removes expired entries before
fresh entries. This is arbitrary batch eviction, not an LRU policy.

## Signed-message contract

[TSIG, RFC 8945 sections 4.1 and 5.5](https://www.rfc-editor.org/rfc/rfc8945.html)
describes transaction-specific authentication and transparent forwarding.
[SIG(0), RFC 2931](https://www.rfc-editor.org/rfc/rfc2931.html) is distinct from
DNSSEC RRset signatures. Qeli detects TSIG type 250 and SIG type 24 with covered
type zero; ordinary RRSIG type 46 and SIG covering an RRset retain ordinary cache
eligibility. Qeli does not verify keys, MACs, timestamps or DNSSEC trust chains.

The tests use structurally shaped **opaque** signatures and verify exact bytes;
they do not claim cryptographic interoperability. A signed client must use TCP
or a sufficient EDNS size when its response exceeds the downstream UDP limit.
A signed response to an unsigned request is unsupported and is not rewritten.
Blocklist and header policy remain effective; locally generated errors/NXDOMAIN
are unsigned and an authenticating client can reject them.

[Multiple questions, RFC 9619 section 4](https://www.rfc-editor.org/rfc/rfc9619.html)
requires FORMERR for ordinary QUERY with more than one question and preserves
zero-question use cases. The proxy serves QUERY, not UPDATE, NOTIFY or DSO.

## Verification

Five new regression tests failed before the production fixes: payload budget,
signed cache admission, signed request mutation, multiple questions and QR=1.
After correction, **36 DNS tests pass**, including real loopback UDP/TCP exchanges,
unsolicited-signature failover, byte-identical signed relay, COOKIE with no question,
16 MiB boundary/large keys, replacement accounting, expiry and limits of 1/2/10 entries.
The insertion stress uses synthetic buffers; it is not a network throughput benchmark.

**697 Rust unit + 52 editor/policy + 7 examples + 12 server INI = 768**, PASS.
Three Python DNS-fixture tests and one import-safety test pass. Linux all-targets
Clippy passes with the existing NDP `chunks_exact_to_as_chunks` exception; minimal
client FFI and documentation checks pass. RU/EN manuals, the audit register,
indexes and the panel's cache hint/maximum were updated.

The external panel script stopped on SSH authentication before its lab mutation
steps. External panel E2E is **not verified**; importing the now-guarded script is
not evidence of E2E success. No live OS DNS, routes or firewall were changed.
Client C#/JVM/Apple tests were not rerun; client interfaces did not change.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/dns-cache-audit-20260923/`:
`before-regressions.log`, `dns-tests.log`, `rust-unit.log`, `rust-integration.log`,
`linux-clippy.log`, `panel-dns-tests.log` (external authentication failure),
`audit-import-tests.log`, `verification.json`, snapshots and `review.diff`.

## Remaining work

Real Linux listener start/stop, ProfileTasks cancellation, sustained concurrent
load/RSS and multi-profile budgets, IPv6 upstream, advanced EDNS/RDATA semantics,
external authenticated DNS and OS DNS apply/rollback remain open. No full DNS PASS,
release certification or new performance benchmark is claimed.

[Follow-up: EDNS, RDATA and TTL](AUDIT-Q19-DNS-EDNS.md) adds IPv6 upstream coverage and further cache/packet fixes. The remaining list above records this report's baseline.
