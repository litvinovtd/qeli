# Q19 audit: server DNS proxy

Date: 23 September 2026. Baseline: `8344392b`, the shared configuration-library and
previous audit-fixes commit. Section 19 remains **IN_PROGRESS**.

## Scope and test architecture

Reviewed DNS name parsing, cache admission, TTL after CNAME, UDP/TCP retries,
upstream failover and the total deadline. Moved the portable engine from Linux
`qeli/src/server/dns.rs` to `qeli/src/server/dns/resolver.rs`; UDP and TCP use one
implementation. Linux listeners and ProfileTasks remain in the original module.
The same engine compiles in host unit tests; GUI release libraries exclude it.

Network tests use real loopback UDP/TCP sockets on ephemeral ports. Production
upstream configuration still accepts IP addresses and uses port 53; no new INI
setting or separate test implementation of the protocol was introduced.

## Findings and fixes

| ID | Priority | Before | After |
|---|---|---|---|
| Q19-F004 | P2 | NOERROR/NODATA with CNAME in ANSWER was treated as positive. A 300-second CNAME and 5-second negative SOA produced a 300-second cache entry. An unresolved chain without SOA could also be cached. | Check for the requested RR type. Negative responses with CNAME respect both alias and SOA lifetimes; without a negative SOA they are not cached. Direct CNAME queries and chains with a final A retain ordinary caching. |
| Q19-F005 | P2 | Message completeness skipped compression pointers without following them, accepting cycles and expanded names longer than 255 bytes. Blocklist used a separate, stricter walker. | One bounded walker for framing and blocklist checks expansion, length, backward targets and bounds. Header pointers and cycles are rejected; valid nested pointers and the 255-byte boundary remain supported. |
| Q19-F006 | P2 | A TCP response carrying TC was treated as success and selected as preferred. A healthy fallback was never tried, both in forced TCP and UDP → TCP retry. | Keep truncated TCP only as a last-resort fallback and give other upstreams the remaining budget. It is not cached or used to update the preferred server. |

Negative caching was checked against [RFC 2308, sections 2.2 and 5](https://www.rfc-editor.org/rfc/rfc2308.html):
a CNAME does not turn NODATA into a positive result. Name compression and limits were
checked against [RFC 1035, sections 2.3.4 and 4.1.4](https://www.rfc-editor.org/rfc/rfc1035.html).
This does not implement DNSSEC validation.

## Verification and evidence

All 12 existing tests passed after extracting the engine. Five new regressions then
failed on the old logic: CNAME TTL, pointer cycle, overlong name, TC over forced TCP
and TC after UDP retry. After the fixes all **22 engine tests** pass, including
cached transaction-ID rewriting, TTL ageing/expiry, blocklist precedence over cache,
a silent preferred upstream and a stalled partial TCP frame. Final review also covers
a 255-byte name containing 127 short labels; the step budget allows extra compression hops.

Total: **683 Rust unit + 52 editor/policy + 7 examples + 12 server-INI = 754**, PASS.
Three Python DNS fixture tests pass. Linux all-targets Clippy passes with the existing
Rust 1.98 NDP exception for `chunks_exact_to_as_chunks`. This compiles the Linux daemon;
it does not execute its lifecycle. C#/JVM/Apple client interfaces did not change and
their tests were not rerun for this pass.

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/dns-proxy-audit-20260923/`.
`before-regressions.log` records initial failures; `dns-tests.log` is the targeted DNS run; `rust-unit.log` is the final overall run;
`before/` contains snapshots; `review.diff` and `engine-review.diff` capture changes;
`verification.json` records checks and hashes.

## Next pass

Remaining: actual Linux start/stop and ProfileTasks cancellation, load/cache byte budgets,
TSIG/SIG(0), EDNS and RDATA semantics, unusual requests, IPv6 upstream and an external
packet-capture lab. OS DNS apply/rollback from the previous pass also remains open.
No overall DNS PASS or release-ready status is claimed.

[Follow-up: cache memory and signed exchanges](AUDIT-Q19-DNS-CACHE.md) records the next pass; the remaining list above describes this report's baseline.
