# Q19 audit: EDNS, RDATA and cache lifetimes

Date: 23 September 2026. Baseline: `03ead2f7`, after the
[cache/signature pass](AUDIT-Q19-DNS-CACHE.md). Section 19 remains **IN_PROGRESS**.

## Scope and implementation

Reviewed the production DNS engine in `qeli/src/server/dns/resolver.rs`:
record framing and content, TTLs in all sections, EDNS negotiation/options,
synthetic errors, truncation and cache storage. One bounded record walker now
serves framing, common RDATA validation, minimum TTL and EDNS parsing. Removed
the separate answer-only TTL walker and duplicated OPT parsing for size/RCODE.
Linux listeners still use this same engine. No config key, client ABI, dependency
or configuration format changed; configs remain INI.

## Findings and fixes

| ID | Priority | Before | After |
|---|---|---|---|
| Q19-F011 | P2 | A 300-second ANSWER could retain authority/additional records with TTL 0 or 5. A high-bit TTL such as `0x80000000` was cached for an hour. | The whole cached response expires at the smallest ordinary RR TTL across all sections. The high bit means zero; OPT metadata does not contribute. Negative SOA bounds still apply. |
| Q19-F012 | P2 | A declared RDLENGTH was enough: an IN A record with one byte, a broken CNAME target or malformed TXT string passed framing. | Validate common RDATA layouts, name boundaries and compressed targets. Bad upstream answers fail over. Unknown types/class-specific formats remain opaque and are not rewritten. |
| Q19-F013 | P2 | Duplicate/misplaced/non-root OPT and truncated option payloads could reach upstream; EDNS version was not handled locally. | One OPT/TLV parser rejects malformed requests with FORMERR and malformed upstream replies with failover. Unsupported query versions get BADVERS with EDNS(0) metadata. |
| Q19-F014 | P2 | UDP truncation discarded OPT, turning extended errors into a different base RCODE. Local NXDOMAIN/errors also discarded EDNS. | Truncated replies retain extended RCODE/version/flags in a fresh empty OPT. Valid EDNS requests receive local EDNS metadata, without reflecting supplied option payloads. |
| Q19-F015 | P2 | COOKIE and other per-exchange response options entered the ordinary cache; OPT was replayed as stored response data. | Any nonempty query/response option payload bypasses cache. For an ordinary empty-OPT exchange, strip the terminal response OPT before storage and rebuild it on a hit. |

TTL handling was checked against [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html).
EDNS structure and metadata use were checked against [RFC 6891 section 6](https://www.rfc-editor.org/rfc/rfc6891.html).
Known layouts follow [RFC 1035 section 3.3](https://www.rfc-editor.org/rfc/rfc1035.html);
unknown data remains transparent under [RFC 3597 section 3](https://www.rfc-editor.org/rfc/rfc3597.html).

## Compatibility and tradeoffs

RDATA checks cover IN A/AAAA, NS/CNAME/PTR/DNAME, MX, IN SRV, SOA and TXT.
They validate supported wire layouts, not owner/alias/RRset coherence, DNSSEC or
all IANA types. Unknown option codes remain legal when their TLV fits the OPT.

All nonempty options bypass caching, including PADDING, COOKIE, ECS and NSID:
this conservative policy can reduce the hit rate. Responses with nonterminal OPT
also bypass storage so removing bytes cannot break later compression offsets.
An EDNS query receiving a legacy reply without OPT is forwarded without caching;
an unsolicited OPT reply to a non-EDNS query is rejected. Ordinary compatible
empty-OPT exchanges still benefit from caching. No throughput claim is made.

The signed-message contract from the prior pass remains: bytes are preserved,
cache is bypassed, signatures are not verified. The TCP relay regression now
includes EDNS options inside the signed exchange. An oversized signed UDP reply
is still dropped; ordinary truncation creates fresh metadata without TLVs.

## Verification and evidence

Six regressions failed on the baseline: short authority/additional TTLs, the TTL
high bit, malformed request OPT, loss of extended error on truncation, malformed
RDATA and cached EDNS options. Final verification passes **51 DNS tests**, including:

- IPv4 loopback UDP/TCP failover across malformed EDNS and RDATA replies;
- IPv6 loopback UDP and TCP upstream exchanges;
- cache hits with no stored response OPT and newly constructed EDNS metadata;
- unknown option preservation and cache bypass, plus local BADVERS/NXDOMAIN;
- positive/negative RDATA vectors and deterministic truncation/byte-mutation sweeps.

During review, the UDP-size wrapper initially suppressed local FORMERR for an
invalid request OPT. An integration assertion reproduced this implementation
mistake; the wrapper now uses the 512-byte floor and delivers the error. The final
unit run includes that assertion. This is recorded separately from baseline bugs.

**712 Rust unit + 52 editor/policy + 7 examples + 12 server INI = 783**, PASS.
Three Python DNS fixture tests pass. Linux all-targets Clippy passes with the
existing NDP `chunks_exact_to_as_chunks` exception; minimal client FFI, rustfmt,
diff and nine documentation checks pass. RU/EN manuals and the register are updated.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/dns-edns-audit-20260923/`.
See `before-regressions.log`, `review-udp-formerr.log`, final `rust-unit.log`,
`rust-integration.log`, `verification.json`, source snapshots and `review.diff`.

## Remaining work

Host loopback tests and Linux cross-compilation do not execute Linux profile
start/stop or ProfileTasks cancellation. Sustained concurrent load/RSS, external
resolver interoperability, option-specific semantics, RRset/bailiwick validation,
cryptographic DNSSEC/signature interoperability and OS DNS apply/rollback remain
open. No external SSH scenario, live OS networking change or release-native build
was run; unchanged C#/JVM/Apple clients were not rebuilt for this server-only pass.
