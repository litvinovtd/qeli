# Qeli 0.8.2 documentation reconciliation — 16 October 2026

<!-- normative-sync: documentation-review-082-v1 -->

Reviewed after dependency integration into `dev` (`a5fb2834`) and relocation of
646 Q01–Q37 reports into this directory. Findings concern documentation, not newly
reproduced VPN defects. Corrections were prepared in the working tree and checked separately before commit.

## Scope

- RU/EN structure, indexes, local links and fragments, normative markers,
  development/planned/published versions and source references.
- Plans, debt register, current summaries and historical reports: agreed audit
  completion, individual scenario PASS and publication readiness are distinct.
- Server defaults and INI examples, shared client matrix and generated fields;
  additionally all INI blocks in user manuals.
- DNS/NetworkPlan, client pin, inner proof versus outer TLS, native core contents,
  reproducibility and CI/evidence applicability.

Structural checks cover every repository Markdown file. Semantic review focuses on
current manuals, references, plans and the 0.8.2 description. Dated reports retain
their original intermediate results. This is not fresh runtime qualification,
a benchmark, a network check of every external URL or independent cryptographic review.

## Findings

| ID | Severity | Discrepancy and result |
|---|---|---|
| DOC-01 | P2 | Indexes still showed 34/37, Q29 IN_PROGRESS and DNS/null open. Corrected to 37/37 within agreed scope; API34 ENONET remains an accepted, unfixed FAIL. The current result now precedes plan history. |
| DOC-02 | P3 | Three fragments were absent: two AUDIT-DEBT links after measurement withdrawal and one English Q06 link. Corrected. |
| DOC-03 | P2 | Eight INI lines in RU/EN GETTING-STARTED/PANEL contained unsupported inline comments, becoming part of DNS/allowlist values. Comments moved to separate lines; empty-allowlist forms are explicit alternatives. |
| DOC-04 | P2 | GETTING-STARTED described only the first DNS address, called the enabled proxy the default and promised unchanged system DNS without a push. It now explains the typed list, negotiated families, legacy field, false default, client override/fallback and full-tunnel refusal without a resolver. |
| DOC-05 | P2 | TRANSPORT-CORE and CLIENT-CONFIG-CORE presented ABI 1.15 binaries and outstanding A/B builds as current. Overviews now identify ABI 1.16 and retained qualification; earlier stages are explicitly historical. |
| DOC-06 | P2 | The threat model conflated inner identity proof with browser validation of outer Certificate/CertificateVerify. Corrected: the hand-rolled client does not validate the outer chain; MITM access to outer TLS does not provide inner credentials/PacketCodec access when a verified pin is enforced. |
| DOC-07 | P2 | `require_client_key_proof` was presented as the client pin setting. Client `[qeli] key`/`bind_static` and separate server `[auth] require_client_key_proof` policy are distinguished. |
| DOC-08 | P3 | The threat model described native reproducibility only as a future plan. Existing A/B, SHA and source/artifact binding are stated with their recorded-source scope. |
| DOC-09 | P3 | A Russian secret-erasure paragraph was malformed. Fixed while retaining temporary-copy and AES key-schedule limitations. Historical roadmap wording no longer promises complete AES-GCM zeroization. |
| DOC-10 | P2 | Release notes listed new dependencies but cited only the old 19-job CI. Added both 20/20 runs on candidate a7694288, explicitly preceding this documentation revision and not certifying a future package. |
| DOC-11 | P3 | The error catalog attributed a separate Kotlin transport to Android and a managed data plane to Windows/macOS. Shared Rust transport and platform-adapter messages are now distinguished. |
| DOC-12 | P2 | Roadmap omitted current 0.8.1/0.8.2 state; the IPv6 plan described physical qualification as ongoing. Current state and user exclusions are stated.OpenWrt README/INSTALL no longer present earlier hardware claims as 0.8.2 qualification. Earlier references to external audits do not establish independent assurance. |
| DOC-13 | P2 | README crypto summaries could imply PQ protection for every mode. Legacy inner hybrid, classical inner plain/reality-tls and negotiated outer-TLS PQ are separated. |
| DOC-14 | P2 | File-existence checks missed fragments and the INI example guard covered only CONFIG. Fragment checks were added to check_docs; the INI guard now covers all manuals, with tests included in CI. New guards actually refused the original texts. |
| DOC-15 | P3 | Three Rust comments lag the implementation: `DnsConfig.push_servers` and the comment before `pushed_dns_servers` describe the first entry, while the client `dns_servers` reader comment describes only fallback. Code builds a list plus a separate legacy field; an explicit client list overrides the push. All three comments were corrected on 16 October without changing executable lines or line numbers. Pinned independent A/B builds for Windows, macOS universal and both Android ABIs matched each other and the previously qualified libraries byte-for-byte; the new source/artifact binding is verified. |

## Evidence inspected

- [INI grammar](../../../../qeli/src/config/format.rs): whole-line comments only.
- [Server DNS push](../../../../qeli/src/server/handler.rs) and
  [DNS defaults](../../../../qeli/src/config/server.rs).
- [Client DNS precedence and full-tunnel admission](../../../../qeli/src/transport_core/network.rs).
- [Client pin](../../../../qeli/src/config/client.rs),
  [hand-rolled TLS client](../../../../qeli/src/protocol/realtls/client.rs),
  [ABI contract](../../../../qeli/src/transport_core/ffi.rs).
- [Latest dependency qualification](../../../../release/certification/evidence/dependabot-integration-20261016.json),
  [native contract](../../../../native-libs/README.md),
  [release draft](../../../../release/RELEASE_NOTES_0.8.2.md).

## Validation and limits

New guards refused three missing fragments and four manuals with invalid INI examples.
Positive/negative cases cover Unicode and duplicate headings, HTML anchors, fenced/inline
code, URL-encoded fragments and release-body self links. Server example/default/collection
contracts, client-key matrix, configuration projection generator, version sync and the
modified workflow were checked. Exact commands, exit codes and logs are retained in the
local `audit-debt-20260924/documentation-audit-20261016` packet.

The product audit remains **37/37 within the agreed scope**. API34 ENONET and D06 are
unfixed; excluded physical platforms are not PASS; 0.8.2 measurements were not restored
as a public benchmark. No release was published. Historical JSON evidence containing
paths, hashes and old-commit identities was not rewritten to support new claims.
