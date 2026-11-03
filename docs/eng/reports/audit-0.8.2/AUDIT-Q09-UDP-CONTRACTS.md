# Q09: UDP handshake, admission publication and cleanup

<!-- normative-sync: audit-q09-udp-contracts-v2 -->

Date: **3 October 2026**. Core: `a3029951`; fixture: `f36c4887`.
Q09-F006–F009 batch qualified; Q09 overall remains **IN_PROGRESS**.
[Evidence](../../../../release/certification/evidence/q09-udp-contracts-20261003.json).
Prior stages: [UDP AUTH/PMTU](AUDIT-Q09-UDP-AUTH.md), [TCP/parser](AUDIT-Q09-TCP-PARSER.md).

## Findings

| ID | Priority | Defect | Fix |
|---|---|---|---|
| Q09-F006 | P2 | AUTH replay published cached AuthOK before admission completed; cache handling preceded revocation. Early authenticated data/control could enter while iroutes were still being installed | Check revocation before cache; replay and authenticated ingress require a successful initial AuthOK send. Verified negotiation errors also publish only after sending |
| Q09-F007 | P2 | Server reassembly accepted ClientHello labelled MSG_SERVER_HELLO/MSG_AUTH_OK; any fragment magic, including empty/malformed headers, triggered a ServerHello replay | Require MSG_CLIENT_HELLO, count 1–24, idx < count, chunk 1–1200. Generic client fragmentation retains its contract |
| Q09-F008 | P2 | Reaper selected addresses under a read lock, then removed without rechecking. An AUTH lease, replacement handshake or fresh activity could appear between locks | Reapply one expiry predicate to the current entry under the removal write lock |
| Q09-F009 | P2 | UDP admission waiting and AuthOK/negotiation-error sends outlived the original AUTH deadline. Ignored send_to errors still set auth_ok_sent | Shared handshake_until for cancellation-safe admission waiting and sends. AuthOK failure explicitly rolls back registry, pool, iroutes and directory; an unsent negotiation error removes its half-open |

## Layer review

1. **Fragments:** validate direction/length/count before reassembly allocation; incomplete messages stay silent. Actual reordered fragments and exact duplicates work; conflicting duplicates clear the partial.
2. **KE:** structural ClientHello, mandatory ML-KEM, canonical EK and checked X25519 precede AUTH. Live negatives mutate a real CLI hello's EK, both X25519 offers or mandatory hybrid group. Legacy camouflage takes DH from the separate classic offer; this is not outer real TLS group selection.
3. **AUTH:** AEAD mutation never reaches verifier/admission. Wrong password and unknown user get neither AuthOK nor a registry entry. Proof-only identity makes an unpinned/TOFU client refuse before AUTH; this is not a forged decrypted client-proof test.
4. **Admission:** internally cached responses stay unpublished until route programming completes. Independent AUTH tasks preserve reception; active reservations survive eviction/reaping. Prior TCP/UDP permit/deadline checks retain their own evidence.
5. **Retries:** initial response follows admission; five later AuthOK retries preserve identical ciphertext. Exhausted replays do not refresh idle activity. Revocation takes precedence over cached responses.
6. **Anti-amplification:** half-open ServerHello uses a cumulative 3× budget; credential/proof-verified AuthOK uses a five-retry count. Counters use inner/post-obfs bytes with the already documented bounded framing slack. 100 tiny retries qualify that bounded scenario, not an exact outer-wire 3× guarantee.
7. **Failure/cleanup:** one original deadline covers verifier, admission queue and response send. Admission mutations are not cancelled wholesale; rollback may finish later. Reaper checks the current owner instead of trusting an earlier address list.

## Validation

- **2294 Linux units PASS**, 0 failed, 60 ignored; four new regressions cover publication, fragment bounds and expiry/lease revalidation. Full/minimal Clippy and fmt PASS.
- **74 actual UDP/QUIC checks PASS**: baseline reproduces early AuthOK, late admission and wrong-direction ServerHello; fixed blocks them while preserving normal admission/retransmission. Three iroutes are actually installed with bounded delays and removed after the original deadline expires.
- **16 pre-auth PMTU + 35 admission checks PASS** on the same binary; **125** domain checks total.
- Fresh **18 cases / 327 assertions**, aggregate leak and **100 TCP + 100 QUIC / 33 soak checks PASS**. Release SHA `d4cd369c4418f507daaf0246d14b7913897028c1d010f0bdf0b231e8c10a66ac`.
- Four native cores match independent A/B builds; exports, consumed copies and provenance verified. Server-only changes leave client-library bytes unchanged.
- All .11 snapshots match. On .10 the same three pre-existing legacy rules vary between save probes, including a later reappearance; both tools use xtables-legacy-multi. Service/executable and all other fields match across four snapshots. Cause remains unattributed; original host_restored=false retained. Full .10 restoration is not claimed.

The first admission run alongside other checks observed an old TCP client's reconnect
and a UDP ping before client route adoption. The fixture now awaits its TUN writer;
a separate final run without native compilers passed all 35 checks. Original failures
remain retained; the first TCP terminal-loss cause remains unattributed. A passing
rerun does not establish arbitrary-load terminal delivery.

Reaper coverage uses a deterministic actual UdpAuthLease and review of write-locked
removal, not a forced live scheduler race. Live timeout exercises the common
send-error rollback; kernel send_to EIO was not forced. No new parser fuzz run is
claimed; prior TCP/parser ASan evidence remains historical. Physical Mac/router/
Windows VM execution was excluded by the user. No push, deployment or new benchmark.

Raw results: `audit-debt-20260924/q09-udp-contracts-20261003` beside the worktree.
This batch's fix checks are complete. Remaining Q09: final review, additional forged
client-proof/capability and contention cases, and investigation of the initial TCP
terminal-loss observation. A single successful rerun does not close the section.

**Q09 final state:** additional decrypted proof/capability, contention and reproducible TCP KICK/EOF coverage is closed in [the final report](AUDIT-Q09-FINAL.md). Q09 DONE; this batch retains its original historical results and limits.
