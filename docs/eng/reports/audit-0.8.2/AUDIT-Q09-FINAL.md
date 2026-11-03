# Q09: final handshake/pre-auth audit and KICK retention

<!-- normative-sync: audit-q09-final-v1 -->

Date: **3 October 2026**. Core: `ac921681`; fixtures: `f0d2caf8`.
**Q09 DONE** within the agreed audit scope; Q10 is next.
[Evidence](../../../../release/certification/evidence/q09-final-20261003.json).
Earlier stages: [AUTH/PMTU](AUDIT-Q09-UDP-AUTH.md),
[TCP/parser](AUDIT-Q09-TCP-PARSER.md), [UDP contracts](AUDIT-Q09-UDP-CONTRACTS.md).

## Final fixes

| ID | Priority | Defect | Fix |
|---|---|---|---|
| Q09-F010 | P2 | An old TCP client lost KICK when EOF was simultaneously ready, reconnected and superseded the new session again. Pipeline loss notification could overtake queued decryption | Handle management before EOF. Reader closes the FIFO and awaits its finite decrypt drain before reporting stream loss; writer requests reader stop. Buffer acquisition also observes stop |
| Q09-F011 | P2 | Failed platform KICK delivery replaced the typed server error with a generic error, losing `reconnect_allowed=false` | Shared TCP/UDP handling retains typed KICK despite delivery failure. After joining producers, inspect the already-published terminal event so cancellation/TUN stop cannot hide it |

This changes the shared client core. Installed GUIs need the rebuilt native core;
a server upgrade alone cannot update an old client library. INI format, ABI and wire bits are unchanged.

## Final layer review

1. **Ingress and framing:** complete ClientHello parsing is separate from partial REALITY peek; lengths, vectors, duplicate extensions and exact JOIN are checked before use. UDP accepts only bounded client-direction fragments. Incomplete/conflicting messages do not invoke AUTH.
2. **Crypto and proof:** mandatory ML-KEM, canonical encapsulation keys, low-order X25519 and transcript binding were checked. The new peer completes real PQ exchange, verifies the server proof and sends a forged client proof inside valid AEAD, rather than merely corrupting ciphertext. Its identity belongs to a private fixture server.
3. **Credentials and capabilities:** TCP/UDP share pinning → IP lockout → user/tarpit → Argon2 → profile/quota ordering. Known malformed extensions cannot silently downgrade to legacy. Valid legacy/current credentials succeed; IPv6-required on an IPv4-only profile is rejected.
4. **Resources and contention:** TCP acquires permits before spawn; UDP crypto and partial/pending entries are bounded. AUTH leases prevent duplicate jobs and active-verifier eviction/reaping. Blocking Argon2 jobs retain permits if their async waiter is cancelled. Admission waiting and response sending share the original deadline; rollback releases registry/pool/iroutes/directory.
5. **Replay and amplification:** cached AuthOK publishes only after successful first send and checks revocation; retries are capped. Retries cannot extend the AwaitingAuth deadline. Reaper revalidates the current entry under its write lock. Carrier accounting limits are recorded below.
6. **Client lifecycle:** decoded KICK precedes EOF. The pipeline drains finite received records before stream-loss notification without blocking TUN I/O. Whole-generation cancellation still aborts and joins owned workers. UI delivery failure cannot alter the server reconnect policy.
7. **Compatibility and review:** capabilities reflect transport, platform bits and explicit rollout. The public legacy proof builder remains a compatible Rust API; inert UDP session metadata creates no separate execution path. No unresolved critical finding remains in this section. Full transport/packet/session audits continue in their own sections.

## Validation

- **2301 Linux units PASS**, 0 failed, 60 ignored; full/minimal Clippy and fmt PASS. Seven additional Linux checks: simultaneous KICK/EOF, ordinary EOF, platform delivery failure, inline/pipeline terminal-before-EOF and shutdown ownership.
- **8 live TCP baseline/fixed checks PASS**: old binary loses KICK in 4/4 rounds; fixed binary retains terminal policy without reconnect in 4/4. SIGSTOP pauses the old client, the server supersedes/closes it, then the client resumes. This reproduces the race without incidental load.
- **66 AUTH/proof/capability checks PASS** across TCP, UDP and QUIC: verified server proof, forged client proof, invalid version/length/policy, truncated extension, IPv6-required refusal, legacy/current success. Eight concurrent peers per transport: four accepted and four rejected. Refusals leave no admitted session.
- **35 admission checks PASS** on the same candidate without concurrent .11 compilers. Fresh domain total: **109**. Historical batch counts are not presented as fresh reruns.
- Fresh **18 cases / 327 assertions**, aggregate IPv4/IPv6 leak and **100 TCP + 100 QUIC / 33 soak checks PASS**. Release SHA `1782aeb453f9fe0d95671b145d1cf5578c8abd58d9e877e43be18ea28177b5a6`.
- Four native cores rebuilt in independent A/B passes; equality, ABI exports, consumed copies and provenance PASS. This qualifies compilation/packaging, not a new physical app E2E.

## Accepted limits

Terminal-policy retention covers authenticated decoded events and finite already-read TCP
records. It cannot guarantee arrival of lost/unread packets or event presentation by a failing
GUI. Pipeline coverage is a unit fixture; the live paused-client case uses fake-TLS.

Original harness failures remain retained: cleanup kicked an already-removed session and
deleted an already-removed veth; the first unit fixture expected EOF without draining an ACK.
After harness correction, baseline and final checks passed. The previous concurrent admission
FAIL also remains retained. This batch reproduces and fixes the corresponding KICK-loss
mechanism without claiming arbitrary-load guarantees.

Earlier parser ASan/fuzz and UDP timeout/reaper evidence remain historical; their server/protocol
inputs match current source. Exact outer-wire 3×, forced kernel send EIO, scheduler-forced live
reaper races and unlimited flooding are not claimed. Carrier overhead uses previously documented
bounded slack.

All .11 snapshots match. On .10, service/executable and all other fields are preserved,
but the legacy save again differs by exactly the same three pre-existing rules. Original
`host_restored=false` remains retained; the cause is not attributed to compilation and full .10
restoration is not claimed. Physical Mac/router/Windows VM were excluded by the user; native
compilation does not establish new Android/iOS runtime qualification. Working services/binaries
were not replaced. No push, deployment or new throughput benchmark.

Raw results: `audit-debt-20260924/q09-final-20261003` beside the worktree.
Required Q09 fix obligations are closed; the overall audit continues with Q10.
