# Q09: TCP authentication and complete ClientHello parsing

<!-- normative-sync: audit-q09-tcp-parser-v3 -->

Date: **3 October 2026**. Core code: `cef54120`. Q09-F003–F005 batch qualified;
Q09 overall remains **IN_PROGRESS**. [Evidence](../../../../release/certification/evidence/q09-tcp-parser-20261003.json).
Previous findings: [UDP AUTH/PMTU](AUDIT-Q09-UDP-AUTH.md).

## Findings and fixes

| ID | Priority | Defect | Fix |
|---|---|---|---|
| Q09-F003 | P2 | TCP timeout ended after the first AUTH/JOIN read. Tarpit, Argon2 queue/password verification, admission waiting and AUTH OK/negotiation-error writes could wait without that deadline | One original deadline for cancellation-safe stages. An expired deadline rejects even immediately-ready futures. AUTH OK timeout enters the existing explicit session/pool/iroute rollback |
| Q09-F004 | P2 | Complete ClientHello checked record length but ignored inner handshake length, trailing extensions and malformed key-share vectors. PQ extraction accepted 1184 bytes without the required X25519 tail | Shared strict classic/PQ input validation: versions, both lengths, session ID, cipher/compression vectors, complete TLV block, duplicate extensions/groups and exact known-share lengths |
| Q09-F005 | P3 | Legacy TCP JOIN accepted arbitrary trailing bytes after stream index | Exact magic + token + index length; short/trailing JOIN rejected, colon-containing legacy AUTH passwords preserved |

The deadline starts at inner Qeli handshake entry. Outer REALITY/obfs stages retain
separate bounded budgets. Admission mutations with already allocated resources are
not cancelled wholesale: send failures trigger explicit rollback, which may finish
after the deadline. Running blocking Argon2 retains its concurrency permit until
completion; cancelling the awaiting future cannot hand it to another job. UDP uses
the same helper without restarting its clock.

Complete ClientHello requires its entire declared message; bounded REALITY peeking
retains its separate truncated-tail contract. Unknown/GREASE extensions remain
accepted, including coinciding GREASE IDs emitted by older builders. Structural
validation does not replace subsequent DH, ML-KEM or proof checks.

## Validation

- **2290 Linux unit tests PASS**, 0 failed, 60 ignored; seven new regressions including a blocked duplex AUTH OK write and 20,000 seeded mutations.
- Pinned full/minimal Clippy and rustfmt PASS; jemalloc release SHA `5dcbd80324562417288d068d58152087cb17a7a8b3cf72253157389d8307e522`.
- **8 TCP checks PASS** with a real CLI through a transparent proxy. For a one-second budget, baseline admits delayed AUTH after approximately 1.064 seconds; fixed rejects after approximately 1.001. Normal authentication remains available. 280 idle sockets fill 256 pre-auth slots; excess sockets are refused before spawn, all close and fresh handshakes are accepted again.
- **ASan/libFuzzer: 9106216 runs in 61 seconds**, complete/truncated seeds, input cap 16,389 bytes and RSS cap 768 MiB; no crash found. This is bounded smoke coverage, not a completeness proof.
- **16 UDP/QUIC PMTU + 35 admission checks PASS** on the new binary; fresh **18/327 release matrix**, aggregate leak and **100 TCP + 100 QUIC / 33 soak checks PASS** on that exact SHA.
- Four native cores independently built A/B; ABI, consumed copies and provenance verified. Cross-builds do not establish physical Mac/router/Windows VM execution, explicitly excluded by the user.
- Full .11 snapshots match. On .10 the service/binary and other fields are preserved, but sequential legacy firewall dumps differ only by three pre-existing rules; both save tools use one backend. Cause is not attributed; original snapshots and the prior lab limitation are retained. No service replacement, push or new benchmark.

A blocked write is covered by the deterministic duplex test and review of existing
rollback; a forced live TCP send-window stall is not claimed. Initial lab-fixture
retries corrected debug-error observability and kernel SYN-backlog interference;
the final run passed and original logs are retained.

Raw results: `audit-debt-20260924/q09-tcp-20261003` beside the worktree.
Remaining Q09: UDP anti-amplification, replay/reordering, invalid PQ/proof/password,
capabilities/downgrade and final section review. This batch has no pending checks.

**Subsequent state:** UDP publication, fragments, expiry and deadline qualified by [Q09-F006–F009](AUDIT-Q09-UDP-CONTRACTS.md). That report records the current remainder and limits; original counts here belong to this historical batch.

**Q09 final state:** additional decrypted proof/capability, contention and reproducible TCP KICK/EOF coverage is closed in [the final report](AUDIT-Q09-FINAL.md). Q09 DONE; this batch retains its original historical results and limits.
