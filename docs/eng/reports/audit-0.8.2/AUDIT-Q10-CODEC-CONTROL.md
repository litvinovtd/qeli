# Q10: PacketCodec, replay and CONTROL_V2 receipts

<!-- normative-sync: audit-q10-codec-v1 -->

Date: **3 October 2026**. **Q10 DONE** within the agreed platform audit scope.
Fixes: `2d6d1b73`. Evidence: `release/certification/evidence/q10-codec-20261003.json`.

## Fixes

- **Q10-F001, P2:** repeating a received part of an unfinished KICK was treated as whole-message delivery. The client could ACK before assembly and event publication. Such repeats now return Pending; a receipt requires a complete valid message.
- **Q10-F002, P2:** malformed KICK entered the completed cache before semantic parsing. The first copy was rejected, its repeat ACKed. The common management receiver validates under the same session lock and removes rejected entries. A corrected message with that ID can succeed. Unsupported types do not receive management receipts.
- **Q10-F003, P2:** message ID alone implied Duplicate even if type, flags, part count or contents differed. The cache now retains metadata and each part's SHA-256 fingerprint; conflicts fail. Exact retransmissions of accepted messages still receive another ACK after a lost receipt.

Three client regression checks reproduced the old behavior before the fix. Fragment splitting
uses authenticated plaintext fixtures of the common consumer; the current server producer's
512-byte text limit emits a single-part KICK. This is a receipt-contract defect; no
unauthenticated remote exploitation is claimed.

## Layer review

PacketCodec checks exact TLS/raw frame length, record bounds before allocation, nonce/tag
and minimum plaintext length. Failures clear the caller buffer while retaining capacity.
AEAD and padding validate before changing replay state. Encryption refuses counter
exhaustion. No additional confirmed defect was found in this path.

The replay bitmap agrees with an independent HashSet model across **98,304 sequences**,
including shifts 63/64/65, edges 2047/2048/2049, 2^63 and u64::MAX. Authenticated malformed
padding cannot consume a replay slot: a corrected packet with that counter succeeds,
then its repeat fails. Both TLS and raw framing are checked.

Legacy CTRL requires exact length and its own magic. ClientInfo bounds UTF-8, size and
alphabet; self-reported platform/version remain diagnostic. CONTROL_V2 limits parts to 4096
bytes, messages to 16 parts/64 KiB, inflight assemblies to 8 and the original timeout to 5 seconds.
The completed cache holds 64 messages, at most **32 KiB of digest bytes** plus bounded metadata
and allocations. Generation is bound by the session AEAD key and enclosing lifecycle;
no CONTROL_V2 generation field was added. Exported C ABI and wire format are unchanged.

The common consumer covers Linux/native clients, inline/pipeline and post-recordizer paths.
Semantic validation and receipt insertion use the same bonded-stream session lock.
Public conformance helpers and generic reassembly remain compatible Rust APIs; no newly
confirmed dead production code was found in this layer.

## Validation and limits

**2307 Linux units PASS**, 0 failed, 60 ignored; 6 new tests, full/minimal Clippy and fmt.
Fresh bounded ASan/libFuzzer campaigns: **46,836 PacketCodec** and **1,002,620 CONTROL_V2**
runs, 61 seconds each; configured max_len 16645, RSS limit 768 MiB. Packet fuzz now generates
authenticated records and checks state/replay/padding and allocating/in-place parity;
control fuzz exercises state, expiration, metadata/conflicts and recovery after refusal.
Counts do not prove absence of every defect or coverage of every branch.

Fresh release qualification: **18 scenarios / 327 assertions**, aggregate IPv4/IPv6 leak,
**8 baseline/fixed terminal checks**,**100 TCP + 100 QUIC / 33 soak checks** PASS.
Four native libraries rebuilt A/B; equality, exports, consumed copies and provenance PASS.
This is build qualification; no new Android/iOS app E2E. Mac/router/Windows VM excluded by user.

Working services and executables were not replaced. All .11 snapshots match. On .10 only
the previously documented three legacy firewall rules may differ; any raw host_restored=false
is retained without claiming full restoration or attributing its cause. This batch's fuzz
snapshot fully matched. Earlier evidence is not represented as freshly rerun.
No push, deployment or new throughput benchmark.

Raw results: `audit-debt-20260924/q10-control-20261003` beside the worktree.
Next plan section: Q11, REALITY/TLS/H2.
