# Q11: REALITY, TLS 1.3 and HTTP/2

<!-- normative-sync: audit-q11-tls-v1 -->

Date: **3 October 2026**. **Q11 DONE** within the agreed audit scope.
Fixes: `e2366a73`. Evidence: `release/certification/evidence/q11-tls-20261003.json`.

## Fixes

- **Q11-F001, P2:** the common client ServerHello parser returned the first key_share before validating the rest. Malformed tails, wrong lengths/version, missing supported_versions, duplicates and nonzero compression were accepted. Cover-target shape parsing repeated the loose walk. One decoder now validates the entire message/extensions, X25519/hybrid lengths, TLS 1.3 and session ID echo. Compact clients reject an unoffered hybrid group. Target shape parsing uses the same decoder.
- **Q11-F002, P2:** RecordCrypto published sequence/byte counters after AEAD but before validating TLSInnerPlaintext. All-zero records burned sequence; oversized inner plaintext and unknown types were accepted. Type, padding-inclusive size and record version are checked before publishing counters. The sending boundary is corrected: 16384 content bytes plus type fit one record instead of two.
- **Q11-F003, P2:** RealTlsStream returned a subsequent record's error before delivering already validated application bytes from the same socket read. Those bytes now drain first; a sticky fatal error follows. Subsequent records and new socket writes are refused after that fault. Empty reads/writes do not consume input or emit TLS records.
- **Q11-F004, P2:** async clients required a whole post-handshake message in one record. Fragmented NewSessionTicket caused a false disconnect. A shared bounded accumulator supports split headers/bodies and multiple messages, with a 128 KiB body cap. Interleaving incomplete handshake messages with application/alert records is refused.
- **Q11-F005, P2:** sans-IO silently skipped KeyUpdate/alerts and stayed established after AEAD failure. The shared policy rejects unsupported KeyUpdate explicitly, processes alerts/close_notify and latches terminal state. Earlier validated payloads are returned once before the next call reports failure. Large FFI input is consumed incrementally with a single-ciphertext-record buffer instead of one full input copy.

All five baseline scenarios reproduced before changes: 0 PASS / 5 FAIL.
Ten tests were added, including rejection and compatible behavior. No newly confirmed
redundant production implementations remain: the second ServerHello walker was removed;
async/sans-IO share post-handshake policy. Public Rust/C helpers remain compatible;
a missing direct GUI call alone does not prove a public ABI is dead.

## Layer review

ClientHello building, X25519/ML-KEM, SHA-256/SHA-384 transcripts/key schedules, Finished,
low-order points, message/transcript bounds and rustls/handrolled interop were checked
by the existing tests in the fresh Linux run. Entire ServerHello validation now precedes
key application. Certificate/CertificateVerify are not validated as a generic HTTPS
client would: REALITY relies on pinned identity/token and inner AUTH. This audit does
not turn the transport into a universal X.509 TLS library.

RecordCrypto retains independent **2^24 record / 64 GiB ciphertext budgets per key and
direction**, sticky exhaustion and whole-call checks before emitting fragments.
TLSInnerPlaintext is limited to **16385 bytes including type and padding**; AEAD tag,
header/version, minimum size, exact ciphertext length and type have distinct checks.
Actual adapters terminate after refusal; primitive counter/recovery tests do not
permit real TLS sessions to continue after a bad MAC.

Tickets are bounded opaque post-handshake messages; ticket-based resumption is not
implemented. KeyUpdate requires a new session. Async close_notify produces read EOF
after buffered plaintext and allows reverse writes. Legacy sans-IO has no separate EOF
code: close_notify terminates its handle through existing `-1`, after preceding data
has drained. Exported functions and the `0/-1` convention are unchanged. Existing async
compatibility with clean TCP record-boundary EOF and underlying stream shutdown is
retained; generic strict TLS closure conformance is not claimed.

The REALITY discriminator uses a profile replay guard, time window and strict short_id.
Ordinary probes and repeated accepted tokens reach the cover target. Decoys have a
separate gate and connect/idle/lifetime bounds; a pre-auth lease is exchanged only after
obtaining a decoy permit. TLS, legacy/H2 selection and inner AUTH retain separate stage
timeouts; their sum is not called one global deadline. Lifetime/profile owners cancel
and join nested tasks; failed receivers and exceptions release I/O through RAII.

H2 retains 2 MiB stream/connection windows, 16 KiB frames and a 256 KiB bridge;
capacity is released after consumer writes. Fresh tests cover zero/small windows,
SETTINGS/WINDOW_UPDATE, RST/GOAWAY during blocked writes, payloads larger than a window,
half-close, rejections/later streams and owner cancellation. Pre-auth permits remain
held until I/O destructors complete. No newly confirmed shipping H2 ownership defect
was found in this batch; Q14-F022/F023 now pass again in native Linux units.

## Validation

**2317 Linux units PASS**, 0 failed, 60 ignored; full/minimal Clippy and fmt PASS.
Fresh groups include 51 realtls, 33 H2, 3 server REALITY and 9 crypto REALITY tests.
ASan/libFuzzer: **806899 record** and **38385 sans-IO handshake** inputs, 61 seconds each,
configured max_len 16645 and RSS limit 768 MiB. Record fuzz produces authenticated
inner messages in both AES suites and checks counters/recovery/fragmentation; handshake
fuzz feeds valid/malformed ServerHello through the public sans-IO API. These bounded
campaigns do not prove complete coverage or absence of every defect.

**73 live REALITY-TLS/H2 checks**: success/resume/grace-expiry, private OpenSSL target
shape/certificate borrowing, standard TLS cover probing, accepted ClientHello replay
and tampered tokens without new Qeli admission. **3 PCAP and 6 wire/probe helper results**
were retained with remote/local SHA verification. Captures verify TLS 1.3 ServerHello,
suites/groups/extensions and encrypted records. The cover certificate is generated for
the lab; this does not test the public Microsoft endpoint, complete JA4/JA3S equality
or resistance to a particular DPI. H2 function and captured wire shape are separate.

The result collector initially requested an unrelated case/result.json. Product runs
had exit0/all PASS; the collector error and original raw result are preserved. Existing
captures/logs were recovered and checked without repeating the product runs.

Fresh **18 release cases / 327 assertions**, aggregate IPv4/IPv6 leak and
**100 TCP + 100 QUIC / 33 soak checks** PASS for the exact new candidate. Four native
libraries were independently rebuilt A/B; equality, exports, consumed copies and
provenance PASS. Native builds are not new Android/iOS app E2E. User-excluded Mac/router/
Windows VM and separate platform sections remain independently scoped.

All .11 snapshots match; working services/executables were not replaced. Only the
previous three legacy firewall rules may differ on .10; raw host_restored=false remains,
cause unattributed, all other fields and service/executable unchanged. No push/deploy,
new throughput benchmark or user WIP modification was performed.

Wire-limit basis: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), §§4.1.3, 5.2, 5.4.
Raw results: `audit-debt-20260924/q11-tls-20261003` beside the worktree.
Overall plan: **11/37 DONE/PASS, 29.7%**. Next: Q12, transports and wire camouflage.
