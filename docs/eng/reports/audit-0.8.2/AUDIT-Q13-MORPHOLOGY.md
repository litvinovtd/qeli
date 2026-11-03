# Q13: recordizer, padding and shaping

<!-- normative-sync: audit-q13-morphology-v3 -->

## 4 October: Q13 completion

**Q13 DONE/PASS. Overall plan: 13/37 (35.1%), 24 sections remaining.**
Core `711782d6d1cb6e41889c7c359f964e7242e314fc`, Linux candidate `5605f4b7867cefb0886f14c943c499693fb41a0d0f767f8675292115d5f27c55`.
Evidence: `release/certification/evidence/q13-close-20261004.json`.

Removed two unreachable UDP stealth/pacing branches, three unused private send-helper
parameters and their arguments. Simplified both UDP idle-cover conditions and corrected
comments. Both peers still force UDP stealth off: saved `stealth=true` does not enable
data pacing or cover under load. TCP pacing and UDP idle cover remain. INI, ABI and
wire format are unchanged. This is dead-code removal, no new reproduced runtime defect.

Final batch:

- **2365 Linux PASS / 60 ignored**, full/minimal Clippy and fmt.
- Shipping rlib: **714992 assertions**,18000 padding compositions,
  10000 rejected callback cases and 64 simultaneous fragment completions;
  peak RSS **11176 KiB**. Bounded invariant campaign, not ASan/libFuzzer.
- **7 live cases / 72 fixture checks**: UDP required/off, idle-cover and saved
  stealth=true; TCP 2 Mbps stealth single/bonded3; normalization with padding on/off.
  UDP data exceeds 2 Mbps; both TCP directions remain below the 2.6 Mbps allowance,
  including aggregate throughput of three flows. Capture SHA and flow counts verified;
  post-load ping and cleanup checked.
- **18/18 matrix / 327 assertions**, aggregate IPv4/IPv6 leak,
  **100 TCP + 100 QUIC / 33 soak checks**, **24 REALITY-TLS/H2 checks** on this exact candidate.
- Four independent native A/B libraries, exports, copies/provenance PASS.
  Active services/executables preserved. Raw desktop snapshot=false is accepted only
  for the recorded exact known legacy firewall-rule delta.

Earlier baseline/fixed probes and 17 INI checks retain their original hashes; their
recordizer/obfuscate/config modules match byte-for-byte. Current units, campaign and
live send paths rerun. Q13 fixed five shaping and four padding/mux defects and removed
both disabled UDP paths. All five section criteria are complete within available scope.

Reassembly internal state remains incremental on errors; callback delivery is atomic
only after complete-envelope success. Bucket targets include data+padding but exclude
AEAD/carrier headers. PCAP timing alone proves neither plaintext buckets nor DPI
resistance. Measurements are owned lab workloads. No fresh installed-app E2E claim;
unavailable Mac/router/Windows VM runtime was excluded by the user. Continue with Q14.

## Earlier padding/normalization/mux batch



## 4 October: padding, normalization and mux error handling

**New batch PASS; Q13 IN_PROGRESS.** Core `97cbe865a8a196e203bc6b3416d2e066ab6e6ebf`,
Linux candidate `0e51469f3a879e1c2061bcbf02b5ece223d600fce5fea6cddbc9aba4fa852b68`. Evidence:
`release/certification/evidence/q13-morphology-r2-20261004.json`.
Overall remains **12/37 DONE/PASS (32.4%)**.

| ID | Correction |
|---|---|
| Q13-M001, P2 | Normalization rounded payload alone then added existing random padding:70+3 bytes became131 instead of128. The shared helper now targets data+all padding, including when payload already equals a bucket. TCP client/server and both UDP client paths updated; UDP server uses the common server helper. |
| Q13-M002, P2 | Disabled padding accepted NaN/Inf; AuthOK serialized null and the client could not deserialize it. Padding probability and recordizer ratios must remain finite even while disabled. Finite dormant tuning is retained without resets. |
| Q13-M003, P2 | decode_with called back on a valid prefix before a later frame error, allowing client management side effects. No callback now runs until the entire envelope succeeds, including conflict and resource checks. |
| Q13-M004, P3 | sample > probability allowed padding when probability=0 and draw=0. Strict sample < probability now enforces the endpoint and rejects nonfinite public API values. |

The first three differences were reproduced against the previous shipping release rlib.
Zero probability is a deterministic RNG boundary check; no rare random baseline failure
is claimed.

Reassembly **does not transact internal state**: accepted partial fragments may remain
following a later error, conflicting state is removed and completed packets in rejected
envelopes are dropped. The guarantee applies to callbacks. Whole packets still borrow
the authenticated record; completed fragments transfer their existing allocation.
The single-packet completion path needs no completion-list allocation.

This candidate's checks:

- **2365 Linux PASS / 60 ignored**, six new tests, full/minimal Clippy and fmt.
- **17 production INI/profile-validator checks**:NaN/Inf rejected even while disabled;finite dormant tuning survives INI roundtrip.
- Shipping rlib campaign: **714373 assertions**, 10000 roundtrips,
  40000 inner packets,40000 malformed records,**18000 combined padding cases**,
  **10000 rejected callback cases**,64 simultaneous fragment completions.
  Peak RSS **11144 KiB**;bounded invariant campaign,not coverage-guided fuzzing.
- **6 TCP/UDP cases / 62 fixture checks**:legacy/required recordizer,
  normalization with padding on/off and three bonded TCP flows. Identical directional
  iperf plus post-load ping;snapshots and working service preserved.
- Fresh **18/18 matrix / 327 assertions**,aggregate IPv4/IPv6 leak,
  **100 TCP + 100 QUIC path flips / 33 checks**,separate **24 REALITY-TLS/H2 checks**.
- Desktop .10 retains raw snapshot=false:only the exact verified known legacy firewall-rule delta is accepted;service and executable unchanged. .11 snapshots match.
- Four native A/B artifacts,copies,exports and provenance PASS. No fresh installed-app
  E2E;Mac/router/Windows VM runtime excluded by the user.

Plaintext bucket targets include data+padding,not AEAD/carrier headers. The campaign
verifies composition and inverse decoding;header PCAP alone cannot prove encrypted
plaintext buckets. Earlier shaping-rate measurements below retain their original
candidate;no universal new benchmark/DPI resistance claim.

Sender batching,flush/PMTU raise,caps,duplicates/conflicts/expiry,cancellation at carrier
boundaries and shared budgets reviewed. Suspected millisecond wrapping was not confirmed:
helper conversions saturate and disabled scheduler select arms are gated.
Remaining Q13 work:remove and verify two production-disabled UDP stealth branches while
preserving the documented TCP-only policy.

## Previous shaping batch


**4 October 2026. Batch: PASS. Q13: IN_PROGRESS.** Overall **12/37 DONE/PASS (32.4%)**.
This does not complete the entire audit. Source: `82c1ad770a6fa43302263babd67dab4e41043e9b`; Linux candidate: `d68bb6dab55234454821a22da1342469759a5d39aaa2c6915781acddddf4d10b`.
All compilation input hashes match this commit; original pre-build identity is retained.
Independent native builds use the clean source commit.

## Fixes

| ID | Problem and resulting behavior |
|---|---|
| Q13-S001 | P1: pacing discarded its final pause of up to 6 ms. One shared scheduler now waits for the entire deadline and counts slow cover writes towards it. Two active TCP writers and two currently disabled UDP branches use it. |
| Q13-S002 | P2: streams sampled time before locking; a stale timestamp moved the shared cover refill clock backwards and generated another refill. The clock now remains monotonic. |
| Q13-S003 | P2: local INI refused inactive `shaping_stealth_mbps = 0` while AuthOK preserved it. INI now retains the dormant value; active stealth still requires a positive rate. |
| Q13-S004 | P2: local INI accepted active 65535-byte cover, exceeding the common record ceiling. INI and AuthOK now share the active shaping validator and bounds. |
| Q13-S005 | P1: client data rate was per bonded TCP stream. All writers now reserve one aggregate direction budget; server rate accounting was already aggregate. |

A TCP cover write failure now terminates the writer rather than merely leaving its
inner pacing loop and trying to send data. Wire format and INI keys are unchanged.
Cover has a separate budget that meters padding bytes, not total interface traffic.

## Verification

- Five baseline assertions FAIL; **7 new tests**. **2359 Linux PASS / 60 ignored**,
  full/minimal Clippy and fmt PASS. Test-import and Send-wrapper compile failures
  are retained; corrected sources passed the complete fresh execution.
- Shipping release rlib campaign: **10000 roundtrips,40000 inner packets,40000 malformed
  records,622431 assertions PASS**, covering fragment/inflight/byte caps, duplicates,
  conflicts, budget recovery and expiry. Peak RSS **11128 KiB**. This is a bounded
  invariant campaign, not ASan/libFuzzer or exhaustive coverage.
- **10 network cases /102 assertions PASS**: TCP off/prefer/required, idle cover,
  stealth,three bonded TCP streams,and UDP recordizer/legacy. Identical post-load
  IPv4 pings have no loss; idle cover gaps vary in both directions.
- Fresh **18-case matrix /327 assertions**,aggregate IPv4/IPv6 leak and
  **100 TCP +100 QUIC path flips /33 soak checks PASS**;separate **24 REALITY-TLS/H2 checks**.
- Independent Windows x64,macOS universal,Android arm64/x64 A/B artifacts,consumer
  copies,exports and provenance PASS. This is not fresh installed application E2E;
  Mac/router/Windows VM runtime was excluded by the user.
- Full .10/.11 snapshots,active services and executables preserved;no replacement.

## Measurements on this lab

Identical directional iperf workload:6 seconds plus a separate warm-up second.
The three-bonded-stream case offers three parallel inner TCP flows.

| Mode | Upload,Mbps | Download,Mbps |
|---|---:|---:|
| TCP required,shaping off | 1041.93 | 1572.58 |
| TCP required,idle cover | 1480.05 | 1563.94 |
| TCP stealth 2Mbps,single stream | 1.89 | 1.92 |
| TCP stealth 2Mbps,three streams aggregate | 1.81 | 1.75 |

This is a local virtual topology,not a WAN benchmark. Uncapped measurements vary
with CPU/capture load;the idle-cover comparison does not demonstrate acceleration.
The rate result establishes that stream count does not multiply the cap;startup
credit may still permit a burst.

UDP **deliberately retains idle cover only**:both peers disable stealth. The first
fixture incorrectly expected a UDP cap and stopped. Eight PASS cases were retained;
only the two remaining cases reran against the documented TCP-only contract. This
was a fixture error,not a product regression or new UDP feature.

Header PCAP retains timestamps,original wire lengths and packet headers. The first
full captures retain source/derived transform hashes;only verified inactive remote
copies were reclaimed,local evidence remains. Ciphertext bodies are unnecessary
for this analysis. No vendor DPI resistance or universal absence of periodicity is claimed.

## Evidence and next work

Registry:`release/certification/evidence/q13-shaping-20261004.json`.
Raw:`../audit-debt-20260924/q13-shaping-20261004` relative to the audit worktree.

Next within Q13:recordizer/reassembly semantics,combined padding/normalization,
dormant UDP stealth branches and extreme timer review. This batch's five fixes
were verified immediately;the remaining section is not marked DONE.
