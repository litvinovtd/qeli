# Q32: trusted notification INI and delivery correctness

<!-- normative-sync: q32-notifications-v1 -->

8 October 2026. Scope: notification INI, process cache, outbound HTTP/URL/address
boundary and panel error redaction. Configuration remains INI; JSON is service traffic.

| Finding | Defect | Resolution |
|---|---|---|
| F389 / Q32-F010, P1 | Stable INI reader discarded its trust metadata; a panel save could authorize attacker-writable contents | Check owner/mode/type before parse and conditional save; no permission upgrade |
| F390 / Q32-F011, P2 | Fragmented status lines exhausted eight reads; arbitrary second tokens and 3xx were treated as delivery; malformed response text could echo secrets | Bounded 4 KiB complete HTTP/1.0–1.1 final status, 2xx success, generic errors |
| F391 / Q32-F012, P2 | Query-only URLs corrupted authority and fragments were sent in request targets | Split query from authority, prepend `/`, omit fragments, reject spaces/control bytes |
| F392 / Q32-F013, P2 | Special-use/documentation/benchmark/transition destinations bypassed the public-address policy | Conservative IPv4/IPv6 range guard, including mapped IPv4 |
| F393 / Q32-F014, P2 | External replacement after save paired B's metadata with A's cached settings indefinitely | Invalidate cache after publication; reload stable current INI next event |
| F394 / Q32-F015, P2 | Cached metadata followed a symlink to the previous regular file and bypassed direct-reader refusal | Stamp the directory entry with symlink_metadata; only regular entries can hit cache |

The status reader intentionally refuses interim 1xx and does not implement a general
HTTP response parser. Redirects are not followed. Address selection checks each candidate
before use and dials a validated address directly; mixed DNS answers do not cause an
unvalidated address to be dialled. This is a conservative application policy, not an
exact IANA globally-reachable classifier; some special globally reachable exceptions,
internal webhooks and NAT64 are unsupported. Primary range references:
[IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry) and
[IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry).

## Verification

Extracted exact production helpers: old source 3 PASS / 3 expected FAIL; fixed source
6 PASS with separate fresh targets. This qualifies helpers, not TLS, queue or config.
The full library additionally tests unsafe INI rejection and preservation on attempted
panel save, safe mode recovery, symlink refusal and malformed status/URL/address cases.

A derived example uses the actual public library and its queue in private Linux
network/mount/PID namespaces. `8.8.8.8` exists only on namespace loopback; there is no
external uplink. It verifies real request body/target, 204/201 success, 302 refusal,
fragmentation, no reflection of a fixture secret, special-address refusal, TLS-to-plain
refusal and shutdown refusal. The redirect trap uses its actual bound port.

A separate test-only fsync interposer replaces the sidecar at directory fsync after
atomic publication. Both binaries load B from disk; the baseline actually emits A,
while the fixed binary emits B on the next real HTTP event. The interposer changes only
the fixture's `/etc/qeli` file inside a private mount, never production code or a host
config. This is a writer-order reproduction, not a power-loss/durability qualification.

Final Linux source is `afa627069b01577bc3a14f0d956be82f6d934c41`: 2439 library tests
PASS, 60 preexisting ignored; strict all-targets Clippy and debug daemon qualify the
same source. Native qualification and final raw seal are recorded in machine evidence.
No ignored test is counted as PASS.

Preparation failures are retained: incorrect generic-function extractor, shared harness
target reused baseline bytes, initial source-verifier typo, HTTP fixture wrote after
status-reader close, and a corrected owned-string lifetime in the derived example and a local encoding alias typo.
The early desktop producer `47c973c3` completed A/B but source-change provenance refused
publication after the cache fix; it is not relabelled as a final-source build.


The additional actual-library cache check reproduces the symlink bypass on `7f5887f3`; the corrected repeat covers chmod rejection, safe-mode recovery, symlink rejection and regular-file recovery.

## Remaining boundaries

This is not external Telegram receipt, positive publicly trusted TLS integration,
browser DOM, managed app/VPN E2E, ARM runtime or Mac/iOS/router/Windows VM networking.
Queue deadlines, drain and cancellation retain their existing tested contract; regular
filesystem/NSS operations cannot be force-interrupted. Admin-chosen labels/details are
message contents, not secrets identified by an arbitrary log-text scrubber. Packet trace
stores metadata, not packet payloads or configuration credentials.

Roaming counters were reviewed at their actual call sites: worker/profile lifetime,
independent relaxed snapshots, attempt after locator lookup, commit after final ACK
write, failures also on detach, separate grace expiry. Therefore outcomes are not a
partition and `attempts = commits + failures` is not a supported invariant. Existing
Q23 runtime evidence and current module tests retain their stated scopes; no fresh
handover/soak is claimed here.

Q32 DONE within the documented Linux/server scope after five-criterion reconciliation.
Q29 SIGKILL/automatic-null ENONET, Q30 callback drain and Q31 release pipeline/writer
coordination remain open. Platform exclusions and D06 ACCEPTED_LIMITATION are retained.
Overall 29/37 DONE (78.4%), eight remain; old debt register 14 DONE plus D06 accepted.
No push, deployment or release.

[Machine evidence](../../../../release/certification/evidence/q32-notifications-20261008.json).

## Combined Q32 closure

Sixteen exact Git source/region comparisons preserve the original scope of metrics,
namespace identity, usage/control/atomic publication, logs/trace and Q23 roaming
counters/control/soak fixtures. Prior execution is reused, not relabelled as fresh.
Q23's bounded TCP soak reads actual attempt/commit/failure/grace/gauge counters;
its equality check applies only to that success-only scenario. Current full library
tests exercise these same modules. Only notification/config-notification files
changed since the latest log/trace producer.

All five Q32 criteria are dispositioned with source review, positive/negative/fault
and concurrency tests, actual Linux I/O integration and final fixes/evidence. Four
final native cores pass A/B/export checks; Windows ABI22 and Android ART JNI23 pass
on the final bytes, preserving the original AVD userdata/packages/links. Desktop A
reuses its own partial cache after the deliberate interruption; B is independent.
No cold/hermetic build or new physical runtime claim. Native SHA/provenance and
docs/bindings/diff checks pass. Remaining limitations above describe the supported
feature/available test scope and are not silently promoted to PASS.
