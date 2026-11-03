# Q28: macOS daemon, helper and observation

<!-- normative-sync: audit-q28-macos-control-v1 -->

**5 October 2026: stage PASS; Q28 IN_PROGRESS. Plan 27/37 (73.0%), 10 sections remain.**

## Fixes

| ID | Problem and resulting behavior |
|---|---|
| F243 | Daemon Load hid failures, accepted plaintext/null fields and could create replacement keys. The codec now validates structure/size/strict UTF-8 and requires authenticated encryption. Only absence returns null; Load cannot create keys. Exclusive first-key publication rereads the persisted winner. Size rejects before key side effects. |
| F244 | GUI could fall back to another profile, mutate its logging settings or publish before Stop. Shared DesktopServiceProfileTransition now handles Windows/Mac: exact snapshot, validation before Stop, completed Stop before Publish and resume according to connection intent. Settings edit a clone. Mac root controls hold a reentrant private file lease across the transition. |
| F245 | Heartbeat overwrote Start/Load/cleanup errors; partial Start lost shutdown cleanup ownership. DaemonLifecycle records ownership before Start, retries Stop, refuses restart/polling after cleanup failure and synchronizes status/detail publication. Shutdown publishes final Error even if it throws. |
| F246 | Stale/future/unknown status looked connected; logs bypassed trust checks and same-sized rotation vanished. Shared status validation checks canonical enum/time/counters/detail. Mac enforces freshness, bounded trusted UTF-8 reads, visible stale Error, append/replacement delta and capped/rotated log writes. |
| F247 | Existing plist could execute another binary or override execution; XML characters in paths broke registration. Trusted descriptor reads validate current/legacy labels, executable/arguments/root identity/settings before mutation. XML paths are escaped. Nonblocking no-follow opens prevent FIFO stalls before type validation. |
| F248 | Tool deadlines missed pipe EOF, output growth or successful outcome; ownership/autostart errors were swallowed. ToolProcess caps both streams and process/pipe waits; exit 0 cannot bypass an outcome callback. Bootout uses one 30-second query budget; unknown errors do not prove absence. Ownership/autostart errors propagate. |

Removed dead ServiceManager Run/Run2, IsRunning and ambiguous LaunchdHasTarget wrappers. JSON is internal IPC/DTO/encrypted archive data; external configurations remain INI-only.

## Verification and limits

- Release Mac, Windows, shared conformance: PASS, zero warnings/errors.
- Mac control-selftest: **83/83 PASS**. Codec/digest/null/UTF-8/size, transition/refusal ordering, snapshots, partial Start/repeated cleanup, status freshness/enum, logs, plist, key races, lease contention/release.
- Real isolated child processes: two 32 KiB output streams, nonzero exit, stalled deadline, output overflow, missing executable, exit 0 without outcome and early confirmed outcome.
- Mac storage-selftest: **54/54 PASS**, fresh after envelope/shared changes.
- Windows selftest: **325/325 PASS**; shared conformance: **549/549 PASS**, fresh after shared source changes.
- Baseline: **5/5 expected FAIL**, exit 1. Original LoadProfile/ReadStatus/Plist/envelope bodies; only reads/key/save/executable path injected. Plaintext accepted, corruption hidden, required-null accepted, numeric status accepted, unescaped path invalid XML.
- Docs, bindings, panel, diff, unchanged native provenance/14 checksums: PASS.

Real profiles/keys, installed services, host/lab networking were not touched. Windows qeli.dll supplies shared computed DTO getters only; not Mac dylib/ABI qualification. Lease tests use the production coordinator with isolated Windows FileStream acquisition. Native flock/openat/renameatx_np are source-reviewed, not executed.

Actual Mac/launchd/Keychain/Darwin/private-mode/Intel-ARM/authorization runtime remain **USER SKIPPED**, not PASS. The lease serializes cooperating Mac controls; it does not bound its owner's whole operation or protect against root edits. Windows retains its per-instance transition gate; no new cross-process Windows guarantee. Pipe cancellation bounds the caller, without guaranteeing termination of already orphaned descendants. Managed timers cannot forcibly interrupt native prompts/OS I/O.

Exact launchctl absence text is a conservative fixture, not a documented stable modern CLI contract: unknown/localized/changed errors fail closed. Foreign/malformed registrations require explicit administrator repair. Status has no process/profile-generation attestation; configured-profile text is not active-worker identity proof.

Primary contracts: [Darwin descriptor/flock flags](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h), [exclusive rename](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/stdio.h), [launchd settings](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/man/launchd.plist.5).

Raw snapshots: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-control-20261005. Evidence: release/certification/evidence/q28-macos-control-20261005.json.
Next: utun/routes/pf/DNS cleanup/roaming, Swift Network Extension/entitlements and build contracts. Q28 remains open. No fresh Linux/JNI/soak/benchmark qualification.
