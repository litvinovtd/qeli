# Q28: macOS forwarding ownership and recovery

<!-- normative-sync: audit-q28-macos-forwarding-v1 -->

**5 October 2026: managed stage PASS. Q28 IN_PROGRESS, plan 27/37 (73.0%), 10 sections remain. Actual Mac USER SKIPPED.**

## Fixes

| ID | Problem and change |
|---|---|
| F262 | Previous sysctl values existed only in memory; another client could adopt an enabled flag and the first could disable it. Before kernel mutation, an exclusive single-owner Qeli journal records PID, UTC start ticks and unique token. A cooperative lock spans claim/recovery/release. Live owners are preserved; the same generation never overwrites its original snapshot. |
| F263 | IPv4 restore failure skipped IPv6; zero sysctl exit was treated as confirmation. Each family is processed independently with read-after-write confirmation. Confirmed progress is checkpointed; failures retain the journal/controller for retry. BeforeTunDispose refuses until forwarding restoration succeeds. |
| F264 | Process loss had no durable recovery; unknown publication/deletion outcomes could lose cleanup responsibility. Root startup recovers only dead owners. The strict 4096-byte journal refuses unknown/duplicate/missing fields, invalid UTF-8 and metadata. Partial publication/checkpoint/deletion is handled; a missing journal after native mutation means unknown cleanup. Observer failure cannot undo confirmed cleanup. |

## Checks

- forwarding-selftest: **58/58 PASS**. Production coordinator with injected sysctl/storage boundaries; also real isolated file storage, current-process UTC lifetime and two competing controllers. Cases include live ownership, same PID/different token, initially enabled flags, partial enable/restore, unchanged flags after successful exit, checkpoint/delete failure, cleanup retry, strict payloads and recovery by a new coordinator.
- Old forwarding transitions were extracted from VpnTunnel; only logging and native read/write boundaries were replaced. **6/6 expected FAIL**: competing claim, disabling another client, lost restart state, skipping IPv6 after IPv4 failure, missing enable and restore confirmation. These are six scenarios, not six independent defects.
- Fresh related checks: per-app **22**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**; total **1208 managed PASS**. Three Release builds and baseline build have zero warnings/errors. The initial harness CS0407 failure is retained; lambda adapters were corrected before fresh build/selftests.
- Docs/bindings/panel/diff PASS. Native source digest and all 14 native hashes remain unchanged. Three Shared DLL copies match byte-for-byte; current managed artifacts and source inputs are pinned in source-proof.
- Actual macOS sysctl, root fd operations/flock, launchd, separate-process crash, utun and NetworkExtension **USER SKIPPED**. File storage plus a new coordinator validates logical recovery, not Darwin crash/runtime behavior.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-forwarding-20261005.
Evidence: release/certification/evidence/q28-macos-forwarding-20261005.json.

## Behavior and boundaries

For ordinary utun profiles with forward=true, one active Qeli forwarding owner is allowed per Mac, including initially enabled flags and disjoint families. Another profile fails before sysctl; stop the first owner before switching. Forwarding alone does not configure NAT/firewall/external routing. No new INI settings; journal JSON is an internal recovery DTO, not user configuration. The per-app branch does not acquire this global lease.

Recovery returns only Qeli-modified flags to their saved off value; initially on flags are not disabled. Coordination covers Qeli users of this journal. Another tool independently writing the same sysctl=1 is indistinguishable from Qeli's value, so preserving its intent is not guaranteed. Direct root journal replacement is unsupported. Unknown/corrupt state refuses automatic cleanup; do not blindly delete the journal or start a competing forwarding profile.

Each sysctl command has a 3-second budget; this is neither an overall operation deadline nor guaranteed interruption of arbitrary Darwin syscalls. This recovery concerns forwarding, not full DNS/routes/TUN recovery. UTC identity applies only to the new journal; old DNS/PF stamps are not migrated by this change.

Remaining Q28: guardian ready/owner-generation, native socket lifetime and connect/write bounds, final integration review. Historical release case artifacts/timestamps and physical rows are preserved. No fresh Linux/JNI/soak/benchmark results; network, services, lab and user profiles were untouched. No push/deploy.
