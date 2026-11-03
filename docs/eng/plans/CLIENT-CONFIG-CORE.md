# Shared client configuration and policies

<!-- normative-sync: client-config-core-v3 -->

**Reconciled 16 October 2026:** the shared ABI 1.16 core and client adapters are implemented. Committed Windows/macOS/Android libraries passed independent A/B builds, ABI/JNI, hashes and provenance; platform builds and available runtime scenarios were checked. [Post-dependency-update evidence](../../../release/certification/evidence/dependabot-integration-20261016.json). Excluded physical platforms are not PASS; 0.8.2 remains unpublished. The dated migration stages below retain their initially open gates.

Historical state on **2026-09-22**: source migration to Rust implemented; Apple verification and
rebuilding committed release libraries remain mandatory before release.
Related: [system audit](FULL-SYSTEM-AUDIT.md), [key matrix](../reference/CLIENT-CONFIG-MATRIX.md),
[transport core](../reference/TRANSPORT-CORE.md).

## Implemented consolidation

The existing Qeli native library now exposes ABI **1.16**. There is no separately downloaded
parser: app and core ship together. Profile files remain **INI**; `qeli://` is a portable
subset. JSON is an internal FFI/JNI service DTO, never a configuration-file format.

| Shared owner | Responsibility |
|---|---|
| `qeli/src/config/editor/` | INI/URI import, document edits, diagnostics, validation, export, runtime/probe projection |
| `editor/schema.rs` | 81 `[qeli]` fields and 3 `[logging]` fields, types, defaults and adapter property mappings |
| `scripts/gen_config_bindings.py` | Generated C#, Kotlin and Swift projections/default constants; `--check` prevents drift |
| `config/client.rs`, `share.rs`, `format.rs` | Canonical configuration/link grammars; runtime uses the same document service |
| `config/policy.rs` + existing `transport_core/network.rs` | IP/CIDR algebra, exclusions, route limits, local subnet decisions, LAN exclusions and capture routes |
| `config/route_file.rs` | CIDR/OpenVPN route-file grammar, masks, normalization, order, deduplication and error line numbers |
| `config/policy.rs` | Retry budgets, backoff/jitter, start-to-start floor and connected-session counters, version comparison, full-tunnel classification, roaming eligibility and private update-path requirements |

Windows/macOS share `QeliShared/Model/ConfigCore.cs`; Android uses `ConfigCore.kt` and real
JNI; iOS uses `ConfigCore.swift` and C ABI. Local parsers, validators, INI/URI serializers
and these algorithms were removed from client models. Models/generated code project data;
there is no fallback parser. Linux calls Rust directly, including retry decisions, counters and delay calculation.

## Document contract

Requests use `version = 1`. Operations: `schema`, `import`, `export`, `validate`, `runtime`,
`uri`, `probe`, `policy`. Responses contain `ok` and `result` or `error`.
`schema` describes types, defaults, numeric projection ranges and sensitivity, rather than
claiming to describe every cross-field or platform constraint.

- INI `import` opens repairable drafts. Duplicates, unknown fields and malformed scalars
  retain diagnostics and source values. Structurally invalid endpoints/INI can be refused.
  URI import validates immediately.
- `export` preserves drafts: absent and explicitly empty differ. Repeated lists and foreign
  fields survive. Comments, indentation and original case are not preserved.
- `values` overlays changed form values on `source`; `patch` explicitly updates INI names,
  with `null` deleting a field. Clearing an invalid scalar's `unresolved` marker confirms
  a form repair even when its new value equals the displayed default.
- `validate`, `runtime` and `uri` reject errors. A duplicate displays the first value in a
  draft but cannot select a live endpoint until the ambiguity is removed.
- `runtime` materializes common defaults. The iOS projection omits desktop `kill_switch`
  while retaining it in the portable document; NetworkExtension/On Demand stays OS-owned.
- Legacy `dns = <IP-list>` migrates to `dns_servers`; an explicit `dns_servers`, including
  an empty one, wins. Legacy mode normalization has one owner.

Common client defaults are **`gateway=true`, padding `0..255`, `heartbeat_jitter=2000` ms**.
This changes CLI profiles that omitted these keys. Set `gateway=false` explicitly to keep
the previous split tunnel, and set desired padding/jitter explicitly when retaining their
old values. Server-profile defaults are unchanged.

## Additional candidates and boundaries

| Area | Decision |
|---|---|
| `route_file` parser | Moved. C# keeps file I/O, cancellation, bounded batches and merging files. Mobile preserves foreign paths without reading them |
| Routes/reconnect | Portable calculations moved. OS route apply/rollback, timers, sleep/wake and network events stay in adapters |
| Updates | Comparison and private-path requirements moved. Network binding, signing, installation and the fact that the app is captured remain platform responsibilities |
| Secrets | Diagnostic redaction/sensitivity in core; DPAPI/Keychain/Keystore, ACLs and store migration remain OS-specific |
| FFI | Configuration projections are generated. Full transport/event/path binding generation is outside this migration; existing ABI gates remain |
| Managed/Swift Crypto/Protocol | Production reachability was checked first. Some code is an independent conformance/benchmark reference, not a fallback production transport; it is retained deliberately |
| Protection summary UI | Shared routing facts moved; platform capability presentation stays in UI. iOS never claims unmanaged per-app rules are enforced |

## ABI, builds and verification: 22 September stage

`qeli_config_request` has no session, DNS, file I/O, network or `password_command` execution.
C ABI uses caller-owned buffers, 2 MiB request/4 MiB response/256 KiB document limits and
panic containment. Adapters clear temporary secret-bearing byte buffers. Managed/Swift/JVM
strings and the original profile do not provide guaranteed erasure of every memory copy.

Development/CI commands from repository root:

```sh
python scripts/gen_config_bindings.py --check
python scripts/build_client_core.py --debug
```

The build prints `QeliNativeCorePath` for dotnet and `QELI_CONFIG_NATIVE_LIBRARY` for JVM
tests. Set those variables before building/testing. With default Cargo paths, output is
`qeli/target/client-core/host`. `--github-env` forwards paths to subsequent Actions steps.
For Android, install the pinned NDK/cargo-ndk and Rust targets, then run:

```sh
python scripts/build_client_core.py --android
```

Set the printed `QELI_NATIVE_JNI_DIR` before Gradle: it replaces all jniLibs inputs instead
of mixing new and old cores. iOS uses `qeli-ios/build_native.sh`. CI builds fresh host
libraries for .NET/JVM, Android libraries for APK/emulator and the iOS XCFramework.
An old ABI never activates a local fallback; ABI 1.16+ is required.

Dev/CI builds do not rewrite release artifacts or provenance. Committed libraries still
need independent A/B builds through `scripts/build_native_libs_p4.py` and
`scripts/build_android_so_11.py`, followed by `native-libs/verify.sh` and
`native-libs/provenance.py`. Those recipes require clean committed source and lab access.
The source/artifact gate remains enabled and will correctly fail until rebuilding.

Local verification covers Rust unit/integration, real C ABI via C#, real JNI via JVM,
Windows selftest, Linux cross-check/Clippy and generated bindings. Apple build/tests, real
devices, release A/B and final packages remain separate unfinished gates; configuring CI
is not evidence that those gates have run for this change.

## Runtime reconnect audit — 22 September 2026

All lifecycle adapters now call the same Rust counter/decision/delay policy. Linux calls
it directly; C#, Kotlin and Swift use `next_attempt` and `retry_decision` through the
configuration service. `connected_ms` is monotonic time in the established session;
`elapsed_ms` in the delay request is time since the attempt started. These are distinct.

Fixed: slow handshakes/desktop cleanup falsely satisfying the stability threshold;
Linux retaining old failures after an established session ended with an error; Android
waiting for a carrier before checking disabled/exhausted retries; desktop settling caps
and mobile carrier restoration erasing finite budgets; iOS roaming fallback counting as
an ordinary failure; the largest accepted retry limit never exhausting a saturated 32-bit
counter. Carrier generation and Linux diagnostic totals no longer reset with the budget.
SIGINT/SIGTERM also wakes a pending Linux backoff and reaches cleanup without a new dial.

The common start-to-start floor is 1.5 s. Only delay is shortened by desktop settling or
mobile carrier restoration; an exhausted budget still stops. The [manual](../manuals/CONFIG.md)
spells out `reconnect_retries=0` versus `reconnect=false`. Platform route cleanup, timers,
network observation and terminal security/kick handling remain adapter responsibilities.

## Configuration boundary audit — 22 September 2026

Eight regression scenarios were reproduced on the pre-fix code: controls removed from
keys/values; overlay names that do not survive serialization; lost legacy DNS duplicates;
BOM bypassing strict URI validation; credentials exposed in patch/URI/uppercase-INI errors;
malformed `dns_servers` erased during migration; dotted `logging.*` in `[qeli]` aliasing a
real logging-section field. Each received a shared-core fix and regression coverage.

The eighth scenario was URI controls disappearing during INI conversion, changing an
endpoint, transport or server key. Canonical `ClientLink` now checks decoded values
before normalization, also covering panel imports.

`IniDoc` now rejects unsupported controls before trimming/serialization, covering server
configs as well. DNS normalization retains errors and returns consistent `source`/`raw`.
Error redaction covers `values`, `patch`, case-insensitive INI keys and decoded URI credentials.
Client model tests exercise real open/clone/copy/save/reopen paths; Swift tests were added
but still require execution on Apple.

## Parameters before runtime — 22 September 2026

Q02-F015–F019 fix malformed zero PINs becoming TOFU, missing shared host checks and
an unsupplied port being repaired during a partial edit. One address grammar now covers
INI, URI, runtime and panel public endpoints. IPv4/IPv6, localhost, ASCII/Punycode and
local `_` names remain supported. The panel's old pre-validator is removed; saves,
summaries and device discovery use the same parser. Explicit/automatic dev handling
honors BOM and client case rules while retaining comments. Command/path restrictions
remain enforced. The Linux boundary unit test still needs execution; cross-Clippy
confirms compilation. See the [Q02 register](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md).

## Verified local run — 22 September 2026

- Rust/Windows: 655 unit + 51 editor/FFI + 7 examples + 12 server-INI — PASS.
- C# with the new Release DLL: 466 conformance; Windows: 143 selftests — PASS.
- Kotlin/JVM using the same DLL through JNI: 154 tests, none skipped — PASS.
- Windows and macOS managed Release builds — PASS; macOS runtime was not run here.
- Linux cross-Clippy: all-targets PASS on Rust 1.98 with one exception,
  `clippy::chunks_exact_to_as_chunks`, for existing NDP code. The minimal FFI build
  passes `-D warnings` without exceptions; CI lint is pinned to Rust 1.97.
- Generator, 69 native-contract tests, rustfmt, 9 documentation checks and diff-check — PASS.
- Release provenance — expected FAIL (`STALE NATIVE CORES`): committed binaries are
  not rebuilt. iOS/Xcode, Android NDK/emulator/device, Linux runtime E2E, fuzz-run
  and a new benchmark were not executed in this local run.

These results verify the source migration and host C ABI/JNI integration;
they do not complete platform certification or package delivery.

D08/D11/D12: [Android JNI and emulator runtime](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-RUNTIME.md): fixed cargo-ndk cwd/API flag, removed the obsolete JSON-config harness; 154 JVM + 6 instrumentation tests PASS. The fresh dev x86_64 APK is SHA-verified. Release A/B, the full config/runtime contract and other platforms remain open.

Reconciliation on 2 October: Q25-F210 closes available D08 — store ownership, 511 .NET/167 JVM/12 Android instrumentation; iOS read-only fix reviewed statically, Apple runtime SKIPPED by user decision. Earlier limitations above are historical; final native/certification refresh remains D15.

[Q25-F210](AUDIT-DEBT.md)
