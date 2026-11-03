# Q02 — client parsers: links and import boundaries

<!-- normative-sync: audit-q02-client-parsers-v2 -->

Date: **2026-09-22**. Base: `fc6f4a5d` plus working Q01 fixes.
Overall section status: **IN_PROGRESS**. This report includes the initial URI pass and continuation after core migration.
The common contract has 81 client fields and 3 logging fields; platform scenarios
and complete runtime validation remain open.

Related: [system plan](../../plans/FULL-SYSTEM-AUDIT.md),
[shared configuration core](../../plans/CLIENT-CONFIG-CORE.md).

## Confirmed findings

| ID | Priority | Before | After |
|---|---|---|---|
| Q02-F001 | P2 | Known query parameters silently overwrote earlier occurrences. `key=<pin>&key=` removed the pin; repeated MTU changed the setting. | Duplicate known parameters are rejected before a profile is created. Unknown extensions retain compatibility: they are ignored, including repetitions. |
| Q02-F002 | P2 | `mtu=abc`, malformed AWG numbers and type overflow became defaults. Languages accepted different numeric forms. | Strict numeric syntax and representation limits reject NUL, whitespace, negative unsigned values and overflow. Existing fallback from a syntactically valid numeric MTU outside the operational range to auto is preserved. |
| Q02-F003 | P2 | `quic=maybe`/`awg=maybe` became false. Rust interpreted `quic=TRUE` as false while the GUI clients interpreted it as true. | One case-insensitive set: `true`, `false`, `1`, `0`. Other values are errors. |
| Q02-F004 | P2 | Rust/C#/Kotlin replaced invalid UTF-8 credential bytes with U+FFFD; Swift retained the original encoded text on failure. Bad percent sequences could pass literally. | Invalid escapes and UTF-8 are rejected. Valid Unicode, literal `+` and `%25` survive. Fragments are checked too. |
| Q02-F005 | P2 | `awg=1&jc=4` created Rust sizes 0/0 but GUI sizes 40/300. Large and reversed sizes were normalized at different layers. | Shared defaults 40/300 and import normalization: count ≤128, sizes ≤1400, min ≤max. |
| Q02-F006 | P3 | Editing `conformance/qeli-links.json` did not invalidate Android/JVM tests: Gradle reported UP-TO-DATE. | The shared conformance directory is declared as a Test input with relative path sensitivity. Corpus edits rerun tests. |

The initial pass updated production Rust, C#, Kotlin and Swift URI parsers.
Those independent implementations were later replaced by one Rust parser and adapters. Swift changes were
reviewed in source but **not built or executed** here. This remains open rather than
being inferred to pass from other languages.

## Initial URI-pass reproduction

First, 18 invalid and 5 valid cases were added to the existing common corpus. Before
fixes, Rust accepted all 18 invalid cases and failed the positive AWG check (0/0 instead
of 40/300). C# accepted 17 invalid cases; Android/JVM failed its reject test. Further
boundary cases cover unsigned -0, trailing NUL, numeric whitespace, maximum u32 AWG count
and reversed sizes.

The final corpus has **21 valid + 29 reject** cases. Its format is existing conformance
runner test data, not a configuration-file format; profiles remain INI.

Q02-F006 was tested separately. Before the fix, a corpus edit yielded
`testDebugUnitTest UP-TO-DATE`. After declaring inputs, only a comment in the same file
was changed. Gradle reported:

```text
Input property 'sharedConformanceFixtures' file .../conformance/qeli-links.json has changed.
```

The task actually executed and passed. This verifies invalidation, not merely the
presence of a new build.gradle.kts line.

## Initial URI-pass verification

| Suite | Result |
|---|---|
| Original Rust config tests | 129 PASS |
| Final portable Rust tests, including Q01 | 632 unit + 7 examples + 12 audit = 651 PASS |
| Full shared C# conformance selftest | 438 checks PASS, 0 FAIL |
| Entire Android/JVM testDebugUnitTest | 137 tests, 16 suites; 0 failures/errors/skips |
| Shared URI corpus on Rust/C#/Kotlin | 21 valid + 29 reject cases passed by each implementation |
| Rust/C#/Kotlin/Swift INI key-name contract | 4 checks PASS; 81 names |
| Linux all-targets cargo check | PASS; not runtime execution |
| Swift/iOS | Changes and fixtures prepared; build/test BLOCKED by missing Apple environment |

Commands from repository root unless noted:

```sh
cargo test --offline --manifest-path qeli/Cargo.toml --no-default-features --features transport-core-ffi --tests
cargo check --offline --manifest-path qeli/Cargo.toml --target x86_64-unknown-linux-gnu --all-targets
dotnet build qeli-shared/QeliConformance/QeliConformance.csproj -c Release --no-restore
dotnet exec qeli-shared/QeliConformance/bin/Release/net10.0/QeliConformance.dll selftest
python scripts/test_native_config_keys.py
python scripts/check_docs.py
```

From `qeli-android`:

```sh
gradlew.bat :app:testDebugUnitTest --offline --no-daemon --console=plain --max-workers=2
```

.NET used `QELI_CONFORMANCE_REQUIRED=1`. Cross-check used the existing Zig CC/AR
wrappers. Gradle still reports deprecated API/future Gradle 10 compatibility warnings;
these were not the cause of the regression failures.

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-q02-20260922/`:
`*-regressions-before.log`, `rust-final.log`, `dotnet-final.log`, `kotlin-final.log`,
`kotlin-corpus-invalidation-{before,after}.log`, `test-summary.txt`, `source-manifest.txt`.
`before/` preserves the pre-Q02 sources. Packaged native artifacts were not rebuilt;
these runs do not certify installed GUIs against newly packaged cores.

## Post-consolidation continuation — 22 September 2026

| ID | Priority | Before | After |
|---|---|---|---|
| Q02-F007 | P2 | INI controls could disappear during trimming/saving and change a key or value. | Shared grammar rejects unsupported controls before trimming; LF/CRLF and valid TAB survive. Server INI is covered too. |
| Q02-F008 | P2 | Editor patch field/section names could become comments, different names or malformed sections. | Nonempty names, edge whitespace, delimiters and controls are checked before mutation. |
| Q02-F009 | P2 | Legacy DNS migration removed a repeated `dns`, hiding ambiguity after saving. | Only a single `dns` can migrate; duplicates retain their error and refuse activation. |
| Q02-F010 | P2 | A BOM was recognized by the URI parser but bypassed strict import validation. | Document-kind detection uses the same preamble handling. |
| Q02-F011 | P2 | Error redaction missed credentials from patch, URI and differently cased INI keys. | Shared handling gathers sensitive values from all these sources and redacts messages. |
| Q02-F012 | P2 | DNS migration erased invalid `dns_servers`; returned `raw` lagged behind `source`. | Invalid DNS fields are not rewritten; valid migration rebuilds both representations together. |
| Q02-F013 | P2 | `logging.level` under `[qeli]` was interpreted as `level` in `[logging]`. | Field identity includes its actual section; the invalid entry remains editable and cannot activate. |
| Q02-F014 | P2 | URI controls disappeared during INI conversion, changing the endpoint, proto/mode or server key. | Canonical `ClientLink` rejects invalid decoded values before normalization. Panel import is covered too. |

All eight scenarios were first reproduced before their respective fixes. Q02-F014 checks
raw host controls and encoded controls in credentials, fragments and queries, including
`proto` subsequently overwritten by a legacy mode alias. Tabs in passwords/labels survive.
Parser errors do not echo input values.

Retest: **654 Rust unit + 47 editor/FFI + 7 examples + 12 server-INI**,
**460 C# conformance**, **143 Windows selftest**, **151 Kotlin/JVM, 0 skips** — PASS.
C# and JVM used one fresh Release DLL through real C ABI/JNI. Windows/macOS managed
builds, Linux cross-Clippy, 69 native-contract tests, 25 panel-editor regressions,
binding generation and 9 documentation checks — PASS. All-targets Clippy on Rust 1.98
retains a `chunks_exact_to_as_chunks` exception for existing NDP code; minimal FFI
passes `-D warnings` without exceptions.

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/config-boundaries-audit-20260922/`.
`before-*.log` record pre-fix failures, `before/` preserves this stage's starting sources,
`review.diff` isolates its changes, `verification.json` records results/hashes and
`RESULT.md` summarizes the stage. Swift regressions were added but not executed here.

## Parameters before runtime — 22 September 2026

| ID | Priority | Before | After |
|---|---|---|---|
| Q02-F015 | P2 | Any zero string (`key=0`, 63/65 zeros) was removed as TOFU before PIN length validation. | Only empty input and exactly 64 zeros mean no pin. Other malformed keys are rejected in both INI and URI. |
| Q02-F016 | P2 | INI accepted `server=host/path:443`, whitespace, `@`, brackets and empty DNS labels. Sharing could change address parsing; runtime received an invalid host. | INI, URI, direct runtime config and panel public endpoints share one IP/ASCII DNS grammar. Invalid INI remains editable but cannot activate or become a link. |
| Q02-F017 | P2 | Partial `values={user:...}` with `unresolved=[]` changed a bad port to 443 although no port was supplied. | A missing marker acknowledges a repair only when that field's value is explicitly supplied. |
| Q02-F018 | P2 | Before shared validation the panel ran the old `from_ini`/unknown-key path. Valid legacy DNS and repeated lists were rejected; summary parsing differed from runtime. | Saving, summaries and occupied-device discovery use the shared strict parser. Panel-only hook/password_command and path restrictions remain enforced. |
| Q02-F019 | P2 | Automatic dev insertion ignored client section/key case and BOM, creating duplicate sections or `dev`/`DEV`. | Explicit dev detection lives in the document service; insertion preserves comments and follows client case rules. Server sections retain their existing case sensitivity. |

Q02-F015–F017 regressions first failed on the pre-fix code; reproduction through the real
C ABI is also retained. Model tests exercise open/copy/save/reopen and strict URI import.
Positive coverage retains 64 zeros, ordinary 64-character pins, localhost, Punycode,
local names containing `_`, trailing DNS root dots, IPv4 and IPv6.
The automatic dev-insertion regression also failed before its fix. The panel's
legacy/list rejection was established from its previous validation path; a Linux unit
test covers valid profiles and hook/path restrictions. It passed all-targets compilation
but still needs Linux execution alongside HTTP/save E2E.
Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/runtime-config-audit-20260922/`.

Final local run for this stage: 655 Rust unit + 51 editor/FFI + 7 examples + 12 server-INI;
466 C# conformance; 143 Windows selftest; 154 Kotlin/JVM (0 skips) — PASS. Also passed:
69 native-contract tests, 25 panel-editor regressions, both Linux cross-Clippy variants,
managed builds, generator, rustfmt, diff-check and 9 documentation checks.


## Shared library status

The document/schema API is implemented inside the existing Rust core (ABI 1.16).
Clients call it through C ABI/JNI; independent config parsers are removed and projections
are generated. All 84 fields surviving model saves and this pass's fixes were checked locally.
See [shared module and platform boundaries](../../plans/CLIENT-CONFIG-CORE.md).
Configuration documents remain INI; the service DTO is not a profile format.

## Remaining work

- Complete parameter-to-runtime coverage and Linux startup/CLI/reload/HTTP-save E2E.
- Swift build/XCTest and actual QR/forms/storage/lifecycle on target devices.
- Large inputs, fuzzing, concurrency and additional diagnostic paths.
- Release native A/B rebuilds, provenance and installable-package validation.

Overall Q02 PASS is not claimed. The local host DLL does not replace release libraries.

## Section completion — 3 October 2026

**Q02: PASS within the agreed scope.** Reviewed INI/editor/URI entry points, panel
import before persist, native runtime, generated projections and C ABI/JNI. No
separate local INI/URI parser or silent fallback when the native core is absent was
found. Editable drafts may retain errors; runtime/validate/share require strict
admission. URIs carry connection essentials, not file-only or OS policy.
Syntactically valid numeric link MTU outside the working range retains the existing
auto fallback; malformed syntax/overflow rejects. Invalid pins never silently become TOFU.

Fresh packaged Windows DLL SHA `653522e6bade8fce705a12ec1566c4c119d49b27d55cb7ba088c018b2bd1dd92`:
eight groups PASS — 84 explicit field values in runtime text; 21 valid + 29 reject
URIs with expected-field and round-trip assertions; 15 independent INI boundaries;
1000 seeded drafts preserving values/raw and admission; unrelated edits; document/ABI
bounds; 128 parallel isolation/redaction scenarios with 16 workers.
These are 5630 service calls, not 5630 independent tests. No session/network was created.

[Machine reconciliation](../../../../release/certification/evidence/q02-reconciliation-20261003.json)
records DLL, fixture, review-input and local-driver hashes. `cargo` is absent from the
current Windows PATH; the attempted targeted Rust command did not run any tests.
The fresh result exercises the real C ABI, not Rust compilation.
D08 results are retained: 511 C# checks, 167 JVM (zero skips), 12 Android instrumentation.
All 164 adapter and 288 Rust hashes match; D15 covers native A/B/provenance.
These platform results are reused, not claimed as new executions.

The historical next-steps list above is reconciled. Apple build/runtime and unavailable
physical environments were skipped at the user's explicit request, not given PASS.
Individual network/OS effects, actual QR/UI and network lifecycle belong to panel/client
sections; bounded mutations do not close the full fuzz/DoS section 35.
No new confirmed defects or removable dead runtime parsers were found.
