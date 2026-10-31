# Q37: documentation and test harnesses — 11 October 2026

<!-- normative-sync: q37-documentation-baseline-v13 -->

**Status on 12 October: DONE within agreed scope; 32/37 (86.5%).** The execution history below retains previous intermediate statuses.

Q37-F001: the updater documentation edit removed versioned attestation examples from OPERATIONS while `sync_version.py` still required them in RU/EN. The baseline failed on two unmatched patterns. Both manuals now include `gh attestation verify` for the published amd64 0.8.1 package against litvinovtd/qeli; strict version checks remain mandatory. Five methods across RU/EN exercised current, stale, missing, development-versus-release examples and exact CRLF-preserving write repair. Actual `sync_version.py` and nine documentation checks PASS.

Q37-F002: `site/` is intentionally private/ignored; the test could not run from a separate Git checkout without its inputs. `--site-root PATH` selects the actual private website. Real RU/EN hub/install pages and clipboard behavior PASS; five negative scenarios (absent default inputs, invalid directory, unknown option, missing option value, removed event handlers in a temporary copy) refused. Five website input hashes match before/after. Missing website data never becomes SKIP/PASS. Website sources/publication were unchanged; this test does not qualify the whole static website.

The baseline also passed panel checks (11 templates/1160 RU strings), 118 editor checks and documentation. Additional 97 native harness tests and 18 certification gate tests PASS. These are tool unit/fixture checks, not actual A/B builds or successful release certification.


Q37-F003: [unreachable legacy implementation removal](../../../data/audits/audit_q37_dead_legacy_2026-10-11.json). Removed6320 lines after unconditional refusal from41 Python/shell files. AST proves only module docstrings and future annotations can precede Python SystemExit; each shell stub contains only shebang, stderr echo and exit1. Names/refusal messages remain so historical commands cannot become active; two messages no longer advertise the removed format. Unused scripts/client-config.json (1510bytes) was deleted; its only reference is a frozen historical fuzz-source inventory, retained unchanged. Total239053bytes removed.

42 actual Python refusal stubs (exit1/RETIRED, no stdout), three shell guards and current generated client bindings checked. The existing retirement test now rejects a body after refusal. That actual test failed when reading original source from the preceding commit;38 current recipe methods PASS. No historical SSH/deploy bodies were executed. INI/parser/runtime/native/benchmark inputs are unchanged; API/internal-model/test/evidence JSON remains permitted. Full feature-aware dead-code review across all modules remains open.

Q37-F004: [configuration/documentation parity](../../../data/audits/audit_q37_config_parity_2026-10-11.json). Dedicated client tables now cover all84 schema fields:81 `[qeli]` plus3 `[logging]`. Added three REALITY fields and complete AWG/shaping defaults; corrected gateway/TOFU/Android exclude/QUIC descriptions. The template explicitly retains `gateway=false`; the shared parser default is `true`. Exit-node comments moved to separate lines. Eight contract methods PASS; four actual methods with original RU/EN documents refused. Generated projections, versions and9 docs checks PASS.

Current factory CLI35da83fd in private network namespaces checked39 cases:16 corrected client INI examples,16 original examples and7 standalone templates; the real users.conf was loaded by four server checks.37 admissions succeeded and two original exit-node examples correctly refused. Endpoint/pin placeholders and three partial fragments per language were explicitly materialized. Inputs/commands/exits/SHA retained; admission proves no connectivity, hook execution or data plane. The first erroneous harness verdict is retained; fixed a regex crossing newlines and materialization of a documented pin placeholder.

**Full host gate FAIL retained:** three previously observed legacy FORWARD/MASQUERADE rules appeared in .10 iptables4/legacy4; other structural fields unchanged. No PASS conversion or exception. Only the owned inactive fixture was removed after full SHA inventory/identity checks; no VPN was started or existing rules/services modified. Native digest7d42e38f unchanged; Q35 continues on .11. Full Q37 and overall30/37 DONE81.1% unchanged.

Q37-F005: [server defaults and all CONFIG INI examples](../../../data/audits/audit_q37_server_parity_2026-10-11.json). Both references now explicitly document all134 scalar default assignments extracted from the profile/auth/web/logging INI readers. This source guard resolves serde default functions/literals/constants and distinguishes sparse roaming=false from new-template=true, and empty DHCP listen from its runtime fallback. It does not claim complete option/list/user/group coverage or Rust runtime default qualification. The actual guard refuses both original manuals; new checks run in CI.

Fixed server exit-node and panel inline comments, split auth/client binding settings into separate sections, and fixed overlapping multi-address listeners: the primary address must be specific when another address uses the same port. Completed default tables for bind/TUN/obfs, bonding, shaping, REALITY and global auth; clarified the enabled shaping budget. Client84-field contract remains PASS.

The current factory CLI35da83fd checked134 final cases:66 original and68 corrected examples/fragments across both languages. All expected outcomes were qualified:126 admissions and8 original refusals. Four sysctl inputs (before/after in each language) were excluded explicitly. Fragments received recorded section/minimal baseline context; documented endpoint/pin/PHC placeholders were materialized with inert fixtures. No connection, network plan, hook, panel startup or sysctl execution was tested. The first134-case attempt retained six failed verdicts (including a harness endpoint insertion into a comment); only changed/affected cases were rerun, nine extra invocations in total. All final materialized case hashes were reconciled with actual uploads/results.

All11 relevant contract methods, generated bindings, versions, nine docs checks and four-workflow actionlint PASS. First, third and fourth full host gates FAIL retained for .10 iptables4/legacy4 changes; the second gate PASS does not erase them. Every owned fixture was SHA/inactive-identity verified and removed; running services/firewall were untouched. Product/native/factory inputs unchanged. Full Q37 remains IN_PROGRESS;30/37 DONE81.1%. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.


Q37-F006: [optional/list/user/group defaults and boundaries](../../../data/audits/audit_q37_collection_parity_2026-10-11.json). Source coverage now inventories all176 consumed keys:123 profile,7 auth,23 web,4 logging,16 user and3 group. In addition to134 scalar defaults, the guard checks41 remaining defaults/82 RU+EN comparisons; the sole obsolete `tun.netmask` only warns and is ignored. This is source/table review, not execution of all Rust defaults. The new guard uses the existing CI glob. The actual method reading original documents found6 RU and4 EN mismatches; current12 contract methods, generated bindings, versions and9 documentation checks PASS.

Clarified empty/repeated lists, optional numerics, scalar types in disabled blocks, group ACL/positive-limit inheritance, strict malformed-listener refusal and nonzero REALITY short IDs padded to8 bytes. INI examples are unchanged. Factory CLI35da83fd checked74 scenarios plus8 REALITY boundaries:30 admissions/52 refusals. After correcting the erroneous refusal expectation for14 hex digits, all82 admission decisions match the contract. Original FAIL is retained. Cases include16/17 client_subnet,256/257 user routes,10000/10001 DNS blocklist, types, duplicates, metadata, routes, IPv4/IPv6 and groups; admission does not qualify connections or runtime inheritance.

In11 refusals the CLI lost the actual users.conf cause when converting `anyhow::Error` into a string. A shared formatter now preserves the cause chain in CLI, panel response, worker startup, SIGHUP and control/write/readback. Two Rust tests cover a nested parser cause and preservation of the IO error type. A bounded offline Rust probe with the exact helper/tests and four consumer formatting expressions reproduced0/3 PASS before and3/3 PASS after the fix. This is not a whole CLI build or qualification of corrected diagnostics in a new package: full rebuild/release qualification remains required. The old11 diagnostic FAIL results are not relabeled PASS.

**Host snapshots:** the original74-case matrix PASS; the Rust probe and extra REALITY matrix FAIL for iptables4/legacy4 changes, with other structural fields unchanged. No exceptions, rule removal or service modification. The first archive qualifier refused one tar hardlink; target membership and extracted-content SHA were verified without recompilation, preserving the original failure. The6138272-byte/64-file archive was fully verified; all three owned inactive roots were removed after SHA/cookie/process guards. Native source digest changed to317e722b; running Q35 and Q36 factory evidence still belongs to the old35da binary. Full Q37 IN_PROGRESS;30/37 DONE81.1%. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.


Q37-F007: [regression connections, dependencies and safe imports](../../../data/audits/audit_q37_reachability_2026-10-11.json). Reviewed 297 Rust files, 306 declaration edges and 5 entry points; no isolated file candidates were found. OS/features, JNI/C ABI, P/Invoke, Swift bridge, generators, router and host-test aliases were considered. The 74 dead_code allowances and 66 extern ABI sites are a lexical inventory, not proof that every function is used or that every platform works. Exported API and ownership descriptors were retained.

Removed the unused direct mio dependency and the production/server tower dependency. Tower remains an axum transitive dependency and a dev dependency for panel tests. Cargo 1.97 regenerated both lock files in a separate directory. Versions and checksums of all 235 main packages are unchanged; only qeli→mio and mio→log edges changed. Four actual locked Linux graphs (default/client-bin/transport-core-ffi/fuzz) differ only by removal of Mio default/log features; net/os-ext/os-poll and all other package/feature nodes remain. This qualifies the graphs, not each platform build. Legal resources are unchanged except lock binding/index; 235 packages and 532 entries were checked.

Of 127 test-entry files, 66 had no direct workflow connection. CI now includes 24 self-contained Python modules and a 14-case LuCI fixture. The current portable suite passed 104 tests on Windows; the Linux suite passed 149 tests without skips. Linux also passed 103 portable tests before the last import guard change, followed by both changed guard methods separately. Four admission guard methods check rejection of empty, incomplete, skipped and expected-failure suites and unknown groups. The 24 manual lab entrypoints, 16 suites requiring SDK/native/rootfs/kernel inputs and private site remain separate checks; they are not declared CI PASS. The new test reproduced rejection of the old workflow.

Router models now publish legal sidecars into temporary output. The new test rejected the exact old helper implementation. The first run's 1,474,055-byte sidecar was preserved with SHA verification, then removed by its exact path. Execution of 23 manual scenarios was placed under a main guard. All 24 scenario imports were checked on Windows and Linux without network actions or output. AST comparison confirmed unchanged bodies and string values; no external Python import consumers were found. The guard reported 23 failures and 0 errors against the 23 original files without running their network scenarios.

Rustfmt corrected layout of one users test and 7 fuzz targets; main/fuzz fmt --check passed. Initial lock/cache/format failures were retained. Missing pinned Linux fuzz crates were fetched by Cargo with checksum verification; both old and new locked fuzz graphs then passed offline. The 38 native recipe, 17 legal and 4 suite methods, plus actionlint for 4 workflows, passed. These are tool and fixture checks, not actual native builds.

All three external host gates remain FAIL: legacy4, then iptables4/legacy4, then iptables4/legacy4 again; other structural fields were unchanged. Running services, rules and binaries were not modified. The 9,298,152 / 9,255,680 / 89,099-byte archives and all 1712 / 1693 / 29 entries passed SHA verification; three owned inactive directories were removed. After the initial run, only lock/format repair and the two changed import methods were executed again; the 149 Linux fixtures were not repeated. Native digest 3538e06c is STALE: current builds and final certification remain required. Q35 continues on frozen35da. Q37 is IN_PROGRESS; overall progress is 30/37 DONE (81.1%). LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q37-F008: [local CI runner](../../../data/audits/audit_q37_ci_runner_2026-10-11.json). ci-check.sh ran tests and Clippy without --locked or pinned Rust and omitted minimal server/client/FFI profiles. It now obtains 1.97.0 from the shared native_repro contract and passes an explicit +toolchain to Cargo: a system Cargo without rustup must refuse. Every dependency-resolving command uses --locked. Added server-only/client-only checks, config_editor, transport-core tests and release build with panic=unwind, C header syntax, conformance freshness, fuzz formatting, minimal FFI Clippy and the qualified self-contained audit suites. This mirrors core local checks, not package/platform qualification.

The new test_ci_check is connected to the workflow and local runner. Five methods actually execute the shell with isolated fake cargo/python/node/cc children: invocation from another directory and paths with spaces, pin/lock/feature/panic policy, retaining Cargo failure while independent checks continue, Node failure, and early refusal of missing or malformed pins. All 5 passed on Linux without skips; a new method rejected the exact original runner, retaining its actual UNPINNED_RUST_REFUSED/UNLOCKED_CARGO_REFUSED output. Explicit Cargo selection was refined after the first fixture run; both results are preserved. The actual common pin was also read by a separate Python invocation. No Rust compiler ran: this qualifies the runner, not current Qeli compilation.

Both .10 runs took about 4 seconds with peak memory 20.4 / 21.3 MiB and zero swap. The initial host gate passed; the final FAIL remains in the artifact: iptables4 changed. Both owned inactive roots were SHA-archived and removed: 50,672 / 51,111 bytes with 9 entries each. Actionlint for 4 workflows and 4 admission guard methods passed. Native inputs remain 3538e06c STALE; the last read-only Q35 checkpoint reached TCP 5300/10000 and is still RUNNING. Full builds and certification remain open. Q37 is IN_PROGRESS; 30/37 DONE (81.1%). LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**Open debt:** `native-libs/provenance.py --check` detects changed native inputs (recorded e3fb04a8, current abcc1494). Real independent A/B builds of current desktop/Android recipes, binary inventories and subsequent provenance update are required. The stock CLI used for Q35/Q36 does not refresh client libraries. Android compilation on .11 waits for Q35 completion; the independent .10 compiler does not share its machine or test network.

Release certification reports 21 problems: its overall digest and all 20 automated Linux cases belong to another tree. The gate hashes the entire committed tree except its own evidence; new documentation/report commits also change that digest. Freeze final release inputs first, then execute and bind the matrix to that tree. Relabeling historical PASS under a new digest is prohibited. User-skipped physical platforms are not reported as tested.

Full Q35 endurance runs separately; Q36-F029 already qualified the finite current data-plane matrix in BENCHMARK. Intermediate Q35 is not declared PASS here. Full Q37 still needs compiler checks of code usage and feature targets, plus integration on current builds. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q37-F009: [actual minimal-feature unit suites](../../../data/audits/audit_q37_current_units_2026-10-11.json). Fixed two test harness defects: libtest's `--nocapture` label joined the first simulated preflight route line; the portable usage test called a directory-fsync failure helper restricted to Linux/server. The helper is now gated only by `cfg(test)`. Atomic-write production behavior and network deadlines are unchanged. CI and the local runner execute separate server, client-bin and transport-core-ffi library tests without default features.

Actual Rust 1.97.0 offline/locked/jobs1 results: all-target Clippy PASS, exact preflight regression PASS; server 2310 passed/56 ignored, client 1933 passed/49 ignored, FFI 1951 passed/49 ignored. Ignored fixtures are not qualified. Complete logs and their SHA bind 920 frozen inputs. Five Linux shell-policy methods passed; the new test rejected the previous runner missing minimal-profile tests. The CI fixture host gate retains an iptables4 delta FAIL.

After completion: all ten phases passed, including INI editor/examples/server-ini, conformance and the stock jemalloc release CLI with fat LTO/codegen1. The new CLI passed all eleven users.conf refusal cases, retaining the specific causes lost by the old binary. CLI SHA `886e525ed909037fafe8ea494094c7eb0c0a4f2a0e0f0e44f1cd68a3e966cff5` binds source `c69f9c9493412aede854cffe308a9a5b22a77c36`. This qualifies the build and those diagnostics, not full release integration or rebuilt native libraries.

The result packet is sealed. The 653036246-byte archive and all 17930 files passed SHA verification; the owned compiler directory and remote archive copy were removed. Temporary 2 GiB swap was disabled and removed; pre-existing swap was preserved. Host gates: collection PASS, cleanup FAIL; all deltas ['legacy4'] remain recorded. Rules and production services were not changed to obtain PASS. Original OOM and test failures remain archived. Native A/B and final certification remain pending. Q37 IN_PROGRESS;30/37 DONE81.1%.

Q37-F010: [current Windows/macOS native libraries](../../../data/audits/audit_q37_native_current_2026-10-11.json). The stock Windows FFI build with `-D warnings` exposed four dead-code errors: TCP counter snapshots compiled without a consumer. Their types, snapshot methods and Serialize import now compile for Linux/client and tests; loss counting remains in the shared core. The fix is bound to `de087865cf65609223a0a0e3970badd47e7116ed`.

Windows x64 and macOS universal x64/arm64 were built twice in independent Cargo/Zig target directories with Rust1.97.0, offline/locked/jobs1 and stock fat LTO/codegen1/panic=unwind. Both pairs are byte-identical. Exact 33 C ABI exports were checked for Windows and each macOS slice; the new DLL passed 22 C ABI/localhost checks without Wintun or route changes. Both TCP counter tests PASS. Initial harness refusals are retained: 12 missing test files, an empty linker placeholder and mistakenly treating the DLL name as an export. After adding files from the same commit, only the two tests were repeated; A/B was not rebuilt. The macOS cross-build retains Xcode SDK lookup warnings; physical macOS execution was excluded by the user and is not qualified.

Canonical and consumed Windows/macOS copies were updated with identical files; desktop evidence binds the current native digest. The 20981357-byte/407-file archive was fully checked; rebuildable caches were retained as a SHA inventory. Owned build roots and temporary swap were removed; original lab resources were preserved. Collection and cleanup retain host FAIL for legacy4. Android A/B/JNI, global PROVENANCE and final certification remain open; old evidence was not restamped. Q37 IN_PROGRESS, 30/37 DONE81.1%.

Q37-F011: [current Android native libraries and global provenance](../../../data/audits/audit_q37_android_native_current_2026-10-11.json). Android arm64-v8a and x86_64 were built twice from 327 frozen inputs at commit `b0b156c5625f2e10599065a63dd8e014b33f83ae` using Rust1.97.0, NDK26.3.11579264 and cargo-ndk4.1.2. Each A/B pair is byte-identical; stock offline/locked/jobs1, fat LTO/codegen1/panic=unwind and `-D warnings` were preserved. ELF64/architecture and exact names of all 55 exports per ABI were independently checked: 33 C API, 21 TransportCore JNI and one ConfigCore JNI.

Canonical libraries and consumed jniLibs copies were updated with identical files. Both desktop/android groups now have valid A/B evidence for the current native digest; global PROVENANCE was updated only after that validation. SHA256SUMS and every canonical/consumed pair check PASS. The source/log/result archive was fully SHA-verified; rebuildable caches were not duplicated. Owned directories, remote archive and temporary swap were removed, and the prior swap table was restored; actual host gates and changes remain in the evidence without exceptions.

This qualifies compilation and the exported API, not Android JNI/VPN execution. Android runtime/integration after Q35 and final release certification remain open. Previously described failures and historical evidence were not restamped. Q37 IN_PROGRESS, 30/37 DONE81.1%.


Q37-F012/F013: [current Android package and R8 rules](../../../../release/certification/evidence/current-android-package-20261011.json). Exact current Android inputs passed201 JVM tests through the current Windows ConfigCore JNI, failures/errors/skipped0. Lint:0fatal/0errors/55warnings; warnings retained. Instrumented Release/test APKs and a separate ordinary unsigned production Release contain the current arm64/x86_64 native hashes. Ordinary production ProGuard rules are unchanged.

Independent TraceReferences --check refused stale433-line instrumented ABI rules:18 of19 newly required types lacked their expected names in actual packaged DEX. Regenerated505-line rules and only the two affected APKs were rebuilt; all19 types are present, inferred rules and packaged Trace/superclass ABI PASS. This reproduces a build/packaging defect, not an Android runtime exception. Original refusal and stale APKs retained. Offline AGP cache miss and local qualifier minSdkVersion mismatch retained; dependencies resolved with normal strict locks/checksums.

The JNI Java/DEX harness compiled separately. Android APK/JNI execution remains pending while .11 runs genuine Q35 endurance. No new Linux execution claimed:922 frozen CLI inputs and453 helper inputs match; prior20/409 current checks remain applicable with original artifact/time/source/raw. Native inputs unchanged. Strict automated certification is checked separately after commit; whole preflight/current push CI/OpenWrt source cut remain OPEN. Q37 IN_PROGRESS,30/37 DONE81.1%; NO_PUSH_DEPLOY_RELEASE.

### 12 October: 20 Linux criteria on the pool-fixed CLI

<!-- normative-sync: current-pool-linux-certification-20261012 -->

[New results and source binding](../../../../release/certification/evidence/current-pool-linux-matrix-20261012.json).
Lab .11 freshly executed every required automated Linux scenario on CLI
`52511ceb`: 19 separate executions, 409 successful assertions and no failures;
the twentieth leak criterion is derived from actual probes in 14 full/split
cases. Elapsed time: 595.0 seconds. Previous executions on a different
binary and their timestamps were not rewritten.

Coverage includes 12 outer/inner IPv4/IPv6 combinations with TCP/UDP fake-TLS/UDP
QUIC, two dual-stack split tunnels, TAP with local NDP/RA, real systemd-resolved
and DNS over IPv4/IPv6/forced TCP, DATA_FRAG/PMTU on MTU 1280 and ICMPv6 PTB,
both directions of Qeli 0.7.16 compatibility, 100 TCP switches and 100 QUIC switches.
Commands, raw logs, result assertions, SHA, separate mount/net/PID namespaces
and the required functional markers were independently checked for each case.

No recompilation was needed: 915 of the existing qualified build's 916 inputs
match exactly. The only two previously declared whitespace replacements in
buffer_pool.rs were reverified without changing logic, strings or comments.
All 453 fixture inputs match. ELF and legacy-client SHA are pinned. DNS tools,
dependencies and the resolver account already existed on .11; no installation
or service change was needed.

Every retained file was SHA-verified. Structural comparisons across all host
backends passed before/after/after cleanup. Production PID/start ticks/binaries,
staged CLI, DNS tools/dependencies and passwd/group were preserved. The owned
root, remote archive and transient unit were removed. Linux certification binds
these new results and the verified applicability of later documentation-only
changes; this execution's original source/time/raw remains a separate immutable fact.

This closes the stale binding of 20 Linux criteria after the pool change.
The bounded 100+100 soak does not replace the eight-hour Q35 release gate.
The old Q35 performance FAIL, Android SIGKILL/ENONET, full Android VPN data plane,
hosted CI and other open criteria remain outside this PASS. The ledger remains
31/37 (83.8%), with Q29/Q31/Q34/Q35/Q36/Q37 open. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: Q37 complete against five criteria

<!-- normative-sync: q37-five-criteria-closure-20261012 -->

[Criterion matrix and verifiable evidence](../../../../release/certification/evidence/q37-closure-20261012.json).

| Criterion | Completion basis |
| --- | --- |
| Review and dead code | 297 Rust modules / 306 edges; 59 diagnostics in four Linux profiles, 73 reviewed suppressions. 41 retired bodies and unused direct dependencies removed; external API, JNI/C/Swift and RAII retained. Subsequent changes covered by current strict profiles and native A/B. |
| Positive, boundary and negative cases | 84 client fields, 134 server defaults and 176 reader keys reconciled; actual INI admissions and original negatives retained. Eight current schema/docs/generated-adapter methods PASS. |
| Failures and concurrency | Four current admission methods and two safe-import methods for 24 scenarios PASS; five real Linux CI-fixture methods remain applicable after exact unchanged runner/test SHA. Empty/incomplete/skipped/expected-failure suites never qualify; child failures remain visible. |
| Integration and target platform | Current four native A/B, exports/provenance, 22 Windows C ABI, 23 Android JNI and two packaged INI checks; fresh 20 Linux criteria / 409 assertions. User-skipped physical platforms are not described as tested. |
| Fixes, retesting and evidence | Original F001–F013 and maintenance failures retained; 915/916 current CLI inputs match, with the sole formatter delta separately proved. Current provenance/docs/version/source gates PASS; owned cleanup and historical host failures retained. |

Final targeted checks: 14 methods without failures/errors/skips; provenance,
documentation, version and strict Linux certification passed. The initial wrapper
expected one import method rather than two: its count refusal is retained; both
actual successful methods were qualified from their original log without a replay.
Previous full Rust suites, 149 Linux fixtures, native/JNI and network executions
retain their actual timestamps and SHA; they are not presented as new executions.

Q37 covers documentation, reachability, test connection/admission and the qualified
integration of changed harnesses. Full Android VPN data plane, SIGKILL recovery and
ENONET belong to Q29; hosted CI and publication to Q34; SDK/bootstrap to Q31;
historical performance failure/full endurance to Q35; TCP asymmetry cause/capacity
to Q36. These remain open without duplicating them as an undefined Q37 remainder.
This does not claim semantic reachability for every possible execution or public API.

**Q37 DONE within agreed scope. Total: 32/37 (86.5%), five sections remain:**
Q29/Q31/Q34/Q35/Q36. The whole audit and release remain incomplete.
Network runs and large builds were not replayed; no new compiler caches were created.
`NO_PUSH_DEPLOY_RELEASE`.
