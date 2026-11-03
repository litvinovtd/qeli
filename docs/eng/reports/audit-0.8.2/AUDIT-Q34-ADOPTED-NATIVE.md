# Q34 — native libraries after adopting the panel fixes

<!-- normative-sync: audit-q34-adopted-native-v3 -->

13 October 2026. The panel CSS build fixes, unsafe legacy entrypoint removal
and Bash marker fix were adopted locally in commit
`da776fb892bd6c02b34194a8e772770744832a77`. Its native source digest is
`27b85c8164e85def83c7c08575e5c3ac1b17d638b52f1cb8c8cf83a1fb5ea17e`.

Before adoption, Rustfmt, strict Clippy, two targeted embedded-assets tests
and the full factory release build passed on .11. The resulting CLI
`15c34473` passed 131 actual HTTP checks covering pages, assets, auth, CSP,
CSRF and INI. Initial incomplete-source-cut, empty-test-filter and CRLF-wrapper
failures are retained; final results bind the corrected inputs and filter.

Fresh independent A/B builds produced Windows x64 and macOS universal
x64/arm64 on .10, and Android ARM64/x86_64 on .11. They used the pinned stock
recipes, Rust 1.97.0, offline/locked/jobs1, separate target directories and
`panic=unwind`. All 327 source inputs were verified. All four library pairs
were byte-identical. Exact exports were checked: 33 C exports for Windows and
each macOS slice; 33 C, 21 TransportCore JNI and one ConfigCore JNI export,
55 total, for each Android ABI. The new DLL passed 22 actual ABI and localhost
checks. Windows network driver execution and physical macOS execution are
outside this result.

All four new libraries differ from their previous SHA values. Old APK and JNI
executions were therefore not restamped. All 679 Android inputs were projected
from the adopted commit; fresh instrumented release app/test APKs and an
ordinary unsigned production APK were built. Both embedded SOs, laboratory
APK signatures, non-debuggable metadata, production rules and two R8 ABI
checks passed. The unchanged 201 JVM tests and lint were not repeated:
applicability was verified using inputs and original SHA-bound XML reports,
retaining the original execution dates.

On .11, the new SO passed 23 JNI checks in a disposable read-only API34
emulator; the installed new release APK passed two INI tests. Original SDK and
userdata bytes were preserved. Logs were archived and independently qualified.
This is not a new VPN data-plane, SIGKILL recovery or generic/null DnsResolver
qualification; the corresponding Q29 limitations remain open.

Both build groups passed owned root/archive cleanup, temporary swap removal
and host restoration checks. The emulator runtime root was also removed;
services, PIDs, binaries, routes and firewall were preserved. Initial desktop
staging failures remain archived: substituting a string inode-cookie into an
`is None` check caused Python to print SyntaxWarning before JSON. External
controllers were corrected; Qeli transport, budgets, recipes and ownership
requirements were unchanged.

The local checkout now contains matching four canonical and four consumed
copies, updated A/B evidence, SHA256SUMS and PROVENANCE. Pair and provenance
checks passed. The [machine-readable result](../../../../release/certification/evidence/q34-adopted-native-20261013.json)
records the actual build commit, APK hashes, runtime receipt and retained local
archive bindings. Packets: `audit-debt-20260924/q34-native-*-adopted-*`,
`q34-adopted-android-package-20261013`, `q34-adopted-android-runtime-20261013`.

The native copy/provenance debt caused by patch adoption is closed.
Q34 remains IN_PROGRESS: global release certification applicability to the new
tree, the public source cut and hosted CI are not qualified by this result.
The plan remains 32/37 (86.5%). `NO_PUSH_DEPLOY_RELEASE`.


## October 15 update: rustls and development on dev

Development continues on `dev`; the original dependency-update commit
`099258dc3719161154c7978347a017a8d90aba75` is included in its history. The
separate verification branch is no longer used for development. The rustls
minimum and the only changed Cargo.lock package are now 0.23.46; license
resources match that lockfile. Hosted cargo audit and the full default Rust
suite passed: 2469 tests, 60 ignored; ignored tests are not counted as executed.
The previous dev run separately confirmed 174 XCTest cases including Keychain.
Final CI after integration is checked separately.

Fresh independent A/B builds produced identical pairs for all four libraries.
The four canonical and four consumed copies, SHA256SUMS and provenance were
updated. Qualification covered 22 Windows ABI cases, exact exports, three new
Android APKs, 23 JNI checks and two installed INI tests on API34. The telemetry
failure after the successful second Android build is preserved as an original
failure; artifacts were independently verified against both builds, source
inputs and the archive.

OpenWrt is pinned to this public commit: two standard SDK download/prepare
passes produced identical archives. Separate Compile/Install/BuildPackage with
Rust 1.89 and SDK 24.10.4 passed seven opkg checks, nine CLI/INI cases and
verification of 533 license files. Owned lab roots, processes and temporary
swap were removed; running services were preserved. No repeated LLVM/Rust
compiler bootstrap was needed.

[Update evidence](../../../../release/certification/evidence/q34-rustls-native-refresh-20261015.json)
records exact hashes and qualification limits. The previous 20 Linux cases
retain their original timestamps, CLI and source digest: the dependency update
does not turn them into new executions. Overall release certification for the
integrated tree requires completion of the next audit step. This commit does
not close Q29, Q31 or Q34 as a whole; the plan remains 34/37. There is no Android
VPN bypass mode.


## Final October 15 reconciliation

Final Q31/Q34 reconciliation completed after successful current hosted CI and fresh Linux20. See [Q34 result](AUDIT-Q34-CLIENT-SUPPLY.md). The current plan is 36/37, with Q29 generic/null API34 open. Previous timestamps and CLI artifacts were not renamed and no physical runtime was added.
