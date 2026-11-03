# Q29: instrumented Release runner

<!-- normative-sync: q29-android-release-runner-v1 -->

5 October 2026. **7/7 network instrumentation tests PASS** on the isolated API34
x86_64 AVD on .11. Q29 remains IN_PROGRESS; overall plan 28/37 (75.7%).

The application and test APK share libraries, but R8 can remove application APIs
used only by the runner. Matching test mapping preserves renames, not deleted
definitions. Keeping three Trace methods exposed the next failure, `kotlin.LazyKt`.
Inferring all pre-R8 references removed missing APIs but exposed an
`IllegalAccessError`: R8 moved a Kotlin subclass to another package while its
package-private parent remained inaccessible. Both failed APK pairs, matching
mappings, runtime logs and lab restoration are retained.

The fix applies only with `-PqeliTestBuildType=release`. The generator derives exact
ABI keep rules from compiled tests and two resolved classpaths;
`allowaccessmodification` lets R8 widen superclass visibility. Default production
Release retains its original rules. The instrumented Release remains R8/minified,
resource shrinking enabled, non-debuggable and signed with a lab key. This is a
separate test variant: its PASS does not relabel historical production APK
failures. Earlier production UI coverage remains separate evidence.

Validation:

- pre-R8 inference: 9,564 target / 832 source classes, 11 known platform-stub
  diagnostics; unknown unresolved references rejected. `--check` PASS.
- Packaged DEX: Trace beginSection/endSection/forceEnableAppTracing have the required
  signatures; no inaccessible superclasses. The previous APK produces the expected
  Kotlin inheritance FAIL, and the initial production APK produces Trace FAIL.
- TCP/UDP/QUIC × split/full: six off-pool IPv4/IPv6 TCP/UDP and system DNS scenarios,
  72 echo receipts, 12 A/AAAA answers through TUN. This run uses preflight and does
  not qualify the immediate first packet.
- Seventh scenario: full kill-switch refuses startup without Android lockdown.
- All three runtime attempts cleaned up: server exit 0, namespaces restored,
  readonly AVD userdata and host/service/firewall/routes unchanged. .10 untouched.

New build/DEX/runtime checks executed; previous 172 JVM/lint and JNI/managed
checks are reused for unchanged relevant inputs, not claimed as fresh. API28/29,
arm64/OEM runtime not executed. SIGKILL recovery FAIL, auto/null DnsResolver ENONET,
Private DNS, remaining per-app and long lifecycle/flapping checks remain open.
USER_SKIPPED and D06 limitations unchanged.

Regeneration/run instructions: [Android README](../../../../qeli-android/README.md).
Evidence: `release/certification/evidence/q29-android-release-runner-20261005.json`.
Raw: `audit-debt-20260924/q29-android-release-runner-20261005` (outside Git), including
failed candidates, APK hashes, mappings, captures and source proof.
