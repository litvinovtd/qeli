# Q34: Android Maven graph security

<!-- normative-sync: q34-maven-security-v1 -->

8 October 2026. F466–F468 / Q34-F020–F022 fixed within the scope below. Q34 remains IN_PROGRESS; full audit30/37 DONE (81.1%),7remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Findings and changes

| Finding | Fix |
|---|---|
| F466 / Q34-F020 | The initial326 locked Maven package/version records had19 affected records and50 distinct OSV advisories. None matched releaseRuntimeClasspath; build tooling, Kotlin plugin and UTP were affected. One gradle/security-versions.properties policy now applies before plugin resolution and to project configurations. KGP2.4.21, Netty4.1.137.Final, BC1.85, Commons Lang3.18.0, jose4j0.9.6, JDOM2.0.6.1 and HttpClient4.5.14 replace the affected versions. Real Gradle regenerated locks and checksum admission. |
| F467 / Q34-F021 | Security CI previously checked RustSec but omitted Android Maven advisories. audit_android_dependencies.py covers all three locks and security-pin consistency. Missing/incomplete API results, errors and pagination loops fail closed; build-only advisories also block. Both new security-audit steps explicitly use repository-root working-directory. |
| F468 / Q34-F022 | wrongPassphraseFails accepted any Exception and checked an always-true condition: AssertionError is not an Exception. Kotlin2.4 rejects it. The test now requires AEADBadTagException. The instrumentation reflection fixture explicitly checks nullable enumConstants without weakening the assertion. |

KGP is upgraded using the supported AGP buildscript classpath mechanism; no standalone Kotlin Android plugin is applied. AGP9.2.1 and Gradle9.7.1 remain. Application Kotlin stdlib does change to2.4.21. VPN profiles remain INI; Gradle properties/locks/XML describe build policy.

## Actual qualification and scope

- Production OSV gate: **318 packages,0 affected**. Fresh real build-only JDOM2.0.6 fixture exit1;2.0.6.1 exit0.8 unit fixtures cover completeness/pagination/network failures/drift; import gate PASS.
- **730 checksum records**:104 new/changed artifacts independently verified by fresh HTTPS stream SHA;626 unchanged exact coordinate/artifact/SHA inherit the prior sealed review. Not730 fresh downloads. Obsolete admission records removed; unchanged Windows/macOS AAPT2 checksum inheritance does not claim new OS builds.
- Private official Temurin Java17.0.20.1+1 published SHA256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`; system Java unchanged. JVM target17; Gradle9.7.1 patch exceeds the published KGP2.4.20 fully-supported ceiling9.7.0, so actual qualification of this combination is scoped here, not Gradle10 compatibility.
- Debug/default unsigned R8/debug and release instrumentation APKs/lintRelease and normal offline/strict builds without write flags PASS. **201 JVM tests,failures/errors/skipped0**, production ConfigCore JNI reused from unchanged sealed evidence SHA6b6d956f; no fresh Rust rebuild. Lint0errors/0fatal/53warnings; existing deprecation diagnostics retained.
- Two real Gradle offline refusals: missing security policy and KGP pin/lock drift; restored positive PASS. Drift includes uncached2.4.20 and unresolved locked2.4.21 modules; not an isolated complete-cache solver test. Separate fixture restored.
- Ordinary unsigned R8 APK preserved before switching testBuildType: SHA `e475123c15d7c8b5f4bf798e44a2328cf468624ae9f7fa35ac202131a4badb6f`. Instrumentation APKs assembled, not installed/executed; no Android device/VPN runtime claim.
- Recoverable archive32720631bytes SHA `7cd085fdf16cdbfc164c01cd92537ba896200171e109607da2288caba2610286`: qualified Android/conformance sources/APKs/reports/mapping/tests/logs/reused JNI. Regenerable public SDK/JDK/Gradle caches excluded; downloaded Java archive and checksum review retained locally. Downloaded SHA precedes proc/cwd/exe/root/fd/mount guarded cleanup. .11 Qeli777/845/CLI75bc preserved;.10 unchanged. Related local native12/release11 tests PASS.


The first Kotlin2.4 run assembled debug/default unsigned R8/debug instrumentation APKs, then failed compiling the always-true unit assertion. That FAIL is retained; retry follows the exact assertion fix. Early draft Unicode/CI working-directory mistakes, Adoptium API refusal, license API404/503 and the license harness assumption that every POM is part of Gradle metadata and the initial negative-harness substitution SyntaxError are preserved separately.

## License inventory and current CI

License metadata was obtained for all318 final packages.23 initial deps.dev errors and one missing license field were supplemented with official POMs: hashes match build verification where the POM is admitted, otherwise the official HTTPS origin and separate SHA are recorded without claiming Gradle admission. Material1.14.0 Apache2.0 is confirmed by the official tagged LICENSE. All76 Maven releaseRuntimeClasspath records declare Apache2.0. This does not close packaging NOTICE/native copyleft/source-cut: Android wrapper MPL2.0 and Rust core AGPL3.0 remain separate review inputs. Non-standard build-tool labels require license-text review; actual APK notice packaging and source admission remain OPEN. App APK entries contain four AndroidX META-INF LICENSE texts; native AGPL/MPL texts were not found by entry names, a concrete next packaging-review input.

Fresh [CI37765333335](https://github.com/litvinovtd/qeli/actions/runs/37765333335),8October, ran SHAf84a78d9 rather than these changes. Android failed on the removed SDK tools package; security-audit failed on old rustls0.23.43/rustls-pemfile/der. The local tree already uses platform-tools/rustls0.23.45/no pemfile/der0.8.1. Successful jobs from another SHA do not qualify this source cut. No workflow dispatch; exact-source Actions and release admission remain OPEN.

`q34-maven-review-20261008`: SEALED 824 files / 245841311 bytes; manifest SHA256 `1bf34d5f422e52d1c66d6c66ac1f3b123e93c134b310813612268e0b67bca3ce`.

Q29 SIGKILL FAIL/ENONET,Q30 Apple/callback OPEN,Q31 capacity/source-cut/currentActions,F459/braces OPEN,D06 ACCEPTED_LIMITATION and USER_EXCLUDED Mac/iOS/router/Windows network VM remain. Old14 debt DONE is preserved. Native sourcee3fb/14 native-copy SHA/CHANGELOG/users/CSS unchanged; no fresh release native A/B or device VPN runtime claim.

References: [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/),[AGP built-in Kotlin upgrade](https://developer.android.com/build/releases/agp-9-0-0-release-notes#runtime-dependency-on-kotlin-gradle-plugin),[Kotlin/AGP/R8](https://developer.android.com/build/kotlin-support),[Kotlin cache advisory](https://github.com/advisories/GHSA-r937-wjx7-w2jp),[deps.dev API](https://docs.deps.dev/api/v3/),[Material LICENSE](https://github.com/material-components/material-components-android/blob/1.14.0/LICENSE).


A subsequent check closes the missing project license texts and retention of embedded Maven notices in APKs: [F469/Q34-F023](AUDIT-Q34-ANDROID-NOTICES.md). Native dependency notices, upstream source notices and source publication remain OPEN.
