# Q34: Android dependency locks and checksum verification

<!-- normative-sync: q34-android-dependencies-v1 -->

8 October 2026. F463–F465 / Q34-F017–F019 closed within this scope. Q34 remains IN_PROGRESS; full audit30/37 DONE (81.1%),7remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Findings and changes

| Finding | Change |
|---|---|
| F463 / Q34-F017 | Exact direct Android versions did not lock transitive application or plugin graphs. Strict project dependency locking and an early buildscript classpath lock now cover the actual debug/release, JVM, instrumentation and lint configurations. Three Gradle-generated lockfiles are committed. Normal builds use them; explicit --write-locks is reserved for reviewed maintenance. |
| F464 / Q34-F018 | The wrapper distribution checksum did not authenticate Maven payloads. A committed verification-metadata.xml admits SHA256 of artifacts and POM/module descriptors; metadata verification remains enabled and no trusted-artifact bypass is added. All 747 records independently match uncached HTTPS downloads from their public Google Maven, Maven Central or Gradle Plugin Portal origins. Public Windows/macOS AAPT2 classifiers are included and resolved by real Gradle under this policy, without claiming those OS builds. |
| F465 / Q34-F019 | Removing verification metadata would silently disable Gradle verification; a missing plugin lock also permitted bootstrap. Settings now reject both missing policy files before project plugins load. Missing app locks are rejected by Gradle STRICT mode. Explicit generation flags are the bootstrap/maintenance exception. |

Dependency versions and Android/Kotlin product sources are unchanged. VPN profiles remain INI-only; Gradle XML/plaintext lockfiles describe build dependencies. SHA256 pins reviewed bytes; this packet does not add publisher PGP signatures or claim every library is free of vulnerabilities. The wrapper9.7.1 checksum and CI wrapper-JAR validation remain separate protections.

## Actual checks

- Fresh Linux host ConfigCore JNI built offline with Rust1.97.0, jobs1, no default features, transport-core-ffi; SHA256 `6b6d956f731f50ce4fadf2161e48862fe96d68823063f8dcb8532fdf5800bd6b`. JNI exercises the production parser.
- Debug, default unsigned R8 release, debug instrumentation APK and release instrumentation variant assembled; locked/offline/strict dependency checks and lintRelease PASS. Separate fresh default-mode JVM execution: **201 tests PASS**, failures/errors/skipped0. Compiled instrumentation APKs were not installed or executed in this packet.
- Five actual default-mode Gradle refusals PASS: missing verification metadata, missing plugin lock, missing application lock, direct version drift and AGP JAR expected-checksum drift. Restored fixture succeeds. Normal commands do not regenerate deleted policy files. Negative tests modify a separate copy and restore their inputs.
- Independent fresh downloads: **747 artifacts**, 377880180 bytes; all SHA256 match. Six initial AndroidX AAR URL404s are retained: Gradle module metadata uses artifact aliases, and the descriptors themselves are hash-verified before following their published relative URLs. No hash mismatch was suppressed.
- Non-Linux AAPT2 PE/Mach-O formats and real Gradle checksum admission PASS; Windows/macOS Android builds and current Java17 CI execution are not claimed. The live lab uses OpenJDK21 and JVM target17.

Initial failures are retained. Activating the root plugin lock only in the project body was too late to write its file; final activation is in buildscript before plugins. The first combined compile/test/lint run exhausted the harness Metaspace384MiB after APK/JVM success. Retry separates lint, uses a bounded768MiB heap/768MiB maximum Metaspace, one worker and in-process Kotlin in the private lab copy; all required checks pass. SDK bootstrap installed build-tools36/platform-tools only into the owned SDK. A harness SDK alias warning and resource guard refusal are preserved. No global JVM/SDK installation, service/firewall/system limit change or emulator run.

Complete sources, dependency payloads, APKs, mapping/test/lint outputs and logs are recoverably archived; downloaded archive SHA and proc/mount ownership checks precede removal of the owned root. Original .11 Qeli processes777/845 and installed CLI75bc593e remain; .10 is read-only. Native source digest e3fb04a80fc8c2e7334fa5187dacb497ca47b2a79954fcddae45b5d5a533052c,14 distributed native SHAs/copies, CHANGELOG/users/CSS remain unchanged. No fresh release native A/B is claimed for this build-policy-only change.

`q34-android-dependencies-20261008`: SEALED 87 files / 414985035 bytes; manifest SHA256 `8a94278f86b39bcfc43d02b89c68697ce3e30f88aa67ef8d9a8adba2b4be22f0`.

## Maintenance and remaining audit

[Android build instructions](../../../../qeli-android/README.md) give the explicit generation matrix. Update policy files in the same change as dependencies; review new coordinates, official origins/checksums and debug/release/instrumentation/lint output. Automatic --write flags in normal builds or CI would invalidate the protection. New host-specific artifacts require their own verified SHA; do not add broad trusted-artifact exceptions.

Remaining Q34 package/license/CVE review, current exact-source Actions, source cut and release admission remain separate work. F459/braces advisory is OPEN without a published patch. Q29 SIGKILL FAIL/ENONET, Q30 Apple/callback OPEN, Q31 capacity/source-cut/currentActions, D06 ACCEPTED_LIMITATION and USER_EXCLUDED Mac/iOS/router/Windows network VM remain unchanged. No push/deploy/release or historical runtime relabel.

Official references: [Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html). Runtime behavior is tested with the repository's Gradle9.7.1; the accessible current manual describes the API but is not a claim of upgrading Gradle.
