# Q34: project licenses and Maven notices in Android APKs

<!-- normative-sync: q34-android-notices-v1 -->

## Finding and fix

**F469 / Q34-F023:** the preceding ordinary R8 APK contained four AndroidX
META-INF LICENSE entries but no Qeli core AGPL or Android client MPL texts.
Repository LICENSE files did not establish their inclusion in the application.

Each variant now generates `assets/licenses/`: canonical AGPL/MPL, Apache 2.0,
a reviewed Maven runtime inventory, original archive identities, and
LICENSE/LICENCE/NOTICE/COPYING/COPYRIGHT resources from JAR/AAR and nested
`classes.jar`/`libs/*.jar`. The index retains original coordinates/paths and SHA256;
equal notice names from different dependencies are kept separately. Outputs are
variant-specific; new/removed coordinates or versions require review.

Original archives are selected with a dedicated [Gradle ArtifactView](https://docs.gradle.org/current/userguide/artifact_views.html)
and compatibility limited to its custom consumer type. Repeated visits to the
same component/physical archive across variants are deduplicated; real filename
conflicts fail. The legacy resolvedConfiguration API is not used.

After assembling both APKs, CI checks canonical texts, inventory/index, hashes,
origin/path binding and duplicate/unindexed files.
[Maintenance](../../../../qeli-android/README.md), [license map](../../../../LICENSING.md).

## Verification

- Private official Temurin17.0.20.1+1 verified against published SHA256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`; system Java unchanged. Gradle9.7.1/AGP9.2.1/KGP2.4.21 and lock/checksum policy unchanged.
- Ordinary strict debug and unsigned R8 release builds without write flags PASS (313.14 s). Release lintVital PASS; full lintRelease and JVM tests were not rerun in this packet.
- Independent Python extraction checked both generated outputs:63 original archives,44AAR,24resources; every archive matched committed Gradle SHA256 and resource origin/SHA. Generated debug/release assets are identical.
- Both actual APKs contain29 indexed assets:AGPL/MPL/Apache/MAVEN/ARTIFACTS plus24upstream resources. Debug SHA `61faba3a75efaa465043c0fb1a9491de1d8fe3264b16f1e2ccfc90a0e66626eb`, release SHA `c99a5de06098916ea97c75680449923deb15ee5ad68a17c3b0e68e7ada4c03c1`; sizes 28587166/10582903 bytes. Repeated local checks of APKs extracted from the SHA-verified backup PASS.
- **12 negative fixtures**, **2 actual offline Gradle refusals** (unreviewed coordinate/duplicate inventory), restored positive and byte-identical regenerated assets PASS. **4 actual APK refusals** after removal of AGPL or one retained resource in each variant.
- 698 Markdown/9docs checks PASS; new CI steps explicitly use root working-directory (local text inspection, not a YAML parser/full workflow run). Native sourcee3fb/14artifact hashes/canonical core license parity/protected CSS/CHANGELOG/users unchanged.
- Recoverable source/APK/generated-assets/log/report archive 24370725bytes,SHA `55fca2447631bfe3f188041ba58256ed43d202033f2efd819c6e8089b25d7e82`; regenerable public SDK/JDK/Maven caches excluded. Local SHA precedes proc/cwd/exe/root/fd/mount guarded cleanup; cleanup results recorded separately.

Initial duplicate variant record failures, the legacy-resolution attempt,
diagnostic run, incomplete offline cache and independent-harness XML namespace
failure and an unavailable optional PyYAML import in local orchestration are retained. They are not product passes; final runs were performed
after repairs. Diagnostics refined the initial cause: repeated visits caused
duplicate filenames; they did not demonstrate notice loss by the default
ArtifactCollection.

## Limits

The 76-coordinate Maven license declaration inventory inherits an earlier
sealed review, not 76 new upstream queries. Independent extraction covers 63
original JAR/AAR files admitted by current Gradle checksums and 24 resources.
A binary archive without a NOTICE does not establish that its upstream sources
have no notices. Native Rust dependency notices, upstream source notices, source
publication, signatures, current-source Actions and full release admission remain
OPEN. Adding AGPL/MPL texts does not change directory licenses or close these items.

Native core and Rust sources are unchanged; no fresh native A/B, JVM/device/VPN
runtime claim. Previous JVM201/lint53 evidence is inherited. Q34 IN_PROGRESS;
full plan30/37 DONE (81.1%),7remain. Historical Q29 SIGKILL FAIL/ENONET,Q30/Q31,
F459,D06 ACCEPTED_LIMITATION and USER_EXCLUDED remain unchanged.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-android-notices-20261008`: SEALED 93 files / 29234394 bytes; manifest SHA256 `0566db24ab52066b5cc339764eef4d65345e23ff37ff03703237b8afcde86db6`.


Owned build root and remote backup removed after local SHA verification and proc/mount guards. .11 Qeli777/845,CLI75bc/active service and .10 Qeli745/901,CLIca0a preserved.
