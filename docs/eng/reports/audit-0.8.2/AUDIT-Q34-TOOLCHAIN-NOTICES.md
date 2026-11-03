# Q34: standard-library and toolchain runtime notices

<!-- normative-sync: q34-toolchain-notices-v1 -->

## F473 / Q34-F027

The common Cargo/NuGet bundle did not cover Rust std and toolchain runtime notices.
One embedded `rust/toolchains` layer now retains 65 original resources across seven
component/version groups, 69 files /3999768 bytes including metadata. The whole
native bundle contains 533 files /6557892 bytes. All 462 old Cargo resources and
metadata remain byte-identical; only outer INDEX/SCOPE changed. Maintenance:
[LICENSING](../../../../LICENSING.md).

Rust1.97.0, nightly-2026-06-10, compatibility1.89.0 and Zig0.13.0 came from four
fully SHA256-qualified official tar archives. 39 installed Rust/doc resources
match official members. Each Rust retains MIT/APACHE, COPYRIGHT-library and 12
license-pool texts with original member directories. Zig retains 12 libc/musl/
MinGW/WASI/libc++/libc++abi/libunwind resources. Three NDK26.3.11579264 notices from
an official ZIP match both labs; identity/version members were also qualified.
HTTP range/ZIP CRC qualification is explicit, without claiming a whole ZIP hash.
Five GCC14.2/MinGW12 legal resources came from exact Git commits/trees/blobs;
observed dpkg source versions and binary ownership are recorded.

Offline checker/generator preserves original bytes/paths and only creates new
outputs. Catalog/current pins bind through BINDING/index/SHA, rejecting missing,
extra, corrupt, reindexed drift and unsafe sources. Native checker includes this
layer; CI requires a separate policy gate. Android Gradle declares external
catalog InputFile and checks embedded SOURCES before copying, preventing policy
drift from hiding behind a cached legal task. Other existing packaging recipes
copy the entire bundle and need no separate client implementations.

## Qualification and limits

- 47 final-source focused fixtures PASS (16 toolchain,17 native,14 APK).
- Actual final-source offline generation:69 toolchain/533 native files byte-identical;65 original upstream resources independently compared. Three Rust HTML documents retain embedded notices and36 companion pool texts; these exact documents have no relative href/src targets.
- Four actual Release desktop publishes PASS:win-net,win-standalone,osx-arm64,osx-x64. Each retains533 exact native files,187 .NET files and client MPL. Published checker:4 positives,6 missing/corrupt/consistent-reindex stdlib refusals and byte-identical restoration.
- Actual debug/default unsigned R8 release APKs PASS,90 tasks executed including release lintVital. Each contains562 indexed legal assets (533 native),63 Maven archives/76 coordinates/24 notices; existing arm64/x64 JNI hashes unchanged. Four actual APK missing-stdlib/index refusals; downloaded backup APKs independently checked locally.
- Actual cached Gradle legal task:baseline UP-TO-DATE,external catalog reorder invalidates cache and fails inventory binding,restored PASS;corrupt stdlib fails checksum,restored PASS. No extra full rebuild needed.
- Actual Debian package/extraction with /bin/true and actual OpenWrt install-body host fixture retain533 files. Deterministic Keenetic export retains533 files. Packaging only,no install/SDK firmware/router runtime claim. iOS folder resource remains SOURCE REVIEW/USER_EXCLUDED.
- 704 Markdown/9 checks PASS;CI source gate/text assertions only,no Actions/YAML parser execution. Original services/processes/installed CLI on both labs preserved; owned .11 root removed only after recoverable backup SHA and /proc/mount guards. Nativee3/14artifact hashes and protected files unchanged.
- Kotlin deprecation/safe-call and Gradle deprecation warnings retained; assembly/lintVital success does not assert full lint or future Gradle10 compatibility. No Mac/iOS physical,Windows network VM or fresh VPN/device runtime qualification.

This is a conservative notices superset, not per-binary linkage or full legal
qualification. Extra license-pool texts do not change Qeli licensing. Old native
metadata does not pin GCC minor; observed lab sources do not prove old artifact
linkage/downstream patches. Rust1.89 covers an earlier OpenWrt SDK compatibility
fixture; an immutable published SDK source cut remains OPEN. Matching source
publication, dynamic system runtime, MicroCom exact binding, final-source Actions/
signatures/release remain OPEN. Initial capture/guessed-path harness failures are
retained, not relabelled PASS. Q29 SIGKILL FAIL/ENONET, Q30/Q31/F459 braces, D06
ACCEPTED_LIMITATION and USER_EXCLUDED preserved. Native e3fb/14 artifact hashes and
protected files unchanged; no fresh core/native A/B/JVM/device VPN qualification.
Q34 IN_PROGRESS, full plan30/37 DONE81.1%,7remain.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-toolchain-notices-20261008`: SEALED 2650 files / 379846049 bytes; manifest SHA256 `f2faf9852b55fd442953779570a95662474dc7e25eefc99c4484b64cbb0a9883`.
