# Q34: common Cargo legal resources

<!-- normative-sync: q34-native-notices-v1 -->

## F470 / Q34-F024: finding and fix

Client/server packages had no common Cargo dependency legal resource bundle.
`cargo deny` checks permitted dependency licenses but does not establish that
license texts accompany distributed artifacts.

The single `qeli/third-party-notices/rust/` covers 235 registry packages in the
locked Cargo.lock: 458 upstream resources, 464 files including indexes/core AGPL,
2544405 bytes. The full lockfile includes server/build/test/other-target packages;
this is an explicit superset, not a per-binary linkage inventory. Published
Cargo.toml license expressions and original resource bytes are preserved.
Offline collection retains LICENSE/NOTICE/COPYING/COPYRIGHT/UNLICENSE/AUTHORS,
LICENSES directories and declared license-file; archive SHA must match Cargo.lock.

Three published subcrates omit LICENSE: asn1-rs-impl, defmt-parser and
jni-sys-macros use six independently checked exact crate-recorded VCS supplements.
`r-efi` contains license/copyright in [AUTHORS](https://github.com/r-efi/r-efi/blob/7e1b0322d31d625f81a5656096330934f9cd835d/AUTHORS),
retained from its checksum-matching published archive.

`scripts/native_licenses.py` generates only into a new directory. Validation
rejects stale lock binding, checksum/version/source drift, missing/extra files,
duplicates and unsafe paths. Git attributes preserve original upstream bytes.
CI checks the common bundle. Android Gradle additionally checks binding/index/SHA
and copies variant assets; the APK checker compares every resource byte.
Windows/macOS publish visible sidecars and client MPL; iOS gets a folder resource.
Debian/OpenWrt install recipes and the Keenetic ZIP use the same common bundle.
Update procedure/packaging paths: [LICENSING](../../../../LICENSING.md).

## Verification

- 235 official `.crate` archives / 35756092 bytes: every SHA matches Cargo.lock. Independent direct tar extraction matches all458 retained resources; six supplements match exact crate VCS commits and upstream Git blob identities.
- 17 native bundle +14 APK policy fixtures PASS. Common bundle/standalone ZIP checks PASS; deterministic ZIP bytes retained. No Qeli router rebuild claimed.
- Four actual publishes PASS: Windows framework-dependent/standalone and macOS osx-arm64/osx-x64, each with464 exact bundle files and client MPL. macOS publish ran on Windows; Apple runtime is excluded.
- Final CLI checks on all four published directories PASS; two actual missing/corrupted resource refusals and restored positives PASS.
- Actual Debian package/extraction and exact OpenWrt install recipe body PASS:464 identical files each, /bin/true ELF fixtures, no package install, full SDK or Qeli release build claim.
- Strict debug/default unsigned R8 APK builds PASS (326.05 s); lintVital PASS. Each has493 indexed assets, including all464 common bundle files. Debug SHA `d3eac85fcee3b3780d9e304ccb52934a6e3b4f21182fa94b0b8ad1ead0d80c1e` (29793867 bytes); release SHA `50341f617e836db18f3d890159907bfa24029bbd2bc56e1609627197dbc9d0d0` (11691588 bytes). APKs extracted locally from the verified backup pass the checker again.
- Two actual offline Gradle refusals (stale native binding/corrupted resource) and restored byte-identical assets PASS; eight actual APK missing core/Maven/native-resource/native-index refusals PASS.
- Recoverable source/APK/generated-assets/log/report archive: 27830087 bytes, SHA `58519cc3f5d77ae4e2b4c72cfb78faa4dfb4e42640d5d25780259729ea7afeb9`. Local SHA verification precedes proc/cwd/exe/root/fd/mount guarded removal of own .11 root/backup. .11 processes777/845 and active service, .10 processes745/901 and installed CLI remain unchanged.
- 700 Markdown /9 docs checks PASS.
- Initial integration assumptions (existing Git attributes/workflow indentation) and Gradle DSL shadowed `java` import failure were repaired and preserved as failures. The successful APK build uses the corrected explicit Files import. CI command text is inspected locally; no Actions/YAML execution claim. Full lintRelease/JVM/device tests were not repeated for this packaging change.

## Scope and next steps

This proves preservation of discovered upstream resources, not complete legal
release qualification. Rust std/toolchain, upstream source notices absent from
archives, .NET notices, matching source publication, signatures and current-source
Actions remain OPEN. OpenWrt still requires a qualified immutable source cut
containing the new bundle: the host install fixture does not qualify an older
mirror or full SDK build. iOS/Xcode and physical router runtime USER_EXCLUDED.

Native Rust sources/recipe and all 14 artifact SHA remain unchanged (e3fb04a8…);
no fresh native A/B, JVM suite or device VPN execution is claimed. Historical Q29
SIGKILL FAIL/ENONET, Q30/Q31, F459 braces and D06 ACCEPTED_LIMITATION are preserved.
Q34 IN_PROGRESS; full plan 30/37 DONE (81.1%), seven remain.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-native-notices-20261008`: SEALED 837 files / 74001463 bytes; manifest SHA256 `5b8d9e61cf51e25dcf6b2c58530171aa519749e809d5ac0d905f22596a3bb3a1`.
