# Q34: .NET notices and embedded font licensing

<!-- normative-sync: q34-managed-notices-v1 -->

## F471 / Q34-F025: common NuGet/runtime notices

Windows/macOS publishes lacked a shared bundle of upstream license/notice and
copyright resources. The new `qeli-shared/third-party-notices/dotnet` contains
67 packages (63 in35 reviewed locks plus4 default runtime packs10.0.12),
187 files /4659411 bytes:67 original nuspec files,65 original archive legal
resources,48 copies of9 reviewed upstream receipts and one decoded font notice.
The reviewed Debug/tools/Linux/otherRID superset is not a per-binary linkage list;
license declarations are preserved.

All67 archives /358040771 bytes match fresh official NuGet catalog SHA512 and
recorded SHA256. All67 signed packages passed CMS cryptographic integrity and
contentHash checks using official NuGet API from exact SDK10.0.401:63 hashes match
locks; four runtime hashes are in the reviewed TSV. Raw signed-nupkg SHA512 differs
from contentHash; cache metadata is not treated as archive validation. Certificate
trust/revocation qualification is outside this check.

Offline generation requires exact SDK and a new output directory, checks archive
paths/nuspec/receipts, and builds an SDK-only helper outside the checkout with no
PackageReferences and empty packageSources. Offline checking binds35 locks,
global.json/runtime inventory and verifies index/SHA/origins/metadata and font
completeness. Git preserves upstream bytes. Both desktop projects publish visible
Legal/DotNet resources even for single-file output. CI checks both Windows flavors
and both macOS RIDs; build_app.sh validates common bundles/MPL before app assembly.
Maintenance: [LICENSING](../../../../LICENSING.md).

## F472 / Q34-F026: separate Inter OFL

Avalonia.Fonts.Inter11.3.20 declares MIT for code; its six embedded Inter fonts
carry copyright2020 The Inter Project Authors, Version3.019;git-0a5106e0b and
SIL OFL1.1. Six exact Avalonia nuspec-commit TTFs passed Git blob/SHA checks and
appear byte for byte in all three packaged TFM DLLs. Decoded SFNT names0/5/13/14
and full Inter LICENSE.txt from commit0a5106e0bde18df09374066bf3a7998e3546307d
are retained separately; the NuGet MIT declaration is unchanged.

## Qualification and limits

- Independent direct ZIP extraction matches all67 nuspec,65 archive legal texts and48 supplement copies; all9 receipts used. Font bytes/name proof is retained separately.
- 19 focused fixtures PASS, covering SDK/lock/runtime drift, helper hash mismatch, unsafe ZIP, missing/extra/corrupt resources, reindexed nuspec identity drift, exact VCS and unbound receipts. Initial overly-specific invalid-TSV fixture failure retained and repaired.
- Final-source actual offline generation PASS and187 regenerated files byte-identical.
- Four actual Release publishes PASS: win-net, win-standalone, osx-arm64, osx-x64 on Windows host. Each contains187 exact DotNet files,464 NativeRust files and client MPL. No Apple runtime/signing claim.
- Final CLI:4 published positives,4 missing/corrupt refusals, semantic OFL removal refusal even after consistent reindexing, and byte-identical restoration. Actual new build_app.sh shell commands:2 positives/1 missing-index refusal/restored. This qualifies the publish gate, not full signed app execution.
- MSBuild legal target and docs/CI text checks are in raw evidence. Actions execution/YAML parser qualification is not claimed.

MicroCom.Runtime0.11.0 has no packaged nuspec VCS commit. A historical2021-11-14
upstream LICENSE matches publisher MIT/copyright; its supplement explicitly uses
publisher-declaration binding, without claiming exact source-to-binary provenance.
Avalonia/Tmds sample/test source notices are retained as a conservative superset,
not a linkage claim.

Desktop toolchain inventory: rustc1.97.0 commit2d8144b78, Zig0.13.0,
cargo-zigbuild0.23.0, MinGW binutils2.44 and rcodesign0.29.0. Their runtime/stdlib
notices and Android NDK assets require separate qualification. Matching source
publication, OpenWrt immutable source cut, final-source Actions/signatures/release
remain OPEN. Nativee3fb04a8/14 artifact hashes unchanged; no new native A/B/JVM/device
VPN execution. Q29 SIGKILL FAIL/ENONET, Q30/Q31/F459 braces/D06 accepted and
USER_EXCLUDED preserved; labs untouched. Q34 IN_PROGRESS,30/37 DONE81.1%,7remain.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-managed-notices-20261008`: SEALED 1115 files / 34492726 bytes; manifest SHA256 `1f0b212530fe7876f20418132dd1446127fe3cc4edb60feaa6a060dcb8c65cac`.

[9October follow-up](AUDIT-Q34-SOURCE-BINDING.md): MicroCom publisher-only limitation resolved by compatible0.11.2 pin, exact VCS binding and fresh qualification. The historical packet above is unchanged.
