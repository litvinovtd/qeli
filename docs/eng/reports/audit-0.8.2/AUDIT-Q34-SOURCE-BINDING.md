# Q34: exact MicroCom.Runtime source identity

<!-- normative-sync: q34-source-binding-v1 -->

9 October 2026. F489 / Q34-F043 closed within publisher source binding, consumed
API compatibility and dependency graph/notices updates.

## Change

Avalonia's MicroCom.Runtime0.11.0 carried no source commit in its nuspec or assembly
informational version. Its MIT supplement was explicitly publisher-declaration
rather than exact-VCS bound.

The Mac project now explicitly pins compatible MicroCom.Runtime0.11.2. The
published nuspec and DLL informational version both name commit
`a83e5a26aa68adaa6001338e2cee2411dd380d1f`. All 76 upstream tree files match Git
blob identities; LICENSE comes from this exact commit. The generator's special
publisher-only exception is removed. All24 Mac lock graphs and the common managed
bundle are updated; other packages and legal resource bytes are unchanged.

This confirms the publisher's consistent source declaration and exact source tree
availability. It does not claim independent byte-reproducible upstream rebuilding
or NuGet certificate trust/revocation qualification.

## Version selection

Official0.11.2–0.11.6 candidates were reviewed.0.11.2 retains all52 previous
public/protected type/method API records and dispatch flags.0.11.3/0.11.4 lack the
previous virtual Dispose(bool);0.11.5/0.11.6 also lack AddMethod(Delegate). This
refuses a blind upgrade; it does not prove that Qeli's actual interface fails on
every later version. Incompatible candidates never entered the project. The
explicit pin/comment requires renewed compatibility review for future upgrades.

## Qualification

- Official NuGet catalog archive size/SHA512 match.0.11.2 archive SHA256 `8e56d08570b33d3ec25087081dcab878a6bd07c63e9b76d028665331c48f3da6`.
- Windows/Linux each12 actual generate+locked restore pairs. Old Windows lock really refuses the new pin. All24 graph comparisons show only the MicroCom record changed.
- One consumer compiled against the old DLL passes12 unmanaged vtable/retained-delegate/virtual-Dispose/explicit ownership/disposed-pointer/IUnknown assertions on Windows with each DLL; the same consumer/new DLL passes on Linux. No finalizer, Cocoa/GUI or VPN runtime claim.
- Actual pinnedSDK10.0.401 cryptographic signature integrity/contentHash for67 archives.66 unchanged official archive admissions inherited; new MicroCom independently catalog checked. Two generations reproduce187files/48supplements/6fonts. Old bundle actually refused.
- 21 generator unit tests, including2 new commit/removed-exception refusals, and38 native recipe fixtures PASS. Actual Debug/tools build,2Mac Release publishes and Windows publish PASS; both Mac outputs contain the exact0.11.2 DLL, all3 contain the exact legal bundle. Shared conformance and Linux-host managed Release build PASS. These are available-host builds/packaging, not Mac/Xcode/signing.

Unique managed build outputs and every local published-file SHA are retained.
Owned .11 fixture used private SDK/NuGet roots. Recovery archive and every member
SHA checked; regenerable official caches excluded with exact URL/hash/contentHash
receipts. First cleanup correctly refused a live build process; it exited on its
own. Retained-file SHA and process/fd/mount guards were rechecked before removing
only the owned root/remote backup. Original active service777/845 and installed
Qeli preserved;.10unused. Preparation assertions/refusals retained separately,
not labelled product defects.

## Boundaries

Core/native inputs14SHA/protectedCSS/templates/qeli tree unchanged. Previous
native qualification and SDK source cut retained; source gate checked without a
new OpenWrt SDK/Rust build. Q34 IN_PROGRESS: 30/37 DONE (81.1%), 7 remain. F459 braces OPEN;
current exact-SHA hostedCI/sourcepublication/signatures/release,Q29SIGKILLFAIL/
ENONET,Q30/Q31,Q35,D06ACCEPTED_LIMITATION andUSER_EXCLUDED retained.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Sources: [official0.11.2 package](https://www.nuget.org/packages/MicroCom.Runtime/0.11.2),
[exact upstream commit](https://github.com/kekekeks/MicroCom/tree/a83e5a26aa68adaa6001338e2cee2411dd380d1f).

Evidence: `q34-source-binding-20261009`; SEALED 894 files; manifest SHA256 `33a0f411c87fb281574d846f1629fabe96ecaf36904d5d7a8028acfc2d6192db`.
21 managed legal and38 recipe tests PASS;724 tracked Markdown/all9 documentation checks PASS.
