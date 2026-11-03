# Q34: release source admission and Docker notices

<!-- normative-sync: q34-publication-gates-v9 -->

Qualification completed9October2026; packet started8October.

## F474 / Q34-F028: actual tag and exact-commit CI

The old shell used short `git rev-list -n1 "$TAG"`, HEAD and version checks. Real
Git reproduces admission of branch `v0.8.2` without a tag. The release workflow also
lacked exact-commit CI admission before build/upload. Checkout now uses `refs/tags/`;
a shared read-only helper requires the actual tag on HEAD, committed Cargo version,
clean source and no assume-unchanged/skip-worktree flags hiding changes. Successful
CI for that exact commit is required before building. Query uses `--commit`; missing,
stale,failed or unavailable CI refuses admission. Source identity is rechecked after
the query; outputs are written only after admission. Tests cover real lightweight/
annotated tags,branch collisions,dirty/untracked/hidden source,HEAD drift,tool timeout
and negative CI. Full multi-platform/SDK/certification preflight remains separate.
Old tags missing the new admission helper/notice policy receive no legacy bypass.

## F475 / Q34-F029: release/Docker compiler pin

Rust action lacked a toolchain value and Docker used moving `rust:1-bookworm`,
diverging from reviewed Rust1.97.0 notices/native policy. Release now takes the
shared DEFAULT_RUST_TOOLCHAIN. Docker1.97.0 builder and Debian runtime bases bind
multiarch digests from official Docker Hub HTTPS tag metadata, listing amd64,
arm64/v8 andarm/v7. Two registry manifest-body attempts failed401 and are retained;
no whole manifest/layer pull qualification is claimed. Docker verifies its pull at
a future build. Live APT repositories are not snapshots; no full image reproducibility.

## F476 / Q34-F030: Docker and extracted DEB common notices

Docker runtime omitted project AGPL/common Cargo/toolchain notices. It now copies
LICENSE/LICENSING and the whole533-file bundle to `/usr/share/doc/qeli`. Context
ignore keeps these paths. Docker publication validates the common bundle before
login/build. Release smoke checks actual extracted DEB resources before checksum/
attestation/upload. This batch qualifies source recipes/common bundle; it does not
claim a fresh whole Docker/native build or container VPN runtime.

## F477 / Q34-F031: CI triggers for every workflow

Both push/PR paths previously covered only `ci.yml`; release-attest/docker-publish
only changes could miss CI. Both now cover `.github/workflows/**`; release tag/CI
contract suites are part of CI. Actual YAML parsing checked all three changed
workflows/fields, without claiming GitHub expression or hosted trigger execution.

## Qualification and limits

- 86methods PASS:17release tag,19release CI,12whole preflight,38existing native recipe contracts. Final17 includes a discovered Git trust-flag bypass/refusal; remaining final inputs did not change after their execution.
- Actual baseline shell/real Git branch-only acceptance reproduced;final CLI branch-only/version negatives and matching tag positive PASS.
- SHA-qualified official PyYAML6.0.3 pure Python BaseLoader parsed three workflows;private scratch only,no system package changes.
- Official Docker Hub metadata/digests/platforms retained;registry401 not relabelled PASS. Read-only hosted CI for the starting local dev commit3cd67555 returned no run;current-source Actions remains OPEN,no dispatch/push.
- Common native/toolchain/managed bundles,protected files,14native artifact hashes/nativee3fb checked. Docs/diff/input scope in raw evidence. Labs untouched;no new core/APK/publish/SDK/router/Mac/device build.

GitHub already provides source archives for release tags; no duplicate source asset
is introduced. Exact source commit is retained in build evidence.
[GitHub source archives](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
This does not prove matching third-party binary sources/downstream patches.
Matching source publication,immutable OpenWrt SDK source cut,MicroCom exact binding,
whole Docker pull/build/current-source Actions/signatures/fullrelease remain OPEN.
Q29SIGKILLFAIL-ENONET/Q30/Q31/F459braces/D06accepted/USER_EXCLUDED preserved.
Q34IN_PROGRESS30/37DONE81.1percent7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-publication-gates-20261008`: SEALED 73 files / 1725534 bytes; manifest SHA256 `ce00677e40dae1fa6d7fee5067f2df5a2d5c5c8db5f3154c8c779411070df9cd`.

## 9 October: F490 / Q34-F044 — prevent an old Docker release from replacing latest

A real Git repository with `v0.8.2` and `v0.9.0` reproduces the defect: the
baseline CLI emits `stable_release=true` for `v0.8.2`, and the workflow uses
that flag for `latest`. Re-running an old stable version could roll back the channel.

`docker_publish_ref.py` now emits a separate `latest_release` flag. Stable tags
require a complete Git repository, the candidate tag in the fetched inventory,
and no higher stable MAJOR/MINOR/PATCH version. Comparison is numeric; build
metadata has equal precedence. Branches and RCs return false without querying
Git; unrelated or invalid tags do not define the stable channel. Older stable
releases retain version and SHA publication, without `latest`. Git failures,
timeout, shallow checkout or a missing tag refuse publication before outputs
and before login/build. Existing Cargo version / exact-commit CI admission
remains separate and mandatory for release tags.

The workflow uses a shared concurrency group across refs, with
`cancel-in-progress: false` to preserve an executing run. Serialization alone
would be insufficient because GitHub does not guarantee queue ordering;
numeric version admission is also required. GitHub may replace a pending run
when another arrives; publication of every queued version is not guaranteed.
See [official concurrency rules](https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency).
Automatic metadata-action `latest` remains disabled; the explicit tag uses
the new output. See [metadata-action](https://github.com/docker/metadata-action).

Sixteen methods passed on Windows and the same sixteen on Linux: old/new tags,
numeric order, RC/unrelated tags, equal build metadata precedence, branches
without Git queries, missing tags/repositories, a real shallow clone, Git
failure/timeout preserving outputs, and the actual CLI. Another 59 related
release admission / CI / preflight / workflow gate methods passed on Windows.
Official SHA-verified actionlint1.7.12 accepted all four workflows. Linux inputs
and the full output were recovered and SHA checked; the owned fixture was
removed after process/fd/mount guards using only an exact file list and
nonrecursive deletion. The .11 service, PID777/845 and installed Qeli SHA
were preserved; .10 was unused.

Scope: this selects the highest fetched stable Git tag, not GHCR registry state.
A newer tag blocks an older version from updating `latest` even before its build
succeeds. Complete current fetching and retained stable tags are prerequisites;
tag deletion/movement, external registry writers and executing old workflow
revisions are not qualified. Old refs use their own workflow and do not acquire
this fix retroactively. No push, hosted Actions, signing or multiarch build ran.
Core/native artifacts and the existing OpenWrt source cut are unchanged;
previous qualification is inherited, not newly executed.

F490 is closed within this scope. Q34 IN_PROGRESS; 30/37 DONE (81.1%), seven
sections remain. Q29 SIGKILL FAIL/ENONET, Q30/Q31, F459 braces OPEN, D06
ACCEPTED_LIMITATION and USER_EXCLUDED are retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F490 evidence: `q34-docker-latest-20261009`; SEALED 31 files / 1049840 bytes; manifest SHA256 `61d93c90e2640e781acf6ef239b72ce1a0cce1fd5e3f5a7eafb8ba24816581d2`.


## 9 October: F494 / Q34-F048 — common release source admission

Real Git reproduced a bypass in baseline preflight and certification:
assume-unchanged and skip-worktree hid a tracked worktree edit from status.
Preflight admitted the old HEAD and certification returned the committed-tree
digest although the worktree file differed. Release tag admission already
rejected these flags.

All three entry points now use release_source.py. Existing commit, index trust
flags and clean source are checked before external queries, using NUL-separated
Git paths. Either flag refuses admission even without an edit. Preflight checks
again between phases and after certification. Certification queries ls-tree for
the admitted commit and checks identity again: HEAD drift, a newly hidden flag
or visible source edit refuses the result. Git queries have a 30-second limit;
missing Git, timeout and nonzero exit produce a certification refusal.

New untracked files are allowed only within release/certification/ for the normal
run_ipv6_release_matrix.py --record writer; that subtree is excluded from digest.
Tracked evidence edits require a commit; untracked source outside that subtree
refuses certification. Ignored build caches remain allowed. Preflight and tag
admission require no new untracked evidence: commit reports before these gates.
A custom --evidence outside certification must be committed or kept in ignored
output. Clean committed-source digest serialization is unchanged; hidden
manifest/evidence edits also refuse. Privileged concurrent ignored-cache writers
remain outside the guard.

165 Windows and 33 Linux methods PASS: actual Git fixtures, hidden edits/flags,
HEAD drift, late flags, query failures, new evidence, tracked evidence changes,
ignored caches, orchestration and prior tag/CI/router/OpenWrt/recipe contracts.
Existing CI suites already cover the new tests; workflows unchanged. External
CI/lab builds in orchestration are controlled; no actual current-source CI
publication, SDK/router compilation or runtime VPN qualification is claimed.

The Linux source archive was SHA-checked before execution; 16 known inputs were
removed after SHA/process/fd/mount guards without recursive deletion. The initial
cleanup generator failed with SyntaxError before execution due to a broad FILES
replacement; a helper encoding typo refused before SSH. Both failures retained,
corrected cleanup completed. Original .11 service777/845 and /usr/bin/qeli75bc
retained; .10 unused. Native14/source digest/qeli tree/protected inputs unchanged,
prior execution proofs inherited without Rust/APK/Maven rebuild.41 certification
cases and95 prior supplements preserved modulo source_digest bookkeeping;
supplement96 records this scoped check. Q34 IN_PROGRESS,30/37 DONE81.1%,7remain;
F459/Q29 SIGKILL FAIL-ENONET/Q30/Q31,D06accepted,USER_EXCLUDED and expected release
publisher OPEN retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F494 evidence: q34-release-source-trust-20261009; SEALED 51 files / 1287941 bytes; manifest SHA256 2c7e1d8ea5e65a74c96f6db525eed2fe05310a1ba8febdafc41d908a11fd39dc.


## 9 October: F495 / Q34-F049 — certification in actual release workflows

DEB and release-tag Docker publishers called release_tag.py --require-ci without
validating the certification manifest. CI ran validator unit tests, not manifest
admission. The exact baseline publisher command returned PASS/rc0 and wrote
GITHUB_OUTPUT with a real private Git tag v0.8.2 and a committed failed mandatory
linux.outer4.inner4.tcp.full result under controlled successful CI. The validator
rejected the same manifest. This reproduces the bypass without publication.

Both publisher entrypoints now pass --require-certification with --require-ci.
After tag/version/source admission the shared validator checks
release/certification/VERSION.json against current source digest and mandatory
runtime case statuses. Missing, malformed, stale and failed evidence refuse before
CI queries, DEB compilation, Docker login/build/push or writing outputs. Source/tag
identity is checked again after reading evidence; HEAD drift and tracked manifest
changes also refuse. I/O and CertificationError failures return rc1. Admission
requires both certification and successful CI for the exact commit.

Unavailable physical cases remain advisory under existing policy; an explicit
failed physical result blocks release. USER_EXCLUDED devices are not claimed
qualified. Branch/SHA Docker publication retains its separate policy; the new gate
is mandatory for release tags. A normal read-only release_tag.py call without
--require-certification checks metadata, not full release admission. Manual gate:
python scripts/release_tag.py --tag vVERSION --require-ci --require-certification
Replace VERSION with committed Cargo version. Full release_preflight.py still
checks additional SDK/router/source gates and is not replaced by this command.

132 Windows and41 Linux methods PASS. Actual offline CLI, Git tags and committed
JSON manifests cover failed automated/physical results, unavailable advisory,
missing/stale/malformed evidence, I/O refusal, HEAD/manifest drift, retained outputs
on refusal, positive metadata and CI refusal. Successful CI responses are
controlled; no actual GH query/build/upload/OIDC in these tests. Pinned semantic
actionlint accepts all4workflows; existing CI suite includes the new tests.
Both workflows explicitly verify admission precedes compilation/login.

Only private Python/Git fixtures ran on .11. Eight source inputs plus archive
were SHA-checked; nine known files removed nonrecursively after process/fd/mount
guards. Original777/845 service and CLI75bc retained; .10unused. Native14/qeli tree/
protected inputs/OpenWrt source cut unchanged; prior qualification inherited
without Rust/APK/Maven rebuild.41 cases and96 prior supplements preserved modulo
source_digest bookkeeping; append97. This is not newly qualified actual release/
OIDC/signatures/current-source Actions or a rerun of the full runtime matrix.
The [primary advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) still lists no published F459 patch; no suppression.
Q34 IN_PROGRESS30/37DONE81.1%,7remain;Q29SIGKILLFAIL-ENONET,Q30/Q31,D06accepted,
USER_EXCLUDED and other open items retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F495 evidence: q34-publisher-certification-20261009; SEALED 42 files / 1211464 bytes; manifest SHA256 d11345555e523dc6296de351daf95a0a2d8b942c4d672527a7cbd43fd5c80837.


## 9 October: F496 / Q34-F050 — refuse packaging without a signer

build_app.sh documented a required signer but merely warned when both codesign
and rcodesign were absent. It then produced an unsigned archive and printed Done.
The reproducer executes the old Bash script with real files/tar and controlled
compiler/sign tools: 8 methods produced 3 expected failed assertions covering
both architectures and native bootstrap before refusal.

The signer is now selected before native build, publish or output replacement.
Missing both tools returns an error and retains the previous bundle/archive.
The codesign priority is preserved; the ad-hoc branch invokes the selected tool
path. A nonzero signer exit stops before tar and preserves the previous archive.
The prepared bundle can remain in dist after a signing error; atomic replacement
and concurrent builds are not addressed. Developer-ID/per-app/notarization
scenarios are unchanged.

57 Windows methods PASS: 8 app-signer,38 native-recipes and11 workflow contracts.
Pinned semantic actionlint accepts all4 workflows; Bash syntax PASS. Linux .11
passes the same8 app-signer methods. Coverage includes arm64/x86_64, missing signer
before native bootstrap,both positive paths,codesign priority,both signer failures
and unknown architecture. The suite is included in CI. Filesystem/tar operations
are real, compiler/sign tools controlled: no actual payload compilation, signature
verification or Mac runtime qualification. Apple runtime remains USER_EXCLUDED.

Two committed Linux source inputs and their TAR were SHA-checked. The private
directory and3known files were removed after exact-set,process/fd and mount guards;
original service777/845 andCLI75bc are unchanged,.10unused. Local disk ran out of
space. Only an old extracted SDK under audit-scratch was removed:5577files/
807336133bytes, complete original ZIP SHA512 and exact every-file SHA/set match.
Resolved-path,no-reparse and active-process guards passed. Original ZIP,SEALED
packets and shared caches retained; approximately800MB recovered.

Native source digest,14artifact SHA,qeli tree,protected inputs and OpenWrt source
cut unchanged; previous execution qualification inherited without rebuilds.
41certification cases and97prior supplements preserved modulo source_digest
bookkeeping; append98scoped supplement. Q34IN_PROGRESS:30/37DONE81.1%,7remain.
Previous open/accepted/excluded items are not closed by this change.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F496 evidence: q34-app-signer-20261009; SEALED 35 files / 1203484 bytes; manifest SHA256 74dd6ad767b38be09ef2513e689c22c42bf4d37754e270684e7d6f30b85e5ea4.


## 9 October: F497–F498 / Q34-F051–F052 — universal2 graph and retired resign helper

REMOTE_PY in build_mac_universal.py copied arm64 after lipo failure or a missing
x64 partner. Apphost/core file output was printed without enforcing both slices.
The exact old assembly body produced7expected failures in9methods; only fixed
workspace/tool assignments were adapted to owned fixtures. Filesystem is real,
subprocess controlled.

The complete Mach-O input graph is now admitted before bundle replacement.
Apphost and canonical universal libqeli.dylib are mandatory; thin arm64 inputs
require corresponding thin x86_64 partners. LLVM archs rejects wrong,incomplete
or ambiguous slices. Intel-only Mach-O and symlink inputs refuse. Lipo failure/
timeout never falls back to arm64-copy; every output Mach-O must contain exactly
arm64+x86_64. Bad input retains the old bundle. A later assembly failure can leave
a partial bundle; atomic replacement/concurrent builds remain outside this change.

Removed build_mac_dist_resign.py: no current nonarchive production caller exists.
It connected via SSH on import, used a fixed workspace, ignored exit status and
downloaded output without SHA admission. Both exact old signing f-string commands,
using controlled false instead of rcodesign and actual Bash/tail, returned rc0
despite signer failure. No old module import or lab execution. README directs
repacking through current build_mac_universal.py with checked signing/download;
historical archive mentions retained.

58Windows methods PASS:9assembly/38native-recipes/11workflow; pinned semantic
actionlint accepts all4workflows. Linux .11:9controlled assembly +2actual LLVM19
tests PASS. Genuine lipo produced universal2 from minimal Mach-O headers,admitted
both architectures and refused the wrong Intel partner,retaining the old marker.
These are synthetic object headers: no full .NET payload,actual signature,Mac/
Intel launch or installer qualification. Assembly suite added to CI.

Two committed inputs plus LLVM harness and TAR SHA-checked;4known files/own root
removed after exact-set/process/fd/mount guards. Service777/845/CLI75bc unchanged,
.10unused. Initial staged-deletion inventory error and local TAR append error
before SSH retained and corrected as harness failures. Native14/digest/qeli tree/
protected/OpenWrt cut unchanged; prior execution inherited.41cases98prior
supplements preserved modulo source_digest bookkeeping; append99. Q34IN_PROGRESS,
30/37DONE81.1%,7remain; previous open/accepted/USER_EXCLUDED retained.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F497-F498 evidence: q34-mac-universal-20261009; SEALED 43 files / 1267910 bytes; manifest SHA256 b9629520955cf7076a8d2d1c9db288a8b397af85a93132fe654e83844588ef5f.


## 10 October: F499–F500 / Q34-F053–F054 — macOS packager inputs and resources

Early version/upload/assembly/download failures leaked SSH/SFTP handles. Shared
/root/mac-build and cache could mix runs; Info.plist/icon lacked SHA admission.
Old source produced 12 expected failures and 2 positive controls in 14 methods
using real local TAR/files and controlled SSH interfaces.

Finally now closes the connection and opened SFTP, including SFTP-close failures.
Each run receives its own mktemp workspace; old shared directories/cache are
neither used nor removed. Before SSH, both TARs admit safe unique paths, ordinary
files/directories, mandatory apphost/core and exact canonical dylib SHA in both
architectures. TAR changes during admission refuse. All four inputs, including
Info.plist.in/Qeli.icns, receive SHA checks after upload before extraction.
Assembly/signing/ZIP receive the explicit workspace; pull retains SHA admission
and atomic local ZIP replacement.

Remote workspaces remain for diagnostics and their paths are printed. Two runs
from one checkout share the local ZIP: the last successful result replaces the
previous one. Separate checkout/output directories retain both. README describes
this limit; complete managed payload trust and concurrent publication are not
qualified by this change.

72 Windows methods PASS: 14 packager, 9 assembly, 38 native-recipes, 11 workflow.
Pinned actionlint accepts all 4 workflows; suite included in CI. Linux .11:
23 methods PASS plus 3 genuine main trials over SSH/SFTP — two successful private
workspaces and an icon corrupted during upload. Actual tar, LLVM19, universal2
assembly, ZIP, SHA and atomic pull. ZIP contents/executable bit/core and distinct
icons checked; corruption refuses before extraction and retains the prior ZIP;
all handles close. Controlled signer and synthetic Mach-O headers: no cryptographic
signature, full .NET payload or Mac runtime qualification.

Six committed modules/source TAR SHA checked. 4 owned lab roots/48 known files
recovered into a small ZIP and removed after exact-set/SHA/process/fd/mount guards.
Service777/845/CLI75bc unchanged; .10 unused.

First baseline failed in setUp due to ENOSPC before product checks; repeat produced
12 substantive expected failures. Initial final shell-wildcard assertion matched
embedded Python rglob; restrict it to the first shell line and repeat. Original
baseline/harness failure retained. HTTP403 automatic review failed before execution
due to a service error; later approved execution passed.

Owned scratch reduction preserves 72 original NuGet archives and SHA/metadata
sidecars (216 files/391161706 bytes) in
audit-scratch-20261008/q34-sdk-locks/nuget-recovery-packages. After all SHA checks,
removed 2718 extracted copies/1067432869 bytes and 72 exact HTTP duplicates/
391142266 bytes. SEALED packets, original archives/shared caches retained.
Recovery inputs must be restored before offline publish and are not an installed
NuGet cache. Current checks do not rebuild SDK/native/app.

Native14/digest/qeli tree/protected/OpenWrt cut unchanged; prior execution inherited.
41 cases/99 prior supplements preserved modulo source_digest bookkeeping; append100.
Q34 IN_PROGRESS;30/37 DONE (81.1%),7 remain; previous open/accepted/USER_EXCLUDED
retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F499-F500 evidence: q34-mac-isolation-20261009; SEALED 42 files / 1477945 bytes; manifest SHA256 c9e0e144657b4029f2e1b01ee959154a4a1e6249a6d17a2a761a2a4d3083085d.


## 10 October: F501 / Q34-F055 — compiler versions in every CI job

Seven jobs (build-test, deb-package, android-build, android-instrumented,
windows-build, macos-build, ios-build) pinned the Rust action SHA without a
toolchain input. Exact pinned action source confirms the input default is stable,
a moving version rather than reviewed Rust1.97.0. Pinning installer code alone
does not pin its compiler selection. See [action source](https://raw.githubusercontent.com/dtolnay/rust-toolchain/4cda84d5c5c54efe2404f9d843567869ab1699d4/action.yml).

These seven jobs now explicitly select1.97.0, matching DEFAULT_RUST_TOOLCHAIN and
reviewed toolchain notices. All12Rust installation steps have explicit input.
Existing format/security pins, four router matrix choices (including compatibility/
nightly) and both fuzz nightly steps remain unchanged.

Baseline/final parsed using actual SHA-verified PyYAML6.0.3 BaseLoader. Exact pinned
action/default retained. Confirmed seven implicit stable choices before and seven
1.97.0 choices after; other choices unchanged. Removing only the seven new inputs
produces semantic YAML identical to baseline: jobs, triggers, matrix, components
and all other steps unchanged.

65 related methods PASS:38native-recipes,11workflow,16toolchain notices. Pinned
actionlint accepts all4workflows; toolchain resources and docs PASS. This qualifies
source/config selection, not hosted Actions, compiler installation or client builds.
Lab unused; no SDK/native/app repeat needed for installer input changes alone.
External registry/CVE checks and full final-source Actions remain separate work.

Native14/source digest/qeli tree/protected/OpenWrt cut unchanged; prior execution
inherited.41cases/100prior supplements preserved modulo source_digest bookkeeping;
append101. Q34IN_PROGRESS,30/37DONE81.1%,7remain; previous open/accepted/
USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F501 evidence: q34-ci-toolchain-20261010; SEALED 22 files / 1183992 bytes; manifest SHA256 3a2362b4f92fadd4dffee764d264748923aa941115c528d20a1f9376f528be8d.


## 10 October: F502–F503 / Q34-F056–F057 — CI event and source coverage

Old CI admission accepted success with matching headSha regardless of event.
Default GitHub PR checkout tests a synthetic merge, while a workflow run headSha
can identify the PR head. A genuine private Git fixture creates different head/
merge trees; exact old gate admits head with a controlled green PR response.
Actual read-only metadata for historical Qeli PR185/run37184654438 confirms
event=pull_request/head_sha=PR head. That historical run failed; no false-green
or successful historical build is claimed.
[Checkout PR semantics](https://github.com/actions/checkout#checkout-pull-request-head-commit-instead-of-merge-commit).

Query now explicitly includes --event push and requests event, then independently
requires event=push. Missing/unknown/PR/manual/scheduled events refuse even with
matching SHA/success. Latest push run is selected, not an arbitrary old green.
Branch/exact-commit callers share this gate; status/SHA/query failures and failed
job diagnostics retained. PR CI continues testing merge integration; release
requires successful push CI for its source.
[gh run list](https://cli.github.com/manual/gh_run_list).

Both paths filters missed global.json, NuGet.Config, Directory.Build.props/
targets, LICENSE, .gitattributes and .gitignore. Actual YAML and these single-level
names versus the old patterns confirm7misses for both push/PR. Remove both filters:
every push/PR starts CI. Semantic YAML except event filters equals baseline, with
jobs/matrix/schedule/dispatch/compiler pins unchanged. No manually maintained root
input list remains. Actionlint validates syntax/semantics, not hosted dispatch.

132 Windows and67 Linux methods PASS. Negatives cover green PR/exact head, missing/
wrong event, query/status/SHA errors, actual Git and real tag caller preserving
existing GITHUB_OUTPUT on refusal. Push positives and existing certification/tag/
preflight/router/recipe cases pass. Pinned actionlint accepts4workflows. Developer
instructions updated: CONTRIBUTING and both GETTING-STARTED use1.97.0/locked
commands; require push CI before release.

Initial Windows failure: old multiline controlled gh fixture lacked event; fixed,
initial log retained. Initial Linux archive missed dynamically read
release_preflight.py:67methods/22FileNotFoundError, not a product regression.
Incomplete archive retained; complete initial log not saved, console traceback in
chat is truncated. Resume reused the same owned root after initial archive SHA,
added exact committed input and passed67methods.24source inputs/TAR read back
byte-identical;25known files removed after SHA/exact-set/process/fd/mount guards.
Source TAR is itself recovery, no duplicate ZIP. Service777/845/CLI75bc unchanged,
.10unused; no SDK/native/APK rebuild.

Live push lookup for starting main commit returned no runs: current-source hosted
CI PASS not claimed. Two read-only GitHub queries, no dispatch/push. F459 braces
refreshed against official npm/GitHub metadata on10October:latest3.0.3,no patched
version; remains OPEN, no advisory suppression or CSS/dependency changes.
[Advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).

Native14/sourcee3fb/qeli tree/protected/OpenWrt cut unchanged; prior execution
inherited.41cases/101prior supplements preserved modulo source_digest bookkeeping;
append102. Q34IN_PROGRESS,30/37DONE81.1%,7remain; previous open/accepted/
USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F502-F503 evidence: q34-ci-admission-20261010; SEALED 51 files / 2003222 bytes; manifest SHA256 e07eb37c184f19b94fb28c807befb0f1afc22b309f3e254d378c0550770f9713.
