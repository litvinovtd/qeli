# Q34: exact local OpenWrt source cut

<!-- normative-sync: q34-openwrt-source-cut-v2 -->

Date: 9 October 2026.

## F483 / Q34-F037

The old pin dd0b736276b9ad5b89d117abd1bfe324210f3b26 contained a different qeli
source tree and the production source gate correctly refused it. The recipe now
pins the original full local dev commit f4b80a9a3052e9ec12c640036928d543f931dafa and actual SDK-generated
qeli-0.8.2.tar.zst SHA256 d6c112641de77b446d3a32a702221b247556b873c11f648087aebb57d3b209c5. No synthetic commit was created: the
original commit and every tree object travelled in a Git pack; missing parents
were marked as a shallow boundary. All 3131 tracked prepared files matched
Git, including source, licenses and notices. Native source and14artifactSHA stay unchanged.

Official OpenWrt24.10.4 SDK SHA256
229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407 was verified.
Its metadata/scripts/host tools were byte-preserved; unused target compiler/build
trees were excluded. Private extracted gawk/dependency and pinned Rust feed/config
supported download/prepare only; no host package install, compiler, Cargo, Rust
bootstrap or IPK invocation. [Official checksum](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/sha256sums).

## Qualification and limits

Two actual SDK downloads, distinct owned Git file URLs and empty DL_DIR caches
produced identical 26381218-byte archives and SHA256. Initial Git download with PKG_SOURCE_MIRROR=0 did not check the old hash;
it did not admit prepare. The measured hash was then verified by production
verify-source.sh during SDK prepare. The second recipe held the correct hash;
archive bytes were independently compared after generation. A hand-produced tar or git-archive
was not substituted for the actual SDK source export.

Public URL stays https://github.com/litvinovtd/qeli.git. Read-only GitHub query for
f4b80a9a3052e9ec12c640036928d543f931dafa returned HTTP422 No commit found; published dev was
83c07f5c31178c67a005f20f59975e14528ab73a. Publish the exact pinned commit before
using the public feed. The source cut is qualified locally; public clone/source
availability and current Actions remain OPEN. Later qeli tree changes require a
new cut/hash. Package version remains0.8.2.

75methodsPASS:25source gate,12whole-preflight,38recipes;three existing
source-suite skips (POSIX symlink/FIFO and opt-in baseline) remain. The actual
committed production gate admitted the real SDK archive and rejected modified
and absent archives. Initial direct-entry fixture lacked sdk/tmp;FAIL66 retained,
only owned tmp directory created. Two SSH launch-channel timeout10s retained as
controller diagnostics; remote jobs continued and completed successfully without
duplicate launch. No compiler/runtime qualification was substituted by fixtures.

Only an owned temporary root on lab .11, jobs1, with no production service,
host package/firewall/sysctl changes. Original service/PID/binary SHA verified
afterward; recoverable archive and guarded cleanup are in raw evidence. Lab .10
was not used. Credential supplied through stdin only; raw and decoded archive credential scan PASS.

Q34 IN_PROGRESS;30/37DONE81.1percent7remain. Q29 SIGKILL FAIL/ENONET, Q30/Q31,
F459 braces OPEN, D06 ACCEPTED_LIMITATION and USER_EXCLUDED preserved. No new
compiler/nativeA-B/platform/runtime/hostedCI/signature/release claim.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-openwrt-source-cut-20261009`: SEALED 81 files / 261832009 bytes; manifest SHA256 `3e57c16820e13a9177f2e8339779d50d09f41573357ae6eed5e6bfa21b8aaa98`.


## 12 October: current source cut after core changes

The previous production pin `746e09cce08b4ffa07f5128427feec99aafcdb98` differs
from the current `qeli/` tree; the actual source gate retained its expected
refusal. The recipe now pins the existing exact commit `c71e4803cd086add92c066dd48a64af1fdb9dec0` and SHA256
`2843576ae0eac173c95bb1f222d9459ef402ea992a0c43ff496e1e1f52ed8137` of the real SDK-generated `qeli-0.8.2.tar.zst` (28029607 bytes).
Public URL/version0.8.2 and Build/Compile/Install are unchanged. The original
commit and all tree/blob objects were transferred; no synthetic/recreated commit
was used. A shallow boundary only marks unavailable parents.

Two real SDK24.10.4 downloads from empty DL_DIRs and distinct owned Git URLs
produced identical bytes. SDK prepare verified the new hash before extraction.
All 3272 tracked files, including LICENSE/notices, matched Git; independent
local verification checked each blob and symlink target again. SDK download.pl
matched the previously SHA-qualified official SDK exactly. The verified SDK
projection was reused without another local duplicate. No Rust/Cargo/bootstrap,
full BuildPackage, IPK or router networking was executed.

The actual committed production source gate accepted the new SDK archive and
refused modified bytes, missing argument and absent file.25 source-admission
methods PASS;3 prior Windows skips (POSIX symlink/FIFO and opt-in old baseline)
remain skips. This is not whole release preflight.

Read-only GitHub returned HTTP422 for `c71e4803cd086add92c066dd48a64af1fdb9dec0`; public dev was
`83c07f5c31178c67a005f20f59975e14528ab73a` and exact-pin push CI was absent.
Publish the exact pinned commit and qualify CI on the final release revision
before using the public feed. The archive contains the full pinned tree;
later recipe/docs changes outside `qeli/` are not attributed to that archive.
Local source admission compares `qeli/`, package version and actual hash.

Lab .11: one owned root,jobs1,MemoryMax1400M,MemorySwapMax512M,CPUQuota150%,
overall900s runtime limit. Original PID777/845,service/start timestamp,all firewall
backends,routes/resolver were preserved. Results/archive were copied and SHA
verified; root removed only after inode/path/process/fd/mount checks. SDK caches
removed;.10 unused. The stale-pin refusal is retained; compiler and large benchmarks were not repeated.

[Machine-readable evidence](../../../../release/certification/evidence/q34-current-source-cut-20261012.json).
Q34 IN_PROGRESS: current public cut/publication,hosted CI,whole release gate and
F459 remain open. Q29/Q31/Q35/Q36 also remain open.32/37 DONE(86.5%).
NO_PUSH_DEPLOY_RELEASE.

## 14 October: local source cut after the core fix

Pinned original commit `ee2b74aafb2a57a2613541223c5522908cb71f71` and actual SDK archive SHA256 `6c82f2162ba9b4939c8d40393a157d5483ccdc6796e41706f0ec2672ee95fb16` (28375941 bytes). The old pin omitted Q36-F030; the actual source gate rejected the mismatching `qeli/` before execution. Two stock SDK24.10.4 downloads from empty caches and distinct private Git URLs matched byte-for-byte; prepare verified the hash and all 3348 tracked files matched Git, including notices and symlinks. The commit was neither synthesized nor rewritten; its shallow mirror contains all original tree/blob objects.

Only recipe pin, hash and qualification date changed; package version, public URL, Compile/Install remain unchanged. Four committed source-gate probes cover admission, changed archive, missing argument and absent file. Unchanged unit suites/Linux matrix were not repeated. Subsequent applicability of the current 20 Linux criteria covers recipe metadata and Markdown only; original execution SHA/time/artifact preserved.

Owned SDK root/cache/unit and remote recovery archive removed after SHA/process/fd/mount/inode guards; production and full host state preserved. Existing verified SDK projection reused without a local duplicate; original archives retained. No fresh compiler/bootstrap/BuildPackage/IPK/32-bit runtime. Prior ARM/MIPS/IPK results retain their source and do not qualify the core delta. Local source-cut debt closed; public pin/hosted CI/full release gate and bootstrap remain open. Q34 IN_PROGRESS,33/37 (89.2%),NO_PUSH_DEPLOY_RELEASE.
