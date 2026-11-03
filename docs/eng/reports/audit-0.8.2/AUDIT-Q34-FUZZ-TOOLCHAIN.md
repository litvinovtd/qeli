# Q34: reproducible fuzz CI and complete ASan smoke

<!-- normative-sync: q34-fuzz-toolchain-v2 -->

Date: 9 October 2026.

## F485–F486 / Q34-F039–F040

Both fuzz jobs previously installed moving nightly/unversioned cargo-fuzz; the
independent fuzz package lacked a lockfile and README listed10of15 targets.
Pin nightly-2026-06-10,cargo-fuzz0.13.2 and inherited RUSTUP_TOOLCHAIN. The new
146-package fuzz lock preserves142 exact parent name/version/source/checksum
records,adding arbitrary1.5.0,jobserver0.1.35,libfuzzer-sys0.4.13 and qeli-fuzz.
The parent lock and shipping core sources remain unchanged.

cargo-fuzz0.13.2 exposes no --locked build/run flag. Require the committed file,
Cargo fetch --locked,build/run offline,and SHA-check before each smoke target
and after each job,including harness failures. Security CI separately audits
fuzz/Cargo.lock with --deny warnings. README covers all15 targets and exact pins.

## Actual qualification

Private .11 nightly/Rustup/Cargo roots,one compile job. Actual compiler
rustc1.98.0-nightly beae78130(2026-06-09);cargo-fuzz0.13.2 reused byte-for-byte from
the installed tool,SHA92e6980f76db9e77f62b6cfd8e74fe47d672f9d7ee59789f238a6fe563e4c29b.
A fresh cargo-fuzz source installation is not claimed.

All15 real harnesses built with default ASan in250.4 seconds,no rlib/profile/
compiler overrides. Exact current CI smoke Bash:30-second budget per target,
85,930,590 executions,15 completed31-second fuzz runs,no crash artifacts.
All15 executed binary SHA and readelf ASan symbols retained. Empty initial
corpus;generated corpus preserved. Peak reported RSS687MiB includes ASan
quarantine and is not shipping-client memory. This is short smoke,not600-second
nightly or proof of full parser safety.47 core warnings with shipping features
disabled are retained,not classified as dead shipping code.

Actual missing lock preflight rc1,stale aes-gcm graph with Cargo --locked rc101,
mutated lock checksum rc1;restoration and positive checks PASS. Fresh official
cargo-audit0.22.2:146 packages/1295 advisories,DB550efd3d587a29b2e2c2b21b17a440da4fede999,
0 vulnerabilities/0 warnings.72 Windows regression methods and13 Linux methods
PASS. Actual YAML parsed using SHA-qualified private PyYAML;no hosted execution.
Initial private rustup self-update rc1 preserved and retried --no-self-update;
missing CI upload directory failed before runtime,then corrected. Local codec/
statistics preparation diagnostics retained;original UTF-8 and final diff checked.

## Source cut and boundaries

New fuzz lock/README change the qeli tree. Recut exact full Git commit
746e09cce08b4ffa07f5128427feec99aafcdb98 through actual SDK24.10.4 download/prepare:
all3140 tracked files match;second empty DL_DIR/different private URL produces
identical archive SHA9b4b2450c5d8d79cb5e559546dab00e1308e9c0c3646af48431634b91eb1df07.
Production pin/mirror hash updated and source gate PASS. SDK download subset is
byte-identical to the prior official-SHA-qualified projection;unused LLVM/cmake/
headers/static archives excluded. No SDK compiler/IPK/public-source download claim.
Publishing the local commit remains a prerequisite.

SHA-qualified recovery preserves unique outputs,all15 binaries,corpus,exact Git/
SDK inputs and failures. Regenerable compiler/Cargo/build/SDK caches are explicitly
excluded with dated manifest/checksum/source-pack anchors. Own root cleanup only
after local archive-member verification and process/mount guards. Original777/845,
active service,CLI75bc preserved;.10unused. Nativee3fb/14SHA/protected unchanged.
Q34 IN_PROGRESS30/37DONE81.1%,7remain;Q35 TODO and full fuzz/concurrency/DoS/soak,
current hosted CI/signatures/release OPEN. Q29SIGKILLFAIL/ENONET,Q30/Q31,F459braces,
D06 ACCEPTED_LIMITATION,USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-fuzz-toolchain-20261009`: SEALED 154 files / 358276286 bytes; manifest SHA256 `eb1dd886685937f9a311420ab44d8b0d59bfcd4825e642cc945d816af3f27b60`.

## Subsequent Actions semantic check: F487 / Q34-F041

Final review found a regression introduced by this patch: env context is unavailable in job-level env. The initial YAML parse did not detect it;hosted CI had not run. Official SHA-qualified actionlint1.7.12 reproduced both baseline failures. Export RUSTUP_TOOLCHAIN through a dedicated GITHUB_ENV step after compiler setup instead. Final actionlint rc0,13 regressions and exact Bash LF export PASS. Smoke Bash,lock,compiler/tool pins and effective real-lab environment remain identical;no repeat of the85,930,590 cases is claimed. Original sealed packet is preserved,with a separate corrective evidence supplement. This repairs our CI patch,not a parser defect.

[GitHub contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) and [GITHUB_ENV](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-environment-variable).

Context correction evidence: `q34-fuzz-context-20261009`;SEALED 33 files;manifest SHA256 `a62231996d1d5eb1a0889cfde3ea4cd65f1121514ecf056cb17fa2282735c3c9`.
