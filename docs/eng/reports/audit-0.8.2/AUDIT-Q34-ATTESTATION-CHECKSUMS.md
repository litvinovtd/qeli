# Q34: artifact provenance and atomic checksums

<!-- normative-sync: q34-attestation-checksums-v1 -->

Date: 9 October 2026.

## F478 / Q34-F032: downloaded bytes are not Linux build output

The Linux release job builds and checks one DEB, then downloads other release
assets and used `actions/attest-build-provenance` with `dist/*` for them. The step
name “publication evidence only” cannot change the predicate. Exact upstream
commit `96278af6caaf10aea03fd8d33a09a777ca52d62f` always invokes the build-provenance
predicate generator and passes its output to the signer. With other assets, the
workflow issued unsupported build evidence. Baseline YAML has two build
attestation steps; final has one with exact `steps.assets.outputs.subject`, set
from the actual CI-built DEB name. Foreign attestation and its dead presence
detector are removed. Downloaded asset checksums remain; their build provenance
must originate in actual platform build jobs. Old published attestations were
not removed; hosted OIDC/signing/verification were not executed.
[Exact upstream action](https://github.com/actions/attest-build-provenance/blob/96278af6caaf10aea03fd8d33a09a777ca52d62f/action.yml).

## F479 / Q34-F033: checksum admission and retained manifest

The old generator accepted whitespace/newline names, could return success with
an updater/installer-incompatible manifest, and checked CR after writing it.
Actual Windows baseline CLI replaced the prior manifest for `bad asset.deb` and
returned0; a whitespace consumer sees only `bad`. Actual Linux newline basename
also returned0, but GNU `sha256sum -c` rejected the manifest. Admission now accepts
regular files named `[A-Za-z0-9][A-Za-z0-9._+-]*`; nested directories are ignored.
Symlinks, including SHA256SUMS, and special files are refused before reading or
publishing. After all input admission/hashing, a temporary regular file in the
same directory is published with `os.replace`. Read/replace errors retain the
old bytes; temporary files are cleaned. Output is deterministically sorted,
ASCII/LF, bare basename. This targets owned release staging; concurrent hostile
replacement or asset mutation after generation was not qualified by this batch.

## Verification

- Linux11 checksum methods PASS without skips: real CLI/exact sorted hashes, invalid/newline names, asset/output symlinks, nonblocking FIFO refusal, empty/missing path, hash/replace errors and retained manifest. GNU verifier on final two-file output PASS.
- Windows7 checksum PASS with4 POSIX skips; all four executed on Linux. Release18 and existing native recipes38 methods PASS on Windows.67 distinct methods overall, without adding repeated Windows/Linux runs.
- Actual SHA-qualified PyYAML6.0.3 parsed three workflows: exact DEB subject, baseline foreign wildcard and new CI suite confirmed. Parser source matched the prior official SHA-qualified archive; no GitHub expressions/Actions execution.
- Only an owned Python fixture root changed on .11. Recoverable archive downloaded and SHA-verified before /proc/mount-guarded deletion. Original PID777/845, service/CLI SHA and network snapshots match before/after. No Docker/native/SDK/APK/daemon rebuild.
- Docs, input scope, protected files,14 native hashes and unchanged native digest/evidence checked in raw packet. Prior common bundle payload qualification inherited, no fresh packaging claimed.

Q34 remains IN_PROGRESS;overall30/37 DONE81.1percent,7remain. Matching third-party
source publication, OpenWrt immutable source cut, whole Docker/current Actions/
signatures/full release remain OPEN. Q29 SIGKILL FAIL/ENONET,Q30/Q31,F459 braces,
D06 ACCEPTED_LIMITATION and USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-attestation-checksums-20261009`: SEALED 54 files / 1417911 bytes; manifest SHA256 `eac43f5804f6d55b789e2e3afbf87db459cdf18325fee1056a920febd94f77a9`.
