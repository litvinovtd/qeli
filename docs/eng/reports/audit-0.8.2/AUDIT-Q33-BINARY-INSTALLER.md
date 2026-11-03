# Q33: binary installer payload and state preparation

<!-- normative-sync: q33-binary-installer-v1 -->

8 October 2026. F417–F421 / Q33-F020–F024. Q33 remains IN_PROGRESS. This batch executes the exact installer prefix/functions and two early whole-program refusals. It does not qualify the full config/users/panel/network/service installation flow or Docker integration.

## Findings and changes

- **F417 / Q33-F020:** local _pkg_file returned0 after failed install, because its caller's conditional disables implicit set-e behavior. Copy failure now propagates explicitly; it cannot be reported as a verified payload file.
- **F418 / Q33-F021:** a missing file in an explicit QELI_SRC fell back to remote content, mixing sources; the binary was replaced before complete examples/unit/rule admission. Explicit source is now exclusive. All eight examples, unit and polkit rule are staged privately before binary/account/state mutation. Missing/copy/SHA/attestation failures during admission preserve the old binary; publication afterward is sequential, not an atomic install/rollback transaction. The rule comes from the admitted payload instead of a potentially different install-polkit implementation. Remote default tag selection reads the supplied binary's version before publishing it.
- **F419 / Q33-F022:** from-binary users creation still followed dangling links; linked roots could redirect writes/chown. Shared installer guards reject linked/non-directory state roots (including identity/client-links) and linked/nonregular config/default users before dependency changes and again at from-binary entry. Both users setup points use private0600 no-replace publication; existing regular files retain contents/mode. Physical/nondereferencing ownership commands are explicit. These pathname checks do not pin descriptors against concurrent replacement by directory owners/admins; complete downstream file publication is still open.
- **F420 / Q33-F023:** INT/TERM invoked cleanup and then continued installation. Signal traps now exit130/143, with EXIT performing cleanup. Deterministic self-signal checks prove the following marker is not written. This does not establish cancellation of every external child or SIGKILL/power-loss durability.
- **F421 / Q33-F024:** remote payload chose the first .deb, accepted a checksum-valid non-qeli package and ignored required attestation. It now selects host dpkg architecture, admits qeli metadata with host architecture/all and enforces requested gh attestation before extraction. Local operator-supplied checkout remains trusted input. Integrity sums are from the release; real OIDC/provenance verification is not simulated as PASS.

## Executed evidence and limits

Run `sudo unshare --mount --net --pid --fork python3 -B scripts/test_binary_installer.py`. Linux root/chroot, real Bash/coreutils/dpkg-deb and jq are required. The suite shares the updater fixture; optional QELI_BINARY_INSTALLER_SOURCE and QELI_BINARY_PAYLOAD_SOURCE select snapshots, QELI_BINARY_FIXTURE_RECORDS retains packages/prefix and QELI_BINARY_OPERATION_RECORDS records executions.

The exact bytes before the existing `# Must run as root.` marker execute without function rewriting. Final18 methods PASS without skips:23 invocations,21 prefix/function invocations and two early whole-program refusals. Fourteen old targeted methods yield19 expected failures (root-link/signal subcases). Cases cover staged admission/copy failure, explicit source isolation, layout/state preservation, private empty users, unsafe roots/config/users, invalid binary before apt, SIGINT/TERM, remote architecture/metadata/CRLF SHA, first remote install without an old binary, and required gh missing/failure/success decisions.

Three real .deb payload fixtures carry exact current example/unit/rule bytes; extraction and hashes are genuine. HTTP metadata/bytes, account creation, systemctl and inert qeli/version are explicit seams; injected copy failure is a deterministic fault. Successful gh only records the requested command, not cryptographic verification. No actual daemon/ELF/apt installation, identity generation, user creation, panel auth, firewall/sysctl, final restart/health or end-to-end VPN is exercised.

The exact CI command independently passes18 methods/23 invocations. All21 updater regression methods also PASS with the changed installer. ShellCheck0.10.0 warning gate and bash syntax PASS. This is local command qualification, not a new Actions run. No setup failures occurred: the first12-method baseline/fixed15 run is retained, followed by the final attestation extension. The own root was SHA-backed-up and guarded-cleaned; service777/845 unchanged.

A complete QELI_SRC provides Qeli payload without HTTP. The full script still invokes apt for OS dependencies, so an entirely disconnected first installation is not yet qualified. Guards/staging do not cover all later secret writes; full installer publication/tuning/service integration and Docker build/recreation/health remain open.

Evidence: `release/certification/evidence/q33-binary-installer-20261008.json`. Raw `audit-debt-20260924/q33-binary-installer-20261008`:62 files/6744559 bytes, manifest SHA256 `67021e3c4669fe6bcb08113ffeb616f6e6f3d2c274e0b1d7b1f44fab7f36c331`. Native/Rust/ABI/core inputs unchanged;14SHA/provenance and38 mocked recipe checks PASS without a new heavy build.

Full29/37 DONE(78.4%),eight remain; Q31 bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, USER_EXCLUDED platforms and D06 ACCEPTED remain. No push/deploy/release.
