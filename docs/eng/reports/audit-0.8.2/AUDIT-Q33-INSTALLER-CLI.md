# Q33: actual installer CLI and version compatibility

<!-- normative-sync: q33-installer-cli-v1 -->

8 October 2026. F437–F438 / Q33-F040–F041. Q33 remains IN_PROGRESS.

## Findings and changes

- **F437 / Q33-F040:** payload-tag discovery and updater fallback read `qeli version`. Current CLI supports it, but an old installation may support only `qeli --version`. Actual lab binary0.7.5 accepts --version and rejects the subcommand. Both scripts now use --version for reading the version number. `qeli version --check` remains a supported current opt-in update check. Binary/updater fixtures now reject unsupported commands rather than return a version for arbitrary argv.
- **F438 / Q33-F041:** actual CLI writers create a persistent `.lock` beside the unique staged INI. Config publication removed the stage but left that lock in /etc/qeli. Its exact sibling name is now registered with the stage for EXIT cleanup, after synchronous writers finish. Live config/users locks are preserved. The secret CLI fixture now creates the stage lock so ordinary failure/success tests also cover cleanup.

## Executed evidence

Version baseline2 methods give2 expected assertion failures, fixed2 PASS. Actual CLI initial5 methods give4 orphan-lock failures; custom-unit override/revert passes. After cleanup fix all5 PASS without skips: UDP, fake TLS and REALITY whole-installer flows; genuine check-config rejection of invalid staged port with unchanged live bytes; actual custom systemd-unit override creation/removal. Each successful flow creates5 real users with Argon2 hashes, a real panel password hash, identity keys and5 share links; validates staged/final INI and checks config owner234/mode0600, summary/journal/temp cleanup. Identity/link creation does not prove a VPN handshake or password-auth round trip.

Commands: `sudo unshare --mount --net --pid --fork python3 -B scripts/test_installer_cli_version.py`; `sudo env QELI_AUDIT_BINARY=/absolute/provenance-checked/qeli unshare --mount --net --pid --fork python3 -B scripts/test_installer_real_cli.py`. Requires Linux root/chroot, Bash/coreutils/dpkg fixture tools, jq, openssl and the binary's loader/libraries. The explicit binary is never downloaded or built by the test; missing binary/platform skips, not PASS qualification. Exact local CI repeats2+5 without skips. Config21/secrets21/admission18/binary18/updater21 regressions PASS (99 total), ShellCheck0.10.0 warning/bash syntax for both scripts, recipes38 mocked/native14 SHA-source-A-B/docs9 checks/678 Markdown PASS.

The reused genuine debug artifact is from source85ea8fa9adab146d52b6f8908e5f29c89f2d8c20, sealed q32-logs-trace-20261008, SHA256 `37a6e349ed5b72c44cb72ba147e4df7e87e277763c250cfe226173a6e9414b7c`. Current main/CLI/parser/identity/users/web/trust/preflight/helper paths are unchanged. Later differences are client/mod, client/plan_publication, config/notify and server/notify. This is scoped reuse, not a current full Rust rebuild, release jemalloc qualification or native ABI rerun. Initial installer input is reconstructed by removing the exact cleanup patch from current bytes, not an independently measured initial-input SHA; final lab input SHA is checked.

Actual CLI performs parsing, key generation, Argon2 hashing, user persistence, links and custom drop-in updates. Account creation, HTTP, systemctl manager/start/health, kernel/tuning and preflight ip commands remain seams. No sockets/TUN/firewall/VPN/Docker qualification. CI now runs the actual-CLI suite after extracting its built portable .deb, with an explicit executable assertion; this package pipeline/Actions run was not executed locally. No extra Rust/native build or product Rust changes.

Default qeli.service root-to-qeli transition remains OPEN: existing helper recursively chowns /etc/qeli, including root0600 secret receipts/backups; installer default qeli does not clear a previous root override. Only a separate custom unit revert was executed. Whole-install/account rollback, restart-after-publication rollback, fsync/SIGKILL/power-loss durability and ancestor-directory race protection are not claimed.

Evidence: `release/certification/evidence/q33-installer-cli-20261008.json`. Raw `audit-debt-20260924/q33-installer-cli-20261008` SEALED334 files/41695825 bytes; manifest SHA256 `463e8729410b56be06f662e2c3193d78cf3aea1daea6971b320c7395e8f80c17`. Includes initial failures, baseline/fixed version logs, final/CI real generated state and recoverable archive containing the SHA-checked actual binary. Own .11 root backed-up and guarded-cleaned; service777/845 unchanged, .10 untouched.

Full29/37 DONE(78.4%),eight remain. Q31 3/5/capacity-deferred bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, USER_EXCLUDED platforms and D06 ACCEPTED retained. Local dev commit; no push/deploy/release.
