# Q33: server updater package transactions

<!-- normative-sync: q33-server-updater-v1 -->

8 October 2026. F404–F411 / Q33-F007–F014. Q33 remains IN_PROGRESS. This batch qualifies the whole updater's Debian package decision and rollback paths in isolated fixtures; production maintainer scripts, full installer, actual systemd/VPN and Docker image/recreation integration remain open.

## Findings and corrections

- **F404 / Q33-F007:** an absent nonempty QELI_DEB previously fell through to remote download while suppressing remote verification. Both installer and updater now reject the invalid local path before downloads/dependency changes. A valid local updater package needs neither curl nor jq.
- **F405 / Q33-F008:** remote selection used the first .deb regardless of host architecture. It now selects the host dpkg architecture; real dpkg-deb metadata must identify qeli with a nonempty version and host architecture or all before installation/cache changes. Wrong name/architecture/corrupt input refuses.
- **F406 / Q33-F009:** CRLF sums did not match filenames; failed downloads left temporary packages. CR is stripped from the sum entry; EXIT/INT/TERM cleanup removes only updater-owned downloads. Supplied local packages remain. Checksums establish integrity against release metadata, not independent provenance. Optional required gh attestation remains unchanged.
- **F407 / Q33-F010:** separate apt/dpkg locks did not serialize backup/install/health/rollback. A nonblocking flock now covers the whole updater transaction in root-owned0700 /run/qeli-updater, outside service-owned directories. Links/nonregular lock entries refuse. This coordinates participating updaters, not unrelated package managers/admin mutations.
- **F408 / Q33-F011:** swallowed install failure followed by successful dependency repair could report success for an unchanged package and cache wrong bytes under its version. Success now requires exact dpkg status/version/architecture; only admitted installs populate root-owned0600 cache entries. Failure enters rollback.
- **F409 / Q33-F012:** restart failure exited under set-e before rollback; an empty successful MainPID reply could pass the old check. Restart is conditional; forward and rollback health require a numeric positive MainPID, stable across the observation window, plus is-active.
- **F410 / Q33-F013:** binary version omitted Debian revision when locating rollback; apt exit0 alone was accepted as a downgrade and rollback health was weaker. Lookup uses installed Debian version, cached metadata is checked, downgrade requires exact configured dpkg identity and the same health gate. Binary-only fallback explicitly warns about inconsistent package metadata. Recovery still exits nonzero because the requested update failed.
- **F411 / Q33-F014:** legacy /var/lib/qeli/packages is service-controlled; ownership of an entry cannot authorize its contents or prevent replacement during migration. The updater now ignores and preserves it. It never imports those bytes into the root-executed rollback cache.

## Executed verification

`scripts/test_server_updater.py` requires Linux root/chroot, real dpkg/dpkg-deb/dpkg-query, jq, flock and standard utilities. Run `sudo unshare --mount --net --pid --fork python3 -B scripts/test_server_updater.py`; optional QELI_UPDATER_SOURCE and QELI_INSTALLER_SOURCE select baseline bytes, and QELI_UPDATER_FIXTURE_RECORDS saves fixture packages. The Linux CI job now includes this command and ensures jq is installed.

On .11,14 targeted old behavior methods fail after complete fixture preparation; these are regression scenarios, not14 independent findings. The final21 methods PASS without skips:24 updater invocations and one installer invocation. Six actual inert .deb packages are built and installed/downgraded through real dpkg with a real private database. Config/users/identity/client-link bytes remain unchanged. Cases additionally cover Architecture all, SHA mismatch, required attestation without gh, held real flock with success after release, unsafe cache/lock links, crash loops and false apt success. The exact CI argument sequence, as root with sudo omitted, separately passes21 methods. This is local CI-command qualification, not a successful Actions run.

Explicit seams: apt command admission (actual dpkg installs packages), release HTTP/bytes, systemctl/PID/active sequence and compressed sleeps. The fixture qeli executable only prints its version. No production Debian maintainer script, real daemon, actual5-second timing, HTTPS/OIDC verification, live firewall/VPN or Docker runtime was exercised. Stable MainPID checks the service supervisor only; it does not establish worker or tunnel readiness.

ShellCheck0.10.0 warning gate and bash syntax pass for both scripts. Initial driver syntax/missing dpkg tools and dpkg-split failures are retained as preparation errors, never product verdicts. Final source SHA matches transferred inputs. SHA-verified recoverable backups precede guarded removal of both own remote roots; active service MainPID777 and worker845 remain unchanged.

Evidence: `release/certification/evidence/q33-server-updater-20261008.json`. Raw packet `audit-debt-20260924/q33-server-updater-20261008`:47 files,8797575 bytes, manifest SHA256 `4d7e7b4036fce28841347b562e4969562b8da3fd34c8ac720be10f87b70a49cd`. Rust/native build inputs, ABI and packaged cores are unchanged; no heavy native rebuild is claimed.

Full audit remains29/37 DONE(78.4%),eight remain. Q31 bootstrap/source-cut/current Actions remain open; Q29 SIGKILL/ENONET, Q30 Apple/callback, user platform exclusions and D06 accepted limitation remain. No push/deploy/release.
