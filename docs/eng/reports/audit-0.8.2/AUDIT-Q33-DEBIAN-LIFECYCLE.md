# Q33: Debian package lifecycle and state protection

<!-- normative-sync: q33-debian-lifecycle-v1 -->

8 October 2026. F412–F416 / Q33-F015–F019. Q33 remains IN_PROGRESS. Production packaging and maintainer scripts are now exercised with real make/dpkg in private chroots. The qeli executable, dependencies and external service/debconf/account operations are fixtures; full installer, real daemon/systemd integration and Docker image/recreation are still open.

## Findings and changes

- **F412 / Q33-F015:** direct package configuration under umask022 created users.conf0644. Postinst uses umask077, a same-directory mktemp0600 and GNU ln -T publication without replacement. It seeds an empty file, never the known sample hash. Existing regular users files retain contents/mode; cleanup removes its own temporary file on exit/INT/TERM. No fsync/power-loss/SIGKILL durability is claimed.
- **F413 / Q33-F016:** dangling/regular users links and linked state roots could redirect root writes, ownership changes and package extraction. New preinst rejects linked/non-directory /etc/qeli, /var/log/qeli and /var/lib/qeli, plus linked/nonregular default users.conf before unpack. Postinst repeats the guard for dpkg --configure, uses explicit physical/nondereferencing recursive chown and refuses unsafe publication. The Makefile includes preinst in the actual package. These are pathname guards, not descriptor-pinned protection against privileged concurrent replacement; the service-owned final directory may still be changed by its owner.
- **F414 / Q33-F017:** failed debconf lookup could consume stale RET, unknown answers silently mapped to qeli, and failed set-service-user was suppressed while claiming success. Failed lookup now defaults to qeli; only root/qeli are accepted. On a booted systemd host, CLI failure leaves dpkg half-configured and requires a successful configure retry. Without /run/systemd/system the failure is warned explicitly, with a retry command; no applied-user message is printed. This preserves nonbooted container/chroot installation and does not certify the choice as applied.
- **F415 / Q33-F018:** prerm swallowed stop failure even on a booted host and let dpkg remove a still-running package. It now refuses removal when systemd is present and stop fails. Nonbooted environments remain supported; disable is best effort. Upgrade does not stop/restart automatically; the updater or administrator performs restart.
- **F416 / Q33-F019:** postinst executes adduser but control omitted the dependency. Depends now declares adduser.

## Executed checks

`scripts/test_debian_lifecycle.py` shares the updater's disposable chroot fixture, requires Linux root, make/dpkg/debconf utility seams and runs with private mount/network/PID namespaces:

```bash
sudo unshare --mount --net --pid --fork python3 -B scripts/test_debian_lifecycle.py
```

Optional QELI_DEBIAN_SOURCE/QELI_DEBIAN_CONFIG_SOURCE select snapshot inputs; QELI_DEBIAN_FIXTURE_RECORDS retains packages and QELI_DEBIAN_OPERATION_RECORDS records actual command results. The Linux CI job includes the exact command; the ShellCheck warning gate now covers preinst/postinst/prerm.

Ten old targeted methods reproduce12 expected failures (the root-link method has three subcases). Final16 methods PASS without skips, including fresh installation, upgrade, failed configure/retry, remove and purge, private empty users, preserved config/users/identity/client-link bytes, bad links/FIFO, debconf replies, root selection and booted/nonbooted failure paths. There are24 actual lifecycle dpkg invocations, plus one admission of seven inert dependency packages. No --force-depends bypass is used. The exact CI command independently passes16 methods and24 lifecycle invocations. Windows16 skips are not runtime qualification.

The production Makefile's deb-prebuilt/stage builds two .deb versions using the production scripts, unit, polkit rule, templates and examples. Version0.8.1 is a synthetic fixture control variation, not an old release artifact. The qeli binary is an inert command recorder. Dependencies are named inert packages; account creation, debconf replies and systemctl are explicit seams. Actual apt resolution, real debconf frontend, account allocation, CLI implementation, ELF/glibc/CPU baseline, daemon/VPN and actual systemd state are not qualified by these tests. The installer from-binary path is not covered and still needs migration of its separate state-file setup.

Two preparation defects (host chroot absent from constrained PATH, inherited host TMPDIR inside chroot) are retained separately and excluded from product findings. Final transferred source SHA matches repository inputs; ShellCheck0.10.0 warning gate and bash syntax PASS. Verified recoverable backup precedes guarded path/process/fd/mount cleanup of the own root. Service MainPID777/worker845 unchanged; host accounts/firewall are not modified.

Evidence: `release/certification/evidence/q33-debian-lifecycle-20261008.json`. Raw `audit-debt-20260924/q33-debian-lifecycle-20261008`:97 files/6721704 bytes; manifest SHA256 `0e2e94ded3ab4c39a26641c5689c98375ba9a22e01e94f9cd729da37df562de2`. Native/Rust build inputs and core artifacts are unchanged; existing14SHA/provenance and38 mocked recipe checks pass without a new heavy build.

Q33 full closure remains open. Full audit29/37 DONE(78.4%),eight remain; Q31 bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, platform USER_EXCLUDED and D06 ACCEPTED_LIMITATION remain. No push/deploy/release.
