# Q33: actual portable DEB, update and rollback

<!-- normative-sync: q33-package-manager-v3 -->

8 October 2026. The scoped DEB/update/remove gate uses actual apt/dpkg, debconf, release CLI and systemd. Q33 remains IN_PROGRESS; the full plan is 29/37 DONE (78.4%), 8 sections remain. No product code defects were found in this stage.

## Build and exact artifacts

Actual `make deb-portable` from commit `9afbb348626ab14d95f86d9ec38117fabb52803d`: Rust 1.97.0, cargo zigbuild, jemalloc, release/fat LTO, locked/offline, one build job, private CARGO_HOME/target/zig caches. Only ZIG_BINARY's path to the same portable target was overridden. The production recipe passed maximum GLIBC 2.28, AES-NI/CPUID heuristic and dpkg-deb/XZ packaging. The heuristic does not prove every CPU path. Build ran on the memory-constrained .10; existing processes 745/901 remained running.

- ELF: 14289320 bytes, SHA256 `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd`.
- DEB: 4553344 bytes, SHA256 `b3d0363b58cc1ae36c3b5da3518fb9d9a8e00d6153b442ac477a5772f36c9809`.

This is not independent A/B reproducibility or release attestation. The qeli Git blobs match the final helpers commit: product code, Cargo inputs and native libraries are unchanged. Previously qualified native A/B and ABI evidence is retained; another client rebuild was unnecessary.

## Isolation and actual components

The .11 fixture has a private chroot with its own dpkg DB, apt/debconf/cache, configuration and unit mapping. It runs genuine apt-get, dpkg, debconf, production maintainer scripts and release CLI. The qeli account and installed dependency status are seeded from the lab; fresh account creation and dependency bootstrap are outside this test. Repositories are empty; QELI_DEB avoids HTTP/download/attestation.

Only the actual systemd 257 manager socket and owned unit/drop-in directories are bound. SYSTEMD_IGNORE_CHROOT enables the genuine client to contact the manager. An explicit adapter maps qeli.service to a unique owned unit, redirects only config/binary/state/runtime/log paths and adds an owned network namespace/control socket. It never fabricates apt, systemctl or health results. Lifecycle commands require the exact network/config/binary bindings. Enable/disable use only runtime state for the owned unit. This qualifies the explicit adapter setup, not a replacement of the host's production qeli.service.

Original service PID/start timestamp, ELF SHA and network snapshot on .11 match before/after; existing processes 777/845 are preserved. No external VPN peer is involved. Real TCP443, panel24990 and TUN live only in the owned network.

## Final 24 checks PASS

1. Fresh dpkg install with genuine postinst/debconf/CLI; exact `install ok installed 0.8.2-1`; actual supervisor/worker and listeners ready.
2. Updater installs revision -2 and exits 0; package DB is fully configured, supervisor changes and listeners recover.
3. Revision -3 intentionally breaks ExecStart. Updater exits 1 and restores cached -2 using actual apt downgrade; configured DB, ELF and running service recover.
4. Revision -4 intentionally corrupts the ELF. Actual postinst/CLI rejects it; updater exits 1 and restores configured -2 and service.
5. All three transitions preserve bytes/UID/mode of INI, users, identity, administrator receipt and backup. The root0600 rollback cache contains the exact DEB. Updater health means a stable supervisor PID; the fixture also checks listeners, not every profile's health.
6. Actual apt remove invokes prerm and stops the owned service; dpkg purge removes packaged examples while preserving operator config/users/identity/receipts/backups.

Revisions -1/-2 share the same release ELF: package revision upgrade is tested, not compatibility between core versions. Fault packages alter only Version and the specified fault location; production maintainer scripts are compared to Git bytes and never substituted.

## Fixture failures and evidence

Three original FAIL runs are retained: missing portable libpthread runtime; missing dpkg architecture tables; apt sanitized PATH and could not reach the /usr/local/bin systemd adapter from postinst. Only audit helpers changed: real loader libraries, dpkg/Perl data and the standard /usr/bin adapter path. All FAIL runs restored the host. Only the final runtime has PASS.

Helpers: `scripts/audit_package_manager_lab.py` and `scripts/audit_package_manager_fixture.py`. Driver requires explicit artifact SHAs and a new output directory; SSH password is read only from stdin. Optional reuse copies only SHA-verified package/ELF inputs from a strict owned /var/tmp/qeli-q33-pkg-* path. Initial-stage helper commit `f1ce7892`.

Every owned root was archived and its downloaded SHA checked, then removed after repeated process cwd/exe/root/fd and mount guards. SSH credential scan covers raw files and uncompressed recoverable archive members; raw manifests are sealed. The previous 20 SEALED packets remain unchanged.

- `q33-package-manager-20261008`: PASS, SEALED 19 files / 54018014 bytes; manifest SHA256 `8c22c42d377bd09f0f459e38c74cddf9409a23052a95efcb68852c3a0ee5983d`.
- `q33-package-manager-runtime-20261008`: FAIL, SEALED 7 files / 87061128 bytes; manifest SHA256 `8120803fabeedf107e2fe44102a36b38e5ece76c81e7b2e9a387630b447c70e0`.
- `q33-package-manager-fixed-20261008`: FAIL, SEALED 7 files / 98297976 bytes; manifest SHA256 `cae6c74cacf938c0ad196657a7bc39a12189118745e6bfd7d6b31f3e3aa62e95`.
- `q33-package-manager-qualified-20261008`: FAIL, SEALED 7 files / 107849891 bytes; manifest SHA256 `aa7414aba3b0997980a0b8599043ad41371ede8043657a4baa10a8764371e839`.
- `q33-package-manager-final-20261008`: PASS, SEALED 8 files / 101777324 bytes; manifest SHA256 `ab426256d692ae7f0ddf7bce58d7afdce1a3f5598387674c10b692b3838885a1`.


## Addendum: release VPN and traffic through the packaged service

The same production DEB SHA `b3d0363b58cc1ae36c3b5da3518fb9d9a8e00d6153b442ac477a5772f36c9809` was extracted without host installation; ELF SHA `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd` verified. No rebuild: qeli/Cargo Git inputs are unchanged.

**Release ELF matrix: 18 scenarios / 376 checks PASS.** Actual server/client in owned NET/mount/PID namespaces: 12 outer4/outer6 × inner4/inner6 × TCP fake-TLS/UDP fake-TLS/UDP QUIC full-tunnel; two dual-stack split; TAP NDP/RA; DNS with IPv4/IPv6 upstream and forced TCP IPv6 through actual resolved; MTU1280/PMTU/DATA_FRAG/PTB; both directions 0.7.16 ↔ 0.8.2. Checks cover authenticated inner traffic, no unsupported-family leak, split routes and route/TUN restoration after clean stop. Aggregate leak criterion for all 14 main cells PASS. Matrix uses bind_static=false/TOFU; it does not qualify pinned H-1 across all 18 scenarios. SIGKILL/roaming soak and extended fault flags were not enabled.

**Packaged systemd pipeline: 36 checks PASS.** The initial production apt/dpkg/debconf/CLI/systemd gate now includes a separate actual client on a private veth carrier. Service runs as qeli with packaged sandbox/capabilities; client pins the actual profile key and default bind_static/H-1 stays enabled. After fresh install, successful revision upgrade and both fault rollbacks, three inner pings succeed, route get proves the client TUN path, and clean client stop removes TUN. Traffic succeeds after restoration of configured package -2. Each stage creates a new client connection; uninterrupted existing sessions during restart are not claimed. This uses one TCP fake-TLS profile, DNS off and client kill-switch off. Other transports use the separate matrix.

`--vpn` enables this scenario in both package helpers. Client has private NET/mount/PID namespaces and tmpfs /run,/var/lib,/var/log; carrier links are created within the owned server namespace. Clean stop signals only the owned client ELF PID with SIGTERM; timeout is FAIL with bounded cleanup. One original FAIL is retained: helper called show-identity as root against qeli-owned configuration, and product trust correctly refused. The repair uses genuine setpriv/show-identity as qeli without altering trust or ownership. Final runtime helper commit `617dc010`; product source remains 9afbb348.

Docker/podman/nerdctl/ctr were absent on .11, so actual image/volume/recreate runtime was not executed. systemd-resolved missing from PATH did not mean its daemon was absent: DNS fixtures found the genuine lib/systemd executable and DNS runtime passed. Original service/listener, firewall, routes, resolver and named namespaces match before/after both runs; processes777/845 and installed host ELF are preserved. .10 was not used in this stage.

Five owned runtime/artifact/seed roots were archived and downloaded SHAs verified, followed by repeated process cwd/exe/root/fd and mount guards before removal. SSH credential scan covers raw files and uncompressed archive members. New raw packets:

- `q33-release-vpn-20261008`: PASS, SEALED 108 files / 15612281 bytes; manifest SHA256 `df241ef3e5a438b04590da49945bf458c76aa931cd23f87ca9865ac6a4d40b87`.
- `q33-packaged-vpn-20261008`: FAIL, SEALED 13 files / 98482535 bytes; manifest SHA256 `c7d71fed01555fd94aae234f90c1e36c255eea544458e76b4fec01de2b67e97f`.
- `q33-packaged-vpn-final-20261008`: PASS, SEALED 7 files / 101843455 bytes; manifest SHA256 `f2e7cbe603bb2af933cab4764f4a64356d59169003caf32d3d0db4403204213c`.


Release data-plane and package→systemd→VPN after install/upgrade/rollback close in this isolation. No new product fixes, native/Rust rebuild, benchmark, independent release reproducibility or Actions run. The previous 25 SEALED packets and certification history are retained; append the 67th scoped supplement to the previous 41 cases/acceptance and 66 supplements.

## Remaining work

This closes package lifecycle/rollback in the stated isolation. [The subsequent complete installer/kernel gate](AUDIT-Q33-INSTALLER-CONFIG.md) closes both positive install branches, VPN and partial kernel apply/recovery; all-or-nothing rollback of installer actions is not claimed. Docker image/volume runtime, independent release reproducibility and current remote Actions remain open. Full Rust suite, matrix, soak and benchmark were not rerun. Q31 SDK/bootstrap/source-cut/Actions, Q29 SIGKILL/ENONET and Q30 Apple/callback retain their previous status. Mac/iOS, router and Windows network VM are user-excluded; D06 is an accepted limitation.

Certification preserves 41 cases/acceptance and 66 prior supplements and adds the 67th scoped supplement. The 20 required automated and 21 advisory physical rows remain separate; historical dates, artifacts and outcomes are unchanged. Local dev commit; no push/deploy/release.
