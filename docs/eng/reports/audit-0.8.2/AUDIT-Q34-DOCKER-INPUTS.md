# Q34: immutable Docker frontend and APT inputs

<!-- normative-sync: q34-docker-inputs-v1 -->

Date: 9 October 2026.

## F481 / Q34-F035

The same source commit could load a changed `docker/dockerfile:1` frontend and
new runtime packages from live Debian mirrors. Two regression methods failed
against the exact prior recipe. The frontend is now SHA256 pinned; the only APT
sources are the Debian and Debian-security snapshot `20261008T000000Z`. Inherited
`.list`/`.sources` are removed before policy COPY. Bookworm, bookworm-updates and
bookworm-security share one date, in `release/docker/debian.sources`.

Frontend digest `4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e`
matches the preceding whole amd64 build. Fresh official index, amd64 manifest and
config bodies match SHA; the index includes amd64, arm64 and arm/v7. This binds
identity, without claiming fresh frontend execution.
[Docker frontend documentation](https://docs.docker.com/build/buildkit/frontend/).

HTTP permits bootstrap without CA certificates in the slim image. APT archive
signatures and package hashes remain mandatory through the Debian archive keyring.
Only the historical metadata expiry check is disabled in these two stanzas;
there is no trusted=yes, allow-unauthenticated or global insecure bypass.
The snapshot also freezes security updates: update its date explicitly and repeat
qualification. [Debian snapshot](https://snapshot.debian.org/).

## Actual APT qualification

Official pinned Debian index, amd64 manifest, config and sole rootfs layer were
SHA checked. The exact base bytes and new sources cleanup/COPY were used in a
separate chroot/mount/PID namespace on .11, with512MiB/oneCPU and no Docker daemon
or host APT installation. APT2.6.1 verified three independently retrieved InRelease
signatures, updated indices and installed all13 runtime packages:62new packages,
150installed total. Thirteen commands, apt-get check and repeat simulation passed;
repeat required zero changes. All three APT InRelease files match independently
retrieved official HTTPS bytes. One package remains not upgraded: this qualifies
runtime installation, not full-upgrade or a vulnerability audit.

Three modified signed bodies failed gpgv. Actual APT rejected an isolated file
repository with a modified InRelease through BADSIG/exit100, without relying on a
network server. All66 focused methods pass:21release-tag/workflow,7Docker ref,
38native recipes. Two new methods reject the prior unpinned inputs.

## Recovery and limits

Original service777845/CLI SHA/network/firewall/resolver/AppArmor snapshots match.
Own unit stopped; full installed rootfs/source/fixtures/logs recoverable archive
was downloaded and its SHA/critical bytes verified before /proc/mount guarded
own-root/archive deletion. The separately retained SHA-qualified public base layer
is excluded from the duplicate backup; proc/dev mounts are ephemeral. No host
packages or AppArmor profile were installed.

Initial harness failures are retained:CRLF shell,collected transient unit,missing
/dev/null for the repeated negative fixture and repeated directory creation.
The first backup verifier also expected a regular file instead of the standard
ip symlink;the link chain and actual target SHA were verified. Only owned harness
fixtures changed;failures were not rewritten as PASS.

No fresh whole Docker compiler/image build, ARM installation, VPN runtime, A/B
reproducibility, hosted Actions/signing/publication. Previous build evidence retains
its source/date; the new policy has actual amd64 APT and source-contract qualification.
Native digest/14 artifact SHA remain unchanged. Matching third-party source,
OpenWrt SDK source cut,MicroCom exact source,F459braces and other prior limits
remain OPEN. Q34 IN_PROGRESS,30/37DONE81.1percent,7remain;Q29SIGKILLFAIL/ENONET,
Q30/Q31,D06 ACCEPTED_LIMITATION/USER_EXCLUDED preserved.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-docker-inputs-20261009`: SEALED 92 files / 101517131 bytes; manifest SHA256 `52fc5c0767d1b726f2127eb18c491eb2de3fe48d97b62748a7bab1cf8e9d0e9e`.
