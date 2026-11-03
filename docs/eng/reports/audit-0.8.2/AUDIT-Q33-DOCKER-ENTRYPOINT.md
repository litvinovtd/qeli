# Q33: Docker entrypoint configuration and first-run publication

<!-- normative-sync: q33-docker-entrypoint-v2 -->

8 October2026. Initial F400–F403/Q33-F003–F006 batch covered the entrypoint; final Docker runtime F446–F448 follows below. Actual DEB/update/systemd/VPN and full installer have separate Q33 reports. Section remains IN_PROGRESS pending final criterion reconciliation.

## Reproduced failures and changes

Four old behavior checks fail on both dash and ash (eight expected failures):

- Empty argv reaches `shift` and exits instead of choosing the documented server default. The script now shifts only a supplied role.
- A supplied `--config` is appended after an injected default option. Clap rejects duplicates, and seeding also touches the wrong file. The entrypoint resolves `--config PATH`, `--config=PATH`, `-c PATH` and `-cPATH` before seeding, preserves argv and injects a path only when the CLI supplies none. An explicit CLI path overrides QELI_CONFIG. Missing/empty/duplicate paths refuse before writes. Help/version options go directly to the executable without seeding.
- First-run config and users files inherit umask022 and are0644. New files now use umask077 and mktemp0600; existing files retain their bytes and modes.
- A dangling users.conf symlink passes the old missing-file check and the empty-file redirection creates its target. Config and users seeding now refuse links and nonregular names. They write a private same-directory temporary file and publish with GNU `ln -T`, which refuses replacement and directory destinations. A concurrent regular creator is preserved; a raced link/directory refuses startup. Failed copy/link leaves no partially published final file and cleans the temporary file.

Publication means complete visible bytes, not fsync/power-loss durability. SIGKILL may leave a temporary file. The volume must support hard links for first-run creation; unsupported/read-only filesystems refuse safely. Privileged concurrent changes to parent directories or final reads are outside this cooperative publication check. Existing files are not chmodded or rewritten.

## Executed checks and scope

`python scripts/test_docker_entrypoint.py` requires Linux root/chroot. Optional QELI_ENTRYPOINT_ASH_ROOT supplies extracted ash/musl; QELI_ENTRYPOINT_TEST_SHELL chooses the shell and QELI_ENTRYPOINT_SOURCE selects baseline/current bytes. This is an argv-recording qeli executable seam, not daemon execution.

The exact whole entrypoint ran on .11 inside disposable chroots in private mount/net/PID namespaces:17 methods per dash/ash,34 scenarios and46 invocations PASS with no skips. Cases include CLI forms/precedence, option-only/no-argument calls, preserved state/modes, help without writes, links/FIFO, deterministic competing file/link/directory creation, copy/link failure cleanup and shell metacharacters as path data. Both shells use actual Debian coreutils for publication; ash is retained SHA-admitted OpenWrt userspace, not a BusyBox-utilities compatibility claim. Windows's17 platform skips do not qualify runtime.

The existing Linux CI job now runs `sudo unshare --mount --net --pid --fork python3 -B scripts/test_docker_entrypoint.py`. The same argument sequence executed as root on .11 in an exact two-file fixture:17 dash methods/23 invocations PASS without skips. Fixture backup/input SHA and cleanup guards passed; PID777/845 unchanged. This local check does not claim a new Actions run. Separate raw packet: `audit-debt-20260924/q33-docker-entrypoint-ci-20261008`.

Initial fixture failures (PATH omitted chroot, generator context, repeat mkdir and missing cp) are retained separately and are not product verdicts. After repair, all four baseline defects reproduced on both shells and the final suite passed. Final remote input SHA matches the committed candidate scripts. Backup SHA was verified locally before process/fd/mount/resolved-path guarded removal of the exact owned root. Service PID777/worker845 stayed unchanged; no VPN, host firewall, Docker daemon or production service was started/reconfigured.

Rust/native recipes, ABI and packaged cores are unchanged; no unrelated native rebuild is required. Evidence: `release/certification/evidence/q33-docker-entrypoint-20261008.json`. Raw packet: `audit-debt-20260924/q33-docker-entrypoint-20261008`,25 files/2072139 bytes, manifest SHA256 `8596d49f7129b2b32856cadd0f60ab6fd6c3ea0d288d21b1fdcc80effe283e46`.

Q31 SDK upstream bootstrap is capacity-deferred, not PASS/compile FAIL; release source-cut/current Actions remain OPEN. Q29/Q30/user exclusions and D06 accepted limitation remain. Full plan29/37(78.4%),eight remain. No push/deploy/release.

## Docker runtime and publication — 8 October, F446–F448

F446 / Q33-F049: manual workflow_dispatch on `dev` enabled raw `latest` because it only checked for a hyphen. SemVer validation now runs before login/build: branches receive a full SHA tag; release tags receive version and SHA; only stable release tags enable latest. `flavor: latest=false` prevents metadata-action from adding latest independently. Invalid release tags refuse before outputs are written. Seven policy/CLI/workflow-contract tests PASS, plus18 CI-admission and38 recipe regressions. These are local contract checks, not Actions/push: an additional upstream action execution without GitHub API context/token returned rc1 and remains NOT_QUALIFIED.

F447 / Q33-F050: Docker compiler stage used Cargo.lock without `--locked`; incompatible resolution now stops instead of silently changing the lockfile. The heavy compiler stage was not repeated: named context `build=<artifact>` replaced the same-named stage with the qualified release ELF. The production runtime stage, actual apt packages, examples and entrypoint were built and executed by real Docker.

F448 / Q33-F051: four obsolete manual harnesses (`docker_test.py`, `docker_kick_test.py`, `docker_2container_test.py`, `test_route_push_docker.py`) removed shared names/directories and ignored SSH status; `0% packet loss` also matched `100% packet loss`. These scripts, unused by CI, were removed; manual links now point to the [owned runtime fixture](../../../../scripts/audit_docker_runtime_case.py). It uses a private socket/CLI config, unique names/labels, ownership checks before cleanup, actual ping status and route. This execution does not repeat historical panel-edit/kick/route-push/Internet NAT/throughput cases; historical benchmark figures remain historical.

### Real execution: 26 PASS

On .11: Debian13/kernel6.12.105, temporary Docker29.8.2 + Buildx0.38.0; service MemoryMax1GiB/CPUQuota100%, delegated subgroup; containers256MiB/0.7CPU. External networking only obtains tools/base/apt and builds the layer. Qeli uses separate container NET on an owned bridge; no host ports or host-network Qeli. Daemon bridge=none/iptables=false/ip6tables=false/ip-forward=false/ip-masq=false; docker-default AppArmor, builtin seccomp and private cgroup namespaces remain enabled, privileged=false.

Image ID `sha256:f72fd97409da8c515c0771395dcf96227f60bf6ca6ddf493ea8a8c0b5784fcc9`; runtime ELF `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd` from genuine production release9afbb348, unchanged Rust/Cargo/core/native inputs. RepoDigests is empty: this is a local image ID, not a published registry manifest digest/attestation. Actual exported image tar SHA256 `357271c9ddb26bfc5dd194c174c90716a1d99a8cffb10682291e76e29612c9a8` is retained in the recoverable archive.

Actual CLI/dependency inventory, help without writes, first seed INI/users root0600/empty users, readonly refusal without partial files, Argon2 add-client/set-web-password/show-identity. Pinned/default-H1 server/client carry three actual inner pings each on fresh/recreated/rollback, with q33dkvpn route proof. Login HTTP200 shows password-protected panel readiness; it is not an authenticated login or Docker HEALTHCHECK. All six container stops exit0 without OOM/SIGKILL. Restart/recreation preserve config/users/identity/session bytes/UID/mode; mutable `etc/usage.json` legitimately flushes counters and is separated from immutable state. A corrupt executable image exits nonzero without damaging volumes; the prior image ID restores VPN. This is operator recovery with a saved image, not automatic Docker rollback.

### Initial harness failures and restoration

Retained FAIL: parent cgroup internal processes; stale PID1/PID10 after private PID namespace termination; comparing updated usage.json to an immutable snapshot; raw image ID in Dockerfile FROM. Fixed delegated subgroup, separate exec/PID paths after no-daemon/mount guards, immutable-state criterion and a checked local parent tag. After graceful dockerd exit the transient unit was garbage-collected; a redundant stop returned not-loaded, and separate recovery confirmed no processes and restored profiles. These are harness failures, not new product regressions; initial FAIL is never relabelled PASS.

Owned containers/network/daemon removed; only the newly created docker-default profile unloaded after checking no process uses it; the original AppArmor list is fully restored. Both hosts match baseline network/firewall/resolver/listener/namespace snapshots; .11 qeli777/845 and installed ELF75bc593e remain. The owned root was SHA-archived, downloaded and verified; removal followed exe/cwd/root/fd/mount guards. `q33-docker-runtime-20261008`: SEALED 137 files / 360220146 bytes; manifest SHA256 `de3c519bbab67a0881c2b579146a0f2132b8cf06ece667a0e0d10259952f2eb7`.

Docker runtime/volume/recreation/known-image recovery gate closed. Compiler stage/multiarch/registry publication/attestation/current Actions are not qualified here; final Q33 command/hook and criterion reconciliation remains. Q33 IN_PROGRESS; full plan29/37 DONE78.4%,8remain; Q29 SIGKILL/ENONET, Q30 Apple callbacks, Q31 capacity/source cut and USER_EXCLUDED/D06ACCEPTED remain unchanged. Local dev commit, no push/deploy/release.
