# Q34: full amd64 Docker build and release admission

<!-- normative-sync: q34-docker-build-v1 -->

Date:9 October2026.

## F480 / Q34-F034: Docker tag must match Cargo and successful CI

Docker publication checked only SemVer syntax. Actual Git fixture tagv0.8.3 on
Cargo0.8.2 received release_tag=true/stable_release=true; the old workflow could
publish a version label inconsistent with its executable, without exact-source
CI admission. Checkout now uses full github.ref/fetch-depth0, followed by shared
release_tag.py --tag "$GITHUB_REF_NAME" --require-ci for release tags. Added
actions:read/GH_TOKEN; admission precedes QEMU/buildx/login. Actual CLI refuses
mismatch before the CI query. Branch builds keep SHA-only tags. Already qualified
helper checks missing/failed/stale CI and tag/source/version drift; no hosted
workflow execution claimed.

## Actual whole Dockerfile build

Private .11 socket/data/config/transient unit and mount/PID namespaces; daemon
firewall/forwarding/masquerade disabled. Docker29.8.2/Buildx0.38.0 recovered only
from prior SHA-qualified tools archive, no global installation or old daemon
state. Input is committed Git archive3ed8d1fba97b154d357d7ba5f4b05704a52c3280;
Rust/compiler/runtime COPY inputs unchanged since snapshot. New publication
workflow/tests and README/docs do not compile into the image. Fresh Rust/Debian
digest pulls and complete default cargo build --locked --release --features
jemalloc --bin qeli PASS in826.546seconds, without named-context binary override
or imported target cache. Default fatLTO/codegenunits1/optlevel3/panicabort kept.
CPU affinity/quota1,RAM1536MiB; own-unit swap ceiling raised512→1536MiB after
checking existing free swap, no global VM/sysctl edits. OOM counters0;
MemoryPeak1610616832. One actual amd64 build, not A/B/multiarch/reproducibility.

Image ID sha256:a22e4c0180b0079ff832c18472ecd4c8baa30755be92a1ccd2a1f52d4053fe36.
Fresh extracted ELF SHA25698335046d0c16b2126b22334102011ecfaff8390e0a3b09be5e6c7df87104bc2.

## Image and runtime

Actual docker cp533 legal files matched transferred inputs; canonical checker
validated extracted image payload, not reconstructed source. RootLICENSE/LICENSING,
8examples,actualCLI0.8.2/runtime commands/dpkg/base-system copyright resources
PASS. Networknone/read-only/cap-drop inventory ran inside actual image. Compact
runtime26 checks PASS on newELF:pinnedTCP VPN/innerpings/TUN route,authenticated
panel200,root0600 seed/readonly refusal,state bytes-owner-mode,recreation,
deliberate invalidELF image and known-image rollback. Six exit0 without OOM/SIGKILL.
Defaultseccomp/privateNET checked;AppArmor explicitlyunconfined,new default-profile
confinement not qualified.

Docker automatically loaded one docker-default(enforce) despite explicit
unconfined containers. After daemon stop, profile absent in baseline/exact sole
delta/no users/no otherDocker processes proved ownership;only that profile removed,
full AppArmor baseline restored.
[Docker AppArmor](https://docs.docker.com/engine/security/apparmor/).
OriginalPID777845/serviceCLI SHA/network-firewall-resolver snapshots match.
Daemon stopped gracefully;manager collected transient unit:notfound/inactive/PID0.
Recoverable archive preserves exact image export/source/fixtures/logs/bothsynthetic
volume trials. Public engine/compiler cache and unchangedtools explicitly excluded;
recovery references prior SHA-qualified public/tool archives. Not a full daemon-cache
snapshot. Local archive SHA/contents/image export verified before /proc/mountguarded
own-root cleanup.

## Checks and retained failures

- 64 distinct focused methods PASS:19release-tag/workflow,7Docker classification,38native recipe contracts. Actual mismatch CLI baseline/refusal and SHA-qualified YAML parser confirmed gate condition/ref/permissions/order.
- Wholeamd64 compiler/runtime image/canonical533notices/26actualcontainerchecks PASS. No new desktop/native14 rebuild,SDK/APK/device/throughput tests.
- Initial harness failures retained: Docker tar top-directory guard,escaped progress newline,generic freeRAM swap-admission refusal,wrongdefaultAppArmor expectation,collected transient-unit stop,unexpectedautomaticprofile addition. Repaired/restored in owned fixture scope,not relabelled productPASS.
- Native digest/evidence/14artifactSHA/protected source/docs checked separately. PriorQ33defaultAppArmor/otherruntime evidence retains originalsource/date/scope,no new PASS for those excluded paths.

Q34IN_PROGRESS30/37DONE81.1percent7remain.MultiarchDocker,immutableAPT/frontend
inputs,current-sourceActions/OIDC/signatures/fullrelease,matchingthirdpartysource
publication/OpenWrtSDKsourcecut/MicroComexactsource remainOPEN.Q29SIGKILLFAIL-ENONET,
Q30/Q31/F459braces/D06ACCEPTED_LIMITATION/USER_EXCLUDED preserved.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-docker-build-20261009`: SEALED 132 files / 117007941 bytes; manifest SHA256 `24bd8604eb638e667f9e14d871a7b4e2bc72340086f018050043898dde5d2799`.
