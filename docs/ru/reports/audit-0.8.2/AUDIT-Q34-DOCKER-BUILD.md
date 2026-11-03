# Q34: полная amd64 Docker build и release admission

<!-- normative-sync: q34-docker-build-v1 -->

Дата: 9 октября 2026.

## F480 / Q34-F034: Docker tag должен совпадать с Cargo и успешным CI

Docker publication проверял только SemVer syntax. Реальный Git fixture с тегом
`v0.8.3` на Cargo0.8.2 получал `release_tag=true`, `stable_release=true`; прежний
workflow мог публиковать version label, несовместимый с executable, без exact
source CI admission. Теперь checkout использует полный `github.ref`/fetch-depth0,
после classifier запускается общий `release_tag.py --tag "$GITHUB_REF_NAME"
--require-ci` для release tags. Added `actions: read`/GH_TOKEN; gate выполняется
до QEMU/buildx/login. Actual CLI отвергает mismatch до CI query. Branch builds
сохраняют SHA-only tags. Missing/failed/stale CI и tag/source/version drift
проверяются уже квалифицированным helper. Сам hosted workflow не запускался.

## Полная сборка actual Dockerfile

На .11 создан отдельный private socket/data/config/transient unit и mount/PID
namespace; firewall/forwarding/masquerade daemon flags выключены. Docker29.8.2 и
Buildx0.38.0 восстановлены только из SHA-qualified прежнего recoverable archive,
без global installation/старого daemon state. Input — Git archive committed
`3ed8d1fba97b154d357d7ba5f4b05704a52c3280`; Rust/compiler/runtime COPY inputs
не изменились после этого snapshot. New publication workflow/tests и README/docs
не компилируются в image. Fresh Rust/Debian digest pulls и whole default build
`cargo build --locked --release --features jemalloc --bin qeli` PASS за826,546с;
нет named-context binary override или перенесённого target cache. Штатные fat LTO,
codegen-units1,opt-level3,panicabort сохранены. CPU affinity/quota1, RAM1536MiB;
swap ceiling собственной unit поднят512→1536MiB после проверки существующего
свободного swap, без global VM/sysctl edits. OOM counters0; MemoryPeak1610616832.
Это одна actual amd64 build, не A/B и не multiarch/reproducible image.

Image ID `sha256:a22e4c0180b0079ff832c18472ecd4c8baa30755be92a1ccd2a1f52d4053fe36`.
Extracted fresh ELF SHA256 `98335046d0c16b2126b22334102011ecfaff8390e0a3b09be5e6c7df87104bc2`.

## Image и runtime

Actual docker cp: все533 legal files совпали с transferred source; canonical
native checker проверил extracted payload, не восстановленную копию. Root LICENSE/
LICENSING и8 examples совпали, actual CLI0.8.2/runtime commands/dpkg/base-system
copyright resources PASS. Networknone/read-only/cap-drop inventory выполнен в
самом образе. Compact runtime26 checks PASS на новом ELF: pinned TCP VPN/inner
pings и TUN route, authenticated panel200, root0600 seed/read-only refusal,
state bytes/owner/mode, recreation, deliberate invalid-ELF image и known-image
rollback. Six exits0, без OOM/SIGKILL. Default seccomp и private NET проверены;
AppArmor явно unconfined, новая default-profile confinement не квалифицирована.

Docker автоматически загрузил один `docker-default (enforce)` даже при explicit
unconfined containers. После остановки daemon baseline не содержал этого profile,
единственная delta, нет users/других Docker processes; удалён только этот owned
profile, полное совпадение AppArmor baseline восстановлено.
[Docker AppArmor](https://docs.docker.com/engine/security/apparmor/).
Original PID777/845, service/CLI SHA/network/firewall/resolver snapshots совпали.
Daemon stopped gracefully; transient unit собрана manager в not-found/inactive/PID0.
Recoverable archive содержит exact image export, source, fixtures/logs и обе
synthetic volume trials. Public engine/compiler cache и прежние tools явно
исключены; их recovery опирается на ранее SHA-qualified public/tool archives.
Это не whole daemon-cache snapshot. Local archive SHA/contents/image export
проверены до /proc/mount-guarded удаления только own root.

## Проверки и retained failures

- 64 distinct focused methods PASS:19 release-tag/workflow,7 Docker classification,38 native recipe contracts. Actual mismatch CLI baseline/refusal и SHA-qualified YAML parser подтвердили gate condition/ref/permissions/order.
- Whole amd64 compiler/runtime image, canonical533 notices и26 real container checks PASS. No new desktop/native14 rebuild, SDK/APK/device/throughput tests.
- Initial harness failures retained: Docker tar top-directory guard, escaped progress newline, generic freeRAM swap-admission refusal, wrong default-AppArmor expectation, collected transient-unit stop and unexpected automatic profile addition. Они исправлены/восстановлены в own fixture scope, не переписаны в product PASS.
- Native digest/evidence/14artifactSHA/protected source и docs проверены отдельно. Prior Q33 default-AppArmor and other runtime evidence keeps original source/date/scope; это не новый PASS этих excluded paths.

Q34 IN_PROGRESS,30/37 DONE81,1%,7 осталось. Multiarch Docker, immutable APT/frontend
inputs, current-source Actions/OIDC/signatures/full release и matching third-party
source publication/OpenWrt SDK source cut/MicroCom exact source остаются OPEN.
Q29 SIGKILL FAIL/ENONET,Q30/Q31,F459 braces,D06 ACCEPTED_LIMITATION,USER_EXCLUDED
не изменены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-docker-build-20261009`: SEALED 132 files / 117007941 bytes; manifest SHA256 `24bd8604eb638e667f9e14d871a7b4e2bc72340086f018050043898dde5d2799`.
