# Q33: конфигурация Docker entrypoint и публикация при первом запуске

<!-- normative-sync: q33-docker-entrypoint-v2 -->

8 октября2026. Первый пакет F400–F403/Q33-F003–F006 проверил entrypoint; итоговый Docker runtime F446–F448 ниже. Реальные DEB/update/systemd/VPN и полный installer квалифицированы отдельными отчётами Q33. Раздел IN_PROGRESS до итоговой сверки критериев.

## Воспроизведённые ошибки и исправления

Четыре проверки старого поведения падают на dash и ash (восемь ожидаемых FAIL):

- Пустой argv приводит к `shift` и выходу вместо документированного server по умолчанию. Теперь сдвигается только переданный аргумент роли.
- Переданный `--config` добавляется после внедрённого default: Clap отвергает дубликат, а создание конфига затрагивает другой файл. До записи entrypoint разбирает `--config PATH`, `--config=PATH`, `-c PATH`, `-cPATH`, сохраняет argv и добавляет путь лишь при отсутствии CLI-опции. Явный CLI-путь имеет приоритет над QELI_CONFIG. Пропущенный/пустой/дублированный путь отвергается до записи. Help/version передаются executable без создания файлов.
- Новые config/users наследуют umask022 и получают0644. Теперь umask077 и mktemp0600; байты и режимы существующих файлов сохраняются.
- Висячая ссылка users.conf проходит прежнюю проверку отсутствия, и перенаправление создаёт её цель. Создание config/users отвергает ссылки и не обычные файлы, пишет временный файл рядом и публикует GNU `ln -T`, запрещающим перезапись и каталог как цель. Конкурирующий обычный файл сохраняется; конкурентная ссылка/каталог блокируют запуск. Ошибка copy/link не оставляет частично опубликованный конечный файл, временный файл очищается.

Публикация означает видимость полных байтов, а не fsync/устойчивость к отключению питания. SIGKILL может оставить временный файл. Для первого создания volume должен поддерживать hard links; неподдерживаемая/readonly FS безопасно отвергается. Привилегированные конкурентные изменения родительских каталогов или финального чтения вне этой проверки согласованной публикации. Существующие файлы не chmodятся и не переписываются.

## Выполненные проверки и границы

`python scripts/test_docker_entrypoint.py` требует Linux root/chroot. Необязательный QELI_ENTRYPOINT_ASH_ROOT задаёт распакованный ash/musl; QELI_ENTRYPOINT_TEST_SHELL выбирает shell, QELI_ENTRYPOINT_SOURCE — старые/текущие байты. Вместо qeli используется executable, записывающий argv; daemon не выполнялся.

Точный целый entrypoint выполнялся на .11 в временных chroot и отдельных mount/net/PID namespaces:17 методов на dash/ash,34 сценария и46 запусков PASS без skips. Проверены CLI-формы/приоритет, option-only/пустой запуск, сохранение состояния/прав, help без записей, ссылки/FIFO, детерминированный конкурентный file/link/directory creator, очистка при copy/link failure и shell-метасимволы как данные пути. Обе shell используют настоящие Debian coreutils для публикации; ash взят из сохранённого SHA-проверенного OpenWrt userspace, совместимость с BusyBox-утилитами не заявляется.17 платформенных skips Windows не квалифицируют runtime.

В существующий Linux CI job добавлена команда `sudo unshare --mount --net --pid --fork python3 -B scripts/test_docker_entrypoint.py`. Та же последовательность аргументов выполнена root на .11 в точном fixture двух файлов:17 методов dash/23 запуска PASS без skips. Проверены backup/input SHA и cleanup guards; PID777/845 сохранены. Локальная проверка не означает новый прогон Actions. Отдельный raw: `audit-debt-20260924/q33-docker-entrypoint-ci-20261008`.

Первые ошибки fixture (PATH без chroot, контекст генератора, повторный mkdir и отсутствующий cp) сохранены отдельно и не считаются продуктовыми результатами. После ремонта все четыре старые ошибки воспроизведены на обеих shell, финальный набор PASS. SHA конечных remote-входов совпадает с кандидатами скриптов. Backup SHA проверен локально до удаления собственного каталога с process/fd/mount/resolved-path guards. Service PID777/worker845 не изменились; VPN, host firewall, Docker daemon и production service не запускались/не перенастраивались.

Rust/native recipes, ABI и поставляемые cores не изменились; повтор несвязанных native-сборок не нужен. Доказательства: `release/certification/evidence/q33-docker-entrypoint-20261008.json`. Raw: `audit-debt-20260924/q33-docker-entrypoint-20261008`,25 файлов/2072139 байт; manifest SHA256 `8596d49f7129b2b32856cadd0f60ab6fd6c3ea0d288d21b1fdcc80effe283e46`.

Штатный bootstrap Rust SDK Q31 отложен по ресурсам, это не PASS и не compile FAIL; release source-cut/current Actions OPEN. Q29/Q30/user exclusions и D06 accepted limitation сохранены. Полный план29/37(78.4%),осталось восемь. Push/deploy/release не выполнялись.

## Docker runtime и публикация — 8 октября, F446–F448

F446 / Q33-F049: ручной workflow_dispatch из `dev` разрешал raw `latest`, поскольку проверял только отсутствие дефиса. Теперь до login/build выполняется SemVer validation: branch получает только полный SHA-tag, release tag — версию и SHA; стабильный tag допускает latest, prerelease — нет. `flavor: latest=false` запрещает независимое автоматическое добавление latest metadata-action. Неверный release tag отвергается до записи outputs. Семь policy/CLI/workflow-contract методов PASS, 18 CI-admission и 38 recipe-regressions PASS. Это локальная проверка контракта, а не запуск Actions/push: дополнительный запуск upstream action без GitHub API context/token вернул rc1 и сохранён как NOT_QUALIFIED.

F447 / Q33-F050: Docker compiler stage использовал Cargo.lock без `--locked`; теперь невозможное разрешение по текущему lockfile останавливает сборку вместо его тихого изменения. Тяжёлый compiler stage в этом пакете не повторялся: named context `build=<artifact>` заменил одноимённый stage уже квалифицированным release ELF. Production runtime stage, apt packages, examples и entrypoint собраны и исполнялись настоящим Docker.

F448 / Q33-F051: четыре устаревшие ручные обвязки (`docker_test.py`, `docker_kick_test.py`, `docker_2container_test.py`, `test_route_push_docker.py`) удаляли общие имена/каталоги, игнорировали SSH exit status; `0% packet loss` совпадало и с `100% packet loss`. Эти не подключённые к CI скрипты удалены; ссылки мануала переведены на [owned runtime fixture](../../../../scripts/audit_docker_runtime_case.py). Он использует отдельный socket/CLI config, уникальные имена и labels, проверяет ownership перед cleanup, реальный exit code ping и route. Старые panel-edit/kick/route-push/Internet NAT/throughput сценарии этим запуском не повторяются; исторические benchmark-числа сохранены как история.

### Реальное выполнение: 26 PASS

На .11: Debian13/kernel6.12.105, временный Docker29.8.2 + Buildx0.38.0; service MemoryMax1GiB/CPUQuota100%, delegated subgroup; контейнеры256MiB/0.7CPU. Внешняя сеть используется только для получения tools/base/apt и сборки слоя. Qeli работает в отдельных container NET на собственном bridge; host ports не публикуются, host NET не используется. Daemon bridge=none/iptables=false/ip6tables=false/ip-forward=false/ip-masq=false; AppArmor docker-default, builtin seccomp и private cgroup namespace сохранены, privileged=false.

Image ID `sha256:f72fd97409da8c515c0771395dcf96227f60bf6ca6ddf493ea8a8c0b5784fcc9`; runtime ELF `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd` из настоящего production release от9afbb348, Rust/Cargo/core/native inputs не менялись. RepoDigests пуст: это локальный image ID, не опубликованный registry manifest digest/attestation. Export actual image tar SHA256 `357271c9ddb26bfc5dd194c174c90716a1d99a8cffb10682291e76e29612c9a8` сохранён в recoverable archive.

Проверены actual CLI/dependency inventory и help без записи; first seed INI/users root0600/empty users; отказ readonly volume без частичных файлов; Argon2 add-client/set-web-password/show-identity. Server/client с pinned key и default H-1: по три реальных inner ping в fresh/recreated/rollback, route через q33dkvpn. Login HTTP200 — готовность защищённой панели, а не выполненный authenticated login или Docker HEALTHCHECK. Все шесть container stops дали exit0, без OOM/SIGKILL. Успешные restart/recreation сохраняют bytes/UID/mode config/users/identity/session state; изменяемый `etc/usage.json` закономерно записывает counters и проверяется отдельно от immutable state. Повреждённый executable image завершается ненулевым кодом, volume остаётся цел; прежний image ID восстанавливает VPN. Это операторское восстановление по сохранённому образу, автоматический rollback Docker не заявлен.

### Исходные ошибки стенда и восстановление

FAIL сохранены: parent cgroup с внутренними процессами; stale PID1/PID10 после завершённого private PID namespace; сравнение обновлённого usage.json со статическим snapshot; raw image ID в Dockerfile FROM. Исправлены DelegateSubgroup, отдельный exec/PID path после проверки отсутствия daemon/mounts, критерий immutable state и проверенный local tag для parent build. После graceful dockerd exit transient unit автоматически выгрузился; дополнительный `systemctl stop` вернул not-loaded, recovery отдельно подтвердил отсутствие процессов и восстановление профилей. Это ошибки обвязки, не новые product regressions; ни один исходный FAIL не заменён на PASS.

Временные containers/network/daemon удалены, только созданный здесь docker-default profile выгружен после проверки отсутствия пользователей профиля; исходный список AppArmor полностью восстановлен. На обоих hosts все network/firewall/resolver/listener/namespace snapshots совпадают с baseline; .11 qeli777/845 и installed ELF75bc593e сохранены. Own root SHA-archived, архив скачан и сверён; удаление только после guards exe/cwd/root/fd/mounts. `q33-docker-runtime-20261008`: SEALED 137 files / 360220146 bytes; manifest SHA256 `de3c519bbab67a0881c2b579146a0f2132b8cf06ece667a0e0d10259952f2eb7`.

Docker runtime/volume/recreation/known-image recovery gate закрыт. Compiler stage/multiarch/registry publish/attestation/current Actions не квалифицированы этим пакетом; итоговая сверка Q33 command/hook paths и критериев раздела остаётся. Q33 IN_PROGRESS; общий план29/37 DONE78.4%,осталось8; прежние Q29 SIGKILL/ENONET, Q30 Apple callbacks, Q31 capacity/source cut и USER_EXCLUDED/D06ACCEPTED не меняются. Локальный dev commit, без push/deploy/release.
