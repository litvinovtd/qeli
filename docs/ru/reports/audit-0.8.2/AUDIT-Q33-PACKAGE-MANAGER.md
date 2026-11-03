# Q33: настоящий portable DEB, обновление и откат

<!-- normative-sync: q33-package-manager-v3 -->

8 октября 2026. Закрыт отдельный этап проверки DEB/update/remove с настоящими apt/dpkg, debconf, release CLI и systemd. Q33 остаётся IN_PROGRESS; весь план — 29/37 DONE (78.4%), осталось 8 разделов. Новых ошибок продуктового кода в этом этапе не выявлено.

## Сборка и точные артефакты

Из commit `9afbb348626ab14d95f86d9ec38117fabb52803d` выполнен настоящий `make deb-portable`: Rust 1.97.0, cargo zigbuild, jemalloc, release/fat LTO, locked/offline, один build job, частные CARGO_HOME/target/zig caches. Переопределён только путь ZIG_BINARY к тому же portable target. Production recipe прошёл проверку максимальной версии GLIBC 2.28, эвристику AES-NI/CPUID и упаковку dpkg-deb/XZ. Эта эвристика не доказывает работу всех CPU paths. Сборка выполнялась на .10 с ограниченной памятью; действующие процессы 745/901 сохранились.

- ELF: 14289320 байт, SHA256 `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd`.
- DEB: 4553344 байта, SHA256 `b3d0363b58cc1ae36c3b5da3518fb9d9a8e00d6153b442ac477a5772f36c9809`.

Сборка не является независимой A/B reproducibility или release attestation. Исходные Git blobs дерева qeli совпадают с финальным commit helpers: код продукта, Cargo inputs и native libraries не менялись. Ранее квалифицированные native A/B и ABI сохранены; повторная пересборка клиентов не требовалась.

## Изоляция и реальные компоненты

На .11 создан отдельный chroot с собственными dpkg DB, apt/debconf/cache, config и unit mapping. Применяются настоящие apt-get, dpkg, debconf, production maintainer scripts и release CLI. Account qeli и состояние установленных зависимостей перенесены из стенда; это не тест создания пользователя и загрузки зависимостей на пустой системе. Repositories пустые; используется QELI_DEB без HTTP/download/attestation.

Для настоящего systemd 257 связан только manager socket и собственные unit/drop-in каталоги. SYSTEMD_IGNORE_CHROOT позволяет реальному клиенту обращаться к manager. Явный адаптер переименовывает qeli.service в уникальный тестовый unit, перенаправляет только config/binary/state/runtime/log paths, добавляет собственный network namespace и control socket. Он не подменяет ответы health/systemctl/apt. Перед lifecycle-командами проверяются точные network/config/binary bindings. Enable/disable выполняются только runtime для собственного unit. Это квалификация с адаптером, а не замена production qeli.service хоста.

Исходные service PID/start timestamp, ELF SHA и сетевой снимок .11 одинаковы до и после; рабочие процессы 777/845 сохранены. Нет внешнего VPN peer. Настоящие TCP443, панель24990 и TUN существуют только в собственной сети.

## Финальные 24 проверки PASS

1. Fresh dpkg install с реальными postinst/debconf/CLI; exact `install ok installed 0.8.2-1`; настоящий supervisor/worker и listeners готовы.
2. Updater устанавливает revision -2, возвращает 0; package DB полностью configured, supervisor заменён и listeners восстановлены.
3. Revision -3 содержит намеренно неисправный ExecStart. Updater возвращает 1, восстанавливает cached -2 через настоящий apt downgrade; DB configured, ELF и работающая служба восстановлены.
4. Revision -4 содержит намеренно повреждённый ELF. Реальный postinst/CLI отвергает его; updater возвращает 1, откат восстанавливает configured -2 и службу.
5. Во всех трёх переходах неизменны bytes/UID/mode INI, users, identity, administrator receipt и backup. Rollback cache root0600 содержит exact DEB. Критерий updater — стабильный supervisor PID; отдельная проверка стенда подтверждает listeners, но не здоровье каждого профиля.
6. Настоящий apt remove вызывает prerm и останавливает собственную службу; dpkg purge удаляет packaged examples, сохраняя пользовательские config/users/identity/receipts/backups.

Revision -1/-2 используют один и тот же release ELF: здесь проверяется upgrade package revision, а не совместимость двух версий ядра. Fault packages меняют только Version и указанную точку отказа; production maintainer scripts проверены по Git bytes и не заменяются заглушками.

## Ошибки тестового окружения и доказательства

Три исходных FAIL сохранены: отсутствовали portable runtime libpthread; затем таблицы архитектур dpkg; затем apt очищал PATH, и адаптер systemd в /usr/local/bin становился недоступен из postinst. Исправлены только audit helpers: реальные loader libraries, dpkg/Perl data и стандартный путь адаптера /usr/bin. Во всех FAIL хост восстановлен. Только финальный запуск имеет runtime PASS.

Helpers: `scripts/audit_package_manager_lab.py` и `scripts/audit_package_manager_fixture.py`. Driver требует явные SHA артефактов, новое output directory и читает SSH пароль только из stdin. Опционально повторно используются лишь SHA-проверенные package/ELF из строгого собственного /var/tmp/qeli-q33-pkg-* пути. Helper первого этапа — commit `f1ce7892`.

Все собственные roots архивированы, SHA проверены после скачивания, затем удалены после повторных process cwd/exe/root/fd и mount guards. Секрет SSH проверен в raw files и распакованном содержимом recoverable archives; raw manifests запечатаны. Предыдущие 20 SEALED packets не изменены.

- `q33-package-manager-20261008`: PASS, SEALED 19 files / 54018014 bytes; manifest SHA256 `8c22c42d377bd09f0f459e38c74cddf9409a23052a95efcb68852c3a0ee5983d`.
- `q33-package-manager-runtime-20261008`: FAIL, SEALED 7 files / 87061128 bytes; manifest SHA256 `8120803fabeedf107e2fe44102a36b38e5ece76c81e7b2e9a387630b447c70e0`.
- `q33-package-manager-fixed-20261008`: FAIL, SEALED 7 files / 98297976 bytes; manifest SHA256 `cae6c74cacf938c0ad196657a7bc39a12189118745e6bfd7d6b31f3e3aa62e95`.
- `q33-package-manager-qualified-20261008`: FAIL, SEALED 7 files / 107849891 bytes; manifest SHA256 `aa7414aba3b0997980a0b8599043ad41371ede8043657a4baa10a8764371e839`.
- `q33-package-manager-final-20261008`: PASS, SEALED 8 files / 101777324 bytes; manifest SHA256 `ab426256d692ae7f0ddf7bce58d7afdce1a3f5598387674c10b692b3838885a1`.


## Дополнение: release VPN и трафик пакетной службы

Использован тот же production DEB SHA `b3d0363b58cc1ae36c3b5da3518fb9d9a8e00d6153b442ac477a5772f36c9809`: бинарник извлечён без установки на хост, проверен SHA `f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd`. Сборка не повторялась; дерево Git qeli/Cargo не изменилось.

**Матрица release ELF: 18 сценариев / 376 проверок PASS.** Настоящие server/client в собственных NET/mount/PID namespaces: 12 outer4/outer6 × inner4/inner6 × TCP fake-TLS/UDP fake-TLS/UDP QUIC full-tunnel; два dual-stack split; TAP NDP/RA; DNS с IPv4/IPv6 upstream и принудительным TCP IPv6 через настоящий resolved; MTU1280/PMTU/DATA_FRAG/PTB; оба направления 0.7.16 ↔ 0.8.2. Проверяются аутентифицированный inner traffic, неподдерживаемая семья без утечки, split routes и восстановление маршрутов/TUN после штатной остановки. Aggregate leak criterion всех 14 основных cells PASS. Matrix использует bind_static=false/TOFU; это не проверка pinned H-1 во всех 18 сценариях. SIGKILL/roaming soak и расширенные fault flags не включались.

**Пакетный systemd pipeline: 36 проверок PASS.** Production apt/dpkg/debconf/CLI/systemd из первого этапа дополнены отдельным настоящим клиентом на приватном veth carrier. Служба работает от qeli с поставляемыми sandbox/capabilities; клиент закрепляет фактический ключ профиля, bind_static/H-1 остаётся включённым по умолчанию. После fresh install, успешного revision upgrade и обоих fault rollback выполняются три inner ping, подтверждается `route get` через клиентский TUN, затем чистая остановка клиента удаляет TUN. Служба успешно передаёт трафик после возврата configured package -2. Для каждого этапа устанавливается новое клиентское соединение; непрерывность существующей сессии во время restart не заявлена. Используется один TCP fake-TLS профиль; DNS выключен, client kill-switch выключен. Остальные транспорты проверяет отдельная matrix.

`--vpn` добавляет этот сценарий в оба package helpers. Клиент имеет собственные NET/mount/PID namespaces и tmpfs /run,/var/lib,/var/log; carrier links создаются внутри собственного server namespace. Штатное завершение направляет SIGTERM только PID собственного клиентского ELF; timeout фиксируется как FAIL, затем выполняется ограниченная очистка. Один первоначальный FAIL сохранён: helper вызывал show-identity от root для config владельца qeli; product trust правильно отказал. Исправление выполняет настоящий setpriv и show-identity от qeli, не меняя доверие или ownership. Финальный runtime helper commit `617dc010`; product source по-прежнему 9afbb348.

Docker/podman/nerdctl/ctr на .11 не обнаружены; реальная проверка образа/volume/recreate не выполнена. Отсутствие systemd-resolved в PATH не означало отсутствия daemon: DNS fixtures нашли настоящий executable в lib/systemd, и DNS runtime прошёл. Исходный service/listener, firewall, routes, resolver и named namespaces одинаковы до/после обоих прогонов; процессы777/845 и установленный ELF хоста сохранены. .10 в этом этапе не использовался.

Пять собственных roots двух прогонов и seed архивированы, скачанные SHA проверены, затем выполнены повторные process cwd/exe/root/fd и mount guards перед удалением. Секрет SSH проверен в raw files и несжатом содержимом архивов. Новые пакеты данных:

- `q33-release-vpn-20261008`: PASS, SEALED 108 files / 15612281 bytes; manifest SHA256 `df241ef3e5a438b04590da49945bf458c76aa931cd23f87ca9865ac6a4d40b87`.
- `q33-packaged-vpn-20261008`: FAIL, SEALED 13 files / 98482535 bytes; manifest SHA256 `c7d71fed01555fd94aae234f90c1e36c255eea544458e76b4fec01de2b67e97f`.
- `q33-packaged-vpn-final-20261008`: PASS, SEALED 7 files / 101843455 bytes; manifest SHA256 `f2e7cbe603bb2af933cab4764f4a64356d59169003caf32d3d0db4403204213c`.


Закрыты release data-plane и package→systemd→VPN после install/upgrade/rollback в описанной изоляции. Нет новых продуктовых исправлений, native/Rust rebuild, бенчмарка, независимой release reproducibility или Actions run. Предыдущие 25 SEALED packets и история certification сохраняются; добавлен 67-й scoped supplement к прежним 41 cases/acceptance и 66 supplements.

## Что остаётся

Закрыт пакетный lifecycle/rollback gate с указанной изоляцией. [Позднейший полный installer/kernel gate](AUDIT-Q33-INSTALLER-CONFIG.md) закрывает обе положительные ветки установки, VPN и partial kernel apply/recovery; атомарный откат всех действий установщика не заявлен. Docker image/volume runtime, independent release reproducibility и текущий remote Actions остаются открытыми. Нет повторного полного Rust suite, матрицы, soak или бенчмарка. Q31 SDK/bootstrap/source-cut/Actions, Q29 SIGKILL/ENONET и Q30 Apple/callback сохраняют предыдущие статусы. Mac/iOS, роутер и Windows network VM исключены пользователем; D06 принят как ограничение.

Certification сохраняет 41 cases/acceptance и 66 прежних supplements; добавлен 67-й scoped supplement. 20 required automated и 21 advisory physical rows остаются раздельными; исторические даты, артефакты и результаты не переписаны. Локальный commit dev; без push/deploy/release.
