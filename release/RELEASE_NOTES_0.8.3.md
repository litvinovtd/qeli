# Qeli 0.8.3 Beta — fixes for 0.8.2 and more resilient connections

**Draft / Черновик. Not published / Не опубликован.**

## English

Qeli 0.8.3 is a maintenance and bug-fix release for 0.8.2, focused on reliability
and recovery rather than a new feature generation. Its main purpose is to make
connections more predictable under long RTT, stalled carriers, changing UDP path
MTU and temporary loss of connectivity — and to make an interrupted upgrade easier
to diagnose and recover safely. It also closes concrete Windows storage-upgrade,
macOS service and router-startup failures. This is not a new VPN protocol or a
claim that every network or device limitation has been resolved.

For users and operators, the changes mean fewer indefinitely stuck paths, clearer
routing and transport state, and safer handling of existing profiles and recovery
journals. The performance-related changes remove specific bottlenecks; they are
not a promised speed increase on every network.

### Transport stability and network efficiency

- TCP server socket buffers now default to OS management instead of fixed sizes.
  This removes an artificial buffer limit on high-RTT paths while preserving explicit
  operator settings. Linux setup enables and verifies receive autotuning without
  changing the global `tcp_mem` budget.
- TCP/TLS/WebSocket writers and genuine HTTP/2 DATA/PING handling have bounded
  no-progress deadlines. A stalled carrier can be terminated rather than reused
  after a partially written record. Idle server readers no longer reserve a shared
  packet-pool slot before the first byte arrives.
- UDP PMTU checks track the current path and budget revision, reject stale replies
  and safely re-fragment unsent records after a budget decrease. A manually selected
  tunnel MTU no longer disables outer-path probing; `mtu_probe=false` remains supported.
- TUN dispatch first tries immediate delivery, retaining bounded backpressure when
  full. Additional queue, pool and batch-send metrics help locate congestion without
  increasing the existing memory budgets. This is not a claim that overload losses
  have been eliminated.
- The existing transport-status page now receives typed per-profile UDP receive-queue
  metrics. Missing or incompatible worker data remains unavailable rather than
  appearing as a misleading zero; unknown worker fields are not forwarded to the API.

### Routing, IPv6 and configuration

- OpenWrt and Keenetic startup no longer fails merely because the firmware exposes
  `/var` as a symlink. Routes, DNS, sysctls and firewall share `STATE_DIRECTORY`;
  updated launchers use the real path to the same existing journals. Child symlinks,
  unsafe permissions and ambiguous recovery are still refused (issue #205).

- `pull_routes=false` declines routes supplied by the server while preserving local
  routes, independent full-tunnel policy and protected tunnel DNS routes. The setting
  round-trips through client editors, INI, backups and new share links.
- IPv6 NDP proxy selects an assigned uplink source, verifies current session ownership
  and joins the relevant solicited-node multicast groups. Administrator-managed routing
  remains administrator-managed in `manual` mode.
- Unused SNI no longer rejects legacy UDP-obfs or non-WebSocket TCP-obfs profiles.
  Validation remains strict where TLS actually uses SNI. Desktop WebSocket profiles
  expose their HTTP Host override; explicit `gateway=false` survives INI serialization.
- Client configuration checks now cover the complete 87-field shared contract:
  84 `[qeli]` keys plus 3 `[logging]` fields, including non-default values in Rust,
  C#, Kotlin and Swift models. Known fields from another platform can survive an
  edit without being applied there; unknown keys are still rejected.

### Client improvements

**Windows:** native components are stored in directories identified by the hash of
the embedded DLL set, so different builds do not overwrite one another. Private
service data is separated from native libraries. Legacy service storage has an
explicit, guarded migration through the elevated GUI, with a private backup and no
silent import of untrusted files. Active network state or unfinished recovery blocks
migration; a stop timeout is not bypassed.

Windows also gains clearer IPv4/IPv6 address display and copying, remembered editor
dimensions and a bounded traffic graph. Service graph samples use monotonic,
sleep-inclusive timestamps, avoiding false rates after duplicate snapshots or clock
changes. Optional Windows sharing-binding control applies only to Qeli's own adapter.

**Android:** recovery after a connectivity gap no longer relies only on another
`onAvailable` callback. Network changes and MTU-only updates are handled separately.
The diagnostic journal uses bounded asynchronous I/O and supports clearing, manual
structured report export and optional last-error retention. Reports omit free-text
messages, profiles, keys and network addresses. New native diagnostics distinguish
queued, in-flight, locally completed and cancelled TCP work; local completion is not
a peer acknowledgement.

**macOS:** fixes cover Apple Silicon `openat`, old root-owned lock-file permissions,
`launchctl` service detection and disconnect/status reporting. Errors during DNS,
firewall or daemon shutdown are not disguised as a successful disconnect.

### Security and distribution

- Updated crypto/TLS dependencies include ML-KEM 0.3.3, ctutils 0.4.4,
  rustls-webpki 0.103.16 and webpki-roots 1.0.10. The changes address secret-dependent
  operations and the relevant certificate-trust advisories. libc is 0.2.191, Tokio is 1.54.1,
  Gradle Wrapper is 9.8.2, Android Tink is 1.24.0; dependency locks and original
  license inventories are synchronized.
- Windows, macOS and Android native cores were rebuilt from the current development
  sources. Independent A/B builds produced byte-identical artifacts, and the
  application-consumed copies are checked against the canonical libraries.
- Windows remains two single-file EXE choices: with the runtime included or requiring
  the .NET 10 Desktop Runtime. No separate native-license ZIP is needed.
- macOS now ships **two self-contained archives**, `Qeli-macos-arm64.tar.gz` for Apple
  Silicon and `Qeli-macos-x86_64.tar.gz` for Intel, requiring **macOS 15 or newer**.
  Its Rust core remains universal2. The ad-hoc packages do not provide a
  Developer-ID-signed per-app Network Extension; such profiles fail closed.
- The distribution also includes the signed Android APK, portable Linux binary and
  `.deb`, Keenetic/OpenWrt clients and installation files. Every payload is covered
  by `SHA256SUMS`. The OpenWrt source pin includes the router fixes; its source
  archive was generated twice with the OpenWrt SDK and verified against its SHA256.

### Updating

1. Update both server and clients to obtain the new native-core behaviour. Updating
   the server does not update a previously installed APK or EXE.
2. For an existing Linux TCP profile, explicitly choose
   `perf.tcp.send_buffer_size = 0` and `perf.tcp.recv_buffer_size = 0` to use OS-managed
   buffers. Review receive autotuning and the OS buffer limits, validate configuration
   and restart/reconnect to create new sockets. Existing manual values are not forcibly
   overwritten. [Setup guide](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/eng/manuals/GETTING-STARTED.md).
3. If Windows reports unsafe legacy service storage, stop the VPN and finish network
   recovery, then follow the preparation/migration offered by the elevated GUI.
   Do not delete recovery journals or bypass a stop timeout. Re-save a trusted profile
   and connect explicitly after migration.
4. On macOS choose the archive matching the processor; a separate .NET installation
   is not required. Installation guidance and platform limitations are in the setup guide.
5. On OpenWrt/Keenetic, update the init/lifecycle scripts from the supplied installation
   archive as well as the client binary. Replacing only the ELF leaves an old launcher
   selecting the wrong state root. Stop the old client cleanly and retain its recovery
   journals; do not delete them or move state to a new empty directory to bypass checks.
6. Docker images are published separately after release-tag admission and multi-arch
   checks. Use `ghcr.io/litvinovtd/qeli:0.8.3` only once that workflow succeeds;
   publishing this Beta does not automatically update `latest`.

### Verification and scope

At the preparation snapshot
[`5aaca5db`](https://github.com/litvinovtd/qeli/compare/v0.8.2...5aaca5dba6efb70233ffcccca5eac2f78326a4d9),
development since 0.8.2 comprised **69 commits**: 61 non-merge and 8 merge commits.
That includes code, dependencies, tests, documentation and packaging, not 69 new
features. The current certification records **20 passed automated Linux
cases** and **21 unavailable device, router or rollout cases**; the latter are
not passes.

Current release admission is recorded in the
[0.8.3 runtime certification manifest](https://github.com/litvinovtd/qeli/blob/v0.8.3/release/certification/0.8.3.json),
including the exact tested artifact hashes and retained evidence. Unavailable physical
device tests remain explicit limitations, not successful results. CI and Linux namespace
tests do not substitute for real-device roaming or a public Internet performance test.

[Earlier targeted transport/PMTU tests](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/data/benchmarks/network_targeted_083_required_2026-10-23.json)
and [the twelve-profile laboratory comparison](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/data/benchmarks/release12_083_required_2026-10-23.json)
retain their original candidate hashes, initial failures and interpretation limits.
They are not new measurements of the final packages or a guaranteed speed increase.
The previously documented Android API34 ENONET limitation is not declared fixed.
New [technology](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/eng/reference/TECHNOLOGIES.md)
and [Recordizer](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/eng/reference/RECORDIZER.md)
references explain existing mechanisms and link to dated measurements; Recordizer
itself did not first appear in 0.8.3.
Links pinned to `v0.8.3` become public when that tag is published.

## Русский

Qeli 0.8.3 — исправляющий релиз для 0.8.2, посвящённый устойчивости и
восстановлению, а не новому поколению функций. Его главная задача — сделать
соединения предсказуемее при большом RTT, зависании носителей, изменении UDP path
MTU и временной потере сети, а прерванное обновление — безопаснее и понятнее для
диагностики. Закрыты конкретные ошибки обновления хранилища Windows, работы службы
macOS и запуска на роутерах. Это не новый VPN-протокол и не заявление об устранении
всех ограничений сетей и устройств.

Для пользователя и администратора это означает меньше путей, застревающих без
прогресса, более ясное состояние маршрутов и транспорта, а также бережное обращение
со старыми профилями и журналами восстановления. Изменения производительности
устраняют конкретные узкие места, но не обещают прирост скорости в любой сети.

### Устойчивость транспорта и работа с сетью

- TCP-буферы сервера по умолчанию переданы под управление ОС вместо фиксированных
  размеров. Убран искусственный предел буфера на путях с большим RTT; явные настройки
  администратора сохраняются. Linux-установка включает и проверяет receive autotuning,
  не меняя глобальный бюджет `tcp_mem`.
- Для записи TCP/TLS/WebSocket и настоящего HTTP/2 введён ограниченный срок отсутствия
  прогресса, отдельно для DATA и PING. Зависший носитель завершается и не используется
  повторно после частично записанной записи. Ожидающие TCP-читатели сервера больше
  не занимают слот общего пула пакетов до получения первого байта.
- UDP PMTU учитывает текущий путь и ревизию бюджета, отбрасывает устаревшие ответы
  и безопасно переразбивает неотправленные записи при уменьшении доступного размера.
  Ручной MTU туннеля больше не отключает проверку внешнего пути;
  `mtu_probe=false` по-прежнему поддерживается.
- Передача пакетов из TUN сначала пробует немедленную отправку, сохраняя ограниченное
  ожидание при заполнении очереди. Новые метрики очередей, пула и пакетной UDP-отправки
  помогают найти перегрузку без увеличения лимитов памяти. Это не утверждение об
  устранении всех потерь при насыщении канала.
- Существующая страница состояния транспорта получает типизированные метрики UDP-очереди
  по профилям. Отсутствующие или несовместимые данные worker остаются недоступными,
  а не показываются как нулевая нагрузка; неизвестные поля worker не проходят в API.

### Маршрутизация, IPv6 и конфигурация

- OpenWrt/Keenetic: запуск больше не ломается лишь из-за системного `/var`-симлинка.
  Маршруты, DNS, sysctl и firewall используют общий `STATE_DIRECTORY`; обновлённые
  шаблоны указывают реальный путь к прежним журналам. Дочерние symlink, небезопасные
  права и неоднозначный recovery по-прежнему отвергаются (issue #205).
- `pull_routes=false` позволяет отказаться от маршрутов сервера, сохранив локальные
  маршруты, независимую full-tunnel-политику и защищённые маршруты tunnel DNS.
  Настройка сохраняется в редакторах клиентов, INI, резервных копиях и новых ссылках.
- IPv6 NDP proxy использует назначенный uplink-адрес, проверяет владельца текущей
  сессии и подписывается на нужные solicited-node multicast-группы. В режиме `manual`
  маршруты и firewall остаются ответственностью администратора.
- Неиспользуемое SNI больше не мешает загрузке старых UDP-obfs и TCP-obfs-профилей
  без WebSocket. Там, где SNI действительно используется TLS, строгая проверка
  сохраняется. В desktop-редакторах WebSocket доступен HTTP Host override;
  явное `gateway=false` корректно сохраняется в INI.
- Проверки конфигурации клиентов охватывают все 87 полей общего контракта:
  84 ключа `[qeli]` и 3 поля `[logging]`, включая нестандартные значения в моделях
  Rust, C#, Kotlin и Swift. Известное поле другой платформы может сохраниться при
  редактировании, но это не означает, что оно применяется; неизвестные ключи
  по-прежнему отклоняются.

### Доработки клиентов

**Windows:** нативные компоненты размещаются в каталогах по хешу встроенного
комплекта DLL — разные сборки не перезаписывают библиотеки друг друга. Закрытые
данные службы отделены от нативных библиотек. Для старого служебного хранилища
предусмотрена явная защищённая миграция через GUI с повышенными правами: с приватной
резервной копией и без скрытого импорта недоверенных файлов. Активное сетевое
состояние и незавершённое восстановление блокируют переход; тайм-аут остановки
не обходится.

Также улучшены отображение и копирование IPv4/IPv6, сохранение размеров редакторов
и ограниченный график трафика. График службы использует монотонные временные отметки
с учётом сна: повторные снимки и изменение часов не создают ложные значения скорости.
Опциональное управление Windows sharing bindings затрагивает только собственный
адаптер Qeli.

**Android:** восстановление после отсутствия сети больше не зависит только от нового
`onAvailable`. Смена сети отделена от изменения одного MTU. Журнал переведён на
ограниченную асинхронную запись; доступны очистка, ручной структурированный отчёт
и опциональное сохранение последней ошибки. Отчёты не содержат свободного текста
сообщений, профилей, ключей и сетевых адресов. Новая нативная диагностика разделяет
TCP-данные в очереди, в работе, локально записанные и отменённые; локальная запись
не объявляется подтверждением получения другой стороной.

**macOS:** исправлены `openat` на Apple Silicon, права старых root-owned lock-файлов,
определение службы через `launchctl` и отображение результата отключения.
Ошибки DNS, firewall и завершения демона не маскируются успешным статусом.

### Безопасность и комплект поставки

- Обновлены криптографические и TLS-зависимости: ML-KEM 0.3.3, ctutils 0.4.4,
  rustls-webpki 0.103.16 и webpki-roots 1.0.10. Изменения закрывают зависимые от
  секрета операции и соответствующие предупреждения о доверии сертификатам.
  libc обновлён до 0.2.191, Tokio — до 1.54.1, Gradle Wrapper — до 9.8.2,
  Android Tink — до 1.24.0.
  Lock-файлы и оригинальные лицензионные тексты согласованы.
- Нативные ядра Windows, macOS и Android пересобраны из актуальных исходников.
  Независимые A/B-сборки дали побайтово одинаковые артефакты; используемые приложениями
  копии проверяются на совпадение с каноническими библиотеками.
- Windows по-прежнему распространяется двумя single-file EXE: со встроенным runtime
  и с требованием установленного .NET 10 Desktop Runtime. Отдельный архив лицензий
  нативных компонентов не нужен.
- Для macOS теперь поставляются **два самостоятельных архива**:
  `Qeli-macos-arm64.tar.gz` для Apple Silicon и `Qeli-macos-x86_64.tar.gz` для Intel.
  Требуется **macOS 15 или новее**. Rust-ядро остаётся universal2. Ad-hoc-пакеты
  не содержат Developer-ID-подписанное per-app Network Extension; такие профили
  отказывают в запуске, а не расширяют выбранный трафик до общего туннеля.
- В комплект также входят подписанный Android APK, переносимый Linux-бинарник и
  `.deb`, клиенты Keenetic/OpenWrt и установочные файлы. Все payload-файлы покрыты
  `SHA256SUMS`. OpenWrt source pin включает исправления роутеров; исходный архив
  дважды сформирован OpenWrt SDK и проверен по SHA256.

### Порядок обновления

1. Обновите сервер и клиенты: обновление сервера не заменяет нативное ядро внутри
   уже установленного APK или EXE.
2. Для существующего TCP-профиля Linux явно установите
   `perf.tcp.send_buffer_size = 0` и `perf.tcp.recv_buffer_size = 0`, если нужны
   буферы под управлением ОС. Проверьте receive autotuning и системные лимиты буферов,
   провалидируйте конфигурацию и перезапустите соединение для создания новых сокетов.
   Старые ручные значения не заменяются принудительно.
   [Инструкция](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/ru/manuals/GETTING-STARTED.md).
3. Если Windows сообщает о небезопасном старом хранилище службы, остановите VPN
   и завершите восстановление сети, затем используйте подготовку/миграцию,
   предлагаемую GUI с повышенными правами. Не удаляйте recovery-журналы и не
   обходите тайм-аут остановки. После миграции заново сохраните доверенный профиль
   и подключитесь явно.
4. На macOS выберите архив для своего процессора; отдельно устанавливать .NET
   не требуется. Инструкция установки и ограничения платформ описаны в руководстве.
5. На OpenWrt/Keenetic обновите не только клиентский бинарник, но и init/lifecycle
   из установочного архива. Замена одного ELF оставляет старый launcher с неверным
   корнем состояния. Штатно остановите старый клиент и сохраните recovery-журналы;
   не удаляйте их и не выбирайте новый пустой каталог ради обхода проверок.
6. Docker-образы публикуются отдельно после допуска тега и multi-arch проверок.
   Используйте `ghcr.io/litvinovtd/qeli:0.8.3` после успешного завершения workflow;
   публикация этой Beta не переключает `latest` автоматически.

### Проверки и границы утверждений

На срезе подготовки
[`5aaca5db`](https://github.com/litvinovtd/qeli/compare/v0.8.2...5aaca5dba6efb70233ffcccca5eac2f78326a4d9)
разработка после 0.8.2 включает **69 коммитов**: 61 обычный и 8 merge-коммитов.
Это код, зависимости, тесты, документация и упаковка, а не 69 новых функций.
В текущей сертификации **20 автоматизированных Linux-проверок
прошли**, а **21 проверка на устройствах, роутерах или при развёртывании
недоступна** и не засчитана как успешная.

Актуальный допуск фиксируется в
[runtime-сертификации 0.8.3](https://github.com/litvinovtd/qeli/blob/v0.8.3/release/certification/0.8.3.json):
с точными SHA проверенных артефактов и сохранёнными результатами. Недоступные проверки
на физических устройствах остаются явными ограничениями, а не успешными тестами.
CI и Linux namespace-проверки не заменяют роуминг на реальных устройствах и замеры
скорости в публичном Интернете.

[Прежние целевые проверки транспорта и PMTU](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/data/benchmarks/network_targeted_083_required_2026-10-23.json)
и [лабораторное сравнение двенадцати профилей](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/data/benchmarks/release12_083_required_2026-10-23.json)
сохраняют исходные хеши кандидатов, неудачные попытки и ограничения интерпретации.
Это не новые замеры финальных пакетов и не гарантия прироста скорости.
Ранее описанное ограничение Android API34 ENONET не объявляется исправленным.
Новые справочники по [технологиям](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/ru/reference/TECHNOLOGIES.md)
и [Recordizer](https://github.com/litvinovtd/qeli/blob/v0.8.3/docs/ru/reference/RECORDIZER.md)
объясняют существующие механизмы и ведут к датированным измерениям; сам Recordizer
появился раньше 0.8.3.
Ссылки на `v0.8.3` станут публично доступными при публикации соответствующего тега.
