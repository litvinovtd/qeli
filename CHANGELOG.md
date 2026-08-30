# Changelog

Заметные изменения qeli, обратно-хронологически. Версии — единые на сервер и все клиенты
(Linux/OpenWrt, Android, iOS, Windows и macOS). Бинарные артефакты публикуются во
вкладке **GitHub Releases** (в git не коммитятся — см. `.gitignore`).

## [0.8.0] — не выпущен

### Исправления по аудиту маршрутизации и роуминга

- `route_local` на Linux, Windows и macOS теперь действительно перехватывает напрямую
  подключённую IPv4 RFC1918 LAN: клиенты добавляют более специфичные дочерние TUN-маршруты,
  не удаляя и не заменяя принадлежащий ОС/оператору connected-route; явный `exclude` сохраняет
  приоритет. Desktop per-app использует тот же контракт: при выключенном `route_local` напрямую
  обходятся только фактически подключённые RFC1918-сети, удалённые private-адреса следуют обычной
  full/split-tunnel политике, а IPv6 ULA/multicast от `route_local` больше не зависят.
- Reverse-PMTU probe сервера больше не создаёт connected UDP endpoint с тем же listener-портом:
  временный DF-сокет отправляет через `send_to`, поэтому точный four-tuple не может перехватить
  быстрый ACK, предназначенный стабильному receive worker.
- Явный `routing.include` теперь применяется fail-closed: маршрут IPv4 нельзя принять без
  активного IPv4-адреса туннеля, а маршрут IPv6 — без активного IPv6-адреса. Вместо тихого
  пропуска несовместимого семейства подключение завершается до установки TUN-плана, поэтому
  указанный пользователем трафик не может незаметно уйти мимо туннеля.
- TCP make-before-break переведён на двухфазную фиксацию между клиентом и сервером. `JOINOK`
  только резервирует и подготавливает новый carrier; клиент сначала фиксирует платформенный
  путь, затем подтверждает `JOINCOMMIT`, и лишь после этого сервер публикует новый carrier и
  начинает drain старого. Ошибка/таймаут до подтверждения отменяет резервирование и сохраняет
  старый рабочий transport.
- Для UDP устранена гонка `PATH_COMMIT` с `DATA`/`DATA_FRAG`: аутентифицированные данные нового
  пути временно удерживаются в epoch-scoped очереди и публикуются строго после commit. Окно
  ограничено 128 датаграммами и 512 KiB; переполнение приводит к безопасному reconnect, а не к
  беззвучной потере уже принятого трафика.
- Rust library target переименован внутри сборки в `qeli_core`, чтобы MSVC больше не создавал
  один и тот же `qeli.pdb` одновременно для DLL и исполняемого файла. Публичные имена ABI
  (`qeli.dll`, `libqeli.so`, `libqeli.dylib`, `libqeli.a`) сохранены во всех desktop, Android,
  macOS и iOS сборочных рецептах; regression-test также проверяет это соответствие.
  Синхронизация исходников на лабу теперь включает `examples`, необходимые для строгого
  `cargo clippy --all-targets` после переименования crate.
- Закрыт post-commit blackhole TCP handover. До выдачи `COMMIT_PATH` точный candidate остаётся
  обратимым; после выдачи rollback разрешён только при явном отказе платформы. Таймаут, отмена,
  закрытие ACK-канала или поздний/ошибочный ACK считаются неоднозначным необратимым результатом:
  текущая generation немедленно завершается и запускает полный reconnect вместо stale
  `ABORT_PATH`. После подтверждённого commit ошибка `JOINCOMMIT` или финального ACK использует тот
  же terminal-путь. Android дополнительно останавливает generation сразу, если
  `setUnderlyingNetworks()` уже изменил сеть ОС, а локальное обновление или JNI ACK завершились
  ошибкой. Сервер ждёт client commit 60 секунд — на 15 секунд дольше клиентского platform ACK
  timeout; fault-injection тест фиксирует late-ACK сценарий.
- ABI transport core повышен до 1.14 и различает безопасный отказ path-команды и неопределённое
  состояние платформы после неудачного внутреннего rollback. Linux передаёт типизированный отказ
  восстановления FIB, macOS сохраняет его через route/policy транзакции, а managed/iOS adapters
  больше не превращают такой COMMIT в обычный отрицательный ACK. Ядро немедленно завершает
  generation, удаляет queued candidate и не выдаёт stale `ABORT_PATH`; fault-injection тест
  фиксирует этот fail-closed контракт. Клиенты со старым native core отключают path transactions
  и используют полный reconnect.
- Клиентский startup и live uplink PMTU probe переведены с 16-битного id на существующий V2
  challenge с независимым 128-битным token. Текущий сервер эхо-подтверждает точные `token + size`
  только для известной сессии; при согласованном roaming V2 probe обрабатывается после точного
  разрешения directional CID и совпадения committed epoch/socket/peer, до PacketCodec. Legacy
  probe старых клиентов по-прежнему обслуживается, а новый клиент со старым сервером сохраняет
  консервативный UDP budget без небезопасного widening.
- PMTU probe API и wire-комментарии теперь явно называют записываемый размер длиной payload до
  QUIC/obfs/UDP/IP-обёрток; расчёт фактических MTU-бюджетов не изменён.
- Двухфазный TCP wire-контракт получил отдельную версию: magic изменён на `QELIRSM2`, версия и
  proof domain — на V2, а согласование использует новые `TCP_RESUME_V2`/`TCP_HANDOVER_V2` bits.
  Старые V1 bits оставлены зарезервированными и не рекламируются; смешанные версии безопасно
  переходят на обычный reconnect вместо ложного согласования несовместимого handover.
- Устранён гарантированный `cargo fmt --check` blocker в probe examples. Глобальный Linux linker
  argument `-s` удалён из Cargo config, поэтому он больше не передаётся MSVC, Android и router
  cross-builds; переносимый stripping выполняет `strip = true` в release profile и защищён тестом.
  EN/RU CONFIG, ROADMAP и нормативный ROAMING синхронизированы с новым wire-контрактом,
  post-commit recovery и фактическими defaults новых/существующих профилей.


### Документация

- Двуязычное дерево `docs/eng` / `docs/ru` переразложено по назначению: практические
  руководства — в `manuals/`, технические контракты — в `reference/`, активные планы — в
  `plans/`, актуальные аудиты и замеры — в `reports/`, завершённые планы и датированные
  проверки — в `archive/plans/` и `archive/audits/`. Все внутренние, корневые и исходные
  ссылки переведены на новые пути.
- `scripts/check_docs.py` теперь рекурсивно проверяет вложенное дерево, запрещает новые
  некатегоризированные страницы, требует прямой доступности каждого документа из локального
  `index.md` и сохраняет строгий паритет RU/EN. Зависимые проверки версий и матрицы клиентских
  ключей также используют новые пути.

### Валидация push-параметров и iOS On-Demand

- Сервер валидирует точный `PushedObf`, который отправляет после аутентификации, а клиент
  строго разбирает и проверяет его вместо молчаливого отбрасывания некорректного JSON.
  Инвертированные диапазоны, невозможные размеры, некорректные probability/jitter и shaping
  budget меньше одной записи теперь отклоняются до запуска data plane. Android, iOS и общий
  C#-клиент применяют те же ограничения к локальным shaping-настройкам; добавлены Rust,
  Kotlin, Swift и managed conformance-регрессии.
- Включённая traffic normalization теперь принимает только строго возрастающий список
  `round_sizes`; серверный конфиг и полученный клиентом push отклоняют неоднозначные наборы
  вроде `512,256`. Клиентская проверка padding использует единый общий предел вместо
  дублированной константы.
- iOS-виджет больше не пытается изменять `NETunnelProviderManager` из extension-процесса без
  Network Extension entitlement. Он передаёт desired-state через App Group и открывает
  container app; `AppModel` выполняет ту же сериализованную транзакцию
  `connectionDesired`/On-Demand, что ручная кнопка. Disconnect всегда снимает автоматическую
  политику, даже если туннель уже остановлен. Команда toggle разрешается только после чтения
  актуального системного `NEVPNStatus`, а не по потенциально устаревшему snapshot. Требуется
  проверка на реальном iOS-устройстве.
- Пул приёмных UDP-буферов перенесён в общий `transport_core` и переиспользуется обычным
  transport-клиентом без изменения размера очереди, лимитов датаграмм и wire-поведения.

### Основа роуминга (stages 0–3E TCP/UDP, включён для новых профилей)

- Все стандартные серверные, standalone-клиентские и FFI-сборки теперь включают общее
  ядро роуминга. Поставляемые серверные примеры, новая установка, новые профили панели и
  все режимы Quick Start явно задают `roaming.enabled = true`; клиенты по-прежнему используют
  `roaming = auto`. Отсутствующий ключ в старом серверном конфиге остаётся `false`, поэтому
  простое обновление бинарника не активирует новую wire-capability без решения оператора.
- Серверный rollout роуминга является явным и профильным: flat-INI ключи
  `roaming.enabled`, `roaming.grace_secs`, `roaming.max_orphaned` и
  `roaming.max_orphan_bytes` проходят lossless round-trip и строгую проверку диапазонов.
  Выключенный профиль не рекламирует ни одного roaming capability; `true` на бинарнике без
  `experimental-roaming` отклоняется fail-closed. TCP grace/orphan budget берутся из профиля,
  а TCP и все UDP camouflage modes используют один и тот же профильный capability gate.

- Клиентская политика `[qeli] roaming = off|auto|required` теперь реализована в общем
  Rust-ядре и моделях Android, Windows, macOS и iOS. `off` маскирует все клиентские roaming
  capability и не может быть обойдён TCP resume/handover; `auto` использует согласованный
  безопасный roam и сохраняет reconnect fallback; `required` отказывает до передачи credentials
  и полной AUTH, если platform/core/peer не предоставляют полный transport-specific контракт.
  Обычный TCP и fake-TLS, QUIC, obfs и AWG поверх UDP используют одну policy/state machine.
  Явные `local` или ненулевой `lport` запрещают native path migration: сочетание с `required`
  отклоняется при валидации, а `auto` возвращается к reconnect.
- Flat-INI и `qeli://` сохраняют non-default `roaming` без потерь во всех четырёх независимых
  реализациях Rust/Kotlin/C#/Swift; `auto` по-прежнему опускается из компактной ссылки, а
  неизвестная политика отклоняется при импорте. Общий conformance fixture проверяет positive
  round-trip и fail-closed negative case. Lab: 966 feature-тестов (3 ignored), strict
  default/feature Clippy, C# conformance и Android unit suite проходят.
- В редакторах профилей Windows и macOS добавлен явный единый выбор роуминга сессии
  `Автоматически / Обязательно / Отключено`. Значение сохраняется и после ручного INI-редактирования;
  `required` не позволяет сохранить профиль с явным `local` или ненулевым `lport`, а общий managed
  conformance фиксирует передачу настройки в flat-INI.
- Редакторы Android и iOS предлагают ту же политику `Автоматически / Обязательно / Отключено`
  над полным INI. Сохранение изменяет общий ключ `roaming` через штатные Kotlin/Swift-модели и
  их валидацию; отдельной мобильной или UDP-only логики не добавлено.

- В форме серверного профиля web-панели добавлена отдельная секция Session Roaming: единый
  профильный переключатель для TCP и всех UDP camouflage modes, grace period, лимит ожидающих
  сессий и лимит памяти в MiB. Старые sparse серверные INI-профили сохраняют совместимый выключенный
  переключатель, а новые профили панели получают включённый роуминг из канонического Rust-шаблона.

- Сервер публикует безопасную worker-lifetime телеметрию роуминга через read-only control/API
  и отдельную карточку dashboard: попытки, подтверждённые миграции, финальные ошибки, истечения
  TCP grace и текущие ожидающие TCP/UDP пути. UDP-счётчики принадлежат общему профильному registry,
  поэтому fake-TLS, QUIC, obfs и obfs-AWG используют одинаковую дедупликацию retransmit и один
  контракт результата; TCP и UDP показаны одной transport-aware моделью. Control API дополнительно
  публикует только агрегированное число активных UDP CID aliases, чтобы resource soak мог обнаружить
  их накопление. Сами CID, session locator, proof и секреты в метрики и логи не попадают, а UI явно
  сообщает, что значения сбрасываются при перезапуске data-plane worker.
- Все поставляемые серверные профили теперь явно включают роуминг с лимитами
  `true / 30 s / 256 sessions / 64 MiB`, включая источник installer-профилей и release Reality.
  Все клиентские шаблоны, в том числе Keenetic/OpkgTun, явно задают `roaming = auto`: единое ядро
  использует согласованную миграцию для TCP и любого UDP camouflage, сохраняя reconnect fallback.
  Regression test проверяет наличие и точные значения ключей в каждом поставляемом профиле.
  Lab source sync теперь загружает те же четыре внешних release-шаблона, которые подключает
  `config_examples.rs`, поэтому gate больше не проверяет оставшиеся на лабе stale-копии.
- Live Linux netns-приёмка теперь явно включает серверный rollout и задаёт клиенту
  `roaming = required`, поэтому TCP и любой UDP camouflage не могут получить зелёный результат
  через reconnect/fallback. Загрузка вынесенных drain/family/fragment/NAT case helpers стала
  fail-closed: отсутствующий или некорректный helper завершает тест с `rc=2`, а не печатает ложный
  `0 failed`. Feature release gate: TCP 15/15; QUIC/fake-TLS/obfs/obfs-AWG по 17/17; rollback
  20/20, supersede 24/24, commit race 24/24, loss/replay 18/18, PMTU 19/19+19/19, drain 26/26,
  outer-family 32/32, fragment loss 25/25 и same-network NAT rebinding 21/21.
- Capability regression теперь для TCP и UDP фиксирует оба legacy-варианта: peer без capability
  trailer и pre-`AUTH_EXT_V1` peer. Политика `auto` в обоих случаях оставляет byte-for-byte legacy
  AUTH и обычный reconnect fallback, а `required` отказывает fail-closed до credentials/полной
  аутентификации. Live mixed-version netns-матрица на реальных бинарниках 0.8.0↔0.7.14 прошла
  24/24 проверки для TCP и UDP: current-server/legacy-client и legacy-server/current-`auto`
  устанавливают TUN, передают трафик и выполняют ровно одну полную AUTH без входа в roaming,
  а current-`required` с legacy server при повторных попытках остаётся до TUN/полной AUTH.
  Тестовые серверы используют отдельные control sockets и не пересекаются с сервисом лабы.
- Добавлен конфигурируемый same-session UDP soak case: release-default выполняет 10 000
  последовательных A↔B PATH_COMMIT и на всём цикле контролирует PID/TUN, одну AUTH, отсутствие
  reconnect, exact carrier route, client/server commit, все fd, отдельное число socket-дескрипторов
  и sampled RSS. Sockets ограничены baseline + 2 финально и baseline + 8 на выборках; control требует
  точные attempts/commits, одну session, ноль failures/candidates и три CID aliases после commit.
  Harness использует общий UDP actor, а all-modes wrapper передаёт один выбранный case, включая
  `soak`, через QUIC, fake-TLS, obfs и obfs+AWG без отдельных транспортных реализаций. Lab smoke
  прошёл по 100 последовательных миграций в каждом из четырёх режимов: каждый сохранил одну AUTH,
  исходные PID/TUN, единственный exact carrier route и точные 100 client/server commit без reconnect.
  Client/server fd остались 14/10, server RSS был стабилен, client RSS во всех режимах уложился
  в 32 MiB budget. Это проверка harness; полный 10k и platform soak gates пока не объявляются
  закрытыми.

- Добавлен симметричный same-session TCP soak case: release-default выполняет 10 000 A↔B
  make-before-break commit и сверяет точное число независимых client commit, server commit и JOIN,
  одну AUTH, отсутствие reconnect/grace, PID/TUN, exact route, все fd, отдельное число socket-
  дескрипторов и RSS. Sockets ограничены baseline + 2 финально и baseline + 8 на выборках; control
  требует точные attempts/commits, одну session и ноль failures/grace/orphaned state. Lab smoke прошёл 100
  последовательных миграций за 223 секунды: client/server fd остались 13/10, server RSS был стабилен,
  а рост client RSS составил около 1,5 MiB при бюджете 32 MiB.
  Полный TCP 10k и остальные transport/platform soak gates остаются открытыми.
- Исправлено накопление завершённых TCP carrier tasks при длительном same-session roaming.
  Каждый stream регистрировал 2–3 Tokio `JoinHandle`, но до полного teardown туннеля registry не
  удалял уже завершённые handles; при 10 000 handover fd оставались стабильны, а client RSS вышел
  за бюджет 32 MiB. Перед регистрацией task следующего carrier registry теперь удаляет только
  фактически завершённые handles, сохраняя активные и ещё закрывающиеся задачи для безопасного
  teardown. Детерминированный async regression фиксирует bounded registry; полный 10k retest
  исправленного бинарника остаётся release gate.
- Исправлен ложный server-side resource probe в TCP/UDP soak harness. `ip netns pids ... | head -n1`
  выбирал supervisor `qeli server`, тогда как fd, sockets и RSS реального data plane принадлежат
  дочернему `qeli _worker`; живой аудит длительного TCP-прогона показал соответственно 10/3/~22 MiB
  у ошибочно измеряемого supervisor и 16/6/~57 MiB у worker. Общий helper теперь требует ровно один
  PID с тем же canonical executable, ролью `_worker` и точным аргументом `-c/--config` текущего
  server.conf. TCP и UDP дополнительно фиксируют `/proc/<pid>/stat` start ticks клиента и worker,
  поэтому исчезновение, неоднозначность или PID reuse завершают gate fail-closed. Linux contract
  matrix прошла 4/4, общий helper и оба soak case прошли ShellCheck. На фиксированном SHA-256
  `b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc` исправленные representative
  TCP fake-TLS и UDP QUIC прошли по 10 000 commit и 15/15 проверок с точным server worker PID.
  TCP сохранил fd 13/16, sockets 4/6, sampled RSS 47 284/57 764 KiB и нулевой orphan state; QUIC —
  fd 14/16, sockets 5/6, sampled RSS 37 176/70 896 KiB, ноль candidates и три CID aliases. Все
  20 000 commit сохранили исходные worker PID, TUN и одну AUTH без reconnect; SHA после gate совпал.
- Tiered UDP adapter matrix завершена на том же SHA: fake-TLS, obfs и obfs+AWG прошли по 1000/1000
  commit и 15/15 проверок. Финальные client/server sampled RSS: 43 388/66 596, 45 316/68 412 и
  35 844/78 288 KiB; fd остались 14/16, sockets 5/6, candidates — 0, CID aliases — 3. Общий
  `CORRECTED_WORKER_UDP_SHORT_ALL_PASS` получен, процесс завершился, тестовые namespaces удалены.
- Уточнён нормативный RU/EN статус после завершения soak: устаревшие утверждения об открытом full
  10k удалены, deliberate DATA_FRAG-loss явно отмечен как закрытый Linux gate 25/25. Открытыми
  остаются только отдельно перечисленные physical-device/platform PMTU, NAT-rebinding, race,
  per-app, sleep и soak gates.
- Добавлен воспроизводимый TCP performance gate для роуминга. Новый `perf` case переиспользует
  тот же netns runner и один бинарник, а wrapper последовательно измеряет медианы upload/download
  и суммарный CPU процессов qeli сначала при `roaming=off`, затем при согласованном
  `roaming=required`. Gate по умолчанию отклоняет регрессию любого направления throughput или CPU
  больше 5%; число раундов, длительность и бюджет настраиваются. Policy overrides разрешены только
  для `perf`, поэтому обычные success/soak сценарии по-прежнему fail-closed требуют роуминг.
  Live gate на отдельной lab `.11` прошёл на фиксированном SHA-256
  `b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc`: baseline `off` дал медианы
  518/648 Мбит/с upload/download и 160.255% суммарного CPU, а `required` — 528/648 Мбит/с и
  161.131% CPU. Оба варианта прошли функциональные инварианты 10/10 без reconnect; итоговое
  сравнение прошло 3/3 при бюджете 5%. Параллельный 10k soak на `.10` использовал отдельную VM и
  не разделял CPU, network namespaces или процессы с performance gate.
- Resource soak сокращён без потери независимого покрытия: один representative TCP и UDP QUIC
  выполняют по 10 000 same-session миграций, а UDP fake-TLS, obfs и obfs+AWG — по 1000. Все UDP
  режимы используют общий actor/state machine; короткие adapter-прогоны сохраняют проверку framing,
  fd/sockets/RSS, PID/TUN, routes, commits, candidates и CID aliases, не дублируя ещё 30 000 циклов
  общей логики. Отдельный fail-closed wrapper фиксирует порядок, бюджеты и PASS-маркеры режимов.
- Добавлен единый fail-closed orchestrator resource release gate. Он фиксирует SHA-256 одного
  бинарника перед запуском, перепроверяет его до и после каждого этапа и строго последовательно
  выполняет TCP/UDP all-mode smoke, TCP resume/grace, TCP 10k, UDP QUIC 10k, остальные UDP
  adapters по 1k, performance и multi-node fallback. Маркер успеха этапа появляется только после
  нулевого exit code; ошибка или подмена
  бинарника исключает запуск всех последующих этапов. Изолированные contract-тесты проверяют
  порядок, остановку после ошибки, hash pin и отсутствие ложного финального PASS.
- Короткие этапы release gate повторно пройдены на одном исправленном бинарнике SHA-256
  `b8add83126dd1b6c608fa6288b7d227bf377ff3d27ce577db2dab5e114b265dc`. TCP smoke закрыл 6/6
  режимов (`reality-tls` 21/21, остальные по 17/17), UDP smoke — 4/4 режима по 19/19, hard resume и
  grace-expiry — по 18/18, отрицательный multi-node fallback — 26/26. SHA совпал после каждой фазы;
  любой non-zero code остановил бы цепочку, а после финала не осталось процессов или network
  namespaces теста.
- Добавлен отрицательный TCP multi-node gate без отдельной транспортной реализации. Path A ведёт
  к исходному серверному процессу, а path B через scoped DNAT — к независимому процессу с теми же
  identity key и users, но отдельным session registry. Foreign authenticated JOIN обязан получить
  `unknown locator` и не может создать roaming commit; после физической потери path A политика
  `auto` должна пройти штатный full reconnect и вторую полную AUTH, заменить выданный tunnel address
  и продолжить трафик. `multinode` принудительно ограничен fake-TLS/server-enabled/client-auto;
  live gate на неизменном бинарнике прошёл 26/26 на лабе: независимый registry отклонил foreign JOIN,
  клиент и первичный сервер одновременно увидели детерминированный двусторонний TCP RST, после
  30-секундного resume budget клиент сохранил supervisor, вошёл в top-level reconnect, получил новый
  tunnel `/32` от второго процесса и восстановил carrier route и трафик без roaming commit. Сам gate
  считает AUTH только по уникальной успешной строке и проверяет фактическую host-route маску `/32`.
- Добавлены постоянные TCP `resume` и `grace-expiry` netns cases. Первый детерминированно сбрасывает
  server-side carrier на неизменном path A и требует ровно один authenticated JOIN внутри grace без
  второй AUTH, top-level reconnect или замены PID/TUN; live gate прошёл 18/18. Второй задаёт серверу
  grace 3 секунды, блокирует replacement carriers до reap locator, проверяет точные `unknown locator`
  отказы без JOIN commit, затем ждёт истечения 30-секундного клиентского resume budget и требует
  обычный full reconnect, вторую AUTH и восстановление трафика; live gate также прошёл 18/18.
  Сценарии проверяют transport grace детерминированно и не подменяют physical-device suspend gate.
- Добавлен воспроизводимый fail-closed Android deep-idle/wake gate для уже установленного туннеля.
  Harness не содержит профилей или credentials, временно включает Doze на AVD, требует фактическое
  состояние `IDLE`, ведёт непрерывный tunnel ping и после wake сверяет PID приложения, идентичность и
  адрес `tun0`, DNS-разрешение, отсутствие новой AUTH/NetworkPlan и точный same-network keep-маркер.
  Исходные флаги Doze и состояние экрана восстанавливаются даже после ошибки. Полная API 34 матрица
  с feature APK `0.8.0` прошла для `fake-tls`, `quic`, `obfs` и `obfs-awg`: каждый режим оставался
  в deep idle 20 секунд, передал 180/180 ping, сохранил PID и `tun0`, разрешил `example.com` через
  серверный tunnel-resolver после wake и не выполнил повторную AUTH/NetworkPlan. После каждого
  режима временный сервер останавливался без оставшегося порта или TUN. Parser-регрессии покрывают
  реальный однострочный формат `dumpsys deviceidle`. Это повторяемый emulator gate; real-device
  suspend/NAT rebinding по-прежнему остаются обязательной приёмкой.
- Добавлен отдельный credentials-free Android UDP grace-expiry gate для уже подключённого
  experimental-roaming профиля. Harness принимает только исполняемый `apply|restore` fault hook,
  не запускает его через shell, проверяет права на исполнение и всегда вызывает идемпотентный
  `restore`, возвращает Doze/экран и снимает fault даже при ошибке. После реального deep `IDLE`
  транспортный путь блокируется дольше общего roaming grace; gate требует упорядоченную попытку
  same-network soft recovery, transport fallback, ровно одну новую AUTH и ровно один применённый
  NetworkPlan. Replacement TUN находится по точному назначенному адресу, а не по имени `tun0`,
  которое Android вправе сменить после полного reconnect.
  Полная API 34 матрица feature APK прошла для `fake-tls`, `quic`, `obfs` и `obfs-awg`: прежний
  UDP-путь блокировался на 40 секунд при общем grace 15 секунд без рестарта endpoint, PID приложения
  сохранялся, каждый режим восстановил tunnel ping 5/5 и DNS через серверный tunnel-resolver.
  Это доказывает единый bounded grace/fallback для всех UDP camouflage adapters на эмуляторе;
  physical-device suspend/NAT acceptance остаётся обязательной.
- Исправлена штатная очистка server-side DNS INPUT permits на хостах со смешанной native nftables /
  iptables-nft цепочкой. На таких системах точные `iptables -C/-D` работают, но `iptables -S INPUT`
  отказывается перечислять chain; прежний tag sweep поэтому молча оставлял по два правила после
  каждого остановленного DNS-профиля. Теперь каждый успешный `enable_dns_input` возвращает RAII lease
  точных interface/pool/listen/port/protocol rules. `ProfileTeardown` освобождает leases до удаления
  TUN и до дополнительного generic cleanup, а отказ частичной установки выполняет тот же exact
  rollback; число удаляемых одинаковых копий ограничено fail-closed.
  Изолированный live gate на mixed-nft lab с release feature-бинарником SHA-256
  `f793789feb7432aa75bc28830baea77f9b84e4449cc4332b00ded3b770559d68` подтвердил, что udp+tcp
  permits появляются при неперечисляемом INPUT, а после SIGTERM отсутствуют supervisor/worker,
  listener, TUN и оба правила; остальные firewall entries не изменяются.
- Все Linux netns-сценарии теперь запускают тестовый сервер с отдельным control socket внутри
  рабочего каталога через `QELI_CONTROL_SOCKET`. Это исключает коллизию с `/var/run/qeli/control.sock`
  работающего сервиса лабы: тесты не могут занять, удалить или использовать его при создании и
  очистке временных network namespaces.
- UDP netns/soak harness проходит строгий ShellCheck preflight: динамический case-helper явно
  помечен как проверенный runtime source, очистка использует обязательный непустой `WORK`, а
  вычисление каталога runner не зависит от внешнего `CDPATH`. После safety-правок feature release
  повторно прошёл success matrix для `quic`, `fake-tls`, `obfs` и `obfs-awg`: 4/4 режима,
  каждый 17/17 без замены PID/TUN или top-level reconnect.
- TCP netns runner использует один roaming path для `fake-tls`, `reality-tls`, `plain`, `obfs-ws`,
  `obfs-none` и `obfs-awg`, а `roaming_tcp_all_modes_netns_e2e.sh` последовательно проверяет все
  режимы без копирования transport-логики. Feature release прошёл 6/6 режимов: `reality-tls`
  19/19, остальные пять по 15/15. Candidate был подготовлен и присоединён с path B, PID/TUN и
  трафик сохранились без reconnect. REALITY gate использует отдельный реальный TLS target, проверяет
  заимствование TLS shape и цепочки сертификатов, прозрачный decoy bridge, точный pinned identity и
  настоящий HTTP/2 carrier. Runner явно пожинает фоновые server/client/target jobs при очистке.
- Общие Linux TCP/UDP roaming harness теперь принимают `QELI_ROAMING_DEVICE_TYPE=tun|tap`,
  создают выбранный тип на сервере и клиенте и fail-closed сверяют фактический kernel `tun_flags`.
  Lab TAP gate прошёл TCP fake-TLS 17/17 и UDP QUIC 19/19: после A→B сохранились PID,
  тот же TAP и одна authenticated session без top-level reconnect. Повторный default-TUN gate
  прошёл те же 17/17 и 19/19, поэтому параметризация не меняет прежний путь. TUN/TAP используют
  одну roaming state machine; отдельной реализации транспорта для TAP не добавлено.
- TCP roaming COMMIT теперь переносит весь bonded carrier set, а не только slot 0: после
  публикации authenticated replacement старые fixed/adaptive writers закрываются, и общий
  stable-slot maintainer восстанавливает требуемую ширину через новый platform route. Закрытие
  последнего sender теперь явно завершает writer; раньше `Some(pt) = recv()` отключал select-ветку
  на `None`, оставляя старые TCP-сокеты принимать flow-pinned пакеты в чёрный путь. Lab regression
  сначала воспроизвёл потерю туннеля, затем прошёл single 17/17, fixed 21/21 и adaptive 22/22:
  adaptive вырос до трёх потоков под реальной iperf-нагрузкой, secondary slots заново JOINed с
  path B, а PID/TUN, одна AUTH и continuous probe сохранились без top-level reconnect.
- Параллельный Linux TUN unit gate больше не проверяет освобождённые номера fd двумя раздельными
  `fcntl`: другой тест мог легально переиспользовать второй номер между вызовами. Проверка теперь
  фиксирует отключение обоих Unix-datagram peers. Feature suite прошёл 973 теста при трёх ignored;
  строгий release Clippy прошёл с `experimental-roaming,jemalloc` и с default `jemalloc`.
- Добавлен отдельный `roaming_wire` fuzz-target для произвольных UDP CID-заголовков, TCP resume
  JOIN/proof и `PATH_*` control bodies; валидные round-trip инварианты и tampered-proof path
  проверяются вместе с reject-путями. Цель включена в обязательный CI smoke и nightly matrix.
  Lab ASan/libFuzzer smoke прошёл 1 324 437 запусков за 31 секунду при coverage 515, corpus 22 и
  peak RSS 371 MiB без падений или ошибок санитайзера.
- RU/EN threat model теперь явно описывает linkability при roaming: CID rotation убирает
  стабильный открытый UDP-идентификатор, но сервер всё равно связывает оба адреса с одной
  сессией, а глобальный наблюдатель может коррелировать переход по timing/volume/overlap.
- Linux `exit_node` теперь обновляет WAN-зависимые MARK/MASQUERADE/FORWARD и sysctl leases до
  публикации нового carrier route при roaming COMMIT. Состояние хранится отдельно для каждого TUN,
  поэтому обычный исходящий профиль в том же daemon-процессе не может унаследовать exit-node rules;
  IPv4 и IPv6 независимо перечитывают свои фактические default uplink и не приравниваются к
  интерфейсу qeli carrier. Правила прежнего WAN остаются на bounded drain/rollback и все поколения
  удаляются при чистой остановке.
  Общий `roaming_exit_node_netns_e2e.sh` поднимает отдельные server, exit, consumer и router
  namespaces и передаёт реальный consumer-трафик через server → exit → WAN A/B для TCP и UDP.
  Feature release прошёл TCP 35/35 и каждый из UDP `quic`, `fake-tls`, `obfs`, `obfs-awg` 35/35
  (`roaming_exit_node_udp_all_modes_netns_e2e.sh`: 4/4): выросли NAT-счётчики обоих WAN,
  сохранились ровно две исходные полные AUTH, PID и TUN, top-level reconnect не запускался, а
  после SIGTERM были удалены правила обоих поколений и восстановлены `ip_forward`/`rp_filter`.
  Identity, TOFU, device-id и control socket теста изолированы в его рабочем каталоге; все
  транспортные маскировки проверяют один и тот же exit-node COMMIT path.

- Android feature adapter объявляет полный `ROAMING_PATH` для TCP и всех UDP-режимов только
  когда загруженное Rust-ядро подтверждает path-transaction ABI. ABI 1.13 дополнительно
  согласует `PATH_REFRESH_EVENTS`/`PATH_REFRESH`: при authenticated RX silence общий UDP actor
  один раз просит свежий generation-scoped snapshot той же Android `Network`, а Kotlin отправляет
  `SameNetworkNatFailure` PathUpdate через прежние exact-Network DNS, `bindSocket`, `protect` и
  PREPARE/BIND/COMMIT/ABORT. Таймер попытки, 15-секундное окно и full-reconnect fallback остаются
  только в общем Rust policy; ошибка Android snapshot не запускает второй platform timer.
  Stale generation и superseded Network проверяются до platform mutation. Default `.so`, старое
  ядро без нового capability и unsupported peer сохраняют обычный полный reconnect.
  На API 34 emulator с feature APK закрыта полная UDP-матрица same-network NAT rebinding для
  fake-TLS, QUIC, obfs и obfs-AWG: старый двусторонний 5-tuple блокировался без изменения Android
  `Network`, ядро запрашивало `PATH_REFRESH`, а сервер выполнял `PATH_CHALLENGE`/`PATH_COMMIT` на
  новый source port. В каждом режиме PID приложения, Network handle и TUN/lease сохранялись,
  ping проходил 5/5 до и после миграции; повторных AUTH, `NetworkPlan` и reconnect не было.
  Повторный gate выполнен после чистой сборки текущего feature core и APK `0.8.0` (`versionCode=720`,
  SHA-256 `710185c288ac0d19e1adfd843d409d8f450270239a5bd241dd91764d996d9ead`): все четыре режима
  снова прошли 44/44 инварианта, включая смену исходного UDP-порта, единственные AUTH/NetworkPlan,
  неизменные PID/TUN и tunnel ping 5/5 до и после commit.
- Общий TCP supervisor теперь отдаёт приоритет exact-path handover перед generic hard-resume:
  уже подготовленный candidate всегда вытесняет обычное восстановление слота, а после потери
  последнего carrier ядро оставляет платформе ограниченное окно в одну секунду на PathUpdate.
  Если candidate не появился, hard-resume продолжает работу как раньше. Это устраняет наблюдавшийся
  на Android двойной `JOIN` без неограниченной задержки восстановления. Повторный API 34 race-gate
  подтвердил ровно один authenticated `JOIN` на каждый переход, единственные `Auth OK` и
  `NetworkPlan 1`, неизменный PID/VPN Network, 76/80 ping при hard loss и 80/80 при обратном
  make-before-break; DNS продолжил разрешать имя. Полный Rust suite: 931 passed, 3 ignored,
  strict all-target Clippy и Android release `-D warnings` также прошли.
- На API 34 emulator feature APK прошёл Wi-Fi → cellular с 198/200 ping и cellular → Wi-Fi с
  200/200. В обоих случаях сохранились PID, VPN Network, `tun0` и `NetworkPlan 1`, а `Auth OK`
  появился ровно один раз. Hard-loss callback выбирает уже доступный физический replacement,
  поэтому потеря Wi-Fi больше не обнуляет путь перед созданием candidate.
- Sleep/wake на неизменном Wi-Fi сохранил 160/160 ping и не создал лишний handover; после обоих
  переходов и сна системный DNS продолжил разрешать имя. Same-network NAT rebinding, реальные
  устройства и race/soak matrix остаются отдельными gate для TCP; для UDP emulator gate закрыт,
  а real-device NAT-rebinding и race/soak остаются впереди.
- Android x86_64 default и feature `.so` собраны NDK r26d в release с `panic=unwind` и
  `-D warnings`; Unix raw-fd trait импортируется без предупреждений всегда на Linux и только вместе
  с `experimental-roaming` на остальных Unix-платформах. Оба path JNI export присутствуют в
  feature-сборке. Kotlin unit tests и `assembleDebug` прошли.
- Общий roaming core больше не ограничивает native candidate socket Unix-дескриптором `i32`:
  `PATH_COMMAND.socket_fd` сохраняет заимствованный signed 64-bit Unix fd или Windows `SOCKET`,
  а native TCP candidate dialer и единый UDP make-before-break actor компилируются на Windows без
  отдельной protocol-specific логики. Wide-handle regression, строгая Windows host feature-сборка
  и Linux all-target feature gate прошли.
- Общий C# desktop-слой получил optional ABI 1.12/1.13 bindings для `PathUpdate`, коррелированного
  `PathCommandResult` и формата событий. Строгий ограниченный parser JSON-контракта
  PREPARE/BIND/COMMIT/ABORT и no-payload `PATH_REFRESH` проверяет generation/sequence/candidate,
  допустимые причины и flags, сетевой token/interface index, TTL и совместимость IPv4/IPv6,
  отклоняет неизвестные поля и сохраняет 64-битный Windows `SOCKET` без сужения к `Int32`.
  Managed conformance suite, shared library и Windows desktop client собираются без предупреждений.
  Base capability по умолчанию остаётся нулевым; default/старые cores сохраняют full-reconnect fallback.
- Windows C# path executor реализует общую для TCP и всех UDP camouflage modes сериализованную
  транзакцию PREPARE → BIND → COMMIT/ABORT. `GetBestRoute2` ограничивается точным физическим
  interface/source; candidate lease создаёт только пригодные `/32`/`/128`, сохраняет operator routes,
  удаляет лишь stale Qeli-owned carrier rows и восстанавливает уже удалённые rows при ошибке COMMIT.
  BIND применяет `IP_UNICAST_IF` в network byte order или `IPV6_UNICAST_IF` в host byte order к
  заимствованному 64-битному `SOCKET` и связывает выбранный local address до connect в Rust core.
  Kill switch и WinDivert используют old+new на PREPARE и new-only после COMMIT без сброса
  tunnel-up, policy generation, NAT/flow state и uplink. Capability объявляется для обычных TCP,
  UDP fake-TLS, UDP-QUIC и UDP-obfs профилей. Явные `local`/`lport`, default/старое ядро и
  unsupported peer используют прежний reconnect fallback. Managed route/socket/policy self-tests
  проходят; Windows real-device, race, kill-switch и soak acceptance остаются до rollout.
- macOS C# path executor реализует ту же общую для обычного TCP и всех UDP camouflage modes
  транзакцию. PREPARE создаёт точные interface-scoped host routes, BIND применяет Darwin
  `IP_BOUND_IF`/`IPV6_BOUND_IF` и выбранный source address к заимствованному fd до connect, COMMIT
  сохраняет scoped route для активного socket, переключает Qeli-owned обычный host route для
  будущего bonded TCP repair и сужает PF old+new до new-only, а ABORT возвращает старую policy и
  удаляет только candidate-owned state. Исходные operator routes сохраняются и восстанавливаются;
  незавершённая очистка повторяется при disconnect. Явные `local`/`lport`, default/старое ядро и
  unsupported peer используют прежний reconnect fallback. Release cross-build прошёл без
  предупреждений, все macOS route/socket/capability self-tests — `PASS`; live macOS device/race,
  route-command, PF, per-app и sleep/soak acceptance остаётся обязательным gate до rollout.
- iOS Swift path executor подключён к той же общей Rust state machine для обычного TCP и всех UDP
  camouflage modes. `NWPathMonitor` отбрасывает TUN/loopback-шум; path-scoped UDP `NWConnection`
  получает effective local/remote endpoint через выбранный интерфейс после DNS/NAT64. PREPARE
  применяет точные old+new carrier `/32`/`/128` как NetworkExtension `excludedRoutes`, BIND связывает
  borrowed fd с `IP_BOUND_IF`/`IPV6_BOUND_IF` и выбранным source address, COMMIT сужает обход до
  new-only, ABORT возвращает old-only. Wake и `PATH_REFRESH` используют тот же generation-scoped
  PathUpdate; невозможность подготовить обычный path сохраняет bounded full-reconnect fallback.
  Явные `local`/ненулевой `lport`, default/старое ядро и unsupported peer также используют reconnect.
  `build_native.sh` теперь по умолчанию включает `transport-core-ffi experimental-roaming`, а
  iOS-only descriptor-backed TUN dependency исключена: strict `aarch64-apple-ios` cross-target
  Clippy на лабе проходит без предупреждений. Swift/Xcode и NetworkExtension в Linux-среде не
  собираются; Xcode 16 и real-iPhone Wi-Fi/cellular, wake, NAT64, rollback, per-app/MDM и soak
  остаются обязательными gate до включения по умолчанию.
- Linux/OpenWrt in-process TCP adapter получил наблюдатель физического пути. Он раз в секунду
  читает только готовые global-адреса и физические default routes, исключает TUN, требует две
  стабильные выборки при смене route/address и распознаёт wake-gap от 5 секунд. `PathUpdate`
  использует уже аутентифицированный закреплённый IP сервера без повторного DNS через возможный
  сломанный туннель. Linux объявляет полный `ROAMING_PATH` только в сборке
  `experimental-roaming`, без явного `server.local_address`: для TCP и всех UDP-режимов.
  Fixed-source, выключенный профиль или legacy peer не согласуют path capability и сохраняют
  reconnect-поведение.
- Двухмаршрутный Linux netns e2e прошёл 15/15: lower-metric default подготовил candidate на
  втором интерфейсе, сервер принял fresh-KE handover JOIN с нового source IP, COMMIT перенёс
  qeli-owned carrier `/32`, старый интерфейс был выключен, но PID клиента, TUN ifindex и
  NetworkPlan сохранились без top-level reconnect. Непрерывная серия сохранила 150/150 ping.
  Базовый routing/IPv6/kill-switch netns gate после исправлений прошёл 26/26.
- Первичная live-проверка `UDP_ROAM_V1` выполнена на feature-gated UDP+QUIC при совпадающем server
  bit и полном platform `ROAMING_PATH`. Изолированный двухмаршрутный UDP netns e2e прошёл 17/17: полный
  PATH_INIT/CHALLENGE/RESPONSE/COMMIT перенёс authenticated session, carrier `/32`, active socket и
  receive pump до выключения старого интерфейса, сохранив PID/TUN и отсутствие top-level reconnect.
  Успешные серверные PATH_CHALLENGE/PATH_COMMIT теперь видны на `info` с peer/epoch.
- Отказ candidate-пути теперь принят отдельным Linux UDP netns gate 20/20: blackhole только пути B
  доводит PATH_INIT до ограниченного expiry, после чего exact platform ABORT удаляет подготовленный
  candidate/socket, не оставляет маршрут через B и сохраняет действующий carrier `/32` на пути A.
  Туннель передаёт трафик с теми же PID и TUN без верхнеуровневого reconnect; success повторно прошёл
  17/17. Завершённый rollback виден на `info`, чтобы live gate проверял фактический ACK платформы.
- Закрыта Linux UDP supersede-гонка: когда новый PathUpdate приходит после BIND старого candidate,
  executor теперь исполняет стоящий первым `ABORT(old)` и только затем `PREPARE(new)`, а не ожидает
  ошибочно новый PREPARE и не оставляет core в `Aborting`. Общий candidate-current guard заставляет
  UDP actor удалить superseded socket, не принимать его поздние control и повторно свериться прямо
  перед platform COMMIT; тот же контракт использует native runtime. Трёхмаршрутный A → blackholed B
  → C netns gate прошёл 24/24: B отправил PATH_INIT, сервер challenge/commit видел только C, carrier
  `/32` сменился A → C ровно одним commit без reconnect, замены PID/TUN или заметной потери трафика.
- Транзакция пути теперь различает действительно незабранный PREPARE и более поздние команды.
  Только PREPARE можно заменить без rollback; незабранный BIND уже следует за применённым PREPARE
  и обязательно превращается в `ABORT(old) → PREPARE(new)`, включая заполненную bounded event queue.
  После начала COMMIT новый PathUpdate больше не отменяет linearized candidate: сохраняется только
  последний replacement, который стартует после точного ACK текущего COMMIT. Поздний ACK старой
  команды и late wire challenge/commit старого message id не могут изменить новый candidate.
- Linux in-process path executor сериализует выдачу команды, OS mutation и ACK, поэтому concurrent
  detector не может забрать BIND/COMMIT event или запустить ABORT параллельно ещё выполняющейся
  platform-команде. Детерминированный A → delayed COMMIT(B) → C netns gate прошёл 24/24: сервер
  аутентифицировал B до локального ACK, B был опубликован до PREPARE(C), затем C закоммитился ровно
  один раз; carrier `/32`, PID, TUN и трафик сохранились без reconnect. Предыдущие success 17/17,
  rollback 20/20 и supersede 24/24 повторно прошли; Rust suites — 870/1 и 950/3, оба strict Clippy.
- Добавлен детерминированный packet-loss gate для UDP path validation. Точные firewall-фильтры
  отбрасывают первый PATH_CHALLENGE и первый PATH_COMMIT на candidate-пути; клиент повторяет
  PATH_INIT/PATH_RESPONSE свежими AEAD records, сервер переотправляет тот же логический PATH_COMMIT
  с новым packet number и не публикует путь второй раз. Live netns прошёл 18/18: оба счётчика DROP
  равны единице, candidate закоммичен ровно один раз, carrier `/32`, PID и TUN сохранены, top-level
  reconnect отсутствует, непрерывный трафик остаётся рабочим.
- Исправлен PMTU-control после согласования UDP roaming. Bare PMTU probes/ACK используют directional
  CID wrapper, но не являются PacketCodec AEAD records; сервер раньше безусловно передавал их в
  decrypt и отбрасывал. Теперь они принимаются до AEAD только после точного разрешения session CID и
  совпадения committed epoch/socket/peer. Candidate-путь по-прежнему допускает только authenticated
  PATH-control, поэтому обход return-path validation и anti-amplification невозможен. ACK старой epoch,
  старого peer или другого socket не может повысить новый budget.
- IPv4 PMTU ladder дополнен ступенями 1100/1000/900/800/700. На outer MTU 1280 прежний переход
  1200 → 576 занижал UDP payload budget до 637 байт; теперь первый проходящий rung 1100 даёт 1161 байт.
  Изолированный Linux netns gate прошёл 19/19: epoch-zero uplink/downlink сертифицировали 1461 байт,
  после commit пути MTU 1280 оба направления независимо пересертифицировали 1161 байт, внутренний TUN
  сохранил MTU 1400, а ping payload 1350 прошёл через DATA_FRAG без замены PID/TUN и без reconnect.
  Переходы между outer-семействами проверены отдельным gate ниже; реальные устройства остаются впереди.
- Серверный reverse PMTU больше не остаётся на conservative budget 548, когда S2C уже сообщённого
  клиентом C2S. Uplink и downlink теперь используют один ladder из protocol core; сервер держит один
  exact pending marker на всём спуске и последовательно пробует меньшие rungs после `EMSGSIZE` или
  timeout. Точный ACK завершает scheduler, смена epoch/peer отменяет его, duplicate budget-report не
  создаёт параллельную последовательность.
- Асимметричный Linux IPv4 netns gate прошёл 19/19: при C2S 1500 и одностороннем S2C blackhole 1280
  uplink сохранил budget 1461, downlink независимо сертифицировал 1161, reverse ping payload 1350
  прошёл через DATA_FRAG, PID/TUN и сессия сохранились без reconnect. Симметричный PMTU gate повторно
  прошёл 19/19; остальные UDP roaming gates также зелёные.
- После PATH_COMMIT клиент и сервер сохраняют точный непосредственно предыдущий UDP receive-path
  только для DATA/DATA_FRAG и только на один `REASSEMBLY_TIMEOUT` (5 секунд). Старые epoch/peer/socket/CID
  не могут переноситься на новый адрес, candidate по-прежнему принимает лишь authenticated PATH-control,
  а на draining-пути запрещены control и PMTU. Следующий commit, expiry или teardown освобождает прежние
  receive task/socket snapshot.
- Детерминированный Linux IPv4 netns gate прошёл 26/26: оба направления старого пути A работали с
  MTU 1280, трёхсекундной задержкой и gap-reorder; путь B закоммитился при двух неполных DATA_FRAG-
  записях по 1350 байт, после чего bounded drain завершил обе. Duplicate 100% на активном B остался
  идемпотентным, PID/TUN и сессия сохранились без reconnect.
- Linux UDP теперь переносит одну аутентифицированную сессию между outer IPv4 и IPv6 без новой AUTH.
  Generation-scoped DNS discovery сохраняет пригодные A/AAAA только для следующей доказанной
  PathUpdate-транзакции, тогда как действующий bypass и bonded-stream остаются закреплены ровно за
  фактическим committed peer. Поэтому pin текущего IPv4 не теряет IPv6-кандидат, но и не выдаёт ему
  маршрут до PATH_CHALLENGE/PATH_COMMIT.
- COMMIT сначала добавляет и проверяет новый family-specific host route обычным source-aware FIB,
  затем удаляет только прежний маршрут из ownership journal qeli. Ошибка удаления откатывает новый
  маршрут и сохраняет старую запись для повторной очистки; operator-owned route не удаляется.
- Dual-listener Linux netns gate прошёл 32/32: одна сессия переместилась IPv4 → IPv6 → IPv4 через
  разных receiving workers, сохранила codec owner, PID и TUN без reconnect, пересертифицировала
  PMTU 1461 → 1341 → 1461, передала DATA_FRAG-sized пакет и после каждого commit оставила ровно один
  активный `/32` или `/128`. Непрерывная серия сохранила не менее 245 из 260 ping.
- Deliberate DATA_FRAG-loss закрыт отдельным двунаправленным Linux netns gate 25/25. После
  сертификации MTU 1280 firewall отбросил ровно первый полноразмерный фрагмент каждой 1350-байтной
  записи, но пропустил её хвост; обе неполные записи не были доставлены в TUN. Путь B закоммитился
  при незавершённой reassembly без новой AUTH, замены PID/TUN или top-level reconnect. После
  пятисекундного reassembly timeout и удаления старого пути следующие фрагментированные записи
  успешно прошли в обе стороны; unit-регрессия отдельно фиксирует удаление просроченной записи до
  выделения бюджета новой.
- Linux UDP теперь восстанавливает сессию после same-network NAT dead mapping, когда интерфейс,
  локальный адрес, default/carrier routes и server endpoint не менялись. Authenticated RX-liveness
  один раз на active epoch просит observer создать свежий `SameNetworkNatFailure` PathUpdate;
  observer остаётся единственным владельцем observation/update id, а actor даёт candidate
  ограниченное 15-секундное окно и затем возвращается к обычному fail-closed reconnect.
  Детерминированный stateless-translation netns gate прошёл 21/21: серверный peer сменился
  `10.41.3.1 → 10.41.3.254`, candidate закоммитился ровно один раз без второй AUTH, замены PID/TUN
  или reconnect, при неизменном физическом пути клиента.
- One-attempt-per-epoch, 15-секундный grace, ожидание уже запущенного candidate и reconnect fallback
  перенесены в общий `udp_roaming_client`; Android, Apple и Linux больше не должны повторять эту
  policy. `PathController` оставляет платформе только bounded hook запроса свежего snapshot того же
  физического пути, сохраняя platform ownership update id. Три unit-теста фиксируют request/wait,
  expiry/fallback и повторное разрешение попытки после authenticated commit.
- UDP roaming больше не раздваивается по внешней маскировке: `UDP_ROAM_V1` согласуется для всех
  UDP fake-TLS/QUIC/obfs/AWG профилей при полном `ROAMING_PATH` и `DATA_FRAG_V1`, после AuthOK они
  используют один directional eight-byte CID envelope, один actor, PMTU и NAT recovery policy.
  Linux и Android больше не ставят QUIC-only platform gate; Android предоставляет те же exact
  `Network.bindSocket + VpnService.protect` и PREPARE/BIND/COMMIT/ABORT для TCP и всех UDP modes.
  Добавлен fail-closed JVM policy test; live netns-матрица `quic`, `fake-tls`, `obfs`, `obfs-awg`
  прошла 4/4 режима и 68/68 проверок без замены PID/TUN или top-level reconnect;
  legacy peer без согласованных roaming/DATA_FRAG capability по-прежнему делает full reconnect.
- Full-tunnel bypass и post-COMMIT pinned-набор теперь содержат только адрес фактически
  подключённого или аутентифицированного candidate socket. Остальные DNS-ответы не получают
  `/32`/`/128` заранее и не могут быть выбраны bonded-stream до отдельной PathUpdate-транзакции;
  регрессия с мёртвым первым A-ответом подтверждает отсутствие лишнего host route.
- Kill-switch считает `iptables-nft: Chain 'QELI_KS_*' does not exist` идемпотентным
  отсутствием только при совпадении ожидаемого имени qeli-цепочки. Поэтому чистый namespace
  больше не отклоняется до создания chain, а посторонние parser/backend ошибки остаются
  fail-closed. Routing netns-конфиги явно используют `dns = off`, поскольку тестируют маршруты
  в namespace без системного DNS-менеджера.
- Linux in-process adapter теперь исполняет PREPARE/BIND/COMMIT/ABORT из общей очереди
  `ClientCore`, завершает те же correlated oneshot ACK и при отказе немедленно исполняет
  обязательный ABORT. Выбор `PathCommand` не удаляет стоящие перед ним lifecycle/diagnostic
  события. Сам этот executor capability ещё не включал; наблюдатель и ограниченное
  feature-gated включение Linux описаны выше.
- Linux TCP handover использует отдельный unbound candidate-сокет во всех TCP wire-mode:
  `reality-tls`, `obfs`, `fake-tls` и `plain`. До `connect()` сокет проходит точный
  BIND по interface/source из `PathUpdate`; после authenticated JOIN COMMIT атомарно меняет
  carrier-маршруты и только затем публикует новый закреплённый набор адресов для bonded-streams.
  Регрессия с намеренно недоступным адресом из конфига подтверждает, что candidate dialer
  соединяется только с адресом `PathUpdate` и получает ACK привязки до connect.
- Linux COMMIT carrier-маршрутов получил полный ownership preflight: совпадающий чужой
  маршрут сохраняется без присвоения, конфликтующий отклоняется до первой мутации, а qeli
  меняет через `replace` только собственный маршрут. Каждый применённый IPv4/IPv6 адрес
  проверяется обычным FIB lookup; ошибка любой семьи откатывает предыдущие `add/replace` в обратном
  порядке. После успешной проверки нового пути прежний qeli-owned carrier другой семьи удаляется;
  отказ этой очистки откатывает новый путь и восстанавливает уже снятые старые маршруты вместе с
  ownership journal.
- Linux PREPARE теперь без изменения маршрутов проверяет каждый carrier через точные
  `from <source> oif <interface>` и требует, чтобы FIB вернул тот же физический интерфейс.
  Изолированный netns-тест подтвердил, что source bind + `SO_BINDTODEVICE` достигает нового
  default route даже при активных туннельных `/1` и старом `/32`; поэтому таблица маршрутов
  будет меняться только в COMMIT после аутентифицированного JOIN.
- В общий Rust-слой вынесен `CorePathController`: получение подготовленного кандидата,
  запросы BIND/COMMIT/ABORT, корреляция ACK, отмена и единая диагностика отказов больше
  не реализуются заново в каждом нативном runtime. Android/Windows/macOS/iOS уже делегируют
  ему; Linux использует тот же контроллер через тонкий route/socket adapter.
- Общая модель `PathUpdate` теперь требует хотя бы одну совместимую пару семейств
  local/resolved и сохраняет DNS-порядок только среди реально доступных carrier-адресов.
  Поэтому IPv4-only/IPv6-only путь больше не срывает handover из-за первого несовместимого
  AAAA/A-ответа при наличии следующего пригодного адреса; правило едино для всех клиентов.
- `LinuxCoreAdapter` переведён на разделяемое, коротко блокируемое состояние `ClientCore`.
  Это позволяет in-process Linux/OpenWrt controller использовать тот же автомат
  PREPARE/BIND/COMMIT/ABORT, корреляцию ACK, supersede и roaming-телеметрию, что FFI-клиенты,
  вместо отдельной реализации протокола. Системные route/socket операции будут выполняться
  после освобождения core-lock; сам по себе этот рефакторинг capability ещё не включал.
- Зарезервированы capability-биты `CONTROL_V2`, `UDP_ROAM_V1`, `TCP_RESUME_V2` и
  `TCP_HANDOVER_V2`. Клиент умеет объявить TCP resume/handover, но negotiation удаляет
  handover-bit без полного platform `ROAMING_PATH` (`PATH_TRANSACTIONS + PATH_SOCKET_BINDING`).
  Полный контракт объявляют Linux/OpenWrt, Android, Windows, macOS и iOS,
  если platform adapter и загруженное ядро подтверждают `ROAMING_PATH`; явные `local`/`lport`
  и старые cores сохраняют reconnect fallback. Сервер предлагает roaming capability
  только на профиле с `roaming.enabled = true`.
  Добавлены строгий
  формат `CONTROL_V2` с ограниченной фрагментацией и дедупликацией, UDP CID-заголовок,
  path challenge/response и аутентифицированный TCP resume proof.
- Из исходного handshake IKM доменно-разделённо выводятся resume, directional CID и control
  secrets с zeroization. Known-answer тесты подтверждают новые labels для classic, hybrid и
  static-bound режимов и одновременно фиксируют неизменность существующих data keys.
- TCP hard-resume и единый для всех camouflage modes UDP roaming data plane активируются
  только при профильном server opt-in и authenticated client negotiation. Выключенные профили,
  legacy cores и non-negotiated соединения сохраняют прежнее поведение.
- Source ABI 1.12 добавляет под `experimental-roaming` ограниченный generation-scoped
  `PathUpdate` и транзакцию `PREPARE/BIND/COMMIT/ABORT`. Вход строго ограничен по размеру,
  адресам, TTL и идентификаторам; stale/duplicate update не создаёт работу, а superseding
  update либо отменяет невыданную команду, либо ждёт обязательного rollback. Действующий
  NetworkPlan и data plane на этом этапе не переключаются.
- Статистика V3 получила отдельные roam attempts/successes/failures/candidates/latency и
  reconnect fallbacks без смешивания с обычным `reconnects`; совместимые V1/V2-префиксы
  размером 64/96 байт сохранены. `stop/start` и terminal failure удаляют невыданные команды.
- Добавлены C ABI roundtrip и mock adapter fault-injection тесты отказов
  PREPARE/BIND/COMMIT/ABORT. Android рекламирует новые platform capability только в feature TCP
  после emulator live e2e; остальные native-клиенты ждут своего lab/e2e этапа 4.
- Release export gates синхронизированы с ABI 1.12: Windows/macOS/Android ожидают 22
  `qeli_client_*` вместо 20, Android — 21 `TransportCore` JNI symbol вместо 19. Новая
  Android x86_64 feature-матрица и emulator live пройдены; остальные платформы и полный
  pre-release matrix остаются обязательными gate.
  Platform FFI `clippy -D warnings` также больше не компилирует Linux-only reconnect jitter
  helper и не считает test-only константу stats V2 частью production-кода.

- Stage 2A добавляет общий TCP lifecycle
  `Active → Orphaned → Resuming → Active/Closing/Revoked`. Resume proof проверяется
  одновременно против fresh-handshake transcript, locator, монотонного `u64` epoch и
  стабильного logical slot. Orphan ownership ограничивается числом сессий и retained bytes
  и помечается `session_id + generation`: запоздалый reaper не освобождает ожившую сессию,
  а повторный revoke/reap не уменьшает счётчики дважды. JOIN reservation атомарна, epoch
  сгорает до JOINOK, make-before-break держит старый transport в Draining до точного
  generation-ACK. Race/security unit-тесты добавлены.
- Stage 2B подключает lifecycle к Linux TCP handler и общему client supervisor.
  Resume secret исходной сессии выводится для всех handshake KDF modes
  и хранится с zeroization; каждый resume JOIN выполняет свежий KE и proof, связанный с
  transcript/locator/монотонным epoch/stable slot. При потере последнего carrier клиент до
  30 секунд сохраняет прежние TUN и NetworkPlan, раз в секунду восстанавливает тот же slot,
  а sibling reader/writer завершаются общим stop-сигналом без утечки старых задач.
  Сервер допускает один bounded authenticated candidate сверх stream cap: это позволяет
  атомарно заменить stale carrier, когда клиент уже увидел обрыв, а сервер ещё не получил
  EOF/RST. После commit старый carrier переводится в draining и закрывается; bearer JOIN для
  negotiated-сессии запрещён. Legacy/non-negotiated scheduler не изменён; UDP roaming остаётся
  следующим протокольным срезом.
- Подготовлена безопасная клиентская основа make-before-break: authenticated resume JOIN
  умеет связывать proof с handover-флагом, а учёт stable logical slot переведён с множества
  на refcount. Поэтому краткое перекрытие старого и нового carrier не делает слот ложным
  «отсутствующим», когда первым завершается draining carrier. Сервер принимает handover
  только если authenticated client capabilities одновременно подтверждают
  `TCP_RESUME_V2 + TCP_HANDOVER_V2` и полный platform `ROAMING_PATH`; один core-bit без
  транзакций и exact socket binding больше не даёт права вытеснить живой transport.
- PathUpdate-driven TCP make-before-break подключён к общему client supervisor. Transport
  получает только ACK-подтверждённый PREPARE candidate, создаёт отдельный unbound socket,
  перед connect требует у платформы точный `BIND_SOCKET`, использует только A/AAAA из данного
  PathUpdate и выполняет fresh-KE authenticated JOIN с handover-флагом. После успешного JOIN
  запрашивается `COMMIT_PATH`, затем новый carrier атомарно заменяет stable slot 0; refcount
  сохраняет слот, пока старый carrier завершается. BIND/COMMIT/ABORT возвращают oneshot-результат
  с 45-секундным пределом ожидания, а supersede/stop закрывает waiter без утечки. После commit
  новый список carrier-адресов используется для восстановления остальных bonded slots.
- Если peer не согласовал `TCP_HANDOVER_V2`, candidate сначала проходит ACK-подтверждённый
  `ABORT_PATH`, затем supervisor выполняет обычный full reconnect. Ошибка candidate connect/JOIN
  также откатывает временные platform-правила. Отказ COMMIT остаётся fail-closed: сервер уже
  аутентифицировал и переключил carrier, поэтому клиент восстанавливается существующим hard
  resume, а не пытается вернуть старый путь. Native application adapter bits остаются
  выключенными до их этапа 4 и прохождения device/race matrix.
- Stage 3A добавляет под `experimental-roaming` изолированную profile-wide модель UDP migration.
  Ограниченный реестр связывает восьмибайтовые CID с generation-tagged сессиями и хранит не более
  трёх deterministic aliases на сессию; directional CID secrets zeroize-ятся. На сессию допускается
  ровно один authenticated candidate. PATH_CHALLENGE/RESPONSE привязан к точным path/epoch/token,
  pre-validation отправка ограничена трёхкратным объёмом принятых байтов, а счётчик bounded.
  CID rotation сначала атомарно проверяет коллизии, затем переключает active path; PMTU generation
  сбрасывается к safe payload budget, stale probe не может изменить новый путь, cleanup удаляет все
  aliases и candidate state. Реестр пока не владеет sockets/codecs и не подключён к UDP hot path:
  production data plane на этом этапе не изменён. Девять unit-тестов, включая 32 последовательные
  ротации и stale/collision/anti-amplification случаи, прошли на лабе.
- До подключения UDP hot path устранено противоречие wire design: roaming short header больше не
  имеет постоянного `D1 52` marker, который создавал бы отдельный DPI-отпечаток. Negotiated форма
  сохраняет обычные QUIC short flags, расширяет только cleartext DCID с четырёх до восьми байтов и
  позволяет выполнять bounded CID lookup при miss по source address; legacy path не изменён.
- Stage 3B добавляет generic profile-wide cross-worker fabric без общего decrypt-lock. CID lookup
  хранит неизменяемый home-worker владельца PacketCodec/session actor; ingress с другого
  `SO_REUSEPORT` worker передаётся ему через bounded `try_send`, а ingress на home-worker не делает
  лишний channel hop. Topology и worker id проверяются до регистрации/маршрутизации; unknown CID,
  неверный worker, full и closed mailbox различаются fail-closed, причём dropped payload возвращается
  владельцу и намеренно не реализует `Debug`. Три unit-теста проверяют local/cross-worker delivery,
  immutable ownership, переполнение, закрытие и точный cleanup. Fabric пока не подключён к server
  hot path, поэтому production data plane не изменён.
- Stage 3C переводит серверный UDP data writer с навсегда захваченных socket/address/4-byte CID
  на общий `UdpActiveEgress`. Для каждой полной зашифрованной записи writer получает неизменяемый
  snapshot точного socket, peer, framing и path epoch; все DATA_FRAG-фрагменты одной записи поэтому
  уходят по одному пути, а PacketCodec, replay-window, rate buckets и TUN-сессия не заменяются.
  Под `experimental-roaming` подготовлен guarded commit следующего epoch: он проверяет семейство
  socket/peer, атомарно публикует новый восьмибайтовый CID и сбрасывает PMTU к безопасному бюджету
  нового IPv4/IPv6-пути. Snapshot пути и PMTU согласованы одним lock; запоздалый `EMSGSIZE` старого
  пути не может расширить или подменить бюджет нового. Расчёт DATA_FRAG вычитает фактические 9 байт
  legacy- или 13 байт roaming-заголовка, а caller-owned encoder не добавляет allocation в hot path.
  Legacy wire остаётся byte-identical.
- Следующий срез Stage 3C перевёл heartbeat и shaping cover на тот же per-record snapshot
  `UdpActiveEgress`: после commit новые вспомогательные записи используют актуальные socket,
  peer и CID, а уже сформированная запись может только завершить отправку по старому snapshot.
  Reverse PMTU probe теперь строится с точной длиной active framing, отправляется через активные
  socket/peer и связывается с точными path epoch и адресом. Pending marker разделяется с timeout-задачей,
  поэтому перенос ключа сессии не оставляет probe навсегда занятым. ACK старого пути не может
  расширить бюджет нового: проверка epoch/peer и запись бюджета атомарны относительно guarded commit.
  Capability всё ещё не рекламируется. Fabric и CID ingress уже доведены через общий PacketCodec,
  replay window и DATA_FRAG reassembler до строгого client-direction CONTROL_V2 boundary, но
  PATH_RESPONSE, guarded commit и post-commit data path остаются следующими срезами.
- Добавлен fail-closed bootstrap-контракт UDP roaming. Режим может включиться только при явном
  двустороннем согласовании `CONTROL_V2 + UDP_ROAM_V1 + UDP_DATA_FRAG_V1`; одного клиентского
  reserved bit недостаточно. Для согласованной QUIC-сессии зашифрованный AuthOK передаёт
  `udp_roaming_session` как ненулевой `u64` в канонической строке из 16 hex-символов. Клиент
  отклоняет отсутствующее или некорректное значение, а legacy builder по-прежнему полностью
  исключает поле. `UDP_ROAM_V1` пока не входит в advertised server/client capabilities, поэтому
  runtime остаётся на прежнем четырёхбайтовом CID и новый bootstrap ещё не активируется.
- Feature UDP-handshake переведён на общий `SessionKeyMaterial`: существующие data keys остаются
  идентичными, а C2S/S2C CID secrets выводятся теми же hybrid/static-bound KDF и хранятся с
  zeroization. После полного negotiation сервер до отправки AuthOK регистрирует initial path,
  epoch-zero CIDs и family-safe payload budget в одном profile-wide registry; клиент независимо
  выводит те же directional CIDs из session id. Регистрацией владеет non-cloneable
  generation-scoped guard: поздний teardown старой сессии не может удалить aliases замены с тем же
  session id. UDP worker IDs теперь уникальны между всеми `bind.listen` профиля, поэтому следующий
  ingress-срез сможет однозначно маршрутизировать packet к immutable codec owner через разные
  listeners и outer address families. `UDP_ROAM_V1` всё ещё не рекламируется, wire/runtime
  действующих сессий не изменены.
- Следующий серверный UDP-срез создаёт один bounded ingress fabric на все `SO_REUSEPORT` workers и
  `bind.listen` профиля и выдаёт каждому worker ровно один non-cloneable mailbox. До new-session
  rate limit декодируется обычный QUIC-shaped short header, но пакет уходит в roaming path только
  после успешного lookup полного восьмибайтового CID; неизвестный CID известного address остаётся в
  legacy-пути, поэтому повтор AUTH после потерянного AuthOK не ломается. Pooled datagram без копии и
  точный receiving socket переходят immutable home-worker владельцу codec. Отдельный
  generation-safe индекс `session_id → address` публикуется только после AUTH и очищается одной
  транзакцией с address map; stale teardown не удаляет replacement.
- CID owner boundary теперь использует тот же session-wide `PacketCodec` и replay window, что
  legacy ingress, а `DATA_FRAG_V1` проходит через существующий bounded reassembler. После успешной
  AEAD-проверки строгий CONTROL_V2 decoder принимает только одночастные клиентские `PATH_INIT` и
  `PATH_RESPONSE` без status flags; replay, server-direction, malformed, non-control и обычные data
  records отклоняются до TUN и до изменения пути. Liveness обновляется только после AEAD. Два
  regression-теста фиксируют direction/shape gates и общий replay window.
- `PATH_INIT` теперь одной операцией profile-wide registry проверяет next epoch, future C2S CID,
  ожидаемый S2C CID и новый socket/peer, после чего создаёт или идемпотентно находит единственный
  candidate с non-zero 128-bit challenge. `PATH_CHALLENGE` шифруется общим TX PacketCodec,
  получает восьмибайтовый проверенный destination CID и отправляется точным receiving socket.
  Cumulative reply budget резервируется до send и учитывает roaming header плюс obfs overhead;
  он не может превысить 3× от консервативно посчитанного authenticated candidate ingress.
  Ticket сохраняется в session actor для следующего PATH_RESPONSE-среза. `UDP_ROAM_V1` по-прежнему
  не рекламируется, новый path не публикуется. Wire-тест проверяет CID, packet number и CONTROL_V2.
- Guarded commit state-machine теперь готовит весь новый CID/PMTU outcome до изменения реестра и
  вызывает синхронный publisher внешнего socket/address state, удерживая profile-registry lock.
  CID aliases, active epoch, PMTU generation и candidate меняются только после успешной публикации;
  отказ publisher оставляет candidate пригодным для безопасной повторной обработки того же
  аутентифицированного ответа. Неверный challenge больше не пополняет anti-amplification budget.
  Последний успешный commit хранится одним bounded exact ticket/path/epoch/token outcome на сессию:
  повторный свежезашифрованный PATH_RESPONSE возвращает тот же PATH_COMMIT без повторного publisher,
  ротации CID и сброса уже уточнённого PMTU; несовпадающий token/path отклоняется. Два regression-теста
  фиксируют rollback publisher и идемпотентный replay.
- Live server handler подключает аутентифицированный PATH_RESPONSE к guarded commit. Он проверяет
  old epoch/peer и синхронно отправляет PATH_COMMIT через candidate socket до публикации новых
  socket/peer/CID/epoch и сброса PMTU. Ошибка неблокирующей отправки, включая `WouldBlock`, оставляет
  registry и writer state неизменными, а candidate — пригодным для повтора; отдельный regression
  фиксирует отсутствие частичного commit. После успеха address map и generation-safe owner index
  переносятся под одним directory lock. Очистка supersede/session-limit/teardown разрешает текущий
  адрес по session id и не использует устаревший connect-time peer. Точный свежезашифрованный
  PATH_RESPONSE replay повторно отправляет PATH_COMMIT без повторной ротации CID и сброса PMTU.
- Post-commit UDP DATA/DATA_FRAG подключены к существующему authenticated uplink. До AEAD/replay
  routed CID классифицируется по writer snapshot под directory lock: previous/farther-future epoch
  отклоняется без изменения replay window, current epoch требует точные committed socket и peer,
  next epoch допускается только как candidate control. После единственного session-wide decrypt
  данные проходят прежние bounded reassembler и recordizer, source guard, destination ACL,
  bandwidth pacing, accounting, MTU/client-info control и общий TUN forwarder. Candidate DATA
  отклоняется, а commit/teardown не могут оставить data plane в частично перенесённом состоянии.
  Regression-тесты фиксируют обычный DATA через общий PacketCodec и exact current/candidate/stale
  epoch/socket/peer gates.
- Negotiated epoch-zero UDP bootstrap теперь создаёт `UdpActiveEgress` сразу с initial
  server-to-client CID; первый post-auth writer snapshot и его PMTU/recordizer budget используют
  13-byte roaming header. AuthOK и cached AuthOK retransmit остаются в legacy 4-byte QUIC framing,
  поскольку клиент узнаёт session id для вывода directional CID только из AuthOK. Routed CID
  ingress закрыт до публикации `auth_ok_sent`, поэтому ранний PATH_INIT не может обогнать отправку
  AuthOK и перезаписать epoch-zero state. Focused regression проверяет initial framing, current epoch
  и next-candidate classification; default/non-negotiated wire не изменён. `UDP_ROAM_V1` всё ещё
  не рекламируется: live client integration, capability activation и live-приёмка остаются впереди.
- Добавлен общий клиентский UDP roaming state machine в `transport_core`. Он единожды для всех
  платформ владеет directional CID derivation/rotation, next epoch, корреляцией platform candidate
  и CONTROL_V2 message id, а также переходом `PATH_INIT → PATH_CHALLENGE → PATH_RESPONSE →
  PATH_COMMIT/PATH_ABORT`. Нулевой challenge, неверные CID/epoch/direction, параллельный candidate и
  stale platform completion отклоняются fail-closed. Повтор точного challenge идемпотентно повторяет
  response; повторная отправка ограничена четырьмя datagrams с интервалом 500 мс и тем же фиксированным
  10-секундным TTL, что на сервере. Полученный wire COMMIT остаётся только предложением: active
  epoch/CID не меняются, пока платформа не подтвердила `COMMIT_PATH`, поэтому поздний ACK после ABORT
  не может опубликовать старый путь. Восемь focused-тестов прошли; strict feature Clippy чист,
  полный feature library suite — 940 passed, 3 ignored.
- Общий клиентский wire-слой теперь единожды в Rust-ядре формирует
  `CONTROL_V2 → PacketCodec → 8-byte CID`, строго отделяет data от полного одночастного `PATH_*`
  и использует общий session replay window. Транспортный контракт переименован из TCP-specific
  `TcpPathController` в общий `PathController`; общий Unix UDP candidate dialer создаёт отдельный
  unbound socket, ждёт точный ACK `BIND_SOCKET` и только затем выполняет connect к первому
  family-compatible адресу из `PathUpdate`. Парный Linux unit-test фиксирует этот порядок для TCP
  и UDP. Capability намеренно не включён; интеграция этого слоя в live actor описана ниже.
- Post-auth UDP actor теперь действительно использует общий Rust framing epoch 0. После AuthOK он
  создаёт единый roaming state и направленную пару CID; обычные data, DATA_FRAG, recordizer output,
  cover/heartbeat, authenticated reports, startup/live PMTU probes и ACK обоих направлений проходят
  через один immutable framing snapshot. Ingress с неверным server-to-client CID отбрасывается до
  PacketCodec/replay window, egress использует client-to-server CID. Расчёты DATA_FRAG и PMTU теперь
  принимают фактическую длину wrapper и для roaming вычитают 13 байт вместо legacy 9, исключая
  oversized DF datagrams после согласования. Legacy QUIC и unmasked wire сохранены byte-for-byte.
  Три focused-теста проверяют passthrough, legacy compatibility и directional CID; strict feature
  Clippy чист, полный suite — 943 passed, 3 ignored. На этом промежуточном срезе `UDP_ROAM_V1`
  ещё не рекламировался; feature-only активация и live-приёмка описаны ниже.
- Live UDP actor под `experimental-roaming` теперь получает подготовленный `PathUpdate`, выполняет
  точный BIND-before-connect candidate socket и запускает для него отдельный bounded receive pump.
  PATH_INIT и ограниченные повторы используют общий PacketCodec; только аутентифицированные
  PATH_CHALLENGE/PATH_COMMIT/PATH_ABORT с точными CID, message id и epoch проходят в общий state
  machine. После peer PATH_COMMIT actor ждёт точный platform `COMMIT_PATH` ACK и затем атомарно
  заменяет active socket, receive pump, directional CID framing, UDP buffer controller и
  консервативные family-aware PMTU/record/padding budgets. Пакеты старой epoch, уже стоящие в общей
  очереди, отклоняются; candidate DATA не становится active до публикации новой epoch. Live PMTU
  probe сбрасывается и планируется заново для нового пути. Expiry, send failure, peer abort и
  teardown закрывают candidate pump/socket и выполняют exact platform ABORT. Если локальный budget
  или platform COMMIT ломается после полученного PATH_COMMIT, actor fail-closed завершает сессию для
  полного reconnect: сервер уже переключил путь, поэтому продолжение по старому socket было бы
  ложным успехом. Отдельно закрыт race, где state machine удалял истёкший candidate при приёме
  control, а actor мог оставить platform/socket ресурс. Focused epoch-классификация проверяет
  candidate → active и stale old queue. После feature-only активации полный gate проходит strict
  default/feature Clippy, default suite 870 passed/1 ignored и feature suite 947 passed/3 ignored.
  Первичная реализация согласовывала `UDP_ROAM_V1` для UDP+QUIC при совпадающем server bit и полном
  platform `ROAMING_PATH`; текущая реализация использует тот же roaming-контракт для всех UDP-
  режимов. Fixed-source, выключенные профили и legacy peers сохраняют прежний reconnect. Первый Linux
  live e2e 17/17 выполнен на QUIC; rollback/adversarial race и soak остаются release gates.
- Незавершённая UDP path validation теперь имеет фиксированный TTL 10 секунд, отдельный
  profile-wide cap `min(max_clients, 1024)` и скользящий admission limit 64 новых candidates в
  секунду. Повтор того же authenticated PATH_INIT увеличивает только 3× anti-amplification budget,
  но не продлевает TTL и не расходует новый rate slot. Истёкший ticket отклоняется до egress/commit,
  а общий registry reaper освобождает молчащие candidates из существующего maintenance tick.
  Счётчик обновляется точно при commit, abort, CID collision, session teardown и expiry; default и
  non-negotiated data plane не изменены.
- Cross-listener IPv4→IPv6 regression проводит future CID через чужой worker, выполняет полный
  candidate commit и возвращает post-commit ingress неизменному codec owner. Тест одновременно
  фиксирует новый IPv6 path/PMTU generation и отсутствие обработки candidate на receiving worker.
- Обновлённый срез прошёл на lab `.10` Rust fmt, default/feature library suites с 865/915 тестами
  (по одному privileged ignored), 4 CLI и 7 integration tests, а также strict all-target Clippy
  в обеих конфигурациях. Точная Windows FFI feature matrix отдельно прошла Rust 1.97 checks и
  strict Clippy. Это был source/unit gate до подключения Linux-наблюдателя; последующий
  feature-gated Linux TCP adapter уже рекламирует полный `ROAMING_PATH` и прошёл отдельный
  двухмаршрутный live netns e2e 15/15. Native application adapters остаются впереди.
- Намеренная остановка TCP-клиента отправляет строгий пустой `CLOSE_SESSION` внутри
  аутентифицированного CONTROL_V2/PacketCodec, принудительно flush-ит `PACKET_MUX_V1` и
  ограничивает ожидание записи 750 мс. Сервер немедленно закрывает все bonded streams,
  запрещает новые JOIN/resume, освобождает lease и не входит в orphan grace. Linux
  SIGINT/SIGTERM теперь использует cooperative teardown вместо `process::exit`.
- Предыдущий изолированный Linux netns e2e с односторонним TCP RST прошёл 13/13:
  authenticated resume занял 2 секунды, внешний carrier сменился, TUN ifindex/IP сохранились,
  ping восстановился, а полная password AUTH выполнилась ровно один раз. Отдельный live e2e
  `.11 → .10` с обязательным `PACKET_MUX_V1` прошёл 3/3 ping, подтвердил оба close-маркера,
  отсутствие established carrier и клиентского TUN после SIGTERM и отсутствие перехода
  сервера в resume grace.

### Reality-TLS: настоящий HTTP/2 carrier и переход со старой схемы

#### Что изменилось на проводе

- `reality-tls` больше не запускает второй fake-TLS handshake внутри уже установленного
  REALITY TLS 1.3. Новый стек на проводе: **TCP → REALITY TLS 1.3 → настоящий HTTP/2 →
  приватный поток qeli**. После ALPN `h2` клиент открывает один долгоживущий двунаправленный
  `POST /v1/events/stream` с `content-type: application/grpc`; сервер отвечает `200` и передаёт
  поток через настоящие HTTP/2 `SETTINGS`/`HEADERS`/`DATA`/`WINDOW_UPDATE`.
- Внутренний `PacketCodec` и его ChaCha20-Poly1305 не удалены: аутентификация, anti-replay и
  шифрование пакетов qeli остаются end-to-end. Удалена именно распознаваемая вложенная
  fake-TLS choreography и связь «один внутренний IP-пакет = одна внешняя TLS-запись».
- H2 carrier автоматически объединяет записи перед отправкой. Первая порция не удерживается
  дольше случайных 2–8 мс; под нагрузкой 72% целевых DATA-блоков растут до 16 КиБ, остальные
  получают случайную цель 4–14 КиБ. HTTP/2 window равен 2 МиБ, максимальный DATA frame —
  16 КиБ, сервер объявляет до 100 одновременных streams. Это внутренние параметры wire-логики,
  отдельных INI-ключей для них нет.
- Новый сервер после аутентифицированного внешнего TLS различает H2 preface и старый внутренний
  fake-TLS ClientHello. Поэтому **новый сервер принимает как новые, так и уже установленные
  legacy `reality-tls` клиенты**. Новый клиент, напротив, требует H2 и намеренно не делает
  скрытый downgrade: при подключении к старому серверу он завершит соединение ошибкой.

#### Изменившиеся defaults и параметры

Для нового/обновлённого серверного Reality-профиля каноническая конфигурация выглядит так:

```ini
[profile:reality-tls]
bind.transport = tcp
bind.port = 443

obf.mode = reality-tls
obf.tls.server_name = www.microsoft.com
obf.tls.reality_proxy.enabled = true
obf.tls.reality_proxy.target = www.microsoft.com
obf.tls.reality_proxy.target_port = 443
obf.tls.reality_proxy.real_tls = true
obf.tls.reality_proxy.handrolled = true
obf.tls.reality_proxy.short_ids = YOUR_EXISTING_SHORT_ID

obf.padding.enabled = false
obf.heartbeat.enabled = false
obf.heartbeat.interval_ms = 15000
obf.heartbeat.data_size_bytes = 16
obf.heartbeat.jitter_ms = 5000

obf.traffic_shaping.enabled = true
obf.traffic_shaping.idle_gap_mean_ms = 700
obf.traffic_shaping.idle_gap_min_ms = 40
obf.traffic_shaping.idle_gap_max_ms = 6000
obf.traffic_shaping.budget_bytes_per_sec = 16384
obf.traffic_shaping.min_size = 64
obf.traffic_shaping.max_size = 1024
```

- `obf.mode = reality-tls` — новое каноническое имя серверного wire-профиля. Старое сочетание
  `obf.mode = fake-tls` + `reality_proxy.enabled = true` + `real_tls = true` новый сервер пока
  понимает для миграции, но новые конфиги должны использовать `reality-tls`.
- `obf.tls.server_name`, `reality_proxy.target` и клиентский `sni` должны обозначать одно
  реальное DNS-имя. Не заменяйте его IP-адресом и не включайте случайную ротацию SNI для
  Reality: SNI обязан соответствовать заимствованной цепочке сертификатов target.
- `short_ids` — allow-list REALITY-токенов. При обновлении сохраняйте существующие значения,
  иначе старые клиенты будут молча приняты за посторонний probe и перенаправлены на target.
- `handrolled = true` сохраняет cert-borrowing и target-like ServerHello; `false` оставляет
  совместимый rustls-путь с другой маскировкой. H2 carrier работает после обоих TLS terminator.
- Heartbeat jitter по умолчанию увеличен с `20` до `5000` мс. Сам scheduler теперь каждый раз
  заново выбирает one-shot задержку `interval ± jitter` после активности или отправки, а не
  держит постоянный периодический ticker.
- В `reality-tls` heartbeat принудительно выключается клиентским ядром независимо от локального
  значения и server push: TCP/H2 уже контролирует жизнь соединения, а периодический qeli-маяк
  создавал устойчивый временной признак. Поля interval/size/jitter можно оставить в конфиге для
  совместимости и других профилей, но трафик heartbeat в Reality/H2 они не включат.
- Для idle camouflage поставляемые stealth-профили используют `traffic_shaping.enabled = true`:
  случайный Poisson cover заменяет фиксированный heartbeat. `budget_bytes_per_sec` ограничивает
  только cover, а не полезный трафик; `stealth = false` не ограничивает скорость реальных пакетов.
- `padding.enabled = false` рекомендуется для Reality/H2: индивидуальный padding каждого
  qeli-пакета только увеличивает расход, тогда как H2 batching уже разрушает границы сообщений.
- Параметры `obf.http2_masking.enabled` и `obf.http2_masking.ratio` больше не являются способом
  включить H2 и считаются retired. Их следует удалить из пользовательских конфигов. Настоящий
  H2 carrier включается автоматически только режимом `reality-tls`; синтетического
  `HTTP/2 masking` переключателя больше нет.
- Важно различать два уровня defaults: schema baseline по-прежнему оставляет shaping выключенным
  для обратной совместимости нестелс-профилей, а поставляемые Reality/max-obfuscation конфиги
  явно задают `heartbeat = false` и `traffic_shaping = true`.

Клиенту для нового carrier не нужны H2-параметры. Его обязательная часть остаётся плоской:

```ini
[qeli]
server = vpn.example.com:443
proto = tcp
mode = reality-tls
key = PINNED_SERVER_IDENTITY_PUBLIC_KEY
sni = www.microsoft.com
reality_sid = YOUR_EXISTING_SHORT_ID
bind_static = true
```

`key` — это pinned identity qeli, а не публичный ключ или сертификат target. `reality_sid`
должен входить в серверный `short_ids`; `sni` должен совпадать с серверными `server_name` и
`target`. Уже установленное приложение не получает H2 автоматически только потому, что
обновлён сервер: Windows/macOS/Android/iOS должны быть выпущены и установлены с новым общим
Rust native-core.

#### Правильный порядок обновления

1. **Сохраните действующий конфиг, identity key профиля и `short_ids`.** Не генерируйте новую
   identity и новые short_id без отдельной плановой ротации: иначе потребуется одновременно
   переиздать все клиентские профили.
2. **Сначала обновите серверный бинарник.** Новый сервер продолжает принимать старые
   `reality-tls` клиенты с внутренним fake-TLS carrier, поэтому server-first обновление не
   требует одновременной остановки всех устройств.
3. **Приведите Reality-профиль к каноническому примеру выше:** TCP, `obf.mode = reality-tls`,
   `reality_proxy.enabled = true`, `real_tls = true`, прежние target/SNI/short_ids, heartbeat
   off и shaping on. Удалите retired `obf.http2_masking.*`.
4. **Перезапустите сервер и проверьте старым клиентом.** До обновления клиента он должен
   по-прежнему пройти `AUTH OK`; это проверяет legacy-ветку нового сервера.
5. **Обновите клиентские приложения/native-core**, затем оставьте или выставьте
   `proto = tcp`, `mode = reality-tls`, прежние `key`, `sni` и `reality_sid`. Скрытого отката
   к старому carrier нет: если сервер не обновлён, новый клиент сообщит
   `reality-tls HTTP/2 carrier failed`/timeout вместо менее защищённого соединения.
6. **Проверьте новую ветку по логам.** Клиент должен написать
   `REALITY-TLS carrier: genuine HTTP/2 stream`, сервер —
   `REALITY: genuine HTTP/2 carrier established`, после чего должны появиться обычные
   `AUTH OK`, адрес туннеля и двусторонний трафик.
7. **Не смешивайте bare fake-TLS с legacy Reality-TLS.** Новый сервер совместим со старым
   `reality-tls`, который уже устанавливал внешний настоящий TLS. Обычный `fake-tls` клиент
   без REALITY TLS не станет H2-клиентом и при необходимости должен оставаться на отдельном
   legacy-профиле/порту.

#### Ожидаемый результат и границы заявления

- На внешнем соединении видны настоящий TLS 1.3 с ALPN `h2` и валидное HTTP/2 framing вместо
  второго fake-TLS handshake. Randomized H2 batching убирает прежнюю связь размеров qeli-пакета,
  внутренней записи и внешнего TLS payload; фиксированный heartbeat отсутствует, idle заполняется
  ограниченным случайным cover.
- В чистом лабораторном PCAP-тесте 6/6 новых сессий прошли AUTH, ping и двусторонний UDP;
  классификатор, обученный на старом транспорт-независимом отпечатке, определил новый Qeli в
  0/6 случаев при 0/6 false-positive на control. Полный отчёт и точные условия:
  [release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md](release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).
- Это не означает «0% обнаружения» промышленным DPI. До такого заявления нужны настоящие
  согласованные browser TLS-профили вместо произвольной JA3-ротации, target-specific H2
  SETTINGS/priority/window/stream choreography, более широкий control corpus и отдельные тесты
  active probe, replay, malformed TLS/H2, reconnect и долгоживущих потоков. `udp-quic` остаётся
  только QUIC-shaped compatibility mode, а не настоящим QUIC/HTTP3; максимальная текущая
  маскировка относится к TCP `reality-tls` с новым H2 carrier.

### Универсальная морфология записей для всех транспортных режимов

- Добавлен согласуемый после аутентификации внутренний формат `PACKET_MUX_V1`. Он работает
  одинаково поверх TCP `plain`, `fake-tls`, `reality-tls`, `obfs`/WebSocket/AWG и поверх UDP
  `fake-tls`, QUIC-shape, `obfs`/AWG. Это **не новый transport mode** и не замена carrier:
  recordizer находится между TUN-пакетами и существующим `PacketCodec`/carrier.
- Data-plane больше не обязан сохранять отношение «один IP-пакет = одна qeli-запись».
  Recordizer за ограниченное случайное окно объединяет несколько пакетов, выбирает полный или
  случайный неполный безопасный payload и при необходимости переносит один IP-пакет несколькими
  зашифрованными записями. Приёмник восстанавливает исходные IPv4/IPv6-пакеты до передачи в TUN.
- Настройка больше не захардкожена в Reality/H2. Каждый серверный профиль получает одинаковый
  набор `obf.recordizer.*`: policy, окно/лимиты batch, распределение целевого record payload,
  разрешение fragment и жёсткие timeout/memory/inflight/fragment limits для reassembly.
  `record.max_payload_bytes = 0` автоматически зажимает размер под фактический TCP/UDP carrier
  и path budget; ручное значение никогда не может расширить вычисленный безопасный предел.
- Сервер передаёт эффективные параметры клиенту только внутри аутентифицированного `AUTH OK`.
  Клиентских `obf.recordizer.*` ключей нет: desktop/mobile приложения получают поведение вместе
  с обновлённым общим Rust native-core и серверным профилем. До успешной аутентификации handshake,
  active-probe fallback и cover остаются в прежнем формате.
- Политика миграции задаётся сервером:
  - `off` — schema default и полный legacy data-plane;
  - `prefer` — включить `PACKET_MUX_V1`, если клиент объявил поддержку, иначе оставить legacy;
  - `required` — отвергнуть несовместимый клиент до выдачи IP-адреса/создания lease.
- Поставляемые серверные профили явно переведены на `prefer`. Это позволяет сначала обновить
  сервер и постепенно обновить клиенты без общей остановки. После обновления всего парка можно
  выбрать `required`; для применения нового policy уже открытые сессии должны переподключиться.
  Быстрый rollback — вернуть `off` и переподключить клиентов.
- Канонические значения поставки: batch `2..8 ms`, до `16` пакетов и `256 KiB`; автоматический
  record payload, диапазон неполной цели `0.25..0.875`, вероятность полного payload `0.72`;
  fragmentation включена, reassembly timeout `3000 ms`, до `64` пакетов / `4 MiB` / `64`
  фрагментов на исходный пакет. Полный справочник и ограничения приведены в `docs/*/manuals/CONFIG.md`.
- Защитные свойства остаются end-to-end: recordizer сериализуется **до** `PacketCodec` AEAD,
  поэтому внутренние заголовки, ID и границы фрагментов не выходят на провод открытым текстом.
  Очереди и reassembly ограничены; просроченные, пересекающиеся, дублированные или превышающие
  предел фрагменты отвергаются без неограниченного выделения памяти.
- Результат — общий для всех режимов контроль распределения размеров и границ, устраняющий
  прежний transport-independent признак «IP packet ↔ qeli record». Он не делает режимы
  одинаковыми и не означает «протокол полностью незаметен»: внешний TLS/REALITY/H2/WebSocket/
  QUIC-shape, адрес назначения, handshake и долгие тайминги по-прежнему классифицируемы. Поэтому
  carrier-specific параметры и PCAP/DPI-регрессия каждого режима остаются обязательными.

#### Переход пользовательских конфигов

1. Обновить серверный бинарник, сохранив существующие identity, ключи и transport-параметры.
2. Добавить в каждый нужный `[profile:*]` как минимум `obf.recordizer.policy = prefer`.
   Остальные `obf.recordizer.*` можно не задавать: будут использованы безопасные defaults.
3. Перезапустить сервер и убедиться, что legacy-клиент всё ещё подключается по fallback.
4. Обновить клиентские приложения/общий native-core и переподключить сессии. Менять клиентские
   ссылки и добавлять recordizer-параметры на клиент не требуется.
5. После подтверждения обновления всего парка при необходимости сменить `prefer` на `required`.
   Не включать `required` раньше: это намеренно прекратит доступ старых клиентов.
6. Полная матрица совместимости, объяснение defaults и профили тюнинга находятся в
   [русском](docs/ru/manuals/OBFUSCATION.md) и [английском](docs/eng/manuals/OBFUSCATION.md)
   руководствах по обфускации.

### Dual-stack по умолчанию в поставляемых шаблонах

- Все поставляемые серверные шаблоны теперь явно задают `tun.ip_mode = dual`, IPv4-пул,
  IPv6 ULA-пул, NAT44, `routing.ipv6.mode = nat66` и DNS-listener обоих семейств. В
  `server-multiprofile.conf` каждый из 10 режимов получил отдельный `/64`; подсети одного
  профиля больше нельзя копировать в другой профиль той же площадки.
- Для внутренних адресов используется локально назначаемая часть RFC4193 — `fd00::/8`
  (в составе `fc00::/7`). `fe80::/10` намеренно не используется и отвергается валидатором:
  link-local адрес интерфейсно-зависим и не маршрутизируется как клиентский tunnel pool.
- Статические файлы содержат заметный пример `fd71:e1:8000::/48`, а не глобально общий
  «дефолтный» адрес. При ручном копировании его **обязательно** заменить уникальным ULA `/48`;
  каждой секции `[profile:*]` оставить собственный subnet ID `/64`.
- One-shot installer проверяет реальный IPv6 default route, выбранный ядром WAN-интерфейс,
  публичный исходный GUA из `2000::/3` и доступность NAT-таблицы `ip6tables`. При успехе он
  генерирует 40 случайных бит Global ID, подставляет новый ULA `/48`, фиксирует WAN-interface
  и оставляет NAT66. При отсутствии любого условия создаваемый активный профиль безопасно
  нормализуется к IPv4, при этом NAT44 остаётся включённым.
- На Debian/Ubuntu отдельного пакета `ip6tables` нет: команды `iptables` и `ip6tables`
  устанавливает один пакет `iptables`. Установщик ставит этот пакет и отдельно проверяет
  наличие команды/рабочей NAT-таблицы до включения NAT66.
- NAT66 реализован как MASQUERADE: ULA клиента переводится в текущий публичный IPv6 адрес
  интерфейса default route. Если провайдер маршрутизирует выделенный GUA-префикс к серверу,
  вместо NAT66 можно назначить клиентам этот префикс и выбрать `routing.ipv6.mode = route`.
- Schema baseline остаётся `ipv4` для обратной совместимости старых пользовательских
  конфигов. Обновление одного бинарника не переписывает существующий `server.conf` и не
  включает IPv6 самопроизвольно; новые defaults относятся к поставляемым шаблонам, Quick
  Start и новой установке.

#### Переход существующей установки на dual-stack

1. Убедиться, что WAN имеет публичный IPv6 и default route (`ip -6 route`, `ip -6 addr`),
   затем установить пакет `iptables` и проверить `ip6tables -t nat -S`.
2. Сгенерировать уникальный RFC4193 `/48`; выделить отдельный `/64` каждому профилю.
3. В каждом профиле добавить `tun.ip_mode = dual`, `tun.ipv6_address`, `pool.ipv6.cidr`,
   `routing.ipv6.mode = nat66`, при необходимости `routing.ipv6.interface`, а для встроенного
   DNS — совпадающий `dns.listen_ipv6`. Существующие IPv4 `tun.address`, `pool.cidr` и NAT44
   сохранить: это и есть dual-stack, а не замена IPv4.
4. На клиентах оставить/добавить `ipv6 = auto`; для release-gate использовать `required`,
   чтобы отсутствие IPv6 завершало подключение ошибкой, а не скрытым downgrade.
5. Выполнить `qeli check-config`, перезапустить сервис и проверить адрес `/128`, IPv4/IPv6
   gateway, DNS, `ping -6`, внешний IPv6 и правила `ip6tables`. Полная процедура и rollback:
   [docs/ru/manuals/IPV6.md](docs/ru/manuals/IPV6.md) / [docs/eng/manuals/IPV6.md](docs/eng/manuals/IPV6.md).

- Закрыт повторный security/runtime-аудит клиентов и поставки. Windows kill-switch теперь
  открывает WinDivert с допустимым приоритетом и проверяет границы в self-test; необработанные
  UI/AppDomain/TaskScheduler ошибки пишутся в аварийный журнал, а per-app capture классифицирует
  новые потоки в ограниченной очереди без 75-мс блокировки общего packet-loop и fail-open потери
  первых пакетов.
- macOS устраняет TOCTOU при привилегированной установке daemon: root читает ровно заранее
  проверенные байты через `O_NOFOLLOW` и сверяет digest. CI теперь загружает настоящие production
  pf-правила в одноразовый не подключённый anchor, читает их обратно и очищает; полный сетевой
  тест подключённого anchor остаётся обязательным release-gate на физическом Mac.
- Панель переведена на официальный Alpine CSP build: `script-src` больше не требует
  'unsafe-eval', динамический QR не использует `x-html`, а все bundled-шаблоны проходят CSP
  smoke-test. REALITY-конфигурация fail-closed требует session-bound static proof; документация
  точно разделяет внешний TLS-camouflage и фактическую аутентификацию pinned qeli identity.
- Android привязывает transport/DNS к выбранной carrier network и сообщает её системе через
  `setUnderlyingNetworks()`. Хранилище профилей переведено с deprecated security-crypto на
  Android Keystore AES-256-GCM с versioned AAD-envelope и одноразовой legacy-миграцией. Emulator
  CI на API 29/35 исполняет production `VpnService.Builder.establish()` для split/full/dual-stack.
  Wake-lock теперь имеет продлеваемый конечный lease и аварийно истекает, если lifecycle-cleanup
  не был вызван.
- Bare `fake-tls` больше не выдаёт себя TLS-1.3-only списком: он переиспользует полный
  15-suite Chrome contract REALITY и отправляет обязательные OCSP/SCT/ALPS/session-ticket/
  ec-point/renegotiation extensions. Случайный SNI decoy-pool удалён: IP endpoint
  означает no-SNI для fake-TLS, фактический `Host` для WebSocket и обязательный явный
  DNS-front для REALITY; CR/LF и некорректные имена отклоняются до сети.
  Managed C# fallback для старого/несовместимого native-core также использует Chrome-набор,
  GREASE и полный набор browser-like расширений; WebSocket fronting без фактического или явно
  заданного Host отклоняется вместо случайной подстановки чужого домена.
- Автоопрос reachability на Windows, macOS и Android стал privacy-safe opt-in и выключен по
  умолчанию; ручная проверка сохранена, а уже запущенные автоматические поколения отменяются.
  RU/EN threat model, troubleshooting и подсказки интерфейса синхронизированы с этим поведением.
- OpenWrt больше не хранит пароль и obfs-key в UCI: LuCI передаёт write-only секрет узкому rpcd
  методу, init-скрипт атомарно кладёт его с mode 0600 в `/var/run/qeli`, а legacy UCI-значения
  мигрируются и удаляются. rpcd ACL больше не позволяет запускать/останавливать произвольные
  службы маршрутизатора.
- Linux `.deb` теперь собирается из точного release-tag в GitHub Actions с `--locked`, проходит
  package smoke-test, получает OIDC build-provenance и только затем заменяет release asset и
  `SHA256SUMS`. Wintun DLL сопровождается официальным Prebuilt Binaries License; CI проверяет
  подпись, hashes и наличие лицензии в обоих publish-путях.
- Из git удалены временные Habr-preview файлы и тестовый APK; бинарные payload релиза
  по-прежнему публикуются только в GitHub Releases и не хранятся в исходном дереве.

- Версии Rust-сервера, Android, iOS, Windows, macOS, shared-компонентов, Debian и
  OpenWrt/LuCI синхронизированы с новой линией разработки `0.8.0`.
- Документация и release-gates для `0.8.0` теперь раздельно фиксируют текущую ветку,
  планируемый выпуск и последний опубликованный релиз. `sync_version.py` проверяет эти
  значения независимо, а docs gate запрещает хрупкие ссылки на номера строк и требует
  одинаковую нормативную ревизию ключевых RU/EN документов.
- Руководства приведены к фактическому flat-INI и 80-key клиентскому контракту: отсутствие
  `perf.*` использует baseline defaults, а явно заданные нулевые timeout/client-limit
  отвергаются с корректной диагностикой. Package CI дополнительно проверяет серверные
  sample-конфиги из собранного `.deb` на Debian 10 и Ubuntu 22.04. Актуализированы
  требования к IPv6/roaming, native ABI 1.11, provenance и обязательной пересборке
  платформенных ядер перед релизом.

- Release-сборка Linux server теперь останавливается на этапе компиляции без feature `jemalloc`;
  debug/test, FFI-библиотеки и отдельный router client остаются изолированными. Debian-рецепты
  жёстко включают allocator и больше не принимают пустой `CARGO_FEATURES`, а CI и lab gate
  проверяют обе стороны контракта: сборка без jemalloc обязана упасть с точной ошибкой, сборка
  с jemalloc — успешно завершиться.

- Android теперь применяет доверенные Wi-Fi и после удаления приложения из недавних: VPN-сервис
  включает location foreground-тип только для активной trusted-Wi-Fi функции, а Android 12+
  callback явно запрашивает `WifiInfo` с SSID. Неизвестный/скрытый SSID по-прежнему обрабатывается
  fail-safe и не отключает VPN; boot/always-on без доступного location-гранта сохраняет туннель.
- Native transport-core сборка выровнена по платформенным `cfg`: Android/macOS используют
  общий Ethernet/TAP framing без Linux-only `AsRawFd` и `DeviceType`, а desktop bind helper
  больше не компилируется для mobile targets. Android arm64/x86_64 cores пересобраны двумя
  воспроизводимыми проходами; canonical и APK-копии синхронизированы по SHA-256.
- Вкладки профилей панели больше не обозначают TCP замком, а UDP антенной: встроенные
  SVG показывают непрерывный двунаправленный TCP-поток и отдельные UDP-датаграммы,
  одинаково отображаясь во всех ОС и не завися от платформенного набора эмодзи.
- Панель, Quick Start, share/usage/logs и worker-restart теперь читают актуальный `server.conf` и выбранный им
  внешний users-файл вместе с inline-пользователями/группами, а не boot-time снимки supervisor.
  Смена `auth.users_file` применяется обычным перезапуском worker; повреждённый текущий конфиг или users-файл
  возвращает явную ошибку вместо тихого отката к устаревшему состоянию.
- CRUD пользователей, групп и сброс пароля выполняются под общей блокировкой ревизии и проверяют полный
  file + inline + profile-reservation candidate до атомарной записи. Inline-пользователь корректно получает
  внешний override при редактировании, а физически невозможное удаление inline-секции честно отклоняется.
  Отсутствующий users-файл разрешён как пустое состояние первой установки одинаково для supervisor/worker.
- Worker-команды `disable-user`, `enable-user`, `set-limit` и `set-bandwidth` сохраняют полный эффективный
  набор file + inline пользователей: inline-учётная запись материализуется во внешний override, а успешная
  запись больше не заменяет runtime ACL одним `users.conf` и не теряет остальных inline-пользователей.
- При `tun.mtu = 0` TCP- и UDP-клиенты после negotiation увеличивают TUN/TAP/utun read buffer до
  фактического MTU с учётом 14-байтового Ethernet и 4-байтового utun framing. Малый допустимый
  `tun_buffer_size` больше не обрезает пакеты после server push с MTU 1280/1400/1500.
- Веб-панель точнее отражает состояние подключений: глобальный счётчик явно показывает активные
  входящие сессии, таблица пользователей объединяет действующие и фиксированные адреса туннеля,
  а исходящие профили больше не растягивают строку сырым многострочным логом при штатной работе,
  сохраняя компактную последнюю ошибку для диагностики старых клиентов.
- Users API теперь различает отсутствующее optional-поле и явную очистку: пустые
  `static_ip`, `static_ipv6` и `group`, которые форма отправляет как `null`, действительно
  удаляются из users-файла; неверные JSON-типы отклоняются вместо молчаливого no-op.
- Контракт share-ссылок снова одинаков на всех клиентах: `apps_mode`/`apps` остаются
  локальной flat-INI политикой и не попадают в переносимый `qeli://`. Windows/macOS больше
  не расширяют ссылку платформенными идентификаторами приложений; INI round-trip сохранён.
- Повторный Quick Start при явном переходе из IPv6-only в IPv4/dual проверяет весь
  активируемый IPv4-план, включая TUN/DNS, DHCP, reservations и host routes. Корректная
  ручная подсеть сохраняется, а конфликтующая переносится в свободный RFC1918 `/24` вместе
  с безопасным сбросом зависимых адресных значений; dormant IPv4-пулы других IPv6-only
  профилей больше не считаются занятыми.
- Android публикует `CONNECTED` только после заполнения полного generation-owned снимка
  (адреса, gateway, время и счётчики), поэтому пересозданный Activity больше не видит
  кратковременный статус нового соединения с полями от предыдущего поколения.
- Документация IPv6, iOS/macOS framing и упаковки приведена к коду: описаны оба семейства
  Packet Tunnel/utun, IPv6 full-tunnel routes и реальный путь установленного примера
  `/etc/qeli/server-ipv6.conf.example` для DEB и install-скрипта.
- IPv6-настройки доведены до всех операторских интерфейсов: Users управляет и показывает
  `static_ipv6`; web Client Manager редактирует `ipv6=auto|required|off` и оба fail-closed
  leak-исключения, а диагностика отображает `family_mode` и весь `NetworkPlan.addresses[]`.
  Windows/macOS получили те же управляемые поля в локализованном редакторе профиля.
  Android/iOS сохраняют полный raw INI-контракт; шаблоны нового профиля теперь явно показывают
  `ipv6 = auto` и оба безопасно выключенных leak-исключения.
- Статусы Windows, macOS, Android и iOS больше не скрывают второе назначение dual-stack:
  детали соединения сохраняют и показывают полный список IPv4/IPv6 адресов с префиксами,
  сохраняя legacy primary IP только для компактного статуса и обратной совместимости.
- Публичный C header синхронизирован с NetworkPlan ABI 1.11: задокументированы
  `family_mode`, typed `addresses[]`, `carrier_address`, leak policy и `connection_log`.
  Добавлены подробные RU/EN руководства `IPV6.md`, исправлено описание Quick Start,
  локализованы IPv6-поля панели, а карта и 80-key клиентская матрица приведены к текущему
  контракту.

- TAP ingress теперь удаляет стандартный Ethernet padding по объявленной длине IPv4/IPv6
  до передачи пакета в L3-туннель. Некорректные total/payload length и неоднозначные IPv6
  jumbogram-пакеты отклоняются; server TAP и общий Linux transport-core используют единый parser.
- Linux client TAP снова активируется из актуального flat-INI: `[qeli] device_type = tap`
  теперь читается, валидируется и сохраняется при round-trip вместо отказа как неизвестный ключ
  и скрытого продолжения с TUN. Windows, macOS, Android и iOS сохраняют этот переносимый
  Linux-only ключ, но fail-closed отклоняют попытку запустить TAP на системном L3-интерфейсе.
  Устанавливаемый `client.conf`, справочник и межклиентская матрица синхронизированы с этим
  контрактом.
- IPv6 Quick Start включает NAT66 только при наличии готового global-unicast адреса на рабочем
  default-route интерфейсе. `tentative`, `dadfailed`, `deprecated`, `dead` и `linkdown` больше не
  создают ложную готовность; имена `eth0@ifN` нормализуются, а полный список адресов сохраняется
  отдельно для строгого поиска коллизий. Документационные, benchmark, ORCHID и переходные
  Teredo/6to4 диапазоны не считаются нативным публичным IPv6 egress.
- Android `versionCode` и iOS `CURRENT_PROJECT_VERSION`/fallback build подняты до `720`.
  `scripts/sync_version.py` сверяет счётчик с последним release-тегом и не позволяет повторно
  выпустить или откатить уже использованный mobile build-number.
- Документация transport-core синхронизирована с ABI 1.11 (`0x0001000B`) и фактически
  реализованными `set_tun_fd`, `set_wintun_adapter`, `tun_push` и `tun_pull`; удалено устаревшее
  описание этих функций как будущего API.

- Активный UDP PMTU probe на Linux/Android теперь использует тот же DF-режим, что и data path,
  и учитывает route/cached PMTU вместо `IP_PMTUDISC_PROBE`, который намеренно его обходил.
  Исправление симметрично применено к client→server и reverse server→client probe: обнаруженный
  бюджет больше не может оказаться крупнее датаграммы, которую обычный `IP_PMTUDISC_DO` способен
  отправить; при узком пути сохраняется безопасный DATA_FRAG fallback.
- Долгоживущая UDP DATA_FRAG-сессия с авто-MTU теперь раз в 10 минут повторно проверяет только
  более широкие ступени пути через единственный socket receive-loop. Расширение применяется
  после трёх независимых точных challenge/ACK, атомарно обновляет uplink record/fragment/padding
  budgets и повторно сообщает серверу новый потолок; потеря ответов сохраняет последний
  подтверждённый бюджет и прежний DF-режим.
- Общий record ceiling приведён к пределу TLSCiphertext из RFC 8446: максимальный inner MTU
  теперь `16602` во всех Rust/C#/Kotlin/Swift, панели, пакетных рецептах и conformance-fixtures.
  Размер packet bridge выводится из финального authenticated NetworkPlan и учитывает также
  normalization/padding даже для прямого native/iOS plan path.
- TCP data plane унифицировал liveness по успешно аутентифицированным RX+TX данным и использует
  negotiated MTU для normalization. Сервер атомарно сериализует revoke/лимит/attach bonded JOIN
  до `JOINOK`, а профиль без heartbeat, shaping, idle timeout и TCP keepalive отклоняется до
  старта. Cover token bucket теперь общий для всей bonded-сессии, поэтому JOIN-потоки не
  умножают допустимый объём маскирующего трафика.
- WebSocket fronting проверяет связанный `Sec-WebSocket-Accept`, направление MASK, RSV/opcode,
  fragmentation/control invariants и сообщает EOF посреди кадра. REALITY stream превращает
  `close_notify` в чистый EOF, явно отклоняет неподдерживаемый `KeyUpdate`, а decoy bridge
  передаёт half-close в обе стороны вместо отмены обратного потока.
- Reconnect backoff получил ограниченный 80–100% jitter во всех клиентах. Windows/macOS больше
  не превращают нормальную гонку отменённого native request (`STALE_REQUEST`) в ложный MITM,
  а Android JNI различает пустую event queue и реальную ошибку native poll.
- Kill-switch корректно считает отсутствующей ещё не созданную собственную `QELI_KS*`-цепочку
  iptables-legacy при exit code 2 / `Couldn't load target ... No such file or directory`.
  Проверка привязана к точному ожидаемому имени QELI-цепочки, поэтому отсутствие стороннего
  target/match по-прежнему остаётся реальной ошибкой firewall, а не маскируется как clean start.
- После успешной проверки credentials несовместимость IPv6 capabilities теперь возвращается
  клиенту как зашифрованный `ERR:<причина>` и по TCP, и по UDP, вместо немого close/timeout.
  UDP использует тот же AuthOK framing/QUIC wrapper и кэш точного AUTH для ограниченных повторов,
  поэтому потеря первого ERR не уничтожает диагностику.
- `static_ip`, `static_ipv6` и профильные reservations стали строгим контрактом: проверяются
  принадлежность пулу, server TUN address, exclude и конфликты между включёнными пользователями.
  `check-config`, панель и `add-client` отклоняют ошибку до записи/старта, а единый TCP/UDP
  allocator больше никогда не подменяет невыдаваемый fixed-адрес динамической арендой.
- UDP `DATA_FRAG_V1` больше не держит server→client поток на консервативных 548/1232 байтах
  всю сессию: после успешного DF-probe клиент передаёт отдельно от inner MTU аутентифицированный
  бюджет внешней UDP-нагрузки. Этот отчёт задаёт только потолок: сервер отдельно посылает в
  обратном направлении полноразмерный DF-probe и расширяет downlink лишь после точного ACK.
  Поэтому асимметричный путь больше не может ошибочно применить client→server результат к
  server→client. До отчёта, при старом клиенте, потере ACK и неуспешном probe остаётся безопасный
  семейный минимум; новый control type обратно совместим. При позднем локальном `EMSGSIZE` сервер
  атомарно откатывает бюджет к минимуму, считает только реально отправленные байты и повторяет
  полную запись с новым DATA_FRAG record id, не смешивая её с недособранными старыми фрагментами.
  Ячейки MTU/budget/client-info публикуются до отправки AuthOK, поэтому немедленный отчёт больше
  не теряется в гонке между worker-задачами. Повторы отчётов теперь планируются даже при ошибке
  самой первой локальной отправки, а receive-loop PMTU не принимает cover/heartbeat или
  запоздалый чужой ACK за провал текущей ступени.
- Общий IPv4/IPv6 parser теперь отклоняет зарезервированные fragment-биты, сочетание DF с
  реальной IPv4-фрагментацией, пустые/невыровненные non-final фрагменты и диапазон фрагмента,
  выходящий за максимальный IP-пакет, включая extension headers до IPv6 Fragment Header.
  Windows per-app применяет те же reserved/alignment/duplicate/overflow проверки и при этом
  принимает корректный 40-байтный IPv6-пакет с нулевой нагрузкой (`No Next Header`), не путая
  его с неподдерживаемым jumbogram.
- Канонический генератор `conformance/udp-frag.json` снова сам выдаёт fail-closed кейс
  конфликтующего дубликата одного fragment index. Поэтому `gen-conformance --check` больше не
  предлагает удалить эту межплатформенную проверку, а Rust/C#/Swift обязаны одинаково отвергать
  зависимую от порядка доставки пересборку.
- Генерация share-ссылок строго проверяет публичный endpoint как IP/DNS-host и больше не
  допускает `@`, путь, query/fragment, пробелы, percent-вставки и повреждённые DNS labels.
  iOS корректно считает установленным pushed-маршрут, который после исключений представлен
  несколькими CIDR-фрагментами, но только если установлены все части; protected DNS routes
  сохраняют fail-closed семантику. Документация EN/RU приведена к фактическому разделению
  inner MTU и внешнего UDP-бюджета, учёту IPv4/IPv6 overhead и отличию автоматического
  DATA_FRAG от handshake-настройки `obf.fragmentation.*`.
- Сборочный гейт обновившегося Rust stable снова проходит strict Clippy: SHA-1 WebSocket
  helper обрабатывает те же 64-байтные блоки через современный slice API, а obfs nonce
  инициализируется выражением без изменения wire-поведения.

- Серверная IPv6-маршрутизация больше не зависит от публичного default route в режиме
  `routing.ipv6.mode = route`: LAN-only/site-to-site включает forwarding без фиктивного WAN,
  тогда как `nat66` по-прежнему требует реальный uplink. Пулы IPv4/IPv6 всех активных профилей
  проверяются на пересечение без зависимости от host snapshot. Межпрофильные DROP ставятся
  выше всех широких ACCEPT и синхронизируются для параллельно стартующих профилей; iptables
  ожидает xtables-lock ограниченные 5 секунд, а cleanup корректно разбирает quoted profile names.
- Устранено расхождение конфиг-валидаторов: `allowed_networks` пользователей и групп одинаково
  принимает IPv4/IPv6 в inline и внешнем users-файле; GUI/retired-ключи освобождаются от
  `check-config` только в своих секциях. Имена экземпляров `[profile:*]`/`[user:*]`/`[group:*]`
  строго проверяются; ссылка пользователя на отсутствующую группу закрывается ошибкой после
  объединения file+inline, а объединённая база повторно проверяется на конфликты адресов.
  Число profile/user pushed routes ограничено 256 до
  handshake. Платформенный transport runtime принимает большие A/AAAA-наборы, канонизирует
  mapped IPv4, удаляет дубликаты и сохраняет до 32 кандидатов каждого семейства вместо отказа
  на корректном семнадцатом адресе.
- DNS-прокси валидирует полное framing всех DNS-секций и EDNS, не кэширует TC, transient/error
  либо malformed-ответы, уважает TTL 1–4 секунды без искусственного повышения, а отрицательный
  TTL берёт из `min(SOA TTL, SOA.MINIMUM)`. Повреждённый ответ и FORMERR/SERVFAIL/NOTIMP/REFUSED/
  extended RCODE переключают запрос на следующий резолвер; все попытки разделяют один общий
  дедлайн. `dns.upstream`/`cache_size`/`timeout_secs` получили явные пределы 16/10000/300,
  эквивалентные дубликаты IPv6/IPv4 upstream отклоняются, а dual IPv4/IPv6 listeners разделяют
  один cache/preferred-upstream,
  blocklist-NXDOMAIN больше не отражает клиентские RR/OPT; список валидируется, ограничен 10000
  уникальных имён и один раз компилируется в `HashSet` вместо аллокаций и полного перебора на
  каждый запрос. Подозрительный UDP-ответ получает не более одной TCP-повторной попытки.
  На Android 12 и ниже точный IPv6 complement для двух разнесённых
  host-exclude (254 CIDR) больше не отвергается старым лимитом 200; защитный предел оставлен 512.
- Windows per-app направляет настроенный/pushed DNS через туннель независимо от PID системного
  resolver-процесса, поддерживает IPv4-запрос к IPv6 tunnel resolver и обратную комбинацию с
  reversible NAT, а при DNS46 учитывает рост IPv6-заголовка в PMTU/MSS и возвращает корректный
  ICMP fragmentation-needed вместо создания непереводимого фрагмента.

- Повторный аудит macOS per-app устранил merge-регрессию тестовой цели и восстановил точную
  семантику `gateway`: обычный публичный трафик split-профиля обходит туннель, а явные/pushed
  маршруты идут только через согласованное семейство и иначе блокируются. Изменения
  `tunnelIpv4`/`tunnelIpv6`/обоих leak-флагов теперь закрывают старые relay вместе с остальной
  policy. Hostname relay запрашивает и A, и AAAA и перебирает family-кандидатов для TCP/UDP,
  поэтому IPv6-only per-app больше не ломается из-за первой IPv4 DNS-записи.
- Windows per-app теперь отличает обычный default full-tunnel от явно заказанных `include`,
  pushed/connected и `route_local` маршрутов: `allow_ipv4_leak`/`allow_ipv6_leak` разрешают
  обход только отсутствующего семейства full-tunnel, но не выпускают явный маршрут в открытую.
  DNS-пакет при настроенных tunnel-резолверах другого семейства блокируется вместо отправки
  исходному физическому DNS; malformed IPv4 остаётся обычным policy-drop без обращения к
  незаполненному metadata.
- macOS per-app guardian проверяет не только существование PID, но и реальное родительство:
  переиспользованный системой PID больше не может бесконечно продлевать stale utun lease.
  Внутренняя схема state получила единый version marker; helper и оба providers отклоняют
  неизвестную будущую версию, закрывают старые relay и безопасно возвращаются к системному пути.
- Linux TCP/UDP carrier нормализует IPv4-mapped IPv6 адреса так же, как общее ядро остальных
  клиентов. Выбор семейства сокета, `local_address`, deduplication и закрепляемый full-tunnel
  bypass route теперь описывают фактический IPv4 пакет, исключая рекурсию carrier в TUN.
- Linux router/exit-клиенты получили межпроцессный журнал владения sysctl с file lock,
  boot-id и владельцем `PID + process start-time + TUN`. Уже выставленное значение всё равно
  регистрируется; остановка одного профиля не выключает forwarding/`accept_ra`/`rp_filter`,
  пока настройка нужна другому процессу или профилю, а stale-владельцы после SIGKILL
  восстанавливаются при следующей операции без риска PID reuse.
- Серверный `routing.ipv6.mode = off` теперь блокирует чужой kernel transit в обе стороны,
  а `route` разрешает source-preserving forwarding по реальным kernel routes профиля между
  TUN и WAN/LAN, включая динамические IPv6 `client_subnet`; NAT66 остаётся привязан к выбранному
  WAN и принимает только related/established входящий трафик.
- Новый профиль Quick Start добавляет внешний V6ONLY `[::]` listener только когда host snapshot
  подтверждает IPv6-интерфейс/default route; IPv4-профиль на ядре с полностью отключённым IPv6
  больше не падает на bind. Повторный запуск по-прежнему сохраняет ручные listeners. Legacy
  Linux pushed-route путь проверяет существующие IPv6 routes через `ip -6` и использует `/128`,
  а не IPv4-хардкод `/32`.
- Согласование IPv6-возможностей больше не требует `IPV6_KILL_SWITCH` у split-tunnel,
  где итоговый `NetworkPlan` всё равно отключает kill switch; full-tunnel по-прежнему
  требует эту возможность и при `ipv6 = required` отказывает fail-closed.
- Серверные `net.ipv6.conf.all.forwarding` и uplink `accept_ra` получили атомарный
  crash-recovery journal исходных значений. После аварийного завершения worker восстанавливает
  только всё ещё принадлежащее qeli состояние до запуска профилей; journal другого boot-id
  отбрасывается, а ошибка восстановления блокирует запуск вместо принятия `1`/`2` за настройки
  администратора.
- Сохраняемый macOS per-app utun теперь снимает IPv4-адрес так же явно, как IPv6 alias,
  поэтому переход dual/IPv4 → IPv6-only не оставляет старый connected route. Windows per-app
  MSS clamp одновременно обновляет TCP checksum до фрагментации, включая MSS-опцию с нечётным
  выравниванием, поэтому первый IPv4/IPv6 фрагмент больше не несёт checksum старого MSS.
- UDP handshake reassembly принимает повтор только при полном совпадении байтов; конфликтующий
  fragment с тем же индексом отклоняется одинаково Rust/C#/Swift и закреплён общим KAT.
  Сохранённые Swift wire-примитивы исключены из обоих production iOS targets и компилируются
  только внутри `QeliIOSTests`.
- Проверка обновлений на Android теперь привязана к конкретному системному VPN `Network`:
  удаление TUN завершает DNS/HTTPS-запрос ошибкой, а не переносит его на физическую сеть;
  отключение opt-in немедленно отменяет активную проверку. На iOS все управляемые остановки
  туннеля сначала отменяют и дожидаются завершения `URLSession`-задачи. Одновременно исправлена
  merge-регрессия iOS: в `disconnectManually()` ошибочно находился фрагмент ping-кода с
  неопределённым `profile`; восстановлено отключение On Demand → cancellation barrier → stop,
  а UDP-probe активного IPv4/IPv6 профиля использует опубликованный `tunnelGateway` и единый
  `toTransportCoreINI()`.
- Серверный `client_subnet` больше не делает разрушительный `ip route replace`: перед `add`
  проверяется существующий exact-prefix; чужой или немаркированный маршрут отклоняется,
  чтобы teardown не удалил состояние администратора, а собственный stale route принимается
  только при совпадении TUN и единого add/post-check/del route-metric ownership marker;
  после добавления владение проверяется повторно. Ошибка `ip`/netlink теперь откатывает TCP/UDP
  session-map, уже добавленные iroute и pool lease до `AuthOK`, поэтому клиент не выглядит
  подключённым при неработающем site-to-site. Число `client_subnet` ограничено 16 на пользователя,
  а каждый iproute2-вызов — одной секундой.
- Quick Start сохраняет новые `rules.v4`/`rules.v6` через полностью записанный непустой временный
  файл и атомарный no-clobber hard link: ошибка `iptables-save`, заполненный диск или конкурирующий
  firewall-manager больше не оставляют пустой persistent ruleset. Внешний IPv4 MSS-clamp снижен
  с 1340 до 1240, чтобы PQ-handshake помещался в консервативный IPv4 PMTU 1280; документация и
  production helper-скрипты приведены к тому же значению и атомарному сохранению.
- Устаревший singular/IPv4 DNS setup больше не входит в production-сборку Linux-клиента:
  рабочий путь использует только аутентифицированный dual-stack `NetworkPlan` и
  `setup_network_plan_dns`. Исправлено противоречие документации: `/0` разрешён как внутренний
  exit-node iroute, но никогда не устанавливается как Linux host default-route.

- После повторного аудита сведения веток восстановлены потерянные Windows/macOS guards
  атомарной замены `NetworkPlan` для `persist_tun`, а TCP disconnect, admin kick и
  quota/expiry teardown теперь удерживают профильный admission до освобождения IPv4/IPv6
  lease. Повторное подключение того же устройства больше не может получить адрес между
  удалением старой сессии и её запоздалым `pool.release()`. UDP idle/dead reaper включён
  в тот же порядок блокировок и больше не освобождает lease ещё публикуемой reconnect-сессии.
  Удаление kernel-iroute также выполняется внутри admission-транзакции: запоздалый
  `ip route del` старой сессии не может удалить уже установленный маршрут быстрого reconnect;
  вызов iproute2 ограничен односекундным timeout, чтобы зависший netlink не остановил новые входы.
- Установщик при IPv6 literal в `PUBLIC_HOST` теперь не только заключает адрес в скобки в
  ссылках, но и добавляет выбранному профилю независимый V6ONLY listener `[::]:port`, сохраняя
  основной IPv4 listener. На хосте с включённым IPv6 такой listener создаётся также для DNS-имени
  или автоматически найденного IPv4, чтобы последующее появление AAAA не требовало переустановки.
  Для TCP-профилей Quick Start симметрично ставит и сохраняет внешние IPv4/IPv6 MSS-clamp
  в обе стороны handshake (`PREROUTING` для ServerHello и `OUTPUT` для ClientHello; IPv6
  MSS 1220), не перезаписывая существующие `rules.v4`/`rules.v6` и не присваивая себе
  владение уже существовавшими правилами в напечатанной команде отката.
  Windows/macOS включают `forward=true` только для реально согласованных семейств, не меняя
  состояние отсутствующего семейства на хосте.
- Android/iOS показывают симметричные предупреждения для `allow_ipv4_leak` и
  `allow_ipv6_leak`; Android больше не изображает `allow_lan` как исключение в split-tunnel.
  Проверка обновлений запускается только через полный туннель без утечки любого семейства и
  без исключённых маршрутов и LAN-bypass; Android дополнительно отвергает `apps_mode=include`,
  где пакет самого VPN намеренно не захватывается. Решение берётся из неизменяемого live-снимка
  реально запущенного туннеля, поэтому редактирование профиля во время соединения не может
  ошибочно разрешить сетевой запрос обновления по физическому интерфейсу или изменить показания
  карточки свойств до reconnect. Если reconnect отменил незавершённый Android/iOS-запрос,
  следующая приватная генерация повторяет проверку; generation-id не позволяет старой iOS-задаче
  затереть состояние новой, а завершившаяся HTTP-ошибка не создаёт цикл запросов.
- Повторное использование desktop-TUN теперь переносит весь согласованный план: macOS заново
  назначает обе семьи и использует неизменяемый снимок route-файла, а Windows обновляет вместе
  с маршрутами также `allow_ipv4_leak`/`allow_ipv6_leak` и per-app process map в сохранённом
  WinDivert-адаптере. Исправлена и инициализация single-stack WinDivert: отсутствующий адрес
  второго семейства больше не считается адресом неверного семейства.
  Неподдерживаемая комбинация `forward=true` с per-app routing отклоняется при валидации вместо
  молчаливо неработающего forwarding. При неудачном TCP/UDP upgrade IPv4 → dual сервер удаляет
  восстановленную allocator-транзакцией, но уже не принадлежащую сессии аренду. Android отменяет
  блокирующий update-запрос и разрывает HTTPS-соединение при любом выходе VPN из приватного состояния,
  а подробные экраны Android/iOS показывают все предупреждения, а не только первое.

- После объединения полной IPv6-разработки с актуальным `dev` устранены скрытые Linux-only
  ошибки сборки в DNS, gateway/exit-node cleanup, lifecycle профилей, IPv6 DNS workers,
  TUN/TAP control replies, web API пользователей и маршрутах. Сервер и все тестовые цели
  снова проходят Linux `cargo check` и `clippy -D warnings`; единое FFI-ядро проходит 451 тест.
- TCP- и UDP-аутентификация одного профиля теперь используют общую admission-транзакцию:
  лимиты, вытеснение сессий, dual-stack lease, authoritative session map и kernel iroute
  изменяются в одном порядке, а `AuthOK` отправляется до допуска следующего конкурирующего
  reconnect. При отказе освобождаются lease и старые маршруты; события connect/disconnect
  соответствуют реально принятой или вытесненной сессии.
- Усилен платформенный rollback: Linux строго удаляет IPv4/IPv6 firewall-состояние и
  восстанавливает исходные sysctl, Windows/macOS проверяют включение forwarding и возвращают
  прежнее состояние, Android считает установку pushed route по фактическим фрагментам после
  CIDR-исключений. UDP reachability снова параллельно проверяет все A/AAAA-кандидаты, а
  дубли `static_ip`/`static_ipv6` отклоняются центральной валидацией users-конфига.
- В Android после сведения веток восстановлено состояние `liveTrustedSsid`, без которого
  приложение не компилировалось и экран ожидания Trusted Wi-Fi не мог показать активную сеть.
  Desktop-команда `selftest` теперь завершается до startup recovery и не изменяет DNS/firewall
  хоста только из-за запуска CI-проверки.

- Закрыт повторный IPv6-аудит: Linux full-tunnel и missing-family fail-closed теперь
  перекрывают не только `::/1` + `8000::/1`, но и более специфичные физические
  `2000::/3`/ULA-маршруты тем же capture-набором, что Windows/macOS. Назначаемый
  `/32`/`/128` либо pool-prefix выбирается по реальному TUN/TAP клиента, а не устройства
  сервера; клиентский TAP обрабатывает ARP/NDP/RS до L3-декапсуляции, поэтому локальные
  NA/RA больше не уходят в транспорт.
- Клиентский flat-INI теперь отклоняет весь конфиг при ошибочном или пустом элементе
  `include`/`exclude`, не меняя маршрутную политику молча; документация теперь явно
  требует единый для всех клиентов CIDR-формат с `/32`/`/128` для одного хоста. Полный набор восьми примеров
  устанавливается скриптом, `.deb` и Docker и проверяется по содержимому собранного пакета.
  Quick Start `auto` безопасно выбирает IPv4, если native IPv6 есть, но нет обязательного
  IPv6 firewall; явные `dual`/`ipv6` по-прежнему отказывают fail-closed. Ручные Windows/macOS
  reachability-пробы не запускаются поверх активного туннеля и не принимают устаревший
  асинхронный результат после смены состояния.
- Реализована полная native dual-stack основа IPv6: режимы профиля `ipv4`/`dual`/`ipv6`,
  атомарные IPv4+IPv6 leases, ULA/routed IPv6/NAT66, двусемейные DNS/ACL/source guard/
  client routes, внешние IPv6 listeners и carrier, а также согласование возможностей,
  которое не позволяет старой стороне молча перейти в частично работающий IPv6. Общий
  `NetworkPlan v2` передаёт адреса, on-link prefixes, gateways, DNS и routes обеих семей;
  ABI платформенного ядра поднят до 1.11.
- Data plane теперь разбирает IPv4 и IPv6 одним строгим parser, учитывает IPv6 extension/
  fragment headers в flow hash, формирует ICMPv6 Packet Too Big и фрагментирует крупные
  зашифрованные UDP records через ограниченный `DATA_FRAG_V1`. Inner MTU отделён от
  внешнего UDP budget; фрагменты поддерживают reorder/duplicates, проходят MAC до
  выделения reassembly-state и ограничены по времени и памяти. Отдельный `data_frag`
  fuzz-target проверяет произвольный ввод, reorder, duplicates, конфликты и bounded
  reassembly в обязательном smoke- и nightly-CI.
- Linux, Android, iOS, Windows и macOS (global и per-app), OpenWrt, Keenetic/OpkgTun и TAP
  получили двусемейные адреса/маршруты/DNS и fail-closed поведение отсутствующей семьи.
  Linux kill-switch симметрично проверяет `iptables`/`ip6tables`; явные
  `allow_ipv4_leak`/`allow_ipv6_leak` остаются единственными escape hatch при реально
  доступном, но незащищённом egress.
- Мобильные IPv6-only режимы доведены до симметрии: Android создаёт fail-closed IPv4 sink,
  но сохраняет `allow_lan` и явные IPv4 `exclude` как физические обходы; iOS применяет
  `allow_lan` только к default capture полного туннеля и больше не вычитает приватные
  server-pushed маршруты из split tunnel. Android и iOS публикуют точный аутентифицированный
  tunnel gateway для диагностики, поэтому IPv6 Ping больше не направляется на адрес клиента,
  а активный UDP-профиль iOS проверяется UDP first-flight, а не TCP connect.
- Панель и Quick Start умеют `auto`/`ipv4`/`dual`/`ipv6`, генерируют отдельные RFC4193
  `/64`, проверяют native IPv6 egress и `ip6tables`, корректно переключают NAT44/NAT66 и
  не понижают сохранённый dual-профиль из-за временного исчезновения uplink. Добавлен
  запускаемый `server-ipv6.conf`; он включён в installer, `.deb`, Docker и проверки всех
  поставляемых flat-INI примеров.
- IPv6-only профиль больше не зависит от фиктивно корректных IPv4 shadow-полей:
  `tun.address`, `pool.cidr` и `dns.listen` не разбираются и не участвуют в allocator/runtime.
  NAT44 теперь явно запрещён для этого режима, а Quick Start отключает также IPv4-only
  `forward_private`. Host preflight и карта socket-конфликтов тоже игнорируют неактивную
  IPv4-тень, не пропуская при этом реальные IPv6 collision-проверки. Installer принимает
  IPv6 literal, правильно заключает его в скобки в ссылках/URL и выбирает IPv6 wildcard
  для публичной панели.
- Сервер пушит только маршруты реально согласованных семейств и выбирает для них шлюз того
  же семейства; клиент аналогично фильтрует pushed/include routes и не добавляет
  RFC1918 `route_local` без IPv4 lease. Android `allow_lan` теперь охватывает IPv6 ULA,
  link-local и multicast как на API 33+, так и через полный route-complement на старых API;
  iOS применяет те же локальные IPv6-исключения к реальному IPv6 и защитному sink.
- Исправлен разбор не-первого IPv6-фрагмента: parser больше не принимает байты fragmentable
  payload за extension header; flow affinity теперь использует стабильный `Next Header` из
  Fragment Header, поэтому первый фрагмент с последующими extension headers и остальные
  фрагменты одного пакета не расходятся по разным очередям. Удалён неиспользуемый
  `IPV6_PER_APP` capability, который
  платформы объявляли, но контракт ядра нигде не проверял и iOS сознательно не применял.
- UDP PMTU-проба теперь выбирает IPv4/IPv6 socket option по семейству внешнего peer на
  Linux/Android, Windows и Apple-платформах. Для старого сервера без `DATA_FRAG_V1` после
  пробы снова разрешается внешняя IP-фрагментация, а внутренний IPv6 MTU не опускается ниже
  обязательных 1280; явный меньший MTU вместе с `ipv6=required` отвергается одинаково ядром
  и моделями Android/iOS/Windows/macOS. Запрос и ACK пробы теперь принимаются только в
  единственной канонической форме: `idx=0`, `count=1`, ACK без хвоста, а заявленный размер
  запроса обязан совпадать с фактически полученной датаграммой. Короткий поддельный запрос
  больше не может подтвердить несуществующий большой PMTU.
- Маршруты после `routing.exclude` теперь вычисляются точным вычитанием CIDR на всех клиентах,
  включая Android до API 33 и iOS, поэтому более специфичный исходный include/push route не
  может случайно вернуть исключённую подсеть в TUN. Для tunnel DNS сохраняется явный host-route;
  точное исключение DNS и исключение, перекрывающее шлюз TUN на уровне on-link-префикса или
  точнее, отклоняются до настройки интерфейса. Широкое LAN-исключение остаётся допустимым,
  когда более специфичный connected route гарантированно удерживает шлюз внутри TUN.
- Разрешённые server-pushed префиксы теперь проверяются по семейству (`/8` для IPv4 и `/3`
  для IPv6), поэтому валидные `2000::/3` и `fc00::/7` не отбрасываются общей IPv4-границей.
  Удалён остаток неподдерживаемого старого `custom_routes`, отсутствующего в flat-INI.
- Server lifecycle hooks получили явные `QELI_POOL_IPV4`/`QELI_POOL_IPV6` и
  `QELI_WAN_IPV4`/`QELI_WAN_IPV6`; `post_down` получает тот же снимок реально выбранных WAN,
  что и `post_up`. OpenWrt разделяет DNS-mode и список resolvers, а Keenetic OpkgTun переносит
  обе семьи и согласованный MTU без установки зацикливающего глобального default route.

### Дополнительное укрепление после 0.7.16

- Full-tunnel carrier bypass строится по полному пригодному набору A/AAAA. Windows, macOS и
  Linux закрепляют и проверяют физический gateway/interface отдельно для каждой семьи; набор
  carrier-адресов входит в `persist_tun` fingerprint. Linux применяет `local`/`lport`, проверяет
  FIB после capture и меняет первого UDP-кандидата между неудачными reconnect-поколениями.
- Применение Linux NetworkPlan стало транзакционным: частичная настройка откатывает DNS,
  созданные qeli routes, gateway/exit firewall, sysctl и принадлежащий клиенту интерфейс.
  Совмещённые gateway и exit-node больше не восстанавливают общие sysctl независимо друг от друга.
- Native adapters отклоняют противоречивый NetworkPlan до системной маршрутизации. Firewall
  DNS/NAT/NAT66/forwarding проверяется fail-closed при отсутствии инструмента, неизвестной
  политике цепочки или невозможности подтвердить установленное правило. Android и iOS применяют
  одинаковые точные LAN/multicast-исключения без чрезмерного обхода IPv6 или multicast.

## [0.7.16] — 2026-08-19

- GitHub Release `v0.7.16` подготовлен как beta/prerelease: 16 платформенных payload-файлов и
  `SHA256SUMS` публикуются только после повторной сверки всех GitHub asset digest с локальным
  кандидатом; tag, `dev` и `main` указывают на один проверенный release-коммит.

### Мобильные клиенты

- Размер QR-диалога Android теперь задаётся до первой инициализации ZXing
  (поздний resize оставлял рамку смещённой на реальных устройствах). Область декодирования
  теперь совпадает со всем видимым квадратом камеры, без дополнительной затемнённой
  70-процентной рамки; поворот устройства пересоздаёт scanner
  с корректной геометрией. На iOS квадрат камеры позиционируется относительно геометрического
  центра sheet независимо от расположенной под ним подсказки.
- Android получил такой же автоматический опрос сохранённых профилей, как Windows и macOS:
  настройка включена по умолчанию, интервал задаётся в диапазоне 10–3600 секунд (30 секунд по
  умолчанию), проверки выполняются только у видимого приложения с отключённым VPN и защищены
  от частых повторных sweep. Ручные проверки одного или всех профилей продолжают работать отдельно.
- Android и iOS получили локальную политику доверенного Wi-Fi с точным списком SSID. Android
  сохраняет foreground-контроллер без TUN и восстанавливает выбранный профиль после выхода из
  сети; Disconnect, смена сети во время teardown и process restart не теряют пользовательский
  intent. Lockdown/`kill_switch` всегда сильнее доверенного SSID и запрещает снимать TUN, а на
  Android 9–11 события вторичных carrier-сетей больше не управляют этой политикой. iOS использует
  упорядоченные On Demand Disconnect/Connect rules и показывает нейтральное ожидание сетевой
  политики, поскольку NetworkExtension не раскрывает приложению, какое правило совпало.
- Выключение Android-автоопроса теперь отменяет не только таймер, но и уже запущенные
  автоматические проверки. Одиночный автоопрос не выходит напрямую в сеть во время Trusted Wi-Fi
  pause; TCP probe закрывает сокет также при timeout/ошибке, а отмена UDP probe доходит через JNI
  до конкретного Rust future и закрывает native socket. Гонка «отмена до регистрации» закрыта
  ограниченным реестром ранних/завершённых `probe_id`, а shutdown локального runtime ограничен,
  чтобы отмена не ждала оставшийся системный DNS-worker. До обязательной финальной пересборки
  19-export ядра Android автоматически использует присутствующий в 17-export baseline старый
  bounded UDP probe, поэтому UDP-профили не помечаются недоступными из-за отсутствующего JNI
  символа; после пересборки включается cancellable-путь. Ручной опрос остаётся независимым.
- Android Always-on проходит через тот же Trusted Wi-Fi gate, что запуск из приложения, tile и
  widget. Если системный NetworkCallback зарегистрировать невозможно, сервис не остаётся в
  вечном observer-less ожидании: он fail-safe поднимает VPN; принудительное восстановление
  запускает reconnect-loop даже при временном отсутствии сети, поскольку ждать следующего
  callback в этом состоянии уже некому. iOS сериализует полные
  mutate/save/load транзакции NetworkExtension FIFO-гейтом, а синхронная ревизия UI-настройки
  гарантирует, что быстро созданная старая Task не перезапишет более новый On Demand policy.
- Активная проверка UDP-профиля на iOS теперь всегда использует нативный UDP first flight, в том
  числе через tunnel gateway при уже поднятом VPN; UDP-only listener больше не проверяется ложным
  TCP connect. Android и iOS ограничивают одновременно выполняемые ручные и автоматические
  проверки четырьмя слотами, поэтому большой список профилей не создаёт burst из DNS-запросов
  и сокетов; повторный запрос уже активного iOS-профиля не ставится в очередь второй раз.
- Android и iOS читают импортируемые профили и backup вне UI thread с жёсткими пределами размера.
  До замены или сохранения проверяются число профилей, active index, уникальность iOS UUID,
  размеры имён/конфигов и полная валидность каждого INI. Android предварительно кодирует весь
  prospective-набор до изменения живого списка, поэтому превышение общего лимита не оставляет
  несохранённое состояние и не затирает старое хранилище при следующем запуске. Encrypted backup
  допускает отдельный 12-МиБ envelope, необходимый для base64-представления валидного 8-МиБ JSON.

### Сон, roaming и восстановление соединения

- Намеренный reconnect после сна или смены физической сети больше не считается неудачной
  попыткой и не увеличивает backoff `1→2→4→…→32` секунд. Исправление действует в общем Rust-ядре,
  Linux CLI, Android, iOS, Windows и macOS.
- Android больше не перезапускает исправный туннель при обычном screen-off: reconnect выполняется
  только при фактическом изменении сигнатуры физической сети либо по RX-liveness watchdog.
  Та же проверка физического пути применяется desktop-клиентами после resume.
- Устаревший platform ACK от уже остановленной generation считается нормальным исходом гонки.
  Ошибка обработки одного Android/iOS event больше не завершает единственный dispatcher и не
  превращает все последующие подключения в постоянный `PLATFORM_REJECTED`.
- Во время handover Android перечисляет доступные carrier-сети и предпочитает валидированную,
  если `currentNetwork` ещё пуст, а `activeNetwork` уже указывает на собственный VPN. Базовая
  сигнатура сети обновляется только после реального reconnect, поэтому событие не теряется.
- Физический DNS Android переведён на ограниченный пул из двух запросов, ключованных по
  `networkHandle:server`: зависший resolver старой сети не блокирует новую, а серия network flap
  не создаёт неограниченное число потоков и заданий.
- Терминальная ошибка фонового transport runner гарантированно вытесняет заполненную очередь
  событий; поздний ACK не может оживить уже упавшую generation. Конфигурация ядра с однослотовой
  очередью отклоняется заранее, потому что она не вмещает атомарную публикацию lifecycle и plan.

### MTU, packet path и диагностика потерь

- Downlink-пулы Android, iOS, Windows packet path и общего ядра рассчитывают размер слота из
  согласованного MTU плюс запас на padding/normalization, а не резервируют 64 КиБ под каждый
  пакет около 1,3 КиБ. Число слотов согласовано с принимающей очередью; превышающий резерв record
  увеличивает свой буфер и не отбрасывается только из-за размера начального слота.
- Общий `internal_drops` разложен в Linux CLI diagnostics на `pool_exhausted`, `queue_full`,
  `oversize`, `unsupported` и `tun_write`. Отказы TUN writer с `EAGAIN`/`ENOBUFS`, ранее не
  попадавшие ни в один счётчик, теперь учитываются отдельно.
- Ошибка `dup()` очереди TUN и частичная запись IP-пакета больше не маскируются как успешная
  передача: writer останавливается с диагностируемой ошибкой вместо отправки усечённого пакета.
- UDP reachability резолвит до 16 различных IPv4 A-записей и проверяет их параллельно в одном
  ограниченном временном окне; недоступный первый адрес DNS больше не делает рабочий профиль
  красным. IPv4 path-MTU ladder опускается до поддерживаемого inner MTU 576, тогда как IPv6
  сохраняет обязательный floor 1280 с учётом внешнего overhead.
- Windows IPv4 fragmentation сохраняет IP options только на тех фрагментах, где установлен copy
  bit, пересчитывает IHL/checksum для сокращённого заголовка и отклоняет malformed options,
  невыравненный non-final fragment и переполнение 13-битного fragment offset.
- Windows per-app NAT больше не пересчитывает TCP/UDP checksum первого входного фрагмента как
  будто отсутствующий хвост payload имеет нулевую длину. Адреса и порты корректируются по RFC 1624,
  IPv4 header checksum считается отдельно, нулевой UDP checksum остаётся отключённым; усечённый
  первый transport header и частичный фрагментированный ICMP error отклоняются fail-closed.
- Windows и macOS per-app теперь соблюдают `gateway = false`: выбранные приложения направляют в
  туннель только явные/pushed routes и связанную туннельную подсеть, остальные публичные IPv4 и
  нативный IPv6 идут напрямую. Явно включённый IPv6-префикс остаётся захваченным fail-closed до
  появления IPv6 inner data plane; Android split-tunnel также явно разрешает остальной IPv6.

### Клиентский lifecycle, DNS, маршруты и kill switch

- Linux/OpenWrt DNS использует приватные per-interface ownership-маркеры до изменения
  systemd-resolved. Неудачный `resolvectl revert` оставляет маркер для повторной очистки;
  recovery не трогает живой интерфейс другого клиента и восстанавливает legacy `resolv.conf`
  только после выхода последнего подтверждённого владельца.
- Настройка gateway NAT и exit node теперь отказывается продолжать работу, если нельзя включить
  `net.ipv4.ip_forward`; частично созданные sysctl/firewall-правила откатываются, а ошибки отката
  возвращаются вызывающему коду. `exit_node = true` несовместим с `gateway = true`, потому что
  самому exit node нужен физический default route.
- Linux kill switch получил отдельные цепочки на экземпляр, строгую проверку наличия/ошибки
  инспекции, откат частично установленного ruleset и удаление legacy-цепочки. Перед reconnect
  разрешения серверных IP обновляются без временного снятия финального DROP; при teardown kill
  switch снимается последним, после TUN/NAT/forwarding.
- Журнал владения маршрутами больше не забывает запись после неудачного удаления: cleanup можно
  повторить. Отсутствующий уже удалённый маршрут остаётся идемпотентным успехом, а ошибки очистки
  TUN-маршрутов, интерфейса и bypass-маршрутов возвращаются раздельно.
- Сервер и Linux-клиент не удаляют и не присоединяются к заранее существующему TUN без доказанного
  владения. Совпадающие имена TUN между профилями, включая отключённые, обнаруживаются до
  `TUNSETIFF`, чтобы разные generation не разделили multi-queue устройство.
- Идентификатор устройства и identity/TOFU-ключи создаются под межпроцессной блокировкой:
  конкурентный первый запуск публикует одно устойчивое значение. Ошибка сохранения device ID
  видна в логе, а повреждённый или заблокированный known-hosts store не заменяется молча.
- Результат `auth.password_command` теперь проверяется по exit status, а размер фактического
  credential проверяется и для `password_file`/`password_command`, а не только для inline password.
  Пароль обёрнут в zeroizing storage; `ClientConfig::drop` очищает password, command и obfs key во
  всех клонах конфигурации после reconnect/bonding.

### Windows и macOS

- macOS GUI снова устанавливает и останавливает launchd-демон через системный диалог
  администратора: root-helper очищает унаследованную от `security_authtrampoline` маску сигналов,
  поэтому завершившиеся `launchctl`, `networksetup`, `route`, `ifconfig` и `pfctl` больше не
  превращаются в ложные 20/30-секундные timeout. Полный сброс ограничен macOS root-helper,
  запущенным GUI с `QELI_INVOKING_UID` и одним из `daemon-install`/`daemon-uninstall`/
  `daemon-start`/`daemon-stop`; обычные GUI, launchd service и CLI сохраняют маску родителя.
- Desktop `Start()` больше не публикует промежуточный `Disconnected` во время внутреннего
  generation handoff. Windows и macOS сохраняют активный профиль только после успешного старта,
  считают живой reconnect-loop работающим даже в статусе Error и не удаляют/не заменяют профиль
  при незавершённом teardown. macOS также не проглатывает ошибку Disconnect, повторно принимает
  SIGINT/SIGTERM после неудачной очистки и безопасно запускает `uishot` без synthetic
  `SelectionChangedEventArgs`.
- `persist_tun` на Windows и macOS больше не считает один неизменившийся client IP достаточным для
  повторного использования старого TUN. Сохраняется канонический fingerprint реально применённого
  сетевого состояния: IP/prefix, эффективные MTU и упорядоченный DNS, NetworkPlan routes,
  include/exclude и snapshot `route_file`, carrier path и platform policy. Wintun/utun повторно
  используются только при полном совпадении; любое изменение пересобирает адрес, маршруты, DNS и
  MTU до положительного NetworkPlan ACK. Self-test покрывает изменение каждого поля, перестановку
  эквивалентных маршрутов и исключение transport-only параметров из fingerprint.
- Изменившийся системный NetworkPlan/физический carrier пересобирается под временным firewall
  guard даже тогда, когда пользовательский kill switch выключен; guard снимается только после
  `Running`, а ошибка восстановления остаётся fail-closed. WinDivert и macOS per-app вместо
  разрушения retained TUN атомарно заменяют classifier/address/MTU/routes/DNS под состоянием
  tunnel-down; macOS до нового dial снимает старый carrier pin, чтобы исчезнувший gateway не
  блокировал повторную аутентификацию. Guard не включается на первом TUN/per-app старте.
  Диагностические gateway/metric, которые platform adapter не применяет, больше не вызывают
  ложную пересборку.
- После терминальной desktop-ошибки Windows и macOS повторно рендерят состояние уже после фактического
  завершения run task: кнопка меняется с неработающего `Disconnect` на `Connect`, снимается stale
  active-profile lock и возобновляется reachability polling.
- Новый desktop tunnel не стартует, пока предыдущая task не освободила общее состояние;
  восьмисекундный таймаут остаётся ошибкой, а не разрешением повторно использовать TUN/socket.
  Ошибки старта, DNS, route, firewall и teardown доходят до службы и UI вместо ложного статуса
  `Disconnected`.
- C#-обвязка проверяет непустой `NetworkPlan`, совпадение generation, поддерживаемость DNS endpoint
  платформенным adapter и наличие заявленного native TUN/Wintun/packet descriptor. Некорректный
  plan отклоняется до изменения сетевого состояния.
- macOS kill switch перенесён в собственный PF anchor и больше не заменяет глобальный ruleset.
  Он различает живого владельца и след от crash, сериализует PF-операции, откатывает частичное
  включение и разрешает UDP/TCP 53 только к системным resolver, а не `to any`.
- Windows native extraction при elevated-запуске использует каталог с ACL только для
  Administrators и SYSTEM, не наследуя запись от пользовательского родителя. Службы Windows и
  macOS отказываются запускать новую generation, если recovery прежнего kill switch не доказан.
- Desktop-редактор сохраняет все поддерживаемые, но не показанные в форме INI-поля и маркеры
  неизвестных/ошибочных ключей. Маркер снимается только с поля, реально исправленного формой;
  устранённая duplicate-key неоднозначность не переносится. Переданный, но некорректный pinned key
  теперь вызывает ошибку и не превращается молча в незакреплённый TOFU.
- Desktop network debounce больше не поглощает реальную вторую смену carrier сразу после
  принудительного reconnect; сохранённая сигнатура обновляется только согласованным состоянием.
  macOS per-app сериализует полные policy replace и guardian heartbeat межпроцессным `flock`,
  поэтому heartbeat не возвращает старую политику. Ошибка update оставляет уже установленное
  расширение и guardian в tunnel-down fail-closed состоянии вместо отключения фильтра.

### Сервер, панель и конфигурация

- Все дочерние задачи profile generation закрываются для новых работ, abort/join выполняется до
  удаления TUN, NAT и реестровой записи. Старый supervisor не может удалить уже зарегистрированную
  replacement-generation с тем же именем; teardown-тест синхронизирован по фактическому Drop.
- Control socket связывается и защищается до старта data plane. Ошибка bind/accept либо исчезновение
  control task теперь фатальны для worker, а дочерние client-tunnel процессы получают timeout,
  kill и обязательный reap вместо потери process handle или zombie.
- Серверная identity создаётся атомарно и конкурентно безопасно без изменения прав произвольного
  пользовательского parent-каталога. REALITY-профиль с `target_port = 0` отклоняется как заведомо
  недостижимый decoy endpoint.
- Usage accounting загружается fail-closed: повреждённый файл не превращается в пустые квоты и не
  перезаписывается. Reload сохраняет последний корректный диагностический снимок, reset и flush
  сериализованы, а неудачная запись откатывает изменение счётчика в памяти.
- Аутентифицированный Logout панели повышает сохранённую session generation и отзывает все
  выданные сессии. Ошибка долговременной записи возвращается оператору и не выдаётся за успешный
  logout. Создание session key сериализовано между процессами, файл имеет режим `0600`,
  повреждённый ключ не перезаписывается, а нечитаемая generation не откатывает проверку к
  разрешающему значению `0`.
- `allowed_networks` пользователей и групп проверяется одинаково для panel, inline, file-based и
  restored config. Ошибочный CIDR отклоняет базу; runtime fallback для явно заданного, но полностью
  невалидного списка остаётся deny-all. Метрика пользовательского route обязана быть целым `u32`.
- Изменения пользователя строятся и валидируются на клоне до публикации: невалидный route/ACL или
  конкурентное удаление не оставляет частично изменённые secrets и поля в памяти.
- Preflight распознаёт `blackhole`, `unreachable`, `prohibit` и другие typed routes и не позволяет
  отключённому профилю скрыть конфликт с физическим интерфейсом или маршрутом.
- Backup/restore принимает active config только по нормальному пути внутри `/etc/qeli`, требует и
  валидирует указанный `users_file`, отклоняет неизвестное содержимое `.conf`, небезопасные hook,
  symlink и расхождение типов staged/live. Exact restore не заявляет успех, если в live-дереве
  останутся отсутствующие в архиве вложенные файлы; вся проверка выполняется до публикации.
- Quick Start проверяет коллизию по фактическим сохранённым bind port и transport существующего
  профиля, а не по текущим значениям карточки. Повторный запуск того же режима разрешён; конфликт
  с другим профилем требует сначала сменить его bind.
- IPv4-only data plane отклоняет IPv6 DNS resolver в client config и server push с явным
  сообщением и текущей версией. Установочный скрипт аналогично не принимает IPv6 literal в
  `PUBLIC_HOST`, вместо генерации заведомо неработоспособного клиентского endpoint.
- Rust round-trip fixture клиента теперь обязательно содержит `server` и `dns_servers`, а
  автоматический тест сверяет fixture со всеми runtime-ключами, чтобы новый параметр нельзя было
  добавить в parser и забыть в проверке сохранения.
- `qeli check-config` теперь загружает внешний `users_file` тем же строгим `UsersDb`, что worker:
  повреждённый INI, нечитаемые лимиты, ACL и неизвестные ключи больше не получают `OK` перед
  отказом worker; отсутствующий файл допустим только при наличии inline users/groups, ровно как
  при реальном запуске supervisor. Инсталлятор проверяет окончательный server.conf вместе с
  users.conf после всех `add-client`/web-изменений и до рестарта существующего сервиса.
- Команды `install-polkit` и `set-service-user` проверяют systemd unit и service user до вставки в
  путь или правило, пишут drop-in/rule атомарно с явными правами и проверяют результат `chmod`,
  `chown` и `systemctl daemon-reload`. При возврате с root на пользователя qeli владение
  `/etc/qeli` исправляется до удаления рабочего root override.
- Форма исходящих клиентских профилей в панели теперь редактирует `include`, `exclude` и
  `lan_subnet_ipv6`, сохраняет их при переключении Field/Raw и передаёт в Rust-сериализатор;
  статический gate и round-trip тест не дают снова потерять маршрутную политику при сохранении
  профиля.
- Панель показывает hostname текущего сервера рядом с версией, а подписи UDP-метрик явно различают
  размер очереди и заполнение сокетного буфера. Наличие административного доступа теперь
  проверяется реальным `pkcheck`, без чтения системных polkit rules, которые обычно недоступны
  непривилегированному пользователю; отсутствие helper или неоднозначный результат не выдаются за
  подтверждённый запрет.
- Удаление client-профиля в панели сначала обязано успешно остановить процесс и удалить основной
  файл; ошибки удаления log/status возвращаются отдельным warning. Ошибка сериализации notification
  config или создания каталога web TLS certificate больше не превращается в пустой/частичный файл
  либо молча продолженный запуск.

### Фрейминг, инкапсуляция и wire-совместимость

- FFI отклоняет `(null, positive_length)` и принимает нулевой указатель только вместе с нулевой
  длиной. EOF посередине TLS record считается `UnexpectedEof`, а не чистым завершением потока.
- Rust, C# и Swift packet decoder требуют, чтобы переданный AEAD record целиком и точно совпадал
  с объявленной длиной. Аутентифицированный корректный префикс с неаутентифицированным хвостом
  отклоняется; in-place буфер при любой ошибке очищается.
- UDP handshake проверяет каждый length-prefixed record, переполнение и полную доступность тела до
  дорогого PQ/TLS key schedule. Усечённый `ChangeCipherSpec`, Certificate, Finished либо
  NewSessionTicket больше не продвигает offset за границы datagram.
- TCP/sans-IO handshake также требует корректный `ChangeCipherSpec` и `NewSessionTicket` вместо
  проглатывания ошибки чтения. Ошибки генерации certificate, настройки TLS 1.3 и session ticketer
  возвращаются из REALITY setup вместо panic; IPv6 decoy target форматируется через общий
  host/port helper.
- Новый QUIC-masking envelope всегда отправляет строгий qeli Initial `0xC3`; parser временно
  принимает только точную legacy-форму `0xE3` для rolling upgrade. Проверяются QUIC v1, DCID ровно
  4 байта, нулевые SCID и Token Length, четырёхбайтовый packet number, корректный varint Length и
  полное потребление datagram. Short header принимает только ожидаемый qeli flags `0x43`.
- Сервер включает QUIC-режим только после полного структурного разбора первого datagram, а не по
  короткому magic-prefix. Переполненные/усечённые varint и лишний хвост отклоняются одинаково в
  Rust, C# и Swift.
- Межъязыковые fixtures packet decode, QUIC, UDP fragmentation, replay window, PRP nonce и HKDF
  генерируются Rust-каноном и явно перечисляют реальные независимые consumers: Rust, retained C#
  и Swift; Kotlin оставлен только для формата qeli-link. Документация больше не называет masking
  полноценным QUIC: Initial AEAD, header protection, CRYPTO frame и padding до 1200 байт не
  реализованы.

### Сборка, release gate и гигиена

- Символ `DELIBERATE_CYCLE` доступен на всех target, а не только Linux; это устранило ошибку E0425
  при сборке Android core. После исправления Android `.so` были воспроизводимо пересобраны и
  разложены, экспортируемые JNI/client ABI не изменились.
- Rust build восстановлен после hardening-рефакторинга, код приведён к `rustfmt`, оставшиеся Clippy
  warnings устранены. Тест teardown raw descriptor выполняется последовательно и ждёт фактического
  освобождения ресурса, исключая ложное падение из-за повторного номера fd.
- Keenetic scripts вычисляют пути от собственного checkout, а не из захардкоженного каталога
  разработчика. Native recipe gate проверяет это и ненулевые exit code helpers.
- Config/multiprofile/installer E2E также вычисляют checkout и текущую версию из manifest,
  принимают lab/tool paths через окружение, валидируют все `qeli/config/*.conf` строгими
  server/client-командами, завершаются ненулевым кодом при любом красном сценарии, запускают
  supervisor в отдельной session и завершают всю его process group с TERM/KILL bound, не оставляя
  `_worker`. PID считается принадлежащим тесту только при совпадении `/proc/<pid>/exe` и PGID,
  поэтому stale/подложенный `/tmp`-файл не может послать групповой сигнал чужому процессу;
  в `finally` восстанавливаются только ранее активные systemd units.
  Management-route override Linux matrix больше не смешивается с захардкоженным prefix при
  проверке/очистке, учитывает IPv4/IPv6 family и передаётся удалённой shell только после
  parse+quoting. Android E2E разрешает путь `adb` на удалённом lab-хосте, а не на машине запуска.
- Все активные Python-рецепты сборки, диагностики и A/B-проверок вычисляют checkout от `__file__`;
  каталоги артефактов и внешние tool paths задаются переменными окружения. Тест сканирует весь
  `scripts/*.py`, чтобы локальный `C:\Users\…` снова не попал в release automation.
- Однохостовые `finish_deploy.py`, `setup_reality_tls.py`, `gen_share_link.py` и
  `gen_reality_link.py`, которые перезаписывали live-конфиг и создавали пользователей с фиксированным
  примером пароля, выведены из эксплуатации до любого SSH/import. Поддерживаемые пути —
  `install-qeli-server.sh`, Quick Start панели и явная команда `qeli add-client --link`.
- Серверный installer выбирает `.deb` по `dpkg --print-architecture`, проверяет поле
  `Architecture` даже у явно переданного файла/URL и fail-closed отклоняет несовместимый пакет.
  Временные `.deb` и `SHA256SUMS` основного download-пути зарегистрированы в общем cleanup-trap.
- Удалены три временных round-trip snippet/fixture из `release/`, которые могли быть ошибочно
  приняты за входы финальной сборки.
- Исходники `0.7.16` синхронизированы для Rust, Android, iOS, Windows, macOS, macOS per-app,
  OpenWrt/LuCI и Debian; Android/iOS build number — `719`, macOS per-app — `716`.
- `sync_version.py` теперь проверяет marketing/build version подписанного macOS per-app extension,
  а сообщения об ограничении IPv4/DNS используют `CARGO_PKG_VERSION` вместо захардкоженного номера
  предыдущего релиза.
- Обновлён dependency baseline: все Avalonia-пакеты macOS синхронизированы на `11.3.20` с
  исправлением `NSTextInputClient`; Windows service hosting/controller — на `.NET 10.0.11`;
  Android — на stable AppCompat `1.8.0` и Gradle wrapper `9.7.0`; wrapper-validation action — на
  подписанный `v6.3.0`. Rust lockfile получил patch-релизы `rcgen 0.14.9`, `serde_json 1.0.151`,
  `socket2 0.6.5`, `clap 4.6.6` и `thiserror 2.0.20`. Поскольку `Cargo.lock` входит в source digest,
  native cores повторно собраны из clean commit `b1e220d` независимыми A/B-проходами на лабах
  `.10`/`.11`; canonical/consumed copies, hashes, evidence и provenance согласованы с digest
  `85d7163bd1f2632077070cd3706ceb49993cc13b21671353ab225161aef4e7e7`.
- Android release sync теперь передаёт на лабу не только Gradle properties, но и pinned wrapper
  JAR, `gradlew` и `gradlew.bat`; после однократного заполнения нового кэша Gradle `9.7.0`
  финальный подписанный APK собран повторно с `clean` и полностью в offline-режиме.
- Lab-helper `fmt_clippy.py push` теперь создаёт отсутствующие удалённые каталоги и синхронизирует
  полный Git-tracked набор Rust build inputs, включая `Cargo.lock`, web templates/fonts, config,
  conformance и `deny.toml`: Clippy/tests больше не зависят от неполного или старого дерева на лабе.
- Транзитивная зависимость `h2` обновлена с `0.4.15` до `0.4.16`, устраняя
  `RUSTSEC-2026-0258` (неограниченный поток пустых HTTP/2 DATA frames); финальный dependency graph
  повторно проходит `cargo audit` без уязвимостей.
- Предыдущий first-party native baseline был пересобран 2026-08-19 из clean source commit `0bbd9a0`
  (source digest `32836c68a6335f7aeb0f42fbc1aa3f3dedc924516fce1dff6167ab78a1811dd7`) двумя
  независимыми A/B-проходами: Windows x64, macOS universal2 и Android arm64-v8a/x86_64 побайтно
  воспроизводимы. Canonical библиотеки, `SHA256SUMS`, reproducibility evidence и `PROVENANCE`
  обновлены в commit `938b9e8`; desktop ABI содержит 6 Reality + 20 client exports, Android —
  те же exports и 19 JNI symbols.
- Регрессионный тест короткой записи учитывает новый строгий контроль полной длины кадра:
  заведомо некорректный UDP datagram безопасно отклоняется как `PacketTooShort` либо более ранний
  `FrameLengthMismatch`; прежнее устаревшее ожидание одного варианта больше не ломает release gate.
- OpenWrt feed закреплён на исходном baseline-коммите `b1e220d`; SDK 23.05.5 сформировал canonical
  `qeli-0.7.16.tar.xz` с SHA-256
  `16d31f7cedadf9aac870d8c398845f242c0a4847ccc4239de7ec114b99084c32`, и повторный
  `package/qeli/download` успешно проверил этот mirror hash.
- Production e2e-скрипты больше не закреплены на путях, временных именах и ожидаемой версии
  `0.7.15`: номер читается из `qeli/Cargo.toml`, поэтому evidence каждого будущего кандидата
  попадает в собственный `release/dist/v<version>/evidence`, а Linux matrix проверяет именно
  собираемую версию бинарника.
- Финальный кандидат `release/dist/v0.7.16` полностью пересобран после Rust/native
  baseline `b1e220d` и platform-изменений по `24e71f7` тем же набором, что 0.7.15: 16
  payload-файлов для Debian/Linux, Android, Windows, macOS, OpenWrt и
  Keenetic плюс `SHA256SUMS`. Прошли Rust/Debian gate (635 library + 8 CLI/config tests),
  подписанная Android Release-сборка, Windows self-test/packetbench, universal macOS packaging,
  четыре OpenWrt и две Keenetic architecture, GitHub CI и полный release preflight; соответствующие
  OpenWrt/Keenetic aarch64 и mipsel бинарники побайтно совпали.
- В `release/` сохранены датированные сырые результаты all-mode benchmark и отдельной серии из
  пяти Reality-TLS прогонов для бинарника `0.7.16` от 2026-08-16. Они привязаны к собственному
  hash/version marker и считаются историческим evidence: последующие Trusted Wi-Fi, polling,
  desktop lifecycle и `persist_tun` изменения требуют новой сборки и повторного performance gate.
- Production all-modes/Android roaming lifecycle e2e не запускался автоматически: он временно
  меняет production profiles и перезапускает сервис, поэтому требует отдельно согласованного окна.

## [0.7.15] — 2026-08-13

- Rust release tests в GitHub CI и лабораторном gate теперь выполняются одним потоком test harness.
  Параллельный запуск позволял соседнему тесту мгновенно переиспользовать уже закрытый Unix fd и
  давал ложное падение проверки teardown по одному raw descriptor number; production-код и
  релизные бинарники этой правкой не изменены.
- Подготовлено и использовано единое двуязычное описание GitHub Release `0.7.15`: сначала английская, затем
  русская версия с обязательными действиями перед обновлением, ключевыми изменениями общего
  Rust transport core, per-app routing, lifecycle/DNS, панели и безопасности, результатами
  release gate и точной таблицей 16 локально собранных артефактов. Файл
  `release/RELEASE_NOTES_0.7.15.md` передан в `gh release --notes-file`; все payload-файлы и
  `SHA256SUMS` проверены локально и повторно сверены по GitHub SHA-256 перед публикацией.
- DNS lifecycle и серверный TUN read path приведены к каноническому `rustfmt`, поэтому
  полный release gate снова проходит форматирование без изменения исполняемой логики.
- Тестовая строка-маркер legacy DNS recovery теперь компилируется только вместе с тестами.
  Это убирает предупреждение release-сборки после перехода Linux/OpenWrt на lifecycle-safe DNS,
  не меняя поведение рабочего бинарника.
- Настройки Windows и macOS переработаны в изменяемое по размеру окно с вкладками «Основное»,
  «Подключение», «Автозапуск» и «Фоновый режим»: содержимое прокручивается, кнопки действий
  остаются видимыми, а высота ограничивается рабочей областью текущего экрана. Редактор
  профиля теперь также ограничен экраном и собран в одну прокручиваемую страницу с логическими
  секциями. Неочевидная кнопка `<>` заменена явной **«Редактировать INI»**. В форму добавлены
  таймаут, политика реконнекта, persist-TUN, режим DNS, MTU-probe и kill switch; `MTU = 0`
  показан как документированный автоматический режим, а новый профиль по умолчанию принимает
  аутентифицированный DNS-push сервера. README и CLI больше не называют JSON форматом профиля.

- macOS больше не подтверждает Disconnect, пока исходный DNS физической сетевой службы не
  восстановлен: ошибки `networksetup` повторяются и поднимаются до UI/службы, а recovery-журнал
  сохраняется до успешного отката. Состояние подключения launchd теперь хранится отдельно от
  установки демона, поэтому ручной Disconnect переживает перезагрузку. Удаление/перемещение
  работающего `Qeli.app` обнаруживается демоном, который отключает туннель и возвращает DNS до
  завершения процесса; uninstall ждёт реального `bootout` и проверяет DNS перед удалением plist.
  Per-app Network Extension теперь получает короткую lease от отдельного guardian-процесса:
  после crash, power loss или удаления app устаревшие DNS/transparent proxy автоматически
  переходят в fail-open и больше не привязывают запросы к исчезнувшему utun.
- Windows-служба, как и macOS daemon, отделяет автостарт процесса от сохранённого желания
  подключаться: ручной Disconnect переживает reboot, а удаление исполняемого файла заставляет
  службу очистить туннель. Сброс DNS временного Wintun выполняется до закрытия адаптера,
  повторяется и больше не маскирует незавершённый teardown как `Disconnected`.
- Linux/OpenWrt больше не устанавливает туннельный DNS прямой постоянной записью в
  `/etc/resolv.conf`: новые подключения используют только lifecycle-safe per-link API
  systemd-resolved, а при другом владельце DNS требуют `dns = off`. Recovery старых снимков
  сохранён, поэтому обновление сначала чинит следы предыдущих версий.

- macOS GUI теперь перехватывает `SIGINT`/`SIGTERM` (включая `Ctrl+C` при запуске через
  `sudo`), отменяет немедленное завершение процесса и выполняет штатный `VpnTunnel.Stop()`.
  Поэтому сохранённые маршруты и DNS физического сервиса, установленные через `networksetup`,
  восстанавливаются до выхода; повторные сигналы не запускают teardown параллельно.
- Сервер теперь сам устанавливает узкие `iptables INPUT`-разрешения UDP/TCP для DNS каждого
  профиля: точные TUN, client pool, адрес и порт resolver. При `INPUT DROP` неудача
  применения правила теперь останавливает профиль вместо выдачи клиенту недоступного DNS.
  Правила маркируются профилем и удаляются при restart/teardown. Это исправляет обнаруженный
  на проде разрыв между новыми пулами `10.9.7.0/24`–`10.9.9.0/24` и устаревшим host firewall.
- Android больше не сообщает ложное `Disconnected`, пока native transport ещё владеет
  дубликатами TUN fd: отмена теперь прерывает DNS/connect/handshake, аварийный `Drop` ждёт
  завершения обоих TUN worker, а сервис публикует отдельное состояние `Disconnecting` и
  разрешает следующий Connect только после полного освобождения маршрутов и DNS. Это закрывает
  поломку DNS устройства и неработающий второй connect после ручного Disconnect.
- IPv4-only data plane отбрасывает захваченные Android IPv6-пробы на клиенте до шифрования,
  поэтому они больше не создают сотни ложных `forged source` на сервере и не занимают очередь
  полезного трафика. Серверный source-guard теперь пишет в debug-лог фактически заявленный
  IPv4/IPv6 source либо `<malformed>`, что отделяет системные IPv6-пробы от подмены IPv4.

### Дополнительное укрепление перед релизом

- Зафиксирован чистый лабораторный benchmark-кандидат `0.7.15`: 604 Rust-теста прошли,
  все TCP-режимы подключились без потерь ping и session drops, а UDP во всех режимах был
  без потерь до 400 Мбит/с. В репозиторий добавлены исходные JSON-результаты, отдельный
  прогон QUIC 100–1000 Мбит/с и сравнительный отчёт с `0.7.14`; отчёт также явно сохраняет
  обнаруженные риски — выброс padding при 500 Мбит/с и увеличившийся RSS — для проверки
  перед публикацией, а не скрывает их итоговой сводкой.
- Конфигурационные операции панели получили единый транзакционный контур. Form/JSON/Raw
  редакторы передают SHA-256-ревизию точного INI и отказываются затирать более новую
  правку из другой вкладки или с SSH; непосредственно перед rename файл проверяется ещё
  раз. Перед каждой изменяющей записью создаётся приватный снимок, хранятся десять
  последних, а History позволяет провалидировать и восстановить их с сохранением текущего
  состояния как обратного снимка. Переход между raw/structured и уход со страницы защищены
  от потери несохранённых правок, перед записью показывается список изменённых путей/строк.
  Quick Start теперь выполняет build + validate + snapshot + write одной серверной операцией,
  поэтому больше нет окна last-writer-wins между отдельными GET/PUT.
- Добавлена страница **Transport Health**: по каждому входящему профилю она объединяет
  фактические сессии/потоки/трафик/drop-счётчики с безопасной проекцией bind, TUN/MTU,
  маршрутов, DNS, masking, multipath, буферов и лимитов и выводит операционные предупреждения.
  Исходящий Linux-клиент публикует приватный структурированный status-sidecar с состоянием,
  retry, согласованным `NetworkPlan` и TX/RX/UDP-счётчиками; вкладка Client показывает его
  через Details и использует лог-парсер только как fallback для старого процесса. Ключи,
  пароли и session material в диагностический контракт не попадают.
- Transport Health получил однозначные подписи сводных показателей и пояснения направлений
  трафика. Локализация теперь загружается до первой оценки Alpine, поэтому подписи не остаются
  пустыми. Подробности профиля открываются в отдельной правой панели (на мобильном — в нижнем
  листе), не растягивая всю строку карточек в CSS Grid.
- Windows, macOS, Android и iOS снова пишут в журнал имя пользователя и endpoint при начале
  подключения и подтверждают пользователя после AUTH. В настройки всех приложений добавлен
  режим журнала **Краткий / Подробная диагностика**. Периодическая UDP-телеметрия больше не
  выводится при каждом изменении счётчика: размер буфера сообщается один раз, его рост — по
  событию, а реальные kernel/internal drops агрегируются и ограничиваются по частоте; подробный
  режим сохраняет rate-limited счётчики для диагностики.
- UI-панели получил общие segmented/code-editor/status/diagnostic/switch-компоненты;
  переключатели Notifications и Logs теперь доступны с клавиатуры. RU-словарь дополнен
  для новых workflow и диагностики, переводится также `aria-label`, удалены дубли ключей.
  CI запрещает неоформленные native select/search, недоступные clickable-div и новые
  `qeliT`/контрольные строки без перевода; добавлен opt-in visual-regression сценарий на
  72 комбинации страниц RU/EN × dark/light × desktop/mobile.
- Пользовательский `bandwidth.limit_mbps` теперь симметрично действует на TCP и UDP в
  обоих направлениях. Upload и download получили независимые session-wide token buckets:
  заданная скорость доступна одновременно в каждом направлении, но multipath-потоки внутри
  одного направления делят общий лимит и не умножают его. UDP upload проходит через
  ограниченную per-client pacing-очередь, поэтому медленный пользователь не блокирует общий
  receive-loop остальных клиентов; при `0` сохраняется прямой быстрый путь без ограничения.
- Карточки активных профилей на Dashboard снова компактны и укладываются до шести в ряд на широком
  экране; сетка адаптивно переходит на 4/3/2/1 колонку. Выпадающие списки и поля поиска во всей панели
  получили единый нативно-независимый стиль, а опции поиска, сортировки и пагинации теперь корректно
  переключаются между русской и английской локалями.
- Веб-панель теперь остаётся управляемой при большом числе подключений и учётных записей:
  Dashboard и Users отображают только выбранную страницу по 25/50/100 строк вместо создания
  всего DOM-списка, длинные таблицы прокручиваются горизонтально, добавлены поиск, фильтры,
  сортировка и постраничная навигация. Страница Users показывает актуальный статус online/offline
  и число одновременных сессий, обновляет его каждые 10 секунд только в видимой вкладке, а массовое
  выделение действует на текущую страницу. `/api/usage` также снова отдаёт накопленное число
  подключений пользователя, которое интерфейс уже умел показывать. Новые элементы локализованы на
  русский и английский.
- Мобильный QR-сканер больше не растягивает камеру на весь вертикальный экран: Android
  открывает адаптивный dialog с квадратным preview, а iOS — компактный sheet с такой же
  квадратной областью. Оба варианта сохраняют ориентацию устройства, ограничивают размер на
  планшетах и оставляют явную кнопку отмены.
- Долгоживущий transport больше не остаётся в ложном `Connected`: закрытие клиентского
  TUN reader разрывает TCP/UDP generation, фатальная ошибка любой очереди серверного TUN
  перезапускает только затронутый профиль с bounded backoff, а остановка worker сначала
  отменяет все profile supervisor и только затем очищает NAT/hooks. Умершие дополнительные
  multipath-потоки восстанавливаются до заданной/adaptive ширины без повторного JOIN-index;
  TCP получил общий suspend detector. При выключенных heartbeat и shaping больше нет скрытых
  90/120-секундных idle timeout: применяется только явно заданная idle policy. Сервер больше
  не принимает UDP-профиль с одновременно выключенными heartbeat/shaping и
  `idle_timeout_secs=0`, иначе исчезнувший клиент удерживал бы IP и слот бессрочно.
- UDP RX-liveness теперь обновляется только после успешных framing, length и AEAD-проверок:
  посторонняя датаграмма больше не удерживает сессию живой. Удалён ложный восьмисекундный
  реконнект при допустимом одностороннем uplink. Deadline учитывает реальный cadence:
  heartbeat вместе с jitter либо максимальную паузу shaping, с тройным запасом и полом 30с.
  Одинаковая формула применяется клиентом и сервером для TCP и UDP. Включённый shaping
  требует `budget_bytes_per_sec >= max_size`, чтобы запланированная cover-запись действительно
  могла накопить токены и поддерживать liveness.
- Reconnect теперь учитывает реальную смену физического пути: Windows/macOS сравнивают адреса,
  prefix, gateway и DNS перед повторным использованием `persist_tun`, пересобирая bypass routes
  и resolver state после Wi-Fi/Ethernet/DHCP/sleep; headless Windows Service и macOS daemon
  теперь доставляют эти изменения активному туннелю. Android отслеживает capabilities/link
  properties того же `Network` и после разблокировки заменяет зависшую native generation,
  когда физический IPv4-путь готов; iOS делает то же после короткого wake-settle. Android и
  iOS допускают не более одного незавершённого блокирующего системного DNS lookup, а Rust
  алгоритмически делит оставшийся TCP connect deadline между ещё не проверенными A-record,
  поэтому один black-holed адрес не блокирует остальные.
- DNS NetworkPlan стал fail-closed и одинаковым на платформах: split-tunnel добавляет `/32`
  route каждому tunnel resolver, full-tunnel с `dns=tunnel` и без доступного resolver отклоняется,
  а IPv6 resolver отклоняется с явной ошибкой до появления IPv6 inner data plane. iOS
  устанавливает `matchDomains=[""]`. При несовпадении pinned server identity iOS full-tunnel
  сохраняет NetworkExtension/TUN как blackhole вместо снятия маршрутов и fail-open выхода в
  физическую сеть.
- Усилен desktop security-контур. macOS daemon открывает root-owned state directory через
  `O_NOFOLLOW`, работает с дочерними файлами через проверенные fd/`openat`, выполняет bounded
  same-descriptor read и атомарные `renameat`+`fsync`; одноразовый несохранённый service key
  больше не возвращается. Пользовательский profile key перенесён с доверия к
  `/usr/bin/security` на прямой Security.framework ACL подписанного Qeli с crash-safe журналом
  миграции старого элемента без ротации: после сбоя между удалением и записью ключ восстанавливается,
  а несовпадение ключей отклоняется. Windows kill-switch дополняет crash-persistent WFP rules
  ядерным WinDivert DROP-gate, поэтому существующие явные Allow-правила не обходят allow-list во
  время работы клиента; фильтр не копирует carrier packets в userspace и не затрагивает throughput.
  Общесистемные owner-marker и operation mutex исключают одновременное управление firewall
  двумя процессами, а снятие блокировки транзакционно восстанавливает Domain/Private/Public и
  сохраняет recovery state при любой ошибке вместо ложного сообщения об успехе и fail-open выхода.
- CI закрепляет минимальные `contents: read` permissions, использует Cargo `--locked`, делает
  fuzz-smoke блокирующим и проверяет также flat INI, `qeli://` и pre-auth WebSocket HTTP head.
  Добавлен `cargo-deny` gate для duplicate/source policy. Пять отслеживаемых исторических
  production deploy-скриптов окончательно выведены из эксплуатации и проверяются как
  неисполняемые; остальные 115 Python-сценариев переведены с `AutoAddPolicy` на общий
  known_hosts/`RejectPolicy` helper с единственным явным opt-in для заново созданной лабы.
- Поставляемый Wintun теперь закреплён не только SHA-256, но и upstream-версией 0.14.1;
  Windows CI проверяет FileVersion и валидную Authenticode-подпись WireGuard LLC обеих
  canonical/embedded копий до сборки клиента.
- Windows per-app больше не превращает fail-closed `Drop` неизвестного процесса в IPv6 bypass
  при `apps_mode = exclude`. Непервые outbound IPv4-фрагменты без affinity удерживаются в
  ограниченном короткоживущем буфере до первого фрагмента, после чего вся датаграмма следует
  одной политике; если первый фрагмент не принят транспортом, накопленный хвост отбрасывается.
- Quick Start лениво перебирает все 69 888 private `/24` из RFC 1918 (`10/8`, `172.16/12` и
  `192.168/16`): дешёвая проверка пересечений выполняется без большого временного списка, а
  полная runtime-валидация и preflight — ровно один раз для выбранного кандидата. Поэтому маршрут
  хоста на весь `10/8` не блокирует автоматическое создание профиля, но запуск больше не делает
  десятки тысяч дорогих копирований конфигурации. Генератор, устанавливаемые примеры и RU/EN
  документация больше не дублируют автоматически зарезервированный `tun.address` в `pool.exclude`.
- Команды установки и проверки provenance в RU/EN документации исправлены с 0.7.13 на
  текущий стабильный релиз 0.7.14; version-sync теперь контролирует также имена, URL и команды
  release-артефактов. README показывает все 10 Quick Start режимов, а benchmark-документация
  отделяет историческое описание от канонического прогона qeli 0.7.13 от 2026-07-28.
- Привилегированный macOS-тракт вызывает `/usr/sbin/sysctl` по абсолютному пути, а из `IpPool`
  удалены неиспользуемые копии server TUN address и prefix length.
- Удалён дублирующий `tun.netmask`: `pool.cidr` теперь единственный источник IPv4-префикса
  для серверного TUN, всех клиентских NetworkPlan и DHCP. Панель больше не показывает отдельную
  маску, поэтому профиль с `pool.cidr = 10.20.0.0/16` не может настроить интерфейс как `/24`;
  `tun.address` валидируется как пригодный адрес внутри пула и, даже если это не `.1`, автоматически
  исключается из AUTH/DHCP-выдачи. Автоматический DHCP выбирает непрерывный диапазон без адреса
  сервера, а явный диапазон с ним отклоняется. Старый ключ принимается при чтении
  INI для совместимости, игнорируется с предупреждением и не записывается обратно.
- IPv4/IPv6 `include`/`exclude` теперь применяются одинаково: Windows/macOS используют family-aware
  route API и заранее определяют отдельный физический путь для IPv6 bypass, iOS формирует
  `NEIPv4Route` и `NEIPv6Route`, Android трактует bare IPv6 как один хост `/128`, а не как `/32`.
  Явный IPv6 include остаётся fail-closed в текущем IPv4 inner data plane и больше не утекает наружу.
- Windows per-app тракт из [PR #112](https://github.com/litvinovtd/qeli/pull/112) приведён к
  общему MTU-контракту: WinDivert получает итоговый MTU, ограничивает TCP MSS, дробит разрешённые
  IPv4-пакеты, возвращает приложению ICMP Fragmentation Needed для DF и reverse-NAT'ит входящие
  ICMP ошибки по вложенному 5-tuple. Общее UDP-ядро больше не пытается молча отправить inner packet
  крупнее TUN MTU и разрывает неисправный carrier при реальной ошибке `send`, а статистика WinDivert
  отдельно показывает MTU drops, фрагментацию и ICMP feedback.
- Windows per-app DNS теперь выбирает resolver стабильно на весь TCP/UDP flow, а DNS source NAT
  живёт столько же, сколько сам flow. Разные исходные DNS-адреса одного сокета получают отдельные
  NAT identity и восстанавливаются без last-writer-wins. Открытый TCP mapping не ограничен
  произвольным TTL: после короткого grace flow сверяется с актуальной системной таблицей владельцев,
  поэтому действительно idle SSH/DB соединение сохраняется, а пропущенный FIN/RST очищается.
  UDP сохраняет короткий TTL; неоднозначный UDP owner при `SO_REUSEADDR` обрабатывается безопасно,
  IPv6 extension headers разбираются, а IPv6 `exclude` больше не игнорируется.
- macOS per-app helper подтверждает реально подключённый transparent provider после `start/update` и
  не сообщает ложный `ACTIVE` при выгруженном extension. DNS provider оставляет системный resolver
  без изменений при пустом `dns_servers`, использует весь список resolver'ов с TCP fallback/UDP
  affinity и применяет apps include/exclude policy; IPv6 exclusions работают. Настроенный tunnel
  DNS всегда привязывается к текущему utun, включая RFC1918 resolver, а UDP reverse mapping
  восстанавливает исходный endpoint по resolver и DNS transaction ID. Монитор app-group state и
  live-update `true → true` закрывают relays прошлого поколения, поэтому они не удерживают удалённый
  utun, прежний DNS или старую apps/route policy. Swift system
  extension, helper и policy tests добавлены в обычный macOS CI, а не только в подписанную сборку.
  Сборочная схема использует корректные XcodeGen tool targets, а relay явно выбирает типы
  NetworkExtension и совместимый с macOS 13 UDP API, поэтому весь per-app комплект собирается
  текущим Xcode.
- `include`/`exclude` теперь строго валидируются как числовые IPv4/IPv6 CIDR в C#, Android и iOS;
  Android не выполняет DNS lookup для route-адресов и отказывается запускать `apps_mode=include`,
  если ни одно выбранное приложение не установлено, вместо неявного захвата всех приложений.
  Устаревшие JSON deployment/lab скрипты отключены, а комментарий `client.conf` уточняет границу
  между компактным `qeli://`, file-only настройками и параметрами, которые обязан заранее знать клиент.
- Windows per-app flow table ограничена 65 536 записями и освобождает TCP state по RST либо
  короткому closing TTL. Пара FIN не удаляет NAT до завершающего ACK: mapping остаётся стабильным
  до closing TTL. Коллизии одинакового local port с разных локальных IP получают
  отдельный tunnel-side NAT port с восстановлением исходного адреса/порта; системные TCP/UDP/PID
  таблицы при classification miss обновляются немедленно на coalesced worker, а неизвестный owner
  не отправляется в VPN даже в exclude-mode. Ранние IPv6 outbound и IPv4 inbound фрагменты
  удерживаются в коротком bounded buffer до первого фрагмента; affinity использует стабильный
  next-header после Fragment Header и полный 32-битный fragment ID. Добавлены счётчики
  buffered/released/buffer-drops.
- Android 9–12 строит отдельный минимальный IPv6 complement для `exclude`, вместо передачи IPv6 CIDR
  в IPv4-only расчёт и последующей установки `::/0`. Неполный complement отклоняется fail-closed.
  Все сценарии исторического `test/` и оставшиеся опасные root-SSH/source-mutation скрипты старого
  `vpn-obfuscated`/JSON/systemd контура теперь завершаются до SSH/команд и указывают поддерживаемые
  INI/lab инструменты; тест фиксирует этот запрет. Из active troubleshooting и release fixtures
  удалены последние упоминания отдельного `tun.netmask`.

- Разблокированы мобильные release-gates: Android теперь обращается к
  `VpnService.isAlwaysOn`/`isLockdownEnabled` только на API 29+, сохраняя fail-closed
  трактовку Android 9; общий `ReconnectPolicy` перенесён в iOS target membership,
  поэтому Packet Tunnel extension компилируется вместе с политикой reconnect.
- Повторный Launch одного Quick Start режима больше не ротирует `reality short_id` или
  `obfs_key` и не сбрасывает ручные настройки профиля: существующий профиль только
  включается и перезапускается. Диалог теперь заранее различает создание новых и
  сохранение действующих credentials; поведение синхронно описано в RU/EN документации.
- Windows/macOS и iOS повторно разрешают hostname перед каждой reconnect generation,
  принимают изменившийся полный набор A-записей и при временной ошибке DNS используют
  последний рабочий набор. Desktop kill-switch обновляет server allowlist до выбора
  нового IP, не снимая fail-closed защиту; `persist_tun` для hostname пересоздаёт host
  routes, чтобы новый DDNS-адрес не ушёл в старый туннель.

- Обновлён Rust dependency lock: `rustls` 0.23.41 → 0.23.43 с дополнительными проверками
  согласованности TLS/QUIC и защитой арифметики ticket/binder, `tokio` 1.52.3 → 1.53.1,
  `serde` 1.0.228 → 1.0.229 и `thiserror` 2.0.18 → 2.0.19 с переходом derive-макросов на
  `syn` 3, `webpki-roots` 1.0.8 → 1.0.9 с актуальным набором корневых CA Mozilla.
- Весь согласованный набор Avalonia для macOS-клиента (`Avalonia`, Desktop, Themes.Fluent,
  Fonts.Inter, Diagnostics и Headless) обновлён с 11.3.18 до patch-релиза 11.3.19 и проверен
  Release-сборкой, полным self-test и PacketCodec benchmark gate.
- Supply-chain actions в CI обновлены и по-прежнему закреплены полными проверенными SHA:
  `actions/setup-java` 5.7.0, `actions/attest-build-provenance` 3.2.0,
  `Swatinem/rust-cache` 2.9.2 и `gradle/actions/wrapper-validation` 4.4.3.
- iOS теперь реально применяет `reconnect`, `reconnect_retries`, `reconnect_base_delay` и
  `reconnect_max_delay`: временный обрыв native transport или packet pump создаёт новую
  generation после backoff, сохраняя NetworkExtension TUN fail-closed. Невалидный NetworkPlan,
  неподдерживаемый DNS port и несовпадение ключа остаются terminal errors.
- Android разрешает hostname через `currentNetwork.getAllByName`, а desktop/iOS сохраняют все
  A-record до перехвата DNS маршрутом. Общее ядро пробует все IPv4 для TCP, а для UDP ротирует
  их между reconnect generation; DNS-loop в сохранённом TUN устранён.
- Активный UDP path-MTU probe доведён до Windows, macOS и iOS через нативные DF socket options;
  все пять клиентов теперь исполняют `mtu_probe` для UDP + auto MTU.
- Quick Start строит профиль на сервере и ищет свободную private `/24`, прогоняя каждый
  кандидат через schema и host route/address preflight. Save, raw save, restart и прямой
  worker start выполняют ту же проверку до остановки рабочего VPN.
- Панель сохраняет fixed/auto признак `perf.udp.recv_buffer_size`; сервер получил общий бюджет
  всех UDP socket buffers — не более 12,5% `MemAvailable`, с учётом всех
  profile/listener/queue и удвоенного Linux accounting. Статистика показывает сумму фактически
  выданных буферов, а не максимум одного worker.
- CLI, панель и installer единообразно отклоняют IPv6 public endpoint до появления IPv6 data
  plane; проверка выполняется до создания или сброса пароля.
- Rust CLI/панель теперь, как Android, iOS и desktop, принимают pinned `key` только как ровно
  64 hex-символа и не все нули. Текстовый placeholder больше не проходит `check-config`, чтобы
  ошибочная конфигурация останавливалась до запуска транспорта, а не при декодировании handshake.
- OpenWrt feed перепривязан к актуальному qeli-дереву (`9ecb807`) и получил настоящий
  `PKG_MIRROR_HASH`, рассчитанный OpenWrt SDK по immutable git-архиву 0.7.15; пакет больше не
  собирает прежний transport под новой версией.
- CI-покрытие расширено на `client.conf`, `client-reality.conf`, `client-maxobf.conf`, отдельный
  `users.conf` и все 10 серверных Quick Start profile. Лабораторный gate теперь синхронизирует
  сами `qeli/tests`, проверяемый REALITY-шаблон и выполняет `cargo fmt --check` до сборки,
  поэтому не может прогнать оставшуюся на лабе
  старую копию integration-теста против старого release input.

### Архитектура клиентов — общее Rust-ядро

- Основой Windows per-app split tunneling послужил
  [PR #112 — feat(win): Windows per-app split tunneling via WinDivert](https://github.com/litvinovtd/qeli/pull/112).
  Перед включением в `dev` его полезные части адаптированы к текущему общему Rust transport,
  единому ABI и конфигурационному контракту вместо сохранения отдельной реализации протокола.
  Для macOS реализован функциональный аналог без WinDivert: подписанное Network Extension
  классифицирует потоки по code-signing identifier приложения и направляет выбранные TCP/UDP/DNS
  соединения в тот же Rust transport. Таким образом, `apps_mode = include/exclude` и `apps`
  имеют одинаковый пользовательский смысл на обоих desktop-клиентах, хотя платформенный перехват
  различается: WinDivert/PID+endpoint на Windows и transparent/DNS providers на macOS.
- Windows и macOS теперь применяют переносимые `apps_mode`/`apps`, а не только сохраняют
  их. На Windows обычный профиль сохраняет zero-copy Wintun, а per-app-профиль использует
  встроенный WinDivert, PID/endpoint-классификацию, DNS destination NAT и fragment affinity,
  передавая выбранные пакеты в то же Rust-ядро ABI 1.10. На macOS выбранные TCP/UDP/DNS
  потоки классифицирует подписанное system extension с transparent- и DNS-provider и
  привязывает их к qeli utun через `IP_BOUND_IF`; невыбранные приложения сохраняют системный
  маршрут и DNS. Оба desktop-адаптера удерживают выбранный трафик fail-closed при reconnect.
  Mac-сборка без Developer ID Network Extension намеренно отклоняет per-app-профиль; per-app
  ICMP не заявлен. GUI, INI и `qeli://` получили общий валидируемый round-trip этих ключей;
  оба desktop-редактора умеют выбирать установленные приложения, а macOS сохраняет настоящий
  code-signing identifier из `codesign` и требует macOS 13+ для per-app режима. Mac release
  pipeline подписывает все вложенные Mach-O изнутри наружу и поддерживает обязательные для
  публичной поставки `notarytool` + stapling через keychain-profile.
- WinDivert 2.2.2 x64 DLL/SYS сверены по SHA-256 с официальным GitHub release archive;
  canonical и embedded-копии контролирует `native-libs/verify.sh`. В publish рядом с обоими
  Windows exe выходит полный официальный LGPLv3/GPLv3/GPLv2 `LICENSE` и provenance `NOTICE`.
  На остановке classifier пишет счётчики captured/tunnelled/bypass, policy/down/queue drops
  и unmatched replies, чтобы диагностика потерь per-app data-plane не зависела от догадок.
- Закрыт конфигурационный контур рефакторинга: все пять клиентов распознают единый контракт
  из 73 ключей, а transport-owned `timeout`, socket settings, padding/heartbeat/shaping,
  `local`/`lport`, DNS и TOFU-политика доходят до общего Rust-ядра без скрытых platform
  defaults. Android/iOS больше не удаляют известные ключи другой платформы при сохранении;
  `gateway` передаётся в ядро явно, публичный fallback DNS удалён. Добавлена двуязычная
  проверяемая таблица каждого ключа «0.7.14 → 0.7.15»:
  `docs/{ru,eng}/CLIENT-CONFIG-MATRIX.md`.
- Устранено расхождение socket-buffer policy после переноса клиентов в общее ядро:
  `recv_buffer_size`/`send_buffer_size` снова применяются только к UDP carrier, а TCP
  сохраняет системный autotuning. Дефолтный UDP receive buffer 4 МиБ не уменьшен.
  Отказ ОС принять best-effort `SO_RCVBUF`/`SO_SNDBUF` теперь пишется в предупреждение,
  но не обрывает подключение — так же, как в клиентах до рефакторинга.
- Общий Rust transport получил bounded UDP receive-buffer controller вместо одного
  жёсткого размера. При отсутствующем `recv_buffer_size` клиент и каждый server worker
  начинают с 4 МиБ и могут вырасти 4→8→16 МиБ по точному per-socket kernel overflow
  (`/proc/net/udp{,6}` на Linux/Android, когда доступен) либо измеренному rate/stall budget; сетевые
  sequence gaps не считаются доказательством локально малого буфера, уменьшения на живом
  сокете нет. Явное значение остаётся fixed override (`0` = настройка ОС), ручные UDP
  send/receive значения ограничены 64 МиБ на сокет. Additive ABI 1.10 дописывает к прежнему
  64-байтовому stats prefix четыре `u64`: kernel drops, внутренние bounded-queue drops,
  число увеличений и фактически выданный `SO_RCVBUF`. Android, iOS, Windows и macOS
  показывают их change-only в журнале подключения.
- Введённый в ABI 1.8 packet seam завершает перенос production transport на iOS; текущий
  platform adapter работает по additive ABI 1.10. Новый
  `QeliNativeTunnelEngine` оставляет Swift только `NEPacketTunnelNetworkSettings`, Keychain
  trust/device ID, lifecycle/statistics и bounded batch-копирование между `packetFlow` и
  `qeli_client_tun_push/pull`; Rust владеет DNS/connect, всеми handshake/crypto,
  TCP/UDP/QUIC/Reality, reconnect, heartbeat/shaping, MTU и bonding. Восемь старых Swift
  runtime-файлов (`QeliTunnelEngine`, handshake/transport/runtime) удалены: 4 046 строк
  wire/runtime-дубля заменены компактным platform adapter без собственной реализации протокола.
- Для iOS зафиксирован memory budget packet bridge: два пула по 32 × 65 535 байт =
  4 194 240 байт core-owned packet storage; три переиспользуемых Swift caller-buffer дают
  ещё не более 768 КиБ. Очереди ограничены 128 элементами и не создают fallback allocation.
  `aarch64-apple-ios` whole-client core успешно прошёл `cargo check`; XCFramework и Xcode
  simulator теперь собираются в CI, а physical-device interop остаётся обязательным gate.
  UI-валидация размера AUTH использует зафиксированный Rust wire scalar (1114 байт), поэтому
  production PacketTunnel больше не зависит от исключённого legacy Swift `Protocol/`; KAT
  отдельно проверяет, что UI-limit не расходится с прежним cross-language fixture.
- ABI 1.8 также добавляет handle-free `qeli_client_udp_probe` и capability
  `QELI_CORE_UDP_DIAGNOSTIC`. Windows, macOS и iOS больше не строят PQ ClientHello,
  fragmentation, QUIC или obfs для reachability в C#/Swift: они передают strict профиль
  общему Rust first-flight builder. C# `Protocol/`/`Crypto/` и Swift conformance primitives
  остаются только для KAT/регрессионных тестов и исключены из production iOS Packet Tunnel.
- Additive поля ABI 1.8 `NetworkPlan` отдельно передают подтверждённые сервером pushed routes
  и effective post-push padding/heartbeat/shaping для UI. iOS больше не смешивает их с
  client/local routes и отклоняет весь план до ACK, если хотя бы один маршрут нельзя применить
  как `NEIPv4Route`, либо адрес/prefix/MTU выходят за поддерживаемые границы; частично
  установленный план не объявляется успешным. Uplink сохраняет точную семантику accepted-prefix
  и отклоняет некорректный размер пакета вместо пропуска/зацикливания; сброс native-счётчика не
  превращается в переполнение показанной скорости.
- После переноса transport в Rust восстановлен полный журнал подключения во всех клиентах.
  Общее ядро теперь прикладывает к authenticated `NetworkPlan` один и тот же безопасный набор
  строк для Linux, Android, Windows, macOS и iOS: исходный server push и итоговое решение по
  адресу/prefix/gateway, MTU и path-MTU, DNS с портом, каждому принятому маршруту и числу
  отклонённых, padding, heartbeat, traffic normalization, shaping и fixed/adaptive multipath.
  Для каждого параметра различаются «не прислан», `IGNORED`, `REJECTED`, `ACCEPTED` и
  фактический platform `APPLIED`/`REJECTED`; причины DNS/NetworkPlan ошибок снова сразу видны в
  UI-журнале, а не только в нативном stderr. Пароли, ключи и session token в эти строки не
  попадают. Android заодно снова читает отдельные `pushed_routes`/`data_plane`, поэтому карточка
  соединения не считает client routes серверными и показывает negotiated padding/heartbeat/
  shaping. Platform DNS fallback теперь проходит через общую Rust-политику и не может повторно
  включить DNS после `dns = off/system`.
- Additive ABI 1.7 переключает активный transport Windows и macOS на то же Rust-ядро,
  которое уже обслуживает Linux/Android. Rust теперь владеет DNS/connect, carrier sockets,
  hybrid handshake, transport crypto, TCP/UDP/QUIC/Reality, heartbeat/shaping и
  fixed/adaptive bonding. Общий C# `VpnTunnelBase` оставляет только lifecycle/reconnect,
  persisted trust/device ID, применение `NetworkPlan`, UI/statistics и lifecycle platform Wintun/utun.
  Ошибка загрузки, ABI/capability negotiation или plan ACK обрабатывается fail-closed;
  managed transport fallback на активном пути не включается.
- Desktop TC-5 cleanup физически удалил dormant runtime-дубль из C#: `VpnTunnelBase.cs`
  сокращён с 3 287 до 1 126 строк, удалён отдельный 139-строчный `RealTls` P/Invoke
  wrapper — чистое сокращение на 2 300 строк. В общем .NET-проекте остаются только
  cross-language wire/KAT; production transport и reachability на них не
  ссылается и managed fallback больше не существует.
- Финальный cleanup общего desktop-адаптера отделил production от conformance: `QeliShared.dll`
  больше не компилирует managed crypto/wire codecs, fixture discovery, network-policy assertions
  и MTU KAT helpers; они запускаются только отдельным `QeliConformance`. Native fake-TLS bridge
  gate теперь строго вызывает Rust `qeli_build_faketls_clienthello` без managed fallback, поэтому
  отсутствующая библиотека или экспорт больше не дают ложный PASS. Production dependency graph
  не содержит BouncyCastle/test runner.
- Persist-TUN fingerprint канонизирует interface-scoped routes как множество CIDR: удаление
  сервером лишнего дубликата больше не пересобирает неизменившийся TUN. Android icon generator
  использует пути относительно checkout вместо developer-specific OneDrive hardcode.
- ABI 1.7 добавляет `QELI_CORE_TUN_PACKET_IO`, `QELI_PLATFORM_TUN_PACKET_BATCH` и
  generation-scoped `qeli_client_tun_push/pull`. Пакеты передаются в caller-owned
  contiguous buffers с массивом длин; packet/batch ограничены 65 535 байтами/64 элементами,
  reusable pools и очереди имеют жёсткий memory bound и backpressure без fallback allocation.
  Stale generation, malformed batch и IO до положительного `NetworkPlan` ACK отклоняются.
  Как и Android, desktop adapters отрицательно подтверждают DNS plan с портом не 53, который
  системные Windows/macOS resolvers не умеют применить, вместо ложного успешного ACK.
  Desktop `NetworkPlan` также несёт IP фактически подключённого carrier, поэтому bypass route
  не выполняет второе DNS-разрешение и не может выбрать другой адрес round-robin hostname.
- Промежуточный desktop packet seam ABI 1.7 больше не выделяет и не копирует временный
  `byte[]` на каждый пакет:
  общий C# pump переиспользует один caller-owned uplink buffer и передаёт downlink прямо из
  Rust batch по `offset+length`; Wintun копировал диапазон сразу в ring. TC-1.2 закрыт без
  изменения ABI 1.8; затем TC-2.2/TC-2.3 полностью убрали desktop payload из C#.
- TC-2.2 переносит macOS utun payload целиком в Rust без повышения ABI. C# `UtunDevice`
  теперь отвечает только за открытие fd, имя интерфейса и lifecycle; перед положительным
  `NetworkPlan` ACK общий adapter передаёт ядру generation-scoped CLOEXEC-дубликат через
  существующий ABI 1.1 `qeli_client_set_tun_fd`. Общий fd-pump снимает/добавляет четырёхбайтовый
  address-family prefix utun, пишет prefix+payload через `writev` без временного `Vec` и работает
  на неблокирующих reader/writer fd, чтобы stop/reconnect не зависал на пустом utun. Локальные
  gate: Windows/macOS Release build 0 warnings/errors, оба selftest `ALL PASS`; новый ABI 1.9
  universal2 dylib пересобран и включён в macOS-пакет. Live macOS full-tunnel остаётся
  аппаратным release gate, потому что на Linux-лабе нет utun/macOS runtime.
- Additive ABI 1.9 завершает TC-2.3 и переносит Wintun session/rings в Rust. Новый
  `QELI_PLATFORM_TUN_WINTUN` + `QELI_CORE_WINTUN_IO` контракт принимает фактическое имя
  созданного C# интерфейса через generation-scoped `qeli_client_set_wintun_adapter` до
  положительного `NetworkPlan` ACK. Rust через уже загруженный проверенный `wintun.dll`
  открывает независимый adapter handle, запускает session, единолично владеет read event и
  обоими rings; C# сохраняет creator handle только для interface lifetime и network cleanup.
  Uplink не копируется из receive ring: RAII packet удерживает указатель и session owner до
  `WintunReleaseReceivePacket`; downlink копируется из bounded decrypt pool прямо в
  `WintunAllocateSendPacket`. Stop сначала закрывает очереди и join-ит reader/writer и только
  затем вызывает `WintunEndSession`, поэтому прежний managed UAF-класс удалён вместе с
  `ReceivePacket`/`SendPacket`, session handle и конкурентным `Dispose`.
- ABI 1.9 локально прошёл 330/330 Rust tests, Windows/macOS strict Clippy, macOS x64/arm64
  cross-check, оба desktop Release build без warnings/errors и оба selftest `ALL PASS`.
  Собранная локально release `qeli.dll` сообщает ABI `0x00010009`, capabilities `0xfe7` и
  содержит все 20/20 объявленных `qeli_client_*` exports. Release scripts обновлены с 19 до
  20 exports для Windows/macOS/Android. Все tracked native libraries пересобраны штатным
  lab-набором как ABI 1.9; живой Windows handshake получил полный `NetworkPlan`. Admin Wintun
  data-plane и live Mac utun full-tunnel остаются платформенными gate.
- TC-0.3/TC-4.3 закрыты постоянным release-mode `PacketCodec` benchmark gate. Новый
  opt-in Rust binary `packet-codec-bench` выполняет 1400-байтовый encrypt/decrypt round-trip,
  проверяет точное содержимое и запрещает рост caller-owned record buffer после warm-up.
  Общий C# `PacketCodecBenchmark` доступен как `packetbench` в Windows/macOS клиентах и
  дополнительно измеряет managed allocations на round-trip. Linux Rust и оба desktop CI jobs
  запускают эти измерители с консервативными anti-regression floors; JSON-строка в логе
  сохраняет фактическую скорость/allocations для тренда, но не подменяет lab throughput.
- Совместимость со строгим Rust 1.97 Clippy восстановлена удалением избыточного `i64 as i64`
  в platform-neutral календарном fallback без изменения результата вычислений.
- iOS-клиент приведён к строгим правилам capture semantics Xcode 26/Swift 6: фоновые transport,
  packet и stats tasks явно обращаются к захваченному `self`, поэтому simulator gate снова
  компилирует `QeliNativeTunnelEngine` после обновления toolchain.
- Windows/macOS/Android нативные библиотеки теперь собираются с
  `--no-default-features --features transport-core-ffi`, а не с
  Reality-only профилем и без неиспользуемого server/web stack. ABI 1.10 export gate ожидает
  6 `qeli_realtls_*` + 20
  `qeli_client_*` экспортов в Windows x64 DLL и universal macOS dylib (arm64+x86_64).
  Предыдущий lab-сценарий для ABI 1.8 реально загружал встроенную Windows DLL, выполнял Rust
  fake-TLS handshake и получал authenticated `NetworkPlan`; после пересборки native artifacts
  он повторён для ABI 1.10 вместе с полным Wintun data plane.
- Additive ABI 1.6 завершает переключение Android payload на общее Rust-ядро:
  `qeli_client_run`/`nativeRunTransport` блокирующе выполняет одну generation, а capability
  `QELI_CORE_NATIVE_DATA_PLANE` не позволяет приложению принять старую shadow-библиотеку.
  Rust теперь владеет connect, handshake, шифрованием, TUN read/write и live packet/byte
  counters; Kotlin обслуживает только `VpnService.protect`, persisted trust,
  `NetworkPlan`/TUN, UI, статистику и reconnect. Ошибка загрузки/negotiation native core
  обрабатывается fail-closed, Kotlin payload fallback не включается.
- Общий Android runtime использует те же зрелые sessions/pumps, что Linux: TCP fake-TLS,
  plain, obfs и Reality-TLS; UDP fake-TLS/obfs с fragmentation/retransmit, QUIC wrapper,
  active MTU probe, heartbeat, shaping, padding/normalization; fixed и adaptive TCP bonding.
  Для secondary streams каждый socket отдельно проходит platform `protect` до connect.
- Long-running ABI owner получил generation-safe registry lease: `run` не удерживает registry
  mutex во время platform ACK/TUN ожиданий, `free` не создаёт UAF и не переиспользует живой
  handle, а `stop/free` сначала выставляет cancellation и будит packet loop даже при заполненной
  event queue. TCP/UDP используют устойчивый cancellation interval, который не перезапускается
  каждым готовым пакетом и потому не голодает под непрерывной нагрузкой. Live counters атомарно
  сливаются в итоговую статистику generation.
- Лабораторная Android-матрица реально передала обратный TUN-трафик с 0% ping loss для TCP
  fake-TLS/plain/obfs, UDP fake-TLS/obfs, UDP+QUIC и Reality-TLS; MTU report дошёл до сервера,
  heartbeat/shaping профиль сохранил трафик, adaptive bonding вырос до четырёх защищённых
  carrier streams под download-only нагрузкой. Специализированные сценарии переведены с
  удалённого JSON на текущий flat-INI и теперь возвращают ненулевой код при отсутствии
  native ownership/auth/ping/JOIN. Reality-сценарий синхронизирует часы snapshot-эмулятора,
  потому что anti-replay token имеет допустимое окно 120 секунд.
- Gate рефакторинга: полный Rust library/binary/integration suite, минимальный
  `transport-core-ffi` профиль 333 passed/1 ignored, default `clippy -D warnings`, Android
  86/86 JVM tests, warning-free NDK release для arm64-v8a/x86_64, 6 Reality C exports,
  19 whole-client C exports и 17 TransportCore JNI exports. Debug APK с финальными `.so`
  имеет 23 289 752 байта; подписанный v2/R8 release APK — 8 275 224 байта
  (`versionName=0.7.15`, `versionCode=718`, arm64-v8a+x86_64). Lab-helper теперь сохраняет ненулевой код
  `cargo fmt/test/clippy/check` через shell pipelines и имеет отдельные `transport`/`ioscheck`
  /`routercheck` режимы, поэтому ошибка компиляции или client-only warning больше не может
  выглядеть как зелёный gate. Linux release sync включает `debian/` и `config/`, portable
  ELF и `.deb` загружаются одним version-derived helper вместо устаревшего абсолютного пути.
- Сформирован и опубликован комплект `release/dist/v0.7.15`: подписанный Android
  APK, два Windows single-file варианта (повторно собраны после добавления desktop per-app
  routing), ad-hoc signed universal2 macOS ZIP, portable glibc-2.28+jemalloc Linux ELF и `.deb`,
  четыре OpenWrt и два Keenetic client-only бинарника, OpenWrt integration archive, полные
  `WinDivert-LICENSE.txt`/`WinDivert-NOTICE.txt` и `SHA256SUMS` для 16 payload-ассетов. Тег
  `v0.7.15` и GitHub Release опубликованы после полного release preflight и проверки digest каждого ассета.
- Android теперь правильно считает применённые pushed routes из строкового массива активного
  `NetworkPlan`. Финальный platform-adapter применяет типизированный канонический список напрямую;
  совместимый legacy object-parser удалён, а UI получает число маршрутов только после успешного
  `VpnService.Builder.establish()`.
- На границе Android → Rust устранено расхождение исторических defaults: Android считал
  профиль без `gateway` полным туннелем, а единая Rust-схема — split-tunnel. Adapter теперь
  явно передаёт `gateway = true` для Android full-tunnel default; split-профиль по-прежнему
  передаёт `gateway = false`. Реальный lab e2e больше не может принять план другого режима.
- Additive ABI 1.5 переводит Android с пассивного shadow-контракта на реальную публикацию
  `NetworkPlan`: `qeli_client_publish_handshake_network` принимает ограниченный JSON с
  аутентифицированным `OK:`-ответом, итоговым MTU и явным platform DNS fallback. Rust повторно
  разбирает недоверенные DNS/routes, назначает generation и публикует единый план. Android
  применяет из него адрес, prefix, MTU, full/split routing, routes и DNS, передаёт ядру
  `CLOEXEC`-дубликат TUN fd и только затем подтверждает generation. Отрицательный ACK закрывает
  native fd и переводит ядро в `Failed`; stale/double ACK отклоняется.
- Android исполняет общий `kill_switch` через системный Always-on VPN lockdown. Ключ теперь
  читается/сохраняется моделью профиля и доходит до Rust `NetworkPlan`; adapter заявляет
  `QELI_PLATFORM_KILL_SWITCH` только после двухфакторной предзапусковой проверки: Qeli является
  текущим подготовленным VPN-провайдером, а защищённая `Settings.Secure`-политика lockdown
  включена. После `Builder.establish()` adapter дополнительно требует live owner-результаты
  `isAlwaysOn` + `isLockdownEnabled` непосредственно перед положительным ACK. Если пользователь
  не включил «Блокировать соединения без VPN», full-tunnel не стартует без защиты и сообщает
  точную настройку; Android 9 отклоняется из-за отсутствия live owner API.
  Нестандартный DNS-порт по-прежнему отклоняется внутри отрицательного ACK/retire-контура.
  Платформенные per-app правила, IPv6 capture, LAN bypass и `exclude` остаются
  Android-операциями поверх канонического Rust-плана.
- ABI 1.5 ввёл control-plane TUN ownership без второго reader; ABI 1.6 активировал общий Rust
  packet pump. Из `QeliService.kt` физически удалены старые Kotlin handshake, packet codec,
  TCP/UDP/Reality transports, MTU/QUIC pumps и bonding: файл сокращён с 3 921 до 1 443 строк
  (2 536 удалённых строк при 58 строках адаптерной переработки). Сервис оставляет только Android
  lifecycle, `protect`, trust, `NetworkPlan`/TUN, UI/statistics и reconnect; скрытого Kotlin
  payload fallback больше нет.
- Android TC-3.1 завершён физически: pre-connect UDP reachability probe перенесён в handle-free
  `TransportCore` JNI и использует тот же Rust hybrid-PQ ClientHello flight, fragmentation,
  QUIC и obfs, что рабочий UDP transport. В JNI передаётся credential-free профиль без
  user/password; lab проверяет отдельный ответ probe до `Connect`, затем независимо полный
  UDP+QUIC tunnel и 0% ping loss. Удалены Kotlin `protocol/*`, transport-crypto, `RealTls`,
  `MlKem`, `TrafficShaper`, четыре дублирующих wire-conformance test suites и 14 legacy JNI
  wrappers — ещё 2 491 строк production Kotlin и 857 строк JVM-дублей. `BackupCrypto` сохранён
  как отдельная функция импорта/экспорта. Обе `.so` уменьшились примерно на 20 КиБ; APK — до
  23 237 892 байта после ABI 1.7.
- Защищённый platform carrier теперь можно передать в общий `transport_core::carrier`, который
  под единым `connection_timeout` выполняет IPv4 DNS resolution и неблокирующий TCP/UDP
  `connect`, проверяет отложенную TCP-ошибку через writable readiness и возвращает готовый
  Tokio socket общему handshake-owner. ABI 1.6 использует этот путь для primary и каждого
  bonded carrier; второго параллельного Kotlin-сеанса нет.
- Проверка доверия в общем TCP-handshake стала асинхронной. Additive ABI 1.4 добавляет
  `ServerIdentity` с JSON `server_id/public_key`, capabilities
  `QELI_CORE_SERVER_IDENTITY_ACK`/`QELI_PLATFORM_SERVER_IDENTITY` и коррелированный
  `qeli_client_server_identity_result`. Событие предназначено только для ключа, владение которым
  уже доказано криптографическим server-auth proof: Android сверяет его со своим persisted
  `qeli_known_hosts`, синхронно записывает неизвестный ключ только после proof и fail-closed
  отклоняет замену или ошибку persistence. ACK/отказ/stop/free покрыты
  oneshot/stale/cancel тестами; Android использует ту же
  bounded queue и не заводит callback или второй dispatcher.
- Основной аутентифицированный TCP-handshake (`plain` и hybrid fake-TLS/
  X25519MLKEM768) перенесён из Linux-клиента в платформонезависимый
  `transport_core::session`. Device ID и проверка доверия к статическому ключу теперь
  явные входы: Linux сохраняет прежний pinned/TOFU adapter, а Android сможет использовать
  уже существующее защищённое хранилище без второй identity. Формат провода, derivation
  ключей и таймаут handshake не изменены.
- Расчёт `NetworkPlan` после `Auth OK` также вынесен в общее ядро: приоритет и проверка
  DNS, фильтрация недоверенных pushed routes, include/local/custom routes, full-tunnel и
  kill-switch теперь принимаются одним кодом до платформенного ACK. Linux-модули оставлены
  исполнителями системных операций и делегируют планирование ядру.
- Additive ABI 1.3 добавляет capability `QELI_CORE_DEVICE_ID_INPUT` и
  `qeli_client_set_device_id`: принимаются только 16 ненулевых байт до `start()`, значение
  копируется во владение ядра и очищается при замене/free. Android передаёт тот же persisted
  device ID; временные JNI/Kotlin-копии очищаются. ABI 1.6 использует его в единственном
  активном native handshake, без конкурирующей identity или второго сеанса.

- Главный Android TCP/UDP e2e приведён к текущему flat-INI и защищённому хранилищу профилей:
  тест очищает только данные lab-приложения, проходит реальную миграцию профиля, находит Connect
  по UI вместо устаревших координат и завершается ошибкой без `Auth OK` и обратного ping через TUN.
  Временные UDP-профиль и тестовый пользователь создаются изолированно и гарантированно удаляются.
  Это исключает ложный зелёный результат, когда старый JSON-профиль был отвергнут клиентом,
  lab-учётная запись изменилась или соединение вообще не запускалось.
- Android передаёт явный список резолверов в общее Rust-ядро под единым ключом `dns_servers`,
  сохраняя прежний `dns = <ip>` только для совместимости собственного backup/import. Ранее строгий
  parser ядра считал Android-форму недопустимым DNS-режимом и отключал shadow-core на валидном профиле.
- Начата поэтапная миграция клиентов на единое транспортное Rust-ядро. Первый совместимый
  слой вводит общий строгий разбор flat-INI и `qeli://`, явную машину состояний, ограниченную
  очередь событий и версионированный C ABI с generation-checked `u64` handles. События
  копируются в буферы вызывающей стороны; недостаточный буфер не извлекает событие из очереди.
- C ABI 1.0 прошёл freeze-review до подключения платформенных адаптеров. Header теперь задаёт
  правила major/minor compatibility, ownership и concurrency, compile-time проверяет layout и
  инициализирует caller-owned размер output-структур. Ядро сохраняет этот размер, пишет только
  общий известный префикс и не потребляет событие при короткой структуре, поэтому будущие поля
  можно добавлять без переполнения памяти старого клиента. Panic внутри операции над handle
  возвращается как `QELI_CLIENT_PANIC` и инвалидирует только этот generation, а не маскируется
  под stale handle.
- Добавлен первый ресурсный срез Android/macOS TUN backend: additive ABI 1.1 экспортирует
  `qeli_client_set_tun_fd(handle, generation, fd)`. Ядро принимает fd только для ожидающего
  network-plan поколения, атомарно создаёт собственный `CLOEXEC`-дубликат и не забирает
  ownership исходного descriptor у платформы. При заявленной `QELI_PLATFORM_TUN_FD`
  положительный ACK теперь невозможен до attach; stale generation отклоняется, а reject,
  stop, replacement и free закрывают только native-дубликат. Packet reader этим вызовом ещё
  не запускается: действующий Android Kotlin data plane остаётся единственным читателем до
  отдельного JNI handoff, поэтому wire format и скорость не меняются.
- Additive ABI 1.2 добавляет fail-closed запрос `SocketProtect`: Rust публикует в той же
  bounded queue JSON-событие `{"fd": N}`, а его одноразовый `event.sequence` служит request
  ID для `qeli_client_socket_protect_result`. Владелец сокета сохраняет fd открытым до ACK и
  ждёт результат через oneshot без busy polling; неизвестный, повторный или отменённый ACK
  возвращает `QELI_CLIENT_STALE_REQUEST`. Android shadow-сервис теперь заявляет
  `QELI_PLATFORM_SOCKET_PROTECT` вместе с фоновым dispatcher: он опрашивает ту же core-очередь
  с адаптивной паузой 20–250 мс, вызывает `VpnService.protect(fd)` до пяти раз с интервалом
  100 мс и подтверждает точный sequence ID. Некорректные и неожиданные события отключают только
  shadow-core, не затрагивая Kotlin data plane. Producer теперь реальный: при `start()` Rust
  создаёт неблокирующий IPv4 TCP/UDP carrier, держит fd открытым до ACK и только после успешного
  `protect()` сохраняет сокет для будущего async handshake; reject переводит shadow-core в
  `Failed`, а stop/free закрывают pending/protected fd. Вторая event-очередь или callback не
  добавлялись.
- Android `VpnService` подключён к текущему ABI 1.4 в shadow-режиме через generation-safe JNI
  adapter: каждый запуск создаёт общий Rust `ClientCore`, прогоняет экспортированный flat-INI
  через strict parser, переводит lifecycle в `Connecting` и гарантированно выполняет
  stop/free при teardown. Временные UTF-8 byte arrays с паролем обнуляются по обе стороны
  JNI. Kotlin теперь через тот же замороженный C ABI опрашивает единственную bounded event
  queue и при старте проверяет реальные `Created → Connecting`: JNI кодирует фиксированный
  48-байтный little-endian header, сохраняет двухпроходную семантику «малый буфер не
  потребляет событие» и ограничивает payload 1 МиБ. Adapter проверяет ABI 1.5 и обязательные
  capability bits, заявляет `TUN_FD` и выполняет generation-scoped network-plan handoff, но
  пока не подключает/не использует открытый core wire socket и не читает пакеты:
  проверенный Kotlin data plane остаётся единственным владельцем payload до общего packet pump.
  Все Android native build scripts теперь включают
  `transport-core-ffi`, а основной сборщик требует для arm64/x86_64 ровно 6 прежних RealTLS,
  15 whole-client C и 14 `TransportCore` JNI exports. Проверено 84/84 JVM-тестами и
  debug/release-minify APK.
- Общие handshake building blocks больше не скрыты в Linux-клиенте: строгий разбор недоверенного
  `AuthOK`, effective MTU, server-proof/static-session проверка и AUTH plaintext вынесены в
  `transport_core::session`. Device ID передаётся в AUTH builder явно, чтобы Android runtime
  использовал существующий persisted ID, а не создавал вторую identity.
- Ядро больше не может считать туннель запущенным сразу после handshake: план адреса, MTU,
  маршрутов, DNS и kill-switch переводит его в `AwaitingNetwork`, а переход в `Running`
  требует ACK платформы с той же generation. Отказ платформы переводит соединение в
  `Failed`, то есть неподдержанная защитная настройка не может быть принята молча.
- Linux-клиент стал первым реальным адаптером общего lifecycle API: конфигурацию разбирает
  `ClientCore`, TCP и UDP после handshake публикуют один generation-scoped `NetworkPlan`,
  платформа поднимает TUN/маршруты/DNS и лишь затем подтверждает план. Каждая новая сессия и
  reconnect проходят через `Created/Stopped → Connecting → AwaitingNetwork → Running`, а
  очередь событий опрашивается тем же способом, который предусмотрен для внешнего C ABI.
- Формат плана уточнён по результатам первого адаптера: маршрут несёт не только CIDR, но и
  gateway/metric, DNS — address/port, отдельно передаётся tunnel gateway. Ошибка обязательного
  pushed/include/local/custom route или применения непустого DNS-плана больше не оставляет
  «частично работающий» туннель: generation отклоняется и сеть откатывается. Пустой DNS-план
  по-прежнему сохраняет системный resolver, поэтому профиль без DNS push не ломается.
- Общий fd-backed TUN backend стал первым data-plane срезом ядра и теперь собирается для Android:
  TCP и UDP Linux-клиента больше не содержат
  две копии `libc::read/write/close`, а используют один bounded packet pump, который владеет
  `OwnedFd`, reader/writer workers, TAP framing и явным shutdown. Ошибочный выход поднимает
  общий stop token, а штатный teardown ждёт освобождения обоих fd. После положительного plan ACK
  ядро one-shot передаёт packet workers два собственных дескриптора (read/write); Android ещё не
  включает этот handoff. Handshake/codec пока остаются прежними, поэтому формат провода не изменён.
- Uplink TUN reader больше не создаёт новый `Vec` для каждого пакета. Он читает в заранее
  выделенный пул размером не более 4 МиБ на соединение, передаёт `TunPacket` без копии через
  TCP flow distributor или UDP encrypt path и возвращает allocation через `Drop` сразу после
  формирования wire record — до pacing/socket await. Исчерпание пула создаёт backpressure,
  а не скрытую fallback-аллокацию. Пять packet/lifecycle тестов проверяют TUN, TAP, memory
  budget, bounded idle shutdown и повторное использование того же буфера после исчерпания пула.
- Uplink wire record также больше не требует нового `Vec` на каждый пакет: новый
  `PacketCodec::encrypt_packet_into` пишет в caller-owned storage и оставляет capacity у
  последовательного TCP/UDP writer. Rust-клиент выделяет два record-буфера один раз на
  соединение (реальный пакет и cover, который может уйти раньше него); UDP-QUIC так же
  переиспользует отдельный caller-owned envelope. Старые allocating entry points сохранены для
  handshake/control и совместимости, а три теста подтверждают байт-в-байт прежний wire format,
  reuse allocation и очистку stale record после ошибки.
- Normalization и padding также переведены на caller-owned storage. Клиентские TCP/UDP writers
  переиспользуют отдельные scratch-буферы для нормализованного пакета и padding реального,
  cover и heartbeat-трафика; сервер переиспользует padding в TCP/UDP handlers и общем
  server→client forwarder. Совместимые allocating-обёртки сохранены для негорячих путей. Два
  теста проверяют сохранение capacity, очистку stale padding и неизменность исходного префикса
  после normalization; wire format не изменён.
- Исходящие зашифрованные records сервера теперь также ограничены RAII-пулом не более 4 МиБ
  на аутентифицированную сессию. Вместимость слота рассчитывается из реального максимума
  `tun.mtu`, heartbeat и traffic shaping конкретного профиля, а не из абсолютного wire-предела:
  при MTU 1400 это 2 906 слотов вместо 251. Один пул разделяют все bonded TCP-потоки; до
  успешного AUTH он не выделяется, поэтому half-open TCP/UDP-сессии не расходуют бюджет.
  Общий forwarder шифрует сразу в pooled storage, точный предварительный расчёт record size
  запрещает `Vec` незаметно вырасти сверх лимита, а bounded writer-очередь сохраняет владение
  до фактической записи в сокет. Исчерпание даёт учитываемый drop без fallback-аллокации.
  Recycling переведён с async mutex + mpsc на короткий общий stack + semaphore; это вернуло
  fake-TLS download из диапазона 605–638 к 680–702 Мбит/с. Тест проверяет точный memory budget,
  исчерпание и возврат того же allocation после `Drop`; формат провода не изменён.
- Серверный client→TUN путь больше не проходит через две очереди и async bridge. Dedicated
  TUN writer читает исходную bounded Tokio-очередь напрямую через `blocking_recv`; stop-флаг
  с wake-пакетом сохраняет ограниченный teardown. Промежуточная 256-слотовая очередь сбрасывала
  bursts: диагностический UDP-прогон при 400 Мбит/с показал 164 потерянных iperf-пакета и ровно
  164 внутренних drop. После удаления bridge прикладные session drops равны нулю.
- Тот же client→TUN путь больше не выделяет plaintext `Vec` на пакет. TCP получает slot из
  отдельного 32-МиБ пула до socket read, читает framing прямо в него, расшифровывает на месте и
  передаёт allocation через исходную очередь до фактической TUN write. UDP берёт slot без
  ожидания, копирует в него borrowed record и также расшифровывает in-place; исчерпание пула
  даёт учитываемый в `DROPS` datagram drop без fallback allocation и без остановки heartbeat loop.
- Обратный server TUN→client путь больше не делает `raw.to_vec()` на каждый пакет. Все TUN
  queues профиля читают прямо в общий RAII-пул с целевым бюджетом 32 МиБ и минимум одним slot
  на очередь; allocation проходит lookup/ACL/MTU/шифрование и возвращается после forwarder.
  Исчерпание останавливает следующий kernel read (backpressure), не создаёт fallback allocation
  и не сбрасывает уже прочитанный пакет; отдельный shutdown signal будит reader, ожидающий pool.
  UDP receive loop также передаёт исходный datagram как borrowed slice, а QUIC unwrap возвращает
  borrowed payload: две промежуточные per-datagram копии удалены. Тест закрепляет расчёт бюджета
  для стандартного 64-КиБ buffer и крайнего числа очередей; wire format не изменён.
- Downlink codec теперь расшифровывает record **на месте**: `decrypt_packet_in_place` удаляет
  framing/nonce/counter/padding/tag внутри исходного `Vec`, а TCP inline/pipeline и UDP client
  передают тот же allocation в TUN writer. При ошибке буфер очищается без потери capacity;
  replay counter по-прежнему фиксируется только после успешных AEAD и padding-проверок. Два
  новых теста проверяют TLS/raw reuse и fail-closed очистку. Это убирает второй plaintext `Vec`
  на каждый downlink-пакет; входной record теперь предоставляет bounded pool.
- Downlink record больше не выделяется на каждый пакет. Общий RAII-пул ограничивает суммарную
  запрошенную capacity 4 МиБ на Linux connection generation: 251 слот вместимостью
  `TLS_RECORD_HEADER + MAX_RECORD_SIZE`. `read_record_into` читает TCP framing прямо в выданный
  слот, а borrowed `unwrap_quic_payload` копирует UDP-QUIC payload без промежуточного `Vec`.
  Allocation остаётся pooled через decrypt, reality pipeline и очередь TUN writer и возвращается
  только после записи либо drop. При исчерпании TCP применяет backpressure до чтения следующего
  record, а UDP сбрасывает datagram, не блокируя heartbeat/liveness `select!`; fallback allocation
  не создаётся. Шесть новых lifecycle/parser тестов проверяют жёсткий предел, повторное
  использование allocation, возврат после TUN write, partial-body EOF и borrowed QUIC view.
- Новый C ABI для остальных клиентов пока включается отдельно через `transport-core-ffi`.
  Feature теперь семантически включает `client`, поэтому минимальный Linux ABI profile
  компилирует реальный whole-client transport и не превращает его API в ложный `dead_code`.
  CI отдельно тестирует ABI, собирает минимальный cdylib без default-features с обязательным
  `panic=unwind` и запускает для этой конфигурации clippy.
- Временная копия пароля и obfs PSK, возникающая при разборе `qeli://`, очищается сразу после
  переноса в конфигурацию ядра; при освобождении handle ядро также zeroize-ит хранимые пароль,
  password-command и obfs PSK.
- Штатные lab-helper’ы синхронизируют вместе с Rust-кодом публичные C-заголовки, проверяют
  SSH host key через общий hardened policy и возвращают настоящий код `cargo test`, не код
  завершающего `tail`. Лабораторная проверка больше не может незаметно пройти на смешанном
  дереве или замаскировать упавшие тесты.
- Network-namespace e2e больше не исчерпывает production pre-auth limiter собственными
  многократными reconnect-сценариями, а трёхрежимный sanity на время теста останавливает
  штатную systemd-службу: временный сервер не сталкивается с её портом/TUN после respawn.
  Ожидание TUN в multi-instance kill-switch сценарии опрашивает интерфейс каждые 100 мс,
  поэтому тест не пропускает его короткое существование перед намеренным отказом от уже занятой
  другим экземпляром full-tunnel `/1` route и не даёт ложный красный результат.
- Benchmark/sanity теперь отказываются запускать UDP-тест при `net.core.rmem_max` ниже
  запрошенных qeli 4 МиБ, показывают потери/пакеты и дельты kernel receive-buffer и session
  drops для каждой ступени. `list-clients` выводит существовавший в control API счётчик `DROPS`,
  а sanity принимает список режимов для короткого целевого повтора. Installer и lab/deploy
  helpers согласованно задают `rmem/wmem_max = 16 МиБ`, defaults 4 МиБ и backlog; это устраняет
  прежний фактически выданный UDP receive buffer 208 КиБ.
- Общий atomic writer явно учитывает отсутствие Unix mode bits на Windows, поэтому
  Windows native-core cross-build проходит без ложного `unused variable` warning.

### Безопасность — транспорт и межплатформенный протокол

- WebSocket-маскировка теперь использует стабильный путь, полученный из PSK через
  HKDF-SHA256. Сервер отвечает `101` только на правильный путь, а остальные запросы получают
  обычный nginx-подобный `404` с корректным `Date`. Это убирает активный признак qeli и
  синхронизировано между Rust, Android, iOS и C#.
- Во всех WebSocket-портах добавлены корректные Pong-ответы, ограничение очереди управляющих
  кадров и лимиты pre-auth чтения. Исправлен Rust write-path, который мог вернуть `Ok(0)` при
  ожидающем Pong и оборвать рабочий туннель. Android больше не принимает кадры в 64 раза
  крупнее предела отправителя, а `Host` согласован с адресом подключения или настроенным SNI.
- Android и C# больше не кодируют «окно replay ещё не инициализировано» отрицательным
  счётчиком. Значения `u64` с установленным старшим битом сравниваются без знака и не могут
  отключить replay-защиту. В общий conformance-набор добавлены векторы для `2^63` и
  `2^64 - 1`.
- Kotlin и C# теперь кодируют QUIC varint в минимальной форме и не обрезают длину молча;
  генератор cover-трафика C# использует системный CSPRNG вместо предсказуемого
  `System.Random`.
- Рукописный TLS отклоняет X25519 low-order points и записи больше лимита RFC 8446 как в
  handshake, так и после него. FFI-сборки получили обязательную feature-проверку
  `ffi-cdylib`: release-библиотека не соберётся с `panic=abort`, при котором `catch_unwind`
  не защищает Android, Windows, macOS и iOS от удалённого падения процесса.

### Безопасность — клиентские политики и локальная система

- Android исполняет `allow_unpinned_tofu = false` и отказывается от неприкреплённого ключа.
  `kill_switch = true` теперь является полноценной fail-closed политикой: профиль проходит
  round-trip без потери, а подключение возможно только при проверенном системном Always-on VPN
  lockdown, который продолжает блокировать трафик после падения процесса и при реконнекте.
- Импорт профилей Windows/macOS теперь запускает семантическую валидацию. C# больше не
  превращает повреждённый или укороченный pin в TOFU, а ссылки `reality-tls`/`obfs` без
  обязательных параметров отклоняются на границе импорта.
- Сервер не может расширить split-tunnel клиента до default route или вернуть через push
  диапазон, который пользователь исключил. Проверка действует в Rust и Android; генерация
  share-link больше не заявляет `reality-tls`, когда reality proxy выключен.
- systemd-resolved получает catch-all домен `~.` для `dns = tunnel`; серверный DNS push в
  split-tunnel принимается только для адреса, достижимого внутри туннельной сети. Запуск
  второго клиента больше не откатывает DNS живого первого туннеля.
- Валидируются размер TUN-буфера и его соответствие MTU. Конфиг с открытыми правами получает
  предупреждение, стабильный device id создаётся с режимом `0600`, а TUN-дескрипторы
  дублируются с `CLOEXEC` и не утекают в hooks/iptables/resolvectl. Signal teardown получает
  тот же hook environment, что и обычное завершение; poisoned mutex восстанавливается с
  предупреждением вместо каскадной паники.
- Trust-check hook-конфига открывает файл с `O_NOFOLLOW`, проверяет дескриптор и не следует
  подменённому symlink. CLI получил `add-client --password-stdin` и
  `set-web-password --password-stdin`, чтобы секреты не попадали в argv, `/proc`, shell
  history и auditd.

### Безопасность — сервер, DHCP и изоляция сессий

- DHCP по умолчанию привязывается к адресу TUN-профиля, а явный wildcard bind отклоняется.
  Публичный `giaddr` больше не превращает сервер в отражатель; DISCOVER резервирует адрес на
  30 секунд вместо суток, а stale lease сверяется с общим пулом перед повторным ACK.
- DNS-прокси создаёт новый случайный upstream transaction id и проверяет не только id, но и
  question ответа до кэширования, закрывая межпользовательское отравление общего кэша.
- IPv4-only source guard теперь fail-closed для IPv6 и коротких пакетов. Client isolation
  учитывает не только pool IP, но и подсети `iroute`; освобождение адресов при TCP/UDP
  eviction выполняется под тем же lock, что и следующая аллокация, поэтому две живые сессии
  больше не получают один tunnel IP.
- Replay старого UDP AUTH не продлевает сессию бесконечно. Нулевые параметры pre-auth rate
  limiter отклоняются, TUN-очереди сервера получают `CLOEXEC`, DHCP collision/preflight
  используют фактический bind, а reality ClientHello parser покрыт hostile-input тестами на
  отсутствие panic и бесконечного цикла.
- Публичный пример `users.conf` содержит намеренно непригодный Argon2id hash, чтобы копирование
  sample-конфига не создавало учётную запись с опубликованным паролем. Sidecar lock-файлы
  открываются без symlink-follow, проверяются как single-link regular files и меняют владельца
  через `fchown` уже проверенного дескриптора.

### Безопасность — web-панель и backup

- Ключ обратимого шифрования пользовательских паролей перенесён из `/etc/qeli` в
  `/var/lib/qeli`: незашифрованный backup больше не содержит одновременно ciphertext и ключ.
  Старый ключ читается и безопасно мигрирует без потери существующих `password_enc`.
  Русская и английская документация backup/restore теперь явно различает панельный архив
  `/etc/qeli` и полный ручной backup с `/var/lib/qeli`, включая последствия потери ключа.
- Logout увеличивает персистентное поколение сессий и отзывает все выданные cookies, а не
  только удаляет cookie текущего браузера. Добавлены тесты подписи, срока действия, смены
  пароля, passwordless-режима, TTL clamp и constant-time сравнения.
- CSRF-проверка loopback origin требует совпадения порта. Restore использует реальный путь
  запущенного server config и дополнительно ищет все `/etc/qeli/...` ссылки в hook-командах,
  не позволяя backup перезаписать код, который затем выполнится с повышенными правами.

### Безопасность — Windows и macOS

- Windows запускает `netsh`, `route`, `schtasks` и PowerShell только по абсолютным путям из
  System32. Установка LocalSystem-сервиса проверяет DACL бинарника и всех родителей, а native
  DLL при elevated-запуске извлекается в защищённый `%ProgramData%`, не в пользовательский
  `%LOCALAPPDATA%`.
- URL обновления принимается только как HTTPS на хосте проекта, поэтому удалённый JSON не
  может передать ShellExecute произвольную схему, UNC или чужой домен.
- macOS root daemon проверяет владельца и mode каталога состояния и файла handoff. Ошибка
  AES-GCM tag больше не трактуется как legacy plaintext ни для профилей GUI, ни для daemon
  profile: повреждённый или подменённый ciphertext отклоняется и не пере-зашифровывается как
  доверенный.
- macOS сохраняет исходные DNS физического network service в атомарном root-only journal до
  вызова `networksetup`. После SIGKILL/native crash следующий привилегированный запуск
  восстанавливает DNS до подключения, не принимает оставшийся tunnel resolver за исходный,
  не откатывает DNS живого второго процесса и сохраняет более новое ручное изменение.

### Установка, обновление, OpenWrt и сборка релиза

- Installer начинает с `umask 077`, удаляет временные `.deb` и распакованные деревья при
  любом выходе и передаёт сгенерированные пароли через stdin. Updater перенёс rollback cache
  из доступного сервисному пользователю `/var/lib/qeli/packages` в root-only
  `/var/cache/qeli`, проверяет owner/type/mode и не следует symlink.
- OpenWrt init-script проверяет имя интерфейса перед изменением firewall UCI. ACL LuCI явно
  документирует, что общий `setInitAction` управляет всеми init scripts и не является
  least-privilege разрешением только для qeli.
- Android CI проверяет целостность Gradle wrapper. Все штатные FFI-build scripts включают
  `ffi-cdylib` и `panic=unwind`; Python-скрипты сборки на лабе проверяют SSH host key и
  требуют явного `QELI_LAB_TRUST_NEW_HOST=1` только для первичного доверия новой VM.
- Финальные нативные ядра Android, Windows и macOS пересобраны из одного source digest
  0.7.15 с ABI 1.10 и полным набором 6 Reality + 20 ClientCore экспортов (Android также 17
  JNI). Независимые A/B-пары побайтно совпали на обеих лабах; canonical/consumed copies,
  `native-libs/SHA256SUMS`, machine-readable evidence и source provenance синхронизированы.
  Финальный повторный прогон 2026-08-13 закреплён за clean source commit `508da77` и digest
  `71a08ebb…`: Android arm64/x86_64, Windows x64 и macOS universal2 снова прошли A/B gate.
  OpenWrt feed финально закреплён на `df03094`, а `PKG_MIRROR_HASH=e6d5f45b…`
  получен из version-specific tarball настоящего OpenWrt SDK 23.05.5; отдельные OpenWrt
  aarch64/x86_64/mipsel/armv7 и Keenetic aarch64/mipsel cross-build матрицы прошли полностью.
- Native build-процесс больше не может сертифицировать случайный или однократный результат.
  Оба lab-скрипта требуют чистый закоммиченный Rust source, сами синхронизируют его на `.10`/
  `.11`, проверяют закреплённые Rust/Zig/NDK/cargo-ndk, строят `--locked` двумя независимыми
  проходами с `SOURCE_DATE_EPOCH`, path remap и отключённым incremental, сравнивают A/B SHA256
  и полный набор экспортов и лишь затем атомарно заменяют обе копии библиотек. Для desktop и
  Android записывается machine-readable evidence; `provenance.py --update` теперь fail-closed
  отклоняет обновление, пока evidence обеих лаб не совпадает с source digest и финальными
  файлами. Живой A/B-прогон всех четырёх библиотек выполнен, release gate зелёный.
- Общая чувствительная часть этих рецептов больше не продублирована: единый fail-closed
  lab-harness владеет SSH/SFTP, ограниченным source-sync, удалённым SHA256 и атомарной заменой
  canonical/consumed copies. Отдельная общая оркестрация всегда запускает оба чистых прохода
  `a`/`b`. Тридцать пять локальных/CI-тестов проверяют в том числе отказ до любой записи при
  подмене SFTP payload, запрет пути назначения вне репозитория и невозможность незаметно
  превратить A/B-рецепт в однократную сборку.
- Контракт конфигурации после унификации транспорта закреплён исходниковым тестом: Rust,
  Android, Windows, macOS и iOS распознают один и тот же набор из 73 ключей. Платформенные
  различия сохранены явно: UI моделирует только применимые поля, остальные валидные ключи
  переносит без потери при open/save. После Android lockdown-интеграции в общей схеме не
  осталось ни одного молча неподдерживаемого security-key: `kill_switch` моделируется и
  подтверждается только при фактически включённой системной защите.
- Воспроизводимый desktop-рецепт дополнительно закрепляет cargo-zigbuild 0.23.0, GNU ld 2.44
  и apple-codesign 0.29.0. Для macOS исправлены два источника недетерминизма Zig 0.13:
  pass-specific `LC_ID_DYLIB` заменён на `@rpath/libqeli.dylib`, content-derived `LC_UUID`
  и стандартный `LOCAL` GOT-index выставляются до детерминированной ad-hoc подписи. Строгий
  структурный gate отклоняет неизвестные indirect symbols и неполную подпись universal2.
- Lab-рецепты идемпотентно устанавливают точные Rust targets и после сохранения каждого
  конечного артефакта освобождают его Cargo target-кэш. Это позволило выполнить независимый
  desktop A/B-цикл на `.10` с 2,2 ГБ свободного места без изменения `/opt/qeli-src/target`.
- Живой Android ABI 1.9 e2e на эмуляторе после перезагрузки лабы прошёл пять вариантов:
  TCP fake-TLS/plain/obfs и UDP fake-TLS/obfs. Во всех случаях Rust применил полный
  `NetworkPlan`, клиент вывел MTU, DNS, routes, padding, heartbeat, normalization, shaping и
  multipath, а обратный ping дал 3/3 и 0% потерь. E2E сам поднимает штатный AVD и восстанавливает
  исходные server/users config побайтно. Windows ABI 1.9 live-handshake отдельно подтвердил
  тот же журнал и выдачу tunnel IP.
- Android source-sync больше не делает отдельный SSH `mkdir` для каждого файла, а macOS
  universal packager подписывает и проверяет все Mach-O одной удалённой транзакцией. Оба
  изменения сокращают время локальной release-оркестрации без ослабления fail-closed gate.
  Неизменившиеся крупные macOS self-contained tar.gz повторно используются на лабе только
  после сравнения с локальным SHA256, а не загружаются заново по медленному SFTP. Итоговый
  артефакт тоже не скачивается, если его verified remote SHA256 уже совпадает со всеми
  локальными назначениями.
- Wrapper validation обновлён на актуальный SHA официального `gradle/actions@v4`: прежний
  pin не знал checksum штатного Gradle 9.6.1 JAR и делал Android CI красным до начала
  сборки. Windows release-рецепт теперь использует отдельные publish-каталоги и
  переименовывает только итоговые EXE; глобальный `AssemblyName` наследовался проектом
  `QeliShared` и останавливал restore с `Ambiguous project name`.
- Русская и английская документация обновлены под новые параметры, права файлов, поведение
  сессий, импорта профилей, DNS/routes и безопасные процедуры установки/эксплуатации.
- Единый двуязычный `CONTRIBUTING.md` — сначала на английском, затем на русском — теперь
  пошагово описывает подготовку PR: разработка от `dev`, отдельная ветка и логические
  DCO-коммиты, rebase, локальные проверки, выбор base/compare на GitHub, содержимое test plan
  и требования к происхождению сторонних бинарников. CHANGELOG и пользовательская
  документация для автора PR прямо отмечены как добровольные — при необходимости их
  дополняет мейнтейнер перед релизом.
- Канонический логотип приложения вынесен в общий каталог `assets/branding`, добавлен в
  главный GitHub README, а для карточек ссылок подготовлен фирменный Social Preview
  1280×640. Общий ассет совпадает с уже используемым iOS-логотипом и визуальным знаком
  Windows, macOS, Android и web-панели.

## [0.7.14] — 2026-08-03

### Исправлено — редактор профиля мог загнать в тупик и терял режим DNS

Правка числа через форму не снимала пометку об ошибке. `port = bad` помечает профиль
невалидным; пользователь исправлял порт в том самом поле, которое диалог и предлагает,
жал «Сохранить» — а пометка переезжала в новый объект нетронутой, и `Validate()` продолжал
отвергать уже правильный профиль. Выхода из UI не было.

Для булевых это было закрыто раньше — вычитанием того, что форма реально задаёт. Числа
переносились целиком. Теперь так же: вычитаются `server (port)`, `mtu`, `padding_min/max`,
`heartbeat_interval/jitter`. Остальные (`timeout`, `reconnect_*`, `lport`, `metric`,
`heartbeat_size`, `shaping_*`) контролов в форме не имеют, и их пометки обязаны выживать —
иначе вернётся ровно та «отмывка» опечаток, которую и чинили в прошлый заход.

Второе: форма правит список DNS-серверов, но сохраняла прежний `dns_mode`. Один ключ — два
смысла (`dns = off` это РЕЖИМ, `dns = 1.1.1.1` — список), поэтому в профиле с `dns = off`
введённый адрес сохранялся, показывался в интерфейсе и не применялся. Непустой список теперь
переводит режим в `tunnel`; пустой оставляет режим как был, так что сохранение профиля с
`dns = off`, где DNS не трогали, по-прежнему не включает публичный резолвер.

### Исправлено — cover-пакет мог обогнать AuthOK и сорвать UDP-подключение

Сессия помечалась `Authenticated` до отправки AuthOK: `handle_udp_auth` уходит в `tokio::spawn`
(чтобы Argon2 не вешал воркер), ставит состояние — и только потом берёт пул, проверяет
`max_clients` и программирует маршруты. Цикл `select!` всё это время работает, поэтому тик
heartbeat или shaping попадал в окно, видел «живую» сессию и писал в сокет **первым**.

Клиент с этим не справляется: он принимает за AuthOK первый успешно расшифрованный record.
Cover расшифровывается идеально — в **пустой** payload, — после чего разбор `OK:` падает и
подключение умирает. На фрагментированном AuthOK лишняя датаграмма вдобавок сбрасывает сборку.
Окно короткое против 15-секундного маяка, но случайный отказ UDP-авторизации с петлёй
реконнекта — ровно тот сорт редкости, который никогда не диагностируют.

Заведён флаг `auth_ok_sent`, который ставится **после** отправки; оба цикла его требуют.

Одного этого мало: флаг говорит «отправили», а не «доставили», а UDP теряет и переставляет
датаграммы — AuthOK может пропасть, и придёт следующий за ним маяк. Поэтому **все четыре**
клиента перестали принимать пустой plaintext за ответ и продолжают ждать. Механизм
восстановления уже был: цикл ретрансмита пересылает AUTH, а сервер по байт-идентичному AUTH
переотправляет AuthOK — клиенты просто выходили из этого цикла на первом же расшифрованном
record. Пропускается именно **пустое**, а не «всё, что не `OK:`»: непустой отказ сервера обязан
падать сразу, иначе он превратится в зависание до дедлайна.

> **Не входит в релиз, но требует проверки перед деплоем.** Локальные снимки
> `release/prod-server-allmodes.conf` и `release/prod-maxobf-migrated.conf` (оба в `.gitignore`,
> в пакет не попадают) включают `reality_proxy` без `short_ids` — новая валидация такой профиль
> отвергает, и сервер на них не поднимется. Файлы намеренно не правились: они отражают то, что
> крутится на проде, и подгонка снимка под новые правила эту информацию потеряет.

### Исправлено — поставляемый пример клиента не мог подключиться

`client.conf` документирует `key = 0000…0` как TOFU («Empty / all-zero = TOFU»), но разбор
отфильтровывал только пустую строку. Нули становились настоящим пином, `verify_server_key`
сверял с ними реальный ключ сервера — и любая копия поставляемого примера падала на первом же
подключении с «SERVER KEY MISMATCH — possible MITM attack!». Это и неверно, и худший из
возможных способов быть неверным: сообщение обвиняет сеть в атаке. C#-порт всегда читал этот
случай правильно.

Побочно закрылась дыра в добавленной проверке: `mode = reality-tls` требует пин, но all-zero
проходил как «непустой». Теперь он превращается в TOFU на разборе, и проверка ловит его сама.

### Исправлено — панель объявляла «сервер поднят», пока data-plane падал в цикле

`restartServer()` возвращал успех по `d.ok`, а `ok` в `/api/status` — константа `true`: она
означает «панель ответила», а не «сервер работает». Занятый порт, ошибка TUN или конфликт
маршрута оставляли worker в respawn-петле, и панель писала «server is live» поверх туннеля,
который не поднялся. Теперь ждём `worker_ok`; цикл и так ограничен дедлайном, так что вместо
ложного «да» приходит честное «нет».

### Исправлено — `obf.mode` для REALITY был этикеткой, которую ничего не проверяло

Рантайм выбирает REALITY-путь по `reality_proxy.enabled`, настоящий TLS — по `real_tls`, а
`obf.mode = reality-tls` не включает **ничего**. Поэтому профиль с выключенным `reality_proxy`
спокойно стартовал, называл себя reality-tls в логах и в панели и клал на провод обычный
fake-TLS: оператор считает, что включил самую сильную маскировку проекта, и не имеет её.
Теперь такой профиль отвергается по имени причины.

`real_tls = false` при `mode = reality-tls` — предупреждение, а не отказ, и асимметрия
намеренная: это связка «REALITY-токен + fake-TLS внутри», её шиппящиеся примеры пишут как
`obf.mode = fake-tls`. Имя преувеличивает, но не врёт о том, что работает, а отказ уронил бы
существующий сервер при обновлении из-за соглашения об именовании.

Отвергаются и две заведомо инертные комбинации: `reality_proxy.enabled` с `obfs`/`plain`
(REALITY читает TLS ClientHello, которого эти режимы не шлют) и на UDP (датаграммный путь его
не несёт). В обоих случаях профиль объявлял устойчивость к активному зондированию, которой нет.

### Исправлено — клиентские валидаторы принимали профили без обязательных секретов

`mode = reality-tls` без `reality_sid`, без корректного `reality_sid` или без закреплённого
ключа сервера, и `mode = obfs` с пустым `obfs_key` — всё это проходило проверку во всех
четырёх клиентах, а падало посреди рукопожатия, где выглядит как проблема сервера или сети,
а не как незаполненное поле.

Самый острый случай — short_id: клиенты парсят hex **снисходительно** (не-hex символы
отбрасываются), сервер — **строго**. `reality_sid = deadbeeg` превращался в другой токен на
клиенте и не совпадал ни с чем на сервере. Отказ от некорректного значения — единственный
способ, которым две стороны могут согласиться о том, что было настроено.

### Исправлено — заголовок fake-TLS проверялся не полностью

Декодеры сверяли `content_type = 0x17` и длину, но не `legacy_record_version`. Все четыре
порта пишут `0x03 0x03`, и настоящий TLS 1.3 на установленном соединении не шлёт ничего
другого, — то есть маскировочный фрейминг был слабее того, что он изображает, без всякой
выгоды. Полезная нагрузка и так под AEAD; исправлено ровно то, что заголовок оставался
единственной частью записи, которую можно было переписать.

### Исправлено — клиенты принимали запрещённые сочетания transport/mode

`proto` и `mode` проверялись каждый по своему списку и никогда — вместе, во всех четырёх
клиентах. Поэтому `udp` + `reality-tls` проходил валидацию, хотя сервер такой профиль
отвергает: клиент не мог подключиться ни к одному рабочему серверу и падал позже и невнятнее.

Опаснее вторая половина: в названии `reality-tls` ничего не говорит про TCP, поэтому оператор
считает, что включил самую сильную маскировку, а датаграммный путь тихо сваливается в
fake-TLS-фрейминг. То же для `plain` — у сырого фрейминга нет датаграммной формы.

Комментарий на сервере утверждал, что «iOS-клиент уже отвергает оба сочетания». Это было
неверно ни для одного клиента. Теперь отвергают все четыре; фикстура
`roundtrip_fixture_client.ini` переведена на `proto = tcp` — она несла ровно эту пару.

### Исправлено — Quick Start строил заведомо нерабочий профиль после сбоя запроса

При недоступности `/api/config/defaults` панель собирала профиль на пустом скелете без секции
`performance`. Производные умолчания давали `max_clients = 0` и `handshake_timeout_secs = 0` —
такой профиль сервер отвергает гарантированно. То есть один неудачный запрос превращал Quick
Start в кнопку, которая собирает, сохраняет и получает отказ, ничем не указывая на причину.

Скелет убран: без канонических умолчаний профиль не собирается. Добавлены повторная попытка
при инициализации и отказ до диалога подтверждения — прежде оператор успевал подтвердить
перезапуск сервера. Прописывать числа литералами в шаблоне было бы хуже: это раздвоило бы
единственный источник умолчаний, и он бы разъехался.

### Исправлено — тест примеров конфигурации не проверял, что они запускаются

`config_examples.rs` разбирал файлы и сверял непрочитанные ключи, но не звал
`validate_profiles`. А `from_ini` говорит лишь о том, что файл синтаксически цел; все правила
о том, может ли профиль **работать** (REALITY без `short_ids`, `plain`/`reality-tls` на UDP,
нулевой `max_clients`, слишком длинное имя TUN), живут в валидации. Пример, который
разбирается и отказывается стартовать, — худший вид зелёного CI, потому что пример именно и
копируют.

Заодно список GUI-ключей в тесте оказался копией, отставшей от оригинала: в нём осталось шесть
имён против двадцати двух. Комментарий «держите два списка синхронными» — это и есть механизм,
которым такое расхождение возникает; тест теперь берёт настоящий `GUI_ONLY_CLIENT_KEYS`.

Охват расширен: добавлен `server-maxobf.conf` — эталон максимальной обфускации, который
шиппился и не проверялся ни разу, хотя именно его копирует оператор во враждебной сети и
именно он задействует связку REALITY, которой нет в остальных примерах. Шаблон
`release/reality-tls/server-reality.conf` закреплён с обратным знаком: он **обязан** не
проходить валидацию, пока в нём стоит `REPLACE_WITH_OWN_SHORT_ID`, — short_id это секрет
конкретной установки, и общий short_id не секрет вовсе.

Комментарии про «9 режимов» в шаблоне мультипрофиля, в Quick Start и в `postinst` исправлены
на 10 — режимов ровно столько и в файле, и в панели.

### Исправлено — карточка защиты выдавала присланные маршруты за установленные

Число маршрутов на карточке бралось из того, что **прислал сервер**, а не из того, что
**встало в интерфейс**. Расходятся эти числа всегда, когда маршрут не удалось поставить:

- на Android `addCidrRoute` глотал исключение в лог и возвращал `Unit`, поэтому вызывающий
  тут же печатал `-> APPLIED` — две строки подряд, «bad route …» и «применён», и верят второй;
- на iOS `compactMap` молча выбрасывает всё, что не превратилось в `NEIPv4Route`, а счётчик
  считал исходный массив;
- факты публиковались **до** создания TUN: на Android `logServerPush` вызывается перед
  `setupTunInterface`, то есть карточка описывала намерение как состояние устройства.

Теперь `addCidrRoute` возвращает `Boolean`, `applyPushedRoutes` — число реально принятых,
`APPLIED` печатается только когда builder маршрут взял, а счётчик публикуется после
`establish()` (iOS — после построения настроек). Расхождение выносится в лог предупреждением
и в строку карточки: «установлено N из M». Отдельное значение `-1` означает «ещё не
устанавливали» — иначе нормальный момент подключения выглядел бы как отказ.

Это единственное направление, в котором карточка защиты не имеет права ошибаться: не
поставленный маршрут — это трафик **вне** туннеля.

### Исправлено — ручной редактор конфига «отмывал» опечатку

«Ручная правка» в десктопных клиентах открывает результат `BuildFromForm().ToIni()`, а `ToIni`
печатал значение, которым порт **в итоге воспользовался**. Для битой строки это умолчание:
`reconnect_base_delay = bad` возвращался как `= 1`, а `gatway = true` не возвращался вовсе.
Человек открывал диалог, своей ошибки там не видел, жал OK — и повторный разбор давал чистый
конфиг, потому что улику выбросили по дороге. Строка исчезала из профиля, настройка
оставалась на умолчании, которое никто не выбирал.

Теперь сырой текст непринятых значений хранится (`InvalidRawValues`) и переиздаётся в `ToIni`
последним, **заменяя** строку ключа, а не дописывая вторую (иначе парсер сообщил бы о дубле —
вторая, выдуманная претензия поверх настоящей). Круг «открыл → OK» сохраняет обе пометки, а
исправление строки руками — то, ради чего диалог и существует, — их снимает.

Нужно это только здесь: Android и iOS хранят профиль **текстом**, и их редактор показывает
файл автора; десктоп хранит объект, поэтому показывает пересборку.

### Исправлено — heartbeat и shaping не проверялись по диапазону на Android и iOS

`heartbeat_interval = -1` разбирался без замечаний и полностью выключал keepalive, тогда как
строкой выше `heartbeat = true` продолжал утверждать обратное. Это хуже и отказа, и честного
`heartbeat = false`: профиль обещает keepalive, которого нет, а соединение умирает на первом
же простое NAT — и указать не на что. То же самое у всех `shaping_*`: это длительности и
размеры, ноль или минус там не настройка. Диапазоны взяты те же, что уже применяет C#.
Границы `heartbeat_jitter` и `heartbeat_size` — от нуля: отсутствие джиттера и пустая нагрузка
это осмысленный выбор, в отличие от нулевого интервала.

### Исправлено — задержка реконнекта могла убить сам цикл реконнекта

`reconnect_base_delay` / `reconnect_max_delay` принимались вплоть до `long.MaxValue`, а
десктопный клиент ждёт через `WaitHandle.WaitOne(int)`: всё, что больше `int.MaxValue`
миллисекунд (~24.8 суток), обрезается на приведении и при отрицательном результате бросает
исключение — то есть просьба «переподключайся пореже» убивала переподключение вовсе.

Граница — сутки, одна на все три клиента: профиль переносим, и расхождение здесь означало бы
три разных поведения из одного файла. Выход за диапазон **записывается** (как и нечитаемое
значение), а не подменяется молча умолчанием: подмена — это не «зажим», зажим прижал бы к
ближайшей границе, а тут значение улетает в совершенно другое. Часовая задержка — законная и
проходит без замечаний.

### Исправлено — `unknown_keys` не смотрел на секцию

Исключения для GUI-ключей клиента сверялись только по имени, без учёта секции. `[logging]
reconnect = false` не считался неизвестным, хотя `reconnect` допустим лишь в `[qeli]` и здесь
не читается никем: строгая проверка пропускала настройку, которая заведомо не работает. После
расширения списка до 22 имён окно для этого стало заметно шире.

Заодно всплыло, что `header()` отдаёт секцию уже в скобках, а сообщение оборачивало её ещё
раз — в выводе было `[[qeli]] reconnect`. Тест на новое поведение написан до фикса и поймал
обе ошибки сразу: и лишние скобки, и то, что первая версия сравнения (`section == "qeli"`)
не совпадала ни с чем и молча отключала исключения целиком.

### Удалено — импорт JSON-конфигов в клиентах

JSON был исходным форматом конфига и не пишется уже давно: его заменил flat-INI, и сегодня
INI отдают все инструменты — панель, `qeli://`-ссылка, экспорт из любого клиента. Оставался
от него только **импорт**, и вместе с ним — второй, полностью параллельный парсер в каждом
клиенте, со своими умолчаниями, своей снисходительностью и своими багами.

Он исправно копил находки, уже закрытые на INI-пути: числа молча подменялись умолчаниями
(`"port": "bad"` → 443, то есть ДРУГОЙ сервер), неизвестные ключи терялись, типы
приводились. Каждая такая правка стоила четырёх реализаций на четырёх языках — ради формата,
который никто не производит. Дешевле снять формат, чем чинить его в четвёртый раз.

Ведущая `{` по-прежнему распознаётся — ровно затем, чтобы **назвать** формат: иначе старый
файл проваливается в INI-парсер и человек получает «missing `[qeli]`», что не говорит ни что
случилось, ни что делать. Сообщение одно на все порты и закреплено в общем conformance-гейте
(`json-retired`).

Затронуто и рядом: миграция старых профилей на Android и восстановление бэкапа на iOS больше
не собирают JSON только затем, чтобы скормить его парсеру, — они строят INI через модель, так
что имена ключей берутся из `toIni`/`toINI` и не могут разойтись с тем, что читает `fromIni`.
Профиль, всё ещё лежащий на устройстве в виде JSON, теперь не открывается — с тем самым
сообщением «экспортируйте профиль заново». Конверт бэкапа (`{active, profiles:[…]}`) и
серверный `OK:{…}` — это протокол, а не формат конфига; их не касается.

### Исправлено — свой резолвер клиента не работал, если сервер пушил свой

`dns_servers` — резолверы, которые пользователь задал в собственном конфиге — применялись
**только когда сервер не прислал ничего**. На любом сервере, который пушит DNS (а это и
`dns.push_servers`, и встроенный прокси профиля), заданный вручную резолвер молча не
использовался: побеждало предложение сервера, и пользователь об этом не узнавал.

Порядок приведён к тому, по которому работает продукт и который остальные клиенты уже
реализуют (см. `EffectiveDns` в C#, где проигнорированный пуш прямо пишется в лог):
**свой `dns_servers` → серверный пуш → встроенный фолбэк**. Резолвер, который пользователь
вписал руками, — осознанный выбор и старше серверного предложения; проигнорированный пуш
теперь виден в логе. `dns = off` / `system` по-прежнему коротко замыкают всё это и означают
«не трогай мой резолвер» — они побеждают оба варианта.

Таблица ключей в CONFIG.md (RU+ENG) описывала прежний порядок и приведена в соответствие.

### Исправлено — `check-config --client` объявлял опечатками ключи десктопных клиентов

`qeli check-config --client` на профиле, только что сохранённом Windows- или macOS-клиентом,
сообщал о **22 ключах** «that nothing reads — check the spelling» и завершался с кодом 1 —
то есть падал на совершенно корректном файле и отправлял оператора искать несуществующие
ошибки правописания. Скрипт деплоя с этой проверкой ломался на исправном конфиге.

Список `GUI_ONLY_CLIENT_KEYS`, который существует ровно для того, чтобы такие ложные
срабатывания гасить, покрывал шесть десктопных ключей и ни одного из этих двадцати двух.
Дополнен до полного набора; почему runtime их не читает, теперь записано рядом:
`padding*`, `heartbeat*` и `shaping*` **приходят с сервера** (клиентское значение могло бы
только разойтись с пиром), `timeout`/`reconnect*` — десктопные ручки бэкоффа (у CLI свои,
и в CONFIG.md колонка CLI для них намеренно «—»), `name` — подпись профиля в списке GUI,
у неё вообще нет рантайм-смысла.

Набор снят не на глаз, а прогоном профиля из **всех** ключей `KnownIniKeys` C#-клиента:
первая проба показала 12 ключей и была неполной — в ней не хватало `heartbeat_size` и всей
группы `shaping*`. Добавлен регресс-тест, который сверяет список с тем, что пишет GUI, и
называет недостающий ключ, если список снова отстанет.

Обнаружение настоящих опечаток не ослаблено: `kill_swtich` по-прежнему ловится.

### Исправлено — документация обещала не ту версию

- `GETTING-STARTED` (RU+ENG) устанавливал `qeli_0.7.12_amd64.deb`, хотя шапка объявляет
  документ описанием актуального релиза, а соседний раздел уже оперировал `0.7.13`.
- `ROADMAP` (RU+ENG) утверждал, что 0.7.12 «ещё не выпущена» — она вышла 2026-07-21.

### Исправлено — сервер отвечал «успешно» клиенту, которого тут же отключал

По UDP сессия помечалась аутентифицированной и AuthOK уходил на провод ДО того, как
проверялся `max_clients`. Клиент при превышении лимита получал успешную авторизацию, поднимал
TUN, показывал «подключено» — и упирался в молчание сервера, который его уже забыл. Ложный
успех с последующей тишиной диагностируется куда хуже честного отказа и гнал циклы
переподключения. Отправка перенесена за решение о лимите: отказанный клиент теперь просто не
получает AuthOK.

### Исправлено — длинные учётные данные вешали подключение по UDP без единого сообщения

AUTH уходит ОДНОЙ датаграммой, в отличие от ClientHello рядом и AuthOK в ответ, а его размер
— это логин и пароль, и они ничем не ограничивались. Длинный сгенерированный токен в роли
пароля выталкивал запись за бюджет, датаграмме требовалась IP-фрагментация, мобильный путь её
дропал — и получался бесконечный таймаут, воспроизводимый только на таких сетях и неотличимый
от недоступного сервера. Теперь это ошибка конфига с указанием полей.

Проверка выполняется ДВАЖДЫ, и это существенно: при загрузке конфига известен только
inline-пароль, а `password_file` и `password_command` читаются много позже, при подключении.
Первая версия проверки жила только в валидации и потому закрывала случай, который проще всего
заметить глазами, оставляя открытыми ровно те источники, ради которых эти ключи существуют.

### Исправлено — некорректный конфиг принимался и подключался не туда

INI-разбор ужесточали, JSON-импорт — нет, и на обоих мобильных портах в нём были закрыты
только булевы значения. Числа возвращали умолчание для всего, что не смогли привести:
`"port": "bad"` превращался в 443, то есть в ДРУГОЙ СЕРВЕР, молча. Теперь присутствующий, но
нечитаемый ключ отвергается; отсутствующий по-прежнему берёт умолчание, и число в кавычках
принимается — профили из других инструментов регулярно их квотят.

Там же `dns.mode` схлопывался в `tunnel` при любом промахе, а это ПРОТИВОПОЛОЖНО тому, о чём
просят `off` и `system`: опечатка `of` отправляла каждый запрос в туннель.

И отдельная ловушка плоского INI: режим и список резолверов пишутся одним ключом `dns`,
поэтому опечатка в режиме проваливалась не в ошибку, а в АДРЕС — `dns = of` становился
«резолвером» с таким именем, туннель его ставил, и запросы уходили в то, что не может
ответить. Резолвер по имени не разрешить, поэтому все клиенты теперь требуют IP-литерал.

Заодно выровнен `dns = system`: он работал на телефонах и отвергался CLI, а попади он в CLI —
ушёл бы в ветку `tunnel` и применил пушнутый резолвер, то есть сделал бы обратное тому, о чём
просит слово. Принят как НАПИСАНИЕ `off`, а не третье поведение, и описан в документации.

### Добавлено — `perf.udp.*`: размеры буферов UDP-слушателя сервера

Отдельно от `perf.tcp.*`, потому что нужны противоположные умолчания: TCP подбирает буфер сам
в границах `tcp_rmem`, у UDP автотюнинга нет вовсе. Сервер не звал `setsockopt` вообще и
полагался на то, что инсталлятор поднимет `net.core.rmem_max` — а это ПОТОЛОК для явных
запросов, сам по себе он не меняет ни одного сокета. Контейнер, запуск руками или уже стоящая
система работали на 208 КБ независимо от того, что написал инсталлятор. Фактически выданный
ядром размер читается обратно и пишется в лог: без этого урезанный буфер неотличим от рабочего
при чтении отчёта о скорости.

### Нативные ядра пересобраны под текущий исходник

`provenance.py --check` был красным: в PROVENANCE лежала база, после которой менялись
`protocol/udp_frag.rs`, `client/mod.rs` и `transport/tcp.rs`. GUI-клиенты поставлялись бы с
ядром старее, чем описывает дерево, — то есть исправления в исходнике до приложений могли не
доехать. Пересобраны Windows (`qeli.dll`), macOS (`libqeli.dylib`, universal2 arm64+x86_64) и
Android (`libqeli.so` для arm64-v8a и x86_64); копии внутри клиентов совпадают с каноническими
побайтово.

Ядра устаревают от ЛЮБОГО изменения в `qeli/src`, а не только клиентского кода, — проверку
стоит гонять перед тегом.

### Исправлено — гейт релиза молча пропускал проверку пина OpenWrt

`release_preflight.py` игнорировал код возврата `git rev-parse HEAD` и при пустом выводе
пропускал сравнение с `PKG_SOURCE_VERSION`. Любая посторонняя проблема с git — отказ по
ownership, отсоединённый worktree, git не в PATH — выключала единственную проверку, которая
ловит сборку роутерного пакета из устаревшего дерева. Выключала незаметно: preflight печатал
SHA из Makefile и не сообщал о расхождении, что читается как «пин верный». Теперь это отказ.

### ⚠️ Изменение поведения — сервер не стартует с непрочитанным значением в конфиге

Раньше значение, которое не удалось разобрать, писалось в лог предупреждением, и сервер
поднимался с подставленным умолчанием. Проблема в том, что умолчание регулярно оказывается
**пермиссивным** концом настройки: `kill_switch = ture` читается как false и выключает
kill switch, непарсящийся лимит читается как 0 и означает «без ограничений». То есть
работающая политика молча отличалась от написанной, причём в сторону снятия защиты, и
именно на том файле, который оператор считает описанием своего сервера.

Прежний аргумент — «отказ уронит работающий сервер при обновлении из-за давней опечатки» —
меняет громкий отказ, который видно сразу, на тихий, который можно не увидеть никогда. К
тому же путь запуска расходился с `check-config` и с перезагрузкой конфига: те отказывали
оба. Теперь отказывает и старт, перечисляя все проблемные ключи.

**Перед обновлением прогоните `qeli check-config`** — он даёт тот же список, не трогая
работающий сервис.

### Исправлено — большой AuthOK ломал переподключение, а его фрагменты дублировали номера пакетов

Две регрессии, внесённые фрагментацией AuthOK в этом же релизе, и обе — про UDP-профили с
большим набором push-маршрутов.

**Номера пакетов.** Провод нумеруется позиционно: ServerHello 0, AuthOK 1, дальше сессия с 2.
Фрагментированный AuthOK занимает 1..N, а счётчик сессии по-прежнему стартовал с двойки — при
двух и более фрагментах первый же пакет данных переиспользовал номер 2. Сегодня это никем не
отвергается (QUIC-обёртка у нас маска, а не протокол), но дублирующийся номер — ложь о
проводе, которая сломается при первой же строгой проверке. Счётчик теперь резервируется за
фрагментами.

**Повтор потерянного AuthOK.** Кумулятивная граница «не больше 3× принятого» душила именно
тот механизм восстановления, ради которого фрагменты и кэшируются: AuthOK в несколько
килобайт невозможно «заработать» повторами AUTH по ~350 байт внутри дедлайна рукопожатия, и
клиент переспрашивал ответ, который ему не разрешено выдать. Граница разведена по
фактическому риску — для неподтверждённого источника (ServerHello, триггером может быть
6-байтовая датаграмма) она остаётся, для аутентифицированной сессии заменена счётчиком
повторов: return-routability там уже доказана. Заодно первичная отправка AuthOK начала
учитываться в бюджете — раньше он описывал сервер, который ответил ServerHello и с тех пор
молчал.

### Исправлено — ошибка в файле пользователей пряталась за inline-конфигом

Любая ошибка загрузки `users_file` — битый файл, обрезанный, нечитаемый, непарсящийся лимит —
проваливалась в ПУСТУЮ базу без единой строки в логе, если в конфиге был хоть один inline
`[user:*]`. Сервер поднимался, обслуживая только inline-набор: все аккаунты, группы, лимиты
полосы и квоты из файла исчезали, а единственным симптомом было то, что люди не могут войти —
с конфигом, который их по-прежнему перечисляет. Панель при этом показывала пустой список и
позволяла «починить» его, создав аккаунты заново, то есть записать свежий файл поверх
непрочитавшегося.

Отсутствующий файл — по-прежнему норма (свежая установка, все пользователи inline).
Существующий, но не загрузившийся — отказ запуска.

Тем же ужесточён и путь ЗАПИСИ, иначе строгость получалась односторонней и создавала обход
отказа. `update_locked` проверял только синтаксис, поэтому файл, на котором сервер теперь
откажется стартовать, панель или `add-client` могли открыть, превратить `max_sessions = ten`
в 0 («без ограничений») и записать обратно — нечитаемое значение исчезало из файла вместе с
ограничением, пройдя ровно через тот код, который держит блокировку записи.

### Исправлено — конфиги на клиентах теряли настройки при сохранении

Ключи, которые понимает только Rust-клиент (`post_up`, `post_down`, `allow_unpinned_tofu`,
`exit_node`, `gateway_nat` и другие), лежат в списке разрешённых ИМЕННО ЗАТЕМ, чтобы
десктопный профиль открывался на телефоне. Он открывался — и сохранение их вычищало, потому
что модель их не хранила. Хуки, настройка TOFU и политика маршрутизации исчезали как побочный
эффект самого факта открытия файла; это хуже, чем если бы профиль просто отвергли. Теперь они
читаются дословно и дословно же выписываются обратно — тем же приёмом, которым уже спасалась
секция `[logging]`. Работает на всех трёх GUI-клиентах: сначала это сделали только на Android,
а в iOS и C# добавили лишь разрешающий список — то есть половину, из-за которой профиль
ОТКРЫВАЕТСЯ, без той, из-за которой он не обрезается. По отдельности это худшая половина:
именно она приводит к тому, что человек нажимает «Сохранить». C# заодно перестал терять
мобильные `allow_lan` / `apps` / `apps_mode`, так что профиль «телефон → десктоп → телефон»
больше не теряет выбор приложений по дороге.

Там же: `recv_buffer_size` / `send_buffer_size` (и `password_file` / `password_command`) не
были известны ни одному GUI-порту, и Android отвергал такой `client.conf` как «likely
misspelled»; опечатка в `apps_mode` молча превращалась в `all` — САМУЮ ШИРОКУЮ настройку, так
что `includ` заворачивал в туннель все приложения вместо выбранных; на iOS не было потолка
`padding_max`, и значение вроде 65535 давало туннель, который подключался и умирал на
`recordTooLarge`; в C# число вне диапазона подменялось умолчанием без записи в список ошибок
(`lport = 99999` → 0, «слушать где угодно»).

### Исправлено — карточка «Защита» на iOS не учитывала общий тумблер LAN

Туннель вырезает приватные диапазоны по `config.allowLAN || settings.allowLAN`, а карточка
смотрела только в профиль — с включённым общим тумблером она заявляла «весь трафик защищён»,
пока RFC1918, link-local и multicast шли мимо VPN. То же исправление, что было сделано для
Android; карточки зеркальные, и iOS тогда не проверили.

### Исправлено — UDP-профили теряли пакеты и отдавали вдвое меньше, чем TCP

Жалоба звучала так: fake-tls выдаёт 56 Мбит, а udp-quic на том же сервере — 22. Интуиция
подсказывает обратное: UDP не платит за «TCP поверх TCP». Разбор на боевом сервере нашёл
три независимые причины, каждая подтверждена счётчиками ядра, а не рассуждением.

**1. Фрагментация из-за MTU, посчитанного без учёта паддинга.** На проводе UDP-пакет это не
только `tun.mtu`: сверху ложатся запись qeli (48 байт), паддинг (`obf.padding`, до 400 байт
на КАЖДЫЙ пакет), заголовок QUIC, UDP и IP. Профиль с `tun.mtu = 1380` давал до 1865 байт
при типичном пути в 1500 — фрагментировался каждый полноразмерный пакет, а профили с 1280
фрагментировались примерно в 70% случаев. Фрагментация удваивает число пакетов и делает
потерю любого фрагмента потерей всей датаграммы. В документацию добавлена формула расчёта
и проверка по счётчику `fragments created`.

**2. Приёмный буфер UDP-сокета оставался на системном умолчании.** Прежний тюнинг поднимал
`net.core.rmem_max`, и для TCP этого достаточно — он подбирает размер буфера сам в границах
`tcp_rmem`. У UDP автотюнинга нет: сокет получает ровно `net.core.rmem_default`, а qeli не
вызывает `setsockopt(SO_RCVBUF)` — то есть `rmem_max` для него не значил ничего, и буфер
оставался 208 КБ. На скоростях туннеля это лишь десятки миллисекунд трафика: одна заминка
планировщика — и ядро отбрасывает датаграммы (замерено: 978 потерь за один спидтест). А
каждая потерянная датаграмма это потерянный TCP-сегмент **внутри** туннеля, после которого
внутреннее соединение вдвое роняет окно — отсюда непропорционально сильное падение.
Установщик, `scripts/prod_tcp_tune.py` и оба CONFIG.md теперь выставляют
`net.core.rmem_default` / `wmem_default` (4 МБ) и `netdev_max_backlog`; `verify_server.py`
проверяет фактический размер буфера, а не только `rmem_max`. Docker-инструкция дополнена
предупреждением: `net.core.*` не неймспейсятся, их нельзя задать через `--sysctl` — тюнить
нужно хост.

**3. Та же ошибка зеркально на клиенте — во всех трёх реализациях.** Android создавал
`DatagramSocket()`, C#-клиенты `Socket(..., Dgram, ...)`, Rust-клиент
`UdpSocket::bind("0.0.0.0:0")` — и ни один не задавал размер приёмного буфера. Android и C#
теперь запрашивают 2 МБ — best-effort, с логом фактически выданного ядром размера, чтобы
зажатый буфер нельзя было спутать с работающим. Rust-клиент (это ещё и **OpenWrt с
Keenetic**, а не только CLI) получил `set_udp_buffers` рядом с существующим
`set_tcp_buffers`.

Заодно **ожили два ключа конфигурации, которые до сих пор ничего не делали**:
`recv_buffer_size` и `send_buffer_size` присутствовали в модели клиента, но не читались из
INI и не применялись нигде. Теперь они читаются, применяются к UDP-сокету и переживают
round-trip. Дефолты у них РАЗНЫЕ, и это осознанно: `recv_buffer_size` = 4 МБ (у UDP нет
автотюнинга, поэтому «оставить как есть» означает 208 КБ и потери), а `send_buffer_size` = 0,
то есть не трогать ядро — переполнение буфера отправки данные не теряет, а жёстко заданное
значение наоборот понизило бы буфер на хосте, где `net.core.wmem_default` подняли под эту же
задачу.

Итог на боевом сервере: udp-quic **22 → 40+ Мбит на приём и 55 на отдачу**, то есть по
суммарной полосе он теперь обгоняет оба TCP-режима, а по отдаче — вчетверо. Остаточный
разрыв по приёму объясняется тем, что у TCP-профилей включён бондинг на 4 потока, а
multipath реализован только для TCP: в пересчёте на один поток UDP-путь вдвое эффективнее.

### Исправлено — веб-панель по HTTPS принимала соединения и не отвечала

Панель с `tls = true` переставала работать полностью: порт открыт, в логе штатное
`Web UI (HTTPS) listening on …`, но TLS-рукопожатие никогда не завершалось — браузер
висел до таймаута. VPN при этом работал нормально, поэтому со стороны сервер выглядел
здоровым. Выяснено на боевом сервере и воспроизведено на стенде.

Причина — в том, как панель стала получать слушающий сокет. Чтобы честно сообщать, поднялась
она или нет (порт мог быть занят), привязку сделали явной: `std::net::TcpListener::bind`
и передача готового сокета в `axum_server::from_tcp_rustls`. Но `std`-слушатель
**блокирующий**, а `tokio` требует неблокирующий и сам флаг не выставляет — как и
`axum-server`, который передаёт сокет в `TcpListener::from_std` как есть. Блокирующий
дескриптор внутри асинхронного рантайма подвешивает цикл `accept`: ядро продолжает
достраивать TCP-соединения в очереди, поэтому порт «открыт», но `ClientHello` никто не
читает. Диагностические признаки — поток, стоящий в `inet_csk_accept`, и соединения с
непрочитанным `Recv-Q`.

Добавлен `listener.set_nonblocking(true)` перед передачей сокета (сбой — это отказ запуска
панели, а не тихое продолжение). HTTP-ветка была не затронута: она привязывается через
`tokio`, который сразу возвращает неблокирующий сокет.

Проверено до и после: `curl -k` к панели — `code=000` за 8 с (таймаут) против `code=200`
за 8 мс; поток вместо `inet_csk_accept` уходит в `do_epoll_wait`.

### Исправлено — AuthOK не долетал, если профиль пушит много маршрутов

По UDP клиент мог намертво зависать на аутентификации, и выглядело это как мёртвый сервер:
клиент повторяет AUTH, ответа нет, соединение отваливается по таймауту — и ни в клиентском,
ни в серверном логе не оставалось ничего, что объясняло бы почему.

AuthOK — единственное сообщение рукопожатия, размер которого ничем не ограничен: он несёт
список push-маршрутов. ClientHello и ServerHello давно фрагментируются на уровне приложения
именно затем, чтобы обойти пути, режущие IP-фрагменты (мобильные сети, CGNAT), а AuthOK
уходил ОДНИМ пакетом — и нескольких десятков маршрутов хватало, чтобы такой путь его
уничтожил.

Добавлен тип сообщения 6: сервер режет AuthOK на фрагменты. Три вещи делают это безопасным
для уже выкаченных клиентов:

- Фрагментация включается ТОЛЬКО выше бюджета. На бюджете и ниже AuthOK уходит той же
  единственной датаграммой, байт в байт, — то есть в любом работающем сегодня случае ничего
  не меняется. Единственный случай, где старый клиент встретит фрагменты, — тот, где сеть и
  так уничтожала его ответ. Это зафиксировано отдельным тестом.
- Режется ГОТОВАЯ зашифрованная запись, а не открытый текст: криптография, транскрипт и
  окно replay не двигаются.
- Настоящую запись невозможно спутать с фрагментом ни в одном из двух фреймингов — 0xF0
  недостижим в первом байте и там и там, — поэтому приёмная сторона не рискует принять
  данные за фрагмент.

Приёмная сторона всех трёх портов (Android, C#, iOS) собирала фрагменты по общему признаку,
без привязки к типу сообщения, — то есть заработала без изменений; проверено по коду
каждого. В них добавлены константа, предикат и сверка с общими векторами
`conformance/udp-frag.json`, чтобы расхождение по номеру сообщения падало в тестах, а не
превращалось на телефоне в «сервер не отвечает».

Кэш повторной отправки стал списком датаграмм: повторить только первый фрагмент значило бы
навсегда оставить сборку у клиента на один фрагмент короче.

Гейты: Rust 472 теста, fmt и clippy чисто; Android 9/9 conformance; C# 253/253. iOS не
собирался — нужен macOS.

### Изменено — карточка стала «Свойства соединения» и показывает пуш сервера

Карточка защиты вела жирным вердиктом «Весь трафик защищён». Это самое сильное заявление в
приложении и самое лёгкое, чтобы незаметно ошибиться, а весила она ~127dp — из-за чего
вкладка «Соединение» уезжала в прокрутку, как только поднимался туннель. Переделано:

- заголовок «Свойства соединения» вместо «Защита», вердикта нет — строка перечисляет факты
  (режим, транспорт, обмен ключами, как доверен пир). Карточка ужалась до ~63dp;
- **показывается только при активном соединении.** Это свойства соединения, а до него
  сообщать нечего — и неподключённый экран получает всю высоту обратно;
- если что-то сужает туннель, строка фактов заменяется янтарным предупреждением;
- кнопки «Приложения» и «Always-on» уехали в детальный лист: обе только открывают другие
  экраны, а на карточке стоили 60dp.

**Добавлено то, что сервер пушит клиенту** и что раньше нигде не показывалось: IP в туннеле,
адаптивный режим multipath, список анонсированных маршрутов и — главное — параметры
обфускации в силе (`padding`, `heartbeat`, шейпинг). Последнее и есть ручки DPI-стойкости,
которыми владеет сервер; клиент их даже переклампливает под свои лимиты.

**Маршруты ограничены на источнике, а не в вёрстке.** Сервер вправе анонсировать очень
длинный список (раздача странового набора префиксов под split-tunnel — нормальный сценарий),
поэтому в снимке хранится не более `ROUTE_SAMPLE` = 6 записей плюс настоящий счётчик, а лист
показывает `10.20.0.0/16, … и ещё 42`. Иначе и `@Volatile`-поле, и диалог, инфлейтящий по
view на строку без переиспользования, масштабировались бы вместе с ответом сервера.

`session_token` не показывается и показываться не будет: это учётные данные, дающие право
подключить bonded-поток к сессии.

**Готча, пойманная по дороге (Android).** Пушнутый `padding` применяется прямо к кодеку
(`encCodec.setPadding`) и обратно в конфиг не копируется — в отличие от heartbeat и шейпинга.
Карточка сначала читала `config.padding*` и показала бы профильные значения, пока на проводе
идут серверные. Теперь всё берётся из самого пуша. На iOS этой ловушки нет: там оба
хендшейка пишут пуш в конфиг и затем клампят.

### Добавлено — карточка «Защита» на главном экране Android и iOS

Сильные стороны qeli — гибридный постквант, REALITY, обфускация, пиннинг ключа — были в
коде и не были видны в интерфейсе: пользователь наблюдал кольцо и счётчики байт, ровно как
в любом другом VPN. Карточка внизу вкладки «Соединение» показывает, что профиль реально
защищает, а тап открывает подробности.

Правило, вокруг которого построено всё остальное: **карточка не имеет права
преувеличивать.** Она делает заявления о безопасности, поэтому «весь трафик защищён»
выводится не из факта подключения, а из `ProtectionSummary.carriesEverything` — и любой из
`allow_lan`, `allow_ipv6_leak`, непустой `exclude`, split-туннель или режим «по
приложениям» этот флаг снимает, а причина уходит в отдельную строку-предупреждение.
Решения вынесены в чистый `ProtectionSummary` (Kotlin + Swift, зеркальные) с enum-выходами
и без строк — так они покрыты юнит-тестами и остаются локализуемыми. Отсутствие
запиненного ключа предупреждает, но заголовок не снимает: пиннинг решает, С КЕМ клиент
готов говорить, а не СКОЛЬКО трафика несёт.

Два места, где карточка это правило нарушала, поправлены до релиза:

- **Android читал только профильный `allow_lan`.** Приватные диапазоны из туннеля
  вырезает `QeliService` по условию `config.allowLan || prefs.allowLan` — то есть общий
  тумблер «Разрешить доступ к локальной сети» работает наравне с полем профиля. Карточка
  же смотрела только в профиль и с включённым общим тумблером объявляла «весь трафик
  защищён», пока RFC1918, link-local и multicast шли мимо VPN. `ProtectionSummary.of`
  получил параметр `globalAllowLan`, и `MainActivity` передаёт в него то же значение
  настройки, что и сервис.
- **iOS выдавал невыполненное ограничение за выполненное.** `apps_mode` на потребительской
  iOS не применяется вовсе: `NEAppRule` требует MDM-конфигурации. Карточка при этом
  отображала режим прямо в заголовок — «защищены только выбранные приложения», — то есть
  подтверждала ограничение, которого нет, и пользователь строил вокруг него свой трафик.
  Теперь scope на iOS следует МАРШРУТАМ (то, что платформа действительно исполняет), а
  невыполненный выбор приложений уходит в отдельное предупреждение. Оно намеренно **не**
  снимает «весь трафик защищён»: неприменённый per-app-выбор туннель не сужает, а
  расширяет.

Постквант заявляется для всех режимов, кроме `plain`: `obfs` и `reality-tls` — обёртки
транспорта поверх того же PQ-ClientHello (`performHandshake`), а `plain` идёт своей веткой
с голым X25519. Проверено по коду, а не по названию режима — показать «X25519 + ML-KEM-768»
там, где его нет, было бы ровно тем случаем, когда карточка вреднее её отсутствия.

Рантайм-значения (пушнутый DNS, применённый MTU, число bonded-потоков, число маршрутов от
сервера) сервисы раньше знали, но в UI не отдавали — они попадали туда только строкой лога.
Добавлен снимок: на Android поля `live*` рядом с существующими `liveIp`/`liveBytes*`, на iOS
поля в `TunnelSnapshot`. **Лог для этого не парсится** — строки лога это документированная
поверхность каталога ошибок (`docs/*/manuals/TROUBLESHOOTING.md`), а не канал данных. Пока
соединения нет, эти строки просто не показываются, а не угадываются из профиля.

Различия платформ (записаны в `qeli-ios/PARITY.md`): на Android в карточке две кнопки —
«Приложения» (существующий диалог выбора) и «Always-on» (системные настройки VPN, которые
приложение не может ни включить, ни даже прочитать из Activity), плюс строка «Блокировать
без VPN» из `isLockdownEnabled`. На iOS ни того, ни другого нет: per-app routing требует
MDM, Always-On приложению не отдаётся, а аналога `isLockdownEnabled` у Packet Tunnel
Provider не существует.

Тесты: `ProtectionSummaryTest` (Android, 10) и зеркальные проверки в `ParityHardeningTests`
(iOS) — каждый способ сузить туннель обязан снимать «весь трафик защищён».

⚠️ iOS-часть, как и прежде, **не собиралась и не запускалась** — нужен macOS с Xcode.

### Добавлено — версия клиента в `list-clients` и в панели

Оператор не мог ответить на вопрос «кто ещё не обновился»: ни CLI, ни панель не знали
о клиенте ничего, кроме имени, IP и трафика — версия по проводу не передавалась вовсе.

- **Новый внутритуннельный control-кадр `CTRL_CLIENT_INFO` (тип 2)**
  ([qeli/src/protocol/ctrl.rs](qeli/src/protocol/ctrl.rs)). Механизм для этого уже
  существовал — тот самый, которым в этом же релизе передаётся отчёт о path-MTU, — поэтому добавлен
  только тип: `[0xC1 0x9B][type=2][len][ver_len(1)][version][platform]`. Кадр едет как
  обычная AEAD-запись, то есть аутентифицирован сессией и одинаково работает на TCP и UDP;
  клиент шлёт его сразу после AuthOK и ничего не ждёт в ответ.
- **Расширение AUTH-сообщения было бы ломающим.** Формат `[proof:32][0x00 device_id:16]?[user:pass]`
  разбирается позиционно, и старый сервер вклеил бы версию в **имя пользователя**. Отдельный
  кадр аддитивен в обе стороны: сервер, не знающий тип 2, разбирает заголовок по `len` и
  пропускает кадр, а не гадает о его размере.
- **CLI**: у `qeli list-clients` появилась колонка `CLIENT` — она добавлена **последней**,
  чтобы позиции существующих колонок не поехали у тех, кто уже парсит этот вывод.
- **Панель**: колонка **Client** на дашборде, рядом с Peer. Поля `client_version` /
  `client_platform` в `ClientInfo` помечены `#[serde(default)]` — по тому же образцу, что
  `dropped` и `streams`, — поэтому новый CLI разбирает ответ старого сервера.
- **Сервер пишет в лог одну строку на изменение** (`client '<user>' (<ip>) reports qeli
  <version> on <platform>`), а не на каждый кадр.

**Значение сообщает сам клиент, и сервер его не проверяет.** Любой прошедший
аутентификацию пир может написать что угодно, поэтому это диагностическая метка и она
никогда не участвует в решениях о сессии. Отсюда строгий разбор: `version` — не длиннее
32 байт из `[A-Za-z0-9._+-]`, `platform` — не длиннее 16 байт из `[a-z0-9-]` и только из
закрытого списка платформ; всё остальное **отвергается целиком**, а не вычищается. Строка
попадает в лог, в терминальную таблицу и в DOM панели, так что перевод строки подделал бы
запись в логе, а разметка — дала бы XSS (в панели такое уже находили — через
`X-Forwarded-Prefix`). Длина `ver_len` — индекс, пришедший от пира, в буфер, пришедший от
пира: тест пиннит, что выход за границы тела не паникует и не читает соседние байты.

**Проверено на лабе, оба транспорта.** Сервер + TCP-клиент + UDP-клиент + клиент **0.7.11**
одновременно: у новых сессий в CLI и в `/api/clients` стоит версия тестовой сборки
(`0.7.13/linux` — на лабе собиралось до бампа), у 0.7.11 —
`-` и `null` (обратная совместимость: старый клиент просто не шлёт кадр). Гейт — **441 тест,
0 падений**, `cargo fmt --check` и `clippy --all-targets` чисто.

**Порт завершён:** кадр теперь шлют **все** клиенты — Windows, macOS, Android и iOS, — а не
только Rust. Версия в каждом берётся из того же источника, который штампует `sync_version.py`
(версия сборки в C#, `versionName` пакета в Android, версия бандла в iOS), поэтому разъехаться
с релизом она не может. Тег платформы — закрытый набор из `ctrl.rs`; в C# он определяется в
рантайме, так как `qeli-shared` общий для Windows и macOS.

Валидация продублирована на стороне клиента намеренно: сервер отвергает негодные строки
**целиком**, поэтому кадр, который он отверг бы, не должен и строиться — иначе клиент молча
не отчитывается и не может понять почему. Байты кадра запиннены одним и тем же вектором во
всех четырёх реализациях (`c19b020c06302e372e31336c696e7578` = версия `0.7.13`, платформа
`linux`), плюс проверки отказа на перевод строки, разметку, пустые значения и превышение
лимитов длины. Повторов на UDP, в отличие от MTU-отчёта, нет: потеря этого кадра стоит метки
в таблице оператора, а не размера нисходящих пакетов.


### По внешнему аудиту 2026-08-01 (четвёртый проход)

Из четырнадцати пунктов подтвердилось одиннадцать, один отклонён по существу, три остаются
осознанно: сервер на **старте** по-прежнему предупреждает, а не падает (прервать запуск
из-за давней опечатки значит уронить работающий сервер при обновлении — при этом SIGHUP и
raw-редактор панели строгие, там отказ ничего не стоит); teardown ограничен тремя секундами
(альтернатива была дедлоком); `PKG_SOURCE_VERSION`/`PKG_MIRROR_HASH` в OpenWrt по своей
природе проставляются на теге.

**Отклонено в четвёртый раз.** «IPv6 path-MTU не работает» — недостижимо: клиент биндит
`UdpSocket::bind("0.0.0.0:0")`, то есть сокет IPv4-only, и `ClientConfig::validate()`
отвергает IPv6-адрес сервера. IPv6-пира не существует, поэтому `IPPROTO_IP` там
единственно верный.

#### ⚠️ DHCP не выдавал адреса из собственного диапазона

Худший пункт раунда, и механика хуже, чем «просто не работает». DHCP просил у общего
аллокатора **любой** адрес и отвергал всё, что не попало в его окно. Но `release()` кладёт
адрес в `freed`, а `freed` — ровно то, что следующий `allocate()` достаёт **первым**.
Получался замкнутый круг: каждый DHCPDISCOVER получал тот же адрес вне окна, освобождал его
и сообщал «no IP available», пока настроенный диапазон `.100–.200` стоял целиком свободным.

Добавлен `pool.allocate_in_range(key, lo, hi)`: поиск свободного адреса **внутри** окна,
идемпотентный для ключа, который уже держит адрес в окне (повторный DHCPREQUEST сохраняет
аренду, а не съедает ещё один адрес). `freed` отдельно не просматривается — освобождённый
адрес просто отсутствует в `allocated`, поэтому скан находит его сам, а `allocate()` при
выборке из `freed` перепроверяет `allocated`, так что дважды выдать один адрес невозможно.
Путь preferred-IP заодно упрощён: он просит именно запрошенный адрес через `allocate_fixed`,
поэтому ветка «получили не то — отпускаем» исчезла вместе с породившей её проблемой.

#### ⚠️ DHCP и `forward_private` запускались fail-open

DHCP биндился внутри detached-задачи, поэтому занятый порт, неверный адрес или отказавший
`set_broadcast` давали одну строку в логе, пока профиль считался работающим: клиенты
подключались и не получали аренду вовсе. Bind вынесен отдельно от serve — то же разделение,
что уже сделано для DNS.

Карта конфликтов при этом читала `dhcp.listen` **сырым**, а рантайм дописывает `:67`, когда
порта нет. Поэтому запись `dhcp.listen = 10.0.0.1` не давала эндпоинта вообще, и ровно то
столкновение, ради которого карта заведена — два профиля на DHCP-дефолте — проходило мимо,
стоило оператору написать адрес без порта.

`routing.forward_private` оставался полностью best-effort: результат `enable_ip_forward`
игнорировался, правила не проверялись, функция ничего не возвращала и всегда писала в лог
успех — то есть профиль поднимался «маршрутизирующим», не маршрутизируя ничего. Приведён к
инварианту полного NAT: без `ip_forward` — отказ, а отсутствие правил фатально только при
непустой/непрочитанной цепочке или политике не `ACCEPT`. Fallback остаётся только для
доказуемо пустой цепочки `FORWARD` с точной политикой `ACCEPT`; один default `ACCEPT` за
явным DROP/jump больше не считается подтверждением маршрутизации.

#### HTTPS-панель сообщала об успехе до bind

`axum_server::bind_rustls` биндит **лениво** внутри `serve()`, поэтому очевидная версия —
разобрать адрес, отчитаться, отдать в `serve` — объявляла панель поднятой, ещё не
притронувшись к порту, и самый частый отказ (порт занят) приходил потом строкой в логе под
статусом «panel on». Разбор `SocketAddr` ничего не говорит о том, можно ли слушать. Теперь
listener биндится явно и передаётся через `from_tcp_rustls` — как в HTTP-ветке, где это было
сделано правильно с самого начала.

#### DNS: пять дефектов кэша, фрейминга и таймаутов

- **TTL в кэше не уменьшался.** Отдавался только переписанный transaction ID, поэтому запись,
  выданная за секунду до истечения, объявляла **полный исходный TTL** — и каждый слой,
  кэширующий по этому числу, умножает просрочку (RFC 2181 §5.2). `decrement_ttls` проходит
  ANSWER + AUTHORITY + ADDITIONAL, вычитает возраст с насыщением в нуле и **пропускает OPT**:
  его «TTL» — это extended RCODE и флаги EDNS, уменьшение испортило бы код ошибки, а не
  состарило запись.
- **TCP-дедлайн оборачивал весь обмен**, поэтому исправное persistent-соединение — ровно то,
  ради чего существует RFC 7766 — обрывалось через `timeout_secs` после accept, посреди
  запроса. Ограничивать надо **простой**: таймаут применён к каждому чтению и записи, включая
  чтение тела после объявленной длины.
- **Ответ апстрима сверялся только по IP.** Принимать любой порт на нужном хосте — значит
  позволить чему угодно на той машине отвечать за резолвер, а 16 бит txid плохая единственная
  защита. Сверяется полный `SocketAddr`.
- **Синтетический TC терял настоящий RCODE**: слишком большой NXDOMAIN уезжал как NOERROR+TC,
  и RA/AA/AD терялись вместе с ним. Флаги берутся из реального ответа, поверх ставятся только
  QR и TC.
- **Буфер входящего запроса** поднят с 4096 до 65535 — это один буфер на цикл приёма, то есть
  64 КиБ на профиль однократно.

#### IPv4: усечённые пакеты и заворачивающееся смещение

Заголовок, **объявляющий больше байт, чем пришло**, зажимался через `clamp`, и фрагментация
шла по фактической длине. Получались фрагменты, заголовки которых описывают целую датаграмму,
а несут лишь то, что оказалось на руках: получатель собирал короткий пакет как целый, потому
что MF и offset о пропаже молчали.

Смещение последнего фрагмента маскировалось `& 0x1FFF` при записи, поэтому датаграмма, уже
далеко ушедшая внутрь большей, **заворачивалась** на малое смещение, и получатель пересобирал
эти байты поверх начала пакета — перезапись данных, которой отправитель не просил. Оба случая
теперь отвергаются.

#### DHCP: лимит по source IP душил всех новых клиентов сразу

DHCPDISCOVER по определению приходит с `0.0.0.0` — клиент ещё не имеет адреса, потому и
спрашивает. Значит IP-ключ складывал **все** новые клиенты сети в один счётчик, и десятая
машина, загрузившаяся после отключения питания, глушилась из-за девяти предыдущих. Ключ взят
из `chaddr` — единственной идентичности в пакете на этом этапе. MAC подделывают, но лимитер
здесь про случайные штормы, а подделка MAC стоит атакующему ровно столько же, сколько стоила
подделка source IP.

Плюс `lease_time_secs = 0` (не «без истечения», а аренда, **уже истёкшая**: клиент обновляется
непрерывно, свой же sweep отбирает адрес) и `domain_name` длиннее 255 байт (не влезает в
однобайтовое поле длины опции и раньше просто не отправлялся) теперь отвергаются при загрузке.

#### ⚠️ DHCP отвечал на чужие запросы

Option 54 (Server Identifier) не разбирался вовсе, поэтому сервер отвечал на **каждый**
увиденный DHCPREQUEST. Клиент в состоянии SELECTING кладёт в запрос тот сервер, который
выбрал; остальные обязаны молчать. Отвечая, qeli NAK-ал аренду, только что предложенную
другим сервером, отбрасывал клиента обратно к DISCOVER, и это могло зациклиться, пока оба
сервера продолжают отвечать — то есть на общей сети активно ломал чужой DHCP.

Адресация ответов была всегда limited broadcast. Это верно для клиента без адреса и неверно
дважды: ненулевой `giaddr` означает relay, и ответ принадлежит **серверному** порту релея,
иначе он никогда не доберётся до клиента (DHCP через relay не работал в принципе); ненулевой
`ciaddr` при снятом флаге BROADCAST означает, что обновляющийся клиент попросил ответить
напрямую. Порядок: relay → unicast → broadcast, выставленный клиентом флаг уважается всегда.

#### Опечатка в имени ключа перестала быть невидимой в GUI

Опечатку не читает никто, поэтому настройка, которую ей хотели изменить, молча остаётся в
значении по умолчанию: `gatway = true` оставлял туннель split-ом. Rust-клиент такие ключи
отвергал всегда, три GUI-порта — нет.

Тонкость, из-за которой это **не** сводится к «сверить со списком того, что читает этот
порт»: сверка идёт с **объединением** ключей всех четырёх портов. У Rust-клиента есть 11
ключей, которых C#/Kotlin/Swift не читают — `keepalive`, `post_up`/`post_down`, `exit_node`,
`lan_subnet`, `gateway_nat`, `autostart`, `dns_servers`, `tcp_nodelay`, `dev_attach`,
`allow_unpinned_tofu`. Это документированные клиентские file-only ключи (см. «Что пушем НЕ
передаётся»), а не опечатки, и профиль CLI, их несущий, обязан открываться в GUI. Отвергать
их было бы регрессом хуже той опечатки, которую ловим.

Защита от неверного списка встроена в тесты каждого порта: всё, что порт **сам** пишет через
`toIni`, должно быть им же принято обратно. Ключ, добавленный в вывод и забытый в списке,
заставил бы клиент отвергать собственный сохранённый профиль — и это падает в гейте, а не у
пользователя.

#### Строгий разбор чисел доведён до всех полей

`mtu = abc` молча превращался в auto-MTU, опечатка в `timeout` — в 30 секунд, в AWG-ручке — в
её умолчание. Через записывающие хелперы теперь идут все числовые ключи в каждом из трёх
портов: `mtu`, `timeout`, `lport`, `metric`, `jc`/`jmin`/`jmax`, `reconnect_*`,
`heartbeat_*`, `shaping_*`.

Различие сохранено намеренно: «вне диапазона» и «вообще не число» — разные вещи. Значение за
границами по-прежнему тихо берёт умолчание (это документированный кламп, и слияние двух
случаев начало бы отвергать конфиги, которые всегда принимались), а нечитаемое —
записывается и отвергается `validate()`. `qeli://` не тронут: импорт ссылки по дизайну
infallible.

### По внешнему аудиту 2026-08-01 (третий проход)

Отчёт снят с состояния до правок по дублям ключей, поэтому часть замечаний оказалась
неактуальной, а часть — завышенной. Разобрано по коду, ниже только то, что подтвердилось.

**Отклонено с обоснованием.** «Rust всегда ставит IPv4 `IP_MTU_DISCOVER`, даже если пир
IPv6» — недостижимо: клиент биндит `UdpSocket::bind("0.0.0.0:0")`, то есть сокет IPv4-only,
а `ClientConfig::validate()` отвергает IPv6-адрес сервера. Это заготовка на 0.8.0, а не
живой дефект. «DNS-прокси не детектирует TC и не повторяет по TCP» — детектирует
(`resp_buf[2] & 0x02`) и повторяет; подтвердилась только узкая часть про размер буфера
запроса. `PKG_MIRROR_HASH` из нулей — намеренная заглушка, падение `release_preflight.py`
на ней и есть работающее напоминание перед тегом.

#### `tun.name`: усечение до 15 байт и коллизии между профилями

`TUNSETIFF` копирует не больше `IFNAMSIZ-1 = 15` байт имени. `create_multiqueue` **всегда**
читал обратно то имя, которое реально дало ядро, — а `run_profile` этот ответ выбрасывал и
продолжал настраивать `pcfg.tun.name`. Длинное имя создавало устройство под одним именем, а
все последующие `ip ... dev <полное имя>` били по несуществующему — по одной команде за раз,
на уже наполовину поднятом интерфейсе.

- **Берём имя от ядра** — теперь его же получают `set_address`/`set_up`/`set_queue_len`,
  правила NAT, `QELI_TUN` для `post_up` и DNS-редирект. Согласованность по построению, а не
  по проверке, которая может разъехаться.
- **Проверка при загрузке**: имя непустое, не длиннее 15 байт, без пробелов и `/`, и
  **уникальное среди включённых профилей**. Последнее — не косметика: `run_profile`
  начинается с `TunInterface::delete(&tun.name)`, то есть старт второго профиля сносил живой
  интерфейс первого.

#### `perf.tun.read_buffer_size` мог остановить data plane

Разбирался как обычный `usize` без единой границы; единственным ограничением во всём дереве
было `min="1500"` у поля в панели, которого не видит ни рукописный конфиг, ни
`PUT /api/config/raw`. Хуже всех ноль: `read()` в пустой буфер возвращает `Ok(0)`, читатель
принимает это за EOF, и профиль перестаёт передавать пакеты **без единой ошибки**. Значение
меньше MTU молча режет каждый полный кадр.

Теперь проверяется при загрузке: не меньше `tun.mtu` (для TAP — плюс 14 байт
Ethernet-заголовка) и не больше 1 МиБ, потому что буфер выделяется **на каждую очередь**, а
очередей по умолчанию по одной на ядро.

#### Карта конфликтов bind учитывала только primary

В карту заносился лишь primary-эндпоинт профиля; дополнительные `listen` проверялись на
форму и выбрасывались. Не ловились `primary ↔ extra`, `extra ↔ extra` и профиль, конфликтующий
**сам с собой** (свой же адрес, повторённый в `listen`). На UDP с `SO_REUSEPORT` оба бинда
**успешны**, и ядро делит клиентов между профилями с разными ключами и пулами.

Теперь в сравнение идут все эндпоинты, которые профиль реально забиндит, и wildcard
учитывается как перекрытие: `0.0.0.0:443` конфликтует с `1.2.3.4:443`. Эквивалентность
hostname и IP намеренно **не** разрешается — `check-config` обязан работать без DNS, а ответ
резолвера в момент валидации не обязан совпадать с ответом в момент бинда.

#### `web.port = 0` проверялся только при включённом DNS

Проверка (добавленная в этом же релизе) стояла **внутри** цикла по профилям и внутри ветки
`if p.dns.enabled`, хотя `[web]` не имеет отношения ни к тому, ни к другому: при выключенном
DNS ноль проходил насквозь. Перенесена к остальным проверкам конфига целиком.

#### ⚠️ `ip tuntap del` не удалял многоочередные устройства

`TunInterface::delete` звал `ip tuntap del mode tun name X` **без** `multi_queue`. Эта команда
пересобирает флаги интерфейса и делает `TUNSETIFF`, поэтому на `IFF_MULTI_QUEUE`-устройстве
она падает с голым `ioctl(TUNSETIFF): Invalid argument`. Многоочередными являются **все**
устройства, которые создаёт этот сервер (`create_multiqueue`, очередей по умолчанию по числу
ядер) — то есть функция не могла удалить ровно то, что кодовая база делает. Молча: оба места
вызова использовали `.ok()`. Из-за этого и «удалить остаток перед созданием» на старте
профиля было пустой операцией. Перебираются все четыре формы (tun/tap × с `multi_queue` и без);
проверено на лабе: без флага — EINVAL и устройство живо, с флагом — удалено.

#### Откат частично стартовавшего профиля

Старт профиля — это последовательность воздействий на **систему** (TUN, правила iptables,
`post_up`, запись в реестре), и только в самом конце поднимаются listener-ы. Любая ошибка
после первого из них возвращалась наверх, где её лишь **логировали**; в многопрофильном
процессе исправный сосед держит воркер живым, поэтому мусор оставался до полного рестарта.

Добавлен guard, который взводится **до** первого воздействия и срабатывает на любом выходе,
включая `?`. Снимает правила NAT (сначала их — они ссылаются на интерфейс по имени), затем
устройство, затем запись из реестра. На успешном пути тоже: `run_profile` возвращается только
когда завершились все listener-задачи, то есть профиль действительно перестал обслуживать.

Само по себе это устройство не убирало: очередь отдаёт `libc::dup` своего fd блокирующим
потокам чтения и записи, а устройство без `IFF_PERSIST` исчезает только когда закрыт
**последний** дескриптор. Закрывать чужие fd из guard нельзя — закрытие дескриптора, на
котором другой поток стоит в `read()`, это use-after-free по его номеру. Поэтому потокам дан
путь остановки:

- **Сигнал, а не опрос.** `read()` возвращает `EINTR`, ветка для которого в цикле уже была, —
  значит на горячем пути пакетов добавилась ровно одна расслабленная атомарная загрузка на
  ветке, которая практически никогда не исполняется. `poll()` на каждый пакет стоил бы
  syscall при сотнях мегабит. Обработчик — пустышка и ставится **без** `SA_RESTART`: с ним
  ядро молча перезапустило бы прерванный `read()`, и весь механизм выглядел бы установленным,
  ничего не делая. `SIGUSR1` занят дампом трассировки, поэтому `SIGUSR2`.
- **Выделенные потоки вместо `spawn_blocking`.** Эти циклы блокируются на всё время жизни
  профиля, то есть держали бы слоты пула, отведённого под короткие операции; и, что важнее,
  поток пула переиспользуется — сигнал, посланный через мгновение после выхода из замыкания,
  попал бы в чужую задачу.
- **Писатели тоже.** Их блокировка — `recv` по каналу, а это ожидание на condvar, а не в
  syscall, поэтому сигнал там бесполезен: заменено на `recv_timeout(250 мс)` с проверкой
  флага. Когда пакеты идут, `recv_timeout` возвращается сразу и не стоит ничего; в простое
  это одно пробуждение в четверть секунды.
- **Ожидание ограничено.** Поток публикует свой id изнутри себя, поэтому между `spawn` и этой
  записью есть окно. Первая версия брала один `try_lock` и потом звала `join` безусловно —
  очередь, упавшая рано (например, ошибка bind DNS сразу после запуска потоков), могла
  остаться с читателем, которому сигнал не пришёл, и `join` вис **навсегда**, а `Drop`
  исполняется на воркере tokio, то есть заклинивал бы поток рантайма — строго хуже утечки
  устройства, ради которой всё затевалось. Теперь флаг проверяется **до** входа в `read()`,
  сигналы подаются в цикле (опоздавший регистрант получит его на следующем проходе), общий
  дедлайн 3 с, а `join` вызывается только для реально завершившихся потоков. Худший случай —
  строка в логе про утечку, а не зависание.
- Ошибка `spawn` больше не выходит через `?` до передачи handle-ов guard-у: иначе уже
  созданные потоки оставались бесхозными.

**Проверено на лабе живым сценарием**: два профиля, порт второго занят посторонним
слушателем. Устройство второго профиля удалено, правила NAT сняты, запись из реестра убрана,
первый профиль не затронут; на прошлом прогоне этот пункт был FAIL. Разборка заняла 46 мс,
то есть в дедлайн не упиралась — потоки вышли штатно.

#### ⚠️ NAT мог «успешно» включиться, не умея маршрутизировать

`routing.nat.enabled = true` — это обещание, что клиенты выходят в интернет, и проверялась
только его iptables-часть.

- **`ip_forward` был best-effort.** Без него ядро отбрасывает любой транзитный пакет, какими
  бы верными ни были правила. Ошибка записи в `/proc/sys/net/ipv4/ip_forward` давала
  предупреждение, после чего `setup()` возвращал `Ok`: профиль поднимался, клиент
  подключался, получал адрес — и не имел связи, а причиной была одна строка WARN над экраном
  INFO. Теперь это отказ с указанием, что сделать (`sysctl -w net.ipv4.ip_forward=1` или
  выключить NAT).
- **Правила `FORWARD ACCEPT` считались необязательными** по одной только default policy.
  Теперь проверяется вся цепочка: предупреждение допустимо лишь для пустого `FORWARD` с
  точным `ACCEPT`. `DROP`, явное правило/jump или непрочитанное состояние откатывают
  частично применённый набор и прерывают запуск, потому что default `ACCEPT` после более
  раннего DROP ничего не доказывает о реальном транзитном пути.

#### Панель и сервисы профиля не участвовали в карте конфликтов

Карта проверяла VPN-listener-ы и не знала об остальном, что этот же конфиг биндит.

- **Панель** — самый неприятный случай: она не профиль и стартует **раньше** (супервизор
  поднимает её до воркера), поэтому порт достаётся ей, а воркер уходит в crash-loop против
  порта, занятого тем же сервером. Снаружи панель выглядит здоровой, а VPN «просто не
  работает».
- **DHCP** — самый вероятный: дефолт `0.0.0.0:67`, так что два профиля с включённым DHCP
  сталкиваются, если оператор его не менял. Проигравший падал на bind внутри detached-задачи
  и оставлял одну строку в логе — профиль при этом обслуживал клиентов, которые не получали
  аренду.
- **DNS** — два резолвера на одном адресе; теперь учитываются оба транспорта, раз резолвер
  обслуживает и TCP.

#### SIGHUP и raw-редактор панели принимали конфиг с находками

Политика «сервер на старте только предупреждает» остаётся — но она распространялась и на два
пути, где отказ **ничего не стоит**, а потому и незачем быть мягким:

- **SIGHUP** разбирал конфиг через `parse_server_config()`, вообще без находок. Отказ здесь
  означает лишь «оставить работающий конфиг»: ничего не останавливается, никого не
  отключает, оператор видит строку в журнале с именем ключа.
- **Raw-редактор панели** сохранял после обычного разбора и структурных проверок, не глядя на
  `bad_values`/`unknown_keys`. Отказ здесь тем более безвреден: оператор смотрит ровно на тот
  текст, который неверен. Именно так `web.tls = ture` — или ключ, написанный дважды, —
  попадали на диск и потом читались как значение по умолчанию.

Разница с загрузкой при старте не в непоследовательности, а в цене отказа: прервать старт
из-за давней опечатки значит уронить работающий сервер при обновлении.

#### `dns.listen` принимал loopback и IPv6

Отвергались только `0.0.0.0` и multicast. `127.0.0.1` при этом биндится на сервере **успешно**
— и потому был особенно коварен: это значение отдаётся клиентам как их резолвер, а внутри
туннеля оно указывает на **собственный** loopback клиента, так что запросы уходят куда угодно,
только не в профиль. IPv6 несовместим с IPv4-only TUN и ломается на `format!("{}:53", ip)` —
та же ловушка, что уже описана для `dns.upstream`. Оба отвергаются при загрузке, с указанием
tun-адреса профиля в сообщении.

#### `post_down` не выполнялся для профиля, упавшего в одиночку

Хук висел в завершении воркера и пробегал сразу по всем профилям. Профиль, умерший после
своего `post_up`, оставлял изменения хука на хосте до тех пор, пока **любой другой** профиль
держал воркер живым. Теперь `post_down` привязан к концу самого профиля, а срабатывание ровно
один раз обеспечивает общий interlock: проверка и вставка в множество идут под одним замком,
поэтому остановка сервера, совпавшая с падением профиля, не запустит хук дважды. Доверие к
конфигу проверяется как и для `post_up` — команда из недоверенного файла это RCE.

#### Панель могла не подняться, а сервер рапортовал «panel on»

`web::start` возвращала `()`, все её пути отказа логировали и выходили, а вызывающий делал
spawn-and-forget. Строка `control plane up (… panel on)` при этом печаталась из `web.enabled`
— поля **конфигурации**, которое ничего не говорит о том, забиндилось ли что-нибудь. Оператору
сообщали, что control plane поднят, пока порт отказывал: неверный TLS, неразобранный адрес,
занятый порт.

Теперь панель сообщает о своём исходе через `oneshot`, вызывающий ждёт его с ограничением в 5
секунд, и статусная строка (плюс `STATUS=` для systemd) печатает фактическое состояние —
`on`, `FAILED TO START` или честное `starting (not confirmed)` вместо выдуманного успеха.
Заодно ошибки `serve` перестали глотаться `.ok()`.

#### ⚠️ Отказ одного listener-а не останавливал профиль

Цикл ожидания ждал, пока завершатся **все** listener-ы. Выглядело добросовестно и было ровно
тем дефектом: accept-цикл сам по себе не возвращается никогда, поэтому профиль с занятым
primary `:443` и живым extra `:8443` вис здесь навсегда. Ошибка **логировалась** — и на этом
всё: `run_profile` не возвращался, guard отката не срабатывал, сервер продолжал считать
профиль здоровым, а клиенты по опубликованному адресу получали отказ соединения.

Теперь профиль завершается на **первом** завершившемся listener-е. «Часть моих адресов
работает» — это не работающий профиль: клиент, настроенный на primary, никак не догадается
перейти на другой. Дальше решение принимает слой, который может что-то сделать — guard
откатывает TUN, NAT и запись реестра, место запуска логирует профиль поимённо, остальные
профили продолжают обслуживать.

- **Выжившие listener-ы гасятся явным `abort_all()`**, а не расчётом на drop `JoinSet`: их
  accept-циклы иначе продолжали бы принимать соединения для профиля, который сносится, и
  клиент мог бы завершить рукопожатие в пул, который вот-вот исчезнет.
- **Закрыт случай «ни одного listener-а не запустилось»** — раньше это молча возвращало `Ok`.
- Штатная остановка не затронута: SIGINT/SIGTERM обрабатываются `select!` по сигналам, а не
  через завершение listener-ов, так что ложных срабатываний нет.

#### ⚠️ Правило DNS-редиректа не удалялось **ничем**

`cleanup_matching` обходил `nat/POSTROUTING`, `filter/FORWARD` и `mangle/FORWARD` — но не
`nat/PREROUTING`, а это единственная цепочка, куда пишет `enable_dns_redirect`. То есть
правило `dns.port` не снимал никто: ни остановка профиля, ни `cleanup_all()` при старте
воркера, ни выключение сервера. Каждый рестарт добавлял ещё одну копию, а профиль, сменивший
`dns.port` или выключивший DNS, оставлял правило, гоняющее `:53` на порт, где уже никто не
слушает.

Цепочка добавлена в обход. **Проверено на лабе**: правило стоит во время работы, после двух
запусков копия ровно одна, после остановки — ноль.

#### Ответ апстрима больше 4 КиБ обрезался молча

Буфер приёма был фиксированным (4096) — верным для распространённых объявлений (1232/4096) и
неверным для клиента, попросившего больше: `recv_from` **отбрасывает** то, что не влезло, без
признака короткого чтения, поэтому ответ приходил обрезанным посреди записи и пересылался как
испорченное сообщение. Размер теперь берётся из того, что объявил **клиент** — его OPT-запись
уходит наверх дословно, значит она и определяет, сколько апстрим вправе прислать, — с полом в
4 КиБ и потолком 65535.

Отдельно закрыт случай, который `recv_from` в принципе не различает: датаграмма **ровно** в
размер буфера. Он сообщает скопированные байты, а не пришедшие, так что «поместилось впритык»
и «обрезано» выглядят одинаково. Считать такое полным ответом — как раз то, из-за чего
обрезанное уезжало дальше; считать усечённым стоит одного повтора по TCP в редком честном
случае и верно в плохом.

#### ⚠️ C#: нечитаемый порт молча превращался в 443

`server = host:notnum` разбирался в `host:443` — то есть клиент подключался к **другому**
серверу, чем написано в файле, и об этом не сообщалось нигде. То же самое с портом вне
диапазона: `:0` и `:99999` — не порты, а тихая подмена на 443 отправляла клиента туда, куда
конфиг его никогда не направлял. Ровно та же болезнь, что уже вылечена для булевых значений.

Проверено, что у остальных портов этой дыры нет: Kotlin (`toIntOrNull() ?: throw`) и Swift
(`parseEndpoint`) отвергали такой порт всегда — аудит здесь был прав про C# и неточен про
мобильные. Зато после починки C# стал строже к **прочим** числам, поэтому Kotlin и Swift
выровнены: значение, которое ПРИСУТСТВУЕТ и не читается как число, записывается и отвергается
`validate()`. Отсутствующий ключ по-прежнему молча берёт значение по умолчанию — ровно для
этого умолчания и нужны.

Разбор при этом по-прежнему **успешен** — редактор обязан уметь открыть плохой профиль, — и
границы padding по-прежнему клампятся, а не отвергаются: «вне диапазона» и «вообще не число»
это разные вещи.

#### Проба MTU ищет реальный максимум пути, а не лучшую ступень

Лестница по определению умеет садиться только на свои же числа, поэтому добавление ступеней
перемещает потерю, а не убирает её: при ступенях 9000 и 6000 путь на 8999 прижимался к 6000 и
выбрасывал треть каждого кадра.

Грубый проход теперь запоминает не только первую **ответившую** ступень, но и самую низкую
**неответившую** — эта пара берёт реальный MTU пути в вилку, которая дальше делится пополам,
по одной пробе на шаг. Инвариант простой: нижняя граница всегда уже доказана рабочей, поэтому
уточнение, ничего не нашедшее, возвращает грубый результат без ухудшения. Останов — по ширине
вилки (256 байт: гнаться за последними десятками байт не стоит round-trip) и по жёсткому
потолку в 5 проб, чтобы патологическая вилка не растягивала рукопожатие.

Выбор следующего размера вынесен в отдельную функцию во всех четырёх портах, поэтому поиск
тестируется **без сокета**: цикл добавляет только «отправить и подождать». Тест гоняет ту же
функцию против смоделированного пути и проверяет три вещи — никогда не сертифицировать выше,
чем путь несёт; недобирать не больше шага; и не проигрывать грубой ступени.

#### IPv4-пакеты с опциями фрагментируются, а не отбрасываются

Фрагментация отказывалась работать с заголовком, несущим ОПЦИИ, — формулировка в коде была
«безопаснее, чем наполовину верная реализация». На практике это означало, что пакет сверх MTU
**без** DF, несущий любую опцию (Record Route, timestamp, Router Alert), молча отбрасывался —
чёрная дыра ровно на том пути, где отправитель прямо сказал, что хочет фрагментацию.

Реализовано по RFC 791 §3.1: бит «copied» в типе каждой опции решает, попадёт ли она во все
фрагменты или только в первый. Первый фрагмент несёт заголовок как пришёл, последующие — лишь
копируемые опции, добитые EOL до границы 4 байт (IHL считает 32-битные слова). Бюджет payload
считается по большему из двух заголовков, чтобы арифметика смещений оставалась в целых
8-байтовых единицах.

Некорректный список опций — длина 0/1 у многобайтовой опции или уходящая за границу заголовка
— по-прежнему отказ: пакет уже невалиден, и догадка о починке отправила бы дальше то, чего
отправитель не писал. Тест проверяет, что Router Alert копируется, Record Route нет, каждый
фрагмент влезает в MTU со сходящейся контрольной суммой, а payload собирается обратно
байт в байт.

#### Ступени лестницы MTU уплотнены — но это компромисс, а не точный ответ

Между потолком и 1360 добавлены 12000, 6000 и 2500. Прежний набор оставлял провалы, где путь
терял до 43% кадра: 7000 сертифицировался как 4000.

**Полностью это не решается ступенями по определению.** Проба фиксированных ступеней находит
лучшую **подходящую** ступень, а не реальный максимум пути, поэтому 7000 теперь садится на
6000 вместо 4000 — лучше, но всё ещё не точно. Точный ответ требует бинарного поиска между
самой высокой непрошедшей ступенью и лучшей прошедшей; это меняет поток управления пробы во
всех четырёх портах, поэтому сделано отдельной задачей, а не протащено сюда. Ограничение
записано в коде рядом с набором ступеней.

#### Буфер DNS-запроса был размером с Ethernet-кадр

Входящий запрос читался в 1500 байт, тогда как ответ — уже в 4096. `recv_from` **отбрасывает**
всё, что не влезло, молча и без признака короткого чтения, поэтому запрос клиента с большим
EDNS0 приходил обрезанным посреди сообщения и уезжал наверх в таком виде. Буфер запроса
приведён к 4096.

#### Резолвер не умел TCP — и потому не мог честно ставить TC

Ответ пересылался клиенту **целиком**, каким бы большим он ни был. Учебное поведение —
обрезать и выставить `TC=1`, то есть «спроси ещё раз по TCP», — было бы здесь **вредным**:
прокси биндил только UDP-сокет, так что клиент ушёл бы на порт, где никто не отвечает, и
работающий резолв превратился бы в отказ.

Причина устранена, а не обойдена: **DNS-over-TCP по RFC 7766 обязателен** для резолвера, и
именно туда идёт клиент после усечённого ответа. TCP-клиент в прокси уже был (`query_tcp`,
length-prefix по RFC 1035 §4.2.2 — им делается повтор при `TC` от апстрима), не хватало
слушателя.

- **Слушатель на том же адресе и порту**, что UDP-половина, с той же ранней диагностикой:
  занятый порт валит профиль на старте, а не всплывает строкой в логе на работающем сервере.
  Несколько запросов в одном соединении (RFC 7766), общий дедлайн на обмен и тот же
  in-flight-предел.
- **Разбор запроса общий** — блоклист, кэш, выбор апстрима и переключение между ними вынесены
  в `resolve()`, которым пользуются оба транспорта. Вторая копия для TCP — это способ развести
  два пути в разные стороны по вопросу «какие имена блокируются».
- **Один кэш и один preferred-апстрим на оба транспорта**: два удвоили бы трафик наверх и
  позволили бы одному имени отвечать по-разному в зависимости от того, каким транспортом
  клиент случайно пришёл.
- **Теперь TC ставится** — по размеру, который клиент объявил в своей EDNS0 OPT-записи (при её
  отсутствии — 512 по RFC 1035 §4.2.1). Ответ строится как заголовок плюс вопрос с обнулёнными
  ANCOUNT/NSCOUNT/ARCOUNT, а **не** как исходные байты, обрезанные посередине: обрезка внутри
  записи оставляет счётчики, обещающие то, чего нет, и резолвер прочтёт это как испорченное
  сообщение, а не как «повтори по TCP». По TCP ответ уходит целиком — ради этого клиент туда и
  пришёл.
- **Редирект расширен на TCP.** Он был UDP-only совершенно правильно: слушателя не было, и
  правило вело бы в закрытый порт. Теперь без него клиент, которому сказали повторить по TCP,
  упёрся бы в `:53`, за которым пусто — ровно та чёрная дыра, ради которой редирект и заведён.

#### ⚠️ Проверка длины `tun.name` роняла обработчик панели

Сообщение об ошибке цитировало ту часть имени, которую оставит ядро, и делало это срезом по
**байтовому** индексу: `&tun_name[..15]`. Если байт 15 попадает внутрь многобайтового
код-пойнта — восемь кириллических букв это шестнадцать байт — Rust паникует. А
`validate_profiles` вызывается из `PUT /api/config`, то есть имя, введённое в панели, роняло
обработчик запроса вместо того, чтобы быть отвергнутым. Режем по границе символа; в тестах
пиннится имя `интерфейс` (9 символов, 18 байт).

#### Опечатки в именах ключей сервера не сообщались нигде

Строгая проверка `unknown_keys` применялась только к клиенту. На сервере всплывали лишь
находки уровня **значений**, поэтому `kill_switch = ture` предупреждал, а `kill_swtich = true`
— та же настройка, молча выключенная, разница в одну букву — не давал ничего, кроме вывода
`check-config`, который на работающем сервере никто не запускает. Теперь имена тоже попадают
в отчёт при старте.

**Политика fail-open сохранена намеренно**: уронить работающий сервер при обновлении из-за
давней опечатки дороже, чем строка в журнале. Отказывают клиентский конфиг, панель при
сохранении и `check-config` (ненулевой код).

#### Документация описывала нерабочие ключи

`[auth] password_hash` и `[auth] token_ttl_secs` перечислены в `RETIRED_KEYS`, но обе таблицы
(ru и eng) описывали их как действующие; `perf.tun.write_buffer_size` — то же самое. Конфиг,
написанный по этой таблице, получал предупреждение о ключах, которых нет. Убраны, с пометкой
не путать с `password_hash` в `[web]` и `[user:*]` — те настоящие. Описание
`perf.tun.read_buffer_size` заодно приведено к новым границам.

#### OpenWrt: инструкция вела в gitignore-каталог

`INSTALL.md` предлагал `scp` из `qeli-openwrt/dist/`, а этот каталог — **локальный вывод
сборки и он в `.gitignore`**: в свежем клоне его нет вовсе, а в дереве мейнтейнера лежит то,
что собиралось последним (во время 0.7.14 там всё ещё были бинарники 0.7.13, побайтово
равные `release/dist/v0.7.13`). Шаг и так начинается со «скачайте с GitHub Releases» — теперь
`scp` берёт скачанный файл. Для мейнтейнеров назван `release/dist/v<версия>/`: путь
версионно-явный именно затем, чтобы не протухать молча.

### ⚠️ Пересборка нативных ядер win/mac не доносила их до репозитория

`native-libs/PROVENANCE` заведён ровно затем, чтобы ответить на вопрос «собраны ли
лежащие в дереве `.dll`/`.dylib`/`.so` из того исходника, который тут же и лежит».
Оказалось, что сам ответ был ложным: [`scripts/build_native_libs_p4.py`](scripts/build_native_libs_p4.py)
собирал Windows- и macOS-ядра на лабе и печатал «pull with the next step» — **а
никакого следующего шага не существовало**, и ни один другой скрипт эти два файла не
копирует. Пересборка оставляла свежие ядра на .10, а в репозитории — старые, после чего
`provenance.py --update` записывал текущий digest исходников против бинарников, которые
из них не собирались.

**Незаметно в ревью и для обеих проверок**: `verify.sh` сверяет копии библиотек друг с
другом, а `provenance.py` — digest с исходниками; обе проходили, потому что все суммы
сходились между собой — просто не с тем, из чего бинарники на самом деле собраны.
По истории коммитов так прошло **три** коммита `build(native): rebuild the FFI cores`:
`.dll` и `.dylib` последний раз менялись в `c6b824a`, а provenance переписывался ещё
трижды после этого. Android-скрипт свою `.so` забирал всегда, поэтому затронуты только
Windows и macOS.

- **Шаг pull добавлен в скрипт** — обе копии каждой библиотеки, в `native-libs/` и в ту,
  которую потребляет сборка, строго в бинарном режиме. Пропуск переноса при неуспешной
  сборке: класть в дерево артефакт недособранной сборки было бы хуже отсутствующего
  переноса.
- **Ядра в дереве пересобраны и заменены**: `qeli.dll` `be6884e7…` → `f0ad75a6…`,
  `libqeli.dylib` `03fc3265…` → `1673e612…`. Повторный прогон скрипта даёт те же байты,
  то есть сборка win/mac воспроизводима. Форма Mach-O не изменилась: `LC_CODE_SIGNATURE`
  на arm64-срезе, как и было.
- **Порядок зафиксирован в [native-libs/README.md](native-libs/README.md)** и печатается
  самим скриптом по завершении.

### Дубль ключа в конфиге: четыре порта решали его по-разному

Ключ, написанный в файле дважды, но читаемый как **одно** значение, разбирался в разных
клиентах в разную сторону: Rust брал **первое** вхождение
([`Section::get`](qeli/src/config/format.rs)), а C#, Kotlin и Swift сворачивают строки в
словарь и оставляют **последнее**. Две строки `server = …` в одном файле уводили
Rust-клиент на один хост, а все GUI-клиенты — на другой, и ни один из них ничего об этом
не сообщал.

**Сведено к одному поведению — отказу, а не выбору победителя.** Выбрать сторону было бы
хуже: какую из четырёх реализаций ни объявить правильной, остальные три остаются
несогласными, а какая строка имелась в виду, знает только автор файла. Поэтому дубль
скалярного ключа теперь **фиксируется как находка** во всех четырёх портах, и `validate()`
отказывается подключаться.

- **Порядок разбора не изменён**: Rust по-прежнему берёт первое вхождение, остальные —
  последнее. Файл, у которого дубля нет, разбирается ровно как раньше; файл, у которого
  дубль есть, разбирается как раньше и **дополнительно** сообщает об этом.
- **Разбор по-прежнему УСПЕШЕН, отказывает `validate()`** — тот же раздел, что у
  нераспознанного булева значения: редактор обязан уметь открыть плохой профиль, чтобы его
  можно было починить.
- **Ключи, которые повторяются законно** (`listen`, `route`, `exclude` и прочие списки),
  читаются через `all()`/`list()` и находкой не считаются — второй `listen` в профиле это
  документированный способ добавить эндпоинт, а не двусмысленность.
- **Одна находка на ключ**, сколько бы раз он ни повторялся и сколько бы раз его ни читали
  (`dup_reported` в Rust, проверка на вхождение в остальных портах).
- **Сервер на старте по-прежнему только предупреждает.** Уронить работающий сервер при
  обновлении из-за давнего дубля — цена выше пользы; оператор видит строку в журнале, а
  `check-config` возвращает ненулевой код. Отказывают клиентский конфиг, панель при
  сохранении профиля и все четыре клиента.
- В C# метка намеренно **не переносится** через `WithEditorFields`: в отличие от опечатки в
  булевом значении дубль не может пережить сохранение формы — разбор уже свёл ключ к одному
  значению, а запись выдаёт по одной строке на ключ, так что двусмысленности больше нет.

Гейты: Rust — **450 тестов** + fmt + `clippy --all-targets` чисто; C# — **231/231**
conformance (4 новые проверки); Android — **45 тестов** и `assembleDebug`. На iOS добавлен
`ConfigHardeningTests`, но он, как и остальные правки этого релиза для iOS, **не
компилировался** — macOS-тулчейна нет.

### Сквозная проверка всех ключей конфига

После истории с kill-switch каждый ключ всех четырёх конфигурационных слоёв проверен
механически на один и тот же класс дефекта: **ключ парсится, сохраняется и переживает
рестарт, но его никто не читает**. Метод — сопоставление полей модели с их использованием
вне слоя сериализации.

| слой | полей | мёртвых |
|---|---|---|
| Rust client | 70 | 0 |
| Rust server | 97 | 0 |
| C# (`VpnConfig`) | 57 | **1** |
| Kotlin (`Config`) | 56 | **1** |

Найденное — одно и то же на трёх клиентах:

- **`obf.heartbeat.data_size_bytes` не работал на Windows, macOS и Android.** Значение
  парсится (дефолт 16), таскается через клонирование конфига и сериализуется обратно — но
  keepalive уходил с **пустой** полезной нагрузкой: `encrypt(ByteArray(0))` в Kotlin и
  `Encrypt(Array.Empty<byte>())` в C#. Ключ учитывал только Rust-клиент. Это ровно то, ради
  чего настройка существует: шифрованный пакет фиксированного размера с фиксированной
  периодичностью — готовая сигнатура для DPI, а пустой — самый характерный размер из
  возможных. То есть десктопные клиенты были самыми узнаваемыми в семействе, притом что
  рычаг против этого стоял в конфиге и выглядел рабочим. Теперь все клиенты набивают
  keepalive случайной длиной из `[data_size, data_size+32]` с тем же ограничением по MTU,
  что и у Rust-клиента.

Ложные срабатывания разобраны и оставлены как есть: `add_default_gateway` и `routing.mode`
читаются внутри самой модели (из них вычисляется full-tunnel), а `logging.file` на Android
только сохраняется при экспорте профиля — файлового лога там нет, и это осознанно.

### Потолок MTU доведён до всех компонентов, а не только до сервера

Прошлая правка подняла предел в **одном** месте — `config::server::MTU_MAX` — и объявила
диапазон `576..=16638` в документации. Остальные шесть точек остались на 9000, и это оказалось
не «частичной поддержкой», а **регрессом**: клампом отчёта о path-MTU служила отдельная
константа `MAX_REPORTED_MTU = 9000`, поэтому клиент, законно работающий на 16 К, сообщал 9000 —
и сервер сам сужал ему нисходящий поток до 9000. То есть фича из этого же релиза резала рабочий
jumbo-туннель.

Теперь у обоих потолков **один источник** — `protocol::packet::MAX_TUNNEL_MTU`, выведенный из
размера записи. Подняты и приведены к нему: кламп отчёта, проверка пушнутого MTU на сервере,
C# (`MtuMax` и разбор push), Android (`MTU_MAX` и разбор push), iOS (валидация, `qeli://`-ссылка
и два места в handshake), поле веб-панели и `range()` в LuCI. Из русской документации убрана
оставшаяся фраза про максимум 9000, противоречившая абзацем выше.

Добавлен тест-страж: два потолка обязаны совпадать и оба обязаны равняться пределу формата
записи. Именно расхождение между ними и дало регресс, поэтому поднять один без другого теперь
не получится — падает сборка тестов.

### Потолок MTU выведен из формата записи, а не взят из соглашения Ethernet

`tun.mtu` был ограничен сверху числом 9000 — «общепринятый jumbo». Это соглашение из мира
Ethernet, к qeli отношения не имеющее, и оно отсекало вполне рабочие конфигурации: карта 10G с
кадрами 16348 байт способна нести туннель заметно крупнее, и кодек его выдерживает.

Настоящую границу задаёт формат записи: запись несёт nonce + счётчик + данные + паддинг + tag и
должна уложиться в `MAX_RECORD_SIZE`, а всё сверх пир **отвергает**. Потолок теперь выводится из
этих же констант и равен **16638**; если кодек изменят, предел поедет за ним сам. Значение выше
по-прежнему отвергается — но уже по причине провода, а не по традиции.

Единицы важны: это MTU **внутренний**. Канал добавляет сверху IP + UDP/TCP + запись и, при
необходимости, obfs/QUIC — до ~76 байт, поэтому на канале с MTU 16348 разумный внутренний
потолок ближе к 16270, и только если такой кадр держит весь путь целиком.

### Пул подставных SNI сведён к одному списку в каждом клиенте

Rust берёт один и тот же список и для SNI фейкового ClientHello, и для заголовка `Host:` в
WebSocket-фронтинге. В C#, Kotlin и iOS эти два списка **разошлись**: в SNI было четыре имени,
в Host — пять. Клиент мог фронтить запрос как `amazon.com`, никогда не предлагая это имя в SNI.
Оба значения наблюдаемы, и несогласованность между ними — сама по себе отличительный признак.

Теперь в каждом языке список один, и он совпадает с Rust-каноном. Заодно снята возможность
разъехаться снова: оба места ссылаются на одну константу, а не повторяют литералы.

### Android: проверка профиля переехала в единственную точку, которую нельзя обойти

Подключиться на Android можно четырьмя путями — главный экран, виджет, плитка Quick Settings и
автозапуск по загрузке, — и все они сходятся в один Intent `ACTION_CONNECT`. Проверку профиля
добавили в каждый из четырёх входов, а сам сервис конфиг не перепроверял: брал объект из Intent
и запускал туннель.

То есть корректность держалась на том, что четыре разных места помнят сделать одно и то же —
ровно тот механизм, из-за которого дефект и возник (`validate()` вызывался при импорте, а
connect, always-on и загрузка про него не знали). Пятый вход, добавленный позже, тихо вернул бы
проблему.

Проверка перенесена в `onStartCommand`, перед запуском. Существующие четыре остаются как ранняя
диагностика: UI показывает причину сразу, а не молча не подключается.

**Не защита от постороннего приложения:** сервис объявлен `exported="false"` и закрыт разрешением
`BIND_VPN_SERVICE`, поэтому прислать этот Intent извне нельзя. Это защита от следующего
вызывающего, а не от атакующего.

### `dns.port` перестал ломать DNS у всех клиентов, кроме одного

`dns.port` существует, чтобы прокси мог обойти занятый на хосте порт 53 — dnsmasq, Pi-hole и
подобные биндят `0.0.0.0:53`, что покрывает и tun-адрес. Но выбранный порт **пушился клиенту**,
а его не умеет выразить ни одна клиентская платформа: `VpnService.Builder` и `NEDNSSettings`
принимают только адрес, Windows и macOS задают резолверы по IP, и даже Rust-клиент применяет
порт лишь через `resolvectl` (`IP#порт`) — при откате на правку `resolv.conf` порт теряется.
Итог: `dns.port != 53` молча отправлял в чёрную дыру всех клиентов, кроме одного сценария.

Настройка разведена на две независимые: **где слушает прокси** остаётся за `dns.port`, а
**куда обращается клиент** теперь всегда 53. Разрыв закрывает ядро: туннель ставит правило
`iptables -t nat PREROUTING -i <tun> -p udp -d <dns.listen> --dport 53 -j REDIRECT --to-ports
<dns.port>` с тем же тегом `qeli-nat:<профиль>`, что и остальные правила, поэтому оно снимается
вместе с ними при остановке профиля. Правило **проверяется** через `iptables -C`, а не по коду
возврата — `iptables-nft` умеет рапортовать об успехе для неустановленного правила.

Поскольку без iptables мост построить нечем, `dns.port != 53` без него теперь **не проходит
валидацию**: сервер не стартует и объясняет, что делать. Раньше он стартовал и ломал DNS.

Проверено на лабе: правило встаёт и подтверждается, а клиент из отдельного network namespace,
отправляющий запрос на **53**, доходит до слушателя на **5353**. Первая попытка проверки была
негодной — я слал пакет с того же хоста, а `REDIRECT` в `PREROUTING` применяется только к
пришедшим с интерфейса; повторил через veth-пару.

**Отказ DNS-прокси перестал быть немым.** Раньше это была одна строка `ERROR`, при этом туннель
поднимался и продолжал раздавать клиентам адрес несуществующего резолвера — имена не
резолвились, и ничто на причину не указывало. Теперь сообщение называет профиль, адрес, цену
отказа и команду для диагностики.

### По внешнему аудиту 2026-07-30 (второй проход)

- **Пять файлов не были добавлены в git.** `CtrlFrame.kt`, `MtuLadder.kt`, `CtrlFrame.swift`,
  `CtrlFrame.cs` и `icmp.rs` лежали в рабочем дереве как неотслеживаемые, при том что на них
  уже ссылался **отслеживаемый** код во всех четырёх языках. Коммит только отслеживаемых
  изменений сломал бы сборку везде. Причина, по которой это не поймали прогоны тестов: сборка
  на лабе синхронизирует рабочее дерево, а не git, поэтому зелёный гейт доказывал
  работоспособность кода и ничего не говорил о том, что попадёт в коммит.

- **Отчёт о path-MTU не отправлялся при multipath (Android, Windows, macOS).** Ветка bonding
  уходит в отдельный цикл, а отправка отчёта была только в однопоточном. Как следствие, при
  профиле с `max_streams > 1` сервер оставался на `path_mtu = 0` и **всё сужение нисходящего
  потока молча не включалось** — то есть фича, добавленная в этом же релизе, не работала у
  бондящихся клиентов. Rust и iOS шлют отчёт до перехода к bonding и дефекта не имели.

- **Отчёт теперь переотправляется на UDP.** Кадр не подтверждается по устройству протокола
  (сервер не отвечает на control-кадры), поэтому одна потерянная датаграмма стоила сужения на
  всю сессию — именно на том транспорте, где оно нужнее всего. Кадр идемпотентен (сервер
  запоминает последнее значение, а все копии несут одно и то же — минимум он **не** берёт),
  поэтому он просто повторяется: в Rust на первых тиках простоя (~0/5/10 с), в Kotlin, C# и
  iOS — примерно на 2-й и 8-й секунде (задержки в цикле последовательные). На TCP повторов
  нет: там ретрансмит даёт сам транспорт.

- **ICMP: генератор глушил ответ на Echo.** Код отказывался строить Fragmentation Needed для
  **любого** пакета с протоколом ICMP, ссылаясь на RFC 1122 §3.2.2. Но стандарт запрещает
  отвечать ошибкой только на ICMP-**ошибку**; Echo Request — запрос, и RFC 1191 §3 требует
  ответить на любую превышающую MTU датаграмму с DF. На практике это ломало `ping -M do` —
  ровно ту команду, которой проверяют работу PMTUD. Теперь подавляются только типы-ошибки
  (3, 4, 5, 11, 12), а усечённый ICMP трактуется как ошибка (fail-closed). Существовавший
  тест этот дефект пропускал: он не задавал тип явно, и в поле типа попадал байт порта.

- **Комментарий в conformance-фикстуре устарел** — утверждал, что реассемблер не проверяет
  размер чанка, хотя `max_chunk_accept` проверяется во всех реализациях.

- **Нисходящие non-DF пакеты сверх MTU теперь фрагментируются, а не теряются.** Половина
  маршрутизаторной семантики была на месте: при выставленном DF сервер отвечает ICMP
  Fragmentation Needed. Без DF отправитель, наоборот, вправе рассчитывать на фрагментацию — но
  qeli форвардит в пространстве пользователя, ядро этот пакет не видит и не фрагментирует, так
  что он просто отбрасывался с debug-строкой. Чёрная дыра ровно для того трафика, который явно
  сообщил, что не хочет в неё попадать. Добавлена фрагментация по RFC 791
  ([icmp.rs](qeli/src/protocol/icmp.rs)) с сохранением смещения и флага MF, если исходная
  датаграмма сама была фрагментом. Хеш потока берётся один раз от исходного пакета и
  переиспользуется для всех его кусков — иначе фрагменты без L4-портов разъехались бы по разным
  bonded-потокам и пришли не по порядку.

  Отказ (и прежнее отбрасывание) остаётся для заголовков с ОПЦИЯМИ: копирование при
  фрагментации задаётся каждой опцией отдельно, и ошибиться здесь хуже, чем не делать —
  на форвардящемся трафике опции практически не встречаются.

- **Ожидание задач профилей — та же схема, что у listener'ов.** Уровнем выше был тот же
  дефект: задачи профилей ожидались по порядку, здоровый профиль не возвращается никогда, и
  завершение любого последующего профиля не логировалось, пока работал первый. Тоже переведено
  на `JoinSet`; имя профиля теперь возвращает сама задача, потому что при конкурентном ожидании
  порядок завершения не совпадает с порядком запуска.

- **Паритет клиентов — три расхождения.**
  - **ACK на path-MTU пробу сверялся только по id** (Android, Windows, macOS). Rust и iOS
    сверяют оба эхо-поля. Сам по себе id подтверждал лишь «какая-то проба дошла», а не «дошла
    проба ИМЕННО этого размера» — единственный факт, ради которого ступень и принимается.
  - **Счётчик записывался в replay-окно до проверки паддинга** (Android, десктоп). Запись,
    которая расшифровалась (то есть действительно пришла от пира), но несёт битый паддинг —
    это ошибка пира, а не атака; запись счётчика до проверки впустую сжигала его слот в окне.
    Порядок приведён к Rust/iOS, где это уже было сделано осознанно и с комментарием.
  - **`resolvectl` искался по абсолютному пути, но запускался по имени.** `which_resolvectl`
    перебирает `/usr/bin`, `/bin`, `/usr/sbin` именно потому, что у systemd-юнита может не
    быть пригодного `PATH`, — а все четыре вызова шли через `Command::new("resolvectl")`, то
    есть снова через `PATH`. Где это срабатывало, симптом был немой: команда не запускалась,
    вызывающий читал это как «resolvectl не сработал», и DNS тихо уходил на правку
    `resolv.conf`. Все вызовы переведены на найденный абсолютный путь, с откатом на голое имя.

- **Отказ дополнительного listener'а был невидим.** Задачи listener'ов ожидались **по
  порядку**, а accept-цикл не возвращается никогда — поэтому первый `await` вставал навсегда, и
  ошибка bind любого следующего listener'а так и лежала непрочитанной в его handle. Профиль с
  `listen = …`, чей второй порт уже занят, поднимался внешне здоровым, ничего не писал в лог и
  просто не отвечал на этом порту. Теперь задачи ожидаются конкурентно (`JoinSet`): отказ
  логируется в момент возникновения, каким бы listener'ом он ни был. Дополнительно: если
  умерли **все** listener'ы, профиль возвращает ошибку — раньше в этом случае возвращался `Ok`,
  то есть профиль с TUN, пулом и пользователями «успешно» не слушал ничего.

- **`check-config` не проверял `listen`.** Разбор дополнительных listener-спецификаций делался
  только на старте профиля, так что команда проверки объявляла конфиг исправным, а об опечатке
  оператор узнавал из лога живого сервера — или не узнавал. Проверка перенесена в
  `validate_profiles`, поэтому `check-config` и реальный старт снова дают одинаковый вердикт.

- **Android: подключение обходило `validate()`.** Проверки диапазонов вызывались при
  **импорте** профиля и при **выводе** (`toIni`/`toQeliUri`), но `parse()` их не делает — а
  обычный connect, always-on и автозапуск по загрузке звали именно `parse()`. Поэтому профиль,
  сохранённый до появления проверок или отредактированный вручную, доходил до туннеля с
  недопустимыми портом, транспортом, режимом, таймаутом, MTU или паддингом. `validate()`
  добавлен во все три точки входа. Для always-on и загрузки это особенно важно: там нет UI,
  который показал бы отказ, поэтому негодный профиль просто не подключается.

- **C#: границы `timeout` и `padding` во flat-INI.** `timeout` принимал любой положительный
  `long`, а `VpnTunnelBase` затем считает `(int)секунды * 1000` — значение больше ~2,1 млн
  переполняло умножение в **отрицательный** таймаут, то есть не «долгое ожидание», а мгновенно
  истёкшее. Теперь значение зажимается в 1..300 с — те же границы, что уже проверяют Android и
  iOS. `padding_min`/`padding_max` проходили только проверку `>= 0` каждое по отдельности, так
  что INI мог задать инвертированный диапазон (`min > max`) или пятизначный паддинг сверх
  потолка; теперь оба идут через тот же `CheckedPadding`, что и JSON-путь.

- **Клиент принимал любые значения строковых enum'ов.** Серверные поля этого класса
  ужесточили в прошлом проходе (#23), клиентские остались без проверки — хотя механизм отказа
  тот же: значение сравнивается с ОДНИМ литералом, поэтому неизвестное не даёт ошибки, а тихо
  выбирает другую ветку. `proto = UDP` (регистр!) подключался по **TCP**; `mode = realty-tls`
  запускал fake-tls, и пир расходился о проводе; `front = webscoket` отключал WebSocket-обвязку;
  `dns = of` пропускал настройку DNS целиком — в full-tunnel это **утечка DNS**. Добавлен
  `ClientConfig::validate()` с проверкой `proto`, `mode`, `front`, `dns`, `device_type` и
  режима маршрутизации; вызывается и при реальном старте, и в `check-config --client`, чтобы
  они совпадали. `device_type` сверяется без учёта регистра — рантайм его так и читает.

- **⚠️ Приватность: DNS без настройки уходил в Cloudflare.** Фикс R5 от 2026-07-27 специально
  отказывался подставлять сторонний резолвер, когда пользователь не настроил свой, — но
  проверял `dns.servers`, а затем `dns.fallback_servers`, у которого стоял дефолт
  `["1.1.1.1", "8.8.8.8"]`. То есть отказ был **недостижим**, и при `dns = tunnel` (значение
  по умолчанию) с сервером, который не пушит DNS, все запросы клиента молча уходили в
  Cloudflare. Документация при этом обещала ровно обратное: «client keeps its own resolvers».
  Дефолт убран — теперь резолверы хоста остаются нетронутыми, а в лог идёт предупреждение.

  Тест пиннит сам **serde-дефолт**, а не результат `::default()`: `#[derive(Default)]`
  игнорирует `#[serde(default = "…")]`, поэтому проверка через `::default()` проходила бы при
  любом значении — ровно поэтому дефект и дожил до аудита.

  Заодно добавлен ключ `dns_servers` во flat-INI (чтение + запись + round-trip). Раньше INI
  умел задать **режим** DNS, но не **сервер**, поэтому совет из текста ошибки («настройте
  резолвер») из INI-конфига выполнить было нечем; сам текст ошибки тоже был испорчен
  склейкой строк и содержал длинные пробельные хвосты.

### Паритет клиентов по лестнице path-MTU (№12) и проба на iOS (№16)

- **Лестница path-MTU перенесена в Windows, macOS, Android и iOS.** Rust-клиент починили
  раньше, а в четырёх остальных нижней ступенью так и стояло число 1280 — но **как MTU
  туннеля**, тогда как 1280 это предел **пути**. То есть у пути с MTU 1280 запрашивалось
  1280 + оверхед (~76 байт), ни одна ступень не проходила, probe возвращал «нет результата»
  и клиент откатывался на pushed-MTU с включённой обратно фрагментацией — ровно тот исход,
  ради предотвращения которого зондирование и существует. Теперь во всех клиентах пол
  выводится как `1280 − внешний оверхед`, а сам оверхед считается по факту (obfs-печать,
  QUIC-заголовок, UDP, IP), а не угадывается.

  Это напрямую разблокировало предыдущий пункт: сервер сужает нисходящий поток по тому, что
  сообщил клиент, но клиент сначала должен узкий путь **обнаружить**. До этой правки на
  Windows/macOS/Android/iOS он его не находил, сообщал pushed-MTU, и сужение на сервере не
  включалось вовсе — то есть №13 работал только с Rust-клиентом.

- **Идентификатор пробы теперь случайный на Windows, macOS и Android.** Был фиксированный
  старт `"MT"` плюс предсказуемый +1 на ступень, что позволяло off-path атакующему подделать
  probe-ACK и закрепить клиента на слишком большом MTU (DoS на `fake-tls`-UDP без obfs, где
  проба идёт в открытом виде). В Rust и iOS случайный старт уже был.

- **iOS: проба доступности не фрагментировала ClientHello (№16).** Post-quantum hello набит
  до ≥1200 байт и уходил **одной** датаграммой, требующей IP-фрагментации, которую мобильные
  и CGNAT-пути режут: проба показывала «сервер недоступен» именно там, где настоящее
  соединение подключается. Теперь порядок слоёв совпадает с дата-планом — сначала
  фрагментация, потом QUIC внутрь каждого фрагмента, потом obfs снаружи каждой датаграммы,
  и ожидание ответа висит на последней. На остальных клиентах это было исправлено ранее.

### По внешнему аудиту 2026-07-30

- **Фрагмент handshake не влезал в минимальный MTU IPv6.** Размер куска был прибит к 1200 —
  числу, взятому у QUIC, где оно бюджетирует **датаграмму целиком**, а не полезную нагрузку
  внутри ещё четырёх слоёв. Handshake оборачивает каждый фрагмент в **длинный** заголовок
  QUIC (18 Б; у data-plane короткий — всего 9), поэтому реальный худший случай был
  1200 + 6 + 18 + 13 + 8 + 40 = **1285 при лимите 1280**: на пути с MTU 1280 (IPv6-минимум,
  обычное дело на мобильных) с включёнными `obfs` + QUIC-маскировкой post-quantum handshake
  не мог завершиться вообще. Теперь размер **выводится** из именованных констант внешних
  слоёв, с резервом 32 Б, и тест падает, если бюджет снова перерасходован.

  Отдельно разведены **отправка и приём**: посылаем по новому бюджету, а принимаем по-прежнему
  до 1200. Это принципиально — та же константа служила верхней границей на приёме, и если бы
  она уменьшилась вместе с отправкой, новый пир отвергал бы каждый фрагмент старого
  («fragment chunk too large»), то есть совместимость сломалась бы в обратную сторону. Обе
  границы теперь зафиксированы в кросс-языковой фикстуре, и порт обязан совпасть по обеим.
  Правка внесена в Rust, C#, Kotlin и Swift.

- **Сервер игнорировал найденный клиентом path MTU (нисходящее направление).** Клиент зондирует
  путь и подстраивает свою отправку, а сервер резал обратный поток по статичному `tun.mtu` из
  профиля — про узкий участок «сервер → клиент» он не знал ничего. Итого path-MTU работал
  наполовину: uplink жил, а downlink продолжал попадать в чёрную дыру. Снаружи это выглядит
  как «подключился, мелкое ходит, крупное висит» — ровно тот сценарий LTE/CGNAT, ради которого
  зондирование и делалось.

  Теперь клиент сообщает выбранный MTU **внутри шифрованного туннеля** — новым контрольным
  кадром (`[0xC1][0x9B][тип][длина][тело]`; старший полубайт `0xC` не равен ни 4, ни 6, поэтому
  кадр никогда не спутать с IP-пакетом). Внутри туннеля, а не отдельной датаграммой рядом с
  пробами, потому что у тех единственный признак принадлежности — адрес источника: кто угодно,
  угадав `IP:port` сессии, мог бы урезать ей MTU. Сервер, узнав про узкий путь, ведёт себя как
  положено маршрутизатору: на превышающий пакет с установленным DF отвечает источнику ICMP
  «Fragmentation Needed» с настоящим next-hop MTU (RFC 1191), и path-MTU discovery сходится
  сам. Тем же значением ограничен и padding — иначе он раздувал пакет обратно за границу.

  Совместимость аддитивная в обе стороны: старый сервер отбрасывает кадр как некорректный
  пакет и остаётся на профильном MTU, а старый клиент ничего не присылает — и проверка на
  сервере не включается вовсе. Отчёт отправляют все клиенты: Rust, Windows, macOS, Android, iOS.

- **Пакет OpenWrt нельзя было собрать.** `PKG_MIRROR_HASH` — заведомо несовпадающая заглушка
  (это правильно: лучше громкий отказ, чем сборка без проверки), но настоящий хеш существует
  только в момент тега, когда опубликован релизный тарбол. Поэтому вместо выдумывания значения
  добавлен предрелизный гейт: `release_preflight.py` теперь падает, если хеш всё ещё заглушка,
  если он равен `skip`, если `PKG_SOURCE_VERSION` указывает не на выпускаемый коммит или если
  `PKG_VERSION` разошёлся с версией crate'а. Забыть про хеш стало нельзя.

### По внешнему аудиту 2026-07-29

- **C#: сохранение профиля молча сбрасывало настройки.** `ToIni` не сериализовал ни один
  из ключей timeout / reconnect / padding / heartbeat / shaping, `FromIni` их не читал, а
  `FromJson` терял вдобавок `traffic_shaping` и `tun.mtu_probe`. Это не только про экспорт:
  редакторы Windows и macOS сохраняют через `BuildFromForm().ToIni()`, то есть достаточно
  было ОТКРЫТЬ профиль и нажать «сохранить», чтобы потерять то, что задал пользователь или
  импортированный профиль с другого клиента. Все три пути приведены к симметрии; имена
  ключей взяты из диалекта Android, который этот же дефект у себя уже закрыл, поэтому
  профили теперь ходят между мобильными и десктопными клиентами без потерь. Проверено
  прогоном round-trip на 24 значениях.

- **Нормализация длины могла нарушить только что найденный MTU.** Она увеличивает пакет до
  следующего настроенного размера, а ограничение ниже по коду применяется **только к
  padding'у** (`mtu − длина данных`). Поэтому если нормализация уже вывела пакет за MTU,
  ограничение схлопывалось в ноль и переросший пакет уходил как есть — а после успешной
  path-MTU пробы на сокете взведён DF, так что такая датаграмма просто отбрасывалась с
  EMSGSIZE. Практический пример: найденный MTU 1280, пакет 1200, в `round_sizes` есть 1500.
  Теперь нормализация знает потолок и пропускает размеры, которые в туннель не влезают,
  выбирая ближайший подходящий. Покрыто тестом на все три случая.

- **Проба доступности UDP отвечала не на тот вопрос.** Она шлёт тот же post-quantum
  ClientHello, что и настоящее соединение, но — в отличие от него — **одной** датаграммой
  больше 1200 байт. Такой пакет требует IP-фрагментации, а мобильные и CGNAT-пути её режут:
  проба показывала «сервер недоступен» ровно на тех сетях, где реальный клиент, фрагментирующий
  на уровне приложения, подключается. На Windows и macOS к этому добавлялись ещё две вещи:
  QUIC и obfs стояли через `if/else`, хотя это **слои**, — поэтому профиль `quic + obfs`
  отправлял QUIC без внешней obfs-печати, сервер его отбрасывал, и такая комбинация не могла
  позеленеть никогда; и длинный заголовок помечался типом Handshake при раскладке Initial.
  Все пробы приведены к обрамлению data-plane: фрагментация, затем QUIC внутрь, затем obfs
  снаружи. На Android слоение уже было верным — там добавлены фрагментация и тип пакета.

  Остаток: у iOS-пробы фрагментации по-прежнему нет. Там это требует смены сигнатуры
  вспомогательной функции с одной датаграммы на список, а Swift в текущем окружении не
  собирается — делать такое без компилятора значит рисковать сборкой всего приложения.

- **Сервер принимал `udp + reality-tls`, хотя настоящего TLS там нет.** REALITY заворачивает
  туннель в НАСТОЯЩУЮ сессию TLS 1.3, а это TCP-поток; у UDP-обработчика такого транспорта нет,
  и он проваливается в датаграммное обрамление fake-tls/obfs. То есть профиль стартовал,
  назывался `reality-tls` и не клал на провод ни одного байта настоящего TLS — оператор
  считает, что включил самую стойкую маскировку из имеющихся, а получил самую слабую.
  Отвергался только `plain+udp`; iOS-клиент обе комбинации запрещал давно, так что
  разрешающей стороной был именно сервер. Живой прод-конфиг проверен — под запрет не попадает.

- **iOS: сторож тишины срабатывал и там, где сервер молчит по построению.** Проверка
  «от сервера ничего не пришло» шла безусловно, поэтому при выключенных heartbeat и cover
  здоровый простаивающий туннель рвался примерно раз в 30 секунд — тот же дефект, что был на
  Android. Теперь она под тем же условием; проверка «мы шлём, а ответа нет» осталась
  безусловной, потому что срабатывает только при нашем собственном трафике. Новый параметр
  сделан со значением по умолчанию, чтобы прежние вызовы сохранили смысл, и покрыт тестом.

- **Мобильные клиенты теряли часть импортируемого профиля.** На Android `fromJson`
  переставал заполнять поля на heartbeat, поэтому канонический JSON с shaping, с явным
  `tun.mtu_probe = false` или с блоком `[logging]` импортировался с ДЕФОЛТАМИ: профиль
  выглядел настроенным и не был им, а повторный экспорт записывал потерю обратно на диск.
  Добавлены все три группы, покрыто тестом (импорт + round-trip через INI); на старом
  импортёре тест падает целиком.

  На iOS та же болезнь по другой причине: читалась секция `obfuscation.shaping` с полями
  `gap_*`, тогда как канонические имена — `traffic_shaping` и `idle_gap_*`. То есть ничего из
  того, что пишет сервер и остальной проект, не совпадало, и shaping всегда приходил
  дефолтным. Теперь читаются канонические имена, короткое написание оставлено запасным
  вариантом, чтобы профили от прежних сборок этого клиента продолжали грузиться.

- **Android принимал сырой INI без проверки.** Оба места импорта звали `VpnConfig.parse`, а
  рядом стоял комментарий «validate» — но `fromIni` валидацию не вызывает, и это и был весь
  дефект: файл с портом `0` или `99999`, неизвестным `proto`/`mode`, таймаутом вне диапазона
  или отрицательным reconnect сохранялся дословно и падал много позже, уже при подключении.
  Проверка перенесена на границу, где входит недоверенный текст, — ровно как это давно
  сделано для `qeli://`-ссылок. Загрузку уже сохранённых профилей намеренно не трогал: иначе
  профиль, записанный до появления проверок, перестал бы открываться.

- **PMTU-зонд не мог измерить узкий путь — тот самый, ради которого он существует.**
  Ступени лестницы задавались в единицах ВНУТРЕННЕГО (туннельного) MTU, а нижняя была равна
  1280 — минимальному ВНЕШНЕМУ пути IPv6. Но зонд для внутреннего `m` занимает на проводе
  `m` плюс наши 48 байт записи, плюс obfs-печать, QUIC-заголовок, UDP и IP: до 76 байт сверх.
  То есть на пути с реальным MTU 1280 не проходила **ни одна** ступень, зонд возвращал
  «результата нет», а вызывающий откатывался к пушнутому MTU (обычно 1400) и заново
  **разрешал IP-фрагментацию** — ровно тот исход, который зондирование должно предотвращать.
  Пол лестницы теперь вычисляется из фактических накладных для этого соединения (obfs и QUIC
  включены или нет, IPv4 или IPv6), добавлены ступени ниже 1280. Расчёт вынесен в чистую
  функцию и покрыт тестом; тест негативно проверен — со старым полом он падает с
  «lowest rung 1280 + overhead 76 exceeds the 1280 path floor».

- **macOS: запуск демона зависал после удаления его каталога.** Plist задаёт
  `StandardErrorPath` внутри `/Library/Application Support/Qeli/`, но launchd создаёт по этому
  пути только файл, не каталог: если каталога нет, задание не стартует, а `launchctl bootstrap`
  виснет, пока его не убьёт 20-секундный бound — и в диалоге видно лишь «timed out», без
  единого упоминания настоящей причины. Каталог до сих пор существовал по случайности порядка
  вызовов (его создавал `daemon-install`, записывая профиль), поэтому достаточно было снести
  `/Library/Application Support/Qeli` — вполне разумное действие при разборе проблемы, — чтобы
  все последующие запуски зависали. `Start()` и `Install()` теперь создают каталог сами.

- **Релизные гейты не проверяли то, что выпускают.** `release_preflight` печатал `headSha`
  зелёного прогона CI и не сверял его ни с чем: прогон с более раннего пуша той же ветки
  удостоверял коммит, которого CI не видел. Теперь расхождение с выпускаемым `HEAD` — отказ.
  Плюс две дыры в path-фильтрах: изменения только в `qeli-openwrt/**` или `release/**` не
  запускали CI вовсе, то есть отдаваемое пользователям можно было править без единой проверки.
  И Android-job наконец собирает `assembleRelease` — раньше APK, который люди устанавливают,
  в CI не собирался ни разу: `assembleDebug` проверяет другой вариант, а `lintRelease` читает
  исходники, не производя артефакт, так что R8, сжатие ресурсов и упаковка впервые
  выполнялись на релизной машине. Проверено на стенде: собирается без подписи, APK 4.0 МБ.

- **Пушнутый размер heartbeat не доходил до клиентов.** Сервер отправляет
  `heartbeat.data_size_bytes`, но декодеры пуша на Android и в C# это поле не несли: клиент
  padding'овал keepalive по своему локальному значению, а выбор сервера — единственная его
  ручка, чтобы сделать удары менее узнаваемыми, — не применялся. Проведено через пуш на обеих
  платформах, с тем же клэмпом, что и остальные размерные поля.

  Оговорка по остальным полям пуша: `padding.randomize`, `padding.probability` и
  `traffic_normalization` GUI-клиенты **не реализуют** — у их кодеков нет соответствующих
  ручек, а нормализация не написана вовсе. Декодировать их значило бы сделать вид, что они
  поддержаны, поэтому оставлены как есть, а неверное утверждение документации, будто пуш
  «безусловно перезаписывает» весь блок, исправлено отдельно.

- **Android: idle-туннель реконнектился примерно раз в 30 секунд.** Сторожевой таймер
  «от сервера ничего не пришло» срабатывал безусловно, хотя при выключенных heartbeat и
  cover-трафике сервер молчит **по построению** — то есть таймер рвал совершенно здоровую
  сессию, и так по кругу. Rust и C# этот случай уже различали, Android нет. Проверка теперь
  под тем же условием (`expectServerData`), в одиночном и в bonded-пути. Смежная проверка
  «мы шлём, а в ответ тишина» осталась безусловной — она и должна быть такой, потому что
  срабатывает только когда трафик идёт от нас.

- **Android не ограничивал пушнутые сервером значения.** `padding.max_bytes` или размер
  cover-пакета сверх того, что влезает в одну запись, заставляли `PacketCodec` бросить
  `MAX_RECORD_SIZE` на первом же пакете: исключение всплывало как ошибка туннеля, клиент
  переподключался, получал тот же пуш и зацикливался. Злого умысла для этого не нужно —
  достаточно лишней цифры в конфиге, а сервер эти поля до сих пор тоже не проверял (закрыто
  в этом же проходе). Значения клэмпятся при декодировании пуша, как уже делает iOS.

- **QUIC-заголовок был помечен Handshake при раскладке Initial.** Сериализатор всегда пишет
  varint `Token Length`, который существует **только** в Initial-пакете, а вызывающие
  передавали тип `0x02` (Handshake). Собственные парсеры это принимали лишь потому, что тоже
  безусловно ждут Initial; сторонний QUIC-разбор прочитал бы длину токена как поле Length.
  Rust уже слал `0x00` — Android, C# и iOS приведены к нему.

- **Усечённая UDP-запись принималась как короткая.** Длина из заголовка обрезалась по размеру
  буфера (`coerceAtMost` / `Math.Min`), поэтому обрезанная посредником датаграмма превращалась
  во внешне валидную запись: дальше падала AEAD и рвался туннель, а настоящая причина в лог не
  попадала. У UDP нет продолжения, поэтому такая датаграмма теперь отбрасывается целиком и
  читается следующая; заодно длина ограничена максимумом записи, чтобы враждебное поле не
  задавало размер копии. Исправлено в Android и C#; iOS это делал корректно и раньше.

- **Валидация конфига: закрыт остаток «опечатка молча меняет режим».** Прошлый аудит закрыл
  этот класс для mtu, brute-force и DHCP-пула, но не для остального. Теперь отвергаются при
  загрузке: `listen`-адрес, который невозможно забиндить (`host:99999`, порт 0, небракетованный
  IPv6 — раньше проверялось только наличие двоеточия, и ошибка bind второго слушателя никем не
  читалась, так что порт просто отсутствовал при здоровом на вид сервере); бессмысленные
  значения padding / fragmentation / normalization / shaping (инвертированные min/max,
  `max_fragments_per_packet = 0`, вероятность вне `0..=1` и NaN); `dns.upstream`, где невалидны
  **все** записи (клиентам при этом раздаётся этот же резолвер — чёрная дыра на каждое имя);
  невалидные `dns.push_servers`; и строковые режимы `obf.fronting`, `tun.device_type`,
  `dns.upstream_protocol`, каждый из которых сравнивался ровно с одним литералом, так что
  опечатка тихо выбирала другую ветку. Отдельно: `upstream_protocol = tls` больше не
  принимается — DoT не реализован, и раньше это значение молча слало открытый UDP.
  Поставляемые примеры и живой прод-конфиг проверены — принимаются.

- **IPv6-bind не мог работать.** Слушатели собирали адрес как `format!("{}:{}", addr, port)`,
  и для `::1` получалось `::1:8080` — не socket-адрес вовсе. Затрагивало VPN-слушатель,
  DNS-прокси и панель (в CSRF-проверке панели скобки уже были — там всё верно). Введён общий
  `util::join_host_port`, который не удваивает уже проставленные скобки; покрыт тестом,
  проверяющим и то, что результат парсится в `SocketAddr`.

### Kill-switch: фантомные адреса резолверов считались настоящими

В allow-лист kill-switch на Windows попадали `fec0:0:0:ffff::1/2/3` — захардкоженные
в системе site-local адреса DNS, которые Windows показывает почти на каждом
IPv6-интерфейсе, хотя туда ничего не маршрутизируется (сам префикс `fec0::/10` объявлен
устаревшим в RFC 3879). Фильтр отсекал IPv6 **link**-local, но не **site**-local.

Утечки это не даёт, но цена двойная. Шесть бессмысленных правил файрвола на каждое
подключение — и, что важнее, список резолверов выглядит непустым. От этого зависит выбор
между «DNS разрешён к таким-то серверам» и fail-closed «физический DNS заблокирован
полностью»: на машине, где в списке одни фантомы, клиент считает, что DNS разрешён, тогда
как реальные запросы блокируются, — и реконнект по имени падает без объяснений в логе.

Введён единый критерий «пригодного внешнего резолвера», одинаковый на всех трёх
платформах: отбрасываются loopback, unspecified, multicast, link-local, site-local
`fec0::/10` и IPv4 APIPA `169.254/16`. На macOS не фильтровалось вообще ничего, на Linux —
только loopback. Покрыто тестом на конкретных адресах.

### Kill-switch: Linux пропускал DNS куда угодно

Правило было `--dport 53` **в любой адрес**, поэтому всё время, пока туннель лежит,
DNS-запросы **всех** приложений уходили открытым текстом через физический интерфейс — и на
резолвер по выбору запрашивающего. Это ровно та утечка метаданных, ради которой kill-switch и
существует. На Windows и macOS её закрыли ещё в клиентском аудите, сузив правило до системных
резолверов; Linux остался с исходным, то есть самая строгая из трёх платформ оказалась самой
дырявой.

Теперь порт 53 разрешён только к резолверам, которые хост реально использует. Список читается
до того, как туннель подменит DNS: сначала `/run/systemd/resolve/resolv.conf` (там настоящие
апстримы, когда работает systemd-resolved), затем `/etc/resolv.conf`; loopback-адреса
пропускаются — stub и так покрыт правилом для `lo`, а считать его «резолвером» значило бы
скрыть, что настоящие апстримы неизвестны. Fail-closed, как на других платформах: не
прочиталось ни одного — правило не ставится вовсе, реконнект идёт по разрешённым IP сервера.
Разбор покрыт тестом (stub, дубликаты, битые строки).

### Клиенты: две вещи, о которых лог молчал

- **`kill_switch = true` при `gateway = false` не делает ничего — и не говорил об этом.**
  Kill-switch блокирует всё, что не туннель, и осмыслен только когда туннель несёт дефолтный
  маршрут; в split-tunnel нетуннелированный трафик — это и есть цель, закрываться не от чего.
  Пропуск правильный, молчаливый пропуск — нет: ключ стоит в конфиге и выглядит как защита,
  а в логе ни строки ни за, ни против. Теперь пишется `NOTE: kill_switch = true is ignored
  in split-tunnel mode …` с указанием, что включить, если защита нужна.

- **Лог смешивал языки.** Собственные строки клиента английские, а текст исключений .NET
  локализуется по языку системы — на русской Windows в тот же лог попадали строки вроде
  «Удаленный хост принудительно разорвал существующее подключение». Их нельзя ни найти в
  каталоге ошибок `TROUBLESHOOTING.md`, ни разобрать при разборе чужого репорта. Проекты
  теперь собираются с `SatelliteResourceLanguages=en`, поэтому `e.Message` приходит
  по-английски независимо от локали. Русский/английский интерфейс самого приложения не
  затронут — он на своей таблице `Loc`, а не на сателлитных сборках.

### Добавлено — `qeli share-link`: повторная выдача конфига существующему пользователю

Раньше `qeli://`-ссылку умела печатать только `add-client`, а она **создаёт** пользователя и
на существующем имени падает. Единственным способом переслать клиенту конфиг заново была
панель. Теперь то же самое есть в CLI:

```
qeli share-link <user> [--host <адрес[:порт]>] [--profile <имя>] [--label <текст>] [--reset]
```

Пароль вводить не нужно: он берётся из обратимо зашифрованной копии, которая пишется рядом с
необратимым Argon2-хешем при заведении пользователя (сам хеш в ссылку превратить нельзя).
Остальное выводится из профиля: порт, транспорт, wire-режим, SNI, obfs-ключ, reality
short_id, awg-параметры, закреплённый ключ сервера. `--host` по умолчанию берётся из
`web.public_host`. Семантика полностью повторяет панель, включая отказ при отсутствии
восстановимой копии и разрушающий `--reset` (новый пароль + предупреждение, что текущий
конфиг пользователя перестаёт работать). Отличие одно и оно названо в выводе: у CLI нет
канала к работающему воркеру, поэтому после `--reset` нужен `systemctl reload qeli`.

**Попутно убрано дублирование.** Соответствие «поля ссылки ← профиль» существовало в ДВУХ
копиях (панель и `add-client`); третья была бы неизбежным источником расхождений — правила
там неочевидные (`awg` объявляется только там, где хендшейк реально шлёт junk; `rsid` — при
любом включённом reality-прокси, не только при `real_tls`), а ссылка, соврав про режим, даёт
клиента, который не подключается. Логика вынесена в `ClientLink::for_profile`, обе прежние
копии переведены на неё.

Проверено на лабе: гейт (build/414 тестов/clippy/fmt) + сквозной прогон 7 сценариев —
подстановка пароля без ввода, host из `web.public_host`, отказ без `--reset` у legacy-юзера,
сброс с сохранением, повторная выдача после сброса, ошибки на неизвестных user/profile.
([main.rs](qeli/src/main.rs), [config/share.rs](qeli/src/config/share.rs),
[web/api/share.rs](qeli/src/web/api/share.rs); доки — `docs/{ru,eng}/GETTING-STARTED.md` §10.2.1)


## [0.7.13] — 2026-07-28

### Панель за reverse-proxy: две тихие ловушки

Обе диагностируются тяжело потому, что панель при этом «почти работает». Проверено на
стенде (nginx 1.26 + панель под `/qeli/`), см. `TROUBLESHOOTING` §6.13.

- **Мусорный `base_path` ронял всю панель в 404 молча.** В flat-INI `#` и `;` начинают
  комментарий **только с начала строки**, поэтому `base_path =   # оставить пустым` даёт
  значением литерал `# оставить пустым`. Панель монтировалась под префиксом, который браузер
  никогда не запросит, и все маршруты, включая `/login`, отдавали 404 — без единой строки в
  логе. Теперь значение проверяется тем же allow-листом, что и заголовок от прокси: если это
  не обычный URL-путь, панель поднимается в корне и пишет ERROR с самим значением и
  напоминанием про правило комментариев. На стенде: было 404 на `/login`, стало 200 + ошибка.

- **`X-Forwarded-Prefix` отбрасывался без следа.** Заголовок принимается только от адреса из
  `web.trusted_proxies`; при пустом списке он игнорируется — это правильно, клиент не должен
  диктовать базовый путь. Но происходило это молча, а видимым следствием был лишь уход
  редиректов (`/login`, `/`) на корень сайта: страницы-то грузятся, относительные ссылки
  разрешаются от URL запроса. Симптом при этом выглядит плавающим — с живой сессией
  редиректа нет вовсе, и панель «ломается» только после рестарта службы. Теперь такой
  запрос один раз за процесс пишет WARN с адресом, который нужно внести в список.

### ⚠️ macOS: демон невозможно было установить из `/Applications`

Проверка расположения бинаря перед установкой LaunchDaemon (`EnsureProtectedLocation`)
требовала, чтобы бинарь и **каждый** его родительский каталог были root-owned и не
group/world-writable. Но macOS штатно раздаёт `/Applications` как `root:admin 0775` —
**group-writable**, именно чтобы администратор мог ставить приложения. То есть проверка
отвергала ровно то расположение, куда её собственное сообщение об ошибке предлагало
переместить приложение. Установить демон из нормальной инсталляции было нельзя, а GUI при
этом продолжал запрашивать пароль администратора.

Проверка измеряла не то свойство. На macOS членство в группе `admin` и так даёт `sudo`,
поэтому её право записи — не повышение привилегий: администратор может стать root напрямую.
Теперь group-write допускается для `wheel` (gid 0) и `admin` (gid 80) и отвергается для всех
прочих групп; world-write фатален всегда, как и не-root владелец. Владелец самого бандла
по-прежнему обязан быть root — пользовательский бандл действительно подменяем без всяких
привилегий, а launchd запускает его как root; лечится `sudo chown -R root:wheel
/Applications/Qeli.app`, эта команда есть в тексте ошибки.

### ⚠️ macOS: клиент с kill-switch не подключался вовсе

Дефект первых сборок 0.7.13, исправлен в этом же релизе.

На обычном маке, где pf никогда не включали, `pfctl -sr` не возвращает ничего — **загруженного**
ruleset просто нет. Переработанный в этом релизе kill-switch ищет в нём точку привязки якоря
(`anchor "com.apple/*"` либо свой `anchor "qeli"`), не находит ни одной и отказывается
вооружаться. Отказ обрабатывается строго fail-closed — при `kill_switch = true` клиент
**не подключается вообще**:

```
[SECURITY] kill-switch could not be engaged: … — not connecting unprotected
```

В 0.7.12 этого не было, потому что старый код просто перезагружал `/etc/pf.conf` — файл
Apple, где нужный якорь есть. Отсюда и картина «на 0.7.12 работало, на 0.7.13 клиент мёртв»,
на которую не влияет ни снос launchd-демона, ни удаление `/Library/Application Support/Qeli`:
демон и права были ни при чём.

Сюда же относится жалоба «просит рут в попапе, даю — и он просит снова». Отдельного дефекта
там нет: в режиме демона **каждое** нажатие Connect идёт через свой вызов
`osascript … with administrator privileges`, а macOS между отдельными вызовами авторизацию не
кеширует, поэтому один клик = один запрос пароля. Повтор возникал потому, что демон
запускался, тут же отказывался подключаться по причине выше и статус не доходил до
`Connected` — пользователь жал Connect снова и снова видел запрос.

Теперь пустой ruleset и непустой различаются. Если не загружено **ничего**, клиент сам
загружает системный `/etc/pf.conf` — терять там нечего, это файл самой ОС, и ровно это делают
её собственные утилиты. Если ruleset непустой, но наших якорей в нём нет, отказ сохраняется:
там пришлось бы затереть чужие живые nat/rdr/scrub-правила.

**Обход на затронутых сборках** — либо выключить kill-switch в настройках, либо разово
выполнить `sudo pfctl -f /etc/pf.conf` (действует до перезагрузки).

Заодно отказ стал самообъясняющим. В строке состояния было глухое `kill-switch failed`, а
единственный полезный текст лежал в журнале — то есть при отказе подключиться интерфейс
показывал ровно то, по чему ничего нельзя понять. Теперь туда выносится причина
(`kill-switch failed — the loaded pf ruleset references neither …`), одной строкой; полное
сообщение с командой по-прежнему в журнале. Касается всех платформ, не только macOS.

### Windows: восстановление после сна — вторая итерация

Первая правка этого релиза закрыла не ту составляющую. Она ограничивала **паузы между**
попытками, а время уходило **внутри одной попытки**, поэтому в сборках 0.7.13 до второй
правки задержка оставалась прежней.

- **Одна попытка могла занять почти минуту сама по себе.** Резолв имени сервера шёл через
  `Dns.GetHostAddresses` — блокирующий `getaddrinfo` **без какого-либо таймаута**, а сразу
  после пробуждения резолвер обычно ещё недоступен, и ОС отрабатывает всю свою схему
  повторов. Следом `ConnectionTimeoutSecs` (дефолт **30с**) отсчитывался на connect, и
  столько же на чтения хендшейка. Итого одна неудачно попавшая попытка перекрывала всё
  30-секундное окно оседания целиком, и ограничение бэкоффа не давало ничего. Теперь на
  время оседания весь преддата-плейновый этап (резолв + connect + хендшейк) ограничен 5с:
  соединение по живому пути укладывается заметно быстрее, а вместо одного 30-секундного
  зависания получается несколько дешёвых повторов, попадающих в момент готовности сети.
  Резолв ограничен по времени **всегда**, а не только при оседании.

- **Окно оседания в самом частом случае не взводилось вовсе.** Оно ставилось за guard'ом
  `_wasConnected`, а после сна туннель к моменту прихода события Resume обычно уже мёртв —
  сокеты ушли вместе с suspend. То есть в единственном сценарии, ради которого окно и
  вводилось, все вызывающие выходили досрочно. Взведение вынесено вперёд отдельным
  `NoteNetworkSettling()`; решение «нужно ли ещё и рвать соединение» принимается после.

- В лог добавлена строка `Network settling — short attempt budget …` — по ней видно, что
  окно взвелось. Если восстановление всё ещё медленное, её наличие означает, что время
  уходит в другом месте.


### ⚠️ Android: APK подписан своим ключом — старое приложение нужно удалить

До первой выкладки 0.7.13 включительно в релизы уходила **отладочная сборка**
(`assembleDebug`) с `android:debuggable=true`, подписанная **debug-ключом Android SDK**.
Этот ключ лежит в каждой установке SDK, то есть подписать им сборку может кто угодно и
подпись не подтверждает происхождение приложения. Google Play Защита стала блокировать
такой APK как вредоносный — при том, что приложение просит `BIND_VPN_SERVICE` и
`QUERY_ALL_PACKAGES`.

Теперь выкладывается `assembleRelease`, подписанный собственным ключом проекта
(RSA-4096, `CN=Qeli`), с включённым R8. Android не обновляет приложение поверх при смене
подписи, поэтому **один раз** потребуется: сохранить конфиги → удалить Qeli → установить
новый APK → перенести конфиги заново. Дальнейшие обновления встанут поверх обычным образом.

Заодно починена сборка подписи: `signingConfigs` живёт в модуле `:app`, поэтому голый
`file()` искал хранилище в `qeli-android/app/`, тогда как `keystore.properties.example`
предписывает класть его в корень проекта — задокументированная раскладка не собиралась
вообще.

### Документация — сверка с кодом

Проверка на достоверность после всех правок релиза. Расхождения ниже — не переформулировки,
а места, где документ описывал не то поведение, которое даёт код.

- **Kill-switch был описан только для Linux**, хотя есть на четырёх платформах и устроен
  везде по-разному. Раздел в CONFIG.md переписан: сводная таблица (механизм / область /
  снятие вручную), общие для всех реализаций гарантии (поднимается до connect-loop, держится
  через реконнекты, fail-closed при неудаче постановки правил, снятие только на чистой
  остановке) и отдельные подразделы. Windows — WFP: `DefaultOutboundAction=Block` +
  allow-группа `qeli_ks`, порядок операций без окна блокировки, сознательное сужение DNS до
  системных резолверов, pid-штамп состояния против сноса чужого активного kill-switch,
  восстановление в `NotConfigured`, а не `Allow`. macOS — pf: свой якорь (или `com.apple/qeli`
  под штатной wildcard-ссылкой) и почему снимать надо flush якоря, а не `pfctl -f /etc/pf.conf`.
  Android — системный Always-on VPN, iOS — не поддерживается. Добавлено предупреждение, что
  на Windows и macOS область действия — весь хост, а не один интерфейс.

- **«Хук выполняется от root»** — неверно для установки из `.deb`: поставляемый юнит
  `User=qeli`, и хук идёт от `qeli` с ambient-capability. От root он работает только при
  явном `set-service-user root`, в контейнере и при ручном запуске из-под root. Разница
  существенная: сетевых команд capability хватает, записи в `/etc` — нет.

- **Три ужесточённые проверки конфига не были описаны**, хотя теперь отвергают конфиг при
  загрузке: диапазон `tun.mtu` `576..=9000` (и на сервере, и на клиенте), границы
  `brute_force.*` (проверяются даже при `enabled = false`; описано, чем именно опасны нули в
  обе стороны), и требование, чтобы DHCP-пул лежал внутри подсети туннеля. Все три раньше
  принимались молча и ломались позже — ровно те отказы, которые выглядят как «подключается,
  но не работает».

- **Маскировка секретов в сыром редакторе панели** (`<unchanged>` вместо `password_hash` /
  `password_enc` / `password`) не была задокументирована — оператор увидел бы плейсхолдер и
  не понял, оставлять его или затирать. Описано в PANEL.md обеих локалей.

- **Docker: заявлялась привязка к :443 «не от root»**, хотя в образе нет `USER` и сброса
  привилегий в entrypoint — процесс внутри контейнера работает от root. Добавлен блок о том,
  что это значит на практике: разделения привилегий нет, ловушка с владельцем `/etc/qeli` не
  возникает (но файлы в томе появляются на хосте с uid 0), хуки действительно идут от root, а
  перезапуск из панели не работает и не пытается.

- **`exit_node`: определение WAN было описано устаревшим способом.** В документации значилось
  «WAN определяется автоматически (`ip route get 1.1.1.1`)», хотя после фикса R4 зонд — это
  фолбэк, а первым читается `ip route show default`. Разница не косметическая: именно
  зонд-как-единственный-способ и был багом (на хосте, где 1.1.1.1 маршрутизируется особо,
  правила ставились не на тот интерфейс). Заодно дописано, что правила exit-узла снимаются
  только на чистой остановке, а краш их оставляет, и добавлена процедура ручной чистки в
  §13.2 GETTING-STARTED — по фактическим тегам правил `qeli-exit-node` / `qeli-gw-nat`.
  Пример на три узла доведён до копипастного: показано, что дефолт пушится **конкретному**
  пользователю (`route = 0.0.0.0/0` в его `[user:*]`), поэтому один выход обслуживает
  выбранных, а не всех, — плюс команды проверки, что схема поднялась.

- Поведение реконнекта после сна и §A.3 приведены в соответствие с фиксами этого релиза
  (см. ниже): §A.3 теперь разделяет закрытый случай (перезапись существующего файла) и
  по-прежнему актуальный (создание новых файлов от root).

### По репорту с эксплуатации (2026-07-25)

Разбор шести пунктов с боевых установок. Диагностика каждого — в
[docs/ru/manuals/TROUBLESHOOTING.md](docs/ru/manuals/TROUBLESHOOTING.md) (§6.9–6.12), включая команды для
установок, уже сломанных до апдейта.

- **Атомарная запись отбирала владельца файла.** «Записать во временный файл и `rename`»
  подставляет новый inode, принадлежащий тому, кто пишет, поэтому один `sudo qeli add-client`
  переводил `/etc/qeli/users.conf` из `qeli:qeli` в `root:root`. Права сохранялись, владелец —
  нет. Проявлялось это далеко от места поломки: файл блокировки создаётся с владельцем
  охраняемого файла, тоже становился root-овым, и панель, работающая от `qeli`, больше не
  могла его взять — «не получается сгенерировать QR и ссылку». `chown -R` из postinst не
  спасал: он отрабатывает при установке, до этих записей. Теперь `write_atomic` переносит
  uid/gid заменяемого файла (регрессионный тест `atomic_write_preserves_owner` — от root, в
  CI помечен `#[ignore]`). **Уже сломанным установкам нужен разовый
  `sudo chown -R qeli:qeli /etc/qeli`.**

- **Реконнект после сна занимал около минуты, иногда с уходом трафика мимо туннеля.**
  Экспоненциальный бэкофф засчитывал и попытки, падавшие в ещё не поднявшуюся сеть (Wi-Fi
  переассоциируется, DHCP не завершён). При базовой задержке 1с задержка удваивается каждую
  попытку, так что несколько сгоревших попыток оставляли клиента спать 16–32с уже после того,
  как сеть заработала. При заданном `max_retries` те же попытки могли его исчерпать, а отказ
  от реконнекта снимает TUN и маршруты — отсюда и трафик в обход VPN. Теперь 30с после
  пробуждения или смены сети счётчик попыток ограничен (повтор не реже ~4с); окно взводят и
  системный power-хук, и детектор пробуждения по дрейфу часов. Бэкофф остаётся там, где он и
  нужен, — когда сервер действительно лежит.

- **Сообщение про `resolvectl` указывало не туда.** Оно гласило «resolvectl unavailable», хотя
  наличие бинарника никогда не проверялось: клиент смотрит, резолвит ли машина **фактически**
  через systemd-resolved (указывает ли `/etc/resolv.conf` на stub). Поэтому после установки
  systemd-resolved предупреждение не исчезало — ставили ровно то единственное, что не было
  сломано. Текст теперь различает «бинарника нет» и «systemd-resolved установлен, но резолвером
  не является», и в обоих случаях говорит, что именно проверялось; сам фолбэк на прямую правку
  `/etc/resolv.conf` работал и работает.

- **Гейт нативных библиотек не сверял пару копий.** Каждая библиотека лежит в дереве дважды —
  каноническая копия в `native-libs/` и та, которую читает сборка (`jniLibs/`,
  `QeliWin/native/`, `QeliMac/native/`). `verify.sh` заявляет, что ловит расхождение между
  ними, но записывал хеш каждого пути отдельно, поэтому `sha256sum -c` сверял каждый файл
  сам с собой, а пару — никогда. При этом `scripts/build_android_so_11.py` копировал только
  в `jniLibs`, так что каждая пересборка Android оставляла каноническую копию устаревшей, а
  `--update` записывал два разных хеша и закреплял расхождение как норму. Обнаружено на
  живом дереве: обе Android-ABI разошлись при зелёном гейте. Теперь `verify.sh` сверяет пары
  побайтово и отказывается делать `--update`, пока расхождение не устранено, а сборочный
  скрипт пишет в обе копии.

Остальные три пункта репорта закрыты ранее в этом же релизе: ошибка `create temp in /etc:
Read-only file system`, отсутствие `systemctl` в контейнере и рестарт службы из панели без
polkit-правила (панель различает эти случаи и подсказывает `sudo qeli install-polkit`).

### Безопасность — аудит 2026-07-27: критичное

Сквозной аудит ядра, панели, пяти клиентов, инсталляторов и документации. Ниже — то, что
меняет поведение; полный чек-лист с обоснованиями в
[docs/archive/audits/AUDIT-2026-07-27-FIXES.md](docs/archive/audits/AUDIT-2026-07-27-FIXES.md).

- **Квоты не переживали ни одного рестарта.** Supervisor и worker — разные процессы, и оба
  открывали `usage.json`. Worker копил трафик и перед выходом делал flush с последующим
  `process::exit(0)`, намеренно пропуская деструкторы. Supervisor не накапливал ничего, выходил
  штатно, и его `Drop` записывал снимок, прочитанный **при старте**, откатывая учёт к моменту
  загрузки supervisor'а. Каждый `systemctl restart qeli`, включая кнопку «Apply & Restart»,
  стирал накопленное, и пользователи за квотой снова проходили проверку. Копия supervisor'а
  теперь read-only.
- **JNI-мост не имел ни одного `catch_unwind`** при 12 точках входа, хотя Android-`.so`
  собирается с `CARGO_PROFILE_RELEASE_PANIC=unwind`. Разворачивание стека через границу JNI —
  UB; на практике ART падал с `abort`, убивая VPN-сервис, вместо возврата `0`/`null`, который
  Kotlin умеет обрабатывать. Комментарий в `Cargo.toml`, объясняющий смысл override,
  перечислял только `ffi.rs`.
- **iOS: режим `plain` не подключался никогда.** `PacketCodec.decrypt` возвращает СРЕЗ `Data`,
  а срезы наследуют индексы родителя — обращение по абсолютному диапазону читало относительные
  байты 24…55 вместо 32…63. Проверка подписи сервера падала всегда, ошибка считалась фатальной,
  и пользователь видел нечто неотличимое от MITM.
- **Повторный запуск установщика уничтожал конфиг.** `/etc/qeli/server.conf` перезаписывался
  без проверки на существование, генерировался новый `short_id` (все выданные `qeli://` ссылки
  становились мёртвыми), после чего скрипт умирал на `add-client` для существующего
  пользователя — под `set -euo pipefail` ещё до собственного сообщения об ошибке.

### Безопасность — управляющие действия не доходили до UDP-плоскости

Ingress в UDP демультиплексируется из **per-worker** карты `HashMap<SocketAddr, UdpClient>`, а
учёт, ACL и управление живут в `profile.sessions.by_ip`. Это два разных реестра, и ни одно
управляющее действие не трогало первый: `shutdown_tx` для UDP — watch-канал без единого
получателя по построению.

Кикнутый или отключённый по квоте клиент переставал ПОЛУЧАТЬ, но продолжал инжектить пакеты в
TUN ещё 30–45 секунд, до срабатывания реапера — с адресом пула, который уже освобождён и мог
быть выдан другому. Это обход `client_to_client = false` и подмена личности в NAT и логах.

- Введён `SessionShared.revoked`: поднимается в `kick_all`, проверяется циклом приёма до траты
  AEAD, запись per-worker удаляется. Закрывает kick, отключение по квоте и вытеснение.
- Отказ по `max_clients` дополнительно удаляет per-worker запись: клиент к тому моменту уже был
  переведён в `Authenticated` и уже получил AuthOK, так что освобождения одного лишь IP было
  недостаточно.
- Сбой отправки AuthOK на TCP теперь откатывает всё: `by_ip`, `by_token`, iroute, адрес пула.
  Раньше сессия оставалась призраком; `device_id` контролируется клиентом, поэтому легальный
  пользователь мог циклически исчерпать пул и `max_clients`.

### Безопасность — веб-панель

- **`GET /api/config/raw` отдавал argon2-хеш админа и секреты всех inline-пользователей.**
  Структурный `GET /api/config` те же поля помечает `skip_serializing` с комментарием «браузер
  их никогда не видит», а raw-редактор возвращал файл дословно. Теперь секреты маскируются, а
  запись восстанавливает их с диска по паре «секция + ключ», чтобы хеши не могли перепутаться
  между пользователями.
- **Пороги brute-force не проверялись при записи конфига.** Жёсткие границы стояли только в
  `POST /api/blocked/settings`; `PUT /api/config` и `/api/config/raw` писали их без проверок.
  При `window_secs = 0` очередь очищалась на каждой попытке и блокировка **не срабатывала
  никогда**, а панель показывала «enabled»; при `max_attempts = 0` первый же неверный пароль
  блокировал источник. Проверка перенесена в `BruteForceConfig::validate` и вызывается из
  `validate_profiles`, то есть сразу на всех путях записи.
- **CSRF доверял loopback-Origin на любом порту** независимо от того, где слушает сама панель.
  Локальный dev-сервер на `:3000` мог дёрнуть `/api/restore` или `/api/server/full-restart` в
  залогиненной панели. Теперь доверие только когда панель сама на loopback — вариант с
  SSH-пробросом продолжает работать.
- **Дубли inline `[user:*]` не дедуплицировались**, хотя `UsersDb::from_ini` это делает.
  `find_user` возвращает первую совпавшую И включённую запись, поэтому отключённый
  `enabled = false` аккаунт пропускался, а старый дубликат продолжал пускать.
- Добавлен `Cache-Control: no-store`: `/api/backup` отдаёт весь `/etc/qeli` вместе с приватными
  ключами обычным GET без валидаторов, то есть эвристически кэшируемым.
- `put_config_raw` больше не слабее структурного пути: те же проверки имён, уникальности
  пользователей и маршрутов, и тот же `needs_full_restart` в ответе.
- Команда обновления собиралась из непроверенного JSON GitHub и предназначалась для root-шелла;
  URL ассета теперь валидируется.

### Безопасность — паники и переполнения на недоверенном вводе

- **`parse_pubkey_hex` паниковал на не-ASCII строке длиной 64 БАЙТА.** Проверка длины считала
  байты, а срез резал по границам символов. Значение приходит прямо из `qeli://`-ссылки, а
  бинарь собран с `panic = "abort"` — импорт вредоносного QR убивал процесс клиента.
- **`short_id_from_hex` молча превращал невалидный hex в нули** — и делал это с ОБЕИХ сторон.
  Сервер строил allow-list тем же парсером, поэтому `short_ids = zzzz` принимал любого клиента
  с таким же невалидным значением. REALITY-pubkey не секретен (он ходит в ссылке), так что
  short_id — единственное, что должен угадать пробер. Добавлен строгий парсер, байт-в-байт
  совместимый с мягким на всём, что тот принимает; сервер отказывается стартовать с
  непарсящимися записями.
- Переполнение вычитания в реаперах idle/rx-dead: `now` берётся до атомарной загрузки, которую
  пишет другая задача, а в release `overflow-checks` выключены — заворот рвал живую сессию.
- `RecordCrypto::encrypt` не ограничивал размер записи и обрезал 16-битную длину. Теперь
  фрагментирует, как требует RFC 8446 §5.1.
- Усечение длины WS-фрейма при приведении к `usize` на 32-битных целях (mipsel/armv7-роутеры):
  подделка старших битов проходила проверку и рассинхронизировала парсер вместо ошибки.
- iOS: счётчик ChaCha20 в obfs-TCP оборачивался вместо отказа — после 256 ГиБ keystream
  перезапускался под той же парой (key, nonce). Вторая реализация ChaCha20 в том же модуле
  guard имела; эта была единственной без него.

### Исправлено — маскировка была слабее заявленной

- **WS-фронтинг отвечал `101 Switching Protocols` на ЛЮБОЙ HTTP-запрос**, а при отсутствии
  `Sec-WebSocket-Key` подставлял СЛУЧАЙНЫЙ `Sec-WebSocket-Accept`. Обычный `curl -i` давал
  однозапросную сигнатуру, которой не даёт ни один реальный сервер. Теперь требуется корректный
  апгрейд по RFC 6455 §4.2.1, иначе уходит обычный `400 Bad Request`.
- **Заголовок `Host` брался случайно из пула пяти CDN-доменов** и отправлялся открытым текстом
  на произвольный VPS: пассивному DPI достаточно сопоставить его с адресом назначения. Теперь
  следует хосту подключения по той же логике, что SNI.
- На `Ping` не было `Pong`, `Close` не подтверждался — RFC 6455 §5.5 этого требует, и для узла,
  маскирующегося под WebSocket, молчание отличительно.
- **QUIC-маскировка слала пакет типа Handshake с полем Token Length, которого у Handshake
  нет**, и без предшествующего Initial — QUIC-осведомлённый middlebox читал нулевую длину и
  отбрасывал датаграмму как malformed. Тип изменён на Initial; классификатор сервера смотрит
  только на long-header бит и версию, поэтому совместимость в обе стороны сохраняется.
- Padding server→client капался константой 1400 вместо `tun.mtu`: на профиле с MTU 1280 пакеты
  фрагментировались, на 1500 обфускация молча не работала вовсе.
- `generate_padding` при равных границах отдавал НУЛИ, а именно так его зовёт большинство
  вызывающих — cover-трафик и нормализация размеров.
- Android генерировал cover-трафик из `kotlin.random.Random.Default`, состояние которого
  восстанавливается по нескольким выходам; теперь `java.security.SecureRandom`.

### Исправлено — teardown не выполнялся на путях ошибок

- **Rust-клиент: маршруты и IPv6-blackhole утекали навсегда**, если `setup_tunnel` падал.
  `setup_routes` журналирует маршруты по мере создания и может упасть позже, а `TunGuard` —
  единственное, что зовёт `cleanup_routes` — создаётся ВЫЗЫВАЮЩИМ кодом уже после. Оставались
  `::/1` и `8000::/1`: ни VPN, ни IPv6.
- **C#: kill-switch не снимался, когда цикл реконнекта сдавался.** Машина оставалась без
  egress, а интерфейс показывал ошибку и предлагал «Подключить» — штатного способа снять
  блокировку у пользователя не было.
- **C#: `Stop` делал teardown до join'а** рабочего потока, который в этот момент мог быть внутри
  `SetupTun`; Wintun-адаптер создавался после обнуления поля и не освобождался.
- **Windows: при завершении сеанса ОС туннель не разбирался вообще.** `Closing` выполняется с
  флагом выхода в false, ставит отмену закрытия (которую путь shutdown игнорирует) и
  возвращается; процесс умирал с поднятым адаптером, маршрутами, подменённым DNS и
  заблокированным egress. Добавлен обработчик `SessionEnding`.
- **Android: после «сдаюсь» оставался зомби-сервис** с бессрочно удержанным `PARTIAL_WAKE_LOCK`
  и уведомлением, навсегда застрявшим на «Переподключение».
- Серверные правила `forward_private` не снимались при остановке: они ставятся под тем же тегом
  `qeli-nat:<profile>`, что и NAT, но чистилась только NAT-ветка.
- CLI C#-клиентов не имел обработчика Ctrl+C.

### Исправлено — Linux-клиент

- **Ослабление `rp_filter` на tun было тихим no-op.** `gateway::engage` выполняется до цикла
  подключения, то есть до создания интерфейса — нужного пути в `/proc` ещё не существовало,
  запись падала, результат отбрасывался, а функция не переигрывается. Ядро считает RPF как
  максимум из общего и интерфейсного значения, поэтому строгая проверка на tun оставалась и
  отбрасывала ровно тот асимметричный трафик, ради которого включают gateway-NAT и exit-node,
  при том что лог рапортовал «engaged».
- **Детект мёртвой линии по RX отключался**, если сервер запушил `heartbeat.enabled = false` и
  shaping выключен. Оставался только TX-таймер, сбрасываемый каждой отправкой, так что
  исчезновение сервера замечалось лишь по TCP-retransmit ядра — порядка пятнадцати минут.
- **Kill-switch только накапливал разрешения.** При DDNS или round-robin за сутки собирались
  десятки прежних адресов, к каждому из которых egress разрешён в обход туннеля, хотя они уже
  не наши. Теперь устаревшие отзываются; новые вставляются ДО удаления старых, поэтому окно
  утечки не появляется.
- **Убраны захардкоженные Cloudflare и Google.** Пользователь, не указавший ни одного
  резолвера, молча отдавал весь DNS Cloudflare; при восстановлении из «повреждённого» бэкапа
  хост закреплялся на публичных резолверах НАВСЕГДА после выхода qeli. Теперь в первом случае
  отказ с внятным сообщением, во втором — файл удаляется, чтобы конфигурация хоста взяла своё.
- WAN-интерфейс определялся зондом к захардкоженному `1.1.1.1`; теперь берётся из
  `ip route show default`, зонд остался фолбэком.
- `exclude` без физического шлюза удалял чужой маршрут без журналирования, нарушая принцип
  «удаляем только то, что создали сами», на котором построен модуль.
- Маркер resolvectl стал per-interface: один общий файл заставлял первый отключившийся клиент
  ревертить конфигурацию чужого линка.
- `load_or_create_key` содержал второй, НЕзалоченный путь генерации, воспроизводивший ту самую
  гонку, ради которой добавлен `FileLock`.

### Исправлено — Android и iOS

- **Android: Always-on VPN и «Блокировать соединения без VPN» не работали вообще.**
  `onStartCommand` не имел ветки для `VpnService.SERVICE_INTERFACE` — именно этим действием ОС
  запускает всегда-включённый VPN. С включённым lockdown устройство оставалось полностью без
  сети, при том что `BootReceiver` рекомендует Always-on как надёжную альтернативу автозапуску.
- Android: любая появившаяся не-дефолтная сеть рвала здоровый туннель, а обратный случай —
  потеря Wi-Fi при уже поднятой LTE — не ловился вовсе, `onLost` не обрабатывался.
- Android: устаревший цикл ретраев проверял поле сервиса вместо своего контекста и закрывал
  сокеты УЖЕ НОВОЙ сессии. Транспорт переведён на per-attempt объект.
- iOS: `setTunnelNetworkSettings` вызывался без таймаута под неотменяемым gate — одно зависание
  блокировало ВСЕ последующие применения настроек, оставляя туннель в состоянии «Connected,
  трафика нет, ретраев нет».
- iOS: `startTunnel` рапортовал успех, хотя супервизор запускается отдельным таском и мог уже
  отменить туннель; с включённым On-Demand iOS перезапускал провайдер в цикле.
- iOS: uplink-таск нельзя было отменить из `readPackets`, поэтому он переживал остановку и
  резюмировался в освобождённый граф объектов.
- iOS: IPv6-blackhole игнорировал `allowLAN` — при включённом «доступе к локальной сети»
  устройства, доступные по IPv6, оставались недоступны без объяснений.
- iOS: `updateOnDemand` при выключенном менеджере ничего не сохранял и возвращал успех, из-за
  чего MDM-политика не применялась после fail-closed.
- iOS: MDM-запрет виджет-контролов работал fail-**open** — политика читалась только из зеркала,
  которое пишет само приложение, поэтому до первого запуска запрет обходился.
- iOS: версия и билд были захардкожены (`0.7.12`/`715` против `0.7.13`/`716` в `project.yml`),
  и свежая установка вечно сообщала о доступном обновлении. Теперь читаются из bundle.

### Изменено — валидация конфигурации стала строже (требует внимания)

Конфиги, которые раньше принимались и ломались молча, теперь отвергаются при загрузке:

- **`tun.mtu` свёлся к одному диапазону 576..=9000.** Раньше их было три: INI-парсер не
  проверял ничего, сервер принимал 68..=65535, а клиент отбрасывал всё вне 576..=9000 и
  откатывался на 1400. `tun.mtu = 300` проходил `check-config`, поднимал TUN на 300 и оставлял
  клиентов на 1400 — односторонний рассинхрон MTU без единой строки в логах.
- **`dhcp.pool_start` и `pool_end` выводятся из подсети туннеля** и проверяются на вхождение в
  неё. Дефолт был захардкожен как `10.0.0.2`/`10.0.0.254` при дефолтном туннеле `10.9.0.1/24`,
  так что включение DHCP без указания пула раздавало неработающие адреса.
- `client_ip` и `server_ip` из AuthOK парсятся как IPv4 — это были последние push-поля,
  принимавшиеся на веру, тогда как pushed-DNS, CIDR и gateway валидируются.
- Параметры Argon2 зафиксированы явно (m=19456, t=2, p=1 — те же, что дефолт крейта, поэтому
  поведение не меняется). Dummy-хеш для выравнивания тайминга использует тот же профиль: иначе
  рост стоимости вернул бы оракул имён пользователей.
- Сохранение конфига из панели больше не теряет ключи чужого транспорта: сериализатор писал
  `obf.multipath.*` и `perf.tcp.*` только для TCP, а `obf.quic.*` только для UDP, тогда как
  парсер читает всё безусловно.
- `mtu` и padding из ссылки и из файлов клампятся во всех клиентах. Правило единое: файл с
  плохим значением отвергается (автор может починить), ссылка откатывается на auto с
  предупреждением (получатель QR-код отредактировать не может).

### Изменено — сервер и эксплуатация

- Глобальный мьютекс FFI-реестра больше не удерживается на время AEAD. Комментарий модуля
  предполагал «один туннель, один поток», но это никогда не было верно для реальных клиентов:
  C# гоняет upload, download и heartbeat разными задачами и создаёт ОТДЕЛЬНЫЙ realtls-handle на
  каждый bonded-стрим, Android допускает до восьми. Бондинг, существующий ради использования
  нескольких ядер, шифровал строго на одном.
- `notify::fire` делал синхронное чтение файла на каждое подключение и отключение даже при
  выключенных по умолчанию уведомлениях; throttle-карта чистилась только по возрасту, а ключи
  вида `authlock:<ip>` при распределённом брутфорсе держались сутки.
- Метрики WAN исключали туннели по префиксам имён, а не по реальному `tun.name`: профиль с
  именем вроде `qeli0` целиком засчитывался как WAN и удваивал нагрузку на дашборде.
- Лог клиентского туннеля открывается на дозапись, а не с усечением: нажатие «Connect» в панели
  уничтожало лог с причиной предыдущего падения.
- Путь control-сокета переопределяется через `QELI_CONTROL_SOCKET`. Флаг `--socket` у CLI
  существовал, но сервер всегда биндил константу, так что указать другой путь можно было только
  клиенту — и он гарантированно никуда не подключался.
- Установщик: `systemctl enable --now` заменён на `enable` плюс `restart` (на активном юните
  `start` — no-op, поэтому повторный прогон печатал «Done», а сервер продолжал работать со
  старым конфигом, и health-check это проходил); `$PUBLIC_HOST` валидируется до подстановки в
  `sed`; сбой iptables больше не прерывает установку после записи конфига; откат апдейта
  возвращает пакет, а не только бинарь.
- CI: добавлены job'ы сборки настоящего `.deb` рецептом релиза с `check-abi` и установкой в
  `debian:10` и `ubuntu:22.04`, а также shellcheck по установщикам; в матрицу роутеров добавлен
  `x86_64-musl`. Ровно этот пробел позволил 0.7.8–0.7.11 уехать с требованием GLIBC_2.39 при
  объявленном `Depends: libc6 (>= 2.28)`.
- Четыре OBSOLETE-скрипта удалены: заглушка с немедленным выходом не мешала снять пять строк и
  получить рабочий скрипт с паролем `changeme` и SSH без проверки ключа хоста.

### Изменено — нативные ядра пересобраны, добавлен провенанс

`native-libs/verify.sh` доказывает, что две копии каждой библиотеки совпадают друг с другом, но
ничего не говорит о том, соответствуют ли они исходнику рядом. И они не соответствовали: ядра
были собраны из источника 0.7.12 и остались, пока `qeli/src` уходил вперёд, — то есть все
GUI-клиенты несли более старое realtls/FFI-ядро, чем описывало дерево, и увидеть это в ревью
невозможно, потому что у `.so` нет читаемого диффа.

- Ядра пересобраны из текущего дерева: Windows и macOS на сборочной машине, Android с NDK, с
  обязательным `CARGO_PROFILE_RELEASE_PANIC=unwind`. Без этой пересборки GUI-клиенты не
  получили бы ни одного из перечисленных выше исправлений FFI-слоя.
- Добавлены `native-libs/PROVENANCE` и `native-libs/provenance.py --check`: дайджест SHA256 по
  всем `qeli/src/**/*.rs` плюс `Cargo.toml` и `Cargo.lock`. Встроен шагом в CI-job `native-libs`.

### Удалено — мёртвый код с расходящейся семантикой

- `Cipher::generate_nonce` строил nonce как счётчик плюс хвост, тогда как живой кодек — как
  seed плюс счётчик с Feistel-PRP. Второй «источник истины» о раскладке nonce, уже разошедшийся
  с первым, вместе с зелёным тестом, закреплявшим неверный вариант.
- `generate_heartbeat` формировал TLS-запись типа Heartbeat (RFC 6520). TLS 1.3 heartbeat не
  использует, а qeli его в ClientHello не объявляет — незапрошенная такая запись демаскировала
  бы поток мгновенно.
- Мёртвые `ParseServerHello` в C# и Kotlin без проверки границ, которая есть в их живых
  PQ-близнецах, и `toConfigJson` в Kotlin, жёстко прописывавший full-tunnel.

### Безопасность — Android принимал подделку INI через `qeli://`-ссылку

`toIni` пишет `key = value` дословно, а проверки управляющих символов не было. Перевод строки
внутри пароля, SNI или маршрута в импортируемой ссылке дописывал в профиль произвольные ключи —
например `bind_static = false`, отключающий привязку сессии к запиненному ключу сервера, — и
подделанная строка возвращалась как доверенный конфиг при следующем сохранении.

- Добавлен `VpnConfig.validate()`: отбивает `\r`, `\n`, `NUL` во всех скалярах, списках и
  метке профиля. Проверка стоит на эмиссии (момент, когда подделка была бы записана) и на
  импорте ссылки (место, где недоверенный ввод входит). Разбор уже сохранённого профиля
  намеренно остаётся мягким — иначе битое значение на диске заперло бы доступ к профилю.
- У iOS такая защита была изначально; это единственная находка сравнения, где iOS был строже.
- Тесты: `ConfigHardeningTest` — подделка через пароль, через `\r`/NUL и через ссылку с
  `%0A`.

### Исправлено — расхождения конфига между Android, iOS и Rust

Сравнение iOS с Android дало 50 полей с идентичными дефолтами, но разошедшиеся детали:

- **`mtu_probe = off` / `no` на Android означало «пробинг ВКЛЮЧЁН»** — ровно наоборот тому,
  что написал пользователь, и наоборот Rust (`bool_or`) и iOS. Теперь общий набор ложных
  значений.
- **iOS писал 16 INI-ключей, которых не знал никто:** `padding*`, `heartbeat*`, `shaping*`.
  Оба клиента применяют эти поля в рантайме, поэтому ключи не выброшены, а добавлены в
  Android — профиль с iOS больше не теряет тюнинг при импорте.
- **Секцию `[logging]` теряли оба клиента.** Десктопный/роутерный `client.conf`, открытый на
  телефоне и сохранённый, лишался `level`, `file` и `time_format`. Теперь она пробрасывается
  насквозь, как это делает Rust.
- **`apps_mode` и `apps` на Android писались только вместе** — режим `include` с пустым
  списком молча откатывался к «все приложения в туннеле».
- **Ссылка с пустым паролем** давала `alice@host` на Android против `alice:@host` в Rust и
  iOS. Выровнено по Rust: один профиль теперь даёт байт-в-байт одинаковую ссылку и QR везде.
- **MTU вне диапазона в ссылке** обрабатывался тремя разными способами (Rust клампил, iOS
  отвергал всю ссылку, Android принимал как есть). Везде кламп в auto, как в Rust.
- Android получил валидацию диапазонов (порт, `proto`, `timeout`, `mode`, `mtu`), которая
  была только на iOS; iOS — список разделяется `", "` как в Rust/Android, и проверку, что
  `reality-tls` требует запиненный ключ и `reality_sid` (Android отбивал это явно, iOS падал
  глубоко в хендшейке). Плюс `routing.allow_lan` в JSON-импорте Android, который читался
  только на iOS.

### Добавлено — iOS догнал Android по интерфейсу

- **Русский язык и переключатель.** Языка в настройках не было вовсе: iOS шёл за локалью
  системы, то есть русский iPhone открывал приложение по-русски, тогда как Android форсирует
  английский дефолт. Добавлен выбор English / Русский, локаль форсируется через
  `environment(\.locale)`, дефолт — английский на любом устройстве.
- **21 строка проходила мимо локализации** — `Text(String)` в SwiftUI не переводит, поэтому
  подписи формата времени, темы и все алерты оставались английскими даже при русском
  интерфейсе. Переведены на `LocalizedStringKey`, файлы `.strings` выросли с 70 до 101 строки
  с полным паритетом ключей.
- **Заблокированные строки профиля теперь приглушены.** Запрет переключения при активном
  туннеле был реализован (и даже строже, чем на Android — iOS не даёт удалить активный
  профиль и восстановить бэкап на живом туннеле), но никак не показывался: пользователь узнавал
  о нём только после тапа.
- **UDP-пинг заработал.** Для UDP-профиля возвращалась заглушка `"protocol probe pending"`,
  то есть любой UDP-профиль вечно выглядел непроверяемым. Теперь отправляется тот же гибридный
  X25519 + ML-KEM ClientHello, что и на Android, с той же послойной упаковкой (QUIC внутрь,
  obfs снаружи — обратный порядок делал живой сервер «недоступным»). Заодно при активном
  туннеле пинг идёт до шлюза, а не до публичного адреса.
- **Виджет и Пункт управления больше не разворачивают приложение.** `openAppWhenRun` был
  `true` в обеих точках, тогда как Android-виджет и QS-тайл подключают в одно касание.
  Теперь туннель поднимается прямо из расширения; если это не удаётся, команда остаётся в
  очереди и применяется при следующем запуске — прежнее поведение как запасной путь.
- Кнопка «Копировать» в окне шаринга (на Android была, на iOS приходилось выделять ссылку
  вручную).

⚠️ **iOS-правки не проверены на устройстве** — здесь их нельзя ни собрать, ни запустить
(нужен macOS с Xcode). Больше всего внимания при проверке требует виджет: это единственное
изменение, способное сломать ранее работавший, пусть и неудобный, сценарий. См.
`qeli-ios/PARITY.md`, пункт 0 списка проверок.

### Безопасность — аудит клиентов (Windows / macOS / Android / iOS)

Аудит всех клиентских кодовых баз с кросс-проверкой крипто/data-plane против Rust-ядра.
Само ядро (крипто, протокол, фрейминг) — чисто и совпадает с сервером; дефекты нашлись в
платформенной обвязке. Собрано: dotnet Release (win/mac/shared) — 0 ошибок; Android
`compileReleaseKotlin` — OK; M6 проверен прогоном (5000/5000 уникальных nonce, round-trip).
Правки iOS внесены, но требуют сборки на macOS перед выпуском.

**HIGH — Android: утечка трафика на КАЖДОМ реконнекте.** `QeliService` на пути реконнекта
закрывал и обнулял `vpnInterface` **до** backoff и повторного хендшейка, из-за чего Android
снимал VPN и весь трафик всех приложений уходил в открытую по физическому линку на всё окно
переподключения (fail-**open**). Это нарушало собственный инвариант кода (бесшовный handoff в
`setupTunInterface` «no leak window»). Теперь реконнект закрывает только транспортные сокеты, а
TUN остаётся поднятым до замены на месте — fail-**closed**, как на iOS (пакеты уходят в мёртвый
TUN и отбрасываются, а не утекают). Полный teardown TUN — только при stop / отказе от ретраев.

**Windows — локальный EoP + boot-MITM через подмену профиля службы.** Каталог
`%ProgramData%\QeliWin` создавался с унаследованным ACL (обычные пользователи могли создавать
файлы), а служба под LocalSystem молча принимала **плейнтекст**-профиль. Не-админ мог подложить
`service-profile.json` и увести машинный туннель на свой сервер с подконтрольными маршрутами/DNS.
Исправлено: жёсткий DACL каталога (`RestrictDirAcl`, снятие «Users») при создании и при каждом
сохранении; сервисный путь отклоняет любой не-DPAPI профиль под LocalSystem (fail-closed).

**macOS:**

- **Kill-switch пропускал DNS на любой адрес.** pf-правило `pass 53 to any` давало утечку
  DNS-метаданных всех приложений в окне переподключения. Теперь DNS ограничен системными
  резолверами (из `/etc/resolv.conf`), fail-closed при пустом списке.
- **Демон подключал не тот профиль.** В launchd-режиме UI позволял выбрать профиль, но демон
  всегда запускал отдельно сохранённый `ServiceProfile` — выбор молча игнорировался. Теперь
  Connect переконфигурирует демон на выбранный профиль, а трей показывает реально запущенный.
- **AES-мастер-ключ мог попасть в `ps`.** Резервный путь сохранения ключа Keychain передавал его
  как argv (виден всем локальным пользователям). Argv-fallback убран — при сбое stdin-пути
  используется файл-хранилище `0600`.
- **`ResolveProfile` мог выбрать не тот аккаунт** при legacy-совпадении по адресу сервера — убран
  fallback по `ServerAddress`, при неоднозначном совпадении — отказ.
- Профиль демона теперь пишется с правами `0600` **до** записи байтов (не после); каталог
  kill-switch приведён к каноническому `Paths.ServiceDir` (регистр).

**M6 — детерминированный, коллизионно-свободный nonce data-plane (все клиенты).** Nonce записи
брался случайным 96-битным (birthday-риск, который ядро устраняет by construction). Теперь клиенты
считают nonce как `PRP(seed(4)‖counter(8))` — 96-битный Feistel-перестановкой, идентичной
Rust-ядру: коллизий нет (перестановка биективна), а на проводе значение не инкрементируется на +1
(снят DPI-тэлл видимого счётчика). Правка односторонняя, без изменения wire-формата (получатель
читает nonce с провода). `PacketCodec` в общей C#-библиотеке (Windows+macOS) и в Swift.

**Прочее (LOW):** имя пользователя убрано из логов (общие/мировые логи, Android logcat); чтение
TLS/raw-записей ограничено `MaxRecordSize` вместо 64 КБ; obfs-keystream на Android при исчерпании
2³² блоков (256 ГиБ) теперь падает, а не переиспользует keystream (паритет с Rust); устранён
рассинхрон учёта junk-фреймов на control-фрейме; cover-traffic PRNG сидится из CSPRNG; DNS-значения
на macOS валидируются как IP перед применением; промежуточные секреты (IKM/PRK) в деривации ключей
зануляются. IPv6 в split-tunnel на iOS оставлен как есть (осознанно: туннель только IPv4,
blackhole сломал бы легитимный v6-трафик не-туннелируемых приложений) — добавлено пояснение.

### Добавлено — подробная инструкция установки .deb + права на `/etc/qeli`

GETTING-STARTED (RU+ENG), раздел «Вариант A»:

- **Скачивание в `/tmp`** с объяснением, почему: `apt` распаковывает от пользователя `_apt`,
  которому `/root` и домашние каталоги недоступны → предупреждение `Download is performed
  unsandboxed as root … couldn't be accessed by user '_apt'`. Из `/tmp` его не возникает.
  Указано, что путь к пакету должен быть полным (`/tmp/…deb` или `./…deb`), иначе apt ищет
  пакет в репозиториях; дана альтернатива `dpkg -i` + `apt-get -f install`.
- **Права на `/etc/qeli` — обязательный шаг (A.3).** Служба работает под `User=qeli` и ПИШЕТ
  в `/etc/qeli` (identity-ключи, users-файл, сохранения панели; в юните `ReadWritePaths`).
  `postinst` выставляет владельца только в момент установки, поэтому созданное позже под root
  (`cp` конфига, `add-client`, `show-identity`) остаётся root-овым и служба его писать не
  может. Добавлены готовые команды (`chown -R qeli:qeli` + моды `700`/`600` на identity),
  способ не наступать на это вовсе (`sudo -u qeli qeli …`) и список симптомов.
- **Исправлено устаревшее:** пакет больше НЕ вешает `cap_net_admin` на бинарь — с 0.7.12
  `setcap` намеренно снимается, права даёт юнит через `AmbientCapabilities`.
- Кейс с правами добавлен первым пунктом в §12 «Частые проблемы»; там же уточнено, что
  fail-closed панели срабатывает на ЛЮБОМ bind, включая loopback (а не только на публичном).
- Напоминание про владельца выведено прямо в `postinst` при установке пакета.

### Исправлено — документация и deb-примеры конфига по веб-панели

Правки фактических ошибок в примерах, которые ставит deb-пакет (`server.conf.example`,
`server-multiprofile.conf.example`), и в PANEL/CONFIG (RU+ENG):

- **Fail-closed был описан неверно.** Примеры и PANEL утверждали, что пустой
  `password_hash` мешает старту только на **non-loopback** bind. По коду (`web/mod.rs`)
  панель не стартует с пустым хешем на **любом** bind, включая loopback (осознанный
  opt-out — `insecure_no_auth`).
- **`tls` не обязателен для старта.** `server-multiprofile.conf` заявлял, что на публичном
  bind без `tls` панель «refuses to start»; на деле это только громкое предупреждение
  в лог, отказа в старте нет.
- **Как разрешить доступ отовсюду.** Явно описано, что отсутствие ключа, `allowed_ips =`
  и `allowed_ips = ""` **равнозначны** (парсер снимает окружающие кавычки) и означают
  «любой источник».
- **Готча: дубликаты `allowed_ips` складываются** в ОДИН список (а не «побеждает
  последняя строка») — забытая ранее строка молча держит фильтр включённым.
- **Диагностика 403.** Голый 403 при открытии панели — это всегда IP-allowlist
  (применяется ко всем маршрутам, тело пустое); CSRF так не может, т.к. пропускает
  `GET`/`HEAD`/`OPTIONS` и отдаёт 403 с текстовым телом. Указаны маркеры в логах:
  `Web panel source-IP allowlist active (N entries)` и `panel: blocked request from <ip>`.
- **Область рестарта.** Отмечено, что `enabled`/`bind`/`port`/`tls*` применяются только
  при полном рестарте процесса (не по кнопке «Применить и перезапустить»), и что при
  `tls = true` заходить нужно по `https://`.

### Исправлено — «Apply & Restart» из панели молча не срабатывал

Кнопка `Apply & Restart` выполняет `systemctl restart <unit>`, но делала это по схеме
fire-and-forget: HTTP-ответ `ok:true` отдавался **до** запуска `systemctl`, а ненулевой/
запрещённый код только писался в лог. Панель рапортовала «Applied», хотя рестарта не было и
изменения не применялись. Два реальных сценария, где это происходило:

- **Установка не из .deb.** Сервис работает как non-root `User=qeli`; чтобы он мог рестартить
  свой юнит, нужно polkit-правило `49-qeli.rules`. `.deb` его ставит, а при установке голым
  бинарём/tarball'ом — нет, и polkit запрещает рестарт.
- **Запуск в контейнере.** systemctl там отсутствует вовсе (qeli — PID 1 без systemd),
  вызов уходил в `Err` и так же терялся.

Что сделано:

- **Pre-flight среды в `full_restart`** (`web/api/control.rs`): перед рестартом определяется
  окружение (нет systemd / контейнер / нет `systemctl` / non-root без polkit-правила) и
  возвращается **честная ошибка с готовой командой**, а не ложный «успех». Реальный рестарт
  планируется только когда pre-flight пройден.
- **Новая CLI-команда `qeli install-polkit`** (`main.rs`) ставит правило
  `/etc/polkit-1/rules.d/49-qeli.rules` для не-.deb установок (`--unit` / `--user` для
  нестандартных имён, `--dry-run` для предпросмотра; требует root). Панель при отсутствии
  правила подсказывает `sudo qeli install-polkit`.
- **Контейнер:** для изменений, не затрагивающих сокет панели, `Apply & Restart` теперь
  **автоматически** применяет их через перезапуск воркера в процессе (работает без systemd);
  для смены сокета панели сообщает, что нужно пересоздать контейнер.
- **Панель** (`layout.html`/`config.html`): `fullRestartServer()` возвращает структуру, тост
  показывает точную причину дольше (команда для копирования). Тосты рестарта переведены на RU.

### Добавлено — общие кросс-языковые KAT-векторы (`conformance/`)

Протокол реализован **четырежды** (Rust-канон, C#, Kotlin, Swift), и до сих пор единственной
общей фикстурой был `qeli-links.json` — разбор `qeli://`. Сам **wire-протокол не сверялся
ничем**, и цена этого известна: фикс M6 (ниже) приземлился в три реализации из четырёх и
пролежал так релиз, потому что сравнить их было не с чем.

**Механизм.**

- **Генератор `gen-conformance`** ([qeli/src/gen_conformance_main.rs](qeli/src/gen_conformance_main.rs)):
  векторы производит **канон**, а не человек — рукописный вектор доказывает лишь, что автор и
  код ошибаются одинаково. Живёт вне `src/bin/` (там `.gitignore` с `**/bin/` тихо выкинул бы
  файл из git — ловушка, которую документирует `src/client_main.rs`) и собирается только под
  выключенной по умолчанию фичей `conformance-gen`, поэтому обычные server/CI/FFI-сборки не
  затронуты.
- **Режим `--check`** перегенерирует в память и падает при расхождении с диском; добавлен
  **гейтом в CI**. Без него фикстура тихо отстаёт от кода, а три остальные реализации
  продолжают сверяться с устаревшей таблицей и считать, что согласны.
- **Поле `platforms` — несущее:** каждый потребитель проверяет, что его платформа в списке,
  поэтому переименованный примитив или уехавший файл делают тест **красным**, а не «зелёным,
  ничего не проверившим». Проверено отрицательно: спрятал фикстуру — Kotlin-тест упал.
- **[conformance/README.md](conformance/README.md)** — формат, правила добавления примитива и
  разбор, что чем пиннится.

**Новые файлы** (6 генерируемых, 53 кейса; вместе с уже существовавшим `qeli-links.json` —
7 файлов и 66 кейсов):

| Файл | Кейсов | Что фиксирует |
|---|---:|---|
| `prp-nonce.json` | 6 | nonce data-plane: `PRP(seed‖counter_be)`, сеть Фейстеля |
| `packet-decode.json` | 7 | декодирование записи: фрейминг TLS/raw, AEAD, счётчик, срез padding + 3 негатива |
| `replay-window.json` | 8 | окно анти-реплея 2048 бит, включая границу 2047/2048 |
| `hkdf.json` | 5 | четыре схемы деривации; порядок секретов — часть wire-формата |
| `quic.json` | 9 | конверт QUIC + 5 crafted-пакетов, которые парсер обязан отвергнуть |
| `udp-frag.json` | 18 | фрагментация/сборка хендшейка + классификация датаграмм |

**Три наблюдения, определившие объём работы.**

- **Декодирование детерминировано по построению** — при данных (ключ, запись) plaintext
  однозначен. Поэтому `packet-decode` пиннит весь входящий путь **без единого тест-шва**:
  каждому клиенту хватает его публичного `decrypt`. То же для окна, HKDF, QUIC и
  фрагментации — это и есть причина, по которой большая часть покрытия далась дёшево.
- **Кодирование требует инъекции рандома** (seed, PRP-ключ, padding) — отдельный шов в каждой
  реализации. Оно того стоит: именно к этому классу относился M6, где сам примитив везде был
  верен, а **проводка** — нет. Пока не сделано.
- **Часть вещей байт-в-байт не фиксируется вовсе** (fake-TLS ClientHello с GREASE и
  перемешиванием расширений; тела junk-декоев и MTU-probe случайны по замыслу). Для них —
  структурные инварианты и проверка рамки, а не байтов.

**Побочный, но важный результат: на Android включён `unitTests.isReturnDefaultValues`.**
`PacketCipher` трогает `android.util.Log` при инициализации класса, а заглушки фреймворка
бросают «not mocked» — из-за этого **wire-кодек, самый ответственный код приложения, был
непроверяем без устройства**. Ровно поэтому на Android не было ни одного теста `PacketCodec`
и ровно поэтому M6 там потерялся. Теперь кодек прогоняется на JVM.

**Находка о ширине типов** (в README): номер QUIC-пакета — `u32` в Rust и Swift, но
**знаковый `int` в C# и Kotlin**, поэтому значение выше 2³¹−1 туда нельзя передать
положительным. На провод выходят те же четыре байта при передаче того же **битового
паттерна** — кейс `short-header-pn-high` существует именно чтобы это доказать и чтобы никто
не «починил» одну реализацию под другую, сломав совместимость.

**Проверено:** Rust — **6/6** conformance-тестов; **C# `selftest` — все кейсы всех шести
фикстур, `ALL PASS`** (независимая реализация побайтово совпала с каноном, включая границу
окна 2047/2048 и все crafted-пакеты); Kotlin — **36 тестов / 0 падений**. Генератор
воспроизводим (одинаковые md5 между прогонами), `--check` = 0, clippy/fmt = 0.
**Swift-тесты написаны, но требуют прогона на macOS.**

**Не покрыто:** кодирование записи (нужен шов), obfs-keystream, тела AWG junk, WS-фрейминг
(сейчас инлайн-вектор в `ObfsStreamTest.kt` — стоит перенести), fake-TLS ClientHello.


### Исправлено — M6 (детерминированный nonce) не был доведён до Android

Фикс M6 из аудита клиентов заявлен в этом же ченджлоге как сделанный «во всех клиентах», но по
факту приземлился в Rust, C# и Swift, а **Android его не получил**: `PacketCodec.kt:113` до сих пор
генерировал **случайный 96-битный nonce** (`random.nextBytes`) — ровно тот birthday-риск, который
конструкция и убирает. Это была единственная точка генерации nonce в Kotlin, поэтому под старым
поведением оставался **весь TX-путь** Android (`encrypt`, `encryptPadded`, `encryptCapped`).

- Порт PRP-nonce: `nonce = PRP(seed(4) ‖ counter_be(8))`, 4-раундовая сбалансированная сеть
  Фейстеля, раунд-функция `SHA256(key‖round‖half)[..6]` — побайтово идентично Rust
  `packet.rs prp_nonce`. Сеть биективна при любой раунд-функции, поэтому различные
  (seed, counter) — счётчик монотонный — **не могут** дать одинаковый nonce, а на проводе
  пропадает инкремент «+1 на пакет» (DPI-тэлл видимого счётчика).
- Преобразование **одностороннее**: nonce едет на проводе, получатель PRP не обращает, поэтому
  ключ PRP не обязан совпадать с пиром — как в C#/Swift, он локально случайный (Rust выводит его
  из AEAD-ключа; оба варианта корректны именно из-за односторонности). Формат провода не меняется,
  совместимость со старыми серверами и клиентами сохраняется.

**Причина, по которой расхождение никто не заметил, тоже закрыта:** теста `PacketCodec` на Android
не существовало вовсе, а единственная кросс-языковая фикстура (`conformance/qeli-links.json`)
покрывает только разбор `qeli://`, но не wire-кодек. Добавлен
`PacketCodecNonceTest` — эталонные векторы, **снятые с реальной Rust-сборки** (не посчитанные
вручную) и независимо воспроизведённые: `counter=0 → 289fe9a937b9d33bc24d3d4b`,
`1 → b8b68234e54408ea9dc18d6c`, `2 → 7cb96371c342fccbcf5c7101`,
`1234567890 → 110f292c571f8996572f6def`; плюс проверка отсутствия коллизий на 100 000 счётчиков и
проверка, что видимый паттерн счётчика разрушен. Построение raw-nonce вынесено в
`rawNonce(seed, counter)`, чтобы вся цепочка деривации тестировалась без создания экземпляра
(конструктор тянет Conscrypt и `android.util.Log`, недоступные в JVM-тестах).

Проверено на Android-лабе: `compileDebugKotlin` OK, юнит-тесты **16/16** (4 новых + 12 прежних).

### Добавлено — выбор пользователя службы: `qeli` (по умолчанию) или `root`

Служба всегда работала от непривилегированного `qeli`, и сменить это можно было только правкой
юнита — которую dpkg молча затирал при следующем обновлении пакета. Теперь выбор поддержан
штатно и переживает обновления.

- **Новая CLI-команда `qeli set-service-user root|qeli`** (`main.rs`). Поставляемый юнит
  **не правится** (его перезаписывает dpkg) — команда управляет **systemd drop-in override**
  `/etc/systemd/system/qeli.service.d/run-as.conf`: `root` пишет туда `User=root`/`Group=root`,
  `qeli` удаляет файл и возвращает владельца `/etc/qeli` (файлы, созданные под root, иначе
  остались бы недоступны непривилегированной службе на запись). Затем `daemon-reload`;
  применяется рестартом. Идемпотентна, требует root, есть `--dry-run` и `--unit`. Закалка
  юнита (`ProtectSystem`, `NoNewPrivileges`, ограниченный `CapabilityBoundingSet`) действует
  в обоих режимах — меняется только то, от кого идёт процесс.
- **Установщик: `QELI_RUN_AS=qeli|root`** (по умолчанию `qeli`) — значение валидируется на
  старте и применяется вызовом `set-service-user` перед первым запуском службы.
- **`.deb` спрашивает при установке** — debconf-вопрос `qeli/run-as` (select `qeli`/`root`,
  default `qeli`; `debian/{templates,config}`, зависимость `debconf`), ответ применяется в
  `postinst` той же командой. Неинтерактивно — через `debconf-set-selections`.
- **Документация** (GETTING-STARTED ru/eng): в §2 — `QELI_RUN_AS` и вопрос .deb; в §10.4 —
  подробно, что именно делает команда (таблица по каждому аргументу), **когда root оправдан**
  (ядро/контейнер без ambient-capabilities, невозможность поставить polkit-правило, ловушка
  владельца `/etc/qeli`) и **предостережение**: root снимает разделение привилегий —
  компрометация демона, доступного из интернета, становится полным root на хосте.

Проверено в контейнере: round-trip CLI (drop-in создаётся/удаляется), и установка `.deb` с
preseed обоих ответов — `root` даёт drop-in `User=root`, `qeli` не создаёт его вовсе.

### Изменено — установщик: переименован, профиль udp-quic, установка из бинаря без .deb

Скрипт-установщик `install-reality-server.sh` **переименован в `install-qeli-server.sh`**
(старое имя отражало только TLS-профили). Все ссылки обновлены — документация (GETTING-STARTED
ru/eng, PANEL, OPERATIONS), README, `site/install/`, комментарии в `update.rs` и клиентских
`UpdateChecker` (та самая команда обновления, что видит пользователь), тест-скрипты. В
замороженных бинарях прошлых релизов (`release/dist/`) имя не трогалось.

- **Профиль `udp-quic` в выборе.** Раньше установщик предлагал только reality-tls / fake-tls
  (оба TCP). Добавлен третий вариант — QUIC/HTTP3-образный UDP (нет TCP-over-TCP, лучше на
  потерях/мобильных). Учтён транспорт: внешний MSS-clamp (он только для TCP) на udp-quic
  пропускается, firewall-подсказка и итоговая сводка показывают UDP, REALITY `short_id` не
  трогается. `QELI_PROFILE=udp-quic` — неинтерактивно.
- **Установка из готового бинаря — `QELI_BIN=<путь>`.** Раньше скрипт умел только скачать и
  поставить `.deb`. Теперь можно указать собранный бинарь, и установщик **сам воспроизводит
  ровно ту же раскладку, что `.deb`**: пользователь `qeli`, `/etc/qeli` + каталоги состояния,
  пять `*.conf.example`, пустой `users.conf`, systemd-юнит, права, polkit-правило
  (переиспользует `qeli install-polkit`, с fallback на файл правила). `QELI_SRC=<чекаут>`
  копирует юнит и примеры прямо из исходников (полностью офлайн) — иначе они тянутся с GitHub.
  Для сборки из исходников и air-gapped-установок. Дефолтная ветка (скачать `.deb`) не изменилась.
- **Исправлено:** запись `/etc/sysctl.d/99-qeli-perf.conf` без `|| true` роняла установку
  (`set -e`) на минимальной системе, где каталога `/etc/sysctl.d` ещё нет (найдено сквозным
  тестом в чистом контейнере). Добавлен `mkdir -p /etc/sysctl.d /etc/modules-load.d`.

Проверено: сквозная установка из бинаря с профилем udp-quic в одноразовом контейнере — паритет с
`.deb` (юнит байт-в-байт, polkit-правило совпадает), корректный udp-quic конфиг, 5 пользователей
со ссылками, панель включена, установщик доходит до конца (21/21 проверок). GETTING-STARTED (ru/eng)
описывает обе ветки установки и пошагово — что делает скрипт.
([install-qeli-server.sh](install-qeli-server.sh))

### Добавлено — предстартовые проверки: сервер не запустится, если конфиг отрежет доступ к машине

Новый модуль [preflight.rs](qeli/src/server/preflight.rs) — проверки, которые выполняются в
**супервизоре, до** того как поднимется панель, стартует воркер и появится хоть один TUN.

Первая проверка — **пересечение подсетей**. Повод: профиль, у которого `tun.address` совпадает с
адресом шлюза хоста. При подъёме TUN шлюз становится локальным адресом, весь исходящий трафик
умирает в туннеле, и сервер пропадает из сети целиком — вместе с SSH и пингом. Вернуться можно
только через консоль хостера или перезагрузку, причём в логе всё выглядит успешным стартом. В
поставляемом одиночном примере при этом стоял `10.0.0.0/24` — один из самых частых шлюзовых
диапазонов у VPS, то есть грабли лежали заряженными.

Отвергается (старт не происходит, в журнале — что именно и как чинить):

- `tun.address` = шлюз по умолчанию, либо адрес, уже занятый интерфейсом хоста;
- `pool.cidr` содержит шлюз по умолчанию или собственный адрес хоста;
- `pool.cidr` / подсеть туннеля пересекается с существующим маршрутом (LAN, сеть провайдера);
- два профиля с пересекающимися пулами.

Логика вердикта **чистая** (принимает снимок состояния хоста, а не читает систему) — как
`validate_profiles`, поэтому покрыта юнит-тестами и переиспользована в `check-config`: команда
теперь отвечает на главный вопрос перед первым запуском — «не отрежет ли этот конфиг меня от
машины». Интерфейсы самого qeli из сравнения исключены, иначе рестарт после неаккуратной
остановки принял бы собственный TUN за конфликт и сервер больше никогда бы не поднялся.

**Fail-open при нечитаемом состоянии хоста** (нет `ip`, вывод не разобрался): это защита от
ошибки оператора, а не граница безопасности, поэтому машина, которую не удалось опросить, обязана
стартовать — с громким предупреждением. Найденное пересечение, наоборот, фатально: конфигурации,
в которой перекрытие собственной адресации хоста работает, не существует.

**Дефолтная подсеть туннеля: `10.0.0.0/24` → `10.9.0.0/24`** — и в коде (`default_tun_addr`,
`default_cidr`, `default_dns_listen`), и в поставляемых примерах, и в документации. Проверка выше
не даст выстрелить, но заряжать ружьё дефолтом всё равно не следует: минимальный конфиг без явных
`tun.address` / `pool.cidr` раньше приземлялся ровно на самый частый шлюзовой диапазон VPS.
`10.0.0.0/8` в примерах `allowed_ips` / `trusted_proxies` не тронут — это про доступ к панели, а не
про туннель. Затронуто: [server.conf](qeli/config/server.conf), [users.conf](qeli/config/users.conf),
`docs/{ru,eng}/{CONFIG,GETTING-STARTED}.md` (+ пункт в «Частые проблемы» о том, что делать при
отказе старта).

### Добавлено — выходной узел `exit_node` (Rust/Linux-клиент)

Схема `клиент → сервер(белый IP) → exit-клиент(серый IP за NAT) → интернет`: трафик одних
клиентов выходит в интернет под IP **другого** клиента (например, за домашним/NAT-адресом).
Новый клиентский флаг `exit_node = true` — **зеркало `gateway_nat`**: тот маскарадит LAN за
клиентом В туннель, а `exit_node` выпускает пришедший ИЗ туннеля трафик в свой физический WAN.

Ставит идемпотентно (по имени интерфейса, держится через реконнект, снимается на чистой
остановке): `ip_forward`, снятие `rp_filter` на tun+WAN, `MASQUERADE` из WAN, `FORWARD` в обе
стороны, `TCPMSS`-клампу. Scoping — по packet-mark (`0x51/0x51`), а не по source-подсети: пул
неизвестен до авторизации, зато локальный трафик хоста не помечается и не маскарадится, и знать
пул не нужно. WAN определяется автоматически (`ip route get 1.1.1.1`). Предупреждает при
`exit_node` + full-tunnel (узел обязан быть split-tunnel).

Парная настройка на сервере — существующие `client_to_client` + `client_subnet = 0.0.0.0/0` у
exit-пользователя; потребителю выхода ничего нового не нужно (обычный пуш дефолта, работает на
всех клиентах). На сервере отдельного флага НЕТ намеренно: сервер и так «выход» через
`routing.nat.enabled`. Exit-узел — Linux/iptables, как `gateway_nat`/`forward`.

Проверено на лабе: канонический гейт (build/test 380/clippy/fmt) + изолированный e2e в netns —
реальный бинарь ставит MARK/MASQUERADE/FORWARD/MSS с верным WAN и снимает всё по SIGTERM.
([client/gateway.rs](qeli/src/client/gateway.rs), [client/mod.rs](qeli/src/client/mod.rs),
[config/client.rs](qeli/src/config/client.rs); доки — `docs/{ru,eng}/CONFIG.md`)

### Исправлено — сбой настройки DNS ронял уже поднятый туннель (Rust-клиент)

`setup_dns_for_interface` вызывался через `?`, то есть неудача с резолвером убивала всё
подключение — хотя data-плоскость к этому моменту уже работала. Ловилось это на read-only `/etc`:
атомарная перезапись `/etc/resolv.conf` падала с `Read-only file system (os error 30)`, и рабочий
туннель уходил в реконнект-петлю. Классические случаи — hardened systemd-юнит с `ProtectSystem`,
контейнер с read-only rootfs, сетевой неймспейс.

Теперь управление резолвером — **best-effort**: при ошибке клиент пишет WARN и **оставляет туннель
поднятым** с нетронутым системным резолвером. В сообщении названа причина (read-only `/etc`) и
лекарство — клиентский `dns = off` (единственный способ вообще не трогать `/etc`: в режиме
`tunnel` клиент пишет resolv.conf даже когда сервер DNS не пушит, подставляя запасной резолвер).
Для full-tunnel добавлено предупреждение, что до этого DNS-запросы могут идти в резолвер
физической сети. `restore_dns` идемпотентен, поэтому ранний выход из setup его не ломает.
([client/mod.rs](qeli/src/client/mod.rs))

### Исправлено — предупреждение про fake-tls советовало неприменимое на UDP

Предупреждение «wire mode 'fake-tls' has LOW DPI resistance» предлагало перейти на `reality-tls`
— но он живёт поверх настоящей TLS-сессии, то есть **только на TCP**, и на UDP-профиле его
включить нельзя. Оператор шёл искать настройку, которой там нет. Теперь на UDP-профиле
предлагается только `obfs`. Само предупреждение верно и для `udp-quic` (это алиас
`fake-tls` + QUIC-маскировка): QUIC-слой лишь надевает заголовок и **не шифрует**, так что
открытые записи хендшейка действительно лежат на проводе — меняется только конверт.
([server/mod.rs](qeli/src/server/mod.rs))

### Документация — каталог ошибок `check-config` доведён до полноты

Сверил каждое сообщение, которое может выдать валидация конфига, с
`docs/{ru,eng}/TROUBLESHOOTING.md` §4.1. Не хватало 7 фатальных: пустое имя профиля, три
проверки heartbeat (`interval_ms`/`jitter_ms`/`data_size_bytes`), разбор `pool.cidr`,
`invalid tun.address`, `invalid tun.netmask`. Добавлены с причиной и фиксом.

Новый §4.1.1 — предстартовые проверки: это отдельный класс, отказ **службы целиком** в
супервизоре, а не рестарт-петля worker'а, поэтому вынесен из общей таблицы. Все 7 сообщений о
пересечении подсетей + WARN про fail-open, когда состояние хоста прочитать не удалось.

Итог: 28 сообщений (16 фатальных, 5 WARN, 7 предстартовых) — покрытие в обеих локализациях
проверено скриптом.

## [0.7.12] — 2026-07-21

### Добавлено — русский интерфейс Android-приложения и переключатель языка

Приложение было англоязычным целиком. Теперь в «Настройках» есть выбор языка (English / Русский).
**По умолчанию — английский, независимо от локали устройства.**

- Заведён `res/values-ru/strings.xml` — **139 строк, ровно столько же, сколько в английском**
  (паритет ключей и форматных аргументов проверен скриптом: пропуск ключа молча откатывает строку
  на английский, а расхождение `%1$s`/`%1$d` роняет приложение в рантайме).
- Локализация была бы половинчатой без выноса хардкода: **~90 строк жили прямо в Kotlin и XML**
  (тосты, диалоги, статусы кольца подключения, уведомление сервиса, подписи в разметке). Все
  вынесены в ресурсы.
- Язык форсируется в `MainActivity.attachBaseContext` (обёртка контекста через
  `createConfigurationContext`) на самом раннем этапе, до загрузки ресурсов. Смена языка —
  `recreate()`. Плюс `applyOverrideConfiguration` переустанавливает локаль, потому что AppCompat
  1.6+ при построении конфигурации для ночного режима сбрасывает её на системную.
- **Почему не `AppCompatDelegate.setApplicationLocales`:** он требует
  `AppLocalesMetadataHolderService` в манифесте для работы на API < 33, а вызов из
  `Application.onCreate` на первом запуске не успевает опередить создание первой Activity. Из-за
  этого русский телефон открывал приложение по-русски вместо задуманного английского дефолта —
  ровно баг, ради которого подход и переделан. (Ранее добавленные `locales_config.xml` +
  `android:localeConfig` удалены за ненадобностью.)
- Сервис (`QeliService`) язык `attachBaseContext` не покрывает, поэтому строки уведомления
  резолвятся через собственную обёртку `createConfigurationContext` с выбранной локалью.
- **Не переводятся сознательно:** строки лога и текстов ошибок. По ним построен каталог ошибок в
  `docs/*/manuals/TROUBLESHOOTING.md` («строки ошибок в коде на английском — так они и печатаются»), и
  перевод сделал бы документацию нерабочей. Плюс единицы измерения, `qeli://`, INI-шаблон.

### Изменено — при активном подключении нельзя переключить профиль

Раньше выбор другого профиля на живом туннеле **молча рвал соединение и поднимал его заново** на
новом профиле — один промах по строке списка убивал подключение без всякого подтверждения.
Теперь переключение отклоняется, пока туннель поднят (`Connected` / `Connecting`).

- **Android:** чужие строки списка приглушены, тап по ним объясняет, почему нельзя. Создание и
  импорт профиля больше не делают новый профиль активным на живом соединении — это был обходной
  путь к тому же переключению.
- **Windows / macOS:** гард в `OnProfileSelected` — единственной точке, через которую проходят и
  список, и меню в трее. Выбор возвращается на работающий профиль, показывается тост. На macOS
  проверка стоит **до** записи `LastProfile`, иначе следующий запуск восстановил бы отклонённый
  профиль. Пункты трея для других профилей теперь неактивны.
- Состояние `Error` не блокируется: туннель уже лежит, и выбор другого профиля — нормальный способ
  восстановиться.
- **Редактирование, дублирование, удаление и шаринг любых профилей по-прежнему доступны** — они
  идут не через выбор, а от конкретной строки.
- **Попутно найден баг:** на Android удаление профиля, стоящего в списке **выше** активного,
  сдвигало индексы, а код лишь ограничивал выход за диапазон — активным молча становился другой
  профиль, в том числе при работающем на нём туннеле. Индекс теперь корректируется.

### Изменено — macOS: bundle-id переименован в `ru.qeli.app` (с миграцией)

macOS-клиент теперь собирается под `ru.qeli.app`: `CFBundleIdentifier` → `ru.qeli.app`,
launchd-демон → `ru.qeli.app.daemon`, login-agent → `ru.qeli.app.autostart`.

**Важно для тех, у кого уже установлен старый клиент** — простое переименование сломало бы
апгрейд: plist демона хранит **путь к бинарю**, а не bundle-id, поэтому старый демон продолжил бы
крутить новый бинарь под старым лейблом, а новый код (смотрит только на новый plist) счёл бы, что
«не установлено», и поднял бы **второй** демон — два демона дерутся за один tun. Поэтому:

- `IsInstalled()` / `IsRunning()` дополнительно репортят и **старую** регистрацию (UI больше не врёт);
- `Install()` / `Start()` / `Stop()` / `Uninstall()` сначала **вычищают** её (всё уже под root —
  бесплатно);
- per-user login-agent **молча мигрируется** при старте приложения, сохраняя выбор «запускать при
  входе».

Ручных действий от пользователя не требуется — миграция происходит сама при первом запуске новой
версии. (iOS-клиент переименован тем же префиксом отдельно; он ещё не выпущен, поэтому миграция там
не нужна.)

### Добавлено — настраиваемый формат времени в логах (`[logging] time_format`)

Метка времени в начале строки лога больше не зашита в код. Ключ действует и на сервере (`qeli`),
и на роутерном клиенте (`qeli-client`), значения одинаковые:

| Значение | Пример |
|---|---|
| `datetime` (дефолт) | `2026-07-18 18:10:03.259` — локальное время |
| `rfc3339` / `iso8601` | `2026-07-18T18:10:03.259Z` — UTC, для сведения логов разных хостов |
| `time` | `18:10:03.259` — без даты |
| `epoch` / `unix` | `1782000603.259` |
| `none` / `off` | метки нет — под systemd/procd, они штампуют строку сами |

Неизвестное значение молча откатывается к `datetime`: опечатка в конфиге не мешает старту.

- Рендер метки — один общий `util::log_timestamp`, оба бинаря используют его (раньше метку ставил
  только сервер, и только под `cfg(target_os = "linux")`; `qeli-client` писал дефолтным
  форматтером `env_logger`).
- OpenWrt: UCI-опция `log_time_format` + выпадающий список в LuCI. Дефолт там — `none`, потому что
  procd отдаёт stderr в syslog, который уже штампует каждую строку.
- Windows и macOS: пункт «Время в логе» в настройках, те же пять вариантов. Значение читается на
  каждой строке, так что применяется сразу — перезапуск не нужен (уже написанные строки, понятно,
  сохраняют старую метку). Рендер метки вынесен в общий `qeli-shared/LogTime.cs` — единственный
  кусок этой правки, который не пришлось писать дважды: UI-слой Win (WPF) и mac (Avalonia)
  дублируется целиком.
- Android: тот же выбор в «Настройках». Дефолт — `time`, как и было в приложении: полная дата в
  каждой строке съедает всю ширину экрана телефона. Формат кэшируется в поле, а не читается из
  prefs на каждой строке — этот экран уже чинили от ANR при шторме логов на реконнекте. Попутно
  диалог настроек завёрнут в `ScrollView`: с пятью радиокнопками на невысоких экранах кнопка
  «Сохранить» уезжала за край.
- Веб-панель: селект «Log timestamp» в разделе Logging. Заодно у соседнего «Log format» в
  подписи честно сказано, что `json` пока не реализован — раньше панель предлагала его как
  рабочий вариант.
- **Попутно найден и закрыт баг round-trip'а конфига.** `logging_from` ключ читал, а
  `logging_to` его не писал — то есть «Save to Disk» из панели молча сбрасывал выбранный
  `time_format` обратно на `datetime` (тот же класс ошибки, что когда-то с
  `bind_static_to_session`). Добавлен регрессионный assert в тест round-trip'а.

Документация: ключ описан в `docs/*/manuals/CONFIG.md` (таблица ключей `[logging]` — её у секции
вообще не было, плюс таблица вариантов с примерами), в `TROUBLESHOOTING.md` (когда что
ставить: `rfc3339` для сведения логов, `none` под journald), в `GETTING-STARTED.md` (где
это в приложениях) и в примерах `server.conf` / `client.conf` / Keenetic. Заодно исправлено
устаревшее описание меток у клиентов: в TROUBLESHOOTING было написано, что десктоп пишет
UTC-таймстамп `2026-07-11T19:02:41Z` — этого формата в коде нет уже давно. И исправлено
враньё про `format = plain | json`: он парсится и показывается в панели, но `init_logging`
его не применяет — строка всегда плоская. Полный набор форматов строки лежит в ROADMAP.

### Исправлено — Linux-клиент намертво вставал после обрыва связи (`interface 'vpn0' already exists`)

После пропадания аплинка (например, передёрнули 3G-модем) клиент переподключался и падал с
`Connection error: interface 'vpn0' already exists` — и дальше **каждая** попытка повторяла ту же
ошибку, пока процесс не убьют вручную. Затрагивало TCP и UDP одинаково.

- **Причина.** Уборка TUN стояла в самом конце `run_tcp_tunnel` / `connect_and_run_udp`, то есть
  выполнялась только при штатном выходе. Любой `?` по пути возвращал ошибку раньше, и уборка
  пропускалась. Ключевое звено — блокирующий поток-читатель: закрытие канала он замечает лишь
  **после успешного чтения**, поэтому на простаивающем TUN бесконечно крутился на `WouldBlock`,
  держа свой dup дескриптора. Устройство non-persistent и живёт ровно столько, сколько последний
  fd, — так что `vpn0` оставался, а проверка «интерфейс уже существует» безусловно отказывалась
  его трогать, считая чужим.
- **Починено (A).** Обязательная часть уборки вынесена в RAII-гвард `TunGuard`: он поднимает
  стоп-флаг читателя (что и освобождает дескриптор), восстанавливает резолвер и снимает устройство
  с маршрутами — на **любом** выходе, включая ранний `?` и панику. Штатный путь снимает гвард
  после полной асинхронной уборки, поэтому поведение при нормальном разрыве не изменилось.
- **Починено (B).** Проверка «интерфейс уже существует» больше не отказывает вслепую, а определяет
  владельца по `/proc/*/fdinfo` (у tun-дескриптора есть строка `iff:`): свой осиротевший интерфейс
  забирается (с ограниченным ожиданием, пока предыдущий читатель отпустит fd), а чужой — по-прежнему
  нет. Отказ сохраняется, если интерфейс не tuntap, если его держит другой процесс и если его не
  держит никто (значит он persistent, а наши такими не бывают).
- Попутно убрано **двойное закрытие** дескриптора TUN в обоих транспортах: `drop(TunInterface)`
  уже закрывает `File`, а следом шёл `libc::close()` того же номера — который к тому моменту мог
  быть переиспользован сокетом другого потока.

Проверено на лабе: старый бинарь воспроизводит отказ, новый — переподключается. Обе защиты
Fix B проверены живьём (чужой persistent-tuntap и не-tuntap с тем же именем остались нетронуты).

### Безопасность — P2 внешнего аудита (12 из 12)

⚠️ **Изменение поведения — панель.** Панель больше **не стартует без пароля**. Раньше пустой
`web.password_hash` запрещался только на публичном bind, а на loopback открывал полный доступ:
«пароль ещё не задан» и «пароль не нужен» были одним и тем же состоянием, и открытая панель на
127.0.0.1 — это админ-права (пользователи, хеши, конфигурация) для любого локального процесса и
для любого SSRF на хосте. Теперь нужен либо пароль (`qeli set-web-password`), либо явный
`web.insecure_no_auth = true` с предупреждением при старте. Правка затронула три пути допуска:
гейт старта, `AuthGuard` (API) и `is_authed_cookie_only` (HTML-страницы).

⚠️ **Изменение поведения — kill-switch.** Цепочка теперь `QELI_KS_<интерфейс>` вместо общей
`QELI_KS` (см. P1). Команды ручной разблокировки в документации обновлены.

- **Права секретных файлов.** Временный файл создавался с umask-правами, и содержимое писалось
  **до** применения прав; на свежей установке секрет так и оставался 0644. Добавлен
  `write_atomic_private` (0600 с момента создания и всегда на выходе) для users-файла, ключей
  identity и панели, токена уведомлений и серверного конфига. Обычный `write_atomic` сохраняет
  режим цели — `/etc/resolv.conf` обязан оставаться читаемым.
- **Гонка при первом создании ключей.** Схема `exists → generate → write` позволяла двум
  процессам сгенерировать разные ключи; переживал последний, а первый оставался с ключом,
  которого на диске нет, — всё запечатанное под ним переставало расшифровываться. Создание идёт
  под блокировкой с повторной проверкой внутри неё.
- **Разбор `X-Forwarded-For`.** Брался правый элемент — верно только при ОДНОМ прокси. С цепочкой
  правым оказывался внутренний прокси, и все клиенты попадали в одну корзину: allowlist сверялся
  с прокси, а брутфорс-лимитер считал весь мир одним IP. Теперь доверенные hop'ы снимаются справа
  налево.
- **`cleanup_routes` сносил чужое.** Удалялись маршрут сервера, exclude-обходы и IPv6-blackhole
  безусловно — включая те, что существовали до запуска (установка считает их безобидным
  no-op «File exists»). Введён журнал: удаляется только реально созданное нами.
- **DNS рапортовал успех при частичном отказе.** `resolvectl domain` мог не отработать, а
  результат отбрасывался; routing-домены решают, какие запросы идут в туннель, поэтому запросы
  продолжали ходить к физическому резолверу, пока лог сообщал об успехе. Теперь откат и честный
  переход на `resolv.conf`. Неудачный `resolvectl revert` больше не удаляет маркер — иначе
  повторить откат было бы нечем.
- **Kill-switch: ACCEPT-правила стали обязательными.** Их результат отбрасывался, проверялись
  только DROP и переход из OUTPUT — цепочка могла арминаться без разрешения на сам туннель,
  отрезая хост от того, что защищает, и рапортуя успех.
- **Шлюз возвращает `ip_forward` / `rp_filter`.** Хостовые переключатели менялись и не
  восстанавливались: рабочая станция оставалась маршрутизатором после остановки VPN, а защита от
  подмены адресов — отключённой.
- **Провал записи TOFU-пина рапортовался как успех** — на переполненном диске пользователю
  сообщали, что ключ закреплён, и следующее соединение приняло бы другой ключ как первый.
- **`max_streams` без потолка.** Серверное значение приводилось через `as u32` (2³² → 0) и
  управляло циклом подключений; теперь `clamp(1, 16)` до приведения.
- **Restore бэкапа**: уникальное имя временного файла (общее позволяло двум одновременным
  restore обработать чужой архив) и отмена восстановления при невозможности снять снапшот.

### Безопасность — остальные P1 внешнего аудита

**Утечки трафика в полном туннеле.** Установка маршрутов была fail-open: провал добавления
`0.0.0.0/1` или `128.0.0.0/1` только писался в `warn`, и клиент продолжал работу — половина
IPv4 (или всё) шла мимо туннеля, пока интерфейс показывал «подключено». Теперь это фатально,
и вдобавок результат **проверяется по факту** чтением FIB: `iptables -C` в kill-switch
существует ровно потому, что nft-обёртка умеет возвращать успех и ничего не сделать, — у
`ip route` та же проблема, а цена ложного успеха выше. Провал `include`-подсети тоже фатален
(это заказанный оператором трафик); провал `exclude` остаётся предупреждением — там отказ
означает «пойдёт через туннель», то есть fail-closed.

**IPv6 мимо туннеля.** qeli туннелирует только IPv4, поэтому в полном туннеле весь IPv6
продолжал ходить через физический интерфейс. Теперь он блокируется blackhole-маршрутами, а
`allow_ipv6_leak` остаётся явным опт-аутом; раньше защита была только при включённом
kill-switch. Снимается при отключении — иначе IPv6 остался бы мёртвым после выхода.

**Bypass-маршрут пинится на фактический адрес сокета.** Имя сервера резолвилось трижды
независимо (сокет, `ip route get`, `ip route add`), и при round-robin DNS `/32` мог указывать
не на тот адрес, к которому подключён туннель. Теперь запоминается `peer_addr()` соединённого
сокета, и пинится он.

**Жизненный цикл TUN.** Три отдельные дыры: (1) дубликаты дескрипторов в `setup_tunnel` были
голыми `i32` и утекали при любой ошибке после них — причём так, что `reclaim_stale_tun` уже не
мог восстановиться (держателем оказывался собственный процесс), и клиент вставал намертво;
теперь это `OwnedFd`. (2) `process::exit` в обработчике сигналов не запускает деструкторы, и
`TunGuard` там не срабатывал — Ctrl-C оставлял маршруты и интерфейс; теперь уборка явная.
(3) Потоковые задачи не имели ручек: читатель, зависший в `read_record` на half-open
соединении, вечно держал клон канала TUN-писателя; теперь все задачи регистрируются и
снимаются.

**Kill-switch.** Цепочка стала `QELI_KS_<интерфейс>` вместо общей `QELI_KS`: раньше второй
экземпляр стирал правила первого, а остановка любого снимала защиту у оставшегося молча.
Плюс в режиме шлюза цепочка цепляется и в `FORWARD` — роутируемый трафик LAN через `OUTPUT`
не проходит вовсе, поэтому сеть за клиентом в окно реконнекта уходила в открытую.

**Потеря записей в `users.conf`.** Файл писали три процесса (панель, воркер, CLI), каждый —
свою копию целиком, без перечитывания, так что последний писатель откатывал чужое. Все **13**
точек записи переведены на `update_locked`: блокировка на sidecar-файле (сама запись атомарна
через rename и меняет inode), перечитывание, применение изменения к свежему состоянию.

**Молчаливые дефолты конфига.** `bool_or` теперь предупреждает о нераспознанном значении, как
давно делает `parse_or`: дефолт выключателя — «выключено», поэтому `kill_switch = ture` тихо
снимал защиту, и отчёт о непрочитанных ключах поймать это не мог. Отбрасываемые записи в
CIDR-списках тоже больше не молчат.

**Паника ChaCha20 и рост transcript.** Raw-путь obfs переведён на проверяемый
`try_apply_keystream` (при `panic = "abort"` исчерпание keystream убивало весь процесс со
всеми соединениями вместо разрыва одного); в REALTLS добавлен кумулятивный потолок
transcript — прежние лимиты были на сообщение и буфер, а принятое сообщение вымывалось, так
что пир мог растить его до OOM.

### Безопасность — закрыты три находки внешнего аудита, доступные до/без аутентификации

**UDP-усиление ~500× (без аутентификации).** Начальный обмен ограничен полом в 1200 Б и
проверкой 3×, но путь идемпотентной переотправки эти ограничения не повторял: датаграмма
в **6 байт** с магией фрагмента заставляла сервер снова выслать закешированный ServerHello
(~2-3.4 КБ), сколько угодно раз за время жизни half-open сессии. Со спуфнутым адресом
источника это превращало сервер в DDoS-рефлектор против третьих лиц. Введён **кумулятивный
бюджет на сессию**: любой ответ обязан укладываться в `отправлено + ответ <= 3 × получено`,
а каждая входящая датаграмма идёт в счётчик. Бюджет положен на сессию, а не на конкретную
ветку, — иначе следующий добавленный путь ответа снова обошёл бы проверку.

**Исчерпание памяти параллельными Argon2 (без аутентификации).** Неудача записывалась в
трекер брутфорса только ПОСЛЕ вычисления хеша, поэтому вся пришедшая волна проходила
предварительную проверку и каждый запрос запускал свою задачу ~19 МБ; тысяча одновременных
попыток — порядка 19 ГБ, то есть OOM небольшого VPS. Добавлен процессный семафор на число
ядер (2..8) на обеих точках — веб-логин и VPN-аутентификация. Ограничивает **ресурсы**;
перелёт по числу догадок остаётся, но теперь ограничен числом пермитов.

**Выполнение команд через restore бэкапа (аутентифицированный админ).** Restore проверял
структуру архива, но не содержимое, и распаковывал произвольный `server.conf` прямо в
`/etc/qeli`. После рестарта восстановленный `routing.post_up` запускался через `/bin/sh -c`.
Проверка владельца файла тут ничего не разделяла: сервис работает под `User=qeli`, а
`/etc/qeli` принадлежит `qeli`, — то есть «наш» и «подсунутый» конфиг неразличимы. При этом
`PUT /config` **намеренно** запрещает менять хуки из панели, и restore был единственным
путём в обход.

Теперь распаковка идёт в **staging-каталог**, содержимое проверяется до публикации, и лишь
затем файлы атомарно переносятся на место. Правило то же, что у редактора конфига: хуки
только из файла — `post_up`/`post_down` (сервер) и `password_command` (клиентский профиль)
не могут быть введены или изменены через панель. Правило именно «не изменились», а не
«пусты», иначе восстановление бэкапа сервера с легитимными хуками всегда падало бы.
Дополнительно восстановленный конфиг обязан проходить `validate_profiles` (чтобы restore не
мог уложить воркер) и не содержать исполняемых файлов.

*Известный остаток, намеренно не замазанный:* если хук ссылается на скрипт, лежащий внутри
`/etc/qeli`, restore по-прежнему может подменить содержимое этого скрипта, не трогая конфиг.
Хуки следует держать вне каталога, доступного панели на запись.

Попутно там же: имя временного файла загрузки сделано уникальным (общее имя позволяло двум
одновременным restore обработать чужой архив), а невозможность снять pre-restore снапшот
теперь **отменяет** восстановление вместо молчаливого продолжения без пути назад.

### Исправлено — `check-config` пропускал битые адресные поля (сервер уходил в крэш-луп)

`check-config` обещает «те же проверки, что делает data-plane воркер», но `validate_profiles`
не смотрела адресные поля вообще. Они объявлены как обычные строки, поэтому парсились без
жалоб, а разбирались только когда воркер **стартовал** профиль (`IpPool::new`,
`TunInterface::set_address` в `run_profile`). Итог: команда отвечала OK с `rc=0`, а сервер
падал на каждом респавне.

| конфиг | было | стало |
|---|---|---|
| `pool.cidr = 10.9.0.0/33` | OK, rc=0 → крэш-луп `invalid CIDR prefix (>32)` | rc=1 с точным сообщением |
| `pool.cidr = not-a-cidr` | OK, rc=0 → крэш-луп `invalid CIDR` | rc=1 |
| `tun.address = 300.1.1.1` | OK, rc=0 → крэш-луп `any valid prefix is expected` | rc=1 |
| `tun.netmask = not-a-mask` | то же (не было в отчёте — тот же класс) | rc=1 |

- Проверка добавлена **в `validate_profiles`**, а не в саму команду, и выполняется тем же
  кодом, что и data-plane (`pool::IpPool::new` — заодно покрывает правило минимума /30 и
  предупреждает о нерабочих записях `pool.exclude`), чтобы они снова не разошлись.
- Побочный, но важный эффект: эту же функцию зовёт **веб-панель при сохранении конфига**
  (`web/api/config.rs`), то есть раньше администратор мог через панель сохранить конфиг,
  который укладывал сервер. Теперь панель такой конфиг отвергает.

### Добавлено — трассировка пакетов (`QELI_TRACE`)

Диагностика раньше упиралась в разрозненные debug-строки на местах drop'ов: единого
таймлайна не было ни на клиенте, ни на сервере. Теперь есть — `qeli/src/trace.rs`.

- Взводится переменной окружения `QELI_TRACE=<файл>`, выключено иначе. Выгрузка по
  **SIGUSR1** (и то и другое работает и на сервере, и на клиенте).
- Пишет только **формы** пакетов: время (мкс), направление, точка съёма, размер, индекс
  потока. **Ни payload, ни адресов** — трассу должно быть не страшно кому-то передать.
- Кольцевой буфер на 65 536 событий (~2.6 МБ); в шапке дампа указано, сколько событий
  затёрлось и сколько потеряно на конкуренции за блокировку, — трасса не бывает молча
  неполной.
- Не мешает данным: точка съёма при выключенной трассировке — одна расслабленная
  атомарная загрузка, а запись идёт через `try_lock` и при конкуренции **отбрасывается**,
  а не ждёт (ожидание исказило бы те самые тайминги, ради которых всё и затевалось).

Обе стороны пишут свои файлы, и они складываются в общий таймлайн; общего идентификатора
пакета нет, поэтому сопоставление — по времени и размеру.

### Исправлено — adaptive-бондинг не реагировал на скачивание (Windows/macOS/Android)

Решение о добавлении bonded-потока принималось по **одному счётчику отдачи**
(`_bytesUp` / `bytesUp`), тогда как Rust-клиент считает обе стороны. Из-за этого в самом
типовом сценарии — большая загрузка при почти пустой отдаче, ровно то, ради чего бондинг и
нужен — рампа не срабатывала никогда, и на трёх платформах из четырёх фича молча
оставалась полумёртвой. Теперь везде учитываются оба направления.

### Исправлено — релизная сборка Android APK (`assembleRelease`) падала на R8

`./gradlew assembleRelease` завершался ошибкой `Missing class javax.annotation.Nullable` /
`javax.annotation.concurrent.GuardedBy`. Это JSR-305-аннотации, на которые скомпилирован Tink
(приходит с `androidx.security:security-crypto`, где лежат профили): они `CLASS`-retention,
в рантайме отсутствуют by design и никогда не загружаются, но R8 обходит ссылки и валит сборку.
Добавлены два `-dontwarn` в `app/proguard-rules.pro` — ничего нужного при этом не вырезается.

Замечание на будущее: зависимость стоит с первого коммита, то есть сборка была сломана всегда —
просто `assembleRelease`, судя по всему, ни разу и не запускался. Все APK в `release/dist/`
имеют размер ~20 МБ при `isMinifyEnabled = true` (реальный релизный билд — 5.4 МБ), а артефакты
0.7.2-0.7.4 прямо называются `qeli-android-debug.apk`. То есть под видом релизов до сих пор
выпускались **debug-сборки**. Переход на настоящие релизные APK — отдельное решение: он меняет
ключ подписи, а значит обновление поверх установленного debug-APK невозможно (только
переустановка, с потерей сохранённых профилей).

### Исправлено — тот же класс дефекта в остальных клиентах (Windows, macOS, Android)

После починки Linux-клиента (выше) остальные клиенты проверены на тот же дефект — «уборка
достижима только по пути, который ошибка пропускает». Нашлось два места; оба прячутся за
неумолчальными опциями, поэтому в поле не всплывали.

- **Android, multipath.** `runMultipathTunnelLoop` глотал причину смерти туннеля: результат
  `tunnelError.receive()` отбрасывался и **не пробрасывался** наружу — в отличие от соседнего
  одноканального `runTunnelLoop`, где это ровно тот же баг уже был исправлен. Возврат выглядел
  как штатное завершение, поэтому `connectWithRetry` писал «Connection closed cleanly», сбрасывал
  backoff в 0, не логировал настоящую причину и **не вызывал `closeTransports()`** — файловый
  дескриптор TUN оставался открыт и оставался дефолтным маршрутом устройства в мёртвый туннель.
  Проявлялось только при разрешённом сервером бондинге. Исправлено пробросом причины.
- **Windows + macOS (общий `VpnTunnelBase`), только при `persist_tun = true`.** Во-первых,
  `keepTun` вычислялся из одного флага конфига, без учёта того, поднялся ли туннель: сбой
  *до или во время* `SetupTun` тоже «сохранялся», пропуская `CleanupPlatform()` — единственное
  место, где освобождается недостроенный адаптер и прогретый Wintun-адаптер, который неудачная
  попытка так и не забрала. Теперь условие включает `_persistedClientIp != null` (признак реально
  поднятого TUN). Во-вторых, выходы «сдаюсь» (`reconnect disabled` / исчерпаны retry) делали
  `break` мимо всякой уборки, и после цикла её тоже не было, — а persist-tun к тому моменту
  намеренно оставил интерфейс, маршруты и подменённый DNS «для следующей попытки», которой уже
  не будет. Хост оставался с перехваченным маршрутом и резолвером при статусе «не удалось
  подключиться». Добавлена уборка на выходе из цикла (пользовательский Stop не трогаем — он
  убирает за собой сам).

В отличие от Linux, жёсткого отказа «интерфейс уже существует» тут не бывает: Windows
авто-суффиксит имя адаптера, macOS отдаёт выбор `utunN` ядру — поэтому дефект проявлялся тихой
утечкой, а не вечным клинчем.

### Исправлено — Linux-релизы не запускались на Ubuntu 22.04 (`GLIBC_2.39 not found`)

Выпущенные Linux-бинари **0.7.8–0.7.11 не стартовали** на Ubuntu 22.04 / Debian 12:
`/usr/bin/qeli: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.39' not found`.

- **Причина.** Релизный бинарь собирался обычным `cargo build --release` на сборочной машине с
  glibc **2.41**. Rust std использует `pidfd_spawnp`/`pidfd_getpid` (появились в glibc 2.39), и
  линкер проставлял им **жёсткую версию `GLIBC_2.39`**. Весь остальной бинарь укладывался в 2.34 —
  то есть несовместимость упиралась ровно в два символа.
- **Хуже того, пакет врал о требованиях:** `.deb` объявлял `Depends: libc6 (>= 2.34)`, а на
  Ubuntu 22.04 стоит 2.35 — условие формально выполнялось, apt ставил пакет без единой жалобы,
  и падение случалось только при запуске. Под ударом самый ходовой серверный дистрибутив.
- **Исправлено:** релизная сборка идёт через `cargo-zigbuild` с **прибитым ABI**
  (`--target x86_64-unknown-linux-gnu.2.28`) — новая цель `make deb-portable`. Тогда pidfd-символы
  остаются **weak + без версии** (std сам берёт запасной путь в рантайме), а максимум требуемой
  glibc падает с 2.39 до **2.28**. `Depends` приведён к правде (`libc6 (>= 2.28)`), а новая цель
  `make check-abi` **валит сборку**, если бинарь требует glibc выше объявленной — чтобы это не
  повторилось молча. Обычный `make deb` оставлен для локальных сборок (линкуется с местной glibc,
  что для локальной установки правильно).
  ([debian/Makefile](qeli/debian/Makefile), [debian/control](qeli/debian/control))
- Портируемый бинарь по-прежнему **со встроенным jemalloc** (`--features jemalloc` — политика
  «jemalloc во всех серверных сборках»): прибивание ABI не отменяет аллокатор, RSS воркера
  остаётся ~40–60 МБ, а не ~180 МБ.
- Docker-образ проблемы не имел (собирается и работает внутри bookworm, несёт свою glibc).
- Артефакты `qeli-linux-amd64` и `qeli_0.7.11_amd64.deb` в релизе **v0.7.11 перевыпущены**
  с прибитым ABI — переустанавливать 0.7.11 заново не нужно, достаточно взять обновлённый файл.
- **Попутно: .deb не собирался из чистого клона.** `debian/Makefile` ставит
  `config/client-reality.conf`, а тот не был в git — его скрывал `.gitignore`-паттерн
  `qeli/config/client-*.conf` (заведён, чтобы не утекали ЛИЧНЫЕ клиентские конфиги с паролями).
  Пакеты собирались только потому, что файл лежал в рабочем каталоге мейнтейнера; из тега или
  свежего клона сборка падала на `install: не удалось выполнить stat`. Файл добавлен в
  репозиторий принудительно (как уже сделанный ранее `client-maxobf.conf`) — это лишь пример
  (`vpn.example.com`, `pass = changeme`, нулевой ключ). ([config/client-reality.conf](qeli/config/client-reality.conf))

### Безопасность — внешний аудит 2026-07-18: повышение привилегий и подмена адресов

Шесть находок, каждая проверена по коду перед правкой. Три из них дали больше, чем было
заявлено, — детали ниже.

**`CAP_NET_ADMIN` раздавалась каждому локальному пользователю.** `postinst` вешал
`setcap cap_net_admin+ep` на `/usr/bin/qeli` — бинарь `0755 root:root`, то есть любой
пользователь мог запустить `qeli client --config /tmp/своё.conf`, поднять TUN, увести
дефолтный маршрут в собственный туннель и переписать правила kill-switch. Службе это не
давало **ничего**: `qeli.service` выдаёт капабилити напрямую через `AmbientCapabilities` и
ставит `NoNewPrivileges=true`, под которым ядро file capabilities вообще игнорирует. Снято;
добавлен `setcap -r`, иначе при обновлении капабилити осталась бы висеть на бинаре.
([postinst](qeli/debian/postinst))

**Служба SYSTEM/root регистрировалась на путь, который может переписать пользователь.**
Windows-служба под LocalSystem, задача планировщика с `/RL HIGHEST` и macOS LaunchDaemon
запоминали текущий путь portable-приложения без единой проверки, а документация прямо
предлагала «скопируйте файл куда угодно». Подмена файла после установки давала постоянный
SYSTEM/root, восстанавливаемый через `KeepAlive`, без единого повышения привилегий по пути.
Теперь регистрация отказывает с инструкцией, куда перенести: на Windows требуется
`Program Files`/`Windows` (там право записи и так только у администраторов), на macOS —
владелец `root` и отсутствие записи для group/other **по всей цепочке родительских
каталогов**, потому что записываемый родитель так же смертелен, как записываемый файл:
файл подменяется переименованием. ([win ServiceManager](qeli-win/QeliWin/Service/ServiceManager.cs),
[AutoStartManager](qeli-win/QeliWin/AutoStartManager.cs), [mac ServiceManager](qeli-mac/QeliMac/Service/ServiceManager.cs))

**Аутентифицированный клиент мог подделать адрес отправителя.** ACL проверял только
назначение; исходный адрес не сверялся нигде. Это обходило `client_to_client = false`
(изоляция отбрасывает пакет, чей источник — *другой клиентский* IP, поэтому подделка под
не-клиентский адрес проходила мимо), позволяло выдавать себя за другого пользователя перед
всем, что авторизует по source IP, и портило учёт: трафик списывался с реальной сессии,
а во всех логах и flow-записях стоял чужой адрес. Добавлен `SrcGuard` — своя IP плюс
подсети, маршрутизируемые за клиентом (iroute), иначе сломался бы site-to-site. Проверка
идёт **перед** ACL назначения: подделка источника — это ложь об identity, судить её надо
раньше, чем что-либо рассуждающее о правах сессии. Судятся только IPv4-пакеты: пул адресов
туннеля IPv4, выдать себя за чужую сессию можно только IPv4-источником, а трогать остальное
значило бы рисковать регрессией ради нуля. ([acl.rs](qeli/src/server/acl.rs) + оба транспорта)

**Kick не прекращал входящий трафик.** `kick_all` сигналил только writer'у, а detached
reader продолжал расшифровывать и писать в TUN, пока клиент сам не закроет сокет — уже
после того, как IP вернулся в пул и мог быть выдан другому. Добавлен `watch`-канал, который
видят обе половины (`watch`, а не `Notify`: значение сохраняется, поэтому kick до того, как
reader припарковался в `read_record`, не теряется). **Сверх находки:** оба reaper'а (idle и
rx-dead) живут внутри цикла writer'а, то есть при ЛЮБОМ его выходе выживший reader переставал
быть ограниченным и по времени; теперь сигнал поднимается и при штатном завершении writer'а —
инвариант «reader умирает вместе с writer'ом». Заодно исправлен комментарий в
[server/mod.rs](qeli/src/server/mod.rs), утверждавший, что баг уже починен `kick_all`.

**Инъекция в PowerShell через файл состояния kill-switch (Windows).** Содержимое
`%LOCALAPPDATA%\qeli\killswitch.state` подставлялось в скрипт без экранирования, а `Sweep()`
вызывается первой строкой `Main` в приложении с `requireAdministrator`: подложенная строка
вида `Domain=Allow; …` выполнялась от администратора. `-EncodedCommand` решает вопрос
кавычек в argv, но не инъекции в тело скрипта. Экранирование здесь было бы хрупким — у
файрвола Windows ровно три профиля и два действия, поэтому поставлен allow-list: всё, чего
мы не писали, отбрасывается. ([KillSwitch.cs](qeli-win/QeliWin/Vpn/KillSwitch.cs))

**Подмена native-DLL (Windows).** `qeli.dll` и `wintun.dll` распаковываются в
пользовательский `%LOCALAPPDATA%`, а существующий файл считался доверенным при **совпадении
длины** — которую тривиально подогнать, раз релизный бинарь публичен. **Сверх находки:** был
второй обход, длину игнорирующий полностью — держать подложенную DLL открытой, тогда
`File.Create` бросал `IOException`, который перехватывался с комментарием «используется
другим экземпляром», и грузился файл злоумышленника любого размера. Теперь сверка по
SHA-256, запись во временное имя с атомарной подменой, а фолбэк на «взять что лежит» убран:
при заблокированном файле загрузка честно проваливается.
([NativeLoader.cs](qeli-win/QeliWin/Vpn/NativeLoader.cs))

**Инъекция через UCI на OpenWrt.** LuCI-ACL даёт запись во весь пакет `qeli`, а значения
подставлялись в flat-INI дословно — один перевод строки превращается во ВТОРОЙ ключ, и
значимы здесь `post_up`/`post_down`/`password_command`, которые клиент исполняет через
`sh -c` от root. Добавлен `ini_sanitize` (вырезает управляющие символы). **Второй слой
важнее:** `config_is_trusted` проверял только режим файла, но не владельца — конфиг `0600`,
принадлежащий непривилегированному аккаунту, проходил проверку и получал root, потому что
хук выполняется от нашего процесса. Теперь требуется владелец root или мы сами.
([qeli.init](qeli-openwrt/files/qeli.init), [hooks.rs](qeli/src/hooks.rs))

**Что в аудите не подтвердилось.** Самая срочная находка — «действующие production-креды в
git, немедленно отозвать и переписать историю» — **ложная**: во всех пяти названных скриптах
пароль читается из окружения с пустыми дефолтами, прод-хост заменён плейсхолдером, и в
истории этих файлов литерала тоже нет (репозиторий проходил скраб перед публикацией).
Заявленный root-RCE на OpenWrt как RCE **не доказан**: сырой `LF`, скорее всего, не переживает
построчный парсер libuci и ломает `/etc/config/qeli` целиком — это отказ в обслуживании;
починено в обе стороны, потому что и DoS через веб-интерфейс неприемлем, а цена — один `tr`.
Инъекция в PowerShell и подмена DLL — **не** повышение из непривилегированного в
администратора, как заявлено, а обход UAC от имени того же пользователя, который Microsoft
границей безопасности не считает.

**Проверка.** Rust: гейт (fmt/build/test/clippy) + живой туннель `fake-tls` и `obfs` — важно,
потому что `SrcGuard` стоит на пути каждого пакета и ошибка в масках проявилась бы молча
отброшенным трафиком, а не падением сборки. C#: `dotnet build` обоих клиентов; привилегированные
сценарии Windows/macOS в этом окружении не воспроизводимы. OpenWrt не исполнялся.

### Добавлено — `qeli check-config`: проверка конфига без запуска службы

Проверить конфиг раньше можно было только одним способом — запустить сервер и посмотреть,
упадёт ли он. Способ плохой сразу по двум причинам: на боевой машине это перезапуск службы,
а супервизор ещё и перезапускает упавший worker по кругу с нарастающей паузой, так что
процесс не завершается даже на заведомо битом конфиге — приходится ловить сообщение
глазами и жать Ctrl-C.

```
qeli check-config --config /etc/qeli/server.conf
qeli check-config --client --config /etc/qeli/client.conf
```

Ничего не поднимается — ни слушателей, ни TUN, ни службы. Код возврата `0`/`1`, то есть
годится в CI и как pre-flight перед `systemctl restart`. Схемная проверка вызывает **ту же**
`validate_profiles`, что и data-plane worker при старте, поэтому вердикт совпадает с
реальным запуском, а не приближает его.

**Главное — теперь видны опечатки в именах ключей.** Неизвестный ключ никогда не был
ошибкой: он просто не запрашивается, параметр молча остаётся дефолтным, и предупреждения
нет **ни на каком уровне логирования**. Ровно так `exclude_routes` вместо `exclude` долго
выглядел рабочей настройкой, пока split-tunnel не применялся вовсе — эту находку и дал
аудит документации.

```
/etc/qeli/client.conf: 1 key(s) that nothing reads — check the spelling:
  [qeli] exclude_routes
```

### Добавлено — три настройки, которые были в конфиге, но не работали, теперь работают

Разбирая мёртвые параметры, три оказались не мусором, а недоделками — их доделали, а не
удалили.

- **Фрагментация ServerHello использует заданные размеры.** `obf.fragmentation.min_chunk_size`
  / `max_chunk_size` / `max_fragments_per_packet` не доходили до провода: живой код резал
  запись надвое по формуле `1 + (len-1) % 4`, а **детерминированное деление — само по себе
  сигнатура**. Готовый настраиваемый фрагментатор при этом лежал рядом, покрытый тестами, и
  вызывался только из них. Заодно из него убран внутренний бросок кубика: он фрагментировал
  лишь в **30% случаев**, то есть оператор, явно включивший фрагментацию, получал её в трёх
  случаях из десяти — для рукопожатия это разница между «сломали сигнатуру DPI» и «в основном
  нет». Решение теперь принимает вызывающая сторона, которая и так проверяет флаг.
  ([obfuscate.rs](qeli/src/protocol/obfuscate.rs), [handler.rs](qeli/src/server/handler.rs))

  **Дефолты размеров при этом сделаны консервативнее: `256/1024/4` вместо `64/512/16`.**
  Прежние на ServerHello ~2 КБ давали ~16 сегментов по ~125 байт: сигнатурный матчинг это
  обманывает, но сам такой поток — аномалия, ни один настоящий TLS-сервер так не пишет,
  то есть мы меняли одну примету на другую. Новые дают 2–4 куска правдоподобного размера,
  неотличимых от обычной сегментации TCP. Смысл фрагментации в том, чтобы запись **не
  приехала одним сегментом**, а не в том, чтобы её измельчить.

  В [CONFIG.md](docs/ru/manuals/CONFIG.md) добавлено пояснение, которого не хватало: фрагментация
  касается **только рукопожатия** — одна запись, один раз за подключение. На скорость она
  не влияет вовсе; цена — около 600 байт и десятки миллисекунд к рукопожатию. Прежняя
  формулировка «дробить записи на чанки» читалась так, будто режется весь трафик.

  Проверено вживую на всех трёх клиентах (Rust `fake-tls` и `obfs`, Android `fake-tls`):
  туннель поднимается, трафик ходит — в том числе на нарочно вывернутых 16/32/16.
- **Сокетные буферы применяются** — `perf.tcp.send_buffer_size` / `recv_buffer_size` теперь
  ставят `SO_SNDBUF` / `SO_RCVBUF`; раньше `setsockopt` для них не вызывался нигде. Дефолт
  сменён на `0` = не трогать автотюнинг ядра: поднимать их имеет смысл только на канале с
  большим произведением полосы на задержку. ([transport/tcp.rs](qeli/src/transport/tcp.rs))
- **Джиттер рукопожатия** (`obf.anti_fingerprinting.add_jitter_to_handshake`) — постоянное
  время ответа сервера тоже телл; теперь ответ размазывается на несколько миллисекунд.
  Клиенту это ничего не стоит.

**Из шаблонов вычищены 26 параметров, которые ничего не делали.** Три из них команда нашла
сама (см. ниже). Остальные 23 — другой класс, который она поймать не может **в принципе**:
ключ читается в структуру конфига, сохраняется, редактируется в панели — и дальше на
поведение не влияет. Для механизма учёта обращений он «прочитан». Нашлись сплошным
проходом по всем полям структур с проверкой, есть ли у каждого читатель в дата-плейне.

Среди них — `auth.password_hash`, **третий по счёту `password_hash` в проекте и
единственный мёртвый** (`user.password_hash` и `web.password_hash` рабочие). Оператор мог
прописать туда пароль, будучи уверенным, что что-то защищает. Также `obf.cipher` (шифр
дата-плоскости не переключается), три размера чанков фрагментации (сама фрагментация
работает, но размер зашит), `perf.tcp.*_buffer_size` (`SO_SNDBUF`/`SO_RCVBUF` не
вызывается нигде), `pool.lease_time_secs`, `logging.format` и остальные.

**15 из них удалены целиком** — из структур конфига, INI-сериализатора и парсера, формы
панели и справочника. Панель почистить было обязательно: поля остались бы привязаны к
несуществующим путям и **дописывали бы мёртвые ключи обратно при каждом сохранении** — те
самые, что `check-config` тут же пометил бы как опечатки. Быстрый запуск профилей правок
не потребовал: он строит профиль из `ProfileConfig::baseline()`, откуда поля исчезли
вместе со структурами. Заодно убрано `IpPool::lease_time_secs` — оно копировалось из
конфига и не читалось ни одним методом.

Две настройки оставлены осознанно и помечены в CONFIG.md как **не реализованные**, потому
что они не мусор, а незакрытые задачи (обе занесены в роадмап): `dns.upstream_protocol`
(резолвер всегда ходит по UDP — то есть **приватности от того, кто видит канал к апстриму,
он не даёт**) и `logging.format = json`.

**Первый же прогон нашёл три мёртвых ключа в собственных шаблонах.** `server.conf` и
`server-maxobf.conf` годами предлагали `obf.tls.session_id`, `obf.tls.supported_groups` и
`obf.tls.key_share_entropy_bytes` — их не читает никто и никогда, в коде таких ключей не
существует вовсе. Оператор, аккуратно настраивавший «форму ClientHello», настраивал
пустоту. Удалены с пояснением, где находятся настоящие рычаги: токен REALITY в `session_id`
задаётся через `obf.tls.reality_proxy.short_ids`, а отпечаток ClientHello не настраивается
намеренно — в reality-tls это байт-в-байт Chrome, и «подстройка» групп сделала бы его
снова уникальным.

Два уточнения, без которых команда врала бы на исправных конфигах. **Динамические
семейства ключей** (`pool.reservation.<юзер>`, `metadata.<ключ>`) читались прямым обходом
`entries` мимо `get`/`all` — механизм считал бы их опечатками; добавлен
`Section::entries_with_prefix()`, который читает и помечает, оба места переведены на него.
И **клиентский конфиг общий с клиентами Windows/macOS**: шесть ключей (`dev_node`, `local`,
`lport`, `metric`, `persist_tun`, `route_file`) реализованы только там, у них свой парсер —
Rust-бинарь ругался бы на исправный файл. Теперь они выводятся отдельной строкой
«используются только клиентами Windows/macOS» и проверку не роняют.

Реализовано **учётом обращений**, а не списком известных ключей: `Section::get`/`all`
запоминают, что у них спрашивали, и после сборки конфига `IniDoc::unread_keys()` отдаёт
всё, что в файле есть, а прочитать никто не пытался. Список ключей вести не нужно — он не
может разойтись с кодом, потому что выводится из самого кода. Учёт лежит в `RefCell` и
намеренно **не входит в значение**: две секции с одинаковым содержимым равны независимо от
того, что из них читали (тест прилагается). `IniDoc` живёт недолго — распарсили, свернули в
структуры, выбросили — и в разделяемом состоянии не хранится, так что `!Sync` здесь ничего
не стоит. ([format.rs](qeli/src/config/format.rs), [main.rs](qeli/src/main.rs))

### Добавлено — `dev_attach`: работа на ЧУЖОМ интерфейсе + Keenetic OpkgTun (web-UI) — PR #82

Вклад [@a-rasskazov](https://github.com/a-rasskazov).

- **Новый клиентский ключ `dev_attach`** (INI, дефолт `false`): вместо создания собственного
  устройства клиент **цепляется к уже существующему интерфейсу** (`dev = <имя>`), которым владеет
  внешний менеджер. В этом режиме qeli **только качает пакеты**: не создаёт устройство, не ставит
  адрес/линк, не ставит маршруты и **не удаляет его при отключении** — L3 и маршрутизация остаются
  за владельцем. Выданный сервером IP экспортируется в файл `$QELI_TUNIP_FILE` (если переменная
  задана), чтобы владелец сам применил адрес. Если интерфейса ещё нет — клиент честно падает с
  ошибкой, и цикл реконнекта ждёт, пока владелец его создаст. Защита «не отбирать существующий
  интерфейс» для обычного режима **сохранена** и обходится только явным `dev_attach = true`.
  Опция общая (не только Keenetic): годится для systemd-networkd / NetworkManager / интерфейсов
  под управлением прошивки. ([config/client.rs](qeli/src/config/client.rs),
  [client/mod.rs](qeli/src/client/mod.rs))
- **Keenetic OpkgTun: интеграция с web-UI роутера.** Причина: `ndm` маршрутизирует только через
  интерфейсы, которые сконфигурировал сам, поэтому собственный tun от qeli роутер не считает
  подключённым (мимо web-UI, политик и маршрутизации). Теперь qeli цепляется к OpkgTun-интерфейсу
  (`dev_attach`), а адрес/линк/маршруты держит `ndm` через wan.d-хук. Всё изолировано в
  `release/keenetic/opkgtun/` (хук `010-qeli.sh`, преднастроенный `S99qeli`, пример конфига,
  README с моделью владения, требованием статического IP, оговорками и диагностикой); базовый
  `release/keenetic/` остаётся чистым gateway-режимом.
- **Документация:** в [KEENETIC-DEPLOY.md](docs/ru/manuals/KEENETIC-DEPLOY.md) описан рассинхрон
  `bind_static` у reality-tls (значение обязано совпадать с серверным, иначе — «decryption failed»).

### Безопасность — `allowed_networks` теперь ДЕЙСТВИТЕЛЬНО применяется (сервер)

Пер-юзерный ACL назначений был **ложной границей безопасности**: поле принималось панелью,
сохранялось, показывалось в UI и описывалось в трёх местах документации («куда юзеру разрешено
ходить; пусто = куда угодно»), но **дата-плейн его не читал вообще** — 16 упоминаний в дереве, все
в config/ и web/, ни одного в server/. Юзер с `allowed_networks = 10.0.0.0/24` доходил до любого
маршрутизируемого адреса. Отягчало то, что соседние контролы той же формы (`profiles`,
`max_sessions`, `data_limit_gb`, `expire_at`, `client_subnets`) enforce'ятся — у оператора были все
основания считать, что и этот тоже.

Реализовано: новый [server/acl.rs](qeli/src/server/acl.rs) компилирует CIDR-список один раз при
авторизации в пары `(сеть, маска)`; проверка назначения идёт на **каждом** внутреннем пакете
клиент→сервер, **после** AEAD/replay (судится только аутентифицированный трафик) и **до** TUN —
симметрично в TCP и UDP. Пустой список = без ограничений (документированная семантика) и
короткое замыкание, поэтому обычная сессия не платит ничего. **Fail-closed** на том, что нельзя
оценить (обрезанный заголовок, не-IPv4). Наследование из группы — `effective_allowed_networks`,
зеркало существующих `effective_bandwidth_limit`/`effective_max_sessions`. Панель теперь
**валидирует** CIDR на входе (раньше поле не парсилось вообще): раз ACL работает, опечатка молча
**расширяла** бы доступ, т.к. нескомпилированные записи пропускаются, а пустой список = «куда
угодно». 6 юнит-тестов.

### Безопасность — `password_file` в профиле клиента = чтение любого файла сервером

API запрещал `password_command` (комментарий: «иначе компрометация панели = root RCE»), но
**текстом ошибки направлял на `password_file`**, у которого не было ограничения пути. Ключевое: этот
файл читает **сам сервер** — client-manager спавнит `qeli client -c <профиль>` дочерним процессом
супервизора (root / `CAP_NET_ADMIN`), и содержимое уходит как пароль на тот `server.address`, что
указан в профиле. То есть админ панели (или CSRF/XSS) мог указать `/etc/shadow`, приватный ключ или
`.env` и выгрузить их на свой сервер, а `autostart` повторял бы это при каждом рестарте. Теперь путь
ограничен тем же whitelist'ом `/etc/qeli`, которым уже проверяются `identity_key`/`users_file`/
`tls_cert`, и текст ошибки исправлен. ([client.rs](qeli/src/web/api/client.rs))

### Исправлено — панель сохраняла конфиг, который сервер отказывался загрузить

Полная валидация профилей жила только в старте воркера, а путь сохранения её не звал. Панель молча
принимала дубли имён профилей, `plain` поверх UDP, obfs без ключа, REALITY без `short_id`, нулевые
обязательные perf-параметры и heartbeat вне диапазона; оператор видел «сохранено», а после
Apply/Restart дата-плейн не поднимался. Теперь `validate_profiles` вызывается в **обоих** путях
(structured проверяет ре-парснутый текст — ровно то, что увидит воркер; raw — свой разбор), и
отказ приходит до записи на диск. ([config.rs](qeli/src/web/api/config.rs), [mod.rs](qeli/src/server/mod.rs))

### Безопасность — CSRF: проверка по Origin вместо «есть ли cookie»

Middleware пропускал Origin-проверку, если в запросе нет session-cookie. В **passwordless**-режиме
cookie не бывает вообще, поэтому проверка не работала ни для одного мутирующего запроса — сторонняя
страница могла инициировать restart / full-restart / **ротацию identity** (ломает всех запиненных
клиентов) / restore на локальной панели. Допущение «Basic-заголовок браузер сам не подставляет»
тоже неверно: браузеры кэшируют Basic-креды по origin и досылают их в cross-site-инициированных
same-origin запросах, т.е. дыра была и в парольном режиме. Теперь правило простое: **есть
Origin/Referer → обязан совпасть с разрешённым хостом**; их отсутствие (curl/скрипты) по-прежнему
пропускается. ([web/mod.rs](qeli/src/web/mod.rs))

### Исправлено — панель: невалидные числа больше не превращаются в «безлимит»

`as_u64()` возвращает `None` для «-5», «1.5» и «abc» ровно так же, как для отсутствующего ключа,
поэтому `unwrap_or(0)` превращал опечатку оператора в **0 = безлимит**, а `if let Some(...)` —
в молчаливый no-op с ответом «успешно». Новый `opt_u32_limit` различает «не задано» и «мусор» и
отвечает ошибкой. Покрыты bandwidth/сессии/группы, а также два места вне исходного отчёта:
дашбордный `set-bandwidth` и **стирание `expire_at`** (воркер пишет это поле безусловно, так что
мусор в теле молча снимал срок действия аккаунта). ([users.rs](qeli/src/web/api/users.rs),
[usage.rs](qeli/src/web/api/usage.rs), [status.rs](qeli/src/web/api/status.rs))

### Исправлено — панель: блокировка входа, `base_path`, лимит тела логина

- **Админ-хеш** принимался как любой текст: обрезанная вставка или введённый открытый пароль
  применялись дословно, инвалидировали все сессии (хеш — соль подписи сессий) и после этого не
  могли пройти проверку — выход только правкой файла на хосте. Теперь в обоих путях сохранения
  проверяется Argon2-PHC. Главное — переписана подсказка в UI: она обещала «пусто = открытый
  доступ», хотя пусто = **сохранить текущий пароль**, то есть сама провоцировала деструктив.
- **`base_path`** не входил в `needs_full_restart`, хотя роутер монтируется по значению на старте:
  панель сообщала «применено live», а адрес не менялся до полного рестарта процесса.
- **`/login`** получил собственный лимит тела 8 КиБ вместо общих 16 МиБ (нужных только restore):
  тело буферизуется и парсится ДО консультации с лимитером, так что залоченный клиент всё равно
  заставлял сервер держать 16 МиБ на запрос. Лимит заодно ограничивает длину пароля.

### Исправлено — панель: мёртвые настройки и уведомления

- **`anti_fingerprinting` и `http2_masking`** помечены бейджем «not active» и честным описанием:
  они парсятся и сохраняются, но транспорт их не читает. Это худшая часть находки — оператор
  включал «ротацию cipher suites и jitter хендшейка против DPI» и получал ноль плюс ложную
  уверенность. У `server_names` расплывчатое «config-surfaced» заменено прямым «не применяется»
  (SNI-ротация берёт встроенный список).
- **Тумблеры уведомлений о подключении/отключении клиента** молча терялись при сохранении:
  `merge_events` знал 5 ключей из 7, хотя сами события исправно стреляют.
- **Тест уведомлений** показывал зелёный тост при провале отправки (реальный результат рендерился
  рядом корректно — врал только тост); теперь тип берётся из вложенного результата.
- **Токен Telegram** невозможно было удалить («пусто = оставить» — осознанное решение, иначе любое
  сохранение затирало бы токен): добавлен явный `clear_token`, и отключение канала теперь стирает
  секрет, чтобы живой бот-токен не лежал в `notify.json` для канала, который оператор считает
  выключенным.
- **Проверка обновлений** блокировалась собственным CSP (`connect-src 'self'`), а ошибку глотал
  пустой `catch` — фича не работала никогда и молча. В `connect-src` добавлен `api.github.com`
  (браузерный путь выбран намеренно: сервер не звонит домой), провал теперь пишется в консоль.
- **`static_ip`** проверяется на формат в панели, а рантайм больше не глотает разбор молча —
  невалидный адрес был неотличим от «не задан», и юзер тихо получал динамический.
- **Basic-auth rate-limit** считал попытки по адресу reverse-прокси (единственная из трёх точек, не
  учитывавшая `trusted_proxies`) — за прокси пять неудач от кого угодно лочили **всех**.

### Исправлено — панель: описание маршрута, restore-бомба, доступность, форма

- **Описание advertised-route больше не уничтожается.** Поле существовало в модели, но
  сериализатор его выбрасывал (о чём честно сообщал собственный докблок), а парсер не читал
  обратно — то есть ЛЮБОЕ сохранение из панели стирало написанное руками примечание. Теперь
  оно пишется как завершающий `desc=`, забирающий остаток строки (описание — свободный текст с
  пробелами, поэтому обычным токеном его не сделать), читается обратно и редактируется в форме;
  round-trip стал по-настоящему lossless. Регрессионный тест прилагается.
- **Restore ограничен по РАСПАКОВАННОМУ объёму** (64 МиБ) и числу записей (5000). Раньше
  проверялись тип записи и путь, но не размер: gzip сжимает ~1000:1, поэтому валидный 16-МиБ
  архив разворачивался в ~16 ГБ в `/etc` и забивал корневую ФС.
- **Тумблеры стали доступны с клавиатуры.** 30+ переключателей были `<div @click>` без `role`,
  `tabindex` и обработчика клавиш — оператор без мыши не мог переключить ни один, включая
  `require_client_key_proof` и брутфорс-политику. Вместо правки каждого места — один апгрейд при
  загрузке: `role="switch"`, фокусируемость, Enter/Space и `aria-checked` для скринридера;
  MutationObserver подхватывает те, что Alpine рисует позже.
- **JSON → форма больше не ломает модель.** `normalizeProfiles` восстанавливал ровно одну вложенную
  секцию, поэтому удаление, например, `heartbeat` в JSON-редакторе роняло форму с TypeError при
  следующем рендере (`:class` вычисляется всегда, `x-show` детей не защищает). Теперь профиль
  добивается по каноническому скелету — добавляются только ОТСУТСТВУЮЩИЕ ключи, значения
  пользователя не затираются.
- **`web.persist_session_key`** добавлен в форму (правился только через raw/JSON).

### Исправлено — панель зависала со спиннером вместо сообщения об ошибке

`fetch(...).then(r => r.json())` бросает на любом не-JSON теле — а именно его панель и получает,
когда сессия истекла: сервер отдаёт HTML страницы входа. Необработанный выброс оставлял
`loading` / `saving` / `modalSaving` навсегда в `true`: крутилка вертится, кнопка заблокирована,
причина не показана, лечится только перезагрузкой страницы. Обёртка `apiFetch`, которая уже была
написана, использовалась ровно на одной странице из десяти.

Теперь она одна на всю панель ([layout.html](qeli/src/web/templates/layout.html), в `<head>` —
чтобы существовать до скрипта страницы) и через неё проходят все 40 вызовов API. Она не бросает
никогда: и на сетевом сбое, и на не-JSON-ответе возвращает `{ ok: false, error }`, поэтому UI
всегда доходит до состояния «показал ошибку», а 401 читается как «сессия истекла, обнови
страницу» вместо `SyntaxError: Unexpected token '<'`.

Три места, где спиннер залипал гарантированно: `saveBw` ([dashboard.html](qeli/src/web/templates/dashboard.html)),
`saveLimit` и `doReset` ([users.html](qeli/src/web/templates/users.html)) — снимали флаг ПОСЛЕ
запроса, без `finally`. Отдельный `try/finally` им не понадобился: не бросает — не залипает.

Три вызова сознательно оставлены сырыми: `api/server/restart` и `api/server/full-restart`
трактуют обрыв соединения как успех (сервер и должен уйти в перезапуск), а проверка обновлений
ходит на GitHub, а не в наш API. `login.html` рендерится без layout и уже обрабатывает всё сам.

### Исправлено — панель на телефоне: сайдбар съедал 60% экрана

Панель была свёрстана только под десктоп: на всю разметку приходилось 4 адаптивных
класса. Сайдбар шириной 224 px рендерился всегда — на экране 375 px под содержимое
оставался 151 px, то есть панель на телефоне была практически неработоспособна.

Ниже 768 px сайдбар стал выдвижным: кнопка в топбаре, затемнённая подложка, закрытие
по клику мимо и по Esc; на 768 px и выше он по-прежнему обычная статичная колонка, и
кнопка скрыта. Счётчики в топбаре на узком экране убраны — это справочная информация,
а не управление, и заголовок с кнопкой важнее.

Остальное — одним правилом в [input.css](qeli/web-assets/input.css) вместо ~41 точечной
правки: все многоколоночные сетки схлопываются в одну колонку, а семь таблиц с данными
получают горизонтальный скролл внутри своей карточки (`.card:has(>table)` достаёт до всех
семи, не трогая ни одного шаблона). Страница больше не едет вбок ни на одном экране.

Это по-прежнему desktop-first панель, приведённая в рабочее состояние на телефоне, а не
отдельный мобильный дизайн.

### Исправлено — правила ширины полей существовали ТОЛЬКО в сгенерированном CSS

`.inp.w-40{width:auto}` и семь его соседей лежали в закоммиченном `app.css`, но их не было
в исходнике `input.css`, из которого он собирается. То есть первый же `npm run build` —
чей угодно — молча снёс бы их, и ~30 узких полей ввода (порты, таймауты, MTU) растянулись
бы на всю ширину формы: `.inp{width:100%}` эмитится после слоя утилит и выигрывает у
`w-40` при равной специфичности. Правила перенесены в источник, где им и место.

Заодно починился `.inp.w-32` — этого правила не было и в старом CSS, так что поле уже
было сломано; теперь 8 rem, как и задумано.

### Устойчивость — connect + handshake теперь ограничены общим дедлайном (все клиенты)

Сервер (или middlebox), принимающий TCP и затем молчащий на прикладном уровне, оставлял клиента
в «Connecting» **навсегда** без автопереподключения — хендшейк-риды были неограниченными
`.await`, а keepalive тут не помогает (живой-но-молчащий пир отвечает на probe). Теперь фаза
connect+handshake (но НЕ data-plane) ограничена `connection_timeout_secs`: **Rust** оборачивает
`connect_*` (connect + obfs/TLS-риды) и `tcp_handshake` (qeli-хендшейк) в `tokio::time::timeout`
(+ оба multipath-JOIN); **C#** выставляет `ReceiveTimeout` на сокет и снимает его перед data-plane;
**Android** — блокирующий `SocketChannel` игнорирует soTimeout, поэтому watchdog-поток закрывает
канал по дедлайну (бросая `AsynchronousCloseException` из зависшего рида → реконнект), и стоит down
перед data-plane (тихий туннель не падает — liveness через rxDead-watchdog). Отдельно закрыт **UDP
Fill-spin**: поток фрагмент-датаграмм, которые никогда не собираются, крутил реассемблинг мимо
дедлайна (per-read таймаут под флудом не срабатывает) — теперь `Fill()`/`fill()` в C# И Android
честно смотрят wall-clock дедлайн хендшейка. ([client/mod.rs](qeli/src/client/mod.rs),
[VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
[QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))

### Устойчивость — UDP-хендшейк: сервер идемпотентно переотправляет ServerHello/AuthOK

Потеря датаграммы сервер→клиент во время UDP-хендшейка (ServerHello или AuthOK) раньше стоила
клиенту **полного простоя `connection_timeout_secs`** (~30 c) до реконнекта со свежего порта:
переотправку клиент делал только по forward-направлению, а на повтор его запроса сервер не отвечал
— ретрансмит ClientHello (plaintext-фрагмент) падал в AEAD-декодер существующей сессии, а ретрансмит
AUTH отбрасывался replay-окном. Теперь сервер кэширует ServerHello (пока `AwaitingAuth`) и AuthOK
(после auth) и **идемпотентно переотправляет** их, распознав повтор запроса: фрагмент при
`AwaitingAuth` → повтор ServerHello; байт-совпадение с исходным AUTH при `Authenticated` → повтор
AuthOK. Крипто-состояние не трогается, кэш ServerHello освобождается при auth. Reverse-потеря теперь
чинится за ~1 RTT вместо ~30 c. ([udp_handler.rs](qeli/src/server/udp_handler.rs))

### Безопасность — C# WebSocket-парсер: pre-auth OOM + десинк на control-фреймах

На пути `fronting=websocket` C#-парсер читал 64-битную длину WS-фрейма **без ограничения** и с
непроверенным `long→int` кастом — rogue-сервер или on-path MITM (ДО проверки server-proof) мог
объявить фрейм в гигабайты → `new byte[~2GB]` (OOM) или отрицательный размер (краш). И payload
любого опкода, включая Ping/Pong/Close, возвращался как ciphertext → сдвиг ChaCha-keystream и
десинк туннеля. Теперь длина ограничена `WsFrameMax` до аллокации, а control-фреймы дропаются —
паритет с Rust (`WS_FRAME_MAX`) и Android (1 МиБ). ([ObfsStream.cs](qeli-shared/QeliShared/Protocol/ObfsStream.cs))

### Безопасность — QUIC-varint: crafted-пакет мог уронить клиент в reconnect-DoS (C#/Kotlin)

8-байтный QUIC token-length varint копился в 32-битный `int` → переполнение в минус → `offset`
уходил отрицательным → `IndexOutOfRange`/`ArrayIndexOutOfBounds` на специально сформированном UDP-
пакете (pre-auth, в режиме udp-quic без obfs; obfs-режим иммунен). Не краш процесса, но
принудительный реконнект; при потоке — DoS. Varint переведён в `long` + bounds-check (Rust уже был
безопасен). ([Quic.cs](qeli-shared/QeliShared/Protocol/Quic.cs),
[quic.rs](qeli/src/protocol/quic.rs))

### Исправлено — фрейминг/MTU: паритет ограничений и корректный размер под DF

Пачка hardening по трактам упаковки/фрейминга/MTU (второй аудит + собственный):
- **Отправитель фрагментов** во всех трёх реализациях теперь жёстко проверяет `MAX_FRAGS` (было:
  `debug_assert` в Rust — вырезан в release; ничего в C#/Kotlin) — будущий крупный хендшейк упадёт
  громко у источника, а не как загадочный простой у пира.
- **C#/Kotlin encode** проверяет `MAX_RECORD_SIZE` перед записью 16-битной длины (паритет с Rust) —
  большой `padding_max`/shaping-cover больше не строит запись, которую пир отвергнет или которая
  завернёт длину и десинкнет TCP-стрим.
- **Rust UDP-uplink** капает `data+padding` по *обнаруженному* MTU (было: литерал `1400` — при узком
  LTE/CGNAT-пути DF-пакеты молча терялись с EMSGSIZE), а cover/heartbeat-паддинг — тоже по MTU
  (иначе DF-cover не уходил, ослабляя DPI-маскировку). Overhead-константа obfs+quic поправлена (65).
- **Локальный explicit `mtu=`** валидируется (0=auto или 576..9000, как pushed) — mtu=1/9000 больше
  не принимаются.
- **PMTU-проба** рандомизирует `probe_id` (был предсказуемый старт `0x4D54`+1) и сверяет echoed size —
  off-path подделка probe-ACK (fake-tls-UDP без obfs) больше не пинит клиента на слишком большой MTU.
  ([packet.rs](qeli/src/protocol/packet.rs), [udp_frag.rs](qeli/src/protocol/udp_frag.rs),
  [client/mod.rs](qeli/src/client/mod.rs), [config/client.rs](qeli/src/config/client.rs),
  PacketCodec/UdpFrag в C#/Kotlin)

### Безопасность — UDP anti-amplification: явный 3×-бонд + честный комментарий (сервер)

Guard на минимальный размер initial-датаграммы фактически ограничивал усиление до <3× (в пределах
QUIC-стандарта), но комментарий утверждал, что рефлексия **невозможна** — это неверно (ответ ~2-3.4 КБ
против запроса ~1.35 КБ). Комментарий исправлен, и добавлена **явная проверка**: сервер отказывается
отвечать, если handshake-ответ превысил бы 3× принятого — чтобы будущий крупный сертификат/расширение
не превратили сервер в высокоусиливающий рефлектор для поддельного источника.
([udp_handler.rs](qeli/src/server/udp_handler.rs))

### Надёжность — half-open эвиктится случайно; C#/Android reassembler capает chunk

Два мелких hardening из собственного аудита. (1) При переполнении таблицы half-open UDP-сессий
сервер эвиктил **самый старый** — под спуф-флудом это преимущественно настоящие клиенты, дождавшиеся
своей очереди на auth (их доля мала и транзиентна). Теперь выбирается **случайная** half-open
(reservoir-выборка за один проход): реальную запись задевает лишь с вероятностью = её малой доли.
(2) C#/Android reassembler фрагментов не ограничивал размер отдельного chunk'а (в отличие от Rust) —
добавлен cap `MAX_CHUNK`, так буфер сборки ограничен `MAX_FRAGS*MAX_CHUNK`, а не `MAX_FRAGS*65535`.
([udp_handler.rs](qeli/src/server/udp_handler.rs),
[UdpFrag.cs](qeli-shared/QeliShared/Protocol/UdpFrag.cs),
[udp_frag.rs](qeli/src/protocol/udp_frag.rs))

### Безопасность — имя профиля могло протащить lifecycle-hook (обход запрета → выполнение команд)

`post_up`/`post_down` намеренно **file-only**: web-API восстанавливает их из файла на диске, чтобы
компрометация панели не превращалась в выполнение команд. Обойти это можно было через **имя**:
значения INI давно чистятся от управляющих символов, а заголовки секций и ключи писались **сырыми**.
Перевод строки в имени профиля разрывал строку `[profile:<name>]` и подделывал лишние строки
конфига — включая `routing.post_up`, который затем выполнялся через `/bin/sh -c` при следующем
старте (под packaged systemd — от пользователя `qeli` с `CAP_NET_ADMIN`/`NET_RAW`/`NET_BIND_SERVICE`;
от root при ручном запуске). Проверка после сериализации ловила только «парсится ли», а подделанная
секция парсится нормально. Тот же корень касался имён групп и ключей `metadata.<key>`, а в
`users.conf` — подделки `[user:…]` с `password_hash` (обход аутентификации).

Закрыто тремя слоями: (1) `put_config` отклоняет имена профилей/групп/юзеров и metadata-ключи,
если они пустые, длиннее 128 байт, содержат управляющие символы или краевые пробелы
(`util::is_valid_ident`); (2) сериализатор вырезает управляющие символы из `kind`/`instance`/`key` —
fail-closed backstop для любого вызывающего, симметрично давней защите значений; (3) ре-парс стал
**семантическим**: текст читается обратно и hooks сверяются с восстановленными из файла, иначе
запись отклоняется. Правило имени намеренно **не** allowlist-charset — режется только структурно
опасное, поэтому `user@example.com` и не-ASCII имена остаются валидными. Эксплуатация требовала
аутентифицированного админа панели (CSRF включён), но обходила намеренный контроль → эскалация до
shell. ([config.rs](qeli/src/web/api/config.rs), [format.rs](qeli/src/config/format.rs),
[util.rs](qeli/src/util.rs))

### Исправлено — Windows/macOS: лог «IPv6 captured» врал, когда захват не удался

Захват IPv6 в туннель (`allow_ipv6_leak` по умолчанию OFF) делается набором необязательных команд, а
сообщение «IPv6 captured into tunnel (…)» писалось **безусловно** — даже если упали все пять
`netsh`/`route`. Конфликт маршрутов, нехватка прав или частичное выполнение давали утечку IPv6 мимо
туннеля, при том что лог утверждал обратное. Теперь результат каждой команды учитывается, и лог
говорит правду: полный захват, частичный (`N/5` с перечислением упавших диапазонов) или ни одного.
Соединение при этом **не рвётся**: на хосте с выключенным IPv6 команды падают штатно и утечки нет —
отказ был бы ложной тревогой, поэтому предупреждение честно разделяет эти случаи.
([NetworkConfigurator.cs](qeli-win/QeliWin/Vpn/NetworkConfigurator.cs),
[NetworkConfigurator.cs](qeli-mac/QeliMac/Vpn/NetworkConfigurator.cs))

### Исправлено — Windows/macOS: внешние сетевые команды могли зависнуть навсегда

`netsh`/`route`/`pfctl`/`powershell` запускались с `WaitForExit()` **без таймаута** и с
последовательным чтением stdout → stderr. Зависший дочерний процесс останавливал подключение,
отключение или снятие kill-switch без шансов на восстановление; вдобавок последовательное чтение
могло войти в классический pipe-дедлок, если процесс заполнит буфер stderr, пока родитель ждёт EOF
stdout. Оба потока теперь дренируются асинхронно, а ожидание ограничено (30 с для сетевых команд,
60 с для шагов kill-switch) с убийством дерева процессов по таймауту. Правильный паттерн уже был в
`ServiceManager.cs` — теперь применён и здесь.
([NetworkConfigurator.cs](qeli-win/QeliWin/Vpn/NetworkConfigurator.cs),
[KillSwitch.cs](qeli-win/QeliWin/Vpn/KillSwitch.cs),
[NetworkConfigurator.cs](qeli-mac/QeliMac/Vpn/NetworkConfigurator.cs))

### CI — общая крипта клиентов не проверялась вовсе; добавлены self-test'ы и все fuzz-таргеты

`qeli-shared/**` отсутствовал в `paths`, поэтому правка **общей крипты/протокола** (PacketCodec,
HKDF, ChaCha20-Poly1305, ObfsStream), на которую ссылаются оба desktop-клиента, не запускала CI
вообще — добавлен в триггеры. Headless-верб `selftest` у Windows/macOS существовал, но CI делал
только `dotnet build`; теперь self-test запускается (15 проверок: X25519, HKDF, ChaCha20-Poly1305,
PacketCodec с counter/replay, ObfsStream, разбор INI и `qeli://`). Вызывается через `dotnet exec` по
управляемой DLL: манифест `.exe` требует повышения прав, а самому тесту оно не нужно. Android
unit-тесты (`BackupCryptoTest`, `ObfsStreamTest`) тоже существовали, но не запускались — добавлен
`testDebugUnitTest`. Fuzz-смоук и nightly гоняли 3 таргета из 6 — добавлены `obfs_datagram`, `quic`,
`udp_frag`. ([ci.yml](.github/workflows/ci.yml))

### Безопасность/надёжность — панель: отказ вместо тихого «безлимита» и рассинхрона

Числовые лимиты (`limit_mbps`/`burst_mbps`/`max_sessions`, в т.ч. у групп) панель принимала как
`u64` и приводила к `u32` через голый `as` — значение `2^32` тихо становилось `0`, а `0` означает
**безлимит**, так что вместо ошибки лимит незаметно снимался; в update-потоке вдобавок воркеру
уходил необрезанный `u64`, а на диск писался усечённый `u32`. Теперь единый `u32_limit` отвергает
значения вне диапазона во всех точках, и воркеру уходит то же проверенное значение, что и на диск.
Отдельно: все CRUD-операции над пользователями/группами (создание, обновление, удаление,
enable/disable, bandwidth, апсерт/удаление группы и **сброс пароля** через share-ссылку) теперь
**снимают snapshot и откатывают** in-memory-состояние, если запись на диск не удалась — раньше
изменение оставалось в памяти супервизора, хотя API отвечал «change NOT applied», и память
расходилась с файлом (worker читает файл). ([users.rs](qeli/src/web/api/users.rs),
[share.rs](qeli/src/web/api/share.rs))

### Исправлено — клиент молча терял входящий трафик при сбое записи в TUN (Linux/router)

TCP- и UDP-writer'ы клиента отбрасывали результат `libc::write` в TUN. При фатальной ошибке fd
(устройство удалили/перезапустили) клиент продолжал получать и расшифровывать трафик, но выбрасывал
каждый пакет в мёртвый дескриптор, оставаясь снаружи «подключённым». Теперь оба writer'а повторяют
на `EINTR`, дропают с логом на `ENOBUFS`/`EAGAIN` (перегрузка очереди) и **останавливают поток** на
фатальном errno — как давно делает серверный writer. ([client/mod.rs](qeli/src/client/mod.rs))

### Исправлено — heartbeat: слабый jitter и переполнения (клиент + сервер)

Джиттер брался как `random_range(0..2*jitter) - jitter`, из-за чего >50% значений оказывались ровно
0 (среднее ≈ jitter/4) — куда более периодичный beat, чем задумано, а `jitter*2` мог переполниться в
пустой RNG-диапазон. Теперь задержка берётся напрямую и равномерно. `data_size_bytes + 32` (размер
cover-паддинга) переведён на `saturating_add` во всех точках. Плюс сервер валидирует диапазоны
heartbeat при загрузке профиля (включённый beat требует `interval_ms > 0`, `jitter_ms < interval_ms`,
`data_size_bytes ≤ u16::MAX-32`). ([client/mod.rs](qeli/src/client/mod.rs),
[handler.rs](qeli/src/server/handler.rs), [server/mod.rs](qeli/src/server/mod.rs))

### Безопасность — панель: reflected-XSS-примитив через `X-Forwarded-Prefix`

Заголовок `X-Forwarded-Prefix` подставлялся в `<base href="…">` без экранирования (шаблонизатора у
панели нет), а CSP разрешает `'unsafe-inline'` — значение с `"` могло закрыть атрибут и внедрить
скрипт. Теперь значение проходит allowlist символов пути и принимается **только от доверенного
прокси** (`web.trusted_proxies`), как соседние `X-Forwarded-For`/`-Proto`. Эксплуатация требовала
нестандартного прокси, лепящего заголовок из пути, но primitive закрыт. ([web/mod.rs](qeli/src/web/mod.rs))

### Исправлено — Android: split-tunnel мог молча развернуться в «весь трафик в VPN»

Если в режиме `include`/`exclude` не совпало ни одно приложение (импортированный профиль, удалённые
с момента настройки приложения), Android снимал per-app-ограничение и гнал в туннель **всё
устройство** — противоположно ожиданию, и молча (проверка гейтила только строку лога). Направление
безопасное (over-capture, данные не утекают), но теперь обе ветки при нулевом совпадении пишут явный
WARNING с причиной. ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))

### Сборка — Windows: убрано лишнее предупреждение NU1510

`System.Security.Cryptography.ProtectedData` есть в составе `net10.0-windows`, поэтому явная
`PackageReference` была избыточна (NU1510). Ссылка удалена, DPAPI-код (шифрование хранилища профилей)
не тронут — сборка QeliWin теперь без предупреждений. ([QeliWin.csproj](qeli-win/QeliWin/QeliWin.csproj))

### Исправлено — `pool.reservation.<user>` никогда не выдавался (сервер)

Профильная резервация IP молча не работала: юзер всегда получал динамический адрес. Причина —
самоблокировка в `IpPool::new`: зарезервированный адрес клался в `excluded` (чтобы его не выдали
динамически), а `allocate_fixed` отвергает **всё** из `excluded` → возвращал `None` → handler
откатывался на динамику с warn «static IP … is outside profile pool or excluded». Теперь резервации
живут в отдельном множестве `reserved`: динамическая выдача их по-прежнему пропускает, но
`allocate_fixed` может назначить адрес владельцу. Жёсткие исключения (сеть/broadcast/шлюз/
`pool.exclude`) отвергаются как раньше. Per-user `static_ip` багом не затронут (в `excluded` не
попадал). Регрессионные тесты — [pool.rs](qeli/src/server/pool.rs).

Плюс диагностика вместо тишины (аудит): на старте сервер теперь логирует невалидный адрес в
`pool.exclude` и невалидную / вне-диапазона / excluded / **дублирующуюся** `pool.reservation.<user>`
(дубликат раньше не всплывал **нигде** — два юзера вечно отбирали адрес друг у друга через
`allocate_fixed`). А панель ([users.rs](qeli/src/web/api/users.rs)) отклоняет назначение одного
`static_ip` двум пользователям при создании и обновлении — источник того же eviction-цикла.

### Добавлено — все клиенты логируют КАЖДОЕ пуш-событие с сервера

Раньше по логам было невозможно отличить «сервер ничего не прислал» от «клиент это выбросил» —
снаружи оба случая выглядят одинаково (настройки нет и ни одной строки). Теперь сразу после
`Auth OK` каждый клиент печатает сводку пуша и по каждому пункту — применено или нет, **с
причиной и указанием, какой ключ это чинит**:

```
server push: ip=10.68.0.2/24 gw=10.68.0.1 mtu=1400 dns=10.68.0.1:53 routes=2 obf=yes streams=1
server push: mtu 1400 APPLIED (client mtu = 0/auto)
server push: DNS 10.68.0.1 IGNORED — this client has dns = off … Set dns = tunnel to apply the pushed resolver.
server push: 2 route(s) received — see the 'Pushed route applied' lines below
server push: obfuscation APPLIED (padding=true, heartbeat=true, normalization=false, shaping=false)
```

**Каждый маршрут логируется целиком — как он прилетел** (`pushed route received: 10.15.0.0/24
gateway=192.168.5.3 metric=100`), а затем что с ним стало. Раньше писался только CIDR, и было не
видно ни шлюза, ни метрики. Отдельно: если Linux/CLI-клиент не смог поставить маршрут, warn теперь
называет **шлюз** и подсказывает фикс — типовая причина `Error: Nexthop has invalid gateway`, когда
`gateway=` указывает на адрес вне подсети туннеля. NB: Android/Windows/macOS маршрутизируют
**по интерфейсу** (VpnService.Builder / `CreateIpForwardEntry2` / `route -interface`), поэтому
пушнутые next-hop и метрику применить физически не могут — их лог теперь честно об этом говорит
(трафик всё равно уходит в туннель, и сервер его форвардит).

Покрыты MTU, DNS, маршруты, obfuscation-параметры и multipath; пустой пуш тоже логируется с
подсказкой («no DNS sent — на сервере задайте `dns.push_servers` или `dns.enabled` + `dns.listen`»;
«no routes sent — у профиля нет валидного `route = <cidr> …`, либо перекрыто персональными»).
Реализовано на всех четырёх клиентах, оба транспорта (TCP и UDP):
[client/mod.rs](qeli/src/client/mod.rs) (`log_server_push`),
[VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs) (`LogServerPush`, покрывает Windows+macOS),
[QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt) (`logServerPush`).

### Исправлено — пуш маршрутов не доезжал до клиентов (сервер + ВСЕ клиенты + панель)

Серверный `route = …` не появлялся в таблице маршрутизации **ни на одном** клиенте. Две
независимые молчаливые причины, обе закрыты:

- **Клиенты игнорировали пуш-маршруты, если не включён `route_local`** (дефолт `false`) — выход
  происходил ДО применения, без единой строки лога. Теперь **раздаваемые сервером подсети
  применяются ВСЕГДА** (это конкретные CIDR, заданные админом — семантика OpenVPN `push "route …"`;
  каждое значение по-прежнему валидируется перед `ip`). За `route_local` осталось только «одеяло»
  RFC1918 (10/8, 172.16/12, 192.168/16), которое по умолчанию выключено, чтобы не угонять
  собственную LAN клиента. ([client/route.rs](qeli/src/client/route.rs),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt),
  [win/VpnTunnel.cs](qeli-win/QeliWin/Vpn/VpnTunnel.cs), [mac/VpnTunnel.cs](qeli-mac/QeliMac/Vpn/VpnTunnel.cs))
- **Битая строка маршрута молча пушилась мусором.** `parse_route` не валидировал CIDR и никогда не
  падал: если CIDR пуст (классика — подсеть вписана в `gateway=`, а панель при пустом поле CIDR
  сериализует ровно `route = " gateway=… metric=…"`), клиенту уезжало `{"cidr":""}`. Теперь такая
  строка **отвергается при загрузке с внятным warn** (с указанием верного формата), а панель/API
  **отказываются сохранять** маршрут с пустым/битым CIDR или с подсетью в `gateway` — и для
  профильных `route`, и для персональных маршрутов юзера (раньше пустой CIDR там молча выбрасывался).
  ([server_ini.rs](qeli/src/config/server_ini.rs), [web/api/config.rs](qeli/src/web/api/config.rs),
  [web/api/users.rs](qeli/src/web/api/users.rs), валидаторы — [util.rs](qeli/src/util.rs))

Формат (напоминание): `route = <cidr> [gateway=<next-hop-ip>] [metric=<n>]` — CIDR **первым**,
`gateway` — это **IP следующего хопа**, не подсеть. Тесты: `scripts/test_route_push.py` (матрица
6 случаев, лаба) и `scripts/test_route_push_docker.py`.

### Исправлено — multipath/бондинг рвался в full-tunnel (C# Win/macOS, #69)

- **`RunMultipathTunnelLoop` больше не ре-резолвит хостнейм сервера внутри петли.** В multipath/
  бондинг-режиме цикл повторно резолвил `config.ServerAddress` через DNS уже ПОСЛЕ того, как
  `SetupTun` в full-tunnel завернул дефолт-маршрут и DNS в туннель → lookup падал
  («No such host is known») и рвал всю бондинг-сессию. Теперь в петлю прокидывается уже
  отресолвленный `serverIp` из primary-соединения (bonded-стримы переиспользуют тот же IP).
  ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))

### Исправлено — UDP-хендшейк: одна потерянная датаграмма = простой на весь таймаут (C# Win/macOS, Android)

Клиенты на C# и Android отправляли ClientHello (а затем auth) **один раз** и уходили в
блокирующее ожидание на весь `connection_timeout_secs` (по умолчанию 30 с). Любая одна
потерянная датаграмма — обычное дело на lossy/CGNAT/мобильном пути и сразу после пробуждения
из сна — стопорила попытку на все 30 с, после чего внешний цикл начинал подключение заново.
В Rust-клиенте это давно исправлено (`hs_deadline` + `HS_RETRANSMIT_INTERVAL`), а десктоп и
Android этот фикс не получили.

Теперь **обе** ноги хендшейка (ClientHello→ServerHello и auth→AuthOK) ретрансмитятся с тиком
~1 с + джиттер 0-250 мс в пределах **одного общего** дедлайна `connection_timeout_secs` —
паритет с Rust. Потерянная датаграмма клиент→сервер восстанавливается за ~1-2 с вместо 30 с.
Пересылка безопасна: серверный reassembler дедуплицирует повторные фрагменты ClientHello,
continuation-фрагменты не тарифицируются лимитером новых сессий, а дубликат auth отсекается
replay-защитой. Внутренний auth-пакет шифруется один раз и пересылается байт-в-байт (иначе
счётчик кодека ушёл бы вперёд относительно того, что видел сервер). Обратное направление
(потерянный ServerHello/AuthOK) здесь не чинится — сервер не переотправляет их для уже
имеющейся сессии — и падает на дедлайне в реконнект с нового порта. TCP не затронут: там
ретрансмитит ядро.

- **C#** ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))
- **Android** ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))

### Исправлено — реконнект после пробуждения бил в ещё не поднятую сеть (Windows)

Хук `PowerModeChanged/Resume` дёргал `ForceReconnect` немедленно — пока Wi-Fi ещё
переассоциируется, а DHCP не отработал. Туннель при этом рвался, и следующий за ним
`NetworkAddressChanged` (когда адрес реально вернулся) уже ничего не чинил: `ForceReconnect`
выходит сразу, если установленного туннеля больше нет. Теперь резюме ждёт (в фоне, не на
UI-потоке) появления IPv4 на физическом интерфейсе и только потом рвёт; ограничение 15 с,
после него рвём всё равно. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs)
`ForceReconnectWhenNetworkReady`, [MainWindow.xaml.cs](qeli-win/QeliWin/MainWindow.xaml.cs))

## [0.7.11] — 2026-07-13

### Исправлено — клиент и сервер в одной локальной сети → реконнект-петля (Windows/macOS)

Когда клиент и сервер находятся в **одной подсети**, десктоп-клиент безусловно пинил
`/32`-маршрут на сервер **через физический шлюз** (чтобы несущий трафик не заворачивался в
туннель). Для on-link сервера это давало асимметричный путь (исходящие через шлюз, ответы —
напрямую): хендшейк проходил, но устойчивая data-плоскость рвалась → бесконечный реконнект.
Теперь клиент определяет, что сервер **on-link** (в подсети физического интерфейса), и **не
пинит** его через шлюз — connected-`/24` и так держит несущий трафик напрямую (и в split-, и в
full-tunnel: `/24` специфичнее `0.0.0.0/1`+`128.0.0.0/1`). Same-LAN теперь работает «из
коробки», без ручного `local = <IP>`.

- **Windows** (`NetworkConfigurator.IsServerOnLink` + гейт в `VpnTunnel.SetupTun`) — основной
  фикс: WinAPI `FindGatewayFor` всегда возвращал дефолт-шлюз интерфейса даже для on-link
  сервера, поэтому пин срабатывал всегда.
- **macOS** — уточнено ветвление: `route -n get` для on-link сервера не отдаёт `gateway:`
  (пин уже пропускался), теперь это распознаётся явно и логируется корректно (без вводящего в
  заблуждение `WARN could not determine gateway`).
- **Rust-клиент / Android** — не затронуты: Rust `default_gateway()` уже возвращает `None`
  для on-link (пин пропускается), Android использует `VpnService.protect()` (OS роутит сам).
- Задокументировано: TROUBLESHOOTING §6.8 + описание ключа `local` в CONFIG (RU/ENG).

### Изменено — отчёт по эксплуатации: DNS-дефолт, чистка конфига, быстрый Wintun

- **DNS 1.1.1.1/8.8.8.8 больше не подставляется в конфиг, который его не задавал.** Дефолт
  `DnsServers`/`dnsServers` был **непустым**, поэтому любой round-trip конфига дописывал
  `dns = 1.1.1.1, 8.8.8.8`, а серверный push-DNS (`dns.push_servers`) вообще не применялся
  (непустой дефолт его перекрывал). Теперь дефолт **пустой**, а публичный фолбэк перенесён в
  момент подключения: явный `dns` → серверный push (`session.DnsIp`) → 1.1.1.1/8.8.8.8 **только**
  на full-tunnel (split-tunnel системный резолвер не трогает). Конфиг без DNS теперь чистый,
  push-DNS работает. C# (Win/macOS) + Android; Rust-клиент не затронут (пишет `dns = <mode>`, не
  список). ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs),
  [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs) `EffectiveDns`,
  [Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt), QeliService)
- **Быстрое подключение на Windows: адаптер Wintun создаётся параллельно хендшейку.** Создание
  NDIS-адаптера ~10с шло **после** Auth OK серийно → холодный коннект занимал 11-17с. Теперь
  база стартует `PrewarmTun` в фоне на старте попытки (имя/GUID адаптера известны до аутентификации),
  а `SetupTun` забирает уже готовый адаптер. Реконнект и так быстр (persist-tun переиспользует).
  Непотреблённый префарм чистится в `CleanupPlatform`. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  [VpnTunnel.cs](qeli-win/QeliWin/Vpn/VpnTunnel.cs))
- **Серверный конфиг: не выводятся неиспользуемые для транспорта опции.** `to_ini_string` больше
  не засоряет UDP-профиль ключами `perf.tcp.*`/`obf.multipath.*`, а TCP-профиль — `obf.quic.*`,
  когда они на дефолте. Не-дефолтное значение по-прежнему пишется, поэтому round-trip-фиделити
  сохранена (гейт-тесты 36/36). ([server_ini.rs](qeli/src/config/server_ini.rs))

### Изменено — веб-панель: 3 кнопки действий вместо 4 + перевод

- **Кнопки конфига упрощены до 3** (было 4: Перезагрузить / Сохранить / Применить и
  перезапустить / Full restart — это путало). «Применить и перезапустить» теперь делает
  **полный** `systemctl restart` (закрывает и изменения сокета панели `web.bind/port/tls/enabled`,
  которые worker-рестарт не применял), а отдельная «Full restart» убрана. Сессия входа
  переживает рестарт при `web.persist_session_key` (дефолт). ([config.html](qeli/src/web/templates/config.html))
- **Допереведены строки панели** (справка/тултипы блока действий конфига — тексты про
  Save/Reload/Apply & Restart были на английском). ([i18n.js](qeli/src/web/assets/i18n.js))

### Безопасность — полный аудит 2026-07-11/12 (Rust-сервер, веб-панель, Android, C# Win/macOS)

Аудит всего кода 7 параллельными агентами по подсистемам, все находки проверены по коду и
на лабе (Rust: сборка + 288 тестов + clippy; C#: build + selftest; Android: unit-тесты).

#### Критично — RCE (веб-панель / INI)

- **RCE через client-manager закрыт.** `save_profile` (`web/api/client.rs`) писал raw-INI
  клиентского профиля дословно, не отсекая `routing.post_up`/`post_down` и
  `auth.password_command` — они выполняются как `sh -c` от root при `connect`, так что
  скомпрометированная/XSS/CSRF-панель получала root-RCE. Теперь `persist` семантически
  отклоняет профиль с любым hook'ом/командой (ловит и сырую строку, и newline-инъекцию).
- **Newline-инъекция в INI-сериализацию закрыта.** `config/format.rs` не нейтрализовал
  `\n`/`\r`, а `put_config` писал `to_ini_string()` без ре-парса — строковое поле со
  встроенным переводом строки подделывало секции `[profile]`/`[user:*]`/`[web]` и внедряло
  `routing.post_up` (обход server-guard) или `password_hash` (обход авторизации).
  Сериализатор теперь стрипает контрол-символы (backstop для всех путей), а `put_config`
  ре-парсит результат перед записью (fail-closed). ([format.rs](qeli/src/config/format.rs),
  [config.rs](qeli/src/web/api/config.rs))
- **`password_command` под guard доверия файла.** Клиент выполнял его через `sh -c` без
  `config_is_trusted` (в отличие от `post_up`/`post_down`) → RCE из group/world-writable
  конфига. Теперь под тем же guard. ([client/mod.rs](qeli/src/client/mod.rs))

#### Сервер / панель

- **Fail-closed при live-reload панели:** `reload_web_settings` больше не откроет публичную
  панель без пароля (через `put_config_raw` + reload) — повторяет стартовый guard.
- **Валидация путей ключей** в `put_config`/`put_config_raw`: `identity_key` / `web.tls_cert`
  / `web.tls_key` (анти-запись key-material в произвольный файл).
- **WS-обфускация:** единый таймаут pre-auth хендшейка (анти-slowloris); guard исчерпания
  ChaCha20-keystream (чистая io-ошибка → реконнект вместо panic=abort на 256 ГиБ).
- **CSRF:** cookie-less запросы (Basic-auth / API-клиенты) больше не блокируются
  same-origin-проверкой — они не являются CSRF-вектором.
- **DHCP:** saturating-арифметика rebinding-time + guard длины `domain_name`; **пул/CIDR:**
  `parse_cidr` отклоняет префикс >32 (анти-underflow); **бэкап панели:** tar исключает
  собственные restore-снапшоты (не раздувает архив → 413); `expire_at` предупреждает о
  нечитаемом значении; `client_manager.connect` без гонки (не плодит 2 процесса на профиль).

#### Стабильность (сервер)

- **UDP-сессии больше не текут, квота реально отключает.** reap и `usage_sweep` удаляли
  сессию из карты, но не звали `kick_all` → writer-таск и сессия парковались навсегда, а
  over-quota / expired TCP-клиент продолжал грузить бесконечно. Теперь оба пути рвут
  стрим-таски. ([mod.rs](qeli/src/server/mod.rs), [udp_handler.rs](qeli/src/server/udp_handler.rs))
- **iroute (#13): маршруты за клиентом не текут.** На supersede / static-steal / cap-evict /
  kick / quota / UDP-reap `client_routes` и kernel-маршруты раньше оставались; same-IP
  реконнект копил дубли и мог blackhole'ить подсеть. Введён инвариант: каждое удаление из
  `by_ip` чистит `client_routes`; `ip route del` — только в disconnect-путях (в auth-time
  только карта, чтобы spawned-del не гонялся с `ip route replace` новой сессии).
- **`ws_write` (fronting=websocket):** частичная запись возвращала `Pending` без регистрации
  waker → туннель вставал; переписан циклом дренажа.

#### Клиенты (C# Win/macOS, Android)

- **Win/macOS: смена профиля (подключение к другому серверу) больше не «залипает».** Туннель —
  единый объект с ОБЩИМИ полями транспортов/TUN/маршрутов, а `Stop()` ждал предыдущий таск лишь
  `Wait(3000)`. При смене старый teardown (join воркеров до 3с + восстановление маршрутов/DNS через
  `netsh`/`route` на Windows) мог пережить `Stop` и затем задиспозить УЖЕ поднятый новый туннель
  (диспоз нового `_tun`, закрытие новых сокетов, откат новых маршрутов). Теперь `Start`/`Stop`
  сериализованы на одном локе, `Stop` полностью дожидается предыдущей попытки (8с) перед
  переиспользованием полей, а switch в UI выполняется вне UI-потока (как edit-путь). Недавний
  `OnProfileSelected`-фикс (смена реально рестартит туннель) обнажил эту латентную гонку. Wintun-
  драйвер не затронут (адаптеры per-profile, Dispose корректен). ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  [MainWindow.xaml.cs](qeli-win/QeliWin/MainWindow.xaml.cs), [MainWindow.axaml.cs](qeli-mac/QeliMac/MainWindow.axaml.cs))
- **C# obfs-запись атомарна:** ChaCha20-transform и отправка под одним локом — при
  одновременных upload + heartbeat записи больше не рассинхронят keystream (разрыв туннеля).
- **C#:** `cancelWait` через `ct.Register` (не парковать threadpool-поток на реконнект);
  UDP-паддинг/cover не отключаются при `mtu=0` (авто-MTU → effective MTU); `kill_switch`
  читается/пишется в flat-INI (был fails-open); `dev` — алиас `dev_node`; `SessionToken`
  валидируется (кривой токен → single-stream, не reconnect-loop); win kill-switch экранирует
  `'` в PowerShell; offline PQ-KAT (`DeriveKeysHybrid`) в selftest.
- **Android:** статус-`BroadcastReceiver` `RECEIVER_NOT_EXPORTED` на всех API (был spoof
  «Connected» на API 26–32); boot-ресивер только `BOOT_COMPLETED` (убран незащищённый
  `QUICKBOOT_POWERON`); UDP-ping для quic+obfs корректно вкладывает оба слоя (ложное
  «unreachable» устранено); WS-reframer толерантен к opcode 0x0/0x2 (парити с Rust).
- **REALITY-профиль переживает save/reload:** `reality_sid` теперь сериализуется клиентом
  (был parse-only → REALITY гиб через панель/autostart). Панель: редактирование
  `client_subnets` юзера больше не теряется; `client.html` эмитит `dev` и гейтит `quic` по
  proto; RU-строки событий client-connect/disconnect.

### Добавлено — доработки из аудита

- **`allow_ipv6_leak` в C# (Win/macOS) и Android.** Opt-out захвата IPv6 в full-tunnel: по
  умолчанию IPv6 заворачивается в туннель и чёрно-дырится (сервер IPv4-only), а dual-stack
  пользователь может оставить нативный IPv6 (`allow_ipv6_leak = true`). Парити с Rust-клиентом
  (дефолт OFF, fail-closed). ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs),
  qeli-win/qeli-mac VpnTunnel, [Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))
- **iroute (#13) для UDP-профилей.** Раньше `client_subnets` регистрировались только на
  TCP-auth; на UDP-профиле фича была silent no-op. Регистрация вынесена в общий helper
  `register_client_subnets` и вызывается из обоих транспортов; inbound-диспетчер (route_lookup)
  уже общий. ([handler.rs](qeli/src/server/handler.rs), [udp_handler.rs](qeli/src/server/udp_handler.rs))
- **Passphrase-шифрованный бэкап профилей (Android).** Экспорт профилей был plaintext JSON с
  паролями/obfs_key. Теперь опциональная парольная фраза → PBKDF2-HMAC-SHA256 (210k итераций)
  + AES-256-GCM (аутентифицированный контейнер; неверный пароль отклоняется чисто по GCM-тегу).
  Импорт прозрачно понимает и plaintext, и зашифрованный бэкап.
  ([BackupCrypto.kt](qeli-android/app/src/main/kotlin/com/qeli/crypto/BackupCrypto.kt),
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt))

### Добавлено — параметр `exclude` / `include` для исключения подсетей (все клиенты)

- **Новые INI-ключи `exclude` и `include`** (список CIDR через запятую) во всех клиентах —
  Rust/CLI, Windows, macOS, Android. `exclude = 1.2.3.0/24, 10.20.0.0/16` вырезает конкретные
  подсети из туннеля (доступ напрямую), `include` — наоборот заворачивает подсети в туннель
  (split-tunnel). Раньше эти списки существовали только в JSON-конфиге и не читались из
  flat-INI / `qeli://` — теперь их можно задать в обычном конфиге профиля.
- **`exclude` теперь реально работает и под full-tunnel.** На десктопе/роутере (Rust, Windows,
  macOS) исключение раньше делалось «удалением маршрута», что под полным туннелем было **no-op**
  (подсеть всё равно ловилась `0.0.0.0/1`+`128.0.0.0/1`). Теперь для каждой исключённой подсети
  добавляется более специфичный маршрут **через физический шлюз** (тот же приём, что и для
  bypass-маршрута к серверу) — он выигрывает по longest-prefix, поэтому подсеть идёт мимо
  туннеля. При разрыве маршруты снимаются (undo на десктопе; `cleanup_routes` + del в Rust).
  На Android применяется штатным `VpnService.excludeRoute` (Android 13+). Значения валидируются
  как строгие CIDR перед подстановкой в route-команды (защита от инъекции аргументов).
  ([client.rs](qeli/src/config/client.rs), [route.rs](qeli/src/client/route.rs),
  [VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs), qeli-win/qeli-mac NetworkConfigurator+VpnTunnel,
  [Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt))

### Исправлено — пачка по репорту эксплуатации (desktop C# + сервер/панель)

- **C#: переключение профиля во время подключения ничего не делало + журнал не сбрасывался.**
  `OnProfileSelected` только менял доступность кнопки; теперь генуинный выбор другого профиля при
  живом туннеле рестартит туннель на нём и чистит лог (как из трея). Программные изменения выбора
  (старт/edit/import/delete/фильтр) обёрнуты guard'ом, чтобы не рестартить туннель случайно.
  Win + macOS. ([MainWindow.xaml.cs](qeli-win/QeliWin/MainWindow.xaml.cs), [MainWindow.axaml.cs](qeli-mac/QeliMac/MainWindow.axaml.cs))
- **C#/UDP: реконнект падал в цикле `Failed to parse ServerHello`.** На реконнекте с фиксированным
  локальным портом (`local`/`lport`) сервер ещё слал data-plane старой, не «kicked» сессии; эти
  записи (0x17) прилетали на новый хендшейк-сокет и принимались за ServerHello. Теперь перед
  ServerHello дренируются не-`0x16` записи (лимит 16 + таймаут сокета). На TCP это no-op.
  ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))
- **C#: при заданном `local` больше не добавляется лишний server-route.** Пиннинг server-route через
  авто-физический шлюз (`GetBestInterfaceEx`) противоречил bind'у на выбранный интерфейс и ломал
  обратный путь. При заданном `LocalAddress` пин пропускается — carrier идёт по маршрутизации
  выбранного интерфейса. Win + macOS. ([VpnTunnel.cs](qeli-win/QeliWin/Vpn/VpnTunnel.cs))
- **C#/UDP: сессия не простаивала во время долгого открытия TUN.** Открытие Wintun-адаптера может
  занимать секунды; в это окно туннельный цикл (шлющий keepalive) ещё не запущен, и UDP-NAT/сессия
  могли протухнуть → «no downlink >8s» → реконнект. Теперь во время `SetupTun` на UDP шлётся
  периодический keepalive. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))
- **Сервер/панель: SNI (и порт/режим) в сгенерированной ссылке применялись только после полного
  рестарта процесса.** «Apply & restart» рестартит лишь worker, а генерация ссылки читала
  замороженный `state.config` супервизора. Теперь `share_link` читает профили СВЕЖИМИ с диска (как
  CLI `add-client`), так что смена SNI отражается сразу после сохранения. ([share.rs](qeli/src/web/api/share.rs))
- **Панель: опция push-DNS.** В карточку DNS профиля добавлено поле «Push DNS to clients» (INI
  `dns.push_servers`) — независимо от локального DNS-прокси; пусто = ничего не пушим. ([config.html](qeli/src/web/templates/config.html))

### Добавлено — маршрутизация подсетей за клиентом (iroute, серверная часть, #13)

- **Сервер теперь может маршрутизировать ВХОДЯЩИЙ трафик на доп. адрес/подсеть, стоящую за
  клиентом**, а не только на его пуловый IP. Раньше форвардер матчил пакет строго по
  назначенному туннельному IP (`by_ip`), поэтому пакет на второй адрес клиента молча дропался
  (сервер→клиент не проходил, хотя клиент→сервер работал). Новое per-user поле
  **`client_subnet`** (список CIDR/IP) регистрирует эти адреса как inbound-маршруты в сессию
  клиента (longest-prefix-match после промаха `by_ip`) и программирует ядровой маршрут
  `ip route ... dev <tun>`; всё снимается при отключении. Аналог OpenVPN `iroute` (в отличие от
  `routes`/`advertised_routes`, которые ПУШатся клиенту). Guard'ы: отказ на default-route /
  подсеть, накрывающую туннельный шлюз, и на подсеть, уже занятую другим клиентом. Настраивается
  в панели (карточка юзера, «Client subnets») или в users-файле.
  ([users.rs](qeli/src/config/users.rs), [mod.rs](qeli/src/server/mod.rs), [handler.rs](qeli/src/server/handler.rs),
  server_ini.rs, web/api/users.rs, users.html)
- **`routing.forward_private` теперь реально работает — чистый L3-роутинг БЕЗ NAT.** Раньше это был
  мёртвый флаг; сервер поднимал `ip_forward` + `FORWARD ACCEPT` только внутри NAT-настройки
  (`routing.nat`), поэтому транзит между сетями без масскарадинга не проходил. Теперь при
  `forward_private=true` и выключенном NAT сервер включает `ip_forward` и разрешает форвардинг
  tun↔сети БЕЗ MASQUERADE (site-to-site: реальные source-IP сохраняются) + MSS-clamp. ([nat.rs](qeli/src/server/nat.rs))
- **Клиентский `forward` — форвардинг LAN за клиентом БЕЗ NAT** (Rust/OpenWrt + Windows + macOS).
  Новый флаг `routing.forward`: клиент, стоящий шлюзом для LAN, включает `ip_forward` + FORWARD
  ACCEPT (обе стороны, unrestricted — дальняя сторона может инициировать в LAN) + MSS-clamp, но
  БЕЗ MASQUERADE (в отличие от `gateway_nat`) — реальные адреса сохраняются. Rust: расширен
  `gateway::engage(masquerade)`; desktop: `net.inet.ip.forwarding=1` (macOS) / `netsh …
  forwarding=enabled` (Windows). Android: VpnService так не умеет (ключ игнорируется).
  ([gateway.rs](qeli/src/client/gateway.rs), [client.rs](qeli/src/config/client.rs),
  [VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs), qeli-win/qeli-mac VpnTunnel)

### Добавлено — несколько listener'ов на профиль (`listen`, #12)

- **Один профиль теперь доступен на нескольких портах/адресах** без клонирования. Новый
  повторяемый ключ `listen` (голый `addr:port` на ТОМ ЖЕ транспорте, что у профиля —
  `bind.transport`; per-listener транспорта нет, профиль = один транспорт). Все listener'ы делят
  одну TUN / пул / identity / юзеров: каждый поднимает свой accept-loop; кривая строка игнорируется
  (лог), занятый порт — «address already in use» (лог), остальные работают. Панель: профиль →
  «Extra listeners».
  ([server.rs](qeli/src/config/server.rs), [mod.rs](qeli/src/server/mod.rs), server_ini.rs, config.html)

### Изменено — панель прячет опции, нерелевантные транспорту профиля (#11)

- В форме конфига профиля блоки **QUIC** (UDP-only), **Stream bonding/multipath** (TCP) и
  **REALITY** (TCP) теперь скрываются по `bind.transport`, чтобы для UDP-профиля не маячили
  TCP-only опции и наоборот. ([config.html](qeli/src/web/templates/config.html))

### Добавлено — версия qeli в `systemctl status`

- Сервер публикует свою версию через `sd_notify STATUS=` — в `systemctl status` появляется строка
  **`Status: qeli vX.Y.Z — N profile(s), panel on/off`**, плюс версия пишется в журнал при старте.
  Тип юнита остаётся `Type=simple` (без READY-хендшейка); нужен `NotifyAccess=main` в юните (добавлен
  в `debian/qeli.service` и генератор `deploy-server.sh`; на кастомном юните — добавить строку вручную).
  ([mod.rs](qeli/src/server/mod.rs), [qeli.service](qeli/debian/qeli.service), scripts/deploy-server.sh)

### Добавлено — сессии панели переживают полный рестарт (`web.persist_session_key`, ON по умолчанию)

- Раньше ключ подписи сессии был **случайным per-process** (H-4) → любой полный рестарт супервизора
  разлогинивал админа. Теперь по умолчанию ключ **персистится в 0600-файл** (`$STATE_DIRECTORY/session.key`,
  иначе `/etc/qeli/.session_key`), так что логин в панель переживает `systemctl restart`. Компромисс:
  утечка конфиг-хеша + файла-ключа позволила бы подделать токен — но ключ в отдельном 0600-файле (не в
  конфиге/бэкапах), так что утечки одного конфига по-прежнему недостаточно. Отключается `web.persist_session_key = false`
  (тогда прежнее строгое поведение — сессии рвутся на каждом рестарте). ([auth.rs](qeli/src/web/auth.rs),
  [server.rs](qeli/src/config/server.rs), server_ini.rs)

### Добавлено — кнопка «Full restart» в панели + предупреждение о настройках, требующих полного рестарта

- **Панель умеет полный `systemctl restart`.** Кнопка «Full restart» (эндпоинт `POST /api/server/full-restart`)
  — для изменений сокета самой панели (`web.bind`/`port`/`tls`/`enabled`), которые worker-рестарт применить
  не может. Ответ отдаётся ДО рестарта, панель-JS переподключается; логин переживает (persist_session_key).
  Юнит определяется из cgroup (`qeli.service`, `qeli-server.service`, …). Права: root — напрямую; non-root
  `User=qeli` — через **polkit-правило `49-qeli.rules`** (в .deb; узко: только юзер `qeli` × только
  `qeli.service`). При отказе — просит выполнить `systemctl restart qeli` вручную.
- **`put_config` отдаёт `needs_full_restart`** (сравнивает новые web-socket поля с текущими); панель
  подсвечивает кнопку «Full restart» и пишет, что именно эта настройка требует полного рестарта — раньше
  было обобщённое «restart to apply». ([control.rs](qeli/src/web/api/control.rs), [config.rs](qeli/src/web/api/config.rs),
  [49-qeli.rules](qeli/debian/49-qeli.rules), config.html/layout.html)

### Зависимости, тулчейн и сборка

- **Обновлены Rust-зависимости (dependabot):**
  - `rand` **0.8 → 0.10** — мажорный бамп с миграцией API по всему коду (`thread_rng()`→`rng()`,
    `gen`/`gen_range`/`gen_bool`→`random`/`random_range`/`random_bool`, `RngCore`→`Rng`,
    `fill()`→`fill_bytes()`, `SliceRandom::choose`→`IndexedRandom`); тянет `rand_chacha` 0.3 → 0.10,
    убирает `ppv-lite86`/`zerocopy`.
  - `x25519-dalek` **2 → 3** (+ фичи `getrandom`, `zeroize`) — `StaticSecret` теперь `ZeroizeOnDrop`
    (убраны ручные `impl Drop`), `StaticSecret::random()` вместо `random_from_rng(OsRng)`; тянет
    `curve25519-dalek` 4 → 5, `fiat-crypto` 0.2 → 0.3.
  - `tikv-jemallocator` **0.6 → 0.7** (`tikv-jemalloc-sys` → jemalloc 5.3.1) — серверный аллокатор.
  - `bytes` 1.12.0 → 1.12.1 (патч).
  - **`aes-gcm` намеренно оставлен на 0.10** (bump до 0.11 даёт −20% throughput на reality-tls —
    известная регрессия, dependabot-PR отклонён).
- **Криптоядро и wire не изменились:** бампы `rand`/x25519 — переход API/семантики владения ключами,
  а не смена алгоритмов; гейт 288 тестов + KAT зелёные, реальный трафик совместим с 0.7.10.
- **FFI-ядра (libqeli .so/.dll/.dylib) пересобраны** из проаудированного исходника с `panic=unwind`
  (эффективный `catch_unwind` в realtls/ffi.rs), клиенты Android/Win/macOS пересобраны с ними.
- **CI/Docker (dependabot):** GitHub Actions в `docker-publish.yml` подняты —
  `docker/setup-buildx-action` v3→v4, `docker/metadata-action` v5→v6, `docker/build-push-action` v6→v7.

## [0.7.10] — 2026-07-10

### Исправлено — удаление/правка активного профиля не трогали живой туннель (Windows/macOS)

- **Удалил старый профиль, импортировал новый — а в логах клиент продолжал долбить IP
  старого сервера.** Reconnect-цикл живёт ВНУТРИ туннеля и был отвязан от списка профилей:
  `DeleteProfile`/`EditProfile` меняли только коллекцию и `ProfileStore`, но не трогали
  `_tunnel`. Поэтому если удалить (или отредактировать IP у) профиля, на котором туннель
  сейчас поднят/переподключается, его цикл переподключения продолжал стучаться на **старый,
  уже удалённый адрес сервера** — новый конфиг при этом ни при чём. Теперь GUI отслеживает
  активный профиль (`_activeProfile`, матчинг по стабильному `VpnConfig.Id`): удаление
  активного профиля сначала останавливает туннель, а правка активного профиля —
  перезапускает его на новом конфиге (сменённый IP вступает в силу сразу). В service/daemon-
  режиме туннелем владеет служба — там GUI в неё не вмешивается. ([MainWindow.xaml.cs](qeli-win/QeliWin/MainWindow.xaml.cs),
  [MainWindow.axaml.cs](qeli-mac/QeliMac/MainWindow.axaml.cs))

### Исправлено — быстрое восстановление после сна / смены сети (все клиенты)

- **После пробуждения из сна download мог висеть в 0 до ~минуты.** Причина: клиенты не
  замечали suspend/resume и продолжали слать в уже реапнутую сервером сессию (сервер
  демуксит UDP по адресу источника и реапит молчащего клиента за `max(3×heartbeat, 30s)`).
  Восстановление зависело только от RX-watchdog’а на **монотонных часах, которые во сне
  замирают** (macOS/Windows) → ему требовались ~45 секунд уже ПОСЛЕ пробуждения.
- **L1 — детект suspend/resume по расхождению часов:** на каждом тике сравниваем ход
  стенных часов с монотонными; большой скачок = хост спал → немедленный реконнект (сессия
  и NAT уже мертвы). Кросс-платформенно (и сон, и закрытие крышки).
- **L2 — детект «шлём вверх, но снизу тишина»:** активный upload при нулевом downlink
  дольше ~8с ⇒ мёртвая сессия. Не зависит от heartbeat/shaping (закрывает и краевой случай
  «оба выключены → watchdog’а не было вообще»), ловит смену сети без сна.
- **L3 — проактивные OS-хуки:** Windows — `PowerModeChanged(Resume)` +
  `NetworkAddressChanged`; macOS — `NetworkAddressChanged` (пробуждение покрыто L1);
  Android — сетевой callback уже был. Все зовут новый `VpnTunnelBase.ForceReconnect()`
  (дебаунс, держит TUN/kill-switch). Итог: восстановление ~минута → секунды.
  ([client/mod.rs](qeli/src/client/mod.rs), [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  qeli-win/qeli-mac MainWindow, [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))
- **Намеренное закрытие сокета при смене сети больше не логируется как ошибка.** `ForceReconnect`
  закрывает живые сокеты, чтобы data-плоскость сразу ошиблась и переподключилась на новую сеть;
  результирующая ошибка чтения (`recvfrom failed: EBADF (Bad file descriptor)` на Android, аналог
  на desktop) раньше писалась в лог как пугающий `ERR:`, хотя это ожидаемый сигнал. Теперь она
  гасится (флаг `forcedReconnectInFlight`/`_forcedReconnectInFlight`) — в логе остаётся только
  «… — reconnecting». Android + desktop C#. ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt),
  [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))

### Исправлено — редактор профиля терял «неформенные» поля при сохранении (Windows/macOS, #69)

- **Правка профиля в форме затирала поля, у которых нет контрола в форме.** `BuildFromForm`
  пересобирал `VpnConfig` с нуля из полей формы, поэтому при сохранении отбрасывались
  OpenVPN-опции (`local`/`lport`/`dev_node`/`metric`/`route_file`/`persist_tun`), а также `Id`
  профиля, kill-switch, AWG-джанк, настройки реконнекта и шейпинга — всё, что задаётся только
  через «Ручное редактирование» (INI) или импорт. Теперь редактор берёт за основу исходный
  (или последний вручную-распарсенный) конфиг и переопределяет **только** поля формы
  (`VpnConfig.WithEditorFields`); остальное сохраняется без потерь. Плюс «Ручное редактирование»
  теперь отражает в форму ВСЕ её поля (MTU/DNS/routing/padding/heartbeat раньше не отражались →
  ручная правка этих полей терялась при Save). Rust- и Android-клиенты неизвестные INI-ключи
  и так игнорируют (generic-KV / «ignore unknown params»), так что кросс-клиентского чтения это
  не ломает. ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs),
  qeli-win/qeli-mac ConfigEditorWindow)

### Изменено — «Подключено» (зелёный) только после поднятия TUN (все клиенты, #69)

- Клиенты сообщали статус **Connected сразу после Auth OK**, ДО фактического поднятия
  TUN-интерфейса. Индикатор загорался зелёным, пока ещё шёл `SetupTun` (на Windows открытие
  Wintun-адаптера занимает до ~10 с) или пока установка вовсе не падала — UI показывал
  «подключено» без рабочего туннеля. Теперь статус остаётся **Connecting (жёлтый)** до успешного
  `SetupTun`/`establish()`. На Android это заодно закрывает краевой случай реконнект-шторма #69:
  преждевременный CONNECTED сбрасывал backoff, поэтому падение установки TUN уводило клиент в
  плотный цикл переподключений (→ бан хостинга); теперь такое падение считается «до-установочным»
  и корректно наращивает задержку. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))

### Добавлено — Android: плитка быстрых настроек (подключение в один тап)

- **QS-плитка `Qeli VPN`.** Один тап из шторки быстрых настроек подключает **дефолтный
  (активный) профиль** / отключает — без открытия приложения. Состояние плитки зеркалит статус
  туннеля (пока шторка открыта — вживую, через приёмник `BROADCAST_STATUS`). Если требуется
  системное согласие VPN (`VpnService.prepare`), рантайм-разрешение на уведомления (Android 13+),
  дефолтный профиль не читается/пустой, или ОС отказывает в фоновом старте foreground-сервиса
  (Android 12+) — плитка открывает приложение с запросом на подключение (оно владеет этими
  флоу), иначе стартует сервис напрямую. Общий `ProfileStore` — единый источник зашифрованного
  хранилища профилей для приложения и плитки.
  ([QeliTileService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliTileService.kt),
  [ProfileStore.kt](qeli-android/app/src/main/kotlin/com/qeli/ProfileStore.kt), MainActivity/AndroidManifest)

### Исправлено — FFI panic-safety: клиентские ядра собираются с panic=unwind

- C-ABI realtls (`protocol/realtls/ffi.rs`) оборачивает точки входа в `catch_unwind`, чтобы
  паника при разборе недоверенных байтов сервера/on-path возвращала ошибку, а не роняла
  host-приложение. Но ядра (`libqeli.so`/`.dll`/`.dylib`) собирались профилем `panic="abort"`,
  под которым `catch_unwind` **инертен** → паника парсера абортила весь GUI-клиент (JVM/.NET);
  баг невидим для `cargo test` (тесты всегда unwind). Ядра теперь собираются с
  `CARGO_PROFILE_RELEASE_PANIC=unwind` (серверный бинарь остаётся `abort`) и пересобраны
  (unwind-таблицы добавлены, экспорты `qeli_realtls_*` целы). ([Cargo.toml](qeli/Cargo.toml),
  scripts/build_android_so_11.py, scripts/build_native_libs_p4.py, [build_dylib.sh](qeli-mac/build_dylib.sh))

### Исправлено — UDP: `recvRecord` падал на датаграмме короче TLS-записи (Android + C#)

- `recvRecord` проверял `pos+5 > size` один раз, затем читал `buf[pos+4]`; датаграмма, чей
  QUIC-развёрнутый payload < 5 Б (мелкая/битая control-датаграмма; валидная qeli AEAD-запись
  ≥ ~43 Б), уводила индекс за конец → `ArrayIndexOutOfBounds` / `IndexOutOfRange` (length=4,
  index=4), срывая udp-quic туннель в реконнект-шторм (проявилось, когда клиент перестал глотать
  реальную ошибку). Теперь цикл `while` пропускает короткие датаграммы. (Android + C#)

### Добавлено — серверный статичный IP на пользователя + полные disconnect-уведомления

- **Статичный IP (вариант B — фикс-адрес юзера всегда побеждает):** `static_ip` был мёртвым
  полем — пул-аллокатор его не читал, юзер всегда получал динамику (`.2`/`.3`/…). Теперь при auth
  (TCP+UDP) сервер берёт фикс-адрес из ЖИВОЙ users-db (`static_ip`, иначе `pool.reservation.<user>`)
  и выдаёт через новый `Pool::allocate_fixed`, вытесняя текущего держателя; невалидный/вне пула/
  исключённый → динамика + warning. Такой юзер имеет по сути одну активную сессию, реконнект с
  нового IP сохраняет тот же tun-адрес. (`pool.rs` + тесты)
- **Disconnect-уведомления** (завершение opt-in алертов A3): `ClientDisconnect` теперь шлётся и на
  остальных путях teardown, а не только на чистом TCP-close.

### Изменено — дефолтные юзеры живут в отдельном `users_file`, не инлайн (#69)

- Example-конфиги (`server.conf`, `server-maxobf.conf`, `server-multiprofile.conf`,
  `server-reality.conf`) больше не несут инлайн `[user:*]` — только ссылку на `auth.users_file`
  (`qeli add-client` дописывает туда). Раньше `server.conf` вёз И инлайн-юзера, И `users_file`, что
  триггерило warning «оба заданы → users_file игнорируется» и молча игнорировало файл (та же ловушка
  била Docker). Упаковка выровнена: `deb postinst` и Docker-entrypoint создают ПУСТОЙ
  `/etc/qeli/users.conf` вместо seed демо-юзера с известным хешем.

### Добавлено — Docker: встроенные диагностические инструменты в образе

- Slim-runtime имел только iproute2/iptables/ping — диагностика в контейнере требовала каждый раз
  `apt-install`. Добавлены traceroute + mtr-tiny + tcpdump + curl (доступность/провод), dnsutils
  (dig/host/nslookup), net-tools (netstat) + procps (ps/top/free/vmstat), nano + less. Проверено на
  `debian:bookworm-slim`.

### Исправлено — смена сети больше не вызывает реконнект-шторм (Windows/macOS)

- L3-хук `NetworkAddressChanged` реагировал в т.ч. на поднятие **собственного** TUN-адаптера
  (`Qeli-*`/`utun`), из-за чего само подключение зацикливалось: TUN встал → «сеть изменилась» →
  реконнект → TUN встал → … Теперь реконнект по сети только при реальной смене **физической** сети
  (сигнатура IPv4-адресов не-туннельных интерфейсов; наш адаптер / loopback / tunnel исключены) —
  как это уже делает Android через `NOT_VPN`-фильтр. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs), MainWindow win/mac)

### Добавлено — настраиваемый авто-опрос доступности профилей + ручная проверка (Windows/macOS)

- Проба доступности («точки») теперь управляема: галка **«Опрашивать профили автоматически»** +
  поле **интервала** в настройках. При выключенном авто есть **ручная проверка** — кнопка ⟳ в шапке
  (проверить все) и **клик по точке** профиля (проверить один). При активном туннеле проба
  пропускается; авто-обходы **дебаунснуты (≤1 в 15с)**, чтобы не забивать серверный per-IP лимит
  новых сессий (иначе пробы резались rate-limit'ом → точки ложно краснели, а реальный коннект
  проходил «с 4-5 раза»). Плюс фикс: при выключенном авто коннект больше **не гасит все точки в
  серый** — результат ручной проверки сохраняется. ([SettingsWindow.xaml](qeli-win/QeliWin/SettingsWindow.xaml),
  MainWindow win/mac, AppSettings, Loc.cs)

### Добавлено — Android: поделиться профилем (`qeli://` ссылка + QR)

- Действия профиля собраны в **меню ⋮** в строке (Поделиться / Редактировать / Удалить) вместо трёх
  кнопок; в освободившемся месте у индикатора доступности показывается **время отклика (мс)**.
- **Поделиться** → диалог с **QR-кодом** и `qeli://`-ссылкой; кнопки **Copy** (в буфер) и **Share**
  (системный share-sheet, `ACTION_SEND`). Android раньше умел только импортировать `qeli://`
  (скан/вставка) — теперь и **генерирует** (новый `VpnConfig.toQeliUri`, зеркалит C#/Rust-формат,
  так что ссылка/QR импортятся на любом qeli-клиенте и совпадают с серверным `/api/share`).
  ([Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt),
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt), item_profile.xml)

### Добавлено — Android: пакет улучшений клиента (9 фич)

- **Раздельный туннель по приложениям (per-app split tunnel).** В меню ⋮ профиля появился пункт
  **«Apps through the VPN»**: режим `all` (по умолчанию — весь трафик в туннель), `include`
  (в туннель ТОЛЬКО выбранные приложения) или `exclude` (все, КРОМЕ выбранных) + чек-лист
  установленных приложений. Выбор хранится в INI профиля (`apps_mode` + `apps`), поэтому
  переносится с бэкапом/шарингом и применяется на `establish()` через
  `addAllowedApplication`/`addDisallowedApplication`. Неустановленные пакеты пропускаются,
  собственный пакет никогда не включается (его туннельный сокет `protect()`-ится). Rust/desktop
  игнорируют эти ключи. ([Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt),
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))
- **Импорт по deep-link `qeli://`.** Тап по расшаренной `qeli://`-ссылке (из мессенджера/браузера)
  открывает приложение и предлагает импортировать профиль (intent-filter `scheme="qeli"` +
  `onNewIntent`, диалог подтверждения). Пара к функции «Поделиться». (AndroidManifest.xml,
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt))
- **Кнопка «Disconnect» в уведомлении.** На постоянном уведомлении foreground-сервиса появилось
  действие отключения (`ACTION_DISCONNECT`, `PendingIntent`). ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))
- **Дублирование профиля** — пункт **«Duplicate»** в меню ⋮ (копия сразу под оригиналом, имя + « (copy)»).
- **Экран настроек** (шестерёнка в шапке): автоподключение при запуске приложения, автоподключение
  при загрузке устройства, резервное копирование/восстановление профилей.
- **Автоподключение при загрузке устройства.** Опциональный `BootReceiver` (`BOOT_COMPLETED`):
  при включённой галке и уже выданном системном согласии на VPN активный профиль поднимается
  после ребута. ([BootReceiver.kt](qeli-android/app/src/main/kotlin/com/qeli/BootReceiver.kt))
- **Бэкап/восстановление всех профилей** через Storage Access Framework (обычный JSON-файл, место
  выбирает пользователь). Внимание: файл несёт пароли открытым текстом — тот же компромисс, что у
  экспорта конфигов WireGuard. ([MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt))
- **Переупорядочивание профилей** — пункты **«Move up» / «Move down»** в меню ⋮ (активный выбор
  остаётся на той же записи).
- **Виджет на рабочий стол** — подключение/отключение активного профиля в один тап (как плитка
  быстрых настроек); статус синхронизируется по package-scoped broadcast сервиса.
  ([QeliWidgetProvider.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliWidgetProvider.kt),
  widget_qeli.xml, qeli_widget_info.xml)
- **Доступ к локальной сети на full-tunnel («Allow local network access»).** Раньше при полном
  туннеле трафик к устройствам домашней Wi-Fi-сети (принтер, NAS, Chromecast, веб-морда роутера)
  уходил в туннель, и до них приходилось дотягиваться, отключая VPN. Новый переключатель в
  Настройках (+ per-profile INI-ключ `allow_lan`) вырезает приватные подсети из туннеля: на
  Android 13+ через `excludeRoute` для RFC1918 + link-local + local-multicast /24 (mDNS/SSDP —
  чтобы работал discovery AirPlay/Chromecast), на более старых — через route-split (маршруты-
  дополнение к 0.0.0.0/0 без RFC1918). Свой /24 туннеля остаётся более специфичным connected-
  маршрутом, поэтому исключение 10/8 не рвёт шлюз туннеля. Включение/выключение на живом туннеле
  делает авто-reconnect (маршруты фиксируются на `establish()`).
  ([Config.kt](qeli-android/app/src/main/kotlin/com/qeli/model/Config.kt),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt),
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt))
- **Фикс поверх per-app split:** в списке приложений не хватало половины установленных. Две
  причины: (1) фильтр видимости пакетов Android 11+ (API 30) — `queryIntentActivities` без
  спец-разрешения возвращает лишь «видимый» набор → добавлено `QUERY_ALL_PACKAGES` (сборка
  сайдлоуженная, не из Play → политика неприменима); (2) `getInstalledPackages(GET_PERMISSIONS)`
  паковал массивы разрешений ВСЕХ приложений в один Binder-ответ и на устройствах с большим
  числом приложений упирался в лимит транзакции (~1 МБ), из-за чего список **молча обрезался**
  (пропадал, например, Firefox). Теперь перечисление лёгкое — `getInstalledApplications(0)` +
  per-package `checkPermission(INTERNET)` (INTERNET — install-time разрешение, granted ⇔
  объявлено), набор осмысленный для split-tunnel (как в WireGuard).
  ([AndroidManifest.xml](qeli-android/app/src/main/AndroidManifest.xml),
  [MainActivity.kt](qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt))

## [0.7.9] — 2026-07-07

### Исправлено — сервер (репорт #69, fake-quic)

- **Сервер молчал на udp-quic, если у профиля не включён `quic.enabled`.** Клиент в режиме
  `udp-quic` заворачивает каждую датаграмму в QUIC-заголовок, но сервер разворачивал QUIC
  **только** когда его собственный профиль имел `obfuscation.quic.enabled = true` (по умолчанию
  выключено). При несовпадении QUIC-Initial принимался за «сырой» ClientHello, не парсился и
  **молча отбрасывался** — клиент не получал ответа. Теперь сервер **определяет QUIC по сигнатуре
  первого пакета** (long-header + версия QUIC v1 — однозначно против сырого `0x16`-ClientHello и
  фрагмента `F0 9B 71`) и **зеркалит выбор клиента для всего соединения** (как уже делает для
  фрагментации). udp-quic-клиент теперь работает независимо от флага профиля; `quic.enabled`
  влияет только на то, что сервер сам проставляет `quic=1` в генерируемых ссылках. Сессия хранит
  своё `quic_enabled`, так что auth-ответ и data-плоскость заворачиваются корректно.
  ([udp_handler.rs](qeli/src/server/udp_handler.rs), [quic.rs](qeli/src/protocol/quic.rs))
- **Отладочные логи на точках отбрасывания UDP-пакета** (по просьбе из #69): неудачный
  QUIC-разворот, отсутствие handshake-permit; в `UDP handshake started` добавлена пометка
  `QUIC-masked`. Уровень `debug` — включаются через `RUST_LOG=qeli=debug`.

### Исправлено — клиенты (репорт #69, udp-quic data-plane)

- **udp-quic: авторизация проходит, но туннель сразу рвётся в цикле (Android + desktop C#).**
  После успешного path-MTU-зонда клиент оставлял на сокете DF (Don't-Fragment), а серверные
  push-паддинги (40–400 Б) раздували каждый data-пакет за probed-MTU → `sendto` падал с
  EMSGSIZE, и любая ошибка отправки трактовалась как **фатальная** → туннель рвался → реконнект
  (в логе вводящее в заблуждение «Connection closed cleanly»). ФИКС (как в рабочем Rust-клиенте):
  (1) паддинг **обрезается под MTU** per-packet (`PacketCodec.encryptCapped`/`EncryptCapped`),
  (2) на UDP ошибка отправки data/cover-пакета **дропает датаграмму, а не рвёт туннель** (как
  естественная UDP-потеря; мёртвая связь ловится RX-таймаутом), (3) Android перестал глотать
  реальную причину обрыва — теперь она пишется в лог, а не «closed cleanly».
  ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt),
  [packet.rs](qeli/src/protocol/packet.rs),
  [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  [PacketCodec.cs](qeli-shared/QeliShared/Protocol/PacketCodec.cs))
- **udp-quic: `ArrayIndexOutOfBoundsException: length=4; index=4` в tunnel loop (Android + C#).**
  Вскрылось после фикса выше (реальная ошибка перестала глотаться): `recvRecord` в UDP-транспорте
  проверял `pos+5 > buf.size` **один раз**, а потом читал `buf[pos+4]` — если датаграмма после
  QUIC-разворота короче 5 байт (шальная/крошечная/битая суб-рекордная датаграмма; валидная qeli-запись
  ≥ ~43 Б, так что это никогда не данные), доступ вылетал за границу и рвал туннель в реконнект-шторм.
  Фикс: `while (pos+5 > buf.size) fill()` — короткие датаграммы **пропускаются**, а не индексируются
  за концом. ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt),
  [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))

### Изменено — пользователи по умолчанию в отдельном файле (репорт #69)

- **Единый подход: юзеры хранятся в `auth.users_file`, не инлайн.** Примеры конфигов
  (`server.conf`, `server-maxobf.conf`, `server-multiprofile.conf`, `reality-tls/server-reality.conf`)
  больше не содержат инлайн-`[user:*]` — только ссылку на `users_file` (`qeli add-client` дописывает
  туда). Раньше `server.conf` вёз **оба** источника (инлайн + `users_file`) → предупреждение
  `both inline [user:*] blocks and an explicit auth.users_file are set … users_file is ignored`
  и молчаливое игнорирование файла (та же ловушка ловила Docker-контейнер, который сидировал
  `server.conf` с инлайн-юзером). Установщики/пакет приведены к файлу: deb-`postinst` и Docker-
  `entrypoint` создают **пустой** `/etc/qeli/users.conf` (не сидируют `users.conf.example` — в нём
  демо-юзер с известным хешем), Docker кладёт `users.conf.example` для справки. `install-qeli-server.sh`
  уже использовал этот путь.
- **Сериализатор больше не пишет оба источника.** `ServerConfig::to_ini_string` (сохранение конфига
  через веб-панель) теперь эмитит `users_file` **XOR** инлайн-`[user:*]`, а не оба — так панель не
  воссоздаёт предупреждение при каждом сохранении. Панель и так управляет юзерами через файл
  (`users_db → users.save(users_file)`). ([server_ini.rs](qeli/src/config/server_ini.rs))

### Исправлено — сервер (статический IP пользователя не применялся)

- **Per-user `static_ip` был мёртвым полем — юзер всегда получал динамику (.2, .3, …).**
  Поле `static_ip` (задаётся `add-client`/панелью, лежит в `[user:*]`) писалось и
  показывалось, но аллокатор пула его никогда не читал: выдача IP (`Pool::allocate`)
  сверялась только с ОТДЕЛЬНЫМИ профильными резервациями `pool.reservation.<user>` — и те
  тоже не срабатывали для современных клиентов, потому что `allocate` звался с device_key
  (`username:hex(id)`), а резервации ключатся по имени. Теперь при авторизации (TCP и UDP)
  сервер резолвит фиксированный адрес из ЖИВОГО users-db (`static_ip`, иначе
  `pool.reservation.<user>`) и выдаёт его через новый `Pool::allocate_fixed`. **Семантика
  (вариант Б): статический адрес всегда побеждает** — новый коннект/устройство забирает его,
  вытесняя текущего держателя (другое устройство того же юзера, либо динамического юзера,
  занявшего адрес, пока владелец был офлайн). То есть у юзера со `static_ip` фактически одна
  активная сессия, и реконнект с нового исходного IP всегда попадает на тот же tun-адрес.
  Невалидный / вне пула / исключённый `static_ip` → фоллбэк на динамику + warning.
  ([pool.rs](qeli/src/server/pool.rs), [handler.rs](qeli/src/server/handler.rs),
  [udp_handler.rs](qeli/src/server/udp_handler.rs))

### Исправлено — сервер (репорт #69, эксплуатация)

- **Ctrl+C не работал, если воркер крэш-лупит (напр. порт занят).** `qeli server` (супервизор)
  перезапускает воркер данных с экспоненциальным backoff; сам `sleep` backoff'а был
  **непрерываемым**, и на крэш-луп-воркере (порт уже занят → воркер сразу выходит) супервизор
  всё время сидел в этом sleep, из-за чего SIGINT/SIGTERM не обрабатывались и приходилось
  `kill -9`. Теперь backoff-sleep прерывается по Ctrl+C / SIGTERM → чистая остановка.
  ([server/mod.rs](qeli/src/server/mod.rs))
- **«invalid config: missing field password_hash» при сохранении конфига/профиля через панель.**
  `UserEntry.password_hash` имел `#[serde(skip_serializing)]` **без** `#[serde(default)]` — поле
  вырезалось из ответа API, но при обратной десериализации было обязательным, поэтому круг-трип
  панели (GET конфиг → POST обратно) падал на первом inline-`[user:*]`. Добавлен `default`
  (как у `web.password_hash`/`password_enc`); реальный хеш по-прежнему восстанавливается с диска
  в `put_config`. ([users.rs](qeli/src/config/users.rs))

### Исправлено — клиенты (репорт #69, пост-0.7.8)

- **Сервер обрывал клиент FIN'ом каждые ~5 минут на idle-туннеле.** Сервер реапит сессию после
  `idle_timeout_secs` (по умолчанию **300с**) молчания **клиента→сервер**; хартбит сервера→клиент
  не считается. Клиентский keepalive слался только когда у сервера включён heartbeat — на профиле
  с выключенным heartbeat (но idle-timeout>0) клиент молчал и его вырубало каждые 5 минут. Теперь
  **все клиенты (Rust, Windows, macOS, Android) шлют keepalive всегда, пока туннель поднят**
  (интервал = heartbeat, фоллбэк 30с), независимо от флага heartbeat сервера; реконнект по
  «тишине сервера» по-прежнему только когда сервер обязан слать (heartbeat/шейпинг), чтобы не
  устроить шторм. TCP и UDP, одиночный и bonded-режимы.
- **Грациозное закрытие (FIN вместо RST).** Desktop-клиент (Win/macOS) при отключении делал
  `Socket.Close()` без `Shutdown` → abortive RST. Теперь `Shutdown(Both)`+`Close` = корректный FIN.
- **Windows: имя Wintun-адаптера уводило от коллизий.** Идентичность адаптера ключилась ТОЛЬКО по
  адресу сервера → два профиля на один адрес (два аккаунта / port-forwarding к разным серверам на
  одном хосте) дрались за один адаптер. Теперь ключ = `host:port` + стабильный `Id` профиля:
  разные профили → разные адаптеры, тот же профиль при реконнекте → тот же (нужно для persist-tun).
- **Жёлтый индикатор подключения.** Спиннер «Подключение/переподключение/TUN ещё не поднят» теперь
  **янтарный** (как в OpenVPN/TunSafe), а не синий акцент. Состояние держится до поднятия TUN.
  Windows + macOS (Android уже жёлтый).
- **Формат времени в логах → ISO 8601 UTC** (`2026-07-07T15:04:05Z`) во всех клиентах и в
  Rust-демоне — однозначно в любом часовом поясе.

### Добавлено — клиенты (OpenVPN-паритет, репорт #69; desktop Win/macOS)

- **`persist_tun`** — держать TUN-адаптер и маршруты поднятыми между реконнектами (до ручного
  отключения) вместо пересоздания на каждой попытке: нет мигания адаптера и разрыва маршрутов,
  fail-closed в окне реконнекта. При смене выданного IP — чистое пересоздание. По умолчанию выкл.
- **`local` / `lport`** — привязать несущий сокет к конкретному локальному адресу и/или исходному
  порту (выбор egress-интерфейса на multi-homed хосте / фиксированный порт для правил файрвола).
- **`dev_node`** — задать имя Wintun-адаптера вручную (Windows).
- **`metric`** — метрика TUN-интерфейса (Windows). Ставится для **IPv4 и IPv6** через типизированный
  WinAPI `SetIpInterfaceEntry` (по LUID адаптера, без `netsh`-строк/спавна; фолбэк на `netsh` для
  того семейства, где API отказал). Раньше метрика бралась только для IPv4 → IPv6-маршруты туннеля
  оставались с дефолтным приоритетом ОС (репорт #69). ([NetworkConfigurator.cs](qeli-win/QeliWin/Vpn/NetworkConfigurator.cs))
- **`route_file`** — подключаемые split-tunnel маршруты из файла со списком CIDR (по одному в
  строке, `#`/`;`-комментарии). Windows + macOS.
- **IPv6-задел:** Windows-клиент перешёл с IPv4-only `GetBestInterface` на `GetBestInterfaceEx`
  (SOCKADDR, dual-stack) + поиск шлюза по семейству адреса — фундамент под подключение к серверу
  по IPv6.

### Документация

- **Сверка покрытия фич 0.7.7–0.7.9.** Ранее выпущенные, но не задокументированные ключи/фичи
  добавлены в доки: `exclude_routes` и `allow_ipv6_leak` (клиентские routing-ключи), алиасы
  `mode = udp-quic`/`udp-obfs`, токены скрытия SNI (`!`/`~`/`@`) — в `CONFIG.md` (ru+eng) и
  примере `client.conf`; десктоп-ключи `persist_tun`/`local`/`lport`/`dev_node`/`metric`/`route_file`
  и AWG-junk на UDP — в `client.conf`; `dns.push_servers` — в `server.conf`. PANEL.md: авто-обновление
  вкладки Blocked IPs + `[web]`-ключи `session_ttl_secs`/`trusted_proxies` в форме конфига. Исправлена
  устаревшая ru-пометка, будто `[web] update_check` «нерабочий» (он парсится/сериализуется).

## [0.7.8] — 2026-07-07

Патч-релиз с фиксами поверх 0.7.7 (клиентские фиксы по репортам #69: реконнект-шторм,
IPv6-утечка, защита чужих интерфейсов/адаптеров) + скрытие SNI и алиасы `mode`. Сетево и по
конфигу совместимо с 0.7.7.

### Исправлено — клиенты (репорты #69, пост-0.7.7)
- **Реконнект-шторм → бан хостинга.** Локальный сбой `SetupTun` (напр. `WintunStartSession failed`)
  после успешной авторизации трактовался как «established drop» — backoff сбрасывался, клиент
  ре-авторизовывался вплотную 10+ раз, и анти-DDoS хостинга банил сервер. Теперь `_wasConnected`
  ставится **только после** поднятия TUN, так что локальный сбой уходит в экспоненциальный backoff.
  Windows + macOS. ([VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs))
- **IPv6-утечка в full-tunnel.** `::/1 + 8000::/1` перебивали только `::/0`, но проигрывали более
  специфичному RA-маршруту `2000::/3` (GUA) по longest-prefix — глобальный IPv6 утекал мимо туннеля,
  хотя лог писал «no dual-stack leak». Добавлены `2000::/4 + 3000::/4 + fc00::/7` (как у OpenVPN
  redirect-gateway), лог исправлен. Windows + macOS.
  ([NetworkConfigurator.cs](qeli-win/QeliWin/Vpn/NetworkConfigurator.cs))
- **Клиент больше не «уводит» чужой сетевой интерфейс.** Linux/Rust-клиент при `dev=<имя>`, если
  интерфейс уже существует, раньше **удалял и пересоздавал** его — мог снести чужой (напр. OpenVPN).
  Теперь при существующем имени клиент **отказывается** стартовать с понятной ошибкой (наш tun
  не переживает выход процесса → существующее имя = чужое/работающий qeli). Windows авто-именует
  адаптер (`Qeli-<hash>`) — коллизии с системой нет; macOS/Android именует ОС.
  ([client/mod.rs](qeli/src/client/mod.rs))
- **Windows: клиент больше не удаляет чужой Wintun-адаптер на «Отключить».** Раньше при сбое создания
  нашего адаптера клиент **усыновлял** существующий (`WintunOpenAdapter`), а на дисконнекте
  `WintunCloseAdapter` его **удалял** — под драйвер-свопом это мог оказаться адаптер OpenVPN (репорт
  #69). Теперь клиент **только создаёт** свой адаптер (при коллизии — свежее имя+GUID) и на teardown
  удаляет **только созданное им** (флаг `_created`). ([Wintun.cs](qeli-win/QeliWin/Vpn/Wintun.cs))

### Добавлено
- **Скрыть/убрать SNI в fake-tls/obfs.** Значения `sni`: `!` = не слать SNI-расширение (как браузер
  по голому IP), `~` = пустое расширение, `@` = пустой `server_name_list`. Для регионов, где
  закреплённый SNI триггерит блок, а хендшейк без SNI проходит. Реализовано в Rust-билдере
  (`tls.rs`, нативный путь) **и** в managed-фолбэках C#/Kotlin. Работает на **Rust/Linux и Android**
  (`.so` пересобран); **Windows/macOS требуют пересборки `qeli.dll`/`.dylib`** на релизе (нативный
  путь). reality/reality-tls не затронуты. ([tls.rs](qeli/src/protocol/tls.rs), TlsHandshake.cs/kt, CONFIG.md)
- **Алиас `mode = udp-quic` / `udp-obfs`.** Клиенты принимают эти значения как «транспорт+обфускация
  свёрнуты в mode» и разворачивают в `proto=udp` + wire-mode + (для quic) флаг QUIC — чтобы частая
  путаница в формате просто работала. ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs),
  [share.rs](qeli/src/config/share.rs))

### Известные ограничения
- **Windows: сосуществование с другим Wintun-VPN.** qeli несёт **Wintun 0.14.1** (актуальный, как у
  WireGuard/Tailscale/современного OpenVPN-Wintun), и Wintun штатно допускает несколько приложений
  одновременно — на **одной версии драйвера** они уживаются. Конфликт возникает, только если у
  другого приложения **старая** версия Wintun: единый kernel-драйвер версионно свопается при загрузке,
  и адаптеры старого приложения могут «пропасть». Наш адаптер уникален (`Qeli-<hash>`) + эфемерен, так
  что через API мы чужие не трогаем. Добавлен стартовый NOTE в лог, если уже загружен Wintun-драйвер
  другого приложения. Решение — держать оба на Wintun 0.14.x.

### Документация
- Уточнён скоуп `dev` (имя TUN-интерфейса): применяется только у Rust/Linux/router-клиента и
  панель-клиент-менеджера; десктоп C# (Windows/macOS) его игнорирует (Windows авто-`Qeli-<hash>`,
  macOS `utunN` от ядра). CONFIG.md ru+eng.

## [0.7.7] — 2026-07-05

Крупный **аудит безопасности и надёжности** (6 зон: протокол/упаковка пакетов, серверный
рантайм, крипто/конфиги, веб-панель, клиенты, инфраструктура) — ~26 фиксов. Закрыт
**критический баг разрыва туннеля под нагрузкой** (oversized-record). Тумблер **`web.csrf`**
и reverse-proxy **`web.base_path`**. Обновление крипто-зависимостей (**`chacha20poly1305` 0.11**;
`aes-gcm` намеренно оставлен на 0.10 — см. Зависимости) и тулчейнов. Новые **fuzz-цели** на парсеры. Дополнительно проверен **внешний аудит (v0.7.6)**:
большинство находок оказались ложными или уже закрытыми, реализован остаток валидных (мелкий
hardening ядра/панели, CI/packaging, docs). Проверено: `cargo test --workspace` зелёный на лабе
(включая новые тесты control-канала), нагрузочный стенд (GRO on, `iperf3 --bidir` — 0 разрывов),
полный CI (build/test/lint/fuzz-smoke/кросс-компиляция aarch64+mipsel/все платформы). Сетево и по
конфигу совместимо с 0.7.6.

### Добавлено
- **Активный path-MTU probing на UDP — `mtu = 0` теперь по-настоящему авто на всех режимах.**
  Раньше `mtu = 0` = «взять MTU, который пушит сервер» (по умолчанию 1400); на узком пути
  (LTE/CGNAT/PPPoE) это фрагментировало UDP-датаграммы. Теперь при `mtu = 0` клиент **перед
  поднятием туннеля** ставит DF и зондирует реальный path MTU probe-датаграммами от pushed-
  потолка вниз (сервер эхо-подтверждает — новые `MSG_MTU_PROBE`/`ACK` в UDP-фрейминге), и ставит
  наибольший размер, проходящий без фрагментации. **На TCP не влияет** (там path-MTU разруливает
  ядро: `tcp_mtu_probing` + MSS-clamp), при `mtu > 0` — ручной оверрайд. Тумблер-выключатель
  **`[qeli] mtu_probe`** (default true). Фейл-безопасно: любой промах (probe/ACK дропнут) →
  фоллбэк на pushed-MTU = прежнее поведение. Реализовано во **всех клиентах**: Rust (сервер-эхо +
  клиент, Linux), C# (Windows/macOS), Kotlin (Android — probe до `VpnService.establish()`, т.к. там
  MTU фиксируется при establish). Заодно унифицированы MTU-дефолты примеров (мультипрофиль/quickstart
  1280 → 1400 = задокументированный дефолт). Live-e2e (netns, Rust): широкий путь → MTU 1400, veth 1380
  → адаптация до 1280, kill-switch → фоллбэк, ping во всех.
  ([udp_frag.rs](qeli/src/protocol/udp_frag.rs), [client/mod.rs](qeli/src/client/mod.rs),
  [udp_handler.rs](qeli/src/server/udp_handler.rs), QeliShared, qeli-android)
- **Учёт трафика раздельно download/upload; лимит квоты — только по загрузке.** Страница
  пользователей теперь показывает две суммы отдельно: `↓` загрузка (сервер→клиент) и `↑`
  отдача (клиент→сервер), вместо одной суммы. **Лимит `data_limit_gb` считается только по
  загрузке** — отдача не лимитируется (пользователя нельзя заблокировать, отправляя данные);
  полоса и энфорсмент квоты смотрят на download. Sidecar `usage.json` расширен полями
  `used_down`/`used_up` (старый `used_bytes` = их сумма, для совместимости); при апгрейде
  исторический total мигрирует в download (доминирующее направление; энфорсмент эквивалентен).
  ([usage.rs](qeli/src/server/usage.rs), [handler.rs](qeli/src/server/handler.rs),
  [mod.rs](qeli/src/server/mod.rs), [web/api/usage.rs](qeli/src/web/api/usage.rs),
  users.html, PANEL.md)
- **Раздельная брутфорс-защита для панели и VPN — две независимые политики + журнала.**
  Раньше одна политика `[auth] brute_force` управляла и входом в веб-панель, и
  VPN-аутентификацией. Теперь у панели своя — **`[web] brute_force`** (свои `enabled` /
  `max_attempts` / `window_secs` / `lockout_secs`), а `[auth] brute_force` отвечает только за
  VPN. Каждую политику можно **полностью отключить** (`enabled = false`). Локауты ведутся как
  **два отдельных журнала**: неудачные входы в панель не трогают счётчики VPN и наоборот.
  Вкладка **Blocked IPs** показывает оба журнала и несёт живой редактор обеих политик (Save
  применяется без рестарта); дубли настроек — в Config → Authentication (VPN) и Config → Web
  UI (панель). Провод/конфиг совместимы: отсутствующий `[web] brute_force` берёт те же дефолты
  (5 / 300 / 900, вкл). ([config/server.rs](qeli/src/config/server.rs),
  [server_ini.rs](qeli/src/config/server_ini.rs), [mod.rs](qeli/src/server/mod.rs),
  [status.rs](qeli/src/web/api/status.rs), CONFIG.md/PANEL.md, config.html/blocked.html)
- **Вкладка Blocked IPs теперь автообновляется + живой обратный отсчёт.** Раньше список
  блокировок грузился один раз при открытии вкладки и не обновлялся. Локауты транзиентные
  (по умолчанию 300с), поэтому активную блокировку было легко не увидеть — таблица казалась
  пустой, хотя IP был заблокирован. Теперь вкладка **перезапрашивает сервер каждые 5с**
  (фоновый поллинг, без мигания спиннера) и **тикает «Unblock in» посекундно**, а истёкшие
  строки сами исчезают — активная блокировка видна в реальном времени. ([blocked.html](qeli/src/web/templates/blocked.html))
- **`web.base_path`** — панель можно отдавать под префиксом (`https://host/qeli/`), а не в
  корне домена. Ядро вкладывает роутер под префикс, вставляет `<base href>`, дописывает
  префикс к редиректам; учитывает `X-Forwarded-Prefix`. Пусто (default) = корень, как раньше.
- **`web.csrf`** (default `true`) — тумблер CSRF-защиты панели. `false` полностью отключает
  проверку Origin/Referer (со стартовым предупреждением) — допустимо только на loopback-bind.
- **Fuzz-цели** `udp_frag`, `quic`, `obfs_datagram` — фаззинг реассемблера UDP-фрагментов,
  QUIC-парсера и обфускации датаграмм (недоверенный вход); гоняются в nightly-CI.
- **AWG junk-маскировка теперь работает и на UDP — на ЛЮБОМ профиле (obfs / fake-tls / QUIC),
  не только на TCP obfs.** Клиент шлёт `jc` decoy-**датаграмм** перед ClientHello тем же
  маскирующим путём (obfs-XOR / QUIC-wrap, чтобы блендиться), а сервер дёшево дропает их по
  типу `MSG_JUNK` **до** rate-limiter, крипто и реассемблера. Отличие от TCP: на UDP `jc` —
  **только на стороне отправителя** (согласовывать не нужно; потерянная/переупорядоченная
  junk-датаграмма безвредна). Каждая junk-датаграмма ≤1200 Б, чтобы не IP-фрагментироваться на
  LTE/CGNAT. По умолчанию ВЫКЛ (`jc=0`) → провод байт-в-байт прежний. Реализовано во всех трёх
  клиентах (Rust / C# / Kotlin) + серверный дроп (Rust); мультипрофиль/CONFIG.md обновлены.
  Live-e2e на лабе: udp-obfs + udp-fake-tls+QUIC + baseline — **3/3 PASS** (Auth OK + ping).
  ([udp_frag.rs](qeli/src/protocol/udp_frag.rs), [udp_handler.rs](qeli/src/server/udp_handler.rs),
  [client/mod.rs](qeli/src/client/mod.rs), [UdpFrag.cs](qeli-shared/QeliShared/Protocol/UdpFrag.cs),
  [udp_frag.rs](qeli/src/protocol/udp_frag.rs))
- **`dns.push_servers`** (сервер) — раздать клиентам конкретный резолвер (первый IP из списка)
  **без** запуска встроенного DNS-прокси: например LAN / AdGuard / NextDNS-бокс. Пушится в
  auth-OK, клиент применяет в режиме `dns = tunnel` со строгой валидацией IP. Пусто = поведение
  как раньше (listen-IP прокси при `dns.enabled`, иначе ничего). ([config/server.rs](qeli/src/config/server.rs),
  [handler.rs](qeli/src/server/handler.rs))
- **Тумблер проверки доступности серверов** в клиентах (Windows/macOS, Настройки → «Проверять
  доступность серверов», по умолчанию ВКЛ). Выключение прекращает отправку PQ-ClientHello-пробы
  на все профили — для тех, кто не хочет светить характерным пробингом в DPI; точки статуса тогда
  показывают «неизвестно».
- **Клиентский `routing.allow_ipv6_leak`** (default `false`) — escape-hatch для kill-switch:
  по умолчанию на хосте с global IPv6, где нет `ip6tables`, kill-switch теперь ОТКАЗЫВАЕТСЯ
  подниматься (fail-closed, см. Безопасность), а `true` разрешает подключиться, приняв IPv6-утечку.
- **Панель: остальные `[web]`-настройки выведены в форму конфига** — `session_ttl_secs`,
  `base_path`, `csrf`, `trusted_proxies`, `update_check` теперь редактируются в UI (раньше только
  ручной правкой INI); backend их уже парсил и round-trip'ил. ([config.html](qeli/src/web/templates/config.html))
- **Панель: ручное имя TUN-устройства в форме клиентского профиля** (поле «TUN device») — раньше
  задавалось только в raw-INI. Пусто = панель авто-назначает свободное `vpnN` (не занятое другим
  профилем или live-устройством хоста). ([client.html](qeli/src/web/templates/client.html))

### Исправлено — надёжность
- **Критический разрыв туннеля под нагрузкой (oversized-record).** На line-rate ядро (GSO)
  склеивало супер-пакет, `encrypt_packet` эмитил запись > `MAX_RECORD_SIZE`, приёмник ловил
  `PacketTooLarge` и **фатально рвал сессию**. Теперь `encrypt_packet` возвращает ошибку ДО
  эмита (guard + защита от тихого `u16`-переполнения длины), а data-путь **дропает такой пакет
  вместо разрыва**. Плюс чтение записей вынесено в отдельную reader-задачу (cancellation-safe).
  Затрагивает все режимы (fake-tls/obfs/plain). Подтверждено нагрузочным стендом.
- **Утечка IP пула** при выселении устройства по лимиту сессий (session-cap): адрес теперь
  освобождается, иначе пул исчерпывался при ротации устройств.
- **UDP liveness-reaper** больше не сносит переподключившуюся сессию (реконнект с нового
  адреса) и не отзывает её IP — добавлен guard по `session_id`.
- **TUN/TAP writer** обрабатывает ошибки `write` (EINTR-retry, drop на ENOBUFS, стоп на
  fatal) вместо тихой потери пакетов и записи в мёртвый fd.
- **Неблокирующая** передача входящих пакетов в TUN-writer (`try_send`) — блокирующий `send`
  больше не паркует tokio-воркер при заполнении канала.
- **DHCP/DNS recv-циклы** не умирают на транзиентной ошибке `recv` (log+continue).
- **Accept-цикл**: backoff при `EMFILE`/исчерпании fd (нет 100%-CPU-спина).
- **Flush** счётчиков трафика перед signal-exit (не теряется последний интервал).
- Рассинхрон фрейминга отличается в логах от чистого обрыва (диагностика).
- **macOS-клиент: выбор профиля** больше не слетает после Edit/Duplicate — восстановление
  по стабильному `VpnConfig.Id`, а не по ссылке на объект (два аккаунта на одном сервере
  больше не путаются при фильтрации/правке).
- **Android-клиент:** `Config.parse()` понимает сырую `qeli://`-ссылку (паритет с C#) —
  раньше она уходила в INI-парсер и падала «missing [qeli] section».
- **Multipath/бондинг не рос под нагрузкой (download-blind).** Adaptive-рамп мерил только
  **исходящий** трафик (`total_tx` инкрементился лишь в writer), поэтому при обычном скачивании
  оставался на 1 потоке — бондинг «не влиял». Теперь проба считает **оба направления** (up+down),
  а плато-детектор даёт свежедобавленному потоку окно на заполнение (не кэпит на 2 потока). Плюс
  стартовое предупреждение при `obf.multipath.enabled` на UDP-профиле (там бондинг — no-op, сервер
  держит 1 поток). ([client/mod.rs](qeli/src/client/mod.rs), [server/mod.rs](qeli/src/server/mod.rs))
- **Windows: маршруты через WinAPI вместо `route.exe` на каждый префикс.** `AddRoute` теперь
  вызывает `CreateIpForwardEntry2` (iphlpapi) в процессе; большой split-tunnel лист (напр. 12k
  префиксов) больше не спавнит 12k процессов при старте (минуты → доли секунды). Fallback на
  `route.exe` при ошибке API; каждый туннель — свой адаптер, ограничения одного туннеля (как в
  OpenVPN 3) нет. ([NetworkConfigurator.cs](qeli-win/QeliWin/Vpn/NetworkConfigurator.cs))
- **Windows: несколько туннелей на одном хосте** больше не дерутся за один Wintun-адаптер — имя и
  GUID адаптера выводятся из адреса сервера (стабильны для того же туннеля, различны между разными).
  ([VpnTunnel.cs](qeli-win/QeliWin/Vpn/VpnTunnel.cs))
- **`ExcludeRoutes` (split-tunnel exclude) теперь ПРИМЕНЯЕТСЯ во всех клиентах.** Ключ парсился,
  но win/mac/Android его игнорировали; теперь win/mac снимают маршрут (`DeleteRoute`), Android —
  `excludeRoute` (Android 13+/API 33), паритет с Rust-клиентом.
- **macOS: выбранный профиль сохраняется между запусками** (`AppSettings.LastProfile`, restore
  по `VpnConfig.Id`) — раньше старт всегда сбрасывал выбор на первый профиль.
- **Android: гонка connect↔disconnect** — поля сессии (`supervisor`/scope/сокеты/tun) стали
  `@Volatile`: пишутся из main-потока в `startVpn()`, а читаются/закрываются фоновыми IO-корутинами
  (реконнект, network-callback), так что быстрый connect↔disconnect мог видеть устаревший сокет.
- **Мультипат: все фрагменты одной IP-датаграммы пиннятся в один поток.** `flow_hash` больше не
  хеширует «порты» у фрагментированного пакета (не-первый фрагмент их не несёт, а первый фрагмент с
  портами оторвался бы от своих продолжений) — иначе фрагменты расходились по разным потокам и
  приёмник видел переупорядочивание. Плюс гард на IHL<20. ([protocol/mod.rs](qeli/src/protocol/mod.rs))
- **Shaper (stealth-пейсинг): долг ограничен 1 секундой** (`-rate_bps`, симметрично положительной
  ёмкости и 1с-клампу sleep) — аномально большой write больше не уводит токен-бакет в глубокий минус
  и не стопорит отправку. ([shaper.rs](qeli/src/protocol/shaper.rs))
- **macOS: гард против повторного `Open()` utun-устройства** — второй `Open()` перезаписал бы `_fd`
  и утёк первый fd; теперь fail-loud вместо тихой утечки. ([UtunDevice.cs](qeli-mac/QeliMac/Vpn/UtunDevice.cs))
- **Панель (client-manager): коллизия TUN-устройства.** Авто-выбор устройства для исходящего
  туннеля сканировал только другие клиентские профили, но НЕ live-интерфейсы хоста — на сервере с
  профилем на `vpn0`/`vpn1` клиент получал то же имя и падал с «device busy». Теперь пропускает и
  всё, что уже есть в `/sys/class/net`. ([web/api/client.rs](qeli/src/web/api/client.rs))
- **Панель (client-manager): клиент не стартовал без папки лога.** `connect()` открывал
  `/var/log/qeli/client-<name>.log`, не создавая `/var/log/qeli` — на хосте, где сервер логирует в
  journald/stderr (папки нет), open падал и клиент вообще не запускался: ни туннеля, ни лога в
  панели. Теперь папка создаётся перед открытием. ([client_manager.rs](qeli/src/server/client_manager.rs))

### Безопасность
- **argon2-хеши больше не отдаются в JSON-API** — ни хеши пользователей (`/api/users`,
  `/api/config`), ни хеш админа (`web.password_hash`).
- **Утечки нативного REALITY-TLS хендла на клиентах** (Windows/macOS/Android) — сессия
  освобождается при single-stream teardown и при провале bonded-JOIN (росли на каждый реконнект).
- **macOS-клиент: валидация server-pushed CIDR** перед `route add` (`IsStrictIp`, паритет с
  Windows) — недоверенный addr-токен больше не splice-ится в командную строку.
- Явный лимит тела запроса (16 MiB) на API-роутере панели.
- Валидация имени пользователя (алфанум + `._-`, ≤64) при создании через панель.
- Верхний предел TTL сессии панели (30 дней) против «вечного» токена.
- Предупреждение при `/0` в `web.trusted_proxies` (иначе клиент может спуфить XFF).
- TOFU `known_hosts` создаётся сразу с правами `0600` (нет окна umask).
- Предупреждение о world-writable хук-скрипте (`post_up`/`post_down`).
- Предупреждение об утечке DNS при full-tunnel + `dns=off` на не-роутерном хосте.
- Диагностический лог имени юзера при коннекте теперь редактируется (`u***2`).
- **Изоляция клиентов (`routing.client_to_client`) теперь применяется.** Флаг раньше парсился, но
  в data-plane не проверялся — клиенты всегда могли достучаться друг до друга внутри подсети
  туннеля. Теперь при `false` (по умолчанию) пакет с source-IP одного клиента на IP другого
  дропается; интернет-трафик (внешний source) не затронут. ([server/mod.rs](qeli/src/server/mod.rs))
- **Kill-switch fail-closed на незащищённом IPv6.** Если у хоста есть global IPv6
  (`/proc/net/if_inet6`), а `ip6tables` недоступен, kill-switch раньше рапортовал ENGAGED, оставляя
  IPv6-egress открытым (утечка при падении туннеля + ложное чувство защиты). Теперь он откатывает
  v4-плечо и отказывается стартовать (opt-out `routing.allow_ipv6_leak`). v4-only хосты не затронуты.
  ([killswitch.rs](qeli/src/client/killswitch.rs))
- **`flow_hash`** отвергает IPv4-пакет с IHL<20 — иначе крафтовый малый IHL хешировался бы как
  L4-порты (только корректность мультипат-пиннинга; без утечки/паники).
- **`tail_lines` панели** читает только хвост лога (~64 KiB) — большой лог не может исчерпать
  память сервера ради показа последних строк.
- **Junk-фаза obfs (pre-auth) ограничена по времени и байтам.** `recv_junk_ws` не имел внешнего
  handshake-таймаута — медленный дрибл или флуд WS-control-фреймов (они пропускались, не
  считаясь junk-ом) мог бесконечно держать/крутить серверный accept-таск. Добавлены дедлайн (15с)
  и байт-бюджет. ([obfs.rs](qeli/src/protocol/obfs.rs))
- **Авто-`Secure` для session-cookie за доверенным HTTPS-прокси** (`X-Forwarded-Proto: https` И
  peer ∈ `web.trusted_proxies`) — оператору больше не нужно вручную ставить `web.secure_cookie`;
  гейтед на доверие, чтобы подделанный заголовок на plain-HTTP-биндe не выставил `Secure` и не
  залочил вход. ([login.rs](qeli/src/web/api/login.rs))

### Изменено
- **Понятный 403 при отклонении CSRF** — панель отдаёт `text/plain` с именем отклонённого
  origin и примером для `web.allowed_origins`.
- **fake-tls ClientHello унифицирован через общий Rust-билдер.** C#/Kotlin-клиенты строят
  fake-tls/obfs/UDP ClientHello через FFI в `qeli.dll`/`libqeli.so`
  (`qeli_build_faketls_clienthello` / `nativeFakeClientHello`), с fallback на прежний managed-путь —
  единый отпечаток (GREASE / per-connection shuffle / ALPN) вместо трёх расходящихся реализаций
  (раньше C# не шаффлил расширения и не слал ALPN). (#69)
- **Убраны мёртвые опции `obf.tls.session_id` / `obf.tls.supported_groups` /
  `obf.tls.key_share_entropy_bytes`** — их не читал ни один билдер ClientHello (группы захардкожены),
  но они торчали в INI и веб-панели. Удалены из конфига/INI/панели/доков; старые конфиги с этими
  ключами по-прежнему парсятся (ключи просто игнорируются). (#69)
- Устаревшие деплой-скрипты эры `vpn-obfuscated` (`deploy-server.sh` и др.) теперь явно
  завершаются с ошибкой (несовместимы с текущим flat-INI форматом).
- **Установщик `install-qeli-server.sh` спрашивает профиль и порт.** Раньше он жёстко
  ставил reality-tls на :443. Теперь в процессе установки в одну команду спрашивает
  **профиль** (reality-tls по умолчанию или fake-tls) и **порт** (по умолчанию 443): блок
  нужного профиля берётся из мультипрофильного примера, выбранный порт форсится в
  `bind.port` и во внешний MSS-кламп, а рандомный REALITY `short_id` генерится только для
  reality-tls (у fake-tls его нет). Неинтерактивно — через `QELI_PROFILE=reality-tls|fake-tls`
  и `QELI_PORT=<1-65535>` (для `curl … | bash` / автоматизации; иначе промпт читается с
  `/dev/tty`). Порт 8080 зарезервирован под веб-панель.
  ([install-qeli-server.sh](install-qeli-server.sh), docs/README.md, GETTING-STARTED.md ru/eng)
- README: инсталлер рекомендуется скачивать и запускать отдельно (не `curl | bash`).
- `client.conf`: комментарий kill_switch — `iptables` (была опечатка `nftables`).
- **Debian: `libcap2-bin` добавлен в `Depends`** + гард `command -v setcap` — `postinst` (`set -e`)
  больше не падает на минимальном образе без libcap (пакет корректно конфигурируется).
- **CI/Docker:** тег `:latest` больше не двигается на пре-релизы (`v*-rc*`); включены
  SLSA build-provenance и кэш слоёв (GHA cache + cargo cache-mount); `cargo test --all` →
  `--workspace`.
- **Конфиг: предупреждения вместо тихого дропа** непарсящихся значений (метрика маршрута,
  bandwidth группы) и пустого имени `pool.reservation.`; warn когда inline-`[user:*]` перекрывает
  явный `users_file`.
- **`get_usage`** кэширует разобранный users-файл по mtime (инвалидация при записи воркером) —
  не парсит весь файл на каждый запрос.
- Удалён мёртвый код: `LogRotation` (не парсился и не читался), Basic-auth `is_authed`/`check_auth`.
- **Клиент: заработали ранее «мёртвые» ключи конфиг-файла** — `password_file`, `password_command`
  (headless-источники пароля), `keepalive`, `tcp_nodelay`: honored кодом, но не парсились из файла
  (документированный ключ, молча ничего не делавший). Теперь парсятся и round-trip'ятся.

### Зависимости
- Rust: **`chacha20poly1305` 0.11** (новая AEAD-серия; внутренний туннель всех режимов).
  **`aes-gcm` оставлен на 0.10** — бамп на 0.11 просаживал throughput reality-tls (~−20% up),
  точечный откат вернул паритет с 0.7.6 (слой затрагивает только reality-tls-запись).
  `chacha20` 0.10.1, `thiserror` 2, `socket2` 0.6, `webpki-roots` 1.0, `log`/`bytes`/`anyhow`.
- CI: `actions/checkout` v7, `cache` v6, `upload-artifact` v7, `docker` login/qemu v4.
- Клиенты: Avalonia 11.3.18 (macOS), gradle-wrapper 9.6.1 + `androidx.lifecycle` 2.11 (Android).

### Исправлено — из пре-релиза
- **DNS / systemd-resolved (клиент).** Пушенный DNS применяется через `resolvectl` только когда
  systemd-resolved действительно активный резолвер (`resolv.conf` → стаб `127.0.0.53`); иначе —
  файловый путь. Раньше на боксах, где systemd-resolved лишь установлен, `resolvectl dns` тихо не
  срабатывал и DNS шёл мимо туннеля.
- **Установщик REALITY.** Публичный IP определяется цепочкой echo-сервисов + локальным
  `ip route get` (работает и с `/32`); пакет ставится с `--no-install-recommends`, а
  systemd-resolved переведён из `Recommends` в `Suggests` — сервер больше не подменяет
  `/etc/resolv.conf` при установке.
- **Android: цикл переподключений «network changed».** Клиент следит за нижележащими сетями
  (`NET_CAPABILITY_NOT_VPN`), а не за дефолтной — собственный tun больше не выглядит как смена
  сети. Плюс ретрай `protect()` в гонках реконнекта и закрытие старого tun после поднятия нового.
- **Панель: проверка обновлений (`[web] update_check`) не включалась (регрессия 0.7.6).**
  Флаг не читался INI-парсером конфига (`server_ini.rs web_from`/`web_to`), поэтому всегда
  резолвился в `false` и баннер обновлений не появлялся, что бы ни стояло в `[web]`. Фронтенд
  и `/api/status` были корректны — ломало только чтение/запись ключа; добавлены оба.
- **Панель / Quick Start: `obfs-none` и `obfs-awg` стартовали с `fronting=websocket` вместо
  `none` (регрессия 0.7.6).** `buildProfile` писал fronting под INI-именем `obfs_fronting` в
  JSON-тело `PUT /api/config`, а serde-поле — `fronting`; неизвестный ключ молча отбрасывался
  → оставался дефолтный `websocket`. Клиент с `front=none` не мог завершить обмен nonce →
  туннель не поднимался, без ошибки в панели. Теперь пишется правильный ключ.
- **Панель: несколько строк RU-локализации** (заголовок модалки «Data cap & expiry»,
  «Copy failed», описания полей CSRF-origin / public_host, «Or until date») показывались
  по-английски на RU — добавлены/поправлены ключи `i18n.js` + `qeliT()` для заголовка модалки.

### Тесты
- **Юнит-тесты control-канала** (`server/control.rs`, 9 шт.) — раньше security-критичный
  диспетчер (kick/disable/set-limit/list-clients) не имел тестов; покрыт парсинг команд: каждый
  verb, дефолты, устойчивость к malformed / unknown / wrong-type входу без паник с сокета.
- **Триппвайр паддинга ClientHello** — `debug_assert` сверяет `NON_EXT_BYTES` с реальной
  раскладкой записи, так что правка cipher-листа ловится тестом, а не тихо ломает анти-fingerprint
  паддинг. Плюс round-trip `allow_ipv6_leak` и регрессия на oversized-record.

### Документация
- **Клиентский `dns`.** Явно сказано, что дефолт `tunnel` **переписывает `/etc/resolv.conf`**
  (Linux) ради анти-DNS-leak, а `dns = off` не трогает системный резолвер. `CONFIG.md` ru+eng.
- **Согласованность семплов/доков.** Устаревшая фраза «Profile defaults»
  (`keepalive_secs=30`/`max_clients=64`) исправлена на реальные `60`/`128`; sample `server.conf`
  `dns.enabled` → `false` (дефолт); в семплы добавлены недостающие ключи (`[web]`
  `trusted_proxies`/`base_path`/`csrf`/`session_ttl_secs`; client `gateway_nat`/`lan_subnet`/
  `post_up`/`post_down`/`allow_ipv6_leak`).
- **`docs/archive/audits/AUDIT-FIXES-2026-07-05.md`** — трекер аудита: статус по каждой находке, что закрыто,
  что переклассифицировано как ложное (anti-replay REALITY, sweep udp_frag уже были в коде).

## [0.7.6] — 2026-07-02

Серия фиксов веб-панели по фидбеку «изменения не применяются» (инлайн-юзеры, live-обновление
`[web]`-настроек, kick полу-мёртвого клиента), **редактор политики блокировки** прямо на
вкладке Blocked IPs, полная локализация этой вкладки, и фикс **сборки Docker-образа**. Плюс
фикс реконнекта UDP-клиента на потерях. Со стороны клиентов — **диагностический лог имени
юзера при коннекте** (все платформы) и **фикс выбора профиля на Windows/macOS** (два аккаунта
на одном сервере больше не путаются) и новая **opt-in проверка новых версий** (все клиенты +
панель + CLI, notification-only). Плюс **оптимизация горячего пути**: in-place AEAD пакетного
кодека (меньше аллокаций на пакет — все режимы и платформы) и конвейеризация двойного
дешифрования reality-tls через ядра. Сетево и по конфигу совместимо с 0.7.5; **все компоненты
бампнуты на 0.7.6**. Затронуты все компоненты (Rust-демон/панель/CLI, GUI Windows/
macOS/Android). Проверено: Rust на лабе (build --release + `cargo test --all` 262/262 — вкл.
`server::update` + новые in-place-тесты — + clippy + fmt + fuzz `packet_decrypt` 6.4M/0 крашей
+ состязательный ревью диффа), C#-клиенты (win/mac Release), Android APK (`assembleDebug`),
панельный JS, Docker-контейнер.

### Изменено — обфускация: junk-маскировка, WS-фрейминг, fake-tls-тикет (wire-breaking, opt-in)
> **Все три правки ломают совместимость по проводу и по умолчанию ВЫКЛЮЧЕНЫ.**
> Включать нужно **одновременно на клиенте и на сервере** — иначе рукопожатие не сойдётся.
- **AmneziaWG-подобная junk-маскировка перед обменом nonce.** Новые серверные obfs-ключи
  `obf.awg.enabled` (bool, default `false`), `obf.awg.jc` (u32, default `0`, потолок `128`),
  `obf.awg.jmin` (u16, default `40`), `obf.awg.jmax` (u16, default `300`; `jmin<=jmax<=1400`).
  До обмена nonce каждая сторона отправляет `jc` junk-записей случайного размера (`jmin..jmax`),
  приёмник отбрасывает первые `jc`. Полиморфное начало obfs-потока убивает фингерпринт по
  размеру/числу первых пакетов. **Обе стороны обязаны использовать один `jc`.** Клиент задаёт
  это в `[qeli]` / `qeli://` параметрами `awg` (`=true`/`1`), `jc`, `jmin`, `jmax`.
- **WebSocket binary framing для obfs `obf.obfs_fronting = websocket`.** Поток после
  `101 Switching Protocols` теперь — настоящие RFC 6455 binary-фреймы (client→server
  маскируются), а не сырой ChaCha20-байтопоток. WS-осведомлённый DPI видит валидные кадры,
  а не аномальный «WebSocket без фреймов».
- **fake-tls: NewSessionTicket уходит как `application_data` (0x17).** Раньше слался открытой
  handshake-записью (0x16); теперь клиенты разбирают flight после ServerHello **позиционно**.
  Убран последний plaintext-handshake DPI-телл fake-tls.

### Безопасность — правки по полному мульти-агентному аудиту (все прогнаны через гейт)
- **Клиенты Windows/macOS: строгая валидация серверных данных до `netsh`/`route`.**
  Пушнутые сервером `client_ip` / маршруты / DNS теперь проверяются **до** попадания в
  `netsh`/`route` (защита от argument injection).
- **UDP: границы pre-auth крипто и реассемблера.** Per-worker семафор ограничивает число
  одновременных pre-auth PQ-рукопожатий (спуфнутый source → CPU-DoS); реассемблер
  UDP-фрагментов лимитирует размер чанка на фрагмент (memory amplification); карта
  `RateLimiter.attempts` ограничена по размеру (рост от спуфнутых IP).
- **realtls: bounds-check и лимиты буферов.** `parse_borrow_profile` проверяет границы
  (OOB-паника на усечённом ServerHello); буферы асинхронного клиентского хендшейка
  ограничены (memory-DoS от вредоносного сервера).
- **`FailedAuthTracker`: карты `by_user`/`by_ip` подметаются, длина имени юзера ограничена**
  (неограниченный рост памяти).
- **TCP: reaper мёртвых соединений двигается только при успешной расшифровке**; per-session
  bandwidth-cap теперь троттлит и **входящий** трафик (upload), а не только download.
- **Клиентские булевы (`kill_switch`, `gateway_nat`, `bind_static`, `quic`, …) парсятся через
  `bool_or`** — нет fail-open на `yes`/`on`/`True`; **TOFU fail-CLOSED**, если `known_hosts`
  не записывается, кроме случая `auth.allow_unpinned_tofu = true` (новый ключ, bool, default
  `false`). Клиент также валидирует пушнутые маршруты/DNS до `ip route` / `resolv.conf`.
- **DHCP:** per-source rate-limit + предупреждение при публичном listen; requested-IP для
  renew берётся из `ciaddr` (а не Option 54); аренды вне диапазона пула освобождаются.
- **reality:** session-id считается через **checked** X25519-обмен (low-order key_share
  отклоняется).
- **Web:** CRLF в webhook-URL отклоняется; whitelist каталога логов сужен до `/var/log/qeli`;
  админ-имя сравнивается в постоянном времени.
- **Конфиг:** неизвестные `bind.transport` / `obf.mode` теперь **отклоняются при загрузке**
  (был тихий фолбэк); исправлено квотирование INI-значений (round-trip `;`/`#`/кавычек);
  пустые секции `[user:]` отбрасываются; порча `usage.json`/`notify.json` логируется, а не
  проглатывается; ошибки flush usage логируются + flush на `Drop`.
- **Установка:** сбой включения `ip_forward` для gateway — предупреждение (не тихо); backup
  отказывается опускать identity-ключи и сохраняет xattrs.
- **fake-tls DPI:** ClientHello всегда шлёт ALPN + GREASE-группу; длины серверного
  сертификата/тикета рандомизируются.
- **Клиенты:** Android — `ObjectAnimator` отменяется в `onDestroy` (утечка), `wakeLock`
  больше не истекает на 12 ч; macOS — дозапись лога `O(n)` вместо `O(n^2)`; Windows —
  kill-switch батчит вызовы PowerShell.

### Добавлено — проверка новых версий (opt-in, notification-only)
- **Все клиенты, веб-панель и CLI умеют проверять GitHub на свежий релиз.** По умолчанию
  **ВЫКЛЮЧЕНО** (opt-in) — выключенная фича вообще не открывает сокет. Показывает «Доступна
  новая версия X» со ссылкой на релиз, а на **сервере** (панель/CLI) — ещё и готовую **команду
  обновления для консоли**. Сам qeli **ничего не скачивает и не устанавливает** — установку
  запускает оператор вручную.
  - **Приватность (главное для VPN).** Это censorship-resistance-инструмент, и сам запрос к
    `api.github.com/.../qeli/releases` — фингерпринт «здесь стоит qeli» + раскрытие IP
    (SECURITY.md относит traffic-confirmation к in-scope; Политика приватности §2.2 запрещает
    «скрытый phone-home»). Поэтому: default OFF + жёсткий выключатель; **обезличенный
    User-Agent** (`Mozilla/5.0`, не `qeli/x.y.z`); минимальный неаутентифицированный GET
    публичных метаданных (без версии/ID/ОС — сравнение локальное); на клиентах — **только при
    поднятом туннеле** (запрос и реальный IP идут внутри туннеля; при отключённом VPN
    авто-проверка молча пропускается); кэш + fail-soft (любая ошибка / лимит 60 req/ч/IP =
    «нет данных», без ошибок пользователю).
  - **Источник истины — СПИСОК релизов** `GET /repos/litvinovtd/qeli/releases`, первый
    non-draft (НЕ `/releases/latest` — он пропускает пререлизы, а релизы qeli — пререлизы;
    ровно как `install-qeli-server.sh`). Сравнение — **числовое semver**, не строковое.
  - **Windows / macOS:** тумблер «Проверять обновления автоматически» в Настройках, кнопка
    «Проверить обновления» в «О программе», dismissible-ссылка в шапке журнала. Общий
    `UpdateChecker` + `SemVer` в `qeli-shared` (BCL `HttpClient`, без новых зависимостей).
  - **Android:** тап по версии в подвале открывает диалог (тумблер + «Проверить сейчас»),
    авто-проверка на коннекте; `HttpsURLConnection` (без новых зависимостей).
  - **Веб-панель:** dismissible-баннер под топбаром, включается ключом `[web] update_check`
    (default false); проверку делает **браузер оператора** (как маркетинг-сайт), не серверный
    процесс — без серверного beacon. Баннер показывает **копируемую команду обновления** под
    способ установки (`.deb`: скачать → сверить SHA256 → `dpkg -i` → restart; Docker: `docker
    pull`; тип установки отдаёт `/api/status.install_kind`) + кнопку «Copy». **Автоустановки
    нет** — команду выполняет оператор.
  - **CLI:** `qeli version --check` — user-initiated, печатает текущую/последнюю версии и ту же
    команду обновления под способ установки. Проверено live против настоящего GitHub на лабе.
  - **Проверка целостности (SHA256).** Релизы теперь публикуют ассет **`SHA256SUMS`**
    (`scripts/gen_checksums.py` генерит, заливается вместе с бинарями); команда обновления и
    `install-qeli-server.sh` сверяют .deb перед установкой (несовпадение → отказ ставить),
    а при отсутствии SHA256SUMS откатываются на доверие TLS-к-GitHub (как раньше).
  - **Роутеры (OpenWrt / Keenetic) исключены** — client-only mipsel/aarch64 не собирают
    HTTPS-стек (ring без MIPS-бэкенда). Фонового таймера демона нет.
  ([server/update.rs](qeli/src/server/update.rs),
  [UpdateChecker.cs](qeli-shared/QeliShared/Update/UpdateChecker.cs),
  [UpdateChecker.kt](qeli-android/app/src/main/kotlin/com/qeli/UpdateChecker.kt),
  [layout.html](qeli/src/web/templates/layout.html),
  [install-qeli-server.sh](install-qeli-server.sh),
  [gen_checksums.py](scripts/gen_checksums.py))

### Добавлено — управление IP-блокировками + редактор политики
- **Заблокированные адреса — CLI и панель.** Брутфорс-защита лочит source-IP после серии
  неверных паролей; теперь их видно и можно снять вручную: `qeli list-blocked` (IP · число
  неудач · сколько осталось до разблокировки), `qeli unblock <ip>`, `qeli unblock --all`. В
  панели — **отдельная вкладка «Blocked IPs»** (таблица + Unblock / Clear all). И CLI, и
  панель ходят к трекеру блокировок через control-сокет воркера (единый источник правды, а
  не пустой трекер супервизора). ([server/control.rs](qeli/src/server/control.rs),
  [web/pages/blocked.rs](qeli/src/web/pages/blocked.rs), [web/api/status.rs](qeli/src/web/api/status.rs))
- **Редактор политики блокировки на вкладке «Blocked IPs».** Карточка *Lockout policy* с
  `Max attempts` / `Window` / `Lockout` (пороги `[auth] brute_force`). Сохранение патчит
  только эти три ключа в конфиг **на месте** (комментарии сохраняются, в отличие от полного
  `PUT /api/config`) и применяет **на лету**: трекер супервизора (вход в панель) пересобирается
  сразу, воркер (VPN-auth) получает `SIGHUP` — без рестарта и разрыва сессий. Одна политика
  управляет обеими плоскостями. Comment-preserving upsert вынесен в общий
  `config::set_section_keys` (его же теперь использует `qeli set-web-password`).
  ([web/api/status.rs](qeli/src/web/api/status.rs), [config/mod.rs](qeli/src/config/mod.rs))
- **Auth-лог показывает профиль и юзера.** TCP-строка теперь `AUTH attempt … on profile
  'X': user=Y` (как в UDP). NB: пофлудные `New TCP connection from …` на `reality-tls` — это
  сканеры/пробы **без юзера** (прозрачно проксируются на upstream, не доходят до проверки
  пароля); реальные попытки видны как `AUTH FAIL … user=Y — wrong password`.

### Добавлено — уведомление о блокировке IP + дата истечения аккаунта
- **Новый тип уведомления «VPN auth IP lockout».** В дополнение к «Panel login lockout»
  (блокировка входа в панель) теперь есть отдельное событие: когда брутфорс-защита **жёстко
  лочит source-IP** после серии неверных VPN-логина/пароля, уходит уведомление (Telegram /
  webhook), троттлинг 1/час на IP (как у quota-breach). Включается на вкладке «Notifications»
  (по умолчанию вкл). `RateLimiter::record_failure` теперь возвращает «IP только что залочен»,
  и auth-путь фаерит `Event::AuthLockout` вне мьютекса. ([notify.rs](qeli/src/server/notify.rs),
  [server/mod.rs](qeli/src/server/mod.rs), [handler.rs](qeli/src/server/handler.rs),
  [web/api/notify.rs](qeli/src/web/api/notify.rs))
- **Дата истечения аккаунта выбором из календаря.** В модалке «Data cap & expiry»
  (Пользователи → ⚙) рядом с «Expire in (days)» добавлено поле **«Or until date»**
  (`<input type="date">`) — можно задать конкретную дату блокировки, а не считать дни. Поля
  синхронизированы (дни↔дата); при сохранении дата приоритетна (аккаунт действует до конца
  выбранного дня). Бэкенд уже хранил `expire_at` как абсолютный Unix-таймстамп — правка
  чисто UI. ([users.html](qeli/src/web/templates/users.html))

### Добавлено/Изменено — панель: имя сервера в уведомлениях + UX-доработки
- **Имя сервера в уведомлениях.** Новое поле «Server name» на вкладке Notifications (хранится в
  `/etc/qeli/notify.json`, редактируется и файлом, и панелью) подставляется в начало каждого
  Telegram/webhook-сообщения (`[имя] …`) + в webhook-JSON поле `server`, чтобы различать
  несколько серверов, шлющих в один чат/хук. Пусто = не добавлять. ([notify.rs](qeli/src/server/notify.rs),
  [web/api/notify.rs](qeli/src/web/api/notify.rs), [notifications.html](qeli/src/web/templates/notifications.html))
- **Quick start: защита от коллизии портов.** «Запустить» теперь сначала проверяет конфиг — если
  порт+транспорт уже занят ДРУГИМ профилем, показывается попап «порт занят профилем X, сначала
  измените его порт», без изменений. Повторный запуск того же режима (он заменяет свой профиль) —
  без предупреждения. ([quickstart.html](qeli/src/web/templates/quickstart.html))
- **AmneziaWG-маскировка выведена отдельным режимом `obfs-awg`.** Это НЕ новый wire-mode — маска
  Amnezia = слой `obf.awg.*` (junk-преамбула) поверх `obfs`. Теперь она доступна как отдельный
  профиль: добавлен `[profile:obfs-awg]` (obfs + `obf.awg.enabled`, TCP :8451) в
  `server-multiprofile.conf`, и одноимённый **одноклик-режим в Quick Start** (obfs + awg jc=4,
  `buildProfile` проставляет `obf.awg`). Конфиг парсится (10 профилей). ([server-multiprofile.conf](qeli/config/server-multiprofile.conf),
  [quickstart.html](qeli/src/web/templates/quickstart.html))
- **Blocked IPs: редактор политики убран** — теперь на странице только заметка, что политика
  блокировки настраивается в Конфигурация → Защита от брутфорса (RU+EN). ([blocked.html](qeli/src/web/templates/blocked.html))
- **Прочие UX-правки панели:** редакторы JSON/Raw INI в Конфигурации растянуты во всю высоту;
  кнопка «Save to Disk» → «Save», у «Reload» добавлена подсказка; синяя черта активной вкладки
  Конфигурации опущена на разделитель (`-mb-px`); кнопки в столбце «Использование трафика»
  выровнены в колонку (`ml-auto`); блок «Нагрузка хоста» переоформлен сеткой статов; страница
  Журнала автопрокручивается вниз при открытии. (config/users/dashboard/logs .html)

### Диагностика — клиенты логируют имя пользователя при коннекте
- **Все клиенты (Rust CLI/router, Windows, macOS, Android) теперь пишут в лог, под каким
  именем юзера идёт подключение** — `Connecting … as user 'X'`. Раньше имя нигде не
  светилось, и было невозможно понять, что клиент отправляет «не того» юзера (реальный кейс
  на macOS: выбрали профиль user3, а на провод ушли креды user2 → сервер упорно лочил IP по
  user2). Логируется **только имя, не пароль**. Rust-клиент вдобавок уже пишет путь конфига
  на старте (`Starting client with config: …`). Серверный лог уже различает причину отказа —
  `AUTH FAIL … wrong password` / `… not found`, `AUTH DENIED … not permitted on profile`,
  `AUTH LOCKOUT (ip)` — все с `user=`, так что клиентское имя + серверная причина дают полную
  картину. NB: при отказе auth сервер просто закрывает соединение (код ошибки клиенту не
  шлёт), поэтому конкретная причина видна ТОЛЬКО в серверном логе.
  ([client/mod.rs](qeli/src/client/mod.rs),
  [VpnTunnelBase.cs](qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs),
  [QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt))

### Исправлено — клиенты Windows/macOS: выбор профиля (два аккаунта на одном сервере)
- **Демон / авто-коннект и списки в настройках путали аккаунты на одном сервере.** Профили
  ссылались по `DisplayName`, а он не уникален: у профиля без явного имени `DisplayName` = адрес
  сервера, поэтому два аккаунта (user2/user3) на одном хосте выглядели одинаково в списке И
  резолвились «первым совпавшим». Настройки `ServiceProfile` / `AutoConnectProfile` хранили
  строку-имя → служба (service-режим) и авто-коннект брали **не тот** профиль (реальный кейс:
  выбран user3, а на провод ушли креды user2 → сервер лочил IP; новая лог-строка `as user 'X'`
  и вскрыла симптом). Теперь у профиля есть **стабильный уникальный `Id` (GUID)**, и настройки
  службы/авто-коннекта ссылаются на профиль **по `Id`, а не по имени**; выпадающие списки несут
  `Id` в `Tag`. `DisplayName` для неименованных профилей стал различимым — `«{сервер} ({юзер})»`
  — так что аккаунты видны раздельно в списке, трее и логе. «Duplicate» профиля получает свежий
  `Id`. Миграция без потери выбора: старые (по имени) настройки продолжают резолвиться по
  запасному пути, пока пользователь один раз не пересохранит «Настройки» (тогда пишется `Id`);
  `profiles.json` без `Id` один раз пересохраняется на старте, замораживая свежесгенерённые `Id`.
  **Android и Rust-клиент (CLI / OpenWrt / Keenetic) багу не подвержены** — Android коннектит
  конфигом выбранного профиля (по индексу, не по имени), роутер работает по явному файлу `-c`.
  Проверено локальной сборкой C#-клиентов (win + mac, Release, 0 ошибок).
  ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs),
  [SettingsWindow.xaml.cs](qeli-win/QeliWin/SettingsWindow.xaml.cs) /
  [SettingsWindow.axaml.cs](qeli-mac/QeliMac/SettingsWindow.axaml.cs),
  [MainWindow.xaml.cs](qeli-win/QeliWin/MainWindow.xaml.cs) /
  [MainWindow.axaml.cs](qeli-mac/QeliMac/MainWindow.axaml.cs),
  [ProfileStore.cs](qeli-win/QeliWin/Model/ProfileStore.cs))

### Исправлено — применение изменений из панели («изменения не применяются»)
- **Правки юзеров через панель не применялись при инлайновых `[user:*]` в конфиге.**
  Панель и `add-client` всегда пишут в `auth.users_file`, но сервер (старт и `SIGHUP`-reload)
  грузил юзеров из инлайновых `[user:*]`, **игнорируя файл**, если инлайн непустой. При таком
  конфиге любые create/edit/delete из панели были no-op для дата-плоскости (список в панели
  обновлялся из памяти супервизора → выглядело «применённым»). Теперь единый
  `server::load_users_db` грузит **объединение файла и инлайна с приоритетом файла**, во всех
  трёх точках загрузки — правки панели применяются всегда. Чисто-файловые и чисто-инлайновые
  конфиги не затронуты. Воспроизведено и проверено на реальном auth (`scripts/test_user_reload.py`,
  файловый + инлайновый, 14/14). ([server/mod.rs](qeli/src/server/mod.rs))
- **Панель больше не рапортует «успех», если запись users-файла провалилась.** Create / update /
  delete / enable-disable / set-bandwidth / delete-group теперь возвращают ошибку при сбое
  `users.save()` (I/O, права), а не молчаливый `ok:true` — раньше это выглядело как «изменение
  не применилось». ([web/api/users.rs](qeli/src/web/api/users.rs))
- **Веб-настройки панели теперь применяются НА ЛЕТУ (без полного рестарта).** Раньше
  супервизор читал `[web]` только на старте, поэтому смена админ-пароля / allowlist / CSRF-origins
  через панель не действовала до `systemctl restart qeli` (старый пароль продолжал работать!).
  Добавлена живая копия `ServerState.live_web` (`Arc<RwLock<WebConfig>>`), которую читают все
  панель/auth-пути; `put_config`/`put_config_raw` обновляют её сразу после записи (`reload_web_settings`).
  Смена пароля мгновенно инвалидирует старые сессии и старый пароль. Socket-поля (`bind`/`port`/`tls`/
  `enabled`) по-прежнему требуют рестарта (биндятся на старте). Проверено e2e (`scripts/test_web_reload.py`,
  12/12). ([server/mod.rs](qeli/src/server/mod.rs), [web/api/config.rs](qeli/src/web/api/config.rs), [web/auth.rs](qeli/src/web/auth.rs))
- **Полная локализация вкладки «Blocked IPs».** Заголовок в топбаре показывал «Qeli» вместо
  «Blocked IPs» (в `pageTitle`-мапе `layout.html` не было ключа `blocked`); диалоги
  `confirm()/alert()` вкладки оставались на английском (i18n-уокер переводит только DOM, не
  JS-литералы). Добавлен ключ заголовка + `window.qeliT` для перевода диалогов из JS; аудит
  подтвердил — все строки вкладки покрыты RU. ([layout.html](qeli/src/web/templates/layout.html),
  [i18n.js](qeli/src/web/assets/i18n.js))

### Исправлено — kick юзера из панели
- **Kick полу-мёртвого клиента не срабатывал: сессия висела в панели и юзер не мог
  переподключиться.** Control-команда `kick` (и «Disable» из панели) слала стриму лишь
  кооперативный сигнал через канал; если задача стрима заблокирована на `write_all` к
  клиенту с забитым TCP-окном (потеря связи, мобильный обрыв), сигнал не обрабатывался →
  сессия не убиралась из `by_ip` (висит в `list-clients`/панели), а pool-IP оставался занят
  (реконнект мог не подняться). Теперь `kick` **сразу авторитетно удаляет** сессии из реестра
  (`by_ip`+`by_token`) и **освобождает pool-IP**, затем шлёт сигнал — эффект мгновенный,
  независимо от того, застряла задача или нет (её поздний self-cleanup становится no-op по
  guard'у session_id). Общий helper `kick_user_on_profile` для `kick` и `disable-user`.
  Воспроизведено (заморозка клиента + flood → сессия висла) и проверено на лабе **6/6** и в
  Docker-контейнере **7/7** (`scripts/test_kick.py`, `scripts/docker_kick_test.py`).
  ([server/control.rs](qeli/src/server/control.rs))

### Исправлено — Docker-образ
- **Контейнер не стартовал при сборке образа из Windows-checkout (CRLF в `entrypoint.sh`).**
  `#!/bin/sh\r` → ядро искало интерпретатор `/bin/sh\r` → `exec …/entrypoint.sh: no such file or
  directory`, контейнер падал. Dockerfile теперь `sed 's/\r$//'` у entrypoint при сборке
  (в дополнение к `.gitattributes eol=lf`) — образ собирается корректно из любого checkout.
  Все панельные/дата-плоскостные тесты прогнаны против сервера **в Docker** (host-net 21/21 +
  bridge/port-map 5/5). ([release/docker/Dockerfile](release/docker/Dockerfile))

### Исправлено — реконнект UDP-клиента
- **UDP-клиент: реконнект больше не «залипает» на потерях / после рестарта сервера.**
  PQ-хендшейк слал (многофрагментный) ClientHello и auth-креды по одному разу и ждал
  ответ весь connect-timeout без переотправки. Одна потерянная хендшейк-датаграмма —
  обычное дело сразу после рестарта сервера или смены пути/NAT (CGNAT/LTE) — стопорила
  всю попытку на ~30 с, и канал поднимался лишь через 60–90 с. Теперь оба лега хендшейка
  переотправляются по джиттерованному ~1 с-таймеру в пределах единого `hs_deadline`
  (ClientHello — пока не соберётся ServerHello; auth — пока не придёт AuthOK), а потеря
  обратного направления (ServerHello/AuthOK) быстро проваливается к реконнекту со свежим
  портом вместо трёх сложенных таймаутов. Сервер терпит переотправки (Reassembler дедупит
  фрагменты, повторный auth отбрасывается replay-защитой). Замер против прода под tc-netem:
  медиана подключения при 15 % потерь ~32 с → 1–2 с; при 50 % старый клиент часто не
  поднимается за 60 с, новый — за ~5 с ([client/mod.rs](qeli/src/client/mod.rs)).

### Производительность — in-place AEAD пакетного кодека + конвейер приёма reality-tls
- **Меньше аллокаций на пакет в горячем пути (все режимы, все платформы).** Пакетный кодек
  теперь выполняет AEAD **на месте** вместо аллокации свежих `Vec` на каждый пакет:
  `encrypt_packet` собирает весь on-wire-рекорд в **одном** буфере и шифрует полезную нагрузку
  in-place с detached-тегом (было 3 аллокации на пакет → **1**), `decrypt_packet` отделяет тег и
  снимает counter/padding без второго `Vec` (было 2 → **1**). Формат на проводе и крипто-модель
  **байт-в-байт прежние** (тот же nonce-PRP, counter, 2048-битный replay-window) — новый тест
  эквивалентности in-place↔аллоцирующего пути и все прежние packet-тесты зелёные, а hot-путь
  `decrypt_packet` дополнительно прогнан фаззером (**6.4M входов, 0 паник** — существенно под
  `panic = "abort"`, где паника на pre-auth входе = удалённый краш). Codec общий в cdylib, так что
  меньше нагрузка на аллокатор и у сервера, и у всех клиентов (в т.ч. клиентский download).
  Старые аллоцирующие `Cipher::encrypt/decrypt` сохранены (их используют `crypto/secret.rs` и
  `crypto/reality.rs`). ([crypto/cipher.rs](qeli/src/crypto/cipher.rs),
  [protocol/packet.rs](qeli/src/protocol/packet.rs))
- **reality-tls: приём двух AEAD-слоёв конвейером через ядра.** Во входящем reality-tls каждый
  пакет снимает ДВА AEAD — внешний TLS AES-GCM (внутри `RealTlsStream`) и внутренний qeli
  ChaCha20-Poly1305 — раньше последовательно в одной задаче, то есть оба слоя жались в одно ядро
  (клиентский download упирался именно в это). Теперь на приёме это **2-стадийный конвейер**:
  стадия A читает сокет и снимает внешний слой, передаёт рекорд по ограниченному FIFO(1024)
  стадии B, а та снимает внутренний слой и пишет в TUN — два слоя перекрываются на разных ядрах.
  Порядок пакетов сохранён (single-producer FIFO, обе стадии однопоточны → TLS-seq и replay-window
  идут строго по порядку), дедлока нет (стадия B никогда не блокирует на записи в TUN), teardown
  корректный (конец стадии A закрывает FIFO → стадия B дочищает очередь и завершается). Включается
  **только для reality-tls**; plain / fake-tls / obfs / reality-proxy / UDP идут прежним inline-
  путём без изменений. ([client/mod.rs](qeli/src/client/mod.rs))

## [0.7.5] — 2026-06-29

Точечные фиксы стабильности: реконнект Rust- и Android-клиентов, создание Wintun-адаптера
на Windows, и понятная ошибка share-ссылки для не-загруженного профиля. Плюс новый
**экспериментальный клиент для OpenWrt** (procd + UCI + LuCI), **router-режим
клиента (`gateway_nat`) и lifecycle-хуки `post_up`/`post_down`** (только бинарник на Linux),
и **уведомления веб-панели** (Telegram/webhook). Сетево совместимо с 0.7.4; новые ключи
конфига по умолчанию выключены (opt-in).

### Исправлено
- **Rust-клиент: реконнект больше не падает с `EBUSY` на TUN.** Adaptive-ramp задача
  (добавление бондинг-потоков) крутилась бесконечно, удерживая клон `tun_write_tx`, →
  после дисконнекта канал TUN-writer'а не закрывался, `writer_fd` (dup TUN fd) оставался
  открыт, `vpn0` числился busy, и каждый реконнект падал с «Device or resource busy».
  Теперь задача abort'ится при teardown ([client/mod.rs](qeli/src/client/mod.rs)).
- **Android: устранена утечка TUN-дескриптора на реконнекте + ретрай `protect()`.** На
  «чистом» реконнекте предыдущий TUN оставался открытым — новый `establish()` заменяет его
  на уровне ОС, но Java-дескриптор старого не закрывался, и осиротевшие fd копились от
  реконнекта к реконнекту. Теперь прошлый интерфейс закрывается **после** поднятия нового
  (без no-TUN-гэпа). Плюс гонка «protect() returned false» при старте/реконнекте больше не
  оставляет сокет незащищённым из-за разового промаха: `protect()` ретраится до 5× по 100 мс,
  прежде чем предупредить ([QeliService.kt](qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt)).
- **Windows: устранён `ERROR_FILE_NOT_FOUND` при создании Wintun-адаптера.** Ghost-запись
  в реестре на стабильный GUID могла «забрикать» старт (`WintunCreateAdapter` падал с
  err 2, при этом открывать нечего). Теперь однократный ретрай со **свежим случайным
  GUID** обходит отравленную stable-GUID запись (драйвер/ребут потом чистят ghost)
  ([Wintun.cs](qeli-win/QeliWin/Vpn/Wintun.cs)).
- **Share-ссылка: понятная ошибка для не-загруженного профиля.** Генерация ссылки для
  профиля, добавленного в конфиг, но ещё не поднятого (профили, в отличие от
  пользователей, **не** хот-релоадятся — каждый биндит свой порт на старте), раньше
  давала невнятное «unknown profile». Теперь сообщение прямо говорит «профиль не загружен,
  перезапустите сервер» и перечисляет загруженные ([web/api/share.rs](qeli/src/web/api/share.rs)).

### Добавлено — клиент для OpenWrt (экспериментально, не тестировался на железе)
- **Нативный OpenWrt-пакет клиента** ([qeli-openwrt/](qeli-openwrt/)): тот же
  client-only `qeli-client` бинарь (без `ring` → собирается и на mips), управляемый
  по-опенвртовски — **procd**-сервис, **UCI**-схема (`/etc/config/qeli`), firewall-зона
  (fw4-native, full-tunnel-NAT для LAN) и страница **LuCI**. Ядро не переписано — клиент
  наследует все фиксы (iptables kill-switch 0.7.3, UDP-фрагментация/liveness 0.7.4,
  device-id/TOFU). Пароль рендерится из UCI в 0600-INI в tmpfs (не ложится на flash).
  Пакет (`Makefile`, `files/`, `luci-app-qeli/`) лежит в репозитории; в Release приложены
  кросс-собранные бинари под **aarch64 / armv7 / mipsel / x86_64**. **Не тестировался на
  реальном OpenWrt-устройстве — использовать на свой риск.** Установка — [qeli-openwrt/INSTALL.md](qeli-openwrt/INSTALL.md).

### Добавлено — router-режим клиента и lifecycle-хуки (только бинарник, Linux)
- **`gateway_nat` — авто-NAT для клиента-шлюза.** Клиент на роутере (Mikrotik-контейнер,
  Keenetic, OpenWrt, любой Linux-шлюз) теперь сам программирует `ip_forward` + `MASQUERADE`
  из tun (+ `FORWARD` + TCP MSS-clamp), чтобы LAN **за ним** выходил в интернет через
  туннель — без ручного iptables и сторожа-entrypoint. Идемпотентно (`iptables -C`, тег
  `qeli-gw-nat`), держится через реконнект, снимается на чистой остановке (краш оставляет —
  fail-safe, как kill-switch). `lan_subnet` ограничивает NAT одной source-подсетью. Новый
  модуль [client/gateway.rs](qeli/src/client/gateway.rs).
- **`post_up` / `post_down` — lifecycle-хуки (клиент и сервер).** Произвольная команда при
  старте / чистой остановке туннеля — для policy-routing, mangle, site-to-site и кастомного
  firewall (аналог `PostUp`/`PostDown` у `wg-quick`). Клиент — `[qeli]` `post_up`/`post_down`;
  сервер — per-profile `routing.post_up`/`routing.post_down`. Хук получает контекст в env
  (`QELI_TUN`, `QELI_SERVER`, `QELI_POOL`, `QELI_WAN`, …), таймаут 30 с, ошибка не валит
  туннель. Новый раннер [hooks.rs](qeli/src/hooks.rs).
- **Безопасность хуков (анти-RCE).** Хук выполняется от root, поэтому берётся **только из
  доверенного файла**: при group/world-writable конфиге (`mode & 0o022`) хуки не
  выполняются; веб-панель/API их **не пишут** (`put_config` восстанавливает из файла на
  диске, `put_config_raw` отклоняет изменение). Задать/изменить хук можно лишь
  редактированием конфига на сервере — как `systemd ExecStartPost`, не из сети.
- **Только бинарник.** Эти ключи действуют исключительно в `qeli` / `qeli-client` на Linux
  (роутер / headless / сервер); GUI-приложения (Android / Windows / macOS) их **игнорируют**.
  Доки — [docs/ru/manuals/CONFIG.md](docs/ru/manuals/CONFIG.md) / [docs/eng/manuals/CONFIG.md](docs/eng/manuals/CONFIG.md).

### Добавлено — веб-панель
- **Уведомления (Telegram + webhook).** Опциональные оповещения о событиях сервера
  (локаут логина панели, и т. п.) в Telegram-бота и/или произвольный webhook; исходящий
  TLS проверяется по бандлу корней `webpki-roots`. **Выключено по умолчанию**, настройки —
  в отдельном sidecar-файле, не трогают основной конфиг. Локаут логина теперь шлёт
  throttled-уведомление (раз/10 мин на IP).
- **Quick-start.** Поднятие типового профиля «в один клик» из панели.
- **Учёт трафика и квоты по клиентам** (usage), endpoint'ы backup / system, обновление
  дашборда и i18n. Все панель-фичи — серверная сторона (бинарь `qeli` на Linux);
  на wire-протокол и дефолты конфига не влияют.
- **Анти-RCE для хуков (см. выше):** панель/API намеренно **не** пишут `post_up`/`post_down`.

## [0.7.4] — 2026-06-27

Надёжность UDP: **фрагментация хендшейка** (фикс LTE / мобильных сетей) + фиксы liveness
(реконнект на простое, реап при односторонней загрузке) и учёта RECV. UDP-хендшейк
меняется, но **обратно-совместимо** — новый сервер принимает и старых, и новых клиентов;
**TCP не затронут**, дефолты конфига не менялись. Фикс LTE требует обновления клиента →
порядок выката **сервер → клиенты**. Фрагментация реализована во **всех** клиентах
(Rust / C# / Kotlin); все компоненты бампнуты на **0.7.4**. Старые GUI-клиенты продолжают
работать (на Wi-Fi) до обновления.

### UDP-хендшейк: фрагментация (фикс LTE / мобильных сетей)
- **UDP теперь поднимается на LTE / CGNAT.** Пост-квантовый хендшейк большой (ML-KEM-768:
  ek 1184 Б в ClientHello, ct 1088 Б + cert в ServerHello → CH ≈1440 Б, SH ≈1959 Б), не
  влезает в один датаграм → IP-фрагментируется, а мобильные/CGNAT-сети **дропают IP-
  фрагменты** → ответ сервера не собирается → хендшейк виснет (на Wi-Fi работает, на LTE
  нет). Теперь ClientHello и ServerHello **бьются на ≤1200-байтные чанки на уровне
  приложения** (новый модуль [protocol/udp_frag.rs](qeli/src/protocol/udp_frag.rs)) и
  собираются на приёмнике — IP-фрагментация не нужна. Затрагивает только **хендшейк**; на
  дата-плоскость, скорость и трафик не влияет. ([server/udp_handler.rs](qeli/src/server/udp_handler.rs),
  [client/mod.rs](qeli/src/client/mod.rs))
- **Обратно-совместимый сервер:** новый сервер понимает и фрагментированный ClientHello
  (новые клиенты), и одиночный (старые 0.7.x клиенты), и отвечает в том же виде — старый
  UDP-клиент продолжает работать (на Wi-Fi). Анти-амплификация и анти-флуд (bounded
  reassembly, таймаут, потолок) сохранены.
- **Реализовано во всех клиентах** единым wire-форматом: Rust (server + client,
  [udp_frag.rs](qeli/src/protocol/udp_frag.rs)), C# `UdpFrag.cs` (qeli-shared → Windows /
  macOS), Kotlin `UdpFrag.kt` (Android). Проверено на лабе (все 3 UDP-режима fake-tls /
  quic / obfs) и на **живом проде**: с дропом IP-фрагментов (эмуляция LTE) хендшейк
  проходит, IP-фрагментов — 0; старый клиент падает (контроль). Все компоненты → **0.7.4**.

### Исправлено — UDP idle/download liveness
- **Сервер: устранён реконнект на простаивающем UDP-туннеле.** Сервер слал клиенту
  heartbeat только если тот «молчал» ≥ interval (idle-gate по `client.last_activity`), но
  клиентские keepalive'ы сами обновляли `last_activity` → сервер вечно считал клиента
  активным и **не слал ничего**. RX-liveness клиента считает только server→client, поэтому
  на полностью idle-туннеле клиент видел `no data from server for >Nс` и реконнектился
  каждые `rx_dead = max(3×heartbeat, 30с)`. Теперь сервер бьёт beacon **безусловно** каждому
  аутентифицированному клиенту раз в interval ([udp_handler.rs](qeli/src/server/udp_handler.rs)).
- **Rust-клиент: устранён реап живой сессии при односторонней загрузке.** Keepalive клиента
  гейтился по `last_activity` (TX+RX), поэтому клиент, который только **принимает** (download
  без upload), переставал слать → серверный reap по «no inbound» убивал сессию через
  `reap_after`. Теперь keepalive гейтится по нашим отправкам (`last_tx_inst`) — как в TCP-пути,
  корректном изначально: download-only клиент шлёт keepalive при TX-молчании и держит сессию
  ([client/mod.rs](qeli/src/client/mod.rs)).
- Managed-клиенты (Android / Windows / macOS) **не затронуты**: их heartbeat безусловный,
  download-only бага у них не было.

### Исправлено — учёт трафика
- **UDP RECV всегда показывал `0 B`.** Счётчик `bytes_recv` на UDP инициализировался, но
  **никогда не инкрементился** на приёме (на TCP считался — [handler.rs](qeli/src/server/handler.rs)),
  поэтому `list-clients` для любого UDP-клиента показывал `RECV 0 B` даже при активном
  трафике (download: `SENT` рос, `RECV` стоял на нуле). Теперь входящие (client→server) байты
  учитываются — общий `AtomicU64` между `UdpClient` (RX-путь) и `SessionShared` (его читает
  `list-clients`), по аналогии с `bytes_sent`. Чисто индикатор — на сам туннель/сессию не
  влияет ([udp_handler.rs](qeli/src/server/udp_handler.rs)).

### Клиенты — Windows/macOS: импорт INI (паритет с Android)
- **Импортированная `qeli://`-ссылка / INI теперь сохраняет выбор маршрутизации.** Десктоп-
  парсер `VpnConfig.FromIni` (qeli-shared → Win+mac) не читал ключ `gateway`, поэтому импорт
  конфига со **split-tunnel** (`gateway = false`) молча приходил как **full-tunnel** —
  приходилось переключать вручную в редакторе. Теперь `gateway` читается (→ `AddDefaultGateway`
  / `RoutingMode`) и пишется в `ToIni` (выбор переживает экспорт/сохранение). Также добавлен
  разбор `dns` (резолвер-список; mode-слова `off/tunnel/system` толерантно игнорируются) —
  паритет с Android-фиксом из 0.7.3. GUI-тумблер маршрутизации и так работал; правка касается
  только импорта/экспорта плоского INI. ([VpnConfig.cs](qeli-shared/QeliShared/Model/VpnConfig.cs))

### Документация
- **CONFIG.md (ru/eng):** описана формула окна RX-liveness `rx_dead = max(3 × heartbeat, 30с)`,
  её настройка через `obf.heartbeat.interval_ms` и зависимость детекта от включённого heartbeat.

## [0.7.3] — 2026-06-25

Клиентские правки (Android tun-сетап и INI-конфиг), перевод Linux kill-switch на
iptables и полиш веб-панели. Сетево совместимо с 0.7.2; дефолты конфига не менялись.

### Клиент — Android: INI-конфиг
- **split-tunnel теперь выбираем через INI.** Раньше INI всегда давал full-tunnel
  (режим маршрутизации не читался и не писался), а split-tunnel выбрать было нельзя
  (UI-тумблера нет, а редактор при сохранении ре-сериализует в INI и терял режим).
  Добавлен ключ `gateway` (как у Rust-клиента): `gateway = false` → split-tunnel;
  дефолт — full-tunnel. Читается И пишется, так что выбор переживает сохранение.
- **Устранён конфликт смысла ключа `dns`.** На Android `dns = 1.1.1.1, 8.8.8.8` —
  список резолверов, а в Rust/роутер-конфиге `dns = off|tunnel` — это РЕЖИМ. Теперь
  Android распознаёт `off`/`tunnel`/`system` как режим и откатывается на дефолтные
  резолверы, а не пытается добавить «off» резолвером (что роняло `establish`).
- **Тонкая настройка реконнекта/таймаута:** ключи `reconnect`, `reconnect_retries`,
  `reconnect_base_delay`, `reconnect_max_delay`, `timeout` (Android-экстра; пишутся
  только при отклонении от дефолтов). Desktop/router-ключи (`kill_switch`,
  `autostart`, `dev`, секция `[logging]`) толерантно игнорируются без ошибки.

### Клиент — Android: tun-сетап
- **Фоллбэк на IPv4-only при отказе IPv6.** Если прошивка отклоняет IPv6-адрес
  захвата (`fd00:71e1::1/128`) на `VpnService.Builder.establish()` (ошибка
  `Cannot set address`, всплывала мимо `try/catch`), туннель теперь **повторно
  поднимается без IPv6** (IPv4-over-VPN) вместо полного отказа подключения.

### Клиент — Linux kill-switch на iptables
- **Переведён с nftables на `iptables`+`ip6tables`** (единый firewall-бэкенд проекта,
  как `server/nat.rs`): выделенная цепочка `QELI_KS` в `filter`, прыжок с верха
  `OUTPUT`, терминальный `DROP`; разрешены lo / tun / DHCP(67) / DNS(53) / IP сервера.
  Верификация каждого правила через `-C` (коды возврата iptables-nft врут),
  идемпотентный teardown, fail-safe lifecycle сохранён. Побочно: теперь работает на
  Keenetic (там iptables, не nft). Прогнано в netns на лабе (правила / блокировка
  egress / idempotency / fail-safe — все сценарии PASS).

### Клиенты — индикатор доступности UDP-профилей (Android / Windows / macOS)
- **Исправлен ложно-красный статус UDP-профилей в списке.** Проба доступности (PING ALL /
  цветная точка у профиля) для UDP-режимов слала «урезанный» ClientHello БЕЗ
  post-quantum доли (`buildClientHello` / `BuildClientHello`), а сервер с 0.7.1 требует
  гибридный X25519+ML-KEM ([[PQ-туннель]]) и на не-PQ hello **молча не отвечает** →
  таймаут → красная точка даже на полностью рабочем/доступном UDP-профиле (в т.ч. при
  ОТКЛЮЧЁННОМ VPN). Проба теперь шлёт **тот же гибридный hello** (`buildClientHelloPq` +
  ML-KEM-768), что и реальное подключение — `MlKem.generate()` (Android) /
  `MlKem.Generate()` с освобождением нативного хэндла (Windows/macOS). Теперь UDP-точки
  зелёные, когда сервер реально доступен, и красные только при настоящей блокировке UDP.
  TCP-профили не были затронуты (там проба — простой `connect`, без hello). Чисто
  индикатор — на сам туннель не влияет. На Android вдобавок: активный подключённый
  профиль красится зелёным сразу (пробовать его через уже поднятый full-tunnel
  ненадёжно). Сборки: Android APK пересобран (BUILD SUCCESSFUL, vc703); Windows и macOS
  компилируются без ошибок. Rust CLI и веб-панель такой пробы не имеют — не затронуты.

### Веб-панель
- Полиш UI клиент-менеджера (кнопки / иконки / бейджи / модалки), светлая тема
  логов и редакторов, единые высоты дропдаунов (фикс схлопывания селектов во flex-ряду).

### Безопасность / гигиена (внешний аудит 2026-06-25)
Точечные defense-in-depth правки по внешнему аудиту. Бóльшая часть пунктов аудита
оказалась ложной/by-design (low-order DH уже `*_checked` на критическом пути хендшейка;
`password_command` — by-design; REALITY не валидирует cert — by-design, внутренний
туннель шифруется независимо; FFI-хэндлы управляются своим кодом, не атакующим).
Внесены подтверждённые:
- **FFI/JNI хэндлы — generation-checked registry вместо сырых `Box`-указателей** (C-1).
  Раньше C-ABI/JNI-функции (`qeli_realtls_*`, `qeli_mlkem_*` и их JNI-двойники)
  кастовали хэндл в сырой `*mut` и слепо разыменовывали — кривая обёртка (двойной
  `free` / use-after-free) давала UB в нативной памяти. Теперь хэндл — непрозрачный
  токен `(generation<<32)|index`; устаревший/повторный токен отбраковывается
  (чистая ошибка/no-op), а не разыменовывается. Токен по-прежнему pointer-width →
  **ABI и C#/Kotlin-обёртки не менялись**. Паника в операции инвалидирует слот
  (poison-on-panic). Новый `protocol/realtls/registry.rs` + юнит-тесты (double-free /
  use-after-free / stale-generation / panic) + FFI-уровневый тест `freed_handle_is_inert`.
- **Сессионные токены веб-панели подписываются отдельным случайным ключом** (H-4).
  Раньше HMAC-ключ = Argon2-хеш админ-пароля → чтение конфига позволяло подделать
  сессию. Теперь ключ = `HKDF(ikm = случайный per-process секрет, salt = password_hash)`:
  утечка конфига больше не раскрывает ключ подписи, а смена пароля по-прежнему
  инвалидирует все сессии. Сессии заканчиваются при рестарте демона (re-login).
- **route-JSON в AUTH OK собирается через `serde_json`**, а не ручным `format!` (C-3):
  значения `cidr`/`gateway` из конфига корректно экранируются (admin-trusted, гигиена).
- **AES-GCM ключи (realtls) зануляются на Drop** — включён feature `zeroize` у `aes-gcm`,
  паритет с ChaCha20-Poly1305 (H-5).
- **CRLF-экранирование непроверенных значений в логах** (`username`, control-команды)
  через `util::log_sanitize` — против log-injection/forging, CWE-117 (H-8).
- **`config.parse_or` логирует warning на непарсящемся значении** вместо тихого отката
  к дефолту (например `max_sessions = abc` раньше молча давал «unlimited») (M-9).

### Прочее
- **Docker** как вариант установки (мульти-arch образ, обе роли, зависимости в образе)
  — см. `GETTING-STARTED.md`.
- Версии → **0.7.3** на всех компонентах; Android `versionCode = 703`.

## [0.7.2] — 2026-06-19

Релиз закрывает находки внутреннего аудита 2026-06-18 и клиент-ориентированного
ревью 2026-06-19 — точечные правки безопасности и надёжности на периферии
(веб-панель + запись на диск + сериализация профилей в клиентах), плюс
public-готовность (политика безопасности, модель угроз, fuzzing-харнес). Сетево
полностью совместимо с 0.7.1; дефолты конфига не менялись.

### Безопасность
- **Веб-панель: CSRF больше не ломает доступ через домен/reverse-proxy.** Проверка
  same-origin сверяла `Origin`/`Referer` только с `bind`+loopback, поэтому панель
  на публичном bind (или за прокси с доменом) **загружалась, но любой POST/PUT/DELETE
  получал 403** — браузерный `Origin` (напр. `panel.example.com`) не совпадал с
  адресом bind. Теперь к разрешённым origin'ам добавляются `web.public_host` и новый
  список `web.allowed_origins` (`host[:port]`; принимается и полный URL). Loopback и
  bind по-прежнему разрешены неявно. Поле выведено в форму панели.
- **Веб-панель: закрыт обход анти-брутфорс/anti-DoS защиты.** HTML-страницы
  (`/`, `/config`, `/logs`, `/users`, `/login`) принимали HTTP Basic и гоняли
  Argon2 **без** rate-limit/tarpit — в обход защиты, что есть на API через
  `AuthGuard`. Это позволяло перебирать пароль админа и заваливать blocking-пул
  memory-hard Argon2 запросами `GET /` с `Authorization: Basic`. Страницы теперь
  аутентифицируются **только сессионной cookie** (новый `auth::is_authed_cookie_only`,
  синхронный HMAC, без Argon2); Basic остаётся только для API под rate-limit.
- **Анти-replay чуть строже:** в `decrypt_packet` валидация padding теперь идёт
  **до** записи счётчика в replay-окно, так что аутентичный пакет с битым padding
  не «сжигает» слот окна.
- **Закрыт pre-auth crash-DoS в `decrypt_packet` (триаж аудита T2).** Поле длины
  записи подконтрольно атакующему и ограничивалось только сверху — короткая
  **UDP**-датаграмма (длина < размера nonce) проходила проверки и роняла срез
  `payload[..NONCE_SIZE]`; при `panic="abort"` это **аварийно завершало процесс
  сервера** одной датаграммой до аутентификации. Срез переведён на
  `payload.get(..NONCE_SIZE).ok_or(..)` + регресс-тест. Триаж прошёл по всем
  парсерам входящих байтов (`protocol/`, `handler.rs`, `udp_handler.rs`) — остальные
  написаны оборонительно.
- **Constant-time проверка TLS Finished в realtls** — сравнение `verify_data`
  переведено с побайтового `!=` на `crypto::auth::ct_eq` во всех трёх точках
  (`client.rs`, sans-IO ядро `sansio.rs`, серверная проверка client-Finished
  `server.rs`). Практически не эксплуатировалось (свежий verify_data на каждое
  соединение + доверие через X25519, не через TLS), но это стандартная TLS-гигиена.

### Надёжность
- **Атомарная запись всех персистентных файлов.** users-БД (хранит все хэши
  паролей, перезаписывается на каждый CRUD из панели), конфиг (структурный и
  raw PUT, `set-web-password`), identity-ключ сервера, panel-secret, self-signed
  web-TLS cert/key и `resolv.conf` пишутся через единый `crate::util::write_atomic`
  (temp в той же директории → `fsync` → `rename`). Обрыв на середине больше не
  оставляет усечённый/битый файл. На Unix — `O_EXCL` + `O_NOFOLLOW` против
  подмены через симлинк (обобщённый H-5) и **сохранение прав исходного файла**
  (0600-секреты не расширяются до umask-дефолта). Дедуплицировал прежнюю
  реализацию из `client/dns.rs`.
- **Android: удалён мёртвый busy-wait в IO-ридерах (триаж аудита T11).** Каналы
  блокирующие → `read()` отдаёт ≥1 или −1; ветка `n==0`+`Thread.sleep`+retry в
  `Stream.readRaw`/`readSomeRaw` была недостижима и не настоящим таймаутом.
  Liveness и так держит дедлайн `rxDead` в data-плоскости.
- **Android: устранено зависание (ANR) при реконнекте.** Сессия, дошедшая до
  CONNECTED и затем оборвавшаяся (рестарт/перегрузка сервера, дрожание Wi-Fi↔LTE,
  взаимное вытеснение сессий двух устройств одного логина), сбрасывала backoff в 0,
  и `connectWithRetry` переподключался **вплотную, без паузы**; шторм лог-бродкастов
  забивал главный поток → UI вис, и тап «Отключить» не доходил (приложение
  закрывалось только через диспетчер задач). Введён **floor 1.5 с между попытками**
  (отсчёт от старта попытки: здоровая долгая сессия реконнектится сразу, а
  sub-секундный флап троттлится), **дебаунс 3 с** для реконнекта по смене сети
  (`forceReconnect` — дрожащая сеть дёргала `onAvailable` многократно), и `appendLog`
  переписан с O(n) `split`/`join` всего буфера на каждую строку на O(1)
  `editableText.delete` + коалесинг автоскролла (один `fullScroll` на кадр).
  Проверено e2e против сервера: обрыв живого туннеля → ровные ретраи по 1.5 с,
  CPU <10 %, без ANR, UI отзывчив; после возврата сервера — мгновенный recovery.

### Android — интерфейс
- **Корректное отображение на низком разрешении / маленьких экранах.** Не было ни
  одного ресурса под размер экрана — все размеры захардкожены под «обычный» телефон.
  Добавлены `values/dimens.xml` (компактные размеры: кольцо коннекта 168dp) и
  `values-sw360dp/dimens.xml` (прежние 200dp для sw ≥ 360dp), так что на sw320
  (480×800 / 540×960 / 320×480 и т.п.) интерфейс больше не теснится, а на обычных
  телефонах вид не меняется. Тулбар лога (три кнопки `wrap_content` без weight →
  «Clear» уезжал за правый край на узких экранах) переведён на равные доли
  (`weight`+`0dp`); фиксированные высоты кнопок заменены на `wrap_content`+`minHeight`
  (текст не режется по вертикали при увеличенном системном шрифте); добавлены
  `maxLines`/`ellipsize` на имени профиля и адресе сервера и автоподбор размера
  (`autoSize`) у значений статистики. Подпись автоскролла укорочена до «Scroll ✓»,
  чтобы галочка-индикатор состояния не отсекалась эллипсисом.

### Сервер — full-tunnel NAT
- **`routing.nat.enabled` теперь реально работает (программирует `iptables`).** Раньше
  тумблер (вкл. «NAT masquerade» в веб-панели) только писался в конфиг, но сервер его
  **не применял** — флаг не читался нигде в рантайме, так что full-tunnel-выход в
  интернет молча не работал. Теперь при старте профиля с `routing.nat.enabled = true`
  сервер сам включает `net.ipv4.ip_forward`, ставит `MASQUERADE` пула на WAN-интерфейс
  (авто-детект через `ip route get`, либо явный `routing.nat.interface`) и MSS-clamp
  форвардимого TCP под MTU туннеля; при остановке/выключении/рестарте правила
  **снимаются** (помечены comment'ом `qeli-nat:<профиль>`, чистятся идемпотентно — в т.ч.
  после нечистого выхода). Используется **только классический `iptables`** (не `nft`,
  не `ufw`). Правила `MASQUERADE`+MSS — обязательные; явные `FORWARD … ACCEPT` —
  best-effort (нужны лишь при FORWARD policy DROP; на хосте со смешанными legacy/nft
  таблицами они пропускаются с предупреждением, MASQUERADE при policy ACCEPT всё равно
  маршрутит). Применение правил проверяется через `iptables -C` (exit-code на
  nft-несовместимой цепочке врёт).
- **Детект отсутствия `iptables`.** Если NAT включён, а `iptables` не установлен — в
  логе сервера `ERROR … NAT requested but NOT applied`, а в **веб-панели** (Dashboard)
  — жёлтый баннер с подсказкой `apt install iptables` (поле `warnings` в `/api/status`).
  У `.deb` `iptables` в зависимостях. Гайд по full-tunnel — в `GETTING-STARTED.md`.
- **Воркер data-плоскости корректно завершается по SIGTERM** (graceful teardown NAT),
  без зависания `systemctl stop` на join блокирующих TUN-ридеров (прямой выход процесса
  после снятия правил; ядро освобождает TUN/fd).
- **Новый пример конфига `config/server-multiprofile.conf`** — готовый шаблон на **9
  профилей** (по одному на wire-режим: reality-tls на :443, остальные на 8443–8450),
  смоделированный с прод-раскладки и **вычищенный от секретов** (PSK/хеши/IP →
  плейсхолдеры). `.deb` ставит его в `/etc/qeli/server-multiprofile.conf.example` рядом
  с исчерпывающим `server.conf.example`. Проверен парсингом текущим бинарём (9/9
  профилей, без ошибок). Дополняет однопрофильный референс, не заменяет.
- **`qeli add-client` работает на свежей установке** (когда users-файла ещё нет). Раньше
  падал с `cannot load users file … No such file` (`.deb` ставит `users.conf.example`, а не
  `users.conf`) — это ломало и документированный сценарий «завести первого пользователя», и
  провижининг. Теперь при отсутствии файла стартует с пустой БД (файл создаётся при
  сохранении); существующий, но битый файл — по-прежнему ошибка.
- **Установщик `install-qeli-server.sh`** (в корне репозитория) — ставит зависимости и
  последний `.deb`, поднимает reality-tls на :443 (full-tunnel NAT), заводит 5 пользователей
  и сохраняет готовые `qeli://`-строки в `/etc/qeli/client-links/`. Запуск от root (sudo
  опционален и не ставится); `QELI_DEB=<путь|URL>` — оффлайн/пиннинг. Проверен e2e в лабе
  (установка→reality-tls→5 строк→сервис→NAT→реальный microsoft-серт на :443).

### Веб-панель — клиентские подключения (Client manager)
- **Панель теперь умеет не только раздавать VPN, но и ПОДКЛЮЧАТЬСЯ к другим серверам.**
  Новая вкладка **Client**: три способа добавить — импорт `qeli://`-ссылки, форма
  (server/user/pass/key/mode/sni/rsid/obfs_key + split/full-tunnel), или **полный raw-INI**
  (режим «Raw INI» / кнопка «Paste INI config») для тонкой настройки ЛЮБЫМ клиентским
  ключом (`dev`/`mtu`/`dns`/`kill_switch`/`bind_static`/`[logging]`…), пишется дословно после
  валидации. **Connect/Disconnect** поднимает/гасит исходящий тоннель, живой статус
  (подключён + хвост лога). Бокс может быть и сервером, и клиентом
  одновременно (релей), или только клиентом. Профили хранятся в `/etc/qeli/clients/<name>.conf`
  (тот же flat-INI, что разворачивает `qeli://`-ссылка).
- **Несколько исходящих тоннелей ОДНОВРЕМЕННО** (к разным серверам / по разным режимам):
  каждому профилю **авто-назначается уникальный TUN-`dev`** (`vpn0`/`vpn1`/…), туннели не
  дерутся за интерфейс — несколько Connect живут параллельно (e2e .11: два сразу, оба AUTH OK,
  vpn0+vpn1). Один и тот же сервер — отдельным профилем (менеджер ключует по имени: один
  тоннель на профиль). Любой режим, не только reality-tls; в форму добавлен чекбокс **QUIC**
  (UDP). NB: несколько full-tunnel конфликтуют за единственный default-route; split-tunnel
  сосуществуют при разных пул-подсетях серверов.
- **Автозапуск исходящих тоннелей при загрузке.** У клиентского профиля появился флаг
  **`autostart`** (ключ `autostart = true` в `[qeli]`): помеченные профили supervisor
  поднимает сам при старте сервиса — после `reboot`/`systemctl restart qeli` тоннели встают
  без ручного Connect. Задаётся **двумя равнозначными путями** — галочкой в форме профиля
  (в списке метка `↻ autostart`) ИЛИ правкой строки в файле `/etc/qeli/clients/<name>.conf`
  (рантайм `qeli client` сам ключ игнорирует — его читает client-manager). Флаг **независим
  для каждого профиля**: автозапускаются только помеченные, остальные ждут явного Connect.
  Документировано в `client.conf`/`client-reality.conf`. E2e .11: 16/16 (autostart после
  рестарта поднимается, non-autostart лежит, toggle-off гасит, file-only-ключ работает).
- **Реализация:** `server::client_manager::ClientManager` ведёт исходящие тоннели как
  дочерние процессы `qeli client` (наследуют `CAP_NET_ADMIN` supervisor'а), Connect = spawn,
  Disconnect = SIGTERM (клиент восстанавливает DNS/маршруты), статус = liveness + лог в
  `/var/log/qeli/client-<name>.log`; API `/api/client/*`; автозапуск помеченных профилей при
  старте (`start_autostart`); на остановке supervisor'а тоннели гасятся. **Безопасность:**
  новые профили по умолчанию **split-tunnel** — full-tunnel (заворот всего трафика) явный
  opt-in с предупреждением в UI (на сервере он может отрезать саму панель/SSH).
- **Клиентский пример конфига `config/client-reality.conf`** (reality-tls) — ставится `.deb`'ом
  как `client-reality.conf.example` рядом с `client.conf.example`.

### Клиенты — ссылки и профили
- **`quic` и `reality_short_id` больше не теряются при сериализации.** Сериализаторы
  клиентов роняли эти поля: C# `ToQeliUri`/`ToConfigJson` и Android `toIni`/`toConfigJson`
  не писали `quic`, а оба `*ConfigJson` — ещё и `reality_short_id` (парсеры их читали).
  Из-за этого профиль **udp+quic** после сохранения/реэкспорта тихо превращался в
  обычный UDP (quic-сервер молчал), а **reality-tls** профиль терял `short_id` и не
  подключался. Все четыре сериализатора дополнены; добавлены round-trip-проверки.
- **Full-tunnel CLI-клиента теперь реально включается.** `route::setup_routes` ставил
  `default via <tun> metric 100`, который проигрывал типовому физическому default'у
  (metric 0) → `mode=full-tunnel`/`add_default_gateway` молча не маршрутил трафик в
  туннель. Заменено на сплит `0.0.0.0/1` + `128.0.0.0/1` via tun (специфичнее `/0` →
  бьёт любой default, не удаляя его; server-bypass `/32` и connected `/24` целы).
  Проверено в изолированном netns. (Стале-замечание про «tun POINTOPOINT без peer»
  неверно: tun = `<ip>/24` + pushed-MTU, tunnel-internal качает 587 Мбит.)
- **`qeli://` корректно кодирует IPv6.** Хост-литерал IPv6 теперь оборачивается в
  скобки (RFC 3986: `qeli://user@[2001:db8::1]:443`) при генерации (Rust `to_uri`,
  C# `ToQeliUri`) и разбирается по границе `]:` в парсерах (Rust/C#/Android), а не по
  последнему `:`. IPv4/hostname не затронуты. (INI `server = host:port` не менялся.)

### Анти-DPI — форма потока (Ось 2B, Фаза 1)
- **Cover-трафик в простое (`obf.traffic_shaping.*`, opt-in).** Закрывает теллы
  DPI-AUDIT 6.2 (периодичный heartbeat-маяк) и частично 6.1 (форма потока =
  «скачивание»). Когда туннель простаивает, сервер шлёт cover-пакеты с паузами,
  сэмплированными **экспоненциально** (Poisson-поток) — вместо фиксированного
  heartbeat (он при включённом шейпинге **заменяется**, чтобы не было метронома) и
  вместо «мёртвой тишины». Cover-пакет — зашифрованная запись с **пустым payload**
  (приёмник отбрасывает, как heartbeat) → **провод не ломается**, старый клиент
  совместим. Реальные пакеты **не задерживаются** (ноль добавленной латентности);
  наполняется только idle, в пределах `budget_bytes_per_sec`. Новый примитив
  `protocol/shaper.rs` (+юнит-тесты), параметры пушатся клиенту. **TCP и UDP, оба
  направления Rust-ядра** (server↔client idle cover) — подтверждено живым захватом
  на лабе (оба направления, оба транспорта: ~непериодичные cover-пакеты, ping 0%
  loss, контроль OFF = мёртвый эфир). **Все клиенты шлют uplink-cover:** C#
  (Windows/macOS, общий `qeli-shared` — `TrafficShaper` + `EncryptPadded`, TCP и
  multipath, build-verified `dotnet`) и Android (Kotlin — `TrafficShaper.kt` +
  `encryptPadded`, TCP и multipath, APK собран 0.7.2).
- **STEALTH (Фаза 2, opt-in `obf.traffic_shaping.stealth` — скорость в обмен на
  незаметность).** Закрывает «download»-tell под нагрузкой (baseline-замер:
  server→client 100% full-MTU, IPT почти константа). При stealth: (1) data-plane
  **rate-cap** до `stealth_rate_mbps` (по умолч. 2 Мбит/с), (2) паузы rate-cap'а
  **заполняются джиттер-cover'ом** (мелкие пакеты вперемешку с full-MTU). Измерено
  харнесом (`scripts/shaping_profile.py`): full-MTU 100%→**81%** (появился микс
  81–1000 Б), IPT CV метроним→**бурстовый (≈1.04)**, rate 666→~2.4 Мбит/с — поток
  перестал выглядеть как высокоскоростной bulk. **Не ломает провод** (cover — те же
  empty-записи). Сервер шейпит downlink для ВСЕХ клиентов; **каждый клиент (Rust,
  Windows/macOS, Android) шейпит свой uplink** (rate-cap + cover-в-паузах). Веб-панель:
  тумблер Stealth + поле rate. Честно: «неотличимо от браузинга» недостижимо (нужна
  сек.-буферизация); stealth даёт «не bulk», не «браузинг». Размер самих data-пакетов
  остаётся full-MTU (для него нужна wire-breaking фрагментация — не делалась).
  **Только TCP-режимы** — на UDP stealth ронял
  throughput (lock-contention), поэтому на UDP игнорируется (остаётся Фаза-1
  idle-cover). Бенч `scripts/bench_stealth.py` (cap 10 Мбит/с): tcp-plain/faketls/
  obfs/reality-tls 442–602 → ~10/10 Мбит/с (чисто, mode-agnostic). См. `docs/{ru,eng}/CONFIG.md`.

### Public-готовность
- **`SECURITY.md`** — политика приватного раскрытия уязвимостей (GitHub Private
  Vulnerability Reporting), область/не-цели, сроки реакции.
- **Модель угроз** — [docs/{ru,eng}/THREAT-MODEL.md]: модели нарушителя, явные
  не-цели и остаточные утечки (корреляция трафика, DNS-метаданные в окне
  kill-switch, Linux-only kill-switch), уровень проверенности (нет внешнего
  аудита самописного realtls).
- **Fuzzing-харнес + continuous fuzzing в CI** — `qeli/fuzz/` (cargo-fuzz): таргеты
  `clienthello`, `packet_decrypt`, `realtls_record` на парсеры недоверенного ввода.
  Отдельный крейт, вне merge-гейта. CI: `fuzz-smoke` (30с на каждый push, build-break
  check) + `fuzz-nightly` (`schedule` 03:17 UTC, 10 мин/таргет, корпус сохраняется
  через `actions/cache` — коверидж накапливается, краш → артефакт). Локально —
  `cargo +nightly fuzz run <target>`.

### Веб-панель — полный ребилд
- **Шапка выровнена:** бренд-полоса сайдбара и топбар контента теперь одной высоты
  (`--topbar-h`) — их разделительные линии совпадают.
- **Настройки профиля одной страницей:** убраны внутренние вкладки секций
  (bind/tun/pool/…); всё в едином скролле + якорная навигация. Верхние вкладки
  профилей сохранены, добавлен тумблер `enabled` на профиль.
- **Панель догнала ядро:** в форму добавлены все ранее отсутствовавшие поля —
  `tun.queues`, `dns.blocklist`, obfs `fronting`/`cipher`/`http2_masking`/
  `traffic_normalization`/`anti_fingerprinting`, TLS `server_names`/`supported_groups`/
  `key_share_entropy`, REALITY `handrolled`/`peek_timeout_ms`, QUIC `cid_length`/`version`,
  `multipath` (stream bonding), perf-буферы и rate-limit/new-session, `auth.bind_static_to_session`,
  `logging.format`, `web.secure_cookie`; в пользователях — `profiles`/`routes`/`allowed_networks`
  и управление группами; на дашборде/конфиге — показ и ротация identity-ключей
  (`/api/identity`), убирающие шаг «зайти по SSH и выполнить show-identity».
- **Единый источник истины:** новый `GET /api/config/defaults` отдаёт
  `ProfileConfig::baseline()`; форма и quick-start строят профили из него — конец
  дрейфу JS-схемы от Rust-структур.
- **Без рантайм-CDN:** Tailwind собирается в статический `app.css`, Alpine.js и
  шрифты Inter/JetBrains Mono завендорены и отдаются с `/assets/*` — панель
  работает на сервере без исходящего интернета. Регенерация: `cd qeli/web-assets && npm run build`.

### Веб-панель — безопасность, локализация, UX
- **axum 0.7.9 → 0.8.9.** Роуты на брейс-синтаксис `{param}`, `FromRequestParts` —
  нативный async-трейт (убран `axum::async_trait`). Тесты-стражи на валидность/захват
  роутов (`web::tests`), чтобы рантайм-паника построения роутера не прошла гейт.
- **Безопасная публикация на внешнем IP** (новые ключи `[web]`): встроенный HTTPS
  (`tls`, rustls/`ring`; self-signed авто через rcgen или свой `tls_cert`/`tls_key`),
  **IP-allowlist** (`allowed_ips`), security-заголовки + HSTS, same-origin CSRF,
  **fail-closed** (публичный bind без `password_hash` не стартует), авто-`Secure`-кука.
- **Локализация RU/EN** — выпадающий список языков в сайдбаре (расширяемый),
  DOM-перевод по словарю без переписывания шаблонов (`/assets/i18n.js`), дефолт EN.
- **Переиздание конфига без пароля.** Сервер хранит обратимо-зашифрованную копию
  пароля (`password_enc`, ChaCha20-Poly1305, ключ `/etc/qeli/panel-secret.key`) рядом
  с argon2-хешем; `POST /api/share` собирает `qeli://`-ссылку/QR **без ввода пароля**;
  для легаси-юзеров — одноразовый сброс. Auth-путь и клиенты не меняются.
- **UX:** дефолтный публичный хост (`web.public_host`) предзаполняет диалог Share;
  выравнивание полей во всех грид-формах (инпут не «прыгает» при многострочном
  описании); якорь-навигация профиля прилеплена вплотную под шапку; фикс отступа на
  странице входа.
- **CLI `qeli set-web-password`** — бутстрап логина панели на свежей установке без
  возни с argon2: генерирует/хеширует пароль и вписывает `web.username`/`password_hash`
  (Argon2id) в секцию `[web]` конфига **с сохранением комментариев** (точечный upsert,
  не перезапись), включает панель (`--no-enable` чтобы только креды). Без `--password` —
  случайный пароль, печатается один раз. Юнит-тесты на INI-правку + e2e на лабе.
- **Документация:** новый гайд панели [docs/{ru,eng}/PANEL.md], секция `[web]` в
  CONFIG.md, пример `[web]` в `qeli/config/server.conf`.

## [0.7.1] — 2026-06-12

Доводка ветки 0.7.x: разбор **двух внешних аудитов** (2026-06-11 и 2026-06-12) +
правки безопасности/надёжности и эргономика ссылок/документации. По PQ-туннелю
**сетево совместимо с 0.7.0**, но изменились несколько **дефолтов конфига** (см. ниже) —
при апгрейде сверьтесь с [CONFIG.md](docs/ru/manuals/CONFIG.md). Полные трекеры аудита
(бóльшая часть находок — ложные): [AUDIT-2026-06-11.md](docs/ru/archive/audits/AUDIT-2026-06-11.md),
[AUDIT-2026-06-12.md](docs/ru/archive/audits/AUDIT-2026-06-12.md).

### ⚠️ Изменения дефолтов конфига
- **H-1 «привязка к сессии» (`bind_static_to_session`)** усилена и включена по
  умолчанию: непиненный/нулевой (`all-zero`) `auth.server_public_key` теперь
  отвергается. Если полагались на анонимное подключение — задайте пиннинг явно.
- **`reality-tls` требует `obfuscation.reality_short_id`** (вместе с пиннингом ключа) —
  без short_id профиль reality не поднимается.

### Безопасность
- Выпущены **M-13 / H-5 / H-3 / H-1** (Rust + C# + Kotlin).
- **L1:** анти-брутфорс по username переведён с жёсткой блокировки на **tarpit**
  (замедление) — нельзя залочить чужой аккаунт перебором имени.
- **T1, T6–T10** + гигиенические правки.

### Исправлено
- **Device-ID: guard от `all-zero`** на всех трёх клиентах — нулевой/битый device-id
  больше не принимается (корректный мульти-девайс учёт сессий).
- Доводка kill-switch и логики reconnect.

### Изменено
- **Человекочитаемые `qeli://`-ссылки:** дефолтный label в `add-client --link` —
  `reality-tls-443` вместо percent-кодированного `reality-tls%20%28443%29`.
- **Документация:** добавлен единый раздел **Команды / Commands** в README; вся
  документация разнесена по локалям **`docs/eng/`** и **`docs/ru/`**.

### Проверено
- Rust (лаба .10): `cargo build` · **194 юнит-теста** · `clippy -D warnings` · `fmt` — зелёное.
- C# (Windows + macOS, .NET 10): `dotnet build -c Release` — 0 ошибок.

## [0.7.0] — 2026-06-11

**Пост-квантовый внутренний туннель** + разбор внешнего аудита (2026-06-11) и фиксы
безопасности/надёжности. **⚠️ Ломающее изменение провода:** во всех режимах кроме
`plain` сервер теперь ТРЕБУЕТ гибридную X25519MLKEM768-долю в ClientHello — нужен
координированный деплой клиент↔сервер (старый клиент к новому серверу не подключится,
и наоборот). Полный трекер аудита (включая ложные срабатывания) —
[AUDIT-2026-06-11.md](docs/ru/archive/audits/AUDIT-2026-06-11.md).

### Пост-квантовая защита
- **Гибридный X25519 + ML-KEM-768 во внутреннем туннеле.** Ключи плоскости данных
  теперь выводятся из X25519 ⊕ ML-KEM-768 (`derive_keys_hybrid`, соль
  `qeli-key-derivation-v2-hybrid`, IKM `x25519‖mlkem` 64 Б) во всех не-`plain`
  режимах (`fake-tls`/`obfs`/`reality-tls`/UDP) — защита от «harvest-now-decrypt-later»
  независимо от обёртки. `plain` остаётся классическим X25519. Сервер отвергает
  не-`plain` клиента без X25519MLKEM768 key_share — **нет тихого PQ-даунгрейда**.
- **ML-KEM для managed-клиентов через нативное ядро.** BouncyCastle 2.6.2 не содержит
  ML-KEM, а `.NET MLKem` привязан к ОС → C#/Kotlin вызывают тот же вердифицированный
  Rust-крейт `ml-kem` по C-ABI / JNI (`qeli_mlkem_keygen/decapsulate/free`,
  `Java_com_qeli_MlKem_*`). Новые `Crypto/Mlkem.cs` и `com/qeli/MlKem.kt`,
  методы `BuildClientHelloPq` / `ParseServerHelloPq` / `DeriveKeysHybrid` во всех
  клиентах; нативные `qeli.dll` / `libqeli.dylib` / `libqeli.so` пересобраны.
- Проверено вживую на лабе: `tcp-faketls` / `tcp-obfs` / `udp-faketls` — гибридный
  handshake + трафик 570–700 Мбит/с TCP, 0 % потерь; Android APK и оба C#-клиента
  собираются, символы `qeli_mlkem_*` экспортированы.

### Безопасность
- **Lockout-DoS по username устранён (L1).** Жёсткий account-lockout (любой IP мог 5
  фейлами выбить чужой логин) заменён на **adaptive tarpit**: жёсткий лок остаётся
  только по source-IP, а username под активным перебором получает ограниченную сверху
  экспоненциальную задержку (200мс→×2, потолок 3с) перед Argon2. Верный пароль всегда
  проходит (в т.ч. с нового IP), распределённый перебор зарезан. `FailedAuthTracker`:
  `check()` → `check_ip()` + `user_tarpit()`; server-key-proof-фейл считается только по
  IP (`record_ip_failure`). Применено и в VPN-auth, и в веб-панели (форма + Basic).
- **Android: constant-time сравнение auth-proof (T1).** `MessageDigest.isEqual` вместо
  `ByteArray.contentEquals()` (Rust/C# уже были constant-time).

### Исправлено
- **TOCTOU на лимитах сессий (T7/T8).** `max_clients` теперь перепроверяется под тем же
  write-локом, что и вставка (с откатом IP при превышении); `max_streams` — атомарный
  `try_add_stream()` (проверка+push под одним локом). Параллельные connect/JOIN больше
  не проскакивают лимит.
- **Poisoned-lock не рушит живую сессию (T6).** Методы `SessionShared` переведены на
  `lock_or_recover` вместо тихой деградации (`unwrap_or(0)` / `Err→teardown`).
- **Утечка сокета при ошибке подключения (T10).** `OpenBondedStream`/`openBondedStream`
  (Win/Mac/Android) обёрнуты в try/catch — сокет закрывается и снимается с учёта при
  фейле connect/JOIN-handshake.
- **Гонка `DeviceId()` (T9, Win/Mac).** Static-кэш + lock — device-id вычисляется один
  раз на процесс, нет двойной генерации при старте bonded-потоков.

### Прочее
- **Портируемость `set_tcp_keepalive`** ([transport/tcp.rs](qeli/src/transport/tcp.rs)) —
  Linux-специфичные `TCP_KEEPIDLE/INTVL/CNT` теперь под `#[cfg(target_os = "linux")]`
  с no-op фолбэком для прочих таргетов (гигиена; крейт собирается под Linux/musl).
- **Единообразие poisoned-lock** — `reality_borrow` читается с recover-from-poison
  (как `lock_or_recover`/T6), а не `expect` (под `panic=abort` это moot, но
  паттерн единый).

### Проверено
- **Rust (.10, `lab_sync_build.py`):** `cargo build --release` OK · `cargo test --all`
  **188 passed / 0 failed** (вкл. новые L1-тесты `…_tarpits_user…`,
  `username_flood_never_hard_blocks_a_clean_ip`) · `clippy --all-targets -D warnings` 0 ·
  `cargo fmt --check` clean.
- **C# (`qeli-shared` + `qeli-win`, `dotnet build -c Release`):** 0 ошибок.
- **Android (.11):** `gradlew clean assembleDebug` BUILD SUCCESSFUL (40 tasks executed —
  T1/T10 перекомпилированы), APK v0.6.0.

## [0.6.0] — 2026-06-10 — релиз рефакторинга

Кодовая реорганизация, унификация и доводка визуала. **Протокол, крипто и провод не
менялись** — релиз сетево совместим с 0.5.6, замеры 0.5.6 остаются актуальными
([docs/*/reports/BENCHMARK.md](docs/ru/reports/BENCHMARK.md)). Детали C#/Rust-правок —
[docs/*/archive/plans/REFACTOR-PLAN.md](docs/ru/archive/plans/REFACTOR-PLAN.md).

### Добавлено
- **`qeli-shared`** — общая C#-библиотека (.NET 10) для клиентов Windows и macOS:
  крипто (X25519 / HKDF / ChaCha20-Poly1305), протокол (fake-TLS / obfs / QUIC /
  packet-codec), модель `VpnConfig`, ядро дата-плоскости `VpnTunnelBase` (за
  интерфейсом `ITunDevice`), `RealTls` (P/Invoke к realtls-ядру) и таблица
  локализации `Loc`. Устранено ~2700 строк, ранее дословно скопированных между
  двумя клиентами. Платформенная часть (Wintun ↔ utun, WPF ↔ Avalonia, DPAPI ↔
  AES-GCM) осталась в клиентах.
- **`scripts/lab_common.py`** — общий SSH-хелпер (хосты + `connect`/`run`),
  централизует обвязку, дублировавшуюся в ~100 лаб-скриптах.

### Изменено
- **.NET 10** — оба C#-клиента переведены на единый таргет (`net10.0` / `net10.0-windows`);
  версии общих NuGet сведены: BouncyCastle 2.6.2, QRCoder 1.8.0.
- **UI (`MainWindow`, win + mac)** — выровнены колонки: левый бренд-бэнд по высоте
  равен правой статус-карте, поиск и ряд плиток начинаются на одной линии, нижние
  края панелей «список профилей» и «журнал» совпадают, единый ритм отступов 14px.
- **Rust web-API** — форма ответов сведена к хелперам `err_json` / `ok_json`;
  авторизация защищённых ручек — через axum-extractor `AuthGuard` вместо ручного
  `check_auth(&headers, …)` в каждой (auth-проверка на тип-уровне, нельзя «забыть»).
- **Версии → `0.6.0`** на всех компонентах; Android `versionCode = 600`.

### Проверено
- C#-клиенты: `dotnet build -c Release` — 0 ошибок; mac `MainWindow` отрендерён
  (Avalonia headless, светлая + тёмная темы) — вёрстка симметрична.
- Rust: лаб-гейт `scripts/lab_sync_build.py` на сервере — `cargo build` /
  **179 юнит-тестов** / `cargo clippy --all-targets -- -D warnings` — всё зелёное.

## [0.5.6] — 2026-06-06

Унификация версий на все компоненты; полный бенчмарк 10 wire-режимов (вкл. `plain` и
`reality-tls`); cert-borrowing в `reality-tls` (паритет JA3S/цепочки с Xray-REALITY);
NewSessionTicket; раунд хардненинга. См. [docs/*/plans/ROADMAP.md](docs/ru/plans/ROADMAP.md) и
[docs/*/archive/plans/RELEASE-FIXES.md](docs/ru/archive/plans/RELEASE-FIXES.md).

[0.7.4]: https://github.com/litvinovtd/qeli/releases/tag/v0.7.4
[0.7.1]: https://github.com/litvinovtd/qeli/releases/tag/v0.7.1
[0.7.0]: https://github.com/litvinovtd/qeli/releases/tag/v0.7.0
[0.6.0]: https://github.com/litvinovtd/qeli/releases/tag/v0.6.0
[0.5.6]: https://github.com/litvinovtd/qeli/releases/tag/v0.5.6
