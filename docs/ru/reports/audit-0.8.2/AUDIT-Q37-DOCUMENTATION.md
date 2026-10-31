# Q37: документация и тестовая обвязка — 11 октября 2026

<!-- normative-sync: q37-documentation-baseline-v13 -->

**Статус на 12 октября: DONE в согласованном объёме; 32/37 (86,5%).** Ниже сохранена история проверок 11–12 октября; прежние промежуточные статусы не переписаны.

Q37-F001: после правки updater из OPERATIONS исчезли versioned attestation examples, хотя `sync_version.py` продолжал требовать их в RU/EN. Исходная проверка упала на двух unmatched patterns. В оба руководства возвращён конкретный `gh attestation verify` для опубликованного amd64-пакета 0.8.1 и репозитория litvinovtd/qeli; строгость проверки сохранена. Пять методов на RU/EN проверили актуальный пример, старую версию, исчезнувшую команду, development-версию вместо релиза и точное восстановление версии с сохранением CRLF. Реальные `sync_version.py` и девять checks документации PASS.

Q37-F002: `site/` намеренно private/ignored; тест не мог работать из отдельного Git checkout без этих файлов. Добавлен `--site-root PATH` для настоящего каталога сайта. Проверены реальные RU/EN hub/установка/копирование команд; пять отрицательных сценариев (нет default-входов, неверный каталог, опечатка параметра, отсутствующее значение, удалённые обработчики в временной копии) отказали. Пять SHA входов сайта до/после совпали. Отсутствие сайта не превращается в SKIP/PASS. Исходники сайта и его публикация не менялись; полный статический сайт этим тестом не квалифицирован.

Исходная точка также дала PASS: панель 11 templates/1160 RU strings, 118 editor checks и документация. Дополнительные 97 тестов нативной обвязки и 18 certification gate tests PASS. Это unit/fixture проверки инструментов, не фактические A/B сборки и не успешная certification.


Q37-F003: [удаление недостижимых legacy реализаций](../../../data/audits/audit_q37_dead_legacy_2026-10-11.json). В41 Python/shell файле убраны6320 строк за безусловным отказом. AST подтвердил, что до Python SystemExit допускаются только docstring и future annotations; shell имеет лишь shebang, stderr echo и exit1. Имена и сообщения отказа сохранены, чтобы старые команды не начинали работать; два сообщения больше не рекламируют удалённый формат. Удалён неиспользуемый scripts/client-config.json (1510bytes); единственная ссылка — frozen inventory прежнего fuzz-source snapshot, который сохранён как историческая запись. Всего убрано239053bytes.

Проверены42 настоящих Python refusal stubs (exit1/RETIRED, без stdout), три shell guards и актуальность generated client bindings. Существующий retirement test усилен: возврат тела после отказа теперь ломает проверку. Этот настоящий test отказал при подстановке оригинального source предыдущего commit;38 текущих recipe methods PASS. Никакие старые SSH/deploy тела не выполнялись. INI/parser/runtime/native/benchmark inputs не менялись; JSON для API, внутренней модели и test/evidence остаётся допустимым. Полный feature-aware dead-code review всех модулей ещё открыт.

Q37-F004: [сверка конфигов и документации](../../../data/audits/audit_q37_config_parity_2026-10-11.json). Dedicated client tables теперь покрывают все84 поля общей схемы:81 `[qeli]` и3 `[logging]`. Добавлены три REALITY поля, полные AWG/shaping defaults; исправлены gateway/TOFU/Android exclude/QUIC. Split tunnel шаблона остаётся явным `gateway=false`, default парсера `true`. Комментарии exit-node перенесены на отдельные строки. Восемь методов contract PASS; четыре настоящих метода с оригинальными RU/EN документами отказали. Generated projections, versions и9 docs checks PASS.

Текущий factory CLI35da83fd в отдельном network namespace проверил39 случаев:16 исправленных client INI examples,16 оригинальных examples и7 самостоятельных templates; users.conf реально загружен четырьмя server checks.37 admission PASS и2 ожидаемых отказа старого exit-node; нужные endpoint/pin placeholders и три partial fragments на язык материализованы явно. Входы/команды/exit/SHA сохранены; parse admission не подтверждает подключение, выполнение hooks или data plane. Первый ошибочный harness verdict сохранён; исправлен regex, пересекавший newline, и подстановка документированного pin placeholder.

**Full host gate FAIL сохранён:** на .10 появились три ранее наблюдавшихся legacy FORWARD/MASQUERADE правила в iptables4/legacy4; остальные structural fields без изменений. Это не превращено в PASS и не исключено из сверки. После полного SHA inventory и проверки неактивности удалён только собственный fixture root; VPN не запускался и существующие правила/службы не менялись. Native input digest7d42e38f остался прежним; Q35 на .11 продолжается. Полный Q37 и общий итог30/37 DONE81,1% не изменены.

Q37-F005: [серверные defaults и все INI-примеры CONFIG](../../../data/audits/audit_q37_server_parity_2026-10-11.json). Обе справки явно описывают все134 скалярных присваивания default, извлечённые из INI-reader профиля/auth/web/logging. Source guard разрешает serde default-функции/литералы/константы и отличает sparse roaming=false от true в новом шаблоне, пустой DHCP listen от runtime-подстановки. Это не полная проверка optional/list/user/group и не подтверждение всех Rust defaults в runtime. Настоящий guard отвергает оба исходных мануала; новые проверки включены в CI.

Исправлены inline-комментарии серверного exit-node и панели, настройки auth/client binding разделены на секции, устранено пересечение слушателей на нескольких адресах: основной адрес должен быть конкретным, если другой адрес использует тот же порт. Дополнены таблицы bind/TUN/obfs, бондинга, шейпинга, REALITY и глобального auth; уточнён бюджет включённого шейпинга. Контракт84 клиентских полей продолжает проходить.

Текущий factory CLI35da83fd проверил134 итоговых случая:66 исходных и68 исправленных примеров/фрагментов на двух языках. Все ожидаемые результаты квалифицированы:126 admission и8 отказов исходных примеров. Четыре sysctl-входа (до/после на каждом языке) явно исключены. Фрагментам добавлен записанный контекст секции/минимального baseline; endpoint/pin/PHC placeholders материализованы инертными fixture. Соединение, NetworkPlan, hooks, запуск панели и sysctl не проверялись. Первый134-case прогон сохранён с шестью неуспешными verdict, включая ошибочную вставку endpoint в комментарий тестовым сценарием. Повторены только затронутые/изменённые случаи, всего девять дополнительных вызовов. SHA всех финальных материализованных случаев сопоставлены с настоящими upload/results.

Все11 затронутых contract methods, generated bindings, версии, девять docs checks и actionlint четырёх workflows PASS. Первый, третий и четвёртый полные host gates FAIL сохранены из-за изменений iptables4/legacy4 на .10; PASS второго прогона их не отменяет. Каждый собственный fixture удалён после проверки SHA/неактивности/принадлежности; работающие сервисы/firewall не изменялись. Product/native/factory inputs прежние. Полный Q37 IN_PROGRESS;30/37 DONE81.1%. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.


Q37-F006: [опциональные значения, списки, пользователи и группы](../../../data/audits/audit_q37_collection_parity_2026-10-11.json). Сверка охватывает все176 читаемых ключей:123 profile,7 auth,23 web,4 logging,16 user и3 group. Помимо134 скалярных значений проверены41 оставшееся значение/82 сравнения RU+EN; единственный устаревший `tun.netmask` только предупреждает и игнорируется. Это анализ исходников и таблиц, а не исполнение всех Rust defaults. Новый guard входит в существующий CI glob. Реальный тест на исходных документах выявил6 несоответствий RU и4 EN; текущие12 контрактных методов, генератор bindings, версии и9 проверок документации PASS.

Уточнены пустые и повторяемые списки, optional-числа, типы отключённых блоков, наследование ACL и положительных лимитов группы, строгий отказ malformed `listen` и ненулевые REALITY short ID с дополнением до8 байт. Примеры INI не изменены. Factory CLI35da83fd проверил74 сценария и8 дополнительных границ REALITY:30 допусков/52 отказа. После исправления ошибочного ожидания отказа для14 hex-символов все82 решения допуска соответствуют контракту. Исходный FAIL сохранён. Проверены границы16/17 client_subnet,256/257 user routes и10000/10001 DNS blocklist, типы, дубликаты, metadata, маршруты, IPv4/IPv6 и группы; это проверка допуска, не подключения или runtime-наследования.

В11 отказах CLI терял конкретную причину ошибки users.conf при преобразовании `anyhow::Error` в строку. Общий formatter теперь сохраняет цепочку причин в CLI, ответе панели, запуске worker, SIGHUP и control/write/readback. Два Rust-теста проверяют вложенную причину и сохранение типа IO-ошибки. Отдельный ограниченный offline Rust probe с точными helper/tests и четырьмя выражениями вывода воспроизвёл0/3 PASS на старом коде и3/3 PASS на новом. Он не компилирует весь CLI и не подтверждает исправленную диагностику в новом пакете: полный rebuild/release qualification ещё требуется. Старые11 diagnostic FAIL не переименованы в PASS.

**Снимки хоста:** исходная74-case матрица PASS; Rust probe и дополнительная REALITY-матрица FAIL по iptables4/legacy4, остальные структурные поля неизменны. Никаких исключений, удаления правил или изменения служб. Первичный архивный qualifier отказал на одном tar hardlink; без повторной компиляции проверены его целевой entry и SHA содержимого. Исходный отказ сохранён. Архив6138272байта/64 файла полностью проверен, все три собственных неактивных каталога удалены по SHA/cookie/процессным guards. Native source digest изменился на317e722b; текущая Q35/Q36 factory-проверка остаётся доказательством старого35da бинарника. Полный Q37 IN_PROGRESS;30/37 DONE81.1%. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.


Q37-F007: [подключение регрессий, зависимости и безопасный импорт](../../../data/audits/audit_q37_reachability_2026-10-11.json). Проверены 297 Rust-файлов, 306 декларационных связей и 5 точек входа; изолированных файлов-кандидатов не найдено. При проверке учтены OS/features, JNI/C ABI, P/Invoke, Swift bridge, генераторы, router и host-test aliases. 74 разрешения dead_code и 66 extern ABI sites — лексический перечень, который не доказывает использование каждой функции или работоспособность всех платформ. Экспортируемый API и дескрипторы-владельцы сохранены.

Удалены неиспользуемая прямая зависимость mio и production/server-зависимость tower. Tower остаётся транзитивной зависимостью axum и dev-зависимостью тестов панели. Cargo 1.97 пересоздал оба lock-файла в отдельном каталоге. Версии и checksum всех 235 main-пакетов сохранены; изменены только связи qeli→mio и mio→log. Четыре настоящих locked Linux graphs (default/client-bin/transport-core-ffi/fuzz) отличаются только удалением default/log features Mio; net/os-ext/os-poll и остальные package/feature nodes сохранены. Это проверка графов, а не сборка каждой платформы. Legal resources неизменны, кроме lock binding/index; проверены 235 пакетов и 532 записи.

Из 127 test-entry файлов 66 не имели прямого подключения к workflow. В CI добавлены 24 самостоятельных Python-модуля и LuCI fixture из 14 сценариев. Текущая portable suite: 104 теста PASS на Windows; Linux suite: 149 тестов PASS без skips. На Linux также проверены 103 portable-теста до последнего изменения import guard, затем отдельно оба его изменённых метода. Четыре метода admission guard проверяют отказ пустым, неполным, skipped и expected-failure suites и неизвестным группам. 24 ручных lab entrypoints, 16 наборов с обязательными SDK/native/rootfs/kernel inputs и private site остаются отдельными проверками; они не объявлены CI PASS. Новый тест воспроизвёл отказ на старом workflow.

Router model теперь публикует legal sidecar во временный каталог. Новый тест отказал на точной старой реализации helper. Созданный первым прогоном sidecar размером 1 474 055 байт сохранён с проверкой SHA, затем удалён по точному пути. У 23 ручных сценариев выполнение перенесено под main guard. Импорты всех 24 сценариев проверены на Windows и Linux без сетевых действий и вывода. Сравнение AST подтвердило сохранность тела и строковых значений; внешних Python-import consumers не найдено. Guard на исходных 23 файлах дал 23 failures и 0 errors, сами сетевые сценарии не запускались.

Rustfmt исправил оформление одного users-теста и 7 fuzz-target; main/fuzz fmt --check PASS. Первоначальные lock/cache/format FAIL сохранены. Недостающие закреплённые Linux fuzz crates загружены Cargo с проверкой checksum; старый и новый locked fuzz graph затем проверены offline. 38 native-recipe, 17 legal и 4 suite methods, а также actionlint для 4 workflows PASS. Это проверки инструментов и fixtures, а не настоящие native-сборки.

Три внешних host gates FAIL сохранены: legacy4, затем iptables4/legacy4 и ещё раз iptables4/legacy4; прочие structural поля неизменны. Рабочие службы, правила и бинарники не изменялись. Архивы размером 9 298 152 / 9 255 680 / 89 099 байт проверены по SHA, включая все 1712 / 1693 / 29 entries; три собственных неактивных каталога удалены. После первого прогона повторены только исправление lock/format и два изменённых import methods, 149 Linux fixtures не повторялись. Native digest 3538e06c STALE: актуальные сборки и финальная certification обязательны. Q35 продолжает работать на frozen35da. Q37 IN_PROGRESS; общий итог 30/37 DONE (81,1%). LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q37-F008: [локальный CI runner](../../../data/audits/audit_q37_ci_runner_2026-10-11.json). В ci-check.sh тесты и Clippy выполнялись без --locked и без закреплённого Rust; минимальные server/client/FFI профили не проверялись. Runner теперь берёт 1.97.0 из общего native_repro и передаёт Cargo явный +toolchain: системный Cargo без rustup должен отказать. Все команды, разрешающие зависимости, используют --locked. Добавлены server-only/client-only, config_editor, transport-core tests и release build с panic=unwind, C header syntax, conformance freshness, fuzz formatting, минимальный FFI Clippy и уже проверенные самостоятельные audit suites. Это локальное зеркало основных checks; оно не заменяет package/platform qualification.

Новый test_ci_check подключён к workflow и локальному runner. Пять методов действительно исполняют shell с изолированными подставными cargo/python/node/cc: проверяют запуск из другого каталога и paths с пробелами, pin/lock/feature/panic policy, сохранение отказа Cargo при продолжении независимых checks, отказ Node и ранний отказ отсутствующему либо некорректному pin. На Linux все 5 PASS без skips; один новый метод отказал на точном старом runner, исходные UNPINNED_RUST_REFUSED/UNLOCKED_CARGO_REFUSED сохранены. Явный выбор Cargo был уточнён после первого fixture-прогона; оба результата сохранены. Настоящий общий pin также прочитан отдельным Python-вызовом. Rust-компилятор не запускался: это проверка runner, а не успешная компиляция актуального Qeli.

Оба .10 прогона заняли около 4 секунд, пиковая память 20,4 / 21,3 МиБ, swap 0. Начальный host gate PASS, окончательный FAIL сохранён: изменилось поле iptables4. Оба собственных неактивных каталога SHA-архивированы и удалены: 50 672 / 51 111 байт, по 9 entries. Actionlint для 4 workflows и 4 admission guard methods PASS. Native inputs остаются 3538e06c STALE; Q35 по последнему read-only checkpoint дошёл до TCP 5300/10000 и продолжает RUNNING. Полные сборки и certification остаются открыты. Q37 IN_PROGRESS; 30/37 DONE (81,1%). LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**Открытый долг:** `native-libs/provenance.py --check` обнаружил изменение native inputs (recorded e3fb04a8, current abcc1494). Нужны реальные независимые A/B пересборки текущих desktop/Android recipes, сверка бинарных inventories и лишь затем обновление provenance. Штатная CLI-сборка для Q35/Q36 не обновляет библиотеки клиентов. Android-компиляция на .11 ждёт завершения Q35; отдельная .10 проверяется независимо, без общей машины или тестовой сети.

Release certification дала 21 проблему: общий digest и 20 автоматизированных Linux cases относятся к другому дереву. Gate сверяет всё committed tree, кроме собственных evidence; даже новые docs/report commits меняют этот digest. Поэтому сначала фиксируется окончательное дерево release inputs, затем выполняется матрица на нём и обновляется evidence. Повторная запись старых PASS под новый digest запрещена. Пропущенные пользователем физические платформы не объявляются протестированными.

Q35 полный endurance выполняется отдельно; Q36-F029 уже квалифицировал текущую конечную data-plane матрицу в BENCHMARK. Здесь промежуточный Q35 не объявлен PASS. Для полного Q37 остаются компиляторная проверка использования кода и feature targets, а также integration на актуальных сборках. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q37-F009: [реальные тесты минимальных feature-профилей](../../../data/audits/audit_q37_current_units_2026-10-11.json). Исправлены два дефекта обвязки: метка libtest `--nocapture` склеивалась с первой строкой маршрута preflight; переносимый тест usage вызывал helper ошибки directory fsync, доступный только при Linux/server. Helper теперь ограничен только `cfg(test)`. Рабочая логика атомарной записи и сетевые таймауты не менялись. CI и локальный runner запускают библиотечные тесты раздельно с server, client-bin и transport-core-ffi, без default features.

Rust 1.97.0, offline/locked/jobs1: фактический Clippy all-targets PASS, точный preflight regression PASS; server — 2310 PASS/56 ignored, client — 1933 PASS/49 ignored, FFI — 1951 PASS/49 ignored. Ни один ignored-тест не объявлен проверенным. Все полные логи сохранены с SHA; тестировались 920 замороженных входов. Пять Linux shell-policy методов PASS; новый тест отверг прежний runner без минимальных тестов. Проверка CI-стенда сохраняет FAIL для изменения iptables4.

После завершения прогона: все десять фаз PASS, включая INI-editor/examples/server-ini, conformance и штатную release-сборку CLI с jemalloc, fat LTO и codegen1. Новая CLI проверила все 11 отказов users.conf; каждое сообщение содержит конкретную причину, которую старый бинарник терял. SHA новой CLI `886e525ed909037fafe8ea494094c7eb0c0a4f2a0e0f0e44f1cd68a3e966cff5` привязан к исходникам `c69f9c9493412aede854cffe308a9a5b22a77c36`. Это квалификация сборки и указанных диагностик, не полная release integration и не пересборка native libraries.

Пакет результатов запечатан. Архив 653036246 байт и все 17930 файлов проверены по SHA; собственный сборочный каталог и удалённая копия архива удалены. Временный swap 2 ГиБ отключён и удалён; исходный swap сохранён. Host gates: сбор PASS, очистка FAIL; все изменения ['legacy4'] сохранены, правила и рабочие службы не исправлялись ради PASS. Исходные OOM/тестовые отказы остаются в архиве. Native A/B и final certification остаются открытыми; Q37 IN_PROGRESS, 30/37 DONE81,1%.

Q37-F010: [актуальные Windows/macOS native libraries](../../../data/audits/audit_q37_native_current_2026-10-11.json). Штатная Windows FFI-сборка с `-D warnings` выявила четыре ошибки dead code: снимки TCP-счётчиков компилировались без потребителя. Их типы, методы snapshot и импорт Serialize теперь доступны для Linux/client и тестов; подсчёт потерь остаётся в общем ядре. Исправление привязано к `de087865cf65609223a0a0e3970badd47e7116ed`.

Windows x64 и macOS universal x64/arm64 собраны дважды в независимых Cargo/Zig target-каталогах с Rust1.97.0, offline/locked/jobs1, штатными fat LTO/codegen1/panic=unwind. Обе пары побайтно совпадают. Проверены точные 33 C ABI-экспорта Windows и каждого среза macOS, а новая DLL прошла 22 C ABI/localhost-проверки без Wintun и изменения маршрутов. Оба теста TCP-счётчиков PASS. Сохранены первоначальные отказы обвязки: недостающие 12 тестовых файлов, пустой служебный объект линковщика и ошибочное включение имени DLL в список экспортов. После добавления файлов из того же коммита повторены только два теста; A/B не пересобирались. macOS-кросссборка сохранила предупреждения поиска Xcode SDK; физический запуск macOS пользователем исключён и не квалифицирован.

Канонические и потребляемые Windows/macOS копии обновлены одинаковыми файлами; desktop evidence привязано к текущему native digest. Архив 20981357 байт/407 файлов полностью проверен; пересобираемые кеши сохранены как SHA-инвентарь. Собственные сборочные каталоги и временный swap удалены, исходные ресурсы лабы сохранены. Сбор и очистка сохраняют host FAIL по legacy4. Android A/B/JNI, общий PROVENANCE и final certification остаются открытыми; старые данные не переподписаны. Q37 IN_PROGRESS, 30/37 DONE81,1%.

Q37-F011: [актуальные Android native libraries и общий provenance](../../../data/audits/audit_q37_android_native_current_2026-10-11.json). Android arm64-v8a и x86_64 собраны дважды из 327 замороженных входов коммита `b0b156c5625f2e10599065a63dd8e014b33f83ae` с Rust1.97.0, NDK26.3.11579264 и cargo-ndk4.1.2. Каждая пара A/B побайтно совпала; штатные offline/locked/jobs1, fat LTO/codegen1/panic=unwind и `-D warnings` сохранены. Независимо проверены ELF64/архитектура и точные имена всех 55 экспортов каждой ABI: 33 C API, 21 TransportCore JNI, один ConfigCore JNI.

Канонические библиотеки и копии jniLibs обновлены одинаковыми файлами. Обе группы desktop/android теперь имеют действительные A/B evidence для текущего native digest; общий PROVENANCE обновлён только после этой проверки, SHA256SUMS и проверка совпадения всех канонических/потребляемых пар PASS. Архив исходников, логов и результатов целиком проверен по SHA; пересобираемые кеши не дублируются. Собственные каталоги, удалённый архив и временный swap удалены, прежняя таблица swap восстановлена; фактические host gates и изменения сохранены в доказательствах без исключений.

Этот результат подтверждает сборку и экспортируемый API, но не выполнение JNI/VPN на Android. Android runtime/integration после Q35 и final release certification остаются открытыми. Ранее описанные отказы и исторические доказательства не переподписаны. Q37 IN_PROGRESS, 30/37 DONE81,1%.


Q37-F012/F013: [текущий Android package и правила R8](../../../../release/certification/evidence/current-android-package-20261011.json). На точных текущих Android inputs выполнены201 JVM tests через текущую Windows ConfigCore JNI; failures/errors/skipped0. Lint:0fatal/0errors/55warnings; предупреждения сохранены. Собраны instrumented Release/test APK и отдельный обычный unsigned production Release, оба с текущими arm64/x86_64 native SHA. Обычные production ProGuard rules не менялись.

Независимый TraceReferences --check обнаружил устаревшие433 строки instrumented ABI:18 из19 новых требуемых типов отсутствовали под ожидаемыми именами в фактическом DEX. Правила перегенерированы до505 строк; пересобраны только два затронутых APK, все19 типов присутствуют, inferred rules и packaged Trace/superclass ABI PASS. Это воспроизведение build/packaging дефекта, не Android runtime exception. Исходный отказ и старые APK сохранены. Offline cache miss AGP и локальный qualifier minSdkVersion mismatch также сохранены; зависимости разрешены со штатными strict locks/checksums.

JNI Java/DEX harness скомпилирован отдельно. APK/JNI execution в Android ещё не выполнен: .11 занят настоящим Q35 endurance. Новый Linux runtime не приписан:922 frozen CLI inputs и453 frozen helper inputs совпадают,20/409 прежних текущих проверок применимы с исходными artifact/time/source/raw. Native inputs unchanged. Strict automated certification отдельно проверяется после commit; whole preflight/current push CI/OpenWrt source cut остаются OPEN. Q37 IN_PROGRESS,30/37 DONE81.1%; NO_PUSH_DEPLOY_RELEASE.

### 12 октября: 20 Linux-критериев на CLI с исправлением пула

<!-- normative-sync: current-pool-linux-certification-20261012 -->

[Новые результаты и привязка к исходникам](../../../../release/certification/evidence/current-pool-linux-matrix-20261012.json).
На .11 заново выполнены все обязательные автоматические Linux-сценарии на
CLI `52511ceb`: 19 самостоятельных запусков, 409 успешных утверждений,
без отказов; двадцатый критерий отсутствия утечек выведен из реальных проб
14 full/split случаев. Длительность — 595.0 с. Старые результаты
другого бинарника и даты их выполнения не переписаны.

Проверены 12 сочетаний outer/inner IPv4/IPv6 и TCP/UDP fake-TLS/UDP QUIC,
два dual-stack split tunnel, TAP с локальными NDP/RA, настоящие systemd-resolved
и DNS через IPv4/IPv6/принудительный TCP, DATA_FRAG/PMTU на MTU 1280 и ICMPv6 PTB,
совместимость с Qeli 0.7.16 в обоих направлениях, 100 переключений TCP и 100 QUIC.
Для каждого случая проверены команды, исходные журналы, итоговые утверждения,
SHA, отдельные mount/net/PID namespaces и нужные функциональные отметки.

Повторная компиляция не выполнялась: из 916 входов существующей квалифицированной
сборки совпали 915; в buffer_pool.rs заново проверены только две прежние явные
замены пробелов/переносов, без изменения логики, строк и комментариев.
Все 453 входа тестовой обвязки совпали. SHA ELF и legacy-клиента закреплены.
DNS-инструменты, зависимости и учётная запись уже присутствовали на .11;
установка или изменение службы не потребовались.

Все сохранённые файлы проверены по SHA. Структурные снимки всех backend хоста
до/после/после очистки совпали. Production PID/start ticks/бинарники, staged CLI,
DNS-инструменты, зависимости и passwd/group сохранены. Созданный каталог,
удалённый архив и transient unit удалены. Сертификат Linux связан с новым
результатом и проверенной применимостью последующих изменений только документации;
первоначальный source/time/raw этого запуска остаётся отдельным неизменным фактом.

Это закрывает устаревшую привязку 20 Linux-критериев после изменения пула.
Короткий 100+100 soak не заменяет восьмичасовой Q35 release gate.
Старый Q35 performance FAIL, Android SIGKILL/ENONET, полный Android VPN data plane,
hosted CI и остальные открытые критерии остаются за пределами этого PASS.
План: 31/37 (83,8%), Q29/Q31/Q34/Q35/Q36/Q37 открыты. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: Q37 завершён по пяти критериям

<!-- normative-sync: q37-five-criteria-closure-20261012 -->

[Матрица критериев и проверяемые доказательства](../../../../release/certification/evidence/q37-closure-20261012.json).

| Критерий | Основание закрытия |
| --- | --- |
| Review и мёртвый код | 297 Rust-модулей / 306 связей; 59 диагностик четырёх Linux-профилей, 73 проверенных подавления. Удалены 41 retired body и лишние прямые зависимости; внешние API, JNI/C/Swift и RAII сохранены. Последующие изменения покрыты актуальными строгими профилями и native A/B. |
| Штатные, граничные и негативные сценарии | Сверены 84 клиентских поля, 134 server defaults и 176 reader keys; реальные INI admissions и исходные отрицательные случаи сохранены. Текущие 8 schema/docs/generated-adapter методов PASS. |
| Отказы и конкуренция | Текущие 4 admission-метода и 2 метода безопасного импорта 24 сценариев PASS; 5 настоящих Linux CI-fixture методов применимы по точным неизменным SHA runner/test. Пустые/неполные/skipped/expected-failure наборы не получают PASS, отказ дочерней команды сохраняется. |
| Интеграция и целевая платформа | Актуальные четыре native A/B, exports/provenance, 22 Windows C ABI, 23 Android JNI и 2 packaged INI; свежие 20 Linux-критериев / 409 проверок. Исключённые пользователем физические платформы не объявлены проверенными. |
| Исправления, повторная проверка и evidence | Исходные отказы F001–F013 и maintenance сохранены; 915/916 входов текущей CLI совпадают, единственный форматный delta отдельно доказан. Все текущие provenance/docs/version/source gates PASS; owned cleanup и исторические host FAIL сохранены. |

Финальная адресная проверка: 14 методов, без failures/errors/skips; provenance,
документация, версия и строгий Linux-сертификат прошли. Исходная обвязка ожидала
один import method вместо двух: сохранён её отказ по счётчику, оба реально
выполненных PASS квалифицированы из исходного лога без повторного запуска.
Прежние полные Rust suites, 149 Linux fixtures, native/JNI и сетевые прогоны
сохраняют исходные даты и SHA; новым выполнением они не названы.

Q37 закрывает документацию, достижимость, подключение и допуск тестов, а также
проверенную интеграцию изменённой обвязки. Полный Android VPN data plane,
SIGKILL recovery/ENONET относятся к Q29; hosted CI и выпуск — к Q34;
SDK/bootstrap — Q31; старый performance FAIL и полный endurance — Q35;
причина TCP-асимметрии и пределы нагрузки — Q36. Они остаются открытыми,
но не дублируются как неопределённый остаток Q37. Не утверждается, что все
возможные исполнения или все публичные API доказаны семантически достижимыми.

**Q37 DONE в согласованном объёме. Итог: 32/37 (86,5%), осталось 5 разделов:**
Q29/Q31/Q34/Q35/Q36. Полный аудит и релиз ещё не завершены.
Сетевые прогоны и большие сборки в этом пакете не повторялись;
новые кэши компиляции не создавались. `NO_PUSH_DEPLOY_RELEASE`.
