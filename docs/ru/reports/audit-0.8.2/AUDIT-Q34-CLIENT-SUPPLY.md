# Q34: зависимости сборки клиентов и подписи Windows

<!-- normative-sync: q34-client-supply-v9 -->

**Актуальный итог 15 октября: DONE в согласованном объёме; критерии и границы — в итоговом разделе ниже.**

**Актуальный статус, 14 октября:** F459 / Q34-F013 закрыт для текущего исходного дерева: принятый граф Tailwind 4 не содержит braces, свежий npm audit возвращает 0. Датированные результаты ниже сохраняют прежние отказы; итоговая проверка описана в конце отчёта. Q34 остаётся IN_PROGRESS; полный план 34/37 (91,9%).

8 октября 2026. F455–F458 / Q34-F009–F012 закрыты в указанном ниже объёме. F459 / Q34-F013 остаётся OPEN. Q34 IN_PROGRESS; полный аудит 30/37 DONE (81.1%), осталось7. Только локальные изменения; без push, deployment и release.

## Находки и исправления

| Находка | Результат |
|---|---|
| F455 / Q34-F009 | npm audit обнаружил selector-parser GHSA-rj75-hqrm-r3gf и source-map-js GHSA-68fv-2mgg-jv7q. Точные overrides7.1.6 и1.2.2 изменили только две записи lockfile. Чистые npm ci --ignore-scripts и сборка CSS PASS; встроенный CSS побайтно прежний. |
| F456 / Q34-F010 | Версия Gradle wrapper закреплена, но checksum скачиваемого архива отсутствовал. Добавлен официальный SHA256 Gradle9.7.1 acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a. Настоящий wrapper принимает проверенный официальный ZIP и отклоняет изменённый ZIP до запуска Gradle. Проверка wrapper-JAR в CI сохранена. |
| F457 / Q34-F011 | Предупреждения NuGet audit не останавливали обычный restore/build. Корневой Directory.Build.props проверяет прямые и транзитивные пакеты начиная с low; NU1900–NU1905 являются ошибками. NuGet.Config задаёт явный официальный источник advisory, не меняя package sources. Три Release restore/build PASS; реальные fixtures с уязвимым пакетом и недоступным источником advisory отклоняются. |
| F458 / Q34-F012 | Windows gate проверял подписи только Wintun. Расширена существующая проверка обеих копий официального WinDivert2.2.2-A: хеши DLL/драйвера/лицензии/отдельных notices, FileVersion драйвера2.2, Valid Authenticode и thumbprint043589F75FCE2795E7F2CC3E526D46784D5DDAB3. Положительный сценарий и четыре реальных отказа на повреждённых/отсутствующих файлах PASS. |
| F459 / Q34-F013 OPEN | Для braces GHSA-vfj7-8cjw-p6xm исправленной опубликованной версии на момент проверки нет: latest3.0.3 и Tailwind v3-lts3.4.19 сохраняют зависимость. Текущий npm audit возвращает1: пять затронутых записей графа от одного advisory. Подавления и заявления о нуле уязвимостей нет; жёсткий npm gate ещё не закрыт. |

npm-пакеты собирают доверенные CSS/templates репозитория и не используются как runtime-парсер VPN/панели. Клиентские INI не менялись. Миграция на Tailwind4 меняет контракт сборки/конфигурации и требует отдельной проверки совместимости CSS. Пробная неопубликованная braces3.0.4 отклонена npm и в репозиторий не попала. Открытый пункт нужно пересмотреть после upstream-исправления либо квалифицированной замены.

## Выполненные проверки и границы

Собственные свежие package/audit cache NuGet, SDK10.0.300: Release build/restore Windows, managed macOS cross-build и QeliConformance PASS. В этих трёх Release-графах известных уязвимостей не обнаружено, включая транзитивные пакеты. Это не квалификация Debug/headless/Linux-зависимостей, актуальности SDK или отсутствия неизвестных дефектов. Обязательный общий conformance с полным tracked-корпусом PASS; selftest Windows-адаптеров PASS. Локальный PacketCodec benchmark:1400bytes,20000iterations,260.953ms,102.328MiB/s; это codec gate, не скорость VPN. Первая неполная scratch-копия провалила восемь обязательных fixture-проверок; полный корпус повторно прошёл их без отключения требований.

Настоящий fixture System.Text.Json8.0.0 отклонён с NU1903. Недоступный только в дочернем fixture источник advisory отклонён с NU1900/NU1905. Глобальные источники NuGet и сетевые настройки ОС не редактировались. Первый запуск SDK сообщил о настройке development HTTPS certificate; исходный лог сохранён. Политика действует для проектов внутри репозитория; отдельные урезанные source-копии должны сохранять корневые файлы политики сборки. Lockfiles .NET и политика SDK остаются отдельной работой Q34.

Независимо скачан [официальный WinDivert2.2.2-A](https://github.com/basil00/WinDivert/releases/tag/v2.2.2); оба x64-файла совпали с bundled по SHA256. В официальном ZIP пользовательская DLL не подписана, SYS имеет Valid-подпись; gate проверяет подпись SYS и закрепляет байты DLL. Notices намеренно различаются и проверяются отдельно. Нет установки драйвера, WinDivert filter, VPN-маршрутизации либо квалификации Windows network VM. Положительный wrapper запускает только Gradle --version с собственным GRADLE_USER_HOME; проверки APK/runtime здесь нет.

Scratch/caches/output находятся в собственных локальных каталогах. SSH, лаба и секреты не использованы. Rust/native source digest прежний: e3fb04a80fc8c2e7334fa5187dacb497ca47b2a79954fcddae45b5d5a533052c; существующие four-target A/B, копии и14SHA подтверждены без пересборки неизменённых Rust inputs. app.css, CHANGELOG и users.html побайтно прежние. Ошибки fixture/encoding/notice-предположений записаны как ошибки harness, без объявления продуктовой регрессии.

`q34-client-supply-20261008`: SEALED 88 files / 404870232 bytes; manifest SHA256 `049420ad624cd500958d4b0a9dacefa18e4142f32ece4d814259da8e36e0e66a`.

Открытые части Q34: SDK, locking/verification .NET/Android, остальные dependency graphs, release payload и текущий exact-SHA Actions admission. Old14 debtDONE+D06accepted; Q29SIGKILLFAIL/ENONET, Q30Apple/callbackOPEN, Q31capacity/source-cut/currentActions и USER_EXCLUDED Mac/iOS/router/Windows network VM сохранены. Нет нового Android runtime/soak либо physical Mac результата.

Источники политики: [Gradle wrapper checksums](https://docs.gradle.org/current/userguide/gradle_wrapper.html#sec:verification), [NuGet audit](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages), [selector-parser advisory](https://github.com/postcss/postcss-selector-parser/security/advisories/GHSA-rj75-hqrm-r3gf), [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).

## 9 октября: F491 / Q34-F045 — APK-builder не должен останавливать чужой Gradle

`scripts/rebuild_apk.py` перед сборкой вызывал глобальный
`pkill -9 -f GradleDaemon` и удалял `/root/.gradle/caches/journal-1`, хотя
собственная Gradle-команда уже использует `--no-daemon`. Имя процесса не
обозначает владельца сборки; этот шаг мог убить другую задачу и повредить её cache.
Глобальная остановка и удаление общего журнала убраны. Gradle управляет своими
блокировками. Команды Rust/Gradle, offline, один worker, зеркалирование исходников,
проверка release-подписи и SHA-загрузка APK сохранены.

Исполнение вынесено в `build`/`main`: импорт больше не подключается к лабе,
ошибочные аргументы отклоняются до SSH, а `finally` закрывает SFTP и SSH при
ошибках открытия/сборки/закрытия. CLI по-прежнему принимает debug по умолчанию
или `--release`; ошибка сборки/подписи завершает CLI неуспешно. Новые тесты
подключены к постоянному CI.

В собственных PID/mount namespaces .11 прежняя точная команда реально убила
подставной сторонний `GradleDaemon` и свой shell, оба с returncode -9.
Shared-cache path был закрыт приватным bind mount; host-процессы и настоящий
cache не были доступны этому воспроизведению. Удаление журнала прежней командой
не заявлено: shell был убит раньше. Исправленная настоящая оркестрация запускает
контролируемый `gradlew`, который возвращает compile failure7; builder правильно
отказывает, а сторонний процесс остаётся жив и marker cache побайтно прежним.
Это проверка процесса и отказа, не запуск настоящего Gradle/compiler/APK.

На Windows:7 новых lifecycle/orchestration методов,38 native recipe и11 workflow
методов PASS. На Linux: те же7 новых методов и отдельное настоящее воспроизведение
конкуренции PASS. Официальный SHA-проверенный actionlint1.7.12 принял четыре
workflow. Входы и полные Linux-логи восстановлены с SHA, собственный каталог удалён
по точному списку после process/fd/mount guards; служба .11,PID777/845 и установленный
CLI75bc сохранены. .10 не использовалась. Исходники ядра/native recipe,14 native SHA,
protected files и прежний OpenWrt source cut неизменны; новый APK не собирался.

Граница: это устранение глобальной остановки и повреждения общего cache.
Builder по-прежнему использует существующие фиксированные source directories;
одновременные APK-сборки разных исходников в этих же directories этим пакетом
не квалифицированы. Release-проверка `apksigner` подтверждает действительную
подпись, но не ожидаемого издателя; текущий подписанный release payload и его
издатель остаются отдельным открытым требованием. F459 braces OPEN; подавлений нет.
Q34 IN_PROGRESS,30/37 DONE81,1%,7 разделов остаются;Q29 SIGKILL FAIL/ENONET,Q30/Q31,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F491 evidence: `q34-apk-builder-20261009`; SEALED 36 files / 1205550 bytes; manifest SHA256 `bf6a65063b2ee57f87813097cb2601d15d075dffa25ebf0a9007139abcaa8bf9`.


## 9 октября: F492 / Q34-F046 — отдельный полный snapshot для каждой APK-сборки

Закрыт дефект общего source workspace сборщика: разные вызовы записывали файлы
в `/root/android-project` и `/root/qeli-src`, поэтому могли смешать исходники и
выходы. Старый фильтр расширений также пропускал 11 tracked-файлов Android,
включая Gradle lockfiles, Java instrumentation receiver и legal inputs; conformance
помещался внутрь Android project вместо соседнего каталога.

Теперь сборщик до SSH требует чистый committed Git tree без скрытых trust flags,
проверяет native provenance и создаёт полный Git snapshot `qeli`, `qeli-android`,
`conformance`, `LICENSE`, `LICENSING.md`. Он сверяет список и Git blob каждого
члена архива, отказывает symlink/unsafe members и export-преобразованиям. На .11
каждый вызов получает собственный `/var/tmp/qeli-apk-build.XXXXXXXX`, свой
Cargo target и Gradle project state. Полный список SHA проверяется после передачи
и после сборки. Native JNI directory задаётся явно. APK и `BUILD.json` сохраняются
в `qeli-android/dist/<commit>-<run>/`, без перезаписи результатов другого вызова.
Неуспешный remote checkout сохраняется для диагностики; автоматической очистки нет.

CLI: debug по умолчанию, `--release` для release. По умолчанию Gradle offline;
`--online` явно разрешает недостающие зависимости при прежних strict locks/checksums.
`--gradle-user-home` и `--android-sdk` принимают абсолютные пути на удалённой лабе.
`--signing-properties` также remote path и допустим только с `--release`;
legacy default `/root/android-project/keystore.properties` остаётся только источником
ключевых параметров. Java Properties корректно разбирает escapes и относительный
`storeFile`; приватная копия с umask077 удаляется в finally. `apksigner` выбирается
из заданного SDK. Это проверено synthetic fixtures, без production release signing.

Реальный snapshot:1046 файлов,25896960 bytes, artifact source commit
`40c644229eb3f91429d6ead272e2428e2ebd320a`. Проверенный builder commit
`82d31cb3bd8567c386236f45668f7f0c6159a890` использует те же выбранные исходники.
Два настоящих каталога были развёрнуты независимо; изменение settings во втором
вызвало SHA-отказ, первый собрал реальный debug APK. Второй конкурентный compiler
не запускался. Свежий host Rust JNI собран за97,89s; финальная проверка использовала
его cache. JVM: 201 tests,0 failures/errors,0 skipped. APK SHA256
`1525e14c4098bca83e3f1557f29c5c9a1d1c85878042c1ea90ef97815b4027ee`; обе JNI совпали с snapshot, упаковка лицензий
прошла полноценный существующий gate; debug-подпись действительна.

71 Windows и22 финальных Linux regression methods PASS; официальный actionlint
проверил4workflow, docs724Markdown/9checks PASS. Сохранены первые отказы: отсутствующий
AGP в offline-cache, неполная SDK-копия harness и ENOSPC при локальном дубликате
Maven-cache. Locks/verification не отключались. Повторный APK использовал явно
разрешённый online-режим, приватные cache/wrapper/SDK из проверенных источников;
нужные Build Tools36.0/licenses скопированы read-only с существующей лабы;
Gradle скачал Platform Tools37.0.1 только в приватный SDK. Последовательное SFTP-чтение
host JNI остановлено уже после успешного build/publication; выход восстановлен через
ограниченный prefetch16 с независимой SHA-проверкой, без повторной компиляции.
Неполный новый архив удалён; освобождены только прежние собственные regenerable
publish-каталоги после проверки2619SHA и сохранности уникальных Qeli-файлов.

APK, host JNI, JUnit XML и все сохраняемые исходники/логи восстановлены с SHA,
оба own remote roots удалены после process/fd/mount guards. Compiler/dependency/SDK
cache исключены из recovery archive как воспроизводимые; их происхождение и hashes
зафиксированы отдельно. Служба .11,PID777/845, установленный CLI75bc сохранены;
.10 не использовалась. Ядро,14 native SHA,protected files/OpenWrt cut неизменны.
Нет установки APK, emulator/VPN runtime, release/expected-publisher qualification
или hosted Actions. Ожидаемый release-издатель и F459 braces OPEN остаются.
Q34 IN_PROGRESS;30/37 DONE81,1%,7 остаются;Q29 SIGKILL FAIL/ENONET,Q30/Q31,
D06 ACCEPTED_LIMITATION,USER_EXCLUDED сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F492 evidence: `q34-apk-snapshot-20261009`; SEALED 127 files / 180541943 bytes; manifest SHA256 `5db226ad94b5c7e764973618383df4955b4b845abd36254b1d9d544907ee3f28`.


## 9 октября: F493 / Q34-F047 — явный проверенный APK для E2E

Четыре installer-сценария e2e_android_faketls.py, e2e_android_udpquic.py,
e2e_android_bonding.py и e2e_final.py брали APK из общего /root/android-project.
Read-only .11 inventory подтвердил там SHA324e19e8…, отличающийся от нового
проверенного APK1525e14c…. Три сценария игнорировали exit status: точные старые
csh/a/install expressions продолжали исполнение при контролируемом Failure/rc7.
В e2e_final отказ установки попадал в finally перезапуска канонического сервера.

Общий android_apk_input.py требует --apk-receipt до SSH и импорта необязательной
SSH-библиотеки. Явный BUILD.json выбирает соседний app-debug.apk. Проверяются debug
variant, размер/SHA, существующий source commit, совпадение выбранных Git source
trees с чистым HEAD и native provenance. Bytes замораживаются до подключения;
перенос всей пары файлов допустим, старое абсолютное local_artifact не управляет
чтением. Общий/latest APK автоматически не выбирается; release APK отклоняется,
поскольку сценарии используют debug/run-as. Fake-TLS --kill-switch сохранён.

Файл передаётся в собственный mktemp-каталог; remote SHA проверяется до ADB.
Установка ограничена180s и требует rc0, отдельную строку Success и отсутствие
Failure. Finally удаляет точный private blob/root через rm/rmdir. Отказ предшествует
настройке сервера/туннеля; в e2e_final подготовка вынесена перед server restoration
block, оба соединения закрываются при отказе. Shared source/cache не меняются.

Сначала запусти scripts/rebuild_apk.py, затем выбранный E2E с --apk-receipt
"qeli-android/dist/COMMIT-RUN/BUILD.json", заменив COMMIT-RUN каталогом из вывода
сборщика. Требуется чистый repository tree и тот же выбранный source/native input.
Команда benchmark-мануала обновлена в обоих языках.

89 Windows и18 финальных Linux методов PASS; новый suite включён в CI,
официальный actionlint принял4workflow; docs724Markdown/9checks PASS. Настоящий
общий installer на .11 передал прежний проверенный30MB APK в пяти случаях:
success, Success/rc7, Failure/rc0, Success+Failure/rc0 и реальная байтовая подмена
до remote SHA. Приватный контролируемый ADB получил четыре вызова с исходным SHA;
при подмене вызова нет. Пять install roots и два fixture roots удалены после
SHA-восстановления inputs/events/logs и guards. Служба777/845 и CLI75bc сохранены;
.10 не использовалась. Ошибки генераторов/cleanup harness сохранены отдельно:
отказали до подключения либо удаления; финальная очистка подтверждена.

Это проверка выбора/передачи/статуса/раннего отказа, без настоящей установки
в emulator, VPN transport matrix или перезапуска production server. Два REALITY
сценария и production lifecycle, использующие уже установленный клиент без данного
installer path, не объявлены новым runtime PASS. Прежние201JVM/debug APK/legal/
signature результаты унаследованы без пересборки. Receipt связывает выбранные
inputs, не является независимой publisher attestation. Native14/source cut/
protected files неизменны; Q34IN_PROGRESS30/37DONE81,1%,7remain;
F459/Q29/Q30/Q31/D06accepted/USER_EXCLUDED и expected release publisher OPEN сохранены.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F493 evidence: `q34-apk-consumers-20261009`; SEALED 90 files / 1637228 bytes; manifest SHA256 `c6888dfc8edc8712f6f92d98fa9165c5e93e350830c1a2f8b0d9c994e349ac84`.

## 14 октября: F459 закрыт после принятия замены сборки CSS

Проверен текущий commit `67b418ddd5cc8a00f495eb744e77fd18cc73302c`. Вместо Tailwind 3 CLI используется публичный compiler API Tailwind 4.3.3 (`@tailwindcss/node` и `@tailwindcss/oxide`), а watch реализован локальным кодом. Во всех 45 package entries lockfile, включая optional platform packages, отсутствуют braces, micromatch, chokidar и `@tailwindcss/cli`; dependency и optionalDependency edges также проверены. Изменение уже принято коммитом `da776fb892bd6c02b34194a8e772770744832a77`; в этом проходе зависимости не обновлялись.

Свежий `npm audit --package-lock-only --ignore-scripts --json --audit-level=low` через официальный registry выполнен на двух неизменённых Git-снимках. Старый граф `3638b43c145ae2dc9ca609c0811d0b56175548b3` вернул exit 1 и пять high-записей от GHSA-vfj7-8cjw-p6xm. Текущий граф вернул exit 0 и ноль известных уязвимостей всех уровней. Node v24.14.0, npm 11.9.0; suppression, audit=false и audit fix не применялись. Это проверка известных advisory для конкретного lockfile на дату запроса, не доказательство отсутствия неизвестных дефектов. [Upstream advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) остаётся без исправленной версии; находка закрыта удалением уязвимой цепочки, а не заявлением об upstream patch.

Точные CSS/build/watch/template входы сверены с уже выполненными 29 Linux и 29 Windows checks. Встроенный CSS совпал по SHA с Linux build и финальными 36 browser variants / 96 paired states; ноль наблюдавшихся JS/geometry/font/spacing/text/aria отличий. Деревья `qeli/web-assets` и `qeli/src/web` не изменились после принятия патча. Ранее выполненные 131 HTTP asset/auth/CSP/CSRF/INI checks сохранены с собственными датами и CLI SHA; новой сборки, browser или HTTP runtime в этом проходе не было. Исторические F459_closed=false в кандидатных пакетах не переписаны.

Первоначальный запрос в sandbox не прошёл сетевые ограничения; JSON ошибки сохранён отдельно. Разрешённый запрос к тому же официальному endpoint прошёл. Собственный npm cache (5458196 байт) удалён, node_modules не создавались, глобальный cache и исходники не менялись.

F459 / Q34-F013 CLOSED в текущем локальном коде. Q34 целиком открыт: hosted exact-source CI, публичный pin/source publication и полный release admission этим результатом не подтверждены. Актуальные SDK/IPK/native/Linux20 имеют отдельные evidence; full feed compiler bootstrap относится к Q31 и остаётся открытым. 33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q34-f459-current-graph-20261014.json`; локальные raw: `audit-debt-20260924/q34-f459-current-graph-r2-20261014`.

## 14 октября: публичный CI и владельцы в Keenetic fixtures

Read-only GitHub проверка без push/dispatch подтвердила публичный dev e7a90130f0bd206e549d0757819c92dbd0e8e135 и его неизменяемое дерево. Оно отличается от локального qeli/ по24 файлам; публичный запрос source pin ee2b74aafb2a57a2613541223c5522908cb71f71 возвращает404. Успешные соседние runs относятся к Dependabot, а [основной CI](https://github.com/litvinovtd/qeli/actions/runs/38231547743) имеет21 job и три failed jobs. Это существующий run опубликованного e7, не новая проверка текущего локального candidate.

В native-libs job восемь отказов Keenetic fixtures связаны с проверкой root-владельца на непривилегированном runner. Старый тест реально воспроизведён от UID65534. Исправлен только scripts/test_keenetic_templates.py: stat моделирует владельца внутри fixture prefix, сохраняет настоящие права и ошибки отсутствующего файла, а остальные пути передаёт настоящему stat. Production templates и проверка root-владельца не менялись. Добавлены отказ для чужого владельца до публикации и проверка mode/missing/outside-path поведения модели.

Квалифицированы44 случая от root и44 от UID65534:43 успешных unprivileged случая сохранены из r2 и один недостающий случай выполнен в r3; общий r2 FAIL из-за неполного набора входов не переписан. Два первых missing-file отказа проекции сохранены. Installer/rollback/hooks и обе новые проверки прошли; собственные каталоги/remote archives удалены, host/service/firewall/routes/resolver сохранены. Физический роутер, новые Qeli/native/APK сборки и полный Linux20 runtime не запускались.

Остаток существующего CI: macos-build self-test обнаружил расхождение у racing key creators; ios-build имеет Keychain status -34018, принятие -Infinity в numeric managed policy и два несработавших ожидаемых отказа roaming/source-pin. CI iOS tests запускались с CODE_SIGNING_ALLOWED=NO. Требуются отдельная локализация/исправления и exact-source hosted validation; ни причина всех iOS отказов, ни их исправление этим пакетом не доказаны. Исключённые пользователем физические Mac/iOS стенды не заявлены как доступные.

Локальная Linux fixture неисправность исправлена и проверена. Публичный source pin, current hosted CI и полный release admission остаются открыты; source publication не выполнена. Q29 дополнительные supported-network API candidates сохранены отдельно, безопасный generic/null workaround пока не найден. Q34 IN_PROGRESS;33/37(89,2%),NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q34-ci-owner-20261014.json`; raw: q34-public-state-20261014 и q34-keenetic-ci-owner-r2/r3-20261014.

## 14 октября: атомарная публикация сервисного ключа Mac

Локализован отказ `racing key creators` из существующего macos-build CI. Helper `ServiceKeySelection.PublishExclusiveFile` применял `File.Move(..., overwrite: false)`: Unix-реализация .NET допускает проверку отсутствия файла перед обычным переименованием, поэтому другой создатель может опубликовать ключ между этими действиями. Исходная реализация реально воспроизвела отказ в Linux при 32 повторениях гонки четырёх создателей. [Исходник .NET 10](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/IO/FileSystem.Unix.cs) подтверждает этот путь; Windows baseline прошёл.

Рабочий Mac-демон уже использовал `renameatx_np(RENAME_EXCL)` с проверенными directory fd; обнаруженный CI отказ не доказывает гонку именно этого production пути. Теперь демон и helper используют один `PublishExclusiveMac`. Сохранены directory fd, проверки root/типов/прав, no-follow, приватный полный temp-файл, flush/fsync и очистка. Linux helper атомарно публикует готовый файл через hardlink, Windows сохраняет платформенный File.Move. EEXIST означает проигранную публикацию, включая dangling symlink; остальные Unix ошибки наблюдаемы, небезопасного copy/rename fallback нет.

Добавлены 32 гонки четырёх создателей с проверкой единственного победителя и одинаковых прочитанных ключей, отсутствие temp-файлов, права0600 и запрет замены dangling symlink. SDK10.0.401 скомпилировал целые ServiceState/ServiceProfileCodec и настоящую shared model library; восемь Windows checks прошли на runtime10.0.12. В Linux старый код дал FAIL, исправленный дал10 PASS от root и10 PASS от UID65534. Итого28 checks на закреплённом SDK/runtime; отдельные SDK10.0.300 проверки supplemental, не новая macOS квалификация. Первый неполный compile fixture без BoundedStorage и первоначально занятый собственным compiler server SDK сохранены как ошибки подготовки; настоящая зависимость добавлена, собственный server остановлен.

Собственные Windows SDK и Linux runtime/root/archive удалены с проверкой; исходные архивы сохранены, службы/firewall/routes/resolver лабы не изменились. Apple syscall runtime, полный UI build и current hosted CI не выполнялись: физический Mac исключён пользователем. iOS Keychain/numeric-policy/roaming failures, публичный source pin и hosted admission остаются отдельными открытыми пунктами Q34. 33/37(89,2%),NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q34-key-publication-20261014.json`; raw: q34-key-publication-20261014.

## 14 октября: три отказа iOS и подготовка исправленного CI

Сравнение Git blobs подтвердило: ManagedConfiguration, KeychainStore, ConfigCore, VPNConfig/Projection и Rust editor/client в существующем публичном e7 CI совпадают с локальной базой212456f7. Старые ошибки относятся к тем же компонентам; это не новый запуск текущего candidate.

MDM reader принимал отрицательную бесконечность как false в существующем Apple CI. Перед NSDecimalNumber теперь явно проверяется number.doubleValue.isFinite; NaN и обе бесконечности отвергаются до конвертации, точные целые и legacy boolean0/1 сохраняют прежнюю обработку. Version-тест дополнен отрицательной бесконечностью. Это исправление по исходному коду и старому воспроизводимому CI-отказу: свежие Swift compile/tests НЕ выполнены. Локально нет Swift/Xcode; Linux-лаба тоже без Swift, официальный toolchain имеет размер1122730813 байт и в этом проходе не скачивался. Apple runtime исключён пользователем; нельзя объявлять numeric тесты прошедшими.

RoamingPolicyTests ошибочно требовал отказа toINI для required+local/lport. Общий export специально сохраняет невалидный INI draft для редактирования; validate/runtime/URI выполняют строгую проверку. Тест теперь проверяет сохранность IPv4/IPv6 local и lport при export/import, отсутствие roaming eligibility, отказ validate/runtime/валидирующего init и разрешённый lport0. Настоящий текущий Windows native ABI с platform=ios прошёл32 DTO requests: экспорт сохраняет параметры, required+pins запрещены на validate/runtime/URI, auto+pins сохраняет reconnect fallback. Swift bridge и Apple runtime этими запросами не исполнены; Rust parser не менялся.

Keychain -34018 означает отсутствие разрешённой access group; Apple рекомендует проверять [entitlements именно собранного приложения](https://developer.apple.com/forums/thread/114456). Existing CI отключал подпись тестового host. Тестовый шаг теперь делает ad-hoc build-for-testing для Debug simulator, проверяет настоящую codesign signature и effective shared-Keychain group собранного Qeli.app, затем test-without-building в том же derivedDataPath. Device signing/provisioning policy и production KeychainStore не менялись. Simulator preflight переиспользует signed-entitlement reader IPA-verifier; запрос codesign ограничен30 секундами и наблюдаемо отказывает при timeout/launch failure. Список симуляторов хранится в RUNNER_TEMP. Это подготовленная CI коррекция, а не доказанный PASS настоящего Keychain.

11 новых portable signing-admission методов и6 существующих IPA методов PASS. Настоящий pinned actionlint принял все workflows; пять точных CI shell fixtures подтвердили успешный порядок и остановку при selector/build/entitlement-check/test отказах. Apple commands в этих fixtures — явные stand-ins. Первоначальные wrapper quoting и Windows-CRLF projection отказы сохранены; первая лаба и исправленный второй запуск очищены с сохранением host/service/firewall/routes/resolver. Новых SDK/native/CLI/VPN сборок, реальной Apple подписи или hosted workflow dispatch не было.

Q34 остаётся IN_PROGRESS: настоящий signed simulator Keychain, изменённые Swift tests, актуальный Mac CI и публичный source pin ещё не подтверждены. Q29/Q31/Q36 обязательства не изменились.33/37(89,2%),NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q34-ios-ci-contracts-20261014.json`; raw: q34-ios-ci-contracts-20261014 и q34-ios-ci-shell-r2-20261014.

## 15 октября: принят проверенный native atomic cleanup

Фикс 7df0ce1fc6daae6565cc1325d064956c82ef6189 запоминает временный путь до write/flush/fsync и использует общий atomic helper для evidence. При отказе прежний destination сохраняется, собственный temporary удаляется. Проверены 14 методов проекта на Windows и 14 на Linux; успешный формат evidence не изменился.

Новый build input потребовал пересборки библиотек: независимые A/B совпали для Android arm64/x86_64, Windows x64 и universal macOS. Проверены 22 Windows ABI, 23 JNI и 2 packaged INI на Android14/API34/x86_64, экспорты и восемь canonical/consumer копий. macOS runtime не заявлен. Собственные roots/unit и временный swap удалены. Native digest `f89a6526de575a292d600cd77e4b3dae6ca8cfd6fd5a9d34001a959268edcfa3`. [Evidence](../../../../release/certification/evidence/q31-native-atomic-cleanup-20261015.json).

Существующие 20 Linux результатов сохранены по неизменности Rust product tree и 50 зависимостей matrix; новых Linux runtime не заявлено. Q29 DNS, source-built SDK consumer и public/hosted qualification открыты. 34/37 (91,9%); полного release PASS нет.


## 15 октября: завершение Q34 в dev

**Q34 DONE в согласованном объёме.** Все 19 обязательных jobs CI на точном
`9fa0903a191aea54019a2ba293c709d740c661de` прошли; два scheduled fuzz jobs
не запускались по условиям workflow. Подтверждены строгие dependency gates,
сборки Windows/macOS/Android, настоящие signed iOS simulator/Keychain tests,
Android API29/API35, четыре router target и пакеты. Это дополняет прежние
проверки locking/checksum/license/source binding и отрицательные fixtures.

В промежуточном CI API29 обнаружена гонка самого lifecycle-теста: действующий
callback мог опубликовать carrier между записью sentinel и проверкой старого
callback. Assertion теперь удерживает тот же lifecycle monitor, что и служба.
Production callback и его проверки владельца не менялись; тест не отключён.
Исправленный API29 job прошёл. Исходный FAIL и журнал сохранены. Пропуски
live-VPN тестов в hosted jobs не считаются выполненными Q29 сценариями.

После rustls0.23.46 выполнены новые native A/B, ABI/JNI/INI/APK и SDK/IPK
проверки. Новый factory release CLI с jemalloc `dbf16592…` прошёл 20 Linux
сертификационных случаев: 19 реальных запусков, 409 assertions, IPv4/IPv6,
DNS, MTU/PTB, TAP/NDP/RA, legacy peer и по 100 TCP/UDP roaming flips.
Старые бинарник, даты и результаты не переименованы. Это ограниченная
функциональная матрица, а не новый восьмичасовой soak.

| Критерий | Результат |
| --- | --- |
| Review и мёртвый код | Dependency/SDK/locks/notices/source/workflow/native/release reports и адресные исправления завершены |
| Штатные, граничные и негативные сценарии | Все 19 текущих обязательных CI jobs, feature/package gates и новые Linux20 PASS |
| Отказы и конкуренция | Сохранённые baseline/CI FAIL, atomic writer/publication checks и исправленный API29 fixture |
| Интеграция и целевая платформа | Hosted Windows/Mac/iOS/Android/router, актуальные SDK/IPK и native A/B; физические исключения сохранены |
| Исправления, повторная проверка и evidence | Публичная dev/source history, свежие runtime receipts, provenance и привязка certification |

[Сводка критериев](../../../../release/certification/evidence/q31-q34-dev-closure-20261015.json)
и [новая Linux-матрица](../../../../release/certification/evidence/q34-dev-linux-runtime-20261015.json)
сохраняют точные SHA, даты, пределы и очистку. Ошибка redundant stop уже
выгруженного systemd unit возникла после успешной сборки CLI и удаления
его собственного root; отдельная read-only проверка подтвердила результат
без повторной компиляции. Ошибки локальной подготовки матрицы также сохранены.

Физические Mac/iOS/router/Windows network VM остаются USER_EXCLUDED; 21
физическая строка certification не превращена в PASS. Теги, release и deploy
не создавались. Текущий итог — 36/37 (97,3%); Q29 generic/null API34 ENONET
остаётся открыт. Отменённый VPN bypass не возвращён. Исторические OPEN и
счётчики выше не являются текущим остатком.
