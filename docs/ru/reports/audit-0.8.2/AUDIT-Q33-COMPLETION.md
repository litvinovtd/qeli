# Q33: итоговая сверка установки, обновления, файлов и hooks

<!-- normative-sync: q33-completion-v2 -->

8 октября 2026. Q33 завершён в согласованном объёме. F449/Q33-F052 и F450/Q33-F053 закрыты; retained hook подтверждён настоящими двумя HTTP restore и проверен после исправления, включая новое поколение worker. Точные результаты и ограничения ниже.

## Последнее исправление

Неизменённый hook `sh /etc/qeli/../qeli/owned.txt` исполняет `owned.txt`, однако прежний collector сохранял только `..`. Архив с неизменённым INI и заменой файла без executable-bit проходил этот защитный слой. В Linux-воспроизведении точной старой функции set содержит `..`, проверка защиты `owned.txt` падает. Это воспроизведение collector, не HTTP-эксплуатация и не запуск вредоносного hook.

Теперь restore защищает верхние entries по исходному пути, нормализованному пути и разрешённому существующему префиксу. Последнее покрывает ссылки из внешнего каталога и ещё не созданные файлы в linked directory; alias и target защищаются вместе. Кавычки/escape-пробелы сохраняют настоящее имя. Дополнительный raw scan сохраняет защиту прямых литералов в нескольких уровнях `sh -c`. Если literal top-level внутри `/etc/qeli` содержит переменные или glob либо читается весь managed root, публикация отклоняется консервативно.

Новый Linux gate использует настоящие production helper и `vet_staged_dir`: четыре запрещённые замены сохраняют live/staged bytes, обычный внешний hook допускает data-only validation. Недостижимые `.conf/.ini` ветви standalone wrapper имеют явные panic seams; серверный Cargo-набор проверяет интеграцию без этих seams. Ни один hook в воспроизведении не исполняется.

Предел: статический collector не является shell sandbox. Пути, целиком собранные переменными, runtime `cd`, зависимости внешних программ и конкурентная несогласованная замена ссылок администратором полностью не анализируются. Исполняемые hooks и их зависимости следует держать вне managed backup tree. [Правила restore](../../manuals/OPERATIONS.md).

## Покрытие Q33 без повторения неизменённых сценариев

| Слой | Подтверждённое покрытие | Evidence / предел |
|---|---|---|
| Источник команды | INI parse из того же доверенного descriptor, owner/mode, snapshot cleanup; bounded password command и hooks | [Config trust](AUDIT-Q14-Q33-CONFIG-TRUST.md), прежние Linux hooks/file-IO и budget проверки в [реестре](../../plans/AUDIT-DEBT.md). Shell hooks намеренно являются доверенным операторским кодом |
| Установщик | metadata/arch/version/dependencies; private stages, configs/identity/users/panel, secret journals, failure propagation, root ownership transition | [Admission](AUDIT-Q33-INSTALLER-ADMISSION.md), [secrets](AUDIT-Q33-INSTALLER-SECRETS.md), [config](AUDIT-Q33-INSTALLER-CONFIG.md), [CLI](AUDIT-Q33-INSTALLER-CLI.md), [service user](AUDIT-Q33-SERVICE-USER.md) |
| Update / Debian | actual dpkg fresh install/upgrade/downgrade/rollback/remove, exact installed identity and health; managers preserve state | [Updater](AUDIT-Q33-SERVER-UPDATER.md), [lifecycle](AUDIT-Q33-DEBIAN-LIFECYCLE.md), [binary](AUDIT-Q33-BINARY-INSTALLER.md), [real package manager](AUDIT-Q33-PACKAGE-MANAGER.md): 36 actual checks |
| systemd / полный installer | actual manager sandbox/capabilities, reload/root transition, bad-INI recovery, genuine production release ELF/DEB; binary/deb installer 24 + 24 actual checks | [systemd](AUDIT-Q33-SYSTEMD.md), [package manager](AUDIT-Q33-PACKAGE-MANAGER.md). Нет whole-install/account rollback или power-loss durability |
| Kernel / VPN | partial tuning apply restores previous values/files, failed probe is not PASS; 18-scenario/376-check TCP/UDP4/6/TAP/DNS/MTU/legacy/leak matrix | [package manager](AUDIT-Q33-PACKAGE-MANAGER.md), real release pipeline gate; host settings/services preserved |
| Docker | production runtime image/owned daemon/private NET, volumes/root0600/readonly, pinned H1 VPN fresh/recreate/known-image recovery, 6 graceful exits; publication policy 7 checks | [Docker](AUDIT-Q33-DOCKER-ENTRYPOINT.md): 26 runtime checks. Compiler stage/multiarch/current Actions/registry attestation belong to unresolved release qualification, no claimed publish |
| Backup / files | archive integrity/trust/budgets/locks/cancellation, per-file publication/exact prune, state-key separation, filesystem EIO/ENOSPC/EACCES and earlier native/runtime validation | [Q07 completion](AUDIT-Q07-BACKUP-RESTORE.md); current F449 adds alias/quote/dynamic literal protection. No whole-tree atomicity/automatic rollback/fsync certification |
| Мёртвый код и обвязка | legacy updater URL/cache branch and четыре destructive/status-ignoring Docker harness удалены; scoped harness ownership/exit status/cleanup | updater/admission/Docker reports. Сохранённые original harness FAIL не считаются product PASS |

## Проверки финальной версии

Targeted helper/gate: 14 PASS на Linux. Raw включает ожидаемый FAIL старого collector, промежуточные 12/13 PASS, ошибку UTF-8 standalone fixture и исправленный 14 PASS. Две native-квалификации промежуточного source остановлены только для собственных compiler PIDs после cwd/root guards; rc143 сохранён и не считается дефектом продукта или PASS. Отказы полного Cargo-набора сохранены: отсутствующие conformance fixtures в первом transfer, несовместимый пустой set в одном прежнем test и запуск отдельного IO test без требуемого private-FS/preload setup. Type adapter исправлен; fixture комплект дополнен; IO запускается отдельно с настоящим shim в private MNT/NET/PID. Запрос остановки сначала истёк в automatic approval review; read-only inventory и безопасный retry выполнены отдельно.

Current Linux source e8f5469e: actual CLI build/bin5/backup49 PASS, including two privileged archive tests; standalone14 PASS; the separately isolated IO method passes twice (normal/cancel), heartbeat180/179 and ~2seconds intercepted read each. Full Clippy -D warnings/rustfmt PASS; recipes38 PASS. ELF SHA256 c098a9899ae41042d8ad19ff211aefba1dfed020b753ca33c3dddfbd74f9f289, 78712856 bytes. HTTP exploitation/end-to-end malicious hook execution were not run; publication gate and existing native roundtrip are qualified.
Fresh independent A/B builds PASS for Windows/macOS universal2/Android arm64+x86_64 from e8f5469e, native source digest8d1cc8fa. Six actual compiler commands use fresh separate A/B targets, offline private registries/caches, jobs1 and panic=unwind. Export gates6Reality+22client (+21JNI Android) PASS. All14 SHA/canonical-consumed pairs/provenance PASS; actual refreshed Windows DLL22 C ABI/control/localhost-runner checks PASS (no Wintun/OS routes). New library bytes are recorded; previous ABI results are not relabeled as executions on these files. Mac runtime/iOS/firmware remain USER_EXCLUDED; no new Android full runtime/soak/benchmark claim.
`q33-hook-restore-20261008`: SEALED 133 files / 160469796 bytes; manifest SHA256 `e11346af579035340f8446e1f9917db7ffa9bf87cbd400c827c7b4143fd37c03`.

## Сохранённый hook: F450 / Q33-F053

Подтверждено настоящими HTTP запросами на исходном ELF e8f5469e: готовый worker сохраняет `post_down = sh /etc/qeli/owned.txt`; первый overlay restore удаляет команду из INI, второй публикует другой `owned.txt`, а остановка прежнего worker исполняет заменённый файл. Безвредный маркер содержит `replaced`. Это actual runtime-воспроизведение, а не только source review; приватные MNT/NET/PID и `/etc/qeli`, `/var/lib/qeli`, `/tmp`, работающая служба лабы не затронута.

Исправление сохраняет набор команд из startup snapshot и конфигов, прочитанных supervisor перед каждым запуском worker. Набор консервативно живёт до завершения supervisor: стирание команды/профиля в INI и выход worker не освобождают защиту прежних файлов. Restore объединяет этот набор с текущим INI. Первый безопасный overlay по-прежнему разрешён; второй с заменой скрипта возвращает HTTP400 до snapshot/publication. Exact restore также отклоняет удаление защищённого верхнего entry, включая весь каталог с вложенным скриптом.

Текущий Linux source aa98f208: actual CLI build/bin5/backup50, retained-generation1, post_down3, отдельные private-FS/preload IO2 и Clippy -D warnings PASS. Runtime: baseline6 expected-vulnerability checks, fixed8 и fixed-later10 PASS. Последний сценарий вручную меняет команду и перезапускает только worker через настоящий API; supervisor сохраняется, новый worker готов, после двух restore при остановке исполняется `original`. Проверки подтверждают отказ exact до публикации, сохранение скрипта и возможность безопасного overlay. Маркер используется только в owned fixture. Linux ELF SHA256 `73af3c9e60b23c17f994f87a198184fc6f624fb6f96f90af7ae5b7877bff5b2b`, 78778192 bytes.

Сохранена ошибка первого baseline fixture: унаследованный `/sys` показывал интерфейсы хоста, поэтому ready assertion ложно упал; фактический `ip link` внутри private NET исправляет проверку. Этот запуск не считается продуктовым FAIL или PASS. Повтор baseline подтверждает всю цепочку. Ранний вызов Android cleanup до завершения скачивания библиотек остановился на отсутствии локального result.json до SSH/удаления; повтор выполнен только после PASS. Root777/845 и установленный ELF75bc сохранены; SHA-verified recoverable archive скачан перед guarded cleanup.

Fresh independent A/B PASS for Windows/macOS universal2/Android arm64+x86_64 from aa98f208, native source digest374be1f4. Six fresh build-command batches, separate A/B targets/private offline registry/caches,jobs1,panic=unwind; exports6Reality+22client (+21JNI Android), all14SHA/canonical-consumed pairs/provenance PASS. Actual refreshed Windows DLL22 C ABI/control/localhost-runner checks PASS; no Wintun/OSroutes. New native bytes are recorded, old ABI/runtime results are not relabeled. Mac cross-build emits retained missing-xcrun/SDK warnings; real Mac/iOS runtime remains USER_EXCLUDED, no new Android full runtime/soak/benchmark claim.

`q33-retained-hooks-20261008`: SEALED 112 files / 167439176 bytes; manifest SHA256 `b817b3916307f8b7ad20d6f07dda0bae0ce99fc1430c34337451370d9e4bb3bc`.

## Итог Q33 и пределы

Пять критериев Q33 закрыты в согласованном объёме: review/dead code; positive/boundary/negative; failures/concurrency; Linux target integration; fixes/retest/evidence. Ссылки в таблице выше сохраняют точные исходники и ограничения прежних installer/package/systemd/Docker/VPN прогонов; их payload не пересобран для F450 и прежние результаты не объявляются запуском нового ELF.

Q33 DONE. Общий план 30/37 DONE (81,1%), осталось 7. Нового обязательного долга этого пункта нет. Static hook collector остаётся best-effort для литеральных путей, не shell sandbox; команды, полностью построенные переменными, runtime cd/внешние зависимости и несогласованные admin edits между чтением supervisor и worker не квалифицированы. Для hooks рекомендуется отдельный каталог вне `/etc/qeli`; консервативная защита может сохраняться до полного restart supervisor. Whole-tree atomic restore, автоматический rollback, power-loss/fsync и пустой OS bootstrap не заявлены. Multiarch compiler/registry/current Actions/release attestation остаются в Q34, а не превращаются в PASS.

Исторический долг 14 DONE + D06 ACCEPTED_LIMITATION; Q29 SIGKILL FAIL/ENONET, Q30 Apple/callback, Q31 3/5/capacity/source-cut и user platform exclusions сохранены. Без push/deploy/release.
