# Q28: daemon macOS, helper и состояние

<!-- normative-sync: audit-q28-macos-control-v1 -->

**5 октября 2026: этап PASS; Q28 IN_PROGRESS. План 27/37 (73,0%), осталось 10 разделов.**

## Исправления

| ID | Проблема и итоговое поведение |
|---|---|
| F243 | Load daemon скрывал ошибки, принимал plaintext/null и мог создавать замену ключа. Codec проверяет структуру/размер/строгий UTF-8, требует аутентифицированное шифрование. Только отсутствие даёт null; Load не создаёт ключ. Первый ключ публикуется без замены; конкурирующие создатели перечитывают победителя. Размер отклоняется до обращения к ключу. |
| F244 | GUI мог выбрать другой профиль через fallback, изменить его logging settings или опубликовать до Stop. Общий DesktopServiceProfileTransition для Windows/Mac обеспечивает точный snapshot, проверку до Stop, завершённый Stop до Publish и рестарт согласно намерению подключения. Настройки редактируют копию. Mac root-команды держат закрытую вложенную файловую блокировку на весь переход. |
| F245 | Heartbeat скрывал ошибки Start/Load/cleanup; частичный Start терял обязанность cleanup при Shutdown. DaemonLifecycle сохраняет её до Start, повторяет Stop, запрещает рестарт/опрос после ошибки cleanup и синхронно публикует status/detail. Shutdown пишет итоговый Error даже при исключении. |
| F246 | Устаревший/будущий/неизвестный статус выглядел подключённым; журнал читался без проверки, ротация одинакового размера терялась. Общая проверка статуса проверяет enum/time/counters/detail. Mac проверяет свежесть, ограничивает доверенное UTF-8 чтение, сохраняет устаревший Error, различает дополнение/замену журнала, ограничивает строки и ротацию. |
| F247 | Plist мог запускать другой binary или переопределять исполнение; XML-символы пути ломали регистрацию. Доверенное чтение descriptor проверяет current/legacy label, executable/arguments/root identity/settings до изменений. XML-пути экранируются. Неблокирующий no-follow open предотвращает зависание FIFO до проверки типа файла. |
| F248 | Deadline утилит не охватывал EOF pipe, рост вывода и результат; ошибки ownership/autostart скрывались. ToolProcess ограничивает обе трубы и ожидание процесса/EOF; exit 0 не заменяет outcome callback. Bootout имеет общий бюджет запросов 30 секунд; неизвестная ошибка не доказывает отсутствие daemon. Ошибки ownership/autostart видны. |

Удалены неиспользуемые ServiceManager Run/Run2, IsRunning и неоднозначный LaunchdHasTarget. JSON остаётся внутренним IPC/DTO/зашифрованным архивом; внешние конфиги только INI.

## Проверки и ограничения

- Release Mac, Windows, shared conformance: PASS, 0 warnings/errors.
- Mac control-selftest: **83/83 PASS**: codec/digest/null/UTF-8/размер, порядок переходов/отказов, snapshots, частичный Start/повторный cleanup, статус, журналы, plist, гонки ключа и contention/release блокировки.
- Реальные изолированные дочерние процессы: две трубы по 32 КиБ, ненулевой exit, deadline зависания, переполнение вывода, отсутствие executable, exit 0 без результата и раннее подтверждение.
- Mac storage-selftest: **54/54 PASS**, повторно после изменений envelope/shared.
- Windows selftest: **325/325 PASS**; shared conformance: **549/549 PASS**, новые прогоны после изменения shared.
- Baseline: **5/5 ожидаемых FAIL**, exit 1. Исходные тела LoadProfile/ReadStatus/Plist/envelope, подменены только reads/key/save/executable path. Дефекты: plaintext принят, повреждение скрыто, обязательный null/числовой статус приняты, XML пути невалиден.
- Docs, bindings, panel, diff, неизменённые native provenance/14 checksums: PASS.

Реальные профили/ключи, установленные службы, сеть хоста/лабы не затронуты. Windows qeli.dll обеспечивает только вычисляемые getters DTO, не Mac dylib/ABI qualification. Проверки блокировки используют рабочий coordinator с изолированным FileStream на Windows. Native flock/openat/renameatx_np проверены по исходникам, не исполнены.

Реальный Mac/launchd/Keychain/Darwin/private-mode/Intel-ARM/authorization runtime остаются **USER SKIPPED**, не PASS. Блокировка сериализует согласованные Mac-команды, но не ограничивает всю операцию владельца и не защищает от записи root. Windows сохраняет per-instance gate; новой межпроцессной гарантии нет. Отмена pipe ограничивает вызывающий код, не гарантируя завершение уже осиротевших потомков. Managed-таймер не прерывает принудительно native prompts/OS I/O.

Точный текст отсутствия launchctl — консервативный fixture, а не документированный стабильный контракт современной CLI: неизвестная/локализованная/изменённая ошибка даёт безопасный отказ. Чужие/повреждённые регистрации требуют явного ремонта администратором. Status не подтверждает process/profile generation; текст настроенного профиля не доказывает identity worker.

Первичные контракты: [Darwin descriptor/flock flags](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h), [exclusive rename](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/stdio.h), [launchd settings](https://raw.githubusercontent.com/apple-oss-distributions/launchd/main/man/launchd.plist.5).

Исходные протоколы: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-control-20261005. Evidence: release/certification/evidence/q28-macos-control-20261005.json.
Далее: utun/routes/pf/DNS cleanup/roaming, Swift Network Extension/entitlements и build contracts. Q28 открыт. Новых результатов Linux/JNI/soak/бенчмарков этот этап не заявляет.
