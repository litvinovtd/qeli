# Q28: macOS forwarding — владение и восстановление

<!-- normative-sync: audit-q28-macos-forwarding-v1 -->

**5 октября 2026: managed этап PASS. Q28 IN_PROGRESS, план 27/37 (73,0%), осталось 10 разделов. Реальный Mac USER SKIPPED.**

## Исправления

| ID | Проблема и исправление |
|---|---|
| F262 | Исходные sysctl хранились только в памяти; другой клиент мог присвоить уже включённое значение, а первый — отключить его. До изменения ядра сохраняется эксклюзивный журнал одного Qeli-владельца: PID, UTC start ticks и уникальный token. Кооперативный lock охватывает claim/recovery/release. Живой владелец сохраняется, повтор того же поколения не перезаписывает исходные значения. |
| F263 | Ошибка IPv4 прерывала восстановление IPv6; нулевой exit sysctl считался достаточным подтверждением. Каждое семейство обрабатывается независимо и проверяется чтением после записи. Подтверждённый прогресс сохраняется; ошибка оставляет журнал/controller для повторной очистки. BeforeTunDispose отказывает до успешного восстановления forwarding. |
| F264 | После потери процесса не было durable recovery; неизвестный исход записи/удаления мог потерять ответственность. Root startup восстанавливает только мёртвого владельца. Строгий журнал до 4096 байт отказывает при неизвестных/повторных/отсутствующих полях, неправильном UTF-8 и метаданных. Частичные публикация/checkpoint/delete учитываются; исчезновение журнала после native mutation означает неизвестную очистку. Ошибка observer не отменяет уже подтверждённую очистку. |

## Проверки

- forwarding-selftest: **58/58 PASS**. Production coordinator с заменёнными sysctl/storage boundaries; отдельно настоящий временный файловый журнал, UTC lifetime текущего процесса и два конкурирующих controller. Проверены live owner, same-PID/different token, исходно включённые флаги, частичный enable/restore, unchanged flag при успешном exit, checkpoint/delete failures, повтор cleanup, строгий payload и восстановление новым coordinator.
- Из старого VpnTunnel извлечены исходные forwarding transitions; подменены только log и native read/write. **6/6 ожидаемых FAIL**: конкурирующий claim, отключение флага другого клиента, потеря состояния при restart, пропуск IPv6 после ошибки IPv4, отсутствие подтверждения enable и restore. Это шесть сценариев, а не шесть независимых дефектов.
- Связанные свежие проверки: per-app **22**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**. Итого **1208 managed PASS**. Три Release-сборки и baseline build без предупреждений/ошибок. Первое падение harness (CS0407) сохранено; исправлены lambda adapters, затем выполнены свежие build/selftests.
- Docs/bindings/panel/diff PASS. Native source digest и все 14 native hashes неизменны. Три Shared DLL побайтово равны; текущие managed artifacts и входные файлы закреплены в source-proof.
- Настоящие macOS sysctl, root fd operations/flock, запуск launchd, crash отдельного процесса, utun и NetworkExtension **USER SKIPPED**. Временный файл и новый coordinator проверяют логическое recovery; это не Darwin crash/runtime проверка.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-forwarding-20261005.
Evidence: release/certification/evidence/q28-macos-forwarding-20261005.json.

## Поведение и границы

Для обычного utun-профиля с forward=true допускается один активный Qeli forwarding owner на весь Mac, включая исходно включённые флаги и непересекающиеся семейства. Другой профиль получает ошибку до sysctl; остановите первого владельца перед переключением. Forwarding сам по себе не настраивает NAT/firewall/внешнюю маршрутизацию. Новых INI-ключей нет; JSON журнала — внутренний recovery DTO, не пользовательский конфиг. Per-app ветка не приобретает этот глобальный lease.

Восстановление возвращает только изменённые Qeli флаги к сохранённому off; исходно on не выключает. Координация распространяется на Qeli, использующие этот журнал. Самостоятельная запись другого инструмента того же значения sysctl=1 неотличима от значения Qeli и не даёт гарантии сохранения его намерения. Прямая подмена root journal не поддерживается. При неизвестном/повреждённом состоянии автоматическая очистка отказывает; не удаляйте журнал вслепую и не запускайте конкурирующий forward-профиль.

Каждая sysctl-команда ограничена 3 секундами; это не общий deadline всей операции и не гарантия прерывания любого Darwin syscall. Recovery здесь относится к forwarding, не к полному восстановлению DNS/routes/TUN. UTC identity введена только для нового журнала; старые DNS/PF stamps этим изменением не мигрируют.

Остаток Q28: guardian ready/owner-generation, native socket lifetime и пределы connect/write, итоговый обзор интеграции. Исторические release case artifacts/timestamps и physical rows сохранены. Новых Linux/JNI/soak/benchmark результатов нет; сеть, службы, лаба и пользовательские профили не изменялись. Push/deploy не выполнялись.
