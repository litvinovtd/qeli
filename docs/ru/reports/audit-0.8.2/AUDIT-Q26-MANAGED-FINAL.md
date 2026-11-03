# Q26: общий C# и managed/native граница — DONE/PASS

5 октября 2026. База `73aa48a2`; .NET SDK 10.0.300, Windows. Раздел закрыт в
доступном объёме; Mac/iOS, роутер и Windows VM network runtime пропущены по решению
пользователя. Это не результат подключения desktop-клиента к VPN или нового бенчмарка.

<!-- normative-sync: audit-q26-managed-final-v1 -->

## Что проверено

| Слой | Проверка и вывод |
|---|---|
| Конфигурация | `ConfigCore`, генерируемая модель `VpnConfig`, INI/link import/export/runtime и native validation. Общий Rust parser остаётся источником правил; сгенерированные bindings и матрица совпадают со схемой. JSON остаётся служебным DTO/API и форматом fixtures/внутреннего хранилища, а пользовательские конфиги — INI. |
| Профили и настройки | Структурная проверка null/ID, миграция ID, ограниченное чтение, атомарная запись/backup, quarantine до пустого recovery, sidecar lock и отказ устаревшей записи. Conformance включает гонку двух отдельных процессов и точные байты победителя/backup. Платформенное шифрование DPAPI/Keychain относится к Q27/Q28. |
| ABI | Cdecl, размеры последовательных структур, синхронные pinned buffers и копирование ответа до освобождения; временные config/request buffers обнуляются. ABI floor уже 1.16, исправлены устаревшие комментарии 1.11/1.15. Managed уведомления не являются сохраняемыми native function pointers. |
| Lifetime | Создание/stop/free, события/sequence/stats, инвалидированный handle, пакетные задачи и отмена, сохранение владения при timeout. Не заявляется Rust memory UAF: native registry сохраняет leased Arc; дефект касался преждевременного повторного использования managed TUN/network state. |
| Мёртвый код | Production QeliShared исключает Crypto/Protocol и LinkConformance; reflection подтверждает отсутствие managed PacketCipher/PacketCodec/LinkConformance и зависимости BouncyCastle. Сохранённые primitives используются отдельным conformance runner и не удалены как «мёртвые». |
| Обвязка | CI запускает mandatory fixtures на обоих desktop hosts. Проверены отсутствие fixtures, пустой config corpus и исключение csharp из generated platforms; все три дают exit 1 без SKIP. README уточняет отдельные schemas старых hand-written fixtures. |

## Подтверждённые дефекты и исправления

- **Q26-F218 — исключения наблюдателей.** Log/Status/ConnectionDropped могли прервать
  lifecycle и cleanup; RunCompleted защищал только весь multicast. Все четыре события
  теперь изолируют каждого подписчика отдельно. Ошибка не отправляется обратно в LogLine.
  На старом коде воспроизведены четыре FAIL для Log/Stop и пропущенного второго подписчика.
- **Q26-F219 — пакетные задачи и владение.** Ошибка или раннее завершение pump не
  проверялись в native event loop. Cleanup игнорировал незавершённые timed joins
  (2/2/5 секунды) и мог освободить handle/вернуться к teardown или reconnect. Event loop
  теперь сообщает ошибку pump с исходной причиной; generation owner joins все задачи до
  free. Внешний Stop сохраняет прежний предел 8 секунд: timeout оставляет живую задачу,
  TUN и владение для повторного Stop. CTS освобождается только после join. В conformance
  реально выполнены Stop timeout и успешная повторная очистка с fake TUN.
- **Q26-F220 — тело ответа проверки обновлений.** `ResponseHeadersRead` завершал
  HttpClient timeout на заголовках; дальнейший JSON body мог зависнуть или неограниченно
  расти. Общий linked token ограничивает headers+body 10 секундами; поток читается до
  1 МиБ + одного контрольного байта. Ошибки по-прежнему дают отсутствие уведомления.
  Проверены обычный/exact-limit body, бесконечный поток, отмена зависшего read и битый JSON.
  Реальный HTTP endpoint и полный 10-секундный network stall не инжектировались.
- **Q26-F221 — чтение и batching route_file.** File.ReadLines выделял строку без
  ограничения до newline; 512 строк с Unicode-комментариями могли переполнить 2 МиБ
  служебный запрос после сериализации. Старый parser реально воспроизвёл
  `Configuration request too large` на восьми корректных длинных комментариях.
  Общий desktop reader ограничивает строку 65 536 UTF-16 units и проверяет отмену между
  блоками 4096 символов; batch ограничен 512 строками и 131 072 символами. CR/LF/BOM
  поведение сохранено; overflow сообщает source/line. Лимит 250 000 уникальных маршрутов
  сохранён. Проверены граница строки, смешанные окончания, отмена до newline и Unicode
  batching, а также прежние CIDR/OpenVPN 14 113 маршрутов, merge и cancellation.

Пустой `config-boundary` corpus теперь даёт FAIL; это исправление gate, не новый дефект
пользовательского парсера. Источником проверки limits и validation остаётся Rust.

## Результаты

- **543/543 shared conformance PASS**, 0 FAIL/SKIP; 32 новых проверки к базе 511.
- **143/143 Windows platform selftest PASS**; Release builds QeliConformance, QeliWin и
  QeliMac без warnings/errors. Mac сборка выполнена на Windows из локального NuGet cache;
  это compile-only, не запуск macOS-клиента. Первоначальная попытка `--no-restore` без
  assets сохранена; offline restore исправил только build prerequisites.
- 32 настоящих DLL handle generations: New/SetDeviceId/Start/Poll/Stats/Stop/Free;
  проверены sequence и инвалидированные IDs. Это проверки ABI без установки OS routes.
- 3 negative fixture runs на изолированных копиях final runner дают ожидаемый exit 1:
  missing (8 FAIL), empty boundary (1 FAIL), missing csharp platform (1 FAIL), 0 SKIP.
- Generated bindings/matrix, RU/EN docs, panel, diff и native provenance/checksums проверены.
  Rust/native inputs и все 14 checksum rows неизменны; native A/B и Linux network matrix
  повторно не собирались/не запускались. Старые executions сохраняют даты и границы.

## Evidence и пределы

`release/certification/evidence/q26-managed-20261005.json` содержит source/artifact hashes,
результаты и raw hashes. Raw root:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q26-managed-20261005`.

Сохранены первоначальные ошибки harness: неподходящий ожидаемый ACK status (-3 без
pending plan вместо stale -11) и неверный catch type у baseline route reproduction.
Исправлены только ожидания harness; повторные baseline/fixed результаты указаны отдельно.

Ни подключение desktop VPN с настоящим TUN/firewall, ни Mac runtime, физический roaming,
peak benchmark или долговременный soak здесь не заявляются. Callback обязан возвращать
управление; исключения изолируются, но произвольный зависший код подписчика не прерывается.
Синхронный OS file read также не получает принудительного прерывания; отмена проверяется
между chunks. Если worker не выходит, Stop сообщает timeout и не разрешает state reuse.
Обнуление временных byte buffers не гарантирует стирание immutable managed strings.

Рабочие сервисы/лабa и native binaries не изменялись. D06 остаётся принятой границей
WAN identity без внедрения BPF. Коммит переносится в dev с сохранением пользовательских
изменений CHANGELOG/users.html; push/deploy не выполняются.

**План: 26/37 DONE/PASS (70,3%), осталось 11. Далее Q27 — Windows GUI/service/drivers.**
