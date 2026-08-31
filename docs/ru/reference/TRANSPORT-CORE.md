# qeli — общее транспортное Rust-ядро для всех клиентов

Предложение и план: перенести установку соединения, выбор транспорта, хендшейк, роуминг,
multipath, автоматический fallback и обработку конфигурации в **одно** Rust-ядро,
подключаемое во все клиенты через FFI. Платформенному коду остаются TUN, UI, уведомления
и системные API.

Формат документа — рабочий чек-лист в стиле [REFACTOR-PLAN.md](../archive/plans/REFACTOR-PLAN.md):
у каждого пункта есть ID, объём, подход и **критерий приёмки**.

Легенда статуса: ⬜ не начато · 🟦 в работе · ✅ сделано · 🧪 ждёт сборки/e2e.

**Статус инициативы: ✅ рефакторинг исходников завершён.** Все production-клиенты используют
общее транспортное Rust-ядро; текущее исходное API — additive ABI 1.15. ABI 1.15 добавляет
типизированные серверные события `NOTICE`/`KICK` и capability `MANAGEMENT_EVENTS`, не меняя
фиксированный event header и число экспортов. Закоммиченные `.so`/`.dll`/`.dylib` пока остаются
последним сертифицированным набором ABI 1.14; перед упаковкой их нужно пересобрать из финального
коммита 0.8.0. Финальные приложения всё равно должны пройти signing/platform/E2E gates. Остались также
administrator Wintun full-tunnel, живой macOS utun и physical-device iOS/Xcode.
Составлено 2026-07-30; статус native cores актуализирован 2026-08-31.
**Правило доставки Reality/H2.** Актуальный H2 carrier режима `reality-tls` принадлежит этому
общему Rust-ядру, а не платформенному UI-коду. Платформа получает его только после пересборки
native `.so`/`.dll`/`.dylib` либо XCFramework из обновлённых исходников, упаковки в приложение
и установки. Обновление сервера не может передать новый wire-код уже установленному клиенту.

ABI 1.10 расширил статистику без изменения её 64-байтового V1-префикса. ABI 1.11 добавляет
dual-family NetworkPlan/platform-capability contract без изменения этих префиксов. Поля
показывают UDP kernel drops, внутренние drops bounded-очередей, число автоматических
увеличений receive buffer и фактически выданный ОС размер. При отсутствующем ключе общий
контроллер начинает с 4 МиБ и растёт 4→8→16 МиБ только по локальному overflow либо
измеренному rate/stall budget; явный размер остаётся фиксированным, `0` оставляет настройку ОС.

ABI 1.12 добавляет закрытую feature gate `experimental-roaming` транзакцию candidate path:
ограниченный generation-scoped `PathUpdate`, команды `PREPARE/BIND/COMMIT/ABORT`, строгую
корреляцию по generation/candidate/sequence и статистику V3 размером 144 байта. Префиксы
V1/V2 размером 64/96 байт сохранены. ABI 1.13 добавляет необязательное generation-scoped событие
`PATH_REFRESH` без payload и парные capability bits ядра/платформы. Rate запроса, grace time и
reconnect fallback принадлежат общему ядру; capable adapter только возвращает свежий `PathUpdate`
того же пути. Linux исполняет запрос in-process, Android повторно снимает snapshot неизменной
`Network`. Адаптер без нового platform bit никогда не получает событие. ABI 1.14 добавляет три
явных результата path-команды: accepted, безопасный для rollback rejected и
platform-state-unknown. Последний разрешён только при неполном внутреннем rollback и завершает
текущую generation без stale `ABORT_PATH`. Path transactions отключаются capability gate, если
desktop, Android или iOS adapter загрузил ядро старее 1.14. ABI 1.15 добавляет negotiated bounded
события серверного `NOTICE` и терминального `KICK`; старые peers не рекламируют `MANAGEMENT_V1`
и сохраняют прежнее поведение. Фиксированный 48-байтовый event header, префиксы статистики и
число экспортов не меняются.
Native-адаптер также обязан объявить platform capability `MANAGEMENT_EVENTS` из ABI 1.15. Поэтому
совместимое новое ядро, загруженное старым GUI до 1.15, не включает wire-capability и сервер не
может прислать неизвестные этому GUI виды событий.

---

## 1. Вердикт: чем это оправдано, а чем — нет

**Оправдано расхождением реализаций. Не оправдано скоростью.**

Это важно зафиксировать до начала работ, потому что от формулировки цели зависит,
чем мерить успех. Продавать это как «ускорим клиентов» нельзя: замер (§2) показывает,
что клиентский data plane сегодня ни во что не упирается.

**Доказательство реального риска уже есть.** Фикс **M6** (детерминированный nonce через
PRP) выехал в трёх реализациях из четырёх и **молча не доехал до Android**. Это
расхождение в криптографии, а не в UI, и обнаружено оно было только потому, что под это
специально построили кросс-языковые KAT-векторы (`conformance/`). Четыре независимые
реализации протокола — это постоянный источник таких дефектов, и цена ошибки здесь
измеряется не мегабитами.

Где скорость всё же аргумент — там, где считают не мегабиты, а такты:

- **мобильные клиенты** — 2.4× меньше циклов на байт плюс отсутствие GC-нагрузки
  (см. §2: C# аллоцирует 2.3 ГБ, чтобы прогнать 280 МБ) — это батарея и отзывчивость;
- **слабые цели** — порт на роутеры ([KEENETIC-PORT.md](KEENETIC-PORT.md)), где
  управляемого рантайма нет вообще.

---

## 2. Замер, на котором основан вердикт

Проведён 2026-07-30. Обе реализации — **на одном CPU**, 200 000 пакетов по 1400 Б,
один поток, паддинг отключён с обеих сторон. Сравнивались одноимённые сущности:
`PacketCodec` (кадрирование + AEAD) и AEAD отдельно.

**Стенд A — лаба (QEMU Virtual CPU, 2 ядра; есть `aes`, `ssse3`, `sse4_2`; AVX2 нет):**

| Что | MB/s | ≈ Мбит/с |
|---|---|---|
| C# `PacketCodec` шифрование | 81.9 | 687 |
| C# `PacketCodec` расшифровка | 133.1 | 1117 |
| **Rust `PacketCodec` шифрование** | **208.4** | **1749** |
| **Rust `PacketCodec` расшифровка** | **317.5** | **2664** |
| AEAD BouncyCastle (новый экземпляр на пакет) | 169.7 | — |
| AEAD встроенный в .NET (переиспользуемый) | 226.5 | — |
| **AEAD Rust (переиспользуемый)** | **410.3** | — |

Аллокации за прогон: C# — **2311 МБ на 280 МБ полезных данных** (восьмикратное усиление),
309 сборок gen0. У Rust GC нет.

**Стенд B — реальное железо (Intel i5-14600KF), только C#:** шифрование 158.7 MB/s
(1331 Мбит/с), расшифровка 225.4 MB/s, AEAD BouncyCastle 315.1 MB/s.

### Что из замера следует

1. **Rust-ядро быстрее в 2.4–2.5 раза** — и это **нижняя граница**: на стенде A нет AVX2,
   а у Rust ChaCha20 есть AVX2-бэкенд, тогда как BouncyCastle скалярный в любом случае.
2. **Дешёвой альтернативы «просто ускорить C#» на Windows не существует.** Встроенный
   в .NET `ChaCha20Poly1305` там докладывает `IsSupported = False` (Windows CNG его не
   предоставляет) — проверено на стенде B. На Linux он есть и даёт +33% к BouncyCastle,
   но главный десктопный клиент остаётся на управляемом BouncyCastle. Судя по всему,
   именно поэтому он и выбран.
3. **Скорость сейчас ни во что не упирается.** Даже C#-клиент выдаёт ~1.3 Гбит/с на
   шифровании против потолка прод-сервера ~311 Мбит/с (упор в одно ядро,
   см. [BENCHMARK.md](../reports/BENCHMARK.md)).
4. **Крипто у клиентов неоднородно.** Android шифрует нативным Conscrypt (BoringSSL),
   C# — управляемым BouncyCastle. «Managed» — не единая категория, и выигрыш от переноса
   на Rust у Android будет заметно меньше, чем у Windows/macOS.

> Первоначальные бенчи были одноразовыми. В 0.7.15 их заменили постоянные release-mode
> Rust/C# harness и CI-gate — команды и границы описаны в **TC-0.3** ниже.

### Точка возврата к производительности: `b6e0796`

Перед продолжением платформенного рефакторинга зафиксирован воспроизводимый checkpoint на
2-vCPU лабе. TCP fake-TLS достиг 468,7↑/700,6↓ Мбит/с при нулевых session drops. Для одного
UDP flow получено: 300 Мбит/с — 0,06% потерь, 400 Мбит/с — 1,86%, 500 Мбит/с — 8,27%; на
последней ступени сервер насчитал 745 kernel receive-buffer errors против 21 554 потерянных
iperf datagrams, а внутренних session drops не было. Это не релизные обещания, а базовая
точка для следующего цикла измерений.

К буферам и скорости возвращаемся **от commit `b6e0796`**, отдельно от текущих ABI/TUN
изменений. Следующий цикл должен сначала добавить клиентские UDP send/drop и qdisc-счётчики,
затем проверить привязку одного flow к одному `SO_REUSEPORT` worker и последовательный
unwrap/decrypt/ACL/TUN участок. Только после локализации выполняется управляемый sweep
4-МиБ budget, размеров/числа pool slots и глубины bounded queues на одном и том же benchmark;
простое увеличение лимитов без счётчиков не считается исправлением. Постоянные Rust/C#
`PacketCodec` benchmarks из TC-0.3 теперь дают micro-level guard для этого цикла, но не
заменяют end-to-end lab baseline.

---

## 3. Что дублируется сегодня

Посчитано по файлам, без тестов и артефактов сборки (2026-07-30):

Это baseline до миграции; фактические удаления и текущий статус зафиксированы в TC-3/TC-5 ниже.

| Кодовая база | Всего строк | Из них ядро протокола/транспорта |
|---|---|---|
| `qeli-shared` (C#, общая для Windows и macOS) | 7 627 | ~6 200 |
| `qeli-android` (Kotlin) | 8 469 | ~5 200 |
| `qeli-ios` (Swift) | 10 668 | ~5 700 |
| **Итого дублей** | | **~17 000** |

Плюс ~930 строк conformance-обвязки в C# и по ~250 в Kotlin/Swift, которые существуют
**только** потому, что реализаций четыре.

Самые крупные узлы дублирования:

| Файл | строк | что делает |
|---|---|---|
| `qeli-android/.../QeliService.kt` | 3 162 | VpnService + соединение + транспорт |
| `qeli-shared/.../Vpn/VpnTunnelBase.cs` | 2 866 | соединение, хендшейк, транспорт, реконнект |
| удалённый iOS QeliTunnelEngine.swift | 1 436 | то же для iOS на baseline |
| `qeli-shared/.../Model/VpnConfig.cs` | 1 060 | обработка конфигурации |
| `qeli-android/.../model/Config.kt` | 929 | то же |
| `qeli-ios/QeliCore/Model/VPNConfig.swift` | 733 | то же |

Для сравнения, Rust-сторона (уже существует и общая с сервером): `client/` 7 609,
`protocol/` 11 514, `config/` 6 682, `crypto/` 1 879. **Нового кода ядро почти не
требует — требуется новый потребитель.**

---

## 4. Где проходит граница

### 4.1. Что уже есть

FFI не нужно изобретать — он есть, но узкий: `qeli/src/protocol/realtls/ffi.rs` (474 строки)
и `jni.rs` (372) экспортируют **sans-io**-ядро realtls: `qeli_realtls_new/recv/seal/open/free`,
`qeli_mlkem_*`, `qeli_build_faketls_clienthello`.

Отсюда два вывода:

- **Накладные расходы FFI уже оплачены и приемлемы.** В режиме reality-tls Windows, macOS
  и Android зовут Rust **на каждую TLS-запись** — это рабочий прод-режим.
- **Текущий контракт нельзя переносить на data plane как есть.** `qeli_realtls_seal`
  делает `Box::into_raw` и требует парного `qeli_realtls_buf_free` — то есть
  **аллокация, освобождение и копия на каждую запись**. На скорости data plane это
  недопустимо (см. TC-1.2).

### 4.2. Владение TUN — главный вопрос и главный драйвер трудозатрат

Правильный разрез — **ядро владеет сокетом и TUN**. Тогда пакеты через FFI не ходят вовсе,
а граница становится управляющей. Упирается всё в то, отдаёт ли платформа дескриптор:

| Платформа | Что даёт ОС | Пересечений FFI на пакет |
|---|---|---|
| Android | `VpnService.establish()` → fd | **нет** (нужен upcall `protect(socket)`) |
| macOS | utun fd | **нет** |
| Windows | Wintun (кольцевой буфер) | **нет**, если кольцом владеет Rust |
| iOS | `NEPacketTunnelProvider.packetFlow` — **дескриптора нет** | есть, но **пачками** |

Оценка стоимости для iOS: на 100 Мбит/с при 1400 Б это ~9 000 пакетов/с; `readPackets`
отдаёт их пачками по ~30 → ~300 вызовов/с. Ничтожно.

**Исходное ключевое ограничение:** `qeli/src/tun/` был **335 строками только для Linux**
(`/dev/net/tun`, `#[cfg(target_os = "linux")]`). Теперь fd-pump общего ядра обслуживает также
Android и macOS utun; Wintun теперь имеет отдельный Rust-бэкенд, а iOS остаётся единственной
платформой, где API `packetFlow` неизбежно пересекает языковую границу пачками.

### 4.3. Что в ядро НЕ идёт

Kill-switch, программирование маршрутов, DNS, автозапуск, уведомления, UI, биллинг
разрешений. Это платформенные API, и именно там ловились платформенные дефекты (два
kill-switch-бага в 0.7.14 — ровно из этой области).

Контракт: **ядро отдаёт план, платформа его исполняет.** Ядро говорит «поставь такие
маршруты, такой DNS, подними kill-switch» — платформа приводит систему в это состояние
и докладывает результат.

---

## 5. Transport API

### 5.1. Реализованный control-plane ABI 1.x

Публичный контракт зафиксирован в `qeli/include/qeli_transport_core.h`, реализация — в
`qeli/src/transport_core/`. Feature `transport-core-ffi` включается отдельно и наследует
обязательный для FFI контракт `panic = "unwind"`.

```text
qeli_client_abi_version()                                      -> 0x0001000F
qeli_client_core_capabilities()                                -> bitmask
qeli_client_udp_probe(config, len, timeout_ms, *latency_ms)     -> rc  // ABI 1.8
qeli_client_new(config, len, platform_caps, queue_cap, *handle) -> rc
qeli_client_start(handle)                                      -> rc
qeli_client_run(handle, json, len)                             -> rc  // ABI 1.6, blocking
qeli_client_stop(handle)                                       -> rc
qeli_client_set_device_id(handle, id, 16)                      -> rc  // ABI 1.3
qeli_client_publish_handshake_network(handle, json, len, *gen) -> rc  // ABI 1.5
qeli_client_set_tun_fd(handle, generation, fd)                 -> rc  // ABI 1.1
qeli_client_set_wintun_adapter(handle, generation, name, len)  -> rc  // ABI 1.9
qeli_client_poll_event(handle, *event, payload, cap, *needed)   -> rc
qeli_client_network_plan_result(handle, generation, rc, reason) -> rc
qeli_client_path_update(handle, json, len, *candidate)          -> rc  // ABI 1.12
qeli_client_path_command_result(handle, generation, candidate, sequence, rc, reason) -> rc  // ABI 1.12
qeli_client_socket_protect_result(handle, sequence, rc, reason) -> rc  // ABI 1.2
qeli_client_server_identity_result(handle, sequence, rc, reason)-> rc  // ABI 1.4
qeli_client_state(handle, *state)                              -> rc
qeli_client_stats(handle, *stats)                              -> rc
qeli_client_tun_push(handle, generation, bytes, bytes_len, lengths, count, *accepted) -> rc // ABI 1.7
qeli_client_tun_pull(handle, generation, bytes, cap, lengths, count_cap, *count, *bytes) -> rc // ABI 1.7
qeli_client_free(handle)                                       -> rc
```

Машина состояний уже не допускает оптимистического «туннель поднят» до выполнения
системной части:

```text
Created → Connecting → AwaitingNetwork ── ACK ──→ Running
                              └──────── reject ─→ Failed
Running/Failed/Created → Stopping → Stopped
```

- входная конфигурация — strict flat-INI или `qeli://`; её разбирает и валидирует Rust;
- handles — generation-checked `u64`, stale use и double-free возвращают ошибку;
- очередь ограничена (по умолчанию 64, максимум 256) и применяет backpressure без частично
  выполненного перехода для операций, которые вызывающая сторона может повторить; терминальный
  сбой фонового runner повторить нельзя, поэтому он вытесняет самые старые события и всегда
  публикует Error с состоянием Failed (и StateChanged при ёмкости не меньше 2);
- заголовок события имеет фиксированную C-layout структуру и version; payload плана,
  socket-protect, server-identity и path-command запросов — UTF-8 JSON, ошибка — UTF-8,
  а смена состояния и path-refresh запрос ABI 1.13 не имеют payload;
- до `new` адаптер сверяет ABI через `QELI_CLIENT_ABI_IS_COMPATIBLE`: major обязан совпасть,
  minor библиотеки должен быть не ниже minor заголовка; неизвестные capability bits, event
  kinds и добавочные JSON-поля не являются ошибкой;
- `QELI_CLIENT_EVENT_INIT` и `QELI_CLIENT_STATS_INIT` задают caller-owned `struct_size`.
  Ядро сохраняет его, пишет только известный обеим сторонам префикс и отвергает короткую
  ABI-1.0 структуру, не потребляя событие. Header проверяет 48-байтовый event и префиксы
  stats V1/V2/V3 размером 64/96/144 байта compile-time;
- ABI 1.12 принимает только ограниченный `PathUpdate` с активной generation, монотонным
  `update_id`, идентификатором физической сети или ненулевым interface index, локальными
  адресами, результатами A/AAAA с TTL, причиной и согласованными флагами. Отказ
  `PREPARE/BIND/COMMIT` обязательно порождает `ABORT`; отказ rollback возвращает platform
  error, увеличивает `roam_reconnect_fallbacks` и требует от адаптера очистить candidate
  state перед полным reconnect. `stop/start` и terminal failure удаляют невыданные команды;
- если caller buffer мал, API возвращает требуемый размер и **не извлекает** событие;
- ABI 1.13 выдаёт path-refresh запрос только при одновременных core/platform capability bits.
  Его положительные `sequence` и `plan_generation` используют прежний 48-байтовый header.
  Adapter отвечает `PathUpdate` той же generation с reason/flag
  `same_network_nat_failure`, не реализуя второй retry timer или reconnect policy.
  `stop/start` и terminal failure удаляют queued refresh вместе с queued path commands;
- план несёт generation, адрес/префикс, MTU, tunnel gateway, фактический IP carrier,
  маршруты с gateway/metric,
  DNS с address/port, full-tunnel, kill-switch, `max_streams` и `adaptive`. Платформа обязана подтвердить ту же
  generation целиком; отказ переводит ядро в `Failed`;
- ABI сейчас собирается только для 64-битных GUI-целей. 32-битные router builds не включают
  feature и продолжают собираться без FFI.
- входные байты заимствуются только на время вызова, выходные буферы всегда принадлежат
  caller. Разные handles выполняются параллельно, операции одного handle сериализуются;
  adapter должен остановить свои workers перед `free`;
- panic внутри операции над handle инвалидирует только этот generation и возвращает
  `QELI_CLIENT_PANIC`, а не маскируется как `QELI_CLIENT_INVALID_HANDLE`.
- ABI 1.1 добавляет generation-scoped владение TUN fd. `set_tun_fd` делает собственный
  атомарный `CLOEXEC`-дубликат, не забирает caller fd и закрывает native-копию при replacement,
  reject, stop или free. Если адаптер заявил `QELI_PLATFORM_TUN_FD`, положительный ACK плана
  без attach запрещён. В этом срезе packet IO намеренно не стартует: до JNI handoff Android
  Kotlin loop остаётся единственным читателем TUN.
- ABI 1.2 добавляет `SocketProtect` через ту же bounded queue. Payload содержит только fd,
  `event.sequence` является одноразовым request ID, а
  `qeli_client_socket_protect_result` возвращает результат синхронного platform protect.
  Владелец Rust-сокета держит descriptor открытым до ACK и получает результат через oneshot;
  stop/free отменяют ожидание, а чужой или повторный ID получает `STALE_REQUEST`. Producer уже
  подключён: при Android `start()` ядро создаёт неблокирующий IPv4 TCP/UDP carrier, а положительный
  ACK переводит его из pending в защищённый socket slot, который потребляет ABI 1.6. Reject
  закрывает fd и переводит core в `Failed` с error event.
- ABI 1.3 добавляет явный `qeli_client_set_device_id` и capability
  `QELI_CORE_DEVICE_ID_INPUT`. Адаптер передаёт ровно 16 ненулевых байт до `start()`;
  ядро копирует значение, очищает старую копию при замене/free и не создаёт конкурирующую
  identity. Android передаёт существующий persisted ID из `SharedPreferences`, очищая
  временные Kotlin/JNI-массивы. ABI 1.6 использует identity в единственном общем handshake;
  второго сеанса нет.
- ABI 1.4 добавляет коррелированный запрос `ServerIdentity` и
  `qeli_client_server_identity_result`. JSON содержит `server_id` и 64-символьный lowercase
  public key, а `event.sequence` служит одноразовым request ID. Producer обязан публиковать
  его только после того, как server-auth proof доказал владение этим ключом. Android применяет
  существующую persisted-политику `qeli_known_hosts`, синхронно записывает first-use ключ только
  после proof и fail-closed отклоняет замену или ошибку persistence. ACK, reject, stale ID и
  отмена при stop/free используют
  ту же bounded queue и oneshot-схему, что socket protection. Verifier общего TCP-handshake
  теперь async и ждёт решение платформы без busy polling.
- ABI 1.5 добавляет ограниченный migration-вход
  `qeli_client_publish_handshake_network` и capability
  `QELI_CORE_HANDSHAKE_NETWORK_INPUT`. Android передаёт полный аутентифицированный plaintext
  `OK:`, итоговый path/config MTU и явный compatibility DNS fallback. Rust повторно разбирает
  server DNS/routes, назначает следующую generation и публикует канонический `NetworkPlan`.
  Android применяет из него address/prefix/MTU, full/split routing, routes и DNS, принимает TUN
  fd и только затем подтверждает generation. Синхронный publish+poll удерживает monitor JNI
  owner, поэтому фоновый event pump не может перехватить plan. Android заявляет `KILL_SWITCH`
  только при уже включённом системном Always-on VPN lockdown и повторно проверяет его перед
  ACK; требующий защиты профиль иначе отклоняется fail-closed. По той же причине отклоняется
  DNS plan с нестандартным портом; любая ошибка проверки после публикации проходит через
  отрицательный ACK/retire.
- ABI 1.6 добавляет capability `QELI_CORE_NATIVE_DATA_PLANE` и блокирующий
  `qeli_client_run`. Generation-safe lease удерживает работающего owner без registry mutex и
  исключает reuse handle/UAF, пока `stop` или `free` отменяет generation. Android runtime
  принимает защищённый carrier, выполняет общие TCP/UDP handshake и packet loops, публикует
  `NetworkPlan`, ждёт точный ACK и прикреплённые TUN descriptors и отдаёт live byte/packet
  counters через существующий stats ABI. TCP поддерживает fake-TLS, plain, obfs,
  Reality-TLS и fixed/adaptive bonding. UDP поддерживает fake-TLS и obfs, QUIC wrapper,
  retransmit/fragmentation handshake, активный MTU probe, heartbeat, shaping, padding и
  normalization. Отмена проверяется во всех ожиданиях и packet loops; `stop/free` будит owner
  даже при заполненной event queue.
- ABI 1.7 добавляет `QELI_CORE_TUN_PACKET_IO`, platform capability
  `QELI_PLATFORM_TUN_PACKET_BATCH` и generation-scoped `qeli_client_tun_push/pull` для
  TUN-реализаций без переносимого fd. Caller передаёт один непрерывный буфер и массив длин;
  размер пакета ограничен 65 535 байтами, batch — 64 пакетами, а обе очереди и их reusable
  buffer pools ограничены и применяют backpressure без fallback-аллокаций. Stale generation,
  malformed lengths и IO до положительного `NetworkPlan` ACK отвергаются. ABI 1.7 был
  промежуточным Windows packet seam и остаётся активным для iOS. Windows/macOS
  запускают тот же `qeli_client_run`: Rust владеет DNS/connect, carrier, handshake, crypto,
  TCP/UDP/QUIC/Reality, bonding и packet loops. После TC-2.2 macOS C# только открывает utun, применяет
  routes/DNS/kill-switch и передаёт fd в Rust через существующий ABI 1.1 `TUN_FD` контракт.
  `NetworkPlan.carrier_address` содержит IP реально подключённого peer, поэтому bypass route
  не делает повторное потенциально отличающееся DNS-разрешение.
- Runtime input теперь несёт все упорядоченные IPv4 carrier-кандидаты, разрешённые платформой
  на физической сети. Android использует `Network.getAllByName`, desktop и iOS кэшируют набор
  до перехвата DNS сохранённым TUN. Rust пробует все адреса для TCP, а reconnect generation
  ротируют список для UDP. Так устранены и отказ первого A-record, и hostname reconnect-loop.
- ABI 1.8 подключает iOS Packet Tunnel к тому же packet seam и добавляет handle-free
  `qeli_client_udp_probe`/`QELI_CORE_UDP_DIAGNOSTIC` для Windows, macOS и iOS.
  Additive `NetworkPlan.pushed_routes` отделяет аутентифицированные серверные маршруты от
  client/local routes, а `NetworkPlan.data_plane` передаёт в status UI effective post-push
  padding, heartbeat и shaping только для отображения — применяет их уже Rust. iOS adapter
  отклоняет весь план до ACK, если хотя бы один маршрут нельзя выразить как `NEIPv4Route`,
  и не объявляет частично установленный plan успешным.
  iOS также применяет разобранный `ReconnectPolicy`: временные runner/packet-pump ошибки
  создают новый native handle после bounded backoff при сохранении fail-closed настроек;
  ошибки identity/config/unsupported plan остаются terminal.
- ABI 1.9 добавляет `QELI_PLATFORM_TUN_WINTUN`, `QELI_CORE_WINTUN_IO` и
  `qeli_client_set_wintun_adapter`. Windows C# создаёт уникальный интерфейс и применяет
  platform network plan, но до ACK передаёт его фактическое имя ядру. Rust открывает
  независимый adapter handle, владеет session/read-event/rings и освобождает receive packets
  по RAII. Managed код больше не видит payload и не синхронизирует ring lifetime.
- Android создаёт `ClientCore` через generation-safe JNI adapter и проводит реальный service
  lifecycle через `new/start/run/stop/free`. Kotlin опрашивает ту же bounded event queue на
  `Dispatchers.IO`, выполняет только platform-операции (`VpnService.protect`, persisted trust и
  `NetworkPlan`/TUN setup), затем передаёт TUN fd Rust. JNI не заводит вторую очередь или
  callback. Adapter требует ABI 1.6 и `NATIVE_DATA_PLANE`; ошибка загрузки или negotiation
  fail-closed останавливает подключение без Kotlin payload fallback. На JNI-границе Android
  переводит совместимую форму `dns = <ip>` в общую `dns_servers = <ip>` и явно передаёт свой
  исторический full-tunnel default как `gateway = true`. Lab e2e подтверждает native ownership
  и обратный TUN-трафик для TCP fake-TLS, plain, obfs и Reality-TLS; UDP fake-TLS, obfs и QUIC;
  heartbeat/shaping; MTU report; adaptive bonding растёт сверх primary-соединения, вплоть до
  настроенных четырёх защищённых потоков. Временные
  профили и пользователи удаляются после теста.

Аутентифицированные TCP/UDP sessions и безопасный расчёт `NetworkPlan` теперь являются общим
client-кодом: identity/trust, device ID, защищённые carriers и TUN setup передаются явными
adapter-входами. Linux использует их через in-process adapter, Android — через ABI 1.6,
Windows — через Wintun ownership ABI 1.9, macOS — через fd ownership ABI 1.9, iOS — через
packet seam ABI 1.8. Все транспорты обязаны выполнить
`NetworkPlan → platform apply → TUN attach/packet seam → ACK` до запуска packet loops.
После ACK общий Android/Linux fd-backed backend владеет двумя `OwnedFd`, ограниченными
очередями, reader/writer workers и TUN/TAP-преобразованием. Uplink reader использует заранее
выделенный пул не более 4 МиБ на соединение:
`TunPacket` проходит без копии через TCP distributor или UDP encrypt path и возвращает
allocation через `Drop` до первого socket await. На Android два native packet worker теперь
являются единственными payload reader/writer; активный Kotlin-путь не читает, не шифрует и не
пишет пакеты туннеля.
`PacketCodec::encrypt_packet_into` затем
формирует record в caller-owned буфере: TCP/UDP writer выделяет real/cover storage один раз на
соединение, а UDP-QUIC переиспользует отдельный envelope. Старые allocating entry points
сохранены для handshake/control и совместимости. `Obfuscator` так же получил caller-owned
варианты: клиентские TCP/UDP writers переиспользуют scratch для normalization и padding
реального/cover/heartbeat-трафика, а серверные TCP/UDP handlers и общий downlink forwarder —
task-owned padding scratch. Allocating-обёртки остаются для совместимости и негорячих путей.
Исходящий wire path сервера использует отдельный RAII-пул размером не более 4 МиБ на
аутентифицированную сессию. Вместимость слота следует за наибольшим payload, который реально
может сформировать профиль (`tun.mtu`, heartbeat или максимум traffic shaping), а не за
абсолютным receive-пределом: профиль с MTU 1400 получает 2 906 слотов вместо 251. Пул общий
для всех bonded TCP-потоков и создаётся только после AUTH, поэтому half-open TCP/UDP-сессии
его не резервируют. Общий forwarder шифрует прямо в pooled storage, заранее отвергает record,
точный размер которого превысит слот и заставит `Vec` вырасти, а bounded writer-очередь
удерживает владение до фактической записи в сокет. Recycling использует короткий общий stack
и semaphore вместо async mutex и mpsc-hop. TCP cover/heartbeat используют один writer-owned
scratch, UDP cover/heartbeat — session pool, а QUIC — один переиспользуемый envelope.
На обратном пути отдельный RAII-пул ограничивает
суммарную запрошенную capacity 4 МиБ на Linux connection generation: 251 record-слот вместимостью
`TLS_RECORD_HEADER + MAX_RECORD_SIZE`. `read_record_into` читает TCP framing прямо в выданный
слот, а borrowed `unwrap_quic_payload` извлекает UDP-QUIC payload без промежуточного `Vec`.
`decrypt_packet_in_place` превращает record в plaintext внутри того же allocation; TCP
inline/pipeline и UDP сохраняют владение им через очередь TUN writer, а `Drop` возвращает слот
только после записи или сброса. При исчерпании TCP создаёт backpressure до следующего чтения,
UDP сбрасывает datagram без блокировки heartbeat/liveness loop, и ни один путь не создаёт
fallback allocation. Поэтому формат провода не изменён.
Generation-scoped data-plane уже реализован с реальным владением: Unix fd-backed клиенты
передают ядру дубликат дескриптора, Windows подключает созданный платформой Wintun-адаптер,
а packetFlow/compatibility-клиенты используют ограниченные push/pull batch-очереди.

### 5.2. Реализованная data-plane поверхность

```text
qeli_client_set_tun_fd(handle, generation, fd)                    -> rc
qeli_client_set_wintun_adapter(handle, generation, name, name_len)-> rc
qeli_client_tun_push(handle, generation, pkts, bytes, lens, n, *accepted) -> rc
qeli_client_tun_pull(handle, generation, buf, cap, lens, lens_cap, *n, *bytes) -> rc
```

Требования к контракту, вытекающие из §4.1:

- **буферы предоставляет вызывающая сторона**, ядро не возвращает `Box::into_raw` на
  горячем пути;
- **события — опрашиваемая очередь**, а не колбэки: колбэк из Rust в JVM/CLR требует
  attach потока и усложняет управление жизненным циклом;
- **конфигурация передаётся текстом** (flat-INI или `qeli://`), парсит её ядро —
  это убирает три реализации парсера разом.

---

## 6. План

### TC-0. Предпосылки

| ID | Пункт | Статус |
|---|---|---|
| TC-0.1 | **Собрать FFI-cdylib с `panic = "unwind"`.** Feature `ffi-cdylib`/`transport-core-ffi` останавливает release-сборку с `panic = "abort"`; штатные build scripts задают unwind, а тест намеренной паники проверяет возврат кода ошибки без unwind через ABI. | ✅ 0.7.15 |
| TC-0.2 | Решить вопрос по iOS: у Network Extension жёсткий потолок памяти, jemalloc там недоступен. Посчитать буферный бюджет ядра до начала работ. | ✅ ABI 1.8: два packet pool по 32 × 65 535 = 4 194 240 байт; caller buffers Swift ≤ 768 КиБ; очереди 128, без fallback allocation |
| TC-0.3 | Завести бенчи `PacketCodec` (Rust и C#) как **постоянные**, чтобы регрессия ловилась в CI, а не разово. | ✅ release-mode Rust/C# harness + CI gate |
| TC-0.4 | Замер managed vs Rust на одном железе. | ✅ 2026-07-30, §2 |

**Критерий приёмки TC-0:** паника в FFI возвращает код ошибки, а не роняет процесс
(проверяется тестом с намеренной паникой); бюджет памяти iOS зафиксирован числом.

Постоянный TC-0.3 измеритель запускается без внешнего benchmark framework:
`cargo run --release --no-default-features --features packet-bench --bin packet-codec-bench -- --ci`
для Rust и `dotnet run --project qeli-shared/QeliConformance -c Release -- packetbench --ci`
для managed codec. Оба выполняют реальный
1400-байтовый encrypt/decrypt round-trip после warm-up и проверяют plaintext. Rust требует,
чтобы caller-owned `Vec` больше не рос; C# фиксирует allocated bytes/round-trip. CI floors
(50 МиБ/с Rust, 10 МиБ/с C#, 32 КиБ managed allocations) намеренно ловят многократный
регресс и не считаются показателем скорости релиза: точный throughput по-прежнему измеряется
на лабе.

### TC-1. Transport API и вынос ядра — 2–3 недели

| ID | Пункт | Статус |
|---|---|---|
| TC-1.1 | Спроектировать и зафиксировать C-ABI (§5), включая таксономию ошибок и формат событий | ✅ ABI 1.0 freeze-review: version/capability negotiation, расширяемые output structs, ownership/concurrency, panic и event/JSON contracts закреплены header и тестами |
| TC-1.2 | Data-plane путь **без аллокаций на пакет**: буферы вызывающей стороны, никаких `Box::into_raw` на горячем пути | ✅ Все active paths используют bounded reusable pools/caller buffers. macOS payload проходит по fd, Windows uplink удерживает Wintun ring packet до RAII-release, а downlink копируется из bounded Rust pool прямо в send ring. Managed per-packet allocation/copy на desktop нет |
| TC-1.3 | Обработка конфигурации целиком в ядре: приём flat-INI и `qeli://` | ✅ все production transports проходят strict Rust parser; платформенные модели остаются UI/editor validation |
| TC-1.4 | План маршрутов/DNS как **событие** ядра, а не действие | ✅ Linux/Android/Windows/macOS/iOS используют канонический plan и обязательный generation ACK |

**Критерий приёмки:** Rust-клиент на Linux работает **через новый API** (а не мимо него),
e2e на лабе зелёный, провод байт-в-байт прежний.

Граница конфигурации сохраняет намеренные платформенные различия, но не допускает расхождения
схемы. Source-contract теперь доказывает, что Rust, Android, C# и Swift распознают один и тот
же набор из 80 ключей. Полная историческая таблица «0.7.14 → 0.7.15» приведена в
[матрице клиентских ключей](CLIENT-CONFIG-MATRIX.md). Platform editors моделируют только применимые поля и переносят остальные
при open/save. Android теперь также моделирует `kill_switch`: общий план требует capability,
а platform-adapter подтверждает его только после проверки системного Always-on VPN lockdown.
Сам системный переключатель по-прежнему принадлежит пользователю/MDM, поэтому отсутствие
lockdown приводит к fail-closed отказу, а не к ложному ACK.

Lifecycle-критерий закрыт; Android, Windows, macOS и iOS теперь используют общий transport data plane. Полный lab
build зелёный (полный default library/binary/integration suite; минимальный
профиль `transport-core-ffi` — 333 passed и 1 ignored), строгий default clippy зелёный;
Android — 67/67 JVM-тестов, warning-free NDK build arm64/x86_64 и APK; netns routing/kill-switch
e2e — 26/26. Финальный бинарник на 2-vCPU лабе показывает TCP fake-TLS 469↑/701↓ Мбит/с и
TCP obfs 540↑/562↓ Мбит/с при нулевых server session drops. UDP достигает 300 Мбит/с при
0,06% потерь и 400 Мбит/с при 1,86%; на 500 Мбит/с потери 8,27%, и эта ступень остаётся
потолком одного flow/worker, а не заявленной характеристикой релиза. Ping loss во всех
режимах 0%. Uplink TUN allocations уже переиспользуются с жёстким
backpressure вместо fallback-аллокации, а uplink-шифрование и QUIC envelope используют
connection-owned buffers вместо нового wire `Vec` на пакет. Downlink record проходит через
фиксированный пул до фактической TUN write: TCP получает backpressure, UDP — drop-on-exhaustion,
без fallback allocation. Normalization и padding реальных/cover/heartbeat records теперь также
используют caller/task-owned scratch вместо временного `Vec`. Зашифрованный server downlink
аналогично живёт в ограниченном session pool до socket write; bonded-потоки разделяют один
бюджет, а half-open сессии его не выделяют. Dedicated inbound TUN writer теперь читает исходную
bounded очередь напрямую; удаление async bridge и второй очереди на 256 слотов устранило
измеренную точку внутренних UDP burst-drops без увеличения memory bound. Серверный TUN→client
reader теперь читает пакет прямо в общий RAII-пул профиля (целевой бюджет 32 МиБ, минимум один
slot на очередь) и возвращает allocation после forwarder. Обратный client→TUN путь читает TCP
record прямо во второй bounded pool, расшифровывает его на месте и передаёт тот же allocation
TUN writer; UDP receive/QUIC unwrap используют borrowed slice и pooled decrypt без промежуточных
`Vec`. macOS передаёт utun fd ядру, а Windows ABI 1.9 открывает Wintun session/rings внутри
Rust: uplink packet остаётся в receive ring до RAII-release, downlink идёт из bounded decrypt
pool прямо в `WintunAllocateSendPacket`. Payload через C# на desktop больше не проходит.
Кодовые критерии TC-1, TC-2.2 и TC-2.3 закрыты; отдельная работа по UDP throughput/buffer
tuning остаётся. XCFramework/Xcode simulator включены в CI; live utun и Wintun full-tunnel
validation с новыми native libraries остаётся release gate.

### TC-2. TUN-бэкенды в Rust — 5.5 недели

| ID | Платформа | Объём |
|---|---|---|
| TC-2.1 | Android: приём fd от `VpnService` + upcall `protect()` | 1 нед |
| TC-2.2 | macOS: utun | 1 нед |
| TC-2.3 | Windows: Wintun, владение кольцом в Rust | 2 нед |
| TC-2.4 | iOS: пакетный шов к `packetFlow` | 1.5 нед |

TC-2.1 **закрыт для активного Android-пути**: ABI 1.1 принимает generation-scoped CLOEXEC-дубликат TUN fd, ABI 1.2
добавляет коррелированный socket-protect request/ACK с oneshot-ожиданием, ABI 1.3 принимает
стабильный platform device ID, ABI 1.4 добавляет server-identity trust request/ACK, ABI 1.5
публикует реальный Android network plan и принимает generation-scoped TUN fd, а ABI 1.6
запускает защищённый carrier и общие packet pumps. Android заявляет `SOCKET_PROTECT`,
`SERVER_IDENTITY`, `TUN_FD` и `NATIVE_DATA_PLANE`; Kotlin обслуживает эти platform-запросы и
не владеет payload-байтами на активном пути. Транспортная половина `QeliService.kt` также
физически удалена (3 921 → 1 443 строки): в сервисе не осталось dormant fallback для handshake,
codec, TCP/UDP/Reality, MTU/QUIC pumps или bonding. Android TC-3.1 теперь закрыт: pre-connect
проверка UDP — handle-free вызов `TransportCore` JNI, принимающий credential-free профиль и
использующий ровно тот же Rust hybrid-PQ ClientHello flight, fragmentation, QUIC и obfs, что
рабочий transport. Kotlin `protocol/*`, transport crypto, RealTls/ML-KEM/TrafficShaper wrappers,
дублирующие conformance suites и 14 legacy JNI-входов удалены. Оставлен только `BackupCrypto`
для импорта/экспорта профилей, а не wire IO.

TC-2.2 **закрыт на уровне исходников и локальных gate без повышения ABI**: macOS C# открывает
utun и сохраняет исходный fd только для lifecycle/route cleanup; перед положительным
`NetworkPlan` ACK ядро получает generation-scoped CLOEXEC-дубликат через ABI 1.1 `TUN_FD`.
Общий Rust fd-pump снимает/добавляет четырёхбайтовый utun address-family prefix, использует
`writev` без временного payload-буфера и неблокирующие reader/writer workers. В `UtunDevice`
не осталось методов чтения/записи payload. Universal2 dylib ABI 1.9 уже прошёл побайтно
идентичную A/B-сборку на лабе, copy/provenance gate и упаковку подписанного приложения. Живой
full-tunnel e2e на macOS остаётся аппаратным gate: доступная лаба работает на Linux и не имеет
utun/macOS runtime.

TC-2.3 **закрыт на уровне исходников и локальных gate в ABI 1.9**: Windows C# создаёт только
уникальный qeli-owned adapter и сохраняет creator handle для interface lifetime/network cleanup.
Перед ACK ядро получает фактическое имя, открывает независимый handle через уже загруженный и
проверенный `wintun.dll`, запускает session и единолично владеет read-event/rings. Uplink не
копируется из ring: Rust-объект удерживает указатель и освобождает его в `Drop`; downlink требует
одну системную копию из bounded decrypt pool в send ring, но без FFI/managed шва. Stop закрывает
очереди, ждёт reader/writer и только затем завершает session, поэтому прежний UAF-класс удалён
вместе с managed `ReceivePacket`/`SendPacket`. Пересобранная `qeli.dll` ABI 1.9 прошла
побайтно идентичный A/B, exports/provenance, Release build/selftest и живой server handshake с
полным `NetworkPlan`. Admin full-tunnel Wintun data-plane остаётся платформенным gate.

TC-2.4 **закрыт в ABI 1.8**: `NEPacketTunnelFlow.readPackets/writePackets` соединены с
generation-scoped bounded `tun_push/pull`; packet pools и очереди имеют фиксированный iOS
budget. Platform adapter применяет/отклоняет весь `NetworkPlan` до запуска pumps.

**Критерий приёмки каждого:** туннель поднимается и передаёт трафик под управлением ядра,
при этом платформенный код не трогает ни одного байта payload.

> TC-2.3 отдельно: у Windows-клиента уже был **UAF в `wintun.dll`**. ABI 1.9 удаляет
> managed session и его конкурентный Dispose: Rust session живёт под `Arc`, workers join
> предшествует `WintunEndSession`, а каждый outstanding receive packet удерживает owner.

### TC-3. Интеграция клиентов — 8 недель

| ID | Клиент | Что удаляется | Объём |
|---|---|---|---|
| TC-3.1 | Android | ✅ transport сервиса, `protocol/*`, transport crypto и legacy JNI удалены; UDP diagnostic использует общий Rust first-flight builder | завершено в 0.7.15 |
| TC-3.2 | Windows | ✅ библиотека ABI 1.9 пересобрана; source path владеет Wintun session/rings в Rust; managed runtime и packet methods удалены; live handshake/NetworkPlan зелёный | platform gate: admin Wintun full-tunnel data plane |
| TC-3.3 | macOS | ✅ universal2 dylib ABI 1.9 пересобран и упакован; source path передаёт utun fd Rust-ядру и не трогает payload | hardware gate: live Mac utun e2e |
| TC-3.4 | iOS | ✅ восемь Swift runtime-файлов (4 046 строк) удалены; компактный platform adapter использует общее Rust-ядро и условно объявляет fail-closed path transactions ABI 1.14, включая появившийся в ABI 1.13 `PATH_REFRESH`, только когда их предоставляет загруженное ядро | code complete; Xcode/device gate остаётся |

**Порядок именно такой:** Android первым — он молча пропустил M6, то есть риск
расхождения там доказан; iOS последним — единственная платформа без fd и с потолком памяти.

**Критерий приёмки каждого:** существующие conformance-тесты клиента продолжают проходить
**против ядра**; e2e на лабе против сервера; UI и уведомления не деградировали.

### TC-4. Сборка, CI, упаковка — 2 недели

| ID | Пункт |
|---|---|
| TC-4.1 | Предыдущая матрица whole-client кросс-сборок закрыта для Android arm64/x86_64, Windows x64 и macOS universal2 с 6 Reality + 20 client exports; source ABI 1.12 расширил gate до 22 client exports и 21 Android JNI export. ABI 1.13 добавляет только event/capability values и сохраняет эти числа экспортов; ABI 1.14 добавляет типизированные path results без новых экспортов. Базовый compatibility floor iOS остаётся ABI 1.11, а fail-closed path transactions вместе с `PATH_REFRESH` требуют 1.14; `build_native.sh` теперь по умолчанию включает `transport-core-ffi experimental-roaming`. Feature Clippy для `aarch64-apple-ios` зелёный, но реальный device+simulator XCFramework/Xcode build требует macOS |
| TC-4.2 | ✅ Все четыре библиотеки прошли живые побайтно идентичные A/B-сборки на лабах `.10`/`.11`; общий mock-tested harness выполняет ограниченный source sync, preflight точных targets и проверенный atomic pull. Закреплены Rust 1.97.0, Zig 0.13.0, cargo-zigbuild 0.23.0, GNU ld 2.44, apple-codesign 0.29.0, NDK 26.3.11579264 и cargo-ndk 4.1.2. macOS до детерминированной ad-hoc подписи нормализует install name, content-derived UUID и недопустимый нестабильный GOT-index Zig; SHA256, экспорты и provenance работают как fail-closed gates |
| TC-4.3 | ✅ Свежесть conformance-векторов + release-mode Rust/C# бенчи TC-0.3 входят в Linux/Windows/macOS CI |

### TC-5. Удаление дублей — 1.5 недели

| ID | Пункт |
|---|---|
| TC-5.1 | ✅ Production runtime-дубли Android, Windows/macOS и iOS удалены; C#/Swift wire/crypto остаются только как conformance/KAT, а сохранённый Swift wire-код не компилирует ни один production iOS target |
| TC-5.2 | ✅ Reachability Windows/macOS/iOS переведена на ABI 1.8 `qeli_client_udp_probe`; старые C#/Swift first-flight helpers не входят в active build |

Desktop cleanup 0.7.15 сократил `VpnTunnelBase.cs` с 3 287 до 1 126 строк и удалил
отдельный 139-строчный wrapper `RealTls`: чистое сокращение на 2 300 строк. Оставшиеся
C# `Protocol/` и `Crypto/` не являются production fallback: их используют только
CLI/cross-language KAT. UI reachability теперь вызывает Rust ABI 1.8.

**Итого: ~19–21 неделя чистой работы**, реалистично **5–7 месяцев** в одиночку с учётом
регрессий и живого тестирования.

---

## 7. Риски

| Риск | Оценка | Что делать |
|---|---|---|
| Паника в FFI роняет хост-приложение | **высокий, существует уже сейчас** | TC-0.1 — блокер |
| Потолок памяти Network Extension на iOS | средний | TC-0.2, бюджет до начала работ |
| Копия downlink из Rust decrypt pool в Wintun send ring | измеряемый | platform/FFI copy удалена ABI 1.9; учитывать в lab throughput и последующем buffer tuning |
| Размер бинаря: +3.7 МБ (win dll), +8.5 МБ (mac universal), по `.so` на ABI у Android | низкий | сплиты ABI у Android |
| Отладка через границу: теряются управляемые стек-трейсы | средний | символизация нативных крашей, коды ошибок вместо исключений |
| Регрессия end-to-end скорости | **открытый риск** | microbench ядра из §2 недостаточен; сохранить TC-0.3 и прогонять lab TCP/UDP baseline, затем tuning очередей/буферов |

---

## 8. Порядок относительно roadmap

Аргумент в пользу «сейчас, а не потом»:

- **Роуминг** ([ROAMING.md](../plans/ROAMING.md)) — общий TCP/UDP core и path executors Android, Linux/OpenWrt, Windows, macOS и iOS source-complete под feature gate; остаются real-device/race/soak matrix и поэтапный rollout;
- **multipath** — реализован только у Rust-клиента.

Если ядро делать после них, обе возможности придётся написать четыре раза. Если до —
один раз. Это самый сильный довод по срокам, и он со временем только дорожает.

Побочный эффект: conformance-фикстуры, заведённые в 0.7.14, становятся **приёмочным
тестом миграции** — после подмены ядра существующие тесты каждого клиента обязаны
продолжать проходить.

---

## 9. Открытые вопросы

1. **Порог отказа от платформенной реализации.** Держим ли мы managed-реализацию как
   запасной путь на время миграции, или переключаемся жёстко? Запасной путь сохраняет
   расхождение, ради устранения которого всё и затевается.
2. **Windows-служба.** Сейчас часть логики живёт в службе, часть в UI — куда попадает
   ядро и кто владеет его жизненным циклом.
3. **Обновление ядра отдельно от приложения** — заманчиво для быстрых фиксов протокола,
   но на iOS и в Play это ограничено правилами магазинов.
