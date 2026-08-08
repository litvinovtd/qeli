# qeli — общее транспортное Rust-ядро для всех клиентов

Предложение и план: перенести установку соединения, выбор транспорта, хендшейк, роуминг,
multipath, автоматический fallback и обработку конфигурации в **одно** Rust-ядро,
подключаемое во все клиенты через FFI. Платформенному коду остаются TUN, UI, уведомления
и системные API.

Формат документа — рабочий чек-лист в стиле [REFACTOR-PLAN.md](REFACTOR-PLAN.md):
у каждого пункта есть ID, объём, подход и **критерий приёмки**.

Легенда статуса: ⬜ не начато · 🟦 в работе · ✅ сделано · 🧪 ждёт сборки/e2e.

**Статус инициативы: 🟦 в работе.** Реализация начата 2026-08-08; первый совместимый
control-plane слой добавлен без переключения существующих клиентов. Составлено 2026-07-30.

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
   см. [BENCHMARK.md](BENCHMARK.md)).
4. **Крипто у клиентов неоднородно.** Android шифрует нативным Conscrypt (BoringSSL),
   C# — управляемым BouncyCastle. «Managed» — не единая категория, и выигрыш от переноса
   на Rust у Android будет заметно меньше, чем у Windows/macOS.

> Воспроизведение: бенчи были одноразовыми (C#-консоль с `ProjectReference` на
> `qeli-shared`, опубликованная self-contained под linux-x64, и `examples/bench_codec.rs`
> в Rust-крейте). В репозиторий не коммитились. При старте работ их следует завести
> заново как постоянные — см. **TC-0.3**.

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
`PacketCodec` benchmarks остаются отдельным пунктом TC-0.3.

---

## 3. Что дублируется сегодня

Посчитано по файлам, без тестов и артефактов сборки (2026-07-30):

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
| `qeli-ios/QeliPacketTunnel/QeliTunnelEngine.swift` | 1 436 | то же для iOS |
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

**Ключевое ограничение:** `qeli/src/tun/` — это **335 строк и только Linux**
(`/dev/net/tun`, `#[cfg(target_os = "linux")]`). Ни Wintun, ни utun, ни iOS. Именно это,
а не FFI, определяет объём работ.

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
qeli_client_abi_version()                                      -> 0x00010002
qeli_client_core_capabilities()                                -> bitmask
qeli_client_new(config, len, platform_caps, queue_cap, *handle) -> rc
qeli_client_start(handle)                                      -> rc
qeli_client_stop(handle)                                       -> rc
qeli_client_set_tun_fd(handle, generation, fd)                 -> rc  // ABI 1.1
qeli_client_poll_event(handle, *event, payload, cap, *needed)   -> rc
qeli_client_network_plan_result(handle, generation, rc, reason) -> rc
qeli_client_socket_protect_result(handle, sequence, rc, reason) -> rc  // ABI 1.2
qeli_client_state(handle, *state)                              -> rc
qeli_client_stats(handle, *stats)                              -> rc
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
- очередь ограничена (по умолчанию 64, максимум 256) и применяет backpressure без
  частично выполненного перехода состояния;
- заголовок события имеет фиксированную C-layout структуру и version; payload плана и
  socket-protect запроса — UTF-8 JSON, ошибка — UTF-8, смена состояния — без payload;
- до `new` адаптер сверяет ABI через `QELI_CLIENT_ABI_IS_COMPATIBLE`: major обязан совпасть,
  minor библиотеки должен быть не ниже minor заголовка; неизвестные capability bits, event
  kinds и добавочные JSON-поля не являются ошибкой;
- `QELI_CLIENT_EVENT_INIT` и `QELI_CLIENT_STATS_INIT` задают caller-owned `struct_size`.
  Ядро сохраняет его, пишет только известный обеим сторонам префикс и отвергает короткую
  ABI-1.0 структуру, не потребляя событие. Header проверяет layout 48/64 байта compile-time;
- если caller buffer мал, API возвращает требуемый размер и **не извлекает** событие;
- план несёт generation, адрес/префикс, MTU, tunnel gateway, маршруты с gateway/metric,
  DNS с address/port, full-tunnel и kill-switch. Платформа обязана подтвердить ту же
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
  ACK переводит его из pending в защищённый socket slot для будущего async handshake. Reject
  закрывает fd и переводит shadow-core в `Failed` с error event.
- Android уже создаёт этот же `ClientCore` через generation-safe JNI adapter и проводит
  реальный service lifecycle через `new/start/stop/free`. Это пока shadow-режим: временные
  config bytes обнуляются, а Kotlin опрашивает ту же bounded event queue через замороженный
  C ABI и проверяет фактическую последовательность `Created → Connecting`. JNI не заводит
  вторую очередь или callback: он переносит фиксированный 48-байтный little-endian header и
  payload с лимитом 1 МиБ, сохраняя двухпроходную семантику `poll_event`. Adapter проверяет
  ABI 1.2 и обязательные capabilities; JNI декодирует socket-protect JSON и возвращает ACK.
  Shadow-сервис теперь заявляет `SOCKET_PROTECT` вместе с фоновым dispatcher, который опрашивает
  ту же очередь с адаптивной паузой 20–250 мс, вызывает `VpnService.protect(fd)` до пяти раз с
  интервалом 100 мс и подтверждает точный sequence ID. Неожиданное событие отключает только
  shadow-core. Стартовые non-state события больше не теряются при lifecycle-проверке: они
  передаются тому же dispatcher на `Dispatchers.IO`. `TUN_FD` пока не заявляется, защищённый
  native wire socket ещё не подключается к серверу и payload не обрабатывается. Поэтому Kotlin
  data plane остаётся единственным рабочим путём, а baseline производительности не меняется.
  На JNI-границе Android переводит собственную совместимую форму `dns = <ip>` в единый
  `dns_servers = <ip>`: strict Rust parser больше не отключает shadow-core на профиле с явным DNS.
  Lab e2e подтверждает активный ABI 1.2 и socket-protect dispatcher для TCP и UDP, затем
  проверяет `Auth OK`, `TUN ready` и обратный ping; временные профиль и пользователь удаляются.

Ядро уже открывает и защищает Android wire-сокет, но пока не выполняет на нём connect,
handshake или шифрование. Linux-клиент
уже использует его через in-process адаптер: конфигурация проходит через `ClientCore`, а оба
handshake-пути (TCP и UDP) обязаны выполнить `NetworkPlan → platform apply → ACK` до запуска
пакетных циклов. После ACK общий fd-backed `transport_core::linux_tun` владеет двумя `OwnedFd`,
ограниченными очередями, reader/writer workers и TUN/TAP-преобразованием для обоих
транспортов. Uplink reader использует заранее выделенный пул не более 4 МиБ на соединение:
`TunPacket` проходит без копии через TCP distributor или UDP encrypt path и возвращает
allocation через `Drop` до первого socket await. Backend теперь также компилируется под Android,
а `ClientCore` умеет one-shot передать подтверждённую TUN generation в два owned read/write fd;
Android handoff ещё не включён. `PacketCodec::encrypt_packet_into` затем
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
`qeli_client_set_tun` и data-plane функции C ABI появятся только вместе с реальным владением
TUN, чтобы не публиковать «успешные» заглушки.

### 5.2. Целевая data-plane поверхность

```text
qeli_client_set_tun(handle, fd | ring)       -> rc  // Android/macOS/Windows
qeli_client_tun_push(handle, pkts, lens, n)  -> rc  // iOS packetFlow → ядро
qeli_client_tun_pull(handle, buf, cap, *n)   -> rc  // ядро → iOS packetFlow
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
| TC-0.2 | Решить вопрос по iOS: у Network Extension жёсткий потолок памяти, jemalloc там недоступен. Посчитать буферный бюджет ядра до начала работ. | ⬜ |
| TC-0.3 | Завести бенчи `PacketCodec` (Rust и C#) как **постоянные**, чтобы регрессия ловилась в CI, а не разово. | ⬜ |
| TC-0.4 | Замер managed vs Rust на одном железе. | ✅ 2026-07-30, §2 |

**Критерий приёмки TC-0:** паника в FFI возвращает код ошибки, а не роняет процесс
(проверяется тестом с намеренной паникой); бюджет памяти iOS зафиксирован числом.

### TC-1. Transport API и вынос ядра — 2–3 недели

| ID | Пункт | Статус |
|---|---|---|
| TC-1.1 | Спроектировать и зафиксировать C-ABI (§5), включая таксономию ошибок и формат событий | ✅ ABI 1.0 freeze-review: version/capability negotiation, расширяемые output structs, ownership/concurrency, panic и event/JSON contracts закреплены header и тестами |
| TC-1.2 | Data-plane путь **без аллокаций на пакет**: буферы вызывающей стороны, никаких `Box::into_raw` на горячем пути | 🟦 Linux TUN uplink/downlink и server encrypted downlink records используют bounded reusable pools; client TCP/UDP wire records, UDP-QUIC envelopes, normalization и padding переиспользуют caller/task-owned storage; внешний FFI-шов и оставшиеся server raw/inbound buffers впереди |
| TC-1.3 | Обработка конфигурации целиком в ядре: приём flat-INI и `qeli://` | 🟦 Linux подключён к единому strict parser; внешние клиенты впереди |
| TC-1.4 | План маршрутов/DNS как **событие** ядра, а не действие | ✅ TCP/UDP handshake Linux подключены к bounded queue и обязательному generation ACK |

**Критерий приёмки:** Rust-клиент на Linux работает **через новый API** (а не мимо него),
e2e на лабе зелёный, провод байт-в-байт прежний.

Lifecycle-часть критерия закрыта, а TUN-половина data plane получила первый общий backend:
полный lab build зелёный (531 пройденный библиотечный тест; профильные ABI-гейты зелёные), minimal-ABI
build/clippy и Windows cross-build зелёные; Android — 77/77 JVM-тестов, debug и release-minify
APK с arm64/x86_64 JNI bridge; netns routing/kill-switch
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
измеренную точку внутренних UDP burst-drops без увеличения memory bound. Весь TC-1 ещё не
закрыт: server raw TUN/inbound
buffers и wire socket/handshake/codec остаются в старом модуле, а внешний data-plane шов для
остальных платформ ещё не подключён.

### TC-2. TUN-бэкенды в Rust — 5.5 недели

| ID | Платформа | Объём |
|---|---|---|
| TC-2.1 | Android: приём fd от `VpnService` + upcall `protect()` | 1 нед |
| TC-2.2 | macOS: utun | 1 нед |
| TC-2.3 | Windows: Wintun, владение кольцом в Rust | 2 нед |
| TC-2.4 | iOS: пакетный шов к `packetFlow` | 1.5 нед |

TC-2.1 **в работе**: ABI 1.1 принимает generation-scoped CLOEXEC-дубликат TUN fd, а ABI 1.2
добавляет коррелированный socket-protect request/ACK с oneshot-ожиданием. Android JNI lifecycle,
event framing/parser, native socket producer, фоновый dispatcher и protect-result binding уже
подключены; платформа заявляет `SOCKET_PROTECT`, а общий POSIX TUN backend собирается Android NDK.
Впереди async connect/handshake на уже защищённом сокете, публикация реального network plan,
включение TUN handoff и packet pump.

**Критерий приёмки каждого:** туннель поднимается и передаёт трафик под управлением ядра,
при этом платформенный код не трогает ни одного байта payload.

> TC-2.3 отдельно: у Windows-клиента уже был **UAF в `wintun.dll`** (исправлен в 0.7.x).
> Перенос владения кольцом в Rust устраняет класс целиком, но требует аккуратности с
> временами жизни — закладывать запас на ревью.

### TC-3. Интеграция клиентов — 8 недель

| ID | Клиент | Что удаляется | Объём |
|---|---|---|---|
| TC-3.1 | Android | транспортная часть `QeliService.kt`, `protocol/*`, `crypto/*` | 2 нед |
| TC-3.2 | Windows | `VpnTunnelBase.cs` и `Protocol/*` из `qeli-shared` | 2 нед |
| TC-3.3 | macOS | то же (общая библиотека с Windows) | 1.5 нед |
| TC-3.4 | iOS | `QeliTunnelEngine`, `*Transport`, `PacketCodec` | 2.5 нед |

**Порядок именно такой:** Android первым — он молча пропустил M6, то есть риск
расхождения там доказан; iOS последним — единственная платформа без fd и с потолком памяти.

**Критерий приёмки каждого:** существующие conformance-тесты клиента продолжают проходить
**против ядра**; e2e на лабе против сервера; UI и уведомления не деградировали.

### TC-4. Сборка, CI, упаковка — 2 недели

| ID | Пункт |
|---|---|
| TC-4.1 | Матрица кросс-сборок: Android, Windows, macOS universal2 и iOS device+simulator **XCFramework** уже существуют для нативного crypto/realtls; расширить их на whole-client core после подключения data plane |
| TC-4.2 | Провенанс и воспроизводимость нативных библиотек |
| TC-4.3 | Гейт: conformance-векторы + бенчи из TC-0.3 в CI |

### TC-5. Удаление дублей — 1.5 недели

| ID | Пункт |
|---|---|
| TC-5.1 | Удалить ~17 000 строк портированного протокола |
| TC-5.2 | Удалять старые **языковые реализации** только после миграции последнего клиента. Conformance/KAT-фикстуры сохранить как регрессионные тесты провода, криптографии, конфигурации и `qeli://`, даже когда исполняющая реализация останется одна |

**Итого: ~19–21 неделя чистой работы**, реалистично **5–7 месяцев** в одиночку с учётом
регрессий и живого тестирования.

---

## 7. Риски

| Риск | Оценка | Что делать |
|---|---|---|
| Паника в FFI роняет хост-приложение | **высокий, существует уже сейчас** | TC-0.1 — блокер |
| Потолок памяти Network Extension на iOS | средний | TC-0.2, бюджет до начала работ |
| Аллокации на пакет через границу | средний | TC-1.2, буферы вызывающей стороны |
| Размер бинаря: +3.7 МБ (win dll), +8.5 МБ (mac universal), по `.so` на ABI у Android | низкий | сплиты ABI у Android |
| Отладка через границу: теряются управляемые стек-трейсы | средний | символизация нативных крашей, коды ошибок вместо исключений |
| Регрессия скорости | **низкий, измерено** | §2: ядро быстрее в 2.4–2.5×; TC-0.3 держит это в CI |

---

## 8. Порядок относительно roadmap

Аргумент в пользу «сейчас, а не потом»:

- **Роуминг** ([ROAMING.md](ROAMING.md)) — код ещё не начат;
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
