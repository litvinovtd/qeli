# qeli — аудит обнаружимости DPI

Документ перечисляет **сигналы (tells)**, по которым современная DPI отличает
трафик qeli от настоящего HTTPS/QUIC, с привязкой к коду, оценкой серьёзности и
приоритетом устранения. Изначально — **аудит** (без правок кода); с тех пор многие
теллы закрыты — отметки **✅** в тексте трекают уже исправленное (режим `reality-tls`,
WS-fronting/QUIC-shape для obfs, закалка fake-tls: PQ key_share, ALPN, чистка sig_algs).

Дополняет [AUDIT.md](AUDIT.md) (там модель безопасности крипто/auth); здесь —
только обнаружимость на проводе.

## Текущее состояние Reality/H2 0.8.0 (2026-08-26)

Текущий `reality-tls` — это **REALITY TLS 1.3 + настоящий HTTP/2**, а не прежний второй
fake-TLS handshake внутри внешнего TLS. Согласуется ALPN `h2`, открывается один долгоживущий
двунаправленный `POST /v1/events/stream`, используются настоящие H2 control frames/flow control,
а private qeli records батчатся в случайном окне 2–8 мс. PacketCodec AEAD остаётся end-to-end,
но его nonce и границы сообщений зашифрованы внутри TLS/H2 и не являются внешней TLS-разметкой.

В чистом lab corpus 6/6 H2-сессий прошли auth и двусторонний трафик; классификатор старой
transport-independent формы обнаружил 0/6 новых сессий при 0/6 false positive на control.
Это регрессионный результат против старого отпечатка, **не** вероятность обнаружения
промышленным DPI. Остались риски synthetic/OOD JA3-ротации, фиксированных H2 SETTINGS и одного
вечного POST; отдельно нужны active-probe, malformed TLS/H2, replay, reconnect и широкий
browser-control corpus. Доказательства:
[датированный PCAP-отчёт](../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).

В текущей dev-ветке поверх всех carriers также реализован согласуемый `PACKET_MUX_V1`
recordizer. После AUTH он одинаково применяется к TCP `plain`/`fake-tls`/`reality-tls`/`obfs`
и UDP `fake-tls`/QUIC-shape/`obfs`, включая AWG-варианты: объединяет несколько IP-пакетов,
случайно меняет внутренние границы записей и при необходимости делит один IP-пакет между ними.
Параметры задаются серверным `obf.recordizer.*` и аутентифицированно передаются клиенту.
Это закрывает транспорт-независимую корреляцию «один IP-пакет = одна qeli-запись» не только
для Reality/H2, но не исправляет специфические признаки самого внешнего carrier.

Важно: приведённый выше результат 0/6 относится к предыдущему Reality/H2 corpus. Общая
recordizer-реализация ещё должна пройти новый чистый PCAP-набор по каждому TCP/UDP режиму,
legacy/required negotiation, IPv4/IPv6 и нагрузке. До этого результат нельзя переносить на
остальные carriers или выдавать за измеренную вероятность обнаружения.

## Модель угроз (уровни DPI)

| Уровень | Метод | Реальные примеры |
|---|---|---|
| **D1** Пассивный сигнатурный | byte-pattern, статический JA3-blocklist | старые корпоративные NGFW |
| **D2** Пассивный статистический | энтропия, JA4/JA4+, распределение размеров/таймингов, SNI↔IP-консистентность | РФ ТСПУ, GFW (2022+), Иран |
| **D3** Активный пробинг | сам достукивается до сервера, реплеит/достраивает handshake | GFW, ряд провайдеров |

qeli `fake-tls`/`obfs` рассчитаны на **D1** (`obfs` также на энтропийный **D2**).
`PACKET_MUX_V1` снижает общий для всех режимов D2-признак размеров/границ, но не маскирует
ClientHello, внешний frame syntax, endpoint и долгосрочные тайминги.
`reality-tls` убирает прежние bare fake-TLS и nested-record признаки настоящим TLS 1.3 + H2
и мостит неавторизованные пробы на target. Он снижает перечисленные D2/D3-сигналы, но не
закрывает универсально timing, target-correlation и H2-semantic классификацию. `plain`
даже с recordizer остаётся самым заметным high-entropy режимом и предназначен только для
доверенных сетей.

Серьёзность: `CRIT` = одиночное правило ловит детерминированно; `HIGH` =
надёжный признак для D2/D3; `MED` = вклад в ML-классификатор / корреляцию.

---

## 1. fake-TLS, сторона клиента (ClientHello)

### 1.1 [CRIT] ClientHello без ALPN — ✅ исправлено
- **Было:** отсутствие ALPN позволяло выделить qeli одним правилом и использовалось как
  незащищённый маркер «свой».
- **Статус:** и bare `fake-tls`, и `reality-tls` безусловно предлагают `h2`/`http/1.1`;
  REALITY различает клиента только по криптографическому token/key_share. Регрессионный
  тест требует ALPN в полном Chrome-наборе расширений.

### 1.2 [HIGH] Набор cipher suites не браузерный — ✅ исправлено
- **Было:** GREASE + только `1301/1302/1303`, устойчивый non-browser JA4.
- **Статус:** bare `fake-tls` использует тот же единый 15-suite Chrome-list, что и
  `reality-tls`, плюс отдельный GREASE. Точный порядок и полный набор закреплены тестом;
  ошибочный запрет современного `0xCCA9` удалён.

### 1.3 [HIGH] Мало supported_groups — ✅ адресовано (PQ-группа добавлена)
- **Где:** [tls.rs build_supported_groups_extension](../../qeli/src/protocol/tls.rs).
- **Почему палило:** актуальный Chrome шлёт `X25519MLKEM768` (post-quantum) первым,
  плюс secp384/521. Отсутствие PQ-группы у клиента «образца 2026» — заметная
  аномалия для D2.
- **Статус — ✅ исправлено:** ClientHello теперь шлёт `X25519MLKEM768` (`0x11ec`)
  **первым** в supported_groups + соответствующий PQ key_share (1216 Б на проводе),
  как Chrome (`build_supported_groups_extension` / `build_key_share_extension`).

### 1.4 [HIGH] Отсутствовали обязательные browser extensions — ✅ исправлено
- **Было:** bare `fake-tls` не отправлял OCSP, SCT, ec_point_formats, session_ticket,
  renegotiation_info и ALPS.
- **Статус:** builder использует полный Chrome-shaped набор с GREASE, ALPN, TLS 1.3/1.2,
  PQ/classic key_share и случайной перестановкой middle-extensions. Тест разбирает реальный
  extension block и требует каждый критичный type, а не ищет случайную пару байт.

### 1.5 [MED] signature_algorithms устаревший — ✅ исправлено
- **Где:** [tls.rs build_signature_algorithms_extension](../../qeli/src/protocol/tls.rs).
- **Почему палило:** список содержал `rsa_pkcs1_sha1` (0x0201), который современные
  браузеры выпилили. Вклад в JA4-несовпадение.
- **Статус — ✅ исправлено:** `rsa_pkcs1_sha1` (0x0201) удалён из списка.

### 1.6 [HIGH] SNI↔IP несогласованность (decoy-pool) — ✅ default-path исправлен
- **Было:** голый IP выбирал новый домен Google/Cloudflare/Microsoft на каждом реконнекте.
- **Статус:** случайный client decoy-pool удалён. `fake-tls` при голом IP корректно не
  отправляет SNI; WebSocket obfs ставит фактический IP в `Host` (IPv6 — в скобках);
  `reality-tls` для IP требует явный валидный DNS `sni`. Контрольные символы/невалидные
  имена отклоняются до соединения. Явный operator front остаётся ответственностью оператора:
  qeli не может доказать соответствие CDN/anycast одному DNS-снимку без ложных отказов.

---

## 2. fake-TLS, сторона сервера (ServerHello / handshake)

### 2.1 [CRIT] Handshake-сообщения сервера идут открытым текстом
- **Где:** [tls.rs build_certificate](../../qeli/src/protocol/tls.rs),
  [build_finished](../../qeli/src/protocol/tls.rs) — оба завёрнуты в record
  `0x16` (handshake) открыто, как и ServerHello.
- **Почему палит:** в настоящем TLS 1.3 после ServerHello+CCS **всё** (Encrypted
  Extensions, Certificate, CertVerify, Finished) едет внутри `0x17`
  (application_data, зашифровано). Открытый `0x16`-Certificate после ServerHello —
  это сигнатура TLS 1.2 ИЛИ подделки. D2 (а тем более D3) ловит детерминированно.

### 2.2 [CRIT] Сертификат — псевдо-DER, не парсится как X.509
- **Где:** [tls.rs build_certificate](../../qeli/src/protocol/tls.rs) — 512 байт
  частично-структурированного мусора.
- **Почему палит:** D3-пробер, завершив handshake (или просто распарсив
  Certificate), видит, что это не валидный X.509 и не цепочка к публичному CA.
  Реальная цепочка для `www.microsoft.com` — ~3–5 КБ из нескольких сертов. 512-байт
  одиночный «серт» — мгновенная классификация.
- **Статус — касается только `fake-tls`/proxy-bridge (где серт в открытом `0x16`).**
  В `reality-tls` Certificate **зашифрован** внутри TLS 1.3 (`0x17`) — пассивному DPI
  не виден вовсе. С **cert-borrowing** (`handrolled=true`, 2026-06-06) hand-rolled
  сервер отдаёт qeli-клиенту **настоящую захваченную цепочку target'а** (не
  self-signed/dummy), с авто-refresh раз в 12ч — даже активный пробер, завершивший
  handshake, видит реальный серт `CN=www.microsoft.com` (issuer Microsoft TLS G2).
  Режим `reality`-proxy дополнительно мостит **чужие** коннекты на реальный сайт.

### 2.3 [MED] Бедный ServerHello
- **Где:** [tls.rs build_server_hello](../../qeli/src/protocol/tls.rs) — только
  supported_versions + key_share, нет других расширений; всегда cipher `1301`.
- **Почему палит:** реальный сервер варьирует выбранный suite и шлёт согласованный
  набор. Постоянный `1301` + минимальный SH = слабый, но устойчивый признак для D2.

---

## 3. Канал данных (application_data)

### 3.1 [HIGH] Явный 12-байтный nonce в каждой записи (legacy outer framing)
- **Где:** [packet.rs encrypt_packet](../../qeli/src/protocol/packet.rs) — record =
  `0x17 ‖ 0303 ‖ len ‖ nonce(12) ‖ ciphertext+tag`.
- **Почему палит:** настоящий TLS 1.3 использует **неявный** nonce (его нет на
  проводе). Постоянный 12-байтный префикс перед шифротекстом в каждой записи —
  структурный отпечаток на всём data-plane (Feistel-PRP в
  [packet.rs](../../qeli/src/protocol/packet.rs) прячет инкремент, но сам факт
  12 «лишних» байт в каждой записи остаётся). D2 при анализе межзаписевой
  структуры это видит.

### 3.2 [MED] Один IP-пакет → ровно одна qeli-запись (закрыто `PACKET_MUX_V1` для всех carriers)
- **Почему палит:** настоящий TLS режет/коалесцирует поток по границам до 16 КБ
  независимо от прикладных сообщений. Соответствие «1 запись = 1 MTU-пакет»
  (плюс фикс-оверхед +33 байта: 5+12+16) даёт характерное распределение размеров
  записей. Вклад в ML-классификатор размеров.
- **Статус dev:** после аутентифицированного согласования общий recordizer batch/coalesce/split
  работает до `PacketCodec` AEAD в TCP и UDP путях. Его служебные заголовки зашифрованы, размеры
  зажаты под carrier/path budget, а reassembly имеет timeout и жёсткие memory/inflight limits.
  `policy=prefer` сохраняет legacy-совместимость, `required` fail-closed отвергает старое ядро.
  Статус «закрыто» здесь означает устранение прямого отображения границ в реализации; внешний
  PCAP/DPI результат для всех режимов будет фиксироваться только отдельным повторным отчётом.

---

## 4. obfs-режим (structure-free)

### 4.1 [CRIT против D2] Полная энтропия с первого байта — ✅ адресовано (WS-fronting)
> **Статус:** закрыто опцией `obf.obfs_fronting = websocket` (дефолт). Начало
> obfs-соединения обёрнуто в рукопожатие WebSocket Upgrade (printable HTTP +
> `\r\n\r\n`), первый пакет проходит exemptions Ex2/Ex3/Ex4. См.
> `protocol/obfs.rs` (модуль `ws`) и `ObfsStream.kt`. Откат — `front=none`.

- **Где:** [obfs.rs](../../qeli/src/protocol/obfs.rs) — `[nonce(12)] ‖ ChaCha20-XOR`,
  никакой структуры; авторский комментарий это признаёт.
- **Почему палит:** ровно категория «fully encrypted traffic», которую GFW
  блокирует с 2022 (Wu et al., USENIX Security '23) и ТСПУ — эвристиками:
  доля printable-байт, popcount/энтропия, длина printable-серий, printable-
  префикс. Поток qeli-obfs не проходит **ни одной** из них → блок по «всё, что
  выглядит как ничто». «Structure-free» сегодня = детектируемая категория, а не
  невидимка.

### 4.2 [MED] UDP-obfs: nonce(12) открытым в каждой датаграмме — ✅ адресовано (QUIC-shape)
> **Статус:** закрыто 2026-06-05. Датаграмма получила форму QUIC short-header
> `[flag(0x40|x)][nonce:12 как conn-id][protected]` — первый байт в диапазоне QUIC
> short-header (fixed-bit set), а не равномерно-случайный. Зеркалировано в obfs.rs /
> ObfsStream.kt / ObfsStream.cs. Breaking wire-change для UDP-obfs (деплой
> скоординированный). Глубокий QUIC-парсинг всё равно отличит (нет настоящего
> handshake) — полноценная QUIC-мимикрия идёт с Осью 2 (tells 5.1/5.2).

- **Где:** [obfs.rs obfs_datagram_seal](../../qeli/src/protocol/obfs.rs).
- **Почему палит:** стабильный 12-байтный высокоэнтропийный префикс на каждой
  датаграмме — отличается и от QUIC (есть structure), и от STUN/DTLS. Узнаваемо
  при наличии образца.

---

## 5. QUIC-masking (UDP)

### 5.1 [CRIT] Номер пакета открытым текстом, инкрементирующий
- **Где:** [quic.rs wrap_quic_long/short](../../qeli/src/protocol/quic.rs) пишут
  `packet_number` в открытую.
- **Почему палит:** настоящий QUIC применяет **header protection** — номер пакета и
  младшие биты первого байта зашифрованы (RFC 9001 §5.4). Видимый растущий
  4-байтный PN — это «не QUIC» детерминированно для любой QUIC-aware D2.

### 5.2 [CRIT] Initial-пакет не защищён по RFC 9001
- **Где:** [quic.rs wrap_quic_long](../../qeli/src/protocol/quic.rs).
- **Почему палит:** в оболочке уже есть поля Initial `Token Length` и `Length`, но нет
  AEAD на Initial-secret, header protection, CRYPTO-фрейма и обязательного padding Initial
  до 1200 байт. Номер пакета и защищаемые младшие биты заголовка остаются видимыми /
  постоянными, тогда как настоящий QUIC Initial их защищает.

### 5.3 [MED] Двойная вложенность структуры
- **Почему палит:** внутрь «QUIC payload» кладётся уже структурированная fake-TLS
  `0x17`-запись (со своим заголовком и 12-байт nonce). Два слоя несовпадающей
  структуры — дополнительная зацепка при глубоком разборе.

---

## 6. Поведение потока (все режимы)

### 6.1 [HIGH] Форма потока = «скачивание», не «браузинг»
- **Почему палит:** туннель несёт двунаправленный объёмный full-MTU поток с
  ~постоянной скоростью. Распределение размеров/межпакетных интервалов
  отличается от веб-сёрфинга (короткие всплески + idle). Padding
  ([obfuscate.rs](../../qeli/src/protocol/obfuscate.rs)) нормализует **отдельный**
  пакет, но не воспроизводит распределение целевого протокола → ML-классификатор
  (D2) отделяет «туннель» от «браузинга».
- **🟡 Фаза 1 (частично):** `obf.traffic_shaping` — idle cover-трафик с
  экспоненциальными (непериодичными) паузами вместо «мёртвой тишины»
  ([shaper.rs](../../qeli/src/protocol/shaper.rs)). Убирает «dead air», но **не**
  воспроизводит распределение размеров/всплесков под нагрузкой — это **Фаза 2**
  (пейсинг реальных пакетов + distribution-matching, opt-in, валидация захватом).

### 6.2 [MED] Heartbeat как маяк
- **Почему палит:** периодический keepalive (даже с джиттером) даёт регулярную
  компоненту в спектре межпакетных интервалов — слабый, но стабильный признак
  «есть постоянное соединение».
- **✅ Закрыто (Фаза 1):** при `obf.traffic_shaping.enabled` фиксированный heartbeat
  **заменяется** Poisson-cover'ом (экспоненциальные паузы) — регулярной компоненты
  в спектре межпакетных интервалов больше нет.

---

## Сводная таблица приоритетов

| # | Tell | Серьёзность | Уровень | Ось устранения |
|---|---|:---:|:---:|---|
| 1.1 | ClientHello без ALPN (+ маркер REALITY) | CRIT | D1/D2 | Ось 1 |
| 2.1 | Открытые handshake-записи сервера | CRIT | D2/D3 | Ось 1 |
| 2.2 | Псевдо-DER сертификат | CRIT | D3 | Ось 1 |
| 4.1 | obfs — полная энтропия | CRIT | D2 | Ось 3 |
| 5.1 | QUIC PN открытым | CRIT | D2 | Ось 2/4 |
| 5.2 | QUIC Initial не по RFC | CRIT | D2 | Ось 2/4 |
| 1.2 | Cipher-набор не браузерный | HIGH | D2 | Ось 1 |
| 1.3 | Мало supported_groups (нет PQ) | HIGH | D2 | Ось 1 |
| 1.4 | Нет обязательных расширений | HIGH | D2 | Ось 1 |
| 1.6 | SNI↔IP mismatch + ротация SNI | HIGH | D2 | Ось 1 |
| 3.1 | Явный 12-байт nonce в записи | HIGH | D2 | Ось 1 |
| 6.1 | Форма потока = скачивание | HIGH | D2 | Ось 2 |
| 1.5 | signature_algorithms устаревший | MED | D2 | Ось 1 |
| 2.3 | Бедный ServerHello | MED | D2 | Ось 1 |
| 3.2 | 1 пакет = 1 запись | MED | D2 | Ось 2 |
| 4.2 | UDP-obfs nonce-префикс | MED | D2 | Ось 3 |
| 5.3 | Двойная вложенность QUIC | MED | D2 | Ось 2 |
| 6.2 | Heartbeat-маяк | MED | D2 | Ось 2 |

**Оси устранения** (см. обсуждение «Mirage»):
- **Ось 1 — true REALITY — ✅ ГОТОВА (2026-06):** режим `reality-tls` — настоящий
  Chrome-TLS 1.3 на клиенте (pure-Rust realtls-core) + терминация на сервере (rustls
  ИЛИ hand-rolled с **cert-borrowing** + зеркалированным JA3S + PQ-гибридом
  X25519MLKEM768 + NewSessionTicket). Снимает 1.1–1.6, 2.1–2.3, 3.1. Плюс точечно
  закалён сам `fake-tls` (PQ key_share, ALPN при REALITY-токене, чистка sig_algs).
- **Ось 2 — carrier/flow shaping — 🟡 ЧАСТИЧНО (2026-08):** настоящий H2 и случайный batching
  ломают старый record-boundary classifier; Poisson idle cover убирает фиксированный heartbeat.
  Target-specific browser H2 SETTINGS/priority/window/stream choreography и проверенный
  distribution matching под нагрузкой остаются открыты. UDP QUIC-shape всё ещё не RFC QUIC/H3.
  QUIC-слой (5.x) деприоритизирован (фундаментальный потолок RFC 9001, см. ROADMAP).
- **Ось 3 — entropy-fix obfs — ✅ ГОТОВА (2026-06-05):** WS-fronting (printable
  HTTP-старт) + QUIC-shape для UDP-obfs. Снимает 4.1, 4.2.

## Вывод

«DPI не видит» — недоказуемый абсолют. `PACKET_MUX_V1` распространяет устранение прямой связи
IP-пакетов с qeli-записями на все TCP/UDP carriers; текущий Reality/H2 дополнительно закрывает
старые детерминированные fake-TLS/nested-record пути, а неавторизованные пробы попадают на target.
Но общий recordizer не превращает fake-TLS, obfs, QUIC-shape и plain в настоящий HTTPS/QUIC.
Различия carrier syntax, browser profiles, endpoint correlation, H2 semantics и таймингов остаются
измеримыми research-задачами, поэтому универсальное закрытие D1/D2/D3 и численная вероятность
обнаружения не заявляются. `fake-tls`/`obfs` остаются для D1/D2-сценариев (быстрее, проще),
`reality-tls` — когда в модели угроз есть active probing; новый all-mode PCAP corpus должен
подтвердить именно recordizer-регрессию отдельно от прежних 6/6 H2-сессий.
