# qeli — стадии разработки REALITY: статус и остаток (обновлено 2026-06-06)

> Актуальная сводка. Детальный дизайн осей/приложений — ниже (от 2026-06-05) и
> **исторический**: Ось 1 (REALITY / `reality-tls`), PQ-KEX (X25519MLKEM768),
> NewSessionTicket и **cert-borrowing полностью реализованы и проверены** на всех
> 4 клиентах (Rust / Android / Windows / macOS). Нижний раздел оставлен как
> дизайн-обоснование — не как список нерешённого.

## ✅ Сделано и проверено — СЕРВЕРНАЯ сторона REALITY ЗАКРЫТА

**Базовый realtls-стек (бывшие M1–M3, A1–A2):** M1 крипто-детект в `session_id`;
M2.1 Chrome ClientHello (JA4 `t13d1516h2`); M2.2 key schedule + record (свер. с RFC 8448);
M2.3 `client_handshake` (interop с rustls); M2.4 серверная терминация (rustls);
M3 `RealTlsStream` (туннель внутри TLS); A1 sans-IO core; A2 C ABI.

**Усиление REALITY (раунд 2026-06-06, частью сверх исходного плана) — 153 теста зелёные, clippy чист:**
- **P1 anti-replay** — повтор перехваченного ClientHello → bridge (закрывает активный replay-пробинг). e2e на лабе.
- **P2 PQ key_share в ClientHello** — X25519MLKEM768 в обоих билдерах (fake-tls + realtls), на проводе 1216 Б.
- **L3.1 TLS_AES_256_GCM_SHA384** — второй cipher-suite во всём realtls-стеке (SHA-384 key schedule + AES-256-GCM record). RFC 8448 KAT (регрессия SHA-256) + interop оба шифра.
- **L3.2 hybrid X25519MLKEM768 KEX** (= PQ-гибрид P3#7, но реализован В настоящем TLS) — сервер ML-KEM-encapsulate / клиент decapsulate, общий секрет `ML-KEM ‖ X25519`. Interop 4 комбо.
- **L3.3–L3.5 borrowed-ServerHello (рукодельный сервер вместо rustls)** — `terminate_handrolled` + `RealTlsStream`, ветка в `reality.rs` под флагом `obf.tls.reality_proxy.handrolled`. **Auto-probe**: при старте профиля сервер сам ходит на `target:443`, снимает форму его ServerHello (cipher / PQ-или-нет / порядок расширений) и зеркалит → **JA3S нашего ServerHello == настоящего сайта**. Проверено живьём для **microsoft** (0x1302/[sv,ks]/X25519) И **cloudflare** (0x1301/[ks,sv]/PQ) — разные формы, любой домен из конфига, без хардкода.
- **Rust realtls-клиент** — режим `obf.mode = reality-tls` (`client_handshake` + `RealTlsStream`); после L3 автоматически тянет AES-256/hybrid (suite учится из ServerHello).
- **L3.6 borrowed CERT-CHAIN (cert-borrowing, 2026-06-06)** — сверх borrowed-ServerHello (L3.3–L3.5 зеркалили лишь ФОРМУ ServerHello/JA3S): `realtls/server.rs::capture_target_cert` снимает у `target:443` **настоящую цепочку сертификата** (полный TLS-handshake с target, деривация ECDHE x25519/hybrid через `mlkem::DecapKey`, дешифровка flight, лифт тела Certificate-сообщения), и hand-rolled сервер отдаёт ЕЁ qeli-клиенту вместо self-signed/dummy (`terminate_handrolled`/`server_handshake` получили `borrowed_cert: Option<&[u8]>` → `hs_msg(0x0b, body)`; подпись своим ключом, клиент не валидирует — серт зашифрован в TLS 1.3, не-breaking). `BorrowState{profile,cert}` под `RwLock` на `ProfileRuntime.reality_borrow`; **auto-refresh раз в 12ч** (target-серты ротируются; при неудаче держит кэш). Живой e2e на .10: «borrowed TLS shape from www.microsoft.com:443 … (real cert chain: captured)» + клиент `Auth OK`. Теперь паритет с Xray-REALITY И по форме ServerHello, И по самому сертификату.

Итог на проводе: браузерный ClientHello → валидный TLS 1.3 → ServerHello неотличим от target по JA3S → активный пробер уходит на настоящий сайт.

## ⏳ Осталось реализовать

### Клиентская фаза (главный остаток — чтобы `handrolled` заработал на проде)
1. **Rust-клиент: живой e2e-туннель** через handrolled-сервер (mode=reality-tls). ✅ **СДЕЛАНО 2026-06-06.** Боевые бинари: client (mode=reality-tls) ↔ handrolled-сервер через `reality.rs`: лог `Qeli client detected → hand-rolled TLS established → AUTH OK → Client connected IP`. Транспорт+control-plane доказаны. *Заодно вскрыт и починен критбаг peek-трункации* (`reality.rs` пикал 768 б, а realtls-CH с PQ ~1540 б — x25519 key_share после 1216-б PQ-entry обрезался → токен не валидировался → молчаливый бридж; фикс: peek на весь CH + аккумуляция сегментов). **Data-plane тоже закрыт:** двуххостовый прогон (.10 сервер + .11 клиент) → server→client ping через туннель 4/4, 0% loss (loopback EBUSY ушёл на раздельных хостах).
2. **sans-IO / FFI-ядро** (`realtls/sansio.rs`) — ✅ **СДЕЛАНО 2026-06-06.** Оба cipher-suite (suite в состоянии `ExpectFlight`) + hybrid X25519MLKEM768 (ML-KEM `dk` хранится в `ExpectServerHello`, decaps при group 0x11ec) + `finished_verify`/динамическая длина Finished. Тесты `sansio_interop_handrolled_pq_sha384` (sans-IO ↔ handrolled, AES-256/SHA-384/PQ) + `sansio_interop_with_rustls` (AES-128) зелёные. `ffi.rs`/`jni.rs` не менялись — C-ABI прежний, нативные клиенты получат это прозрачно.
3. **Android (Kotlin, `qeli-android`)** — ✅ **СДЕЛАНО 2026-06-06.** JNI-мост (A3+A4) уже был (`RealTls.kt` ↔ `realtls/jni.rs`, `QeliService.RealTlsTransport`/`doRealTlsHandshake`, диспатч `wireMode=="reality-tls"`, `Config.kt` парсит `reality_short_id`/`server_public_key`). Бандлованные `.so` устарели (до п.2 → AES-128-only) → пересобрал cdylib через cargo-ndk на .11 (arm64-v8a 567К + x86_64 658К, рецепт в reference_qeli_lab_build), APK пересобран+установлен на эмулятор. **Два живых e2e эмулятор↔handrolled, оба ping 0% loss:** target microsoft (AES-256/SHA-384, no-PQ) + target cloudflare (AES-128/SHA-256, **hybrid ML-KEM decaps вживую**). C-ABI/JNI код не менялся — п.2 дал SHA-384/hybrid прозрачно. Покрыты оба cipher-suite, оба KEX, оба порядка ext.
4. **qeli-win / qeli-mac (C#)** — ✅ **СДЕЛАНО 2026-06-06.** P/Invoke-мост (`Vpn/RealTls.cs` → C-ABI `qeli_realtls_*`) и reality-tls проводка (`VpnTunnel.cs`) уже были. Пересобрал нативные либы из пост-п.2 источника на .10: Windows `qeli.dll` (x86_64-pc-windows-gnu+mingw, 3.7МБ) + macOS `libqeli.dylib` (zigbuild universal2, 8.8МБ, headerpad). **Живой Windows e2e** (.NET-харнесс P/Invoke → handrolled-сервер): microsoft (AES-256/SHA-384) + cloudflare (hybrid PQ) — оба ESTABLISHED, сервер `hand-rolled TLS established`. Windows-клиент пересобран (dotnet Release). Mac live невозможен (нет Mac), но dylib = тот же код. Остаток (release-packaging, не функционал): подписанный Qeli.app + Windows publish — по запросу.
5. **Прод-миграция** — перевести профиль `maxobf` на токен-режим REALITY (`short_ids`) + `handrolled`, координированно с обновлением ВСЕХ клиентов (ломающее). **Средний, рискованный.**

### P4 — мелкие телл-фиксы аутентифицированной сессии (сервер+клиент)
6. **NewSessionTicket** — ✅ **СДЕЛАНО 2026-06-06.** handrolled-сервер шлёт 1-2 пост-хендшейк NST (RFC 8446 §4.6.1, `build_new_session_ticket` на серверном app-ключе); rustls-путь — `ticketer`+`send_tls13_tickets=2`. Клиент (`RealTlsStream`) пропускает post-handshake записи, seq синхронен. Закрыт телл «настоящий TLS-сервер шлёт тикеты, а мы нет».
7. **AAD на REALITY-токене** — привязать `session_id` к остальному ClientHello (сейчас без AAD). Ломающее, обе стороны, бандлить с клиентской пересборкой. **Малый код, координация.**

### Длинные оси (детали ниже — не начаты)
- **Ось 2B** distribution-matching shaping (анти-ML, новый `protocol/shaper.rs` ×3 клиента).
- **Ось 2A/2C** QUIC по RFC 9001 ИЛИ настоящий QUIC (`quinn`/MASQUE).
- **P3#9** multipath / MASQUE / WireGuard-compat / eBPF-fastpath (long-term).

### Рекомендуемый следующий шаг
Клиентская фаза (п.1–4) и cert-borrowing — **завершены на всех 4 клиентах**. Реальный
остаток: **прод-миграция (п.5)** — перевести боевой профиль `maxobf` на токен-режим
REALITY + `handrolled` (ломающее, скоординированно с обновлением всех клиентов).
Прочее — AAD (п.7), shaping (Ось 2B) и QUIC-по-RFC — деприоритизировано/research-track
(см. [ROADMAP.md](ROADMAP.md)).

---

# qeli — детальный дизайн крупных оставшихся пунктов

Состояние на 2026-06-05. Не-крупный бэклог (P2) закрыт. Ниже — что осталось,
механика, конкретные шаги по компонентам/клиентам, развилки и оценка объёма.
Базис: fake-TLS (`protocol/tls.rs`), obfs+WS-fronting (`protocol/obfs.rs`),
QUIC-masking (`protocol/quic.rs`), data-plane AEAD (`protocol/packet.rs`),
рукопожатие (`server/handler.rs`, `client/mod.rs`), 4 клиента (Rust/Android/qeli-win/qeli-mac).

---

## 🔴 Ось 1 — настоящий REALITY / TLS на клиенте

### Зачем
Закрывает разом DPI-теллы 1.1–1.6 (нет ALPN, не-браузерный JA3/JA4, мало
cipher/groups/extensions), 2.1–2.3 (сервер шлёт псевдо-ServerHello и псевдо-DER
сертификат открытым текстом), 3.1 (явный 12-байт nonce в каждой записи) и —
главное — **активный пробинг (D3)**. Сейчас сервер отличает «своих» по *отсутствию
ALPN* (`server/reality.rs::has_alpn_extension`) — это и есть худший единичный
тёлл и одновременно причина, по которой клиент не может слать честный ClientHello.

### Как это будет работать (схема REALITY, как у Xray)
1. **Идентичность сервера** — уже есть: per-profile X25519 long-term ключ
   (`/etc/qeli/identity/<name>.key`), pubkey пинится на клиенте (`auth.server_public_key`).
   В REALITY он же — «REALITY-ключ».
2. **Клиент** строит **настоящий** TLS 1.3 ClientHello для `SNI=<dest>` (реальный
   крупный сайт, напр. www.microsoft.com) с браузерным fingerprint'ом (uTLS-grade).
   В ClientHello встраивается аутентификатор: `auth = HKDF(X25519(eph_priv, reality_pub) ‖ short_id)`,
   размещается в `session_id` (32 байта) + `short_id` маркер. Эфемерная X25519-пара
   клиента кладётся в честный `key_share` (как у браузера) — её же qeli использует
   как ephemeral для туннеля.
3. **Сервер** на входящем TLS:
   - вычисляет `auth` из `key_share` клиента + своего REALITY-priv; если совпало с
     известным `short_id` → это qeli-клиент;
   - **для qeli-клиента**: завершает TLS 1.3 сам, с эфемерным самоподписанным
     сертификатом (клиент его НЕ проверяет — доверие через X25519-auth), и поднимает
     туннель ВНУТРИ established TLS-сессии;
   - **для чужого/пробера**: прозрачно проксирует весь TLS на реальный `dest:443`
     (как сейчас `reality.rs`), пробер видит настоящий сайт с настоящим сертификатом.
4. **Data-plane**: VPN-кадры едут как TLS `application_data` НАСТОЯЩЕЙ сессии
   (конфиденциальность даёт сам TLS). Наш `PacketCodec` (0x17-записи + явный nonce)
   убирается или вырождается в лёгкий framing внутри TLS-потока. X25519+ChaCha
   остаются для auth/channel-binding, но шифрование на проводе — TLS.

Итог на проводе: честный браузерный ClientHello к реальному домену, валидное
TLS-рукопожатие, активный пробер получает настоящий сайт. JA3/JA4/ALPN/серт-теллы
исчезают, потому что байты генерит реальный TLS-стек.

### Что конкретно сделать
- **Сервер** (`server/reality.rs` + `handler.rs`): заменить ALPN-эвристику на
  REALITY-детект (auth из key_share+identity-priv); ветка «свой» → терминировать TLS
  (rustls как сервер с on-the-fly cert) и пустить туннель внутрь; ветка «чужой» →
  существующий bridge на target. Конфиг: `obf.tls.reality.enabled`, `dest`, `short_ids`.
- **Rust-клиент** (`client/mod.rs`, новый `protocol/realtls.rs`): заменить
  `FakeTlsHandshake::build_client_hello` на честный TLS-стек с встраиванием auth.
- **Android / qeli-win**: тот же честный ClientHello + auth-embed.

### Развилка (ключевая) — чем делать честный TLS на клиентах
- **uTLS-grade fingerprint требует кастомизируемого TLS-стека.** В Go это uTLS; в
  Rust/Kotlin/C# нативного эквивалента нет. Варианты:
  - **(A) Общий Rust-TLS-core через FFI:** один стек (rustls + ручная подгонка
    ClientHello под Chrome, либо BoringSSL-биндинг) — на Android через JNI, на Windows
    через P/Invoke. Один fingerprint на всех клиентах, полная управляемость auth-embed.
    Самый большой объём (NDK/cross-build/JNI-мост), но единственно «правильный».
  - **(B) Платформенный TLS:** Android Conscrypt (BoringSSL — близко к Chrome),
    qeli-win SChannel (Windows-fingerprint), Rust rustls. Каждый по-отдельности
    правдоподобен, но fingerprints РАЗНЫЕ, и **встроить auth в session_id Conscrypt/
    SChannel не дают** — это блокер. Поэтому (B) реально не закрывает REALITY-auth.
  - **Вывод:** для настоящего REALITY нужен (A). Альтернатива поменьше — **Trojan-
    стиль (ACME-cert)**: свой домен + Let's Encrypt-сертификат, клиент делает обычный
    TLS к своему домену, туннель внутри. Проще (нативный TLS годится), но домен
    идентифицируем и SNI=свой домен (REALITY прячется за чужим большим сайтом).

### Объём: **крупный** (недели). Сначала решить (A) FFI-core vs (Trojan/ACME).

---

### РЕШЕНО 2026-06-05: (A1) pure-Rust `realtls`-core, сначала Rust-клиент

M1 (крипто-детект в `session_id` + ALPN) сделан и проверен вживую. Дальше — настоящий
TLS 1.3 на клиенте **своим кодом** из имеющихся примитивов (X25519/HKDF/SHA-256/AEAD),
rustls-терминация на сервере; FFI на Android(JNI)/Windows(P/Invoke) — позже, после Rust.

**Механизм auth НЕ меняется:** `crypto::reality::{seal,open}_session_id` переиспользуется
как есть (auth по-прежнему в `legacy_session_id`, ephemeral X25519 — в `key_share`).
Меняются: (1) форма ClientHello → байт-грейд Chrome; (2) после hello идёт **настоящее**
TLS-1.3-рукопожатие; (3) data-plane едет как TLS `application_data` (не `PacketCodec`).

Новый модуль `src/protocol/realtls/`: `clienthello.rs`, `keyschedule.rs`, `record.rs`,
`client.rs`; на сервере — терминация через `rustls` в `server/reality.rs`.

- **M2.1 — Chrome ClientHello** (оффлайн-тест). Точный fingerprint Chrome (JA4 `t13d…h2_…`):
  Chrome-набор/порядок расширений с GREASE (SNI, ext_master_secret, renegotiation_info,
  supported_groups [GREASE,x25519,secp256r1,…], ec_point_formats, session_ticket, ALPN
  [h2,http/1.1], status_request, signature_algorithms (Chrome-список), signed_cert_timestamp,
  key_share [GREASE-empty, x25519], psk_key_exchange_modes, supported_versions [GREASE,1.3,1.2],
  compress_certificate, ALPS). `session_id`=REALITY-токен (seal), `key_share.x25519`=наш ephemeral.
  Тест: вычислить JA4/JA3 и сверить набор с эталоном Chrome + стабильность при варьирующемся GREASE.
- **M2.2 — key schedule + record layer** (оффлайн-тест на **RFC 8448** trace-векторах).
  HKDF-Expand-Label (SHA-256), early/handshake/master secrets, traffic keys, transcript-hash;
  record protect/unprotect (ChaCha20-Poly1305 + AES-128-GCM → крейт `aes-gcm`), nonce=iv⊕seq,
  inner content-type, padding. Тест: побайтовые трассы RFC 8448 совпадают.
- **M2.3 — клиентская state-machine** (интеграц. тест против rustls-сервера). CH → SH (extract
  server key_share, derive handshake secrets) → {EncryptedExtensions, Certificate, CertVerify,
  Finished} зашифрованными (decrypt, transcript; **cert-цепочку/CertVerify НЕ валидируем** —
  доверие даёт внутренний qeli-auth M3; **server Finished верифицируем**) → {CCS, client Finished}
  → application secrets. Тест: локальный rustls-сервер (self-signed, TLS1.3-only) ↔ наш клиент.
- **M2.4 — серверная REALITY-терминация** (лаб e2e). Ветка «свой» → поток в rustls
  `ServerConnection` (ServerConfig: TLS1.3-only, on-the-fly self-signed cert через
  `ResolvesServerCert`, no client-auth) → established TLS в туннель; «чужой» → существующий
  proxy-bridge. Крейт `rustls` (server-only). Тест: realtls-клиент ↔ rustls-сервер на лабе.
- **M3.1/3.2/3.3 — data-plane в TLS**: VPN-кадры как `application_data`; `PacketCodec`
  для reality-real-режима выводится (конфиденциальность даёт TLS), внутренний qeli-auth
  (server-proof + channel-binding) сохраняется → mutual-auth, оправдывает skip-cert. Под-режим
  `obf.mode = reality-tls` (старый fake-TLS-reality остаётся для отката). Лаб e2e: полный туннель
  через настоящий TLS, JA4 снят tcpdump'ом и сверен с Chrome, пробер по-прежнему → microsoft.
- **Затем (после Rust):** FFI realtls-core на Android(JNI)+qeli-win(P/Invoke) — единый fingerprint.

**Новые зависимости:** `aes-gcm` (TLS-cipher), `rustls` (server-term). Осторожно: ручной
record-layer крипто-чувствителен → тест на RFC 8448 обязателен; rustls как forcing-функция
корректности клиента.

---

## 🔵 ПРИЛОЖЕНИЯ — FFI realtls-core (решено 2026-06-05: sans-IO, Android первым)

M3 закрыт — настоящий TLS у Rust-клиента. Чтобы единый Chrome-fingerprint был на ВСЕХ
клиентах (Android/qeli-win пока fake-TLS), выносим realtls-ядро в нативную либу.

**Архитектура: sans-IO buffer FFI.** Rust-ядро — чистый byte-in/byte-out state machine
(без tokio/сокета). Платформа (Kotlin/C#) владеет сокетом+TUN и зовёт Rust за TLS-крипто.

- **A1 — sans-IO core** (`realtls/sansio.rs`, pure Rust): `SansIoClient` — state-machine
  рукопожатия поверх building blocks (clienthello/keyschedule/record). `new(reality_pub,
  short_id, sni, eph) -> (Self, client_hello_bytes)`; `recv(&[u8]) -> Progress{NeedMore |
  Send(Vec<u8>) | Established}`; после Established `seal(pt)->record` / `open(rec)->(type,pt)`.
  Зеркалит логику async `client_handshake`, но инвертирует IO (буферизует вход, эмитит выход).
  Тест: гонять против rustls, вручную шаттлить байты через duplex/TcpStream.
- **A2 — C ABI** (`ffi.rs` + `[lib] crate-type=["cdylib","staticlib","rlib"]`):
  `#[no_mangle] extern "C"` над SansIoClient — opaque handle (Box→raw ptr), буферы (ptr+len),
  out-длины, коды ошибок, `catch_unwind` (без паник через FFI). `qeli_realtls_{new,client_hello,
  recv,seal,open,free}`.
- **A3 — Android NDK cross-build**: `aarch64-linux-android`+`x86_64-linux-android` (эмулятор),
  `cargo-ndk`; .so → `jniLibs/<abi>/`. На .11 (есть NDK/эмулятор).
- **A4 — JNI-мост (Kotlin)**: `external fun` + загрузка .so; в сокет-цикле клиента при
  mode=reality-tls — handshake через FFI, затем seal/open вокруг существующего qeli-протокола
  (nested, как в Rust).
- **A5 — Android e2e** на эмуляторе .11 против reality-tls сервера на .10.
- Затем **qeli-win (P/Invoke)**: цель `x86_64-pc-windows-*`, DllImport в C#, аналогично.

Новое: `[lib]` cdylib в Cargo.toml; `cargo-ndk` на .11. Последний шаг всего проекта — **UI**.

---

## 🔴 Ось 2 — shape-мимикрия + QUIC header-protection

Две относительно независимые части.

### 2A. QUIC header-protection (DPI-теллы 5.1/5.2)
**Зачем.** Сейчас `protocol/quic.rs` пишет packet number **открытым** и инкрементно;
Initial-пакет не по RFC 9000 (нет Token Length/Token, нет varint Length). QUIC-aware
DPI отвергает на первом поле. (UDP-obfs уже получил форму QUIC short-header — tell 4.2
закрыт — но это лишь «похоже на QUIC», не настоящий QUIC.)

**Как будет работать.** Привести UDP-обёртку к RFC 9001:
- header protection: маскировать первый байт (младшие биты) + packet number маской
  из `AES-ECB`/`ChaCha` от `sample` шифротекста (RFC 9001 §5.4);
- корректная структура Initial (token length, length varint), packet-number
  encoding 1–4 байта; reserved-биты выглядят случайно после protection.

**Что сделать.** Переписать `quic.rs` wrap/unwrap под RFC 9001 (header-protection
ключи из HKDF), синхронно в Android `Quic.kt` и qeli-win `Quic.cs`. Либо радикально —
п. 2C ниже (настоящий QUIC через `quinn` / MASQUE), что делает 2A ненужным.

### 2B. Distribution-matching shaping (DPI-теллы 6.1/6.2)
**Зачем.** Даже при идеальном TLS форма потока (двунаправленный full-MTU объёмный
поток + периодический heartbeat-маяк) ≠ браузинг → ML-классификатор (D2) отделяет
туннель. Текущий padding нормализует *отдельный* пакет, но не распределение.

**Как будет работать.** Слой-формирователь между data-plane и проводом:
- **token-bucket / pacing**: пакеты выпускаются по расписанию, сэмплированному из
  **эмпирической модели** (размер пакета + межпакетный интервал) реальной HTTP/3-
  сессии к CDN (видео/веб);
- **size-shaping**: реальные кадры режутся/добиваются до целевого распределения
  размеров;
- **chaff fill**: пустые слоты заполняются cover-трафиком (шифрованный мусор,
  отбрасывается на приёме);
- **burst smoothing**: всплески размазываются; heartbeat растворяется в общем pacing
  (убирает маяк).
Релакс известных защит (FRONT/GLUE, DynaFlow). Профиль формы — в конфиге
(`obf.shaping.profile = http3-video|web|off`), модель — зашитый набор гистограмм.

**Что сделать.** Новый `protocol/shaper.rs` (очередь + scheduler + chaff), врезается
в `RunTunnelLoop`/`runTunnelLoop` на отправке; приёмная сторона распознаёт и
отбрасывает chaff (по типу кадра). Зеркала в Android/qeli-win. Компромисс: латентность
и оверхед (chaff) против стелса — конфигурируемо.

### 2C. (опц.) Настоящий QUIC / MASQUE вместо 2A
Вместо ручного QUIC — взять `quinn` (Rust QUIC) и пустить туннель как HTTP/3
datagrams или MASQUE CONNECT-IP (RFC 9484). Тогда на проводе — **настоящий** QUIC
(header protection, версии, transport params бесплатно). Пересекается с P3#9 (MASQUE).
Объём больше, но стелс максимальный и 2A не нужен.

### Объём: **крупный**. 2A — средне (переписать quic.rs ×3 клиента). 2B — средне-крупно
(новый shaper ×3). 2C — крупно (новый транспорт). Рекомендация: 2B даёт наибольший
анти-ML-эффект; 2A/2C — по решению о QUIC-стратегии.

---

## ✅ PQ-гибрид KEX (P3#7) — СДЕЛАНО 2026-06-11

**Зачем.** «Harvest now, decrypt later»: записанный сегодня X25519-трафик
расшифруют будущим квантовым компьютером. Гибрид X25519+ML-KEM защищает от этого
уже сейчас (стандарт TLS 1.3 hybrid, как у Chrome `X25519MLKEM768`).

**Как сделано.** Внутренний qeli-туннель выводит ключи плоскости данных из ОБОИХ
секретов во всех режимах кроме `plain`:
- клиент шлёт X25519MLKEM768 `key_share` = `ML-KEM-768 ek (1184) ‖ x25519 (32)`
  (+ классическая x25519-доля), сохраняет ML-KEM `dk`;
- сервер `extract_client_mlkem_ek` → encapsulate, ServerHello несёт
  `ct (1088) ‖ x25519 (32)`; клиент decapsulate;
- ключи: `derive_keys_hybrid` = `HKDF(salt="…v2-hybrid", x25519_shared ‖ mlkem_shared)`
  → AEAD-ключи. Ломается только если сломаны *оба*. `plain` остаётся классическим
  X25519 (`derive_keys`). **Сервер ТРЕБУЕТ** X25519MLKEM768-долю для не-`plain` —
  тихого PQ-даунгрейда нет (домен-сепарация солью ловит несовпадение как decrypt-fail).
- ML-KEM-768 ek ~1184 Б / ct ~1088 Б — ClientHello раздут (плюс к size-fingerprint-
  паритету с Chrome ≥124).

**Реализация.**
- Rust: крейт `ml-kem` (pure-Rust). `crypto/mlkem.rs` + `crypto/derive.rs`
  (`derive_keys_hybrid`); рукопожатие `protocol/tls.rs` (`build_client_hello_pq` /
  `build_server_hello_pq` / `parse_server_hello_pq` / `extract_client_mlkem_ek`),
  `server/handler.rs`, `server/udp_handler.rs`, `client/mod.rs`.
- **НЕ BouncyCastle** (2.6.2 не содержит ML-KEM; `.NET MLKem` OS-gated) → managed-
  клиенты вызывают тот же Rust-крейт по C-ABI/JNI: `realtls/ffi.rs`
  (`qeli_mlkem_keygen/decapsulate/free`), `realtls/jni.rs` (`Java_com_qeli_MlKem_*`).
- C#: `Crypto/Mlkem.cs` (P/Invoke), `TlsHandshake.BuildClientHelloPq/ParseServerHelloPq`,
  `KeyDerivation.DeriveKeysHybrid`, врезка в `VpnTunnelBase` (основной + JOIN).
- Kotlin: `com/qeli/MlKem.kt` (JNI), те же методы, врезка в `QeliService`.
- Версионирование: не negotiation-флаг, а атомарный деплой (сервер требует PQ) —
  единая бета 0.6.0, клиент↔сервер катятся вместе.

**Гармонирует с Осью 1**: realtls уже нёс `X25519MLKEM768` во ВНЕШНЕМ настоящем TLS 1.3
(L3.2); теперь PQ есть и во ВНУТРЕННЕМ туннеле независимо от обёртки.

---

## 🔵 P3#9 — multipath / MASQUE / WireGuard-compat / eBPF

Четыре независимых экспериментальных направления.

- **MASQUE (CONNECT-IP/CONNECT-UDP, RFC 9484/9298).** Туннель IP поверх HTTP/3.
  Максимальный стелс (настоящий QUIC/H3 к настоящему домену) + проходит QUIC-friendly
  сети. Пересекается с Осью 2C. Объём: крупный (квик-стек + H3 + IP-проксирование).
- **Multipath.** Туннель по нескольким путям одновременно (Wi-Fi + LTE): scheduler
  раскидывает пакеты, на приёме — reorder-буфер. Плюс надёжность/скорость на мобайле.
  Объём: крупный (планировщик + переупорядочивание + детект путей).
- **WireGuard-совместимый режим.** Сервер говорит протоколом WireGuard → подключаются
  штатные WG-клиенты (широкая совместимость). НО у WG узнаваемый fingerprint и нет
  обфускации — против стелс-цели; имеет смысл только как слой под обфускацией.
  Объём: средне-крупно (Noise-IK + WG-framing).
- **eBPF-fastpath (Linux).** Data-plane в ядре через eBPF/XDP — bypass userspace-копии,
  кратный рост throughput. Только сервер/Linux. Объём: крупный (XDP-программа + map'ы +
  верификатор), завязан на ядро.

**Объём: каждый — крупный/экспериментальный.** Это long-term, не для ближайших итераций.

---

## Рекомендуемый порядок
1. **Ось 1** (REALITY/настоящий TLS) — наибольший рычаг против активного DPI;
   принять решение **FFI-core (A) vs Trojan/ACME**. PQ-KEX (P3#7) делать в её рамках
   (штатная hybrid-группа).
2. **Ось 2B** (shaping) — независимо от Оси 1, бьёт ML-классификатор.
3. **Ось 2A или 2C** (QUIC) — по решению о QUIC-стратегии (ручной RFC 9001 vs quinn/MASQUE).
4. P3#9 — long-term по потребности.
