# План развития qeli

Приоритеты: **P1** — заметно влияет на безопасность/функциональность, **P2** —
качество, **P3** — long-term/экспериментальное.
## 0.8.0 (dev, 2026-08-26) — настоящий H2 carrier для Reality

- ✅ `reality-tls` теперь несёт приватный поток qeli records в одном долгоживущем настоящем
  HTTP/2 POST (`/v1/events/stream`, ALPN `h2`) со случайным batching 2–8 мс; прежнего второго
  fake-TLS handshake/framing больше нет. Пользовательского переключателя H2 нет.
- ✅ Поставляемые Reality/max-obfuscation шаблоны выключают qeli heartbeat и включают shaping.
  H2 carrier принудительно выключает qeli heartbeat даже при старом local/pushed значении.
- ✅ Миграция — **сначала сервер**: новый сервер принимает H2 и legacy Reality carrier;
  новый клиент использует только H2 и не делает downgrade. Bare `fake-tls` остаётся отдельным режимом.
- ✅ Датированный lab PCAP: завершены 6/6 сессий; старый carrier-classifier совпал в 0/6
  (контроли 0/6). Это проверка данного capture/classifier, а не универсальная вероятность обнаружения.
- ✅ Чистый full-speed H2 lab benchmark опубликован для бинарника SHA-256 `2f69b48f…`:
  `reality-tls` 827,9 Мбит/с upload и 647,8 Мбит/с download, server drops 0.
- 🟡 Осталось: TLS/H2 профили семейств браузеров, H2 SETTINGS под target, hostile active
  probes, malformed/reconnect/long-lived тесты и повторяемый 5× benchmark на финальном SHA.
- 🔵 Настоящий H3/MASQUE перенесён в 0.9.x. `udp-quic` остаётся маскировкой формы QUIC и
  не должен называться HTTP/3.

См. [DPI-AUDIT.md](../reports/DPI-AUDIT.md), [CONFIG.md](../manuals/CONFIG.md) и
[датированный PCAP-отчёт](../../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).

## 0.7.5 (2026-06-29) — фиксы стабильности + экспериментальный OpenWrt-клиент

Сетево совместимо с 0.7.4; дефолты конфига не менялись.

- ✅ **Rust-клиент: реконнект больше не падает с TUN `EBUSY`** — adaptive-ramp задача
  вечно держала клон `tun_write_tx`, утекал `writer_fd`, `vpn0` числился busy; теперь
  abort'ится при teardown.
- ✅ **Android: утечка TUN-дескриптора на реконнекте** — прошлый интерфейс закрывается
  после поднятия нового (без no-TUN-гэпа); `protect()` ретраится до 5× перед предупреждением.
- ✅ **Windows: `ERROR_FILE_NOT_FOUND` при создании Wintun-адаптера** — однократный ретрай
  со свежим случайным GUID обходит отравленную stable-GUID запись.
- ✅ **Share-ссылка: понятная ошибка для не-загруженного профиля** (профили, в отличие от
  пользователей, не хот-релоадятся — перезапустите сервер).
- ✅ **Экспериментальный OpenWrt-клиент** (procd + UCI + LuCI; на железе не тестировался).
  Версии → 0.7.5.

## 0.7.4 (2026-06-27) — надёжность UDP на мобильном

Обратно-совместимое изменение UDP-хендшейка (сервер принимает старых + новых клиентов);
TCP не затронут; дефолты конфига не менялись. Порядок выката: **сервер → клиенты**.

- ✅ **Фрагментация UDP-хендшейка** — пост-квантовый hello (ML-KEM-768) большой и
  дропался на LTE/CGNAT → UDP-режимы не поднимались на мобильном. Теперь фрагментируется +
  пересобирается во всех клиентах (`udp_frag.rs` / `UdpFrag.cs` / `UdpFrag.kt`).
- ✅ **Фиксы UDP liveness/RECV** — реконнект на простое, реап при односторонней загрузке,
  учёт RECV-байт. Версии → 0.7.4; Android `versionCode = 704`.

## 0.7.3 (2026-06-25) — Android-клиент + Linux kill-switch + аудит-гигиена

Сетево совместимо с 0.7.2; дефолты конфига не менялись.

- ✅ **Android INI-конфиг** — ключ `gateway` (выбор split-tunnel), дизамбигуация `dns`
  (режим/список), ключи тюнинга `reconnect`/`timeout`.
- ✅ **Android TUN-сетап** — фоллбэк на IPv4-only, когда прошивка отклоняет IPv6-адрес
  захвата на `establish()` (был `Cannot set address` → не подключался).
- ✅ **Linux kill-switch nftables → iptables** (единый firewall-бэкенд; работает на
  Keenetic), netns-тест.
- ✅ **Security-гигиена** (внешний аудит 2026-06-25): FFI/JNI handle-registry (C-1),
  HKDF веб-токенов (H-4), serde route-JSON (C-3), zeroize AES-GCM (H-5), CRLF-escape
  логов (H-8), parse-or warn (M-9).
- ✅ **Полиш веб-панели** + **Docker** как вариант установки. Версии → 0.7.3.

## 0.7.2 (2026-06-18) — периферийный хардненинг (внутренний аудит 2026-06-18)

Сетево совместимо с 0.7.1; дефолты конфига не менялись. Трекер — внутренний аудит
2026-06-18.

- ✅ **Веб-панель: закрыт обход анти-брутфорс/anti-DoS.** HTML-страницы гоняли Basic
  через Argon2 без rate-limit (в обход `AuthGuard`). Теперь страницы — только
  cookie (`auth::is_authed_cookie_only`); Basic — только API под троттлингом.
- ✅ **Атомарная запись всех персистентных файлов** (users/config/identity/secret/
  web-TLS/resolv.conf) — единый `crate::util::write_atomic` (temp→fsync→rename,
  Unix `O_EXCL`+`O_NOFOLLOW`, сохранение прав 0600). Обрыв не бьёт файл с хэшами.
- ✅ **Анти-replay строже** — padding валидируется до записи счётчика в окно.
- ✅ **`SECURITY.md` + модель угроз** (`THREAT-MODEL.md`) + **fuzzing-харнес**
  (`qeli/fuzz/`: clienthello / packet_decrypt / realtls_record).
- ✅ **Версии → 0.7.2**; Android `versionCode=702`. Лаб-гейт .10: build / **203 теста** / clippy / fmt — зелёный.
- ℹ️ Перепроверено: kill-switch есть на ВСЕХ десктопах (Linux iptables / Win WFP /
  mac pf) — паритет, не гэп (исходная находка #4 снята).

## 0.7.1 (2026-06-12) — security-hardening (аудит 2026-06-12)

Фиксы по внешнему аудиту; дефолтный провод не менялся, **кроме H-1**, который теперь
**включён по умолчанию** (wire-breaking — сервер и все клиенты апгрейдятся в lockstep).
Трекер — [AUDIT-2026-06-12.md](../archive/audits/AUDIT-2026-06-12.md).

- ✅ **H-1** — привязка data-ключей к статической личности сервера (Noise-IK): KDF
  подмешивает `es = X25519(client_eph, server_static)`. Rust+C#+Kotlin; **дефолт on**
  (`bind_static_to_session` на сервере, `bind_static` у клиента). Беспиновый/TOFU-клиент
  отключает явным `bind_static = false`.
- ✅ **M-13** — анти-replay окно 64 → 2048 бит (WireGuard-размер), receiver-only (Rust+C#+Kotlin).
- ✅ **H-5** — атомарная запись resolv.conf без symlink-follow (O_EXCL+O_NOFOLLOW), Rust-клиент.
- ✅ **H-3** — санитизация nft-правил kill-switch (валидация ifname + реформат IP), Rust-клиент.
- ✅ **Версии → 0.7.1**; Android `versionCode=701`. Большинство пунктов аудита оказались ложными.

## 0.7.0 (2026-06-11) — пост-квантовый туннель

- ✅ **PQ-гибрид X25519+ML-KEM-768** во внутреннем хендшейке на всех клиентах
  (Rust/C#/Kotlin); сервер требует PQ для не-plain режимов.
- ✅ Persistent TOFU; reality требует непустые `short_ids` (строгая валидация конфига).
- ✅ Фиксы внешних аудитов 2026-06-10/11. Версии → 0.7.0; Android `versionCode=700`.

## 0.6.0 (2026-06-10) — релиз рефакторинга

Кодовая реорганизация и доводка визуала; протокол/крипто/провод **не менялись**
(замеры 0.5.6 актуальны). Полный список — [CHANGELOG.md](../../../CHANGELOG.md), детали
C#-консолидации и Rust-правок — [REFACTOR-PLAN.md](../archive/plans/REFACTOR-PLAN.md).

- ✅ **Общий C#-слой `qeli-shared`** — крипто, протокол, модель (`VpnConfig`), ядро
  `VpnTunnel` (за интерфейсом `ITunDevice`), `RealTls`, локализация `Loc` сведены из
  двух копий win/mac в одну библиотеку (.NET 10); устранено ~2700 строк дублей.
- ✅ **Унификация .NET 10** обоих C#-клиентов + единые версии NuGet (BouncyCastle 2.6.2, QRCoder 1.8.0).
- ✅ **Rust web-слой**: хелперы `err_json`/`ok_json` + axum-extractor `AuthGuard`
  (auth-проверка на тип-уровне, нельзя «забыть»). Лаб-гейт .10: build / 179 тестов / clippy — зелёный.
- ✅ **Выравнивание UI** (win/mac `MainWindow`): симметричные колонки, бренд-бэнд = статус-карта,
  совпадающие нижние края панелей, единый ритм отступов 14px.
- ✅ **`scripts/lab_common.py`** — общая SSH-обвязка (хосты + connect/run) для лаб-скриптов.
- ✅ **Версии → 0.6.0** на всех компонентах; Android `versionCode=600`.

## Сделано

- ✅ **Channel-binding** auth_proof к transcript рукопожатия (анти-MITM).
- ✅ **Per-profile идентичность** сервера (`/etc/qeli/identity/<name>.key`) + CLI
  `show-identity` / `rotate-identity`.
- ✅ **`require_client_key_proof`** — отказ непиненным клиентам + скрытие
  static-ключа от сканеров.
- ✅ **Авторизация по профилям** (`users.profiles`) — изоляция интерфейсов.
- ✅ **Новый wire-режим `obfs`** (ChaCha20 stream) в дополнение к `fake-tls`.
- ✅ **REALITY-proxy** — проксирование «не-наших» соединений на реальный сайт.
- ✅ **UDP анти-амплификация** (padded initial ≥1200, отказ мелким).
- ✅ **Скрытие счётчика** в nonce (96-битный Feistel-PRP).
- ✅ **Идемпотентный/crash-safe DNS** с само-восстановлением и обработкой SIGTERM.
- ✅ **Авто-reconnect** клиента (RX-liveness + корректное завершение TUN-reader).
- ✅ **Cancellation-safe data-plane** (выделенные reader-задачи) — устранён старый
  framing-desync «cliff».
- ✅ **Единый flat-INI конфиг** (`server.conf`/`client.conf`/`users.conf`) — TOML и
  JSON ВЫПИЛЕНЫ полностью (один формат); web-UI пишет INI. Юзеры — секции
  `[user:<name>]`/`[group:<name>]`.
- ✅ **SIGHUP-reload** (юзеры + brute-force пороги).
- ✅ **Логи**: формат `ГГГГ-ММ-ДД ЧЧ:ММ:СС:ммм`, вывод в файл, аудит админ-действий.
- ✅ Heartbeat idle-gating; padding probability/randomize; кап UDP-датаграммы < MTU.
- ✅ **Хардненинг (раунд 1)**: OOB-чтение в DHCP-парсере (bound-check, тест); CSRF
  allowed_hosts для IPv6 (`[::1]`, bracketed bind); `keepalive_secs=0` не вызывает
  EINVAL; flat-INI loader применяет baseline-дефолты к пропущенным `perf.*` ключам, а явные нули критичных connection-параметров отклоняются с внятной ошибкой.
- ✅ **Хардненинг (раунд 2)**: OOB-panic при парсинге QUIC SCID (bound-check + fuzz-тест);
  валидация DNS-ответа upstream (источник + transaction-ID — анти-poisoning, плюс
  txid-нормализованный ключ кэша); константно-временное сравнение auth-proof
  (`subtle`, все 4 точки: TCP/UDP × server/client); неблокирующий `try_send` на
  TUN-writer клиента (TCP+UDP — не стопорит select-loop под backpressure);
  DHCP REQUEST проверяет аллокацию из пула и шлёт NAK вместо echo любого IP;
  bound на длину control-команды (анти-OOM); clamp паддинга u16; guard `gen_range`
  во фрагментаторе; `private_bytes()` → `Zeroizing`. Подтверждено: 99 unit-тестов +
  e2e (tcp-plain/obfs/udp, 0% loss, throughput без регресса).

## Сделано (2026-06-04, сессия #2)

- ✅ **Выпил TOML/JSON → единый flat-INI** (см. выше). Тесты 110 зелёные.
- ✅ **Фикс реконнекта с нового IP** — supersede stale-сессии по username до
  проверки лимита (handler.rs); смена БС/Wi-Fi↔LTE больше не блокирует клиента.
- ✅ **Server-side reaping** (бывш. P1#3) — отдельный `last_rx`, RX-liveness в
  idle-check: мёртвый/half-open клиент реапится через 3×heartbeat даже при
  `idle_timeout=0`, освобождая IP/слот.
- ✅ **Device-ID / мульти-девайс** — клиент шлёт стабильный 16-байтный device-id в
  auth (`[proof:32][0x00][device_id:16][user:pass]`, маркер 0x00 backward-compat);
  сервер ключует сессии/пул IP по `username:hex(device_id)` вместо чистого username.
  Несколько устройств одного логина сосуществуют (свои tun-IP), то же устройство при
  смене IP кикает только СВОЮ старую сессию. Все 4 клиента (Rust/Android/Win/Mac)
  генерят+хранят device-id. E2E PASS на лабе (fake-tls) и проде (reality-tls).
  Идентификация по device-id, НЕ по имени tun-интерфейса (оно серверу не уходит).
- ✅ **Enforcement `max_sessions`** (раньше настройка существовала, но не применялась)
  — per-user лимит одновременных устройств (фолбэк на группу, 0=безлимит); при
  превышении вытесняется самое старое устройство юзера (newest wins). Реконнект того
  же устройства слот не тратит. TCP+UDP, E2E PASS. Включается заданием `max_sessions`
  у юзера/группы.
- ✅ **Фикс «застрявшего» реконнекта/Disconnect** — сокет публикуется в поле ДО
  блокирующего `connect()` (Android/Win/Mac), поэтому Disconnect может закрыть
  подключающийся сокет (NIO/Socket прерываются только закрытием, не отменой
  корутины/токена) → кнопка Disconnect работает во время реконнекта. Android: детект
  смены сети через `registerDefaultNetworkCallback` → мгновенный forceReconnect на
  новой сети. Runtime-проверка на живом телефоне — за юзером (эмулятор-UI хрупок).
- ✅ **Keyed push-формат** auth-OK — `OK:{json}` с ключами вместо позиционного
  `OK:a:b:c:…` (устранён класс багов рассогласования полей).
- ✅ **`route_local_networks`** — клиентский опт-ин маршрутизации приватных
  сетей (RFC1918 + server-pushed) в туннель.
- ✅ **DNS-push footgun** — сервер не пушит мёртвый `dns.listen` при выключенном
  прокси; клиент фолбэчит на свой резолвер.
- ✅ **Android-клиент**: рефакторинг (Transport-абстракция, дедуп TCP/UDP),
  qeli://-импорт + QR, replay-окно, full-tunnel-дефолт; аудит-фиксы.
- ✅ **Web-UI**: генерация QR/share + API; CLI `qeli add-client`.
- ✅ **Cleanup** (бывш. P2#5): мёртвые `bypass_*` удалены, 0 dead-code warning'ов.
- ✅ **CI-scaffold** (бывш. P2#4): `.github/workflows/ci.yml` (build+test — гейт;
  fmt/clippy — advisory до нормализации) + `scripts/ci-check.sh`.
- ✅ **Прод-деплой** (`YOUR_PROD_HOST`): миграция конфига TOML→INI с сохранением
  identity-ключа/юзеров/client-конфигов, свежий keyed-билд.

## Сделано (2026-06-05)

- ✅ **Ось 3 — anti-FET fronting для `obfs`** (DPI-AUDIT tell 4.1). Начало
  obfs-соединения замаскировано под рукопожатие WebSocket Upgrade (printable
  HTTP + `\r\n\r\n` → первый пакет проходит exemptions Ex2/Ex3/Ex4 энтропийного
  детекта GFW/ТСПУ «fully encrypted traffic», Wu et al. USENIX'23). Сервер
  считает корректный `Sec-WebSocket-Accept` (inline SHA-1, без новых зависимостей),
  запрос рандомизирован (path/Host/UA/key) — нет статической сигнатуры. Новый
  флаг `obf.obfs_fronting = websocket|none` (дефолт `websocket`), проброшен в
  qeli://-ссылку (`front`), INI и JSON; зеркалирован в Android
  (`ObfsStream.kt`/`Config.kt`) и **qeli-win** (`ObfsStream.cs`/`VpnConfig.cs`).
  Rust `ObfsStream` общий для клиента и сервера. Тесты: RFC6455-вектор Accept,
  FET-exemptions для запроса, fronting round-trip, config round-trip.
  Проверено: Rust 114 тестов + clippy + e2e (lab .10); Android assembleDebug + APK;
  qeli-win build 0w/0e + selftest ALL PASS + e2e (клиент шлёт WS GET, printable 0.935).
  Все три клиента + сервер согласованы.

## Сделано (2026-06-05, продолжение)

- ✅ **UDP-obfs в qeli-win** — раньше Windows-клиент по UDP умел только fake-tls/QUIC.
  Добавлены `DatagramSeal/DatagramOpen` (ChaCha20 per-datagram) + обёртка в `UdpTransport`.
  Теперь **все три** клиента (Rust/Android/qeli-win) поддерживают obfs по UDP. E2e: Auth OK
  против прод udpobfs:8448.
- ✅ **Индикатор скорости ↓/↑** при активном соединении — счётчики goodput в дата-плоскости,
  обновление раз в секунду. qeli-win: `BytesUp/BytesDown` + DispatcherTimer (+ стат-плитки,
  спарклайн, поиск профилей в UI). Android: `AtomicLong` + statsJob-broadcast → `tvSpeed`.
- ✅ **UDP reachability-проба** (Android + qeli-win) — вместо TCP-коннекта (давал ложно-красный
  на UDP-портах) шлётся mode-framed ClientHello, любой ответ сервера = «достижимо».
- ✅ **`quic` в qeli://-ссылке и INI** — флаг QUIC раньше нёс только JSON; теперь `quic=1`
  (ссылка) / `quic=true` (INI). Парсят **все три** клиента: Android, qeli-win и Rust
  (`ClientLink.quic`, `client.rs` from_link/from_ini/to_link/to_ini_string), а серверные
  генераторы (`qeli add-client`, web `/api/share`) его эмитят. Лаба: 114 тестов зелёные.
- ✅ **Ось 3 для UDP — энтропия UDP-obfs** (DPI-AUDIT tell 4.2). Per-datagram obfs-кадр
  получил форму QUIC short-header: `[flag(0x40|x)][nonce=12 как conn-id][protected]` вместо
  случайного префикса с байта 0. Зеркалировано в obfs.rs (клиент+сервер), Android, qeli-win.
  ⚠️ Breaking wire-change для UDP-obfs — потребовал скоординированного деплоя. **Выполнено
  2026-06-05:** прод-бинарь обновлён (бэкап `/root/backup/qeli-deploy/`), пересобраны и
  разложены в dist новый APK + qeli-win. E2e против прода: udpobfs `Auth OK` (новый формат),
  udpquic `Auth OK` (quic=1).
- ✅ **Android: квадратные тени** — на эмуляторе (swiftshader софт-GPU) elevation-тени рисуются
  квадратными; убраны native-тени (`cardElevation=0`), карточки — плоские со скруглённой рамкой
  (stroke). Чисто на любом рендере. На реальном устройстве тени и так были круглыми.
- ✅ **Прод-тест-стенд** (`YOUR_PROD_HOST`): 7 профилей по типу обфускации (tcp 443/8443/8444/8445
  + udp 8446/8447/8448), firewall/NAT, flat-INI client-конфиги `/etc/qeli/client/test-*.conf`
  (см. [[reference_qeli_prod_server]]).

## Сделано (2026-06-06)

- ✅ **Multi-queue TUN + клиентский `dev=`** (2026-06-06). Сервер: `tun.queues`
  (per-profile, дефолт auto=nproc, `IFF_MULTI_QUEUE`) — дата-плоскость открывает N
  очередей TUN и качает их N reader/forwarder/writer-задачами, так что и TUN-помпа, и
  пер-очередь encrypt идут на нескольких ядрах (раньше единый reader+forwarder+writer
  был воронкой ~1.5 ядра). Server-only, на проводе ничего не меняется, клиентов НЕ
  пересобирать. Контролируемый A/B на 2-ядерной лабе (2 туннеля): `queues=1`→`2` дал
  607→718 Мбит/с (+18%), qeli 159%→167%; на лабе эффект ограничен насыщением хоста
  (server-host 93→95%, почти насыщен `iperf3`-сервером на том же хосте), на бОльших
  серверах растёт (полный A/B и методология — [BENCHMARK.md](../reports/BENCHMARK.md)).
  Клиент: `dev=` в `[qeli]` (дефолт `vpn0`) — выбрать имя tun, чтобы не отбирать чужой
  интерфейс / поднять несколько клиентов; + warn перед reclaim существующего + внятная
  ошибка при занятом интерфейсе. **169 тестов**, e2e на лабе. Скрипты-пробники
  `multicore_probe.py` / `multitunnel_probe.py`.
  - **Рефайны (2026-06-06):** (1) **blocking-read** TUN-читателей — убран nonblocking+
    `sleep(1ms)` busy-poll (на простое было N×1000 wakeups/с; теперь поток спит в `read`,
    idle CPU замерен 0%). (2) **UDP-помпа многоядерная** — N воркеров на `SO_REUSEPORT`-
    сокетах (socket2), ядро flow-хеширует датаграммы по клиентам; раньше один `recv`-цикл
    держал весь UDP-decrypt на одном ядре. (3) `tun.queues` cap 16→256 (MAX_TAP_QUEUES).
    (4) TAP-фикс в `delete` (перебор обоих режимов tun+tap). E2e: TCP+UDP `Auth OK` + ping,
    `dev=` вживую (2 клиента qtcp/qudp на одном хосте). `scripts/refine_e2e.py`.
- ✅ **Новый wire-режим `plain`** (raw, без обфускации) — сырой обмен X25519 +
  голые записи `[len][nonce][ct]` (никакой TLS-мимикрии); **TCP-only** (UDP+plain
  отвергается явной ошибкой). `Framing::{Tls,Raw}` в `packet.rs`, сырой хендшейк
  на клиенте и сервере, guard в валидации профиля. Бенчмарк: ≈ fake-tls по
  скорости (560↑/707↓ Mbps). TCP-only инвариант закреплён регрессионными
  тестами (`validate_profiles`: plain+udp → ошибка, plain+tcp / fake-tls+udp →
  ok). 161 unit-тест зелёный, e2e на лабе.
- ✅ **`rsid=` в `qeli://`-ссылке** — `reality-tls` теперь раздаётся QR (раньше
  только полным INI): `ClientLink.reality_sid` + to_uri/from_uri (Rust), парсеры
  Android (`Config.kt`) и .NET win+mac (`VpnConfig.cs`); `/api/share` и CLI
  `add-client` эмитят `mode=reality-tls`+`rsid` для профиля с `real_tls`+`short_ids`.
- ✅ **Cert-borrowing (Путь B REALITY) — РЕАЛИЗОВАНО (2026-06-06)** — hand-rolled
  REALITY-терминатор (`obf.tls.reality_proxy.handrolled = true`, требует `real_tls=true`)
  при старте профиля **захватывает настоящую цепочку серта target'а**: полный TLS-
  handshake с `target:443`, деривация ECDHE x25519/hybrid, дешифровка flight, лифт
  Certificate-сообщения (`realtls/server.rs::capture_target_cert`) — и отдаёт эту
  цепочку qeli-клиенту вместо self-signed/dummy (подпись своим ключом, клиент не
  валидирует — доверие через X25519 inner-auth, как Xray; серт зашифрован в TLS 1.3,
  не-breaking). Зеркалит JA3S/ServerHello target'а. `BorrowState{profile,cert}` под
  `RwLock` на `ProfileRuntime.reality_borrow`. **Auto-refresh**: фоновая задача раз в
  12ч ре-пробит target и обновляет cert+JA3S (при неудаче держит кэш). Живой e2e на .10:
  «borrowed TLS shape from www.microsoft.com:443 … (real cert chain: captured)» + клиент
  `Auth OK`. Честно: свежесть СЕРТА для **пассивного** DPI ≈ ноль (серт зашифрован в
  TLS 1.3); ценность — **активный** пробер, завершивший handshake, видит реальную
  microsoft-цепочку, + свежий plaintext JA3S/ServerHello. Конфиг — `CONFIG.md` `handrolled`.
- ✅ **`/api/share`: пароль → POST-тело** (был query-string — утечка в access-логи/историю).
- ✅ **Версии унифицированы → `0.5.6`** (бета) на всех компонентах; Android `versionCode=506`.
- ✅ **CI собирает клиентов** — добавлены android/windows/macos build-jobs в `ci.yml`.
- ✅ **Полный прогон бенчмарка всех 10 режимов** (incl. `plain` + `reality-tls`) с
  метриками CPU/RSS процесса — см. [BENCHMARK.md](../reports/BENCHMARK.md).
- 🟡 **Legacy carrier reality-tls download ~430 Мбит/с (≤0.7.16)** (было ~320 на 0.6.0; hand-rolled TLS с 0.7.0 поднял ~320→417→430, замер 0.7.4) — диагностировано на лабе: outer TLS + inner fake-TLS path =
  двойной AEAD + двойной фрейминг серийно в клиентском reader (CPU клиента ~67%
  ядра, AES-NI на VM есть → не software-AES, не CPU-потолок). Оптимизация
  `RealTlsStream::poll_read` (батч-дешифровка всех записей за poll + 64-КиБ буфер +
  курсор вместо per-record `drain`/alloc) **сделана и оставлена** (161 тест
  зелёный), но download не сдвинула — узкое место не в буферизации. Реальный fix
  (follow-up, design-изменение): (а) убрать избыточный внутренний AEAD в reality-tls
  (внешний TLS уже шифрует — гнать inner-дату в `plain`/Raw-фрейминге), либо
  (б) распараллелить TLS- и inner-крипто по задачам/ядрам.
- ✅ **NewSessionTicket (P4#6)** — REALITY-сервер теперь шлёт 1-2 post-handshake NST
  как настоящий TLS 1.3 (отсутствие — телл). Оба пути: rustls (`make_server_config`:
  ticketer + `send_tls13_tickets=2`) и hand-rolled (`server_handshake` шлёт 2 NST на
  серверном app-ключе; `build_new_session_ticket` RFC 8446 §4.6.1). Клиент не
  резюмирует — `RealTlsStream` пропускает post-handshake записи, seq синхронен. 161 тест.
- ⏸️ **QUIC по RFC (Ось 2A) — ДЕПРИОРИТИЗИРОВАН (2026-06-06).** Анализ `quic.rs`:
  текущий QUIC — структурный masking-shim (pn открытым текстом, нет header protection и
  шифрования QUIC Initial; Token Length и Length присутствуют и строго проверяются).
  «По-настоящему по RFC» = почти реализовать QUIC, И есть **фундаментальный потолок**:
  QUIC Initial расшифровывается кем угодно (Initial-ключи из DCID, RFC 9001 §5.2) —
  спрятать наш payload в «настоящем» Initial нельзя (DPI расшифрует, не найдёт
  CRYPTO-фрейм → телл). Достижимо лишь data-plane HP на short-header (убирает
  инкрементный-pn телл), но это breaking + зеркалить в Android/.NET. Решение: не
  затевать; для серьёзного анти-DPI — `reality-tls`/`obfs`. udp-quic = лёгкий masking.
  AAD-на-токене (P4#7) тоже пропущен: токен уже крипто-прочен (eph связан ключом +
  replay-guard + timestamp), AAD добавил бы лишь marginal SNI-binding ценой breaking.
- 🔬 **Distribution-matching shaping (Ось 2B, tell 6.1) — RESEARCH-TRACK (2026-06-06).**
  Placeholder'ом не реализуется. Механизм был бы **non-breaking/Rust-only** (паддинг +
  send-pacing на стороне отправителя; получатель и так срезает паддинг), НО «done» не
  определить без (а) целевой модели трафика (распределение размеров/таймингов реального
  HTTP/3) и (б) harness'а для валидации против ML-классификатора — на лабе нет ни того,
  ни другого. Наивный джиттер+паддинг = низкий доказуемый анти-ML эффект (ML смотрит
  flow-уровень: объёмы/длительность/burst/асимметрию) ценой перфа (pacing режет
  throughput). Уже есть: нормализация размеров (`round_sizes`), random padding,
  idle-gated heartbeat. Недостающее ядро — тайминг/pacing. Браться, когда появятся
  target-модель + measurement-harness.

## Сделано (2026-06-08) — Stream bonding (multipath)

- ✅ **Бондинг потоков (multipath)** — N параллельных TCP-соединений агрегируются в
  ОДНУ сессию (один tun-IP), исходящие пакеты раскидываются round-robin; обходит
  потолок single-stream «TCP поверх TCP» (на проде reality-tls ~6 Мбит на 1 поток,
  тогда как оператор на UDP/WireGuard даёт десятки). Мультипоток к одному HTTPS-хосту
  DPI-чистый (браузер открывает 6+ TLS). Per-profile `obf.multipath.{enabled,max_streams,
  adaptive}`; сервер пушит `max_streams`+`session_token` в AUTH OK, вторичные коннекты
  презентуют `JOIN_MAGIC‖token‖index` (сервер отвечает `JOINOK`). Каждый коннект делает
  СВОЙ qeli-KE → свой nonce-space из коробки.
  - ✅ **Сервер** — `SessionShared` (Arc) с `streams: Mutex<Vec<StreamHandle>>` +
    round-robin `pick_stream()`; `qeli_handshake`/`parse_first_message` ловят JOIN **на
    любом TCP-профиле любого режима** (mode-agnostic, имя профиля не при чём). 171 тест,
    clippy 0.
  - ✅ **Rust-клиент** — насос: 1 upload round-robin + per-stream reader/heartbeat;
    режимы FIXED (открыть ровно max_streams) и ADAPTIVE (ramp 1→max по throughput, стоп
    на плато). Реальные коннекторы для **всех TCP-режимов** (reality-tls/fake-tls/obfs/
    plain; `connect_obfs`/`connect_bare_tcp`, plain-ветка raw-KE в `tcp_join_handshake`).
    E2e лаб: 4 потока = 1 AUTH + 3 JOIN на один IP — на всех режимах.
  - ✅ **Android-клиент** — Kotlin-порт (per-socket `SocketIO`, per-mode `openBondedStream`,
    `runMultipathTunnelLoop`, `performJoinHandshakePlain`); все TCP-режимы. E2e эмулятор:
    reality-tls (4 потока, IP 10.9.0.3 на проде) + fake-tls.
  - ✅ **Прод-деплой** — release-бинарь `8b8ee19f` + `obf.multipath` в профиле
    reality-tls:443 (identity 7ff1c274 сохранён); e2e под user05 = 4 потока, телефон
    user01 НЕ задет (обратная совместимость: старый апп игнорит push-поля = 1 поток).
    См. [[reference_qeli_prod_server]] деплой 2026-06-08.
  - ✅ **Док**: `CONFIG.md` раздел «Бондинг потоков — multipath».

**Осталось доделать (multipath):**

1. ✅ **Win/Mac клиенты — ПОРТ СДЕЛАН+КОМПИЛИРУЕТСЯ 2026-06-08** (`qeli-win`/`qeli-mac`
   `Vpn/VpnTunnel.cs`): per-socket `SocketIO` + JOIN-хендшейк (вкл. plain raw-KE) +
   round-robin насос + per-mode `OpenBondedStream` для всех TCP-режимов — точный мирор
   Rust/Android. `dotnet build` обоих = 0 ошибок (нужен **.NET 10 SDK**: win=net10,
   mac=net8). ⚠️ RUNTIME e2e НЕ прогнан: qeli-win требует UAC-elevation (Wintun) →
   headless-тест в CLI не запустить; полный multipath-тест Win/Mac = на живой машине с
   админом (как замер телефона). Осталось: e2e на реальной машине + сборка подписанных
   дистрибутивов (Win exe готов в bin; Mac universal — кросс-сборка+rcodesign на .10).
2. 🔴 **P1 — замер реального прироста «4 vs 1»** на проде/телефоне — пока доказан только
   МЕХАНИЗМ бондинга (4 соединения → 1 сессия/IP), сам прирост throughput **НЕ измерен**.
   Мерять на телефоне/Android с новым APK (speedtest 1 поток vs 4 vs adaptive). NB: старый
   статус «CLI-клиент поднимает tun POINTOPOINT без peer / не качает» **устарел/неверен** —
   проверено 2026-06-19: клиентский tun = `<ip>/24` + pushed-MTU, tunnel-internal качает
   (bench 587 Мбит). Реальный CLI-баг был в **full-tunnel-маршруте** (см. ниже, исправлен).
   - ✅ **Full-tunnel CLI-маршрут ИСПРАВЛЕН 2026-06-19:** `route::setup_routes` ставил
     `default via <tun> metric 100`, проигрывавший типовому физическому default'у
     (metric 0) → full-tunnel (`mode=full-tunnel`/`add_default_gateway`) молча не
     активировался. Заменён на сплит `0.0.0.0/1` + `128.0.0.0/1` via tun (специфичнее /0
     → бьёт любой default без его удаления; server-bypass `/32` и connected `/24` целы;
     teardown — `flush dev` убирает /1 сам). Проверено в изолированном netns: OLD →
     `route get 8.8.8.8` шёл через физический gw, NEW → через `dev vpn0`. Гейт зелёный.
3. ✅ **P2 — adaptive-режим под реальной tunnel-нагрузкой** — Linux live gate прошёл:
   single 17/17, fixed 21/21, adaptive 22/22; adaptive вырос до трёх потоков и восстановил
   learned width после handover. Физический замер прироста «4 vs 1» остаётся в пункте 2.
4. ✅ **P2 — устойчивость к потере одного потока СДЕЛАНО 2026-06-08** — смерть bonded-
   потока теперь рвёт туннель ТОЛЬКО если это был последний; иначе поток выбывает из
   round-robin, туннель идёт на оставшихся (счётчик `live` + per-stream `dead`-флаг;
   распределитель лениво удаляет закрытые каналы). Все 4 клиента (Rust/Android/Win/Mac).
   E2E: убил 1 из 4 потоков на сервере → Rust и Android выжили на 3 (без реконнекта,
   UI «Connected», «stream lost; 3 remain»). Win/Mac компилируются. Осталось (опц.):
   **re-JOIN** упавшего для восстановления числа потоков (сейчас только деградация).
5. 🔵 **P3 (опц.) — глобальный дефолт multipath** вместо per-profile (профиль
   переопределяет) — чтобы не дублировать `obf.multipath.*` в каждом TCP-профиле.

## P1 — следующее

### Разбивка потерь наружу, в мобильный ABI (планируется V4)

Разбор «после сна падает скорость» закрыт: политика пробуждения, размер слотов downlink-пула,
неэскалация намеренного реконнекта и разбивка `internal_drops` на пять причин плюс отказы
писателя TUN уже есть в ядре и CLI-диагностике.

`QeliClientStats` уже имеет 144-байтовый **V3**: после стабильных V1/V2-префиксов он хранит
шесть roaming-метрик (attempts/successes/failures/reconnect fallbacks/candidates/latency).
iOS читает весь V3, но Android JNI пока возвращает восемь V2-подобных значений, а C# desktop
заканчивает структуру на V2 и не показывает roaming-телеметрию.

Пять per-cause UDP drop полей поэтому требуют **V4**, а не V3. Сначала нужно вывести уже
существующий V3 в Android/Windows/macOS, затем единым additive ABI-дополнением добавить V4
в C header, Rust FFI, JNI, Swift и C# без изменения прежних префиксов.

### Завершение CONTROL_V2 как управляющего канала (→ 0.8.x)

DNS/routes/MTU/multipath по-прежнему применяются из `AuthOK`; live-изменение требует
переподключения или нового runtime handler.

[`control_v2.rs`](../../../qeli/src/protocol/control_v2.rs) уже реализует magic/version/type/
flags/message id, bounded fragmentation/reassembly, ACK/error и ограничения. Roaming path
messages используют этот формат end-to-end. Но общий server → client runtime dispatcher пока
обрабатывает только path-control/закрытие; `PUSH_CONFIG`, `KICK` и `NOTICE` существуют как
типы и тестовые кадры, а не как завершённые функции продукта.

Осталось:

1. общий negotiated dispatcher с capability, idempotency, retry и явным error-result;
2. сначала `KICK` с причиной и `NOTICE` квоты/срока — без изменения сетевого состояния ОС;
3. затем типизированный `PUSH_CONFIG` с generation-safe применением DNS/routes/MTU/multipath;
4. на Android route push должен делать новый `VpnService.Builder.establish()` и короткую
   замену TUN, потому что живой интерфейс не умеет менять маршруты.

Для 0.8.0 `KICK`/`NOTICE` желательны, а полный `PUSH_CONFIG` можно явно перенести в 0.8.1.
Готовый roaming от этого больше не зависит и использует собственные negotiated capabilities.

### Полная поддержка IPv6 (линия разработки 0.8.0; сертификация не завершена)

**Полный план: [IPV6-IMPLEMENTATION-PLAN.md](IPV6-IMPLEMENTATION-PLAN.md).** IPv6-адрес
сервера — лишь внешний carrier и не считается реализацией IPv6 сам по себе. Задача включает
независимые outer IPv4/IPv6, внутренние `ipv4|dual|ipv6`, TUN и TAP, TCP/UDP/QUIC, серверную
маршрутизацию и DNS, MTU/PMTU и UDP data fragmentation, kill switch, все системные/per-app
клиенты, панель, Quick Start, установщик, пакеты и примеры.

Исходная реализация теперь относится к линии разработки 0.8.0. Автоматическая базовая
Linux-матрица 2026-08-31 прошла 14/14 сочетаний outer/inner/transport, включая cross-family
leak и cleanup. Остаются специальные DNS/PMTU/PTB/TAP/legacy-сценарии и physical/native-матрица.
До прохождения этих gate на финальных артефактах это development implementation, а не релиз.

Промежуточные стадии используются только для разработки. Возможность нельзя выпускать или
называть полной до прохождения всей IPv6-only/dual-stack release matrix. Пользовательские
конфиги остаются flat INI; внутренние wire/FFI-сообщения не являются JSON-конфигами.

### Роуминг — бесшовная смена сети (после IPv6; целевая ветка 0.8.x, Linux live-срез готов)

**Нормативный план: [ROAMING.md](ROAMING.md).** Поддерживаемые сборки включают общий TCP/UDP roaming
core под внутренним compile gate. Выключенные профили, legacy peers и неподдерживаемые adapters при
смене Wi-Fi↔LTE/IP выполняют быстрый reconnect с новым handshake и Argon2. Path executors
Linux/OpenWrt, Android, Windows, macOS и iOS source-complete; Linux TCP/UDP+QUIC и Android TCP/UDP имеют частичную live-приёмку с
сохранением session id, внутренних IPv4/IPv6, NetworkPlan, TUN/TAP, маршрутов и квоты.
На сервере реализован профильный rollout: новые профили включают роуминг, а sparse старые
профили остаются выключенными для совместимости. Клиентская политика `off|auto|required`,
её flat-INI/`qeli://` round-trip и общие transport-specific gates source-complete во всех клиентах.
Панель и явные GUI controls реализованы; оставшаяся platform/race/soak matrix и поэтапный rollout относятся к этапу 6.

- Общая основа: negotiated `CONTROL_V2`, `UDP_ROAM_V1`, `TCP_RESUME_V2` и
  `TCP_HANDOVER_V2`; domain-separated resume/CID secrets; generation-scoped динамический
  PathUpdate ABI и транзакция PREPARE/COMMIT/ABORT.
- **UDP с UDP_ROAM_V1 + DATA_FRAG_V1:** единый directional восьмибайтовый CID envelope для
  fake-TLS, QUIC masking, obfs и AWG, profile-wide registry между всеми workers/listeners,
  per-session actor и dynamic egress socket. PATH_CHALLENGE/PATH_RESPONSE, anti-amplification и
  двунаправленный PMTU reset/re-probe обязательны до переключения downstream. Legacy peers без
  согласованных authenticated roaming capabilities остаются на полном reconnect.
- **TCP:** authenticated JOIN с новым key exchange и fresh AEAD, широкий resume epoch,
  grace с bounded orphan limits, стабильные logical slots и make-before-break. Token
  является locator, но не доказательством владения.
- **Криптографический инвариант:** UDP migration сохраняет тот же `PacketCodec` и общую
  replay-window — codec нельзя пересоздавать с тем же ключом. TCP JOIN всегда получает
  новые направленные ключи. Поэтому сброс nonce/counter при resume конструктивно запрещён.
- Платформы сначала атомарно подготавливают host route, kill-switch/per-app allowlist,
  physical DNS и точный bind/protect candidate socket; после validation/JOIN выполняются
  commit, drain и cleanup. Без этого capability не объявляется.
- Пользовательская настройка остаётся flat INI: серверные `roaming.*` внутри профиля,
  клиентский `[qeli] roaming = off|auto|required`. Новые серверные профили включены по умолчанию,
  клиенты используют `auto`; sparse старые профили и legacy peers сохраняют reconnect.

Порядок: спецификация/KDF/control → dynamic path ABI → TCP lifecycle/supervisor → UDP
registry/validation/PMTU → Android/Windows/macOS/iOS/Linux/OpenWrt → конфиги/панель/docs →
полная lab/soak-матрица. Небезопасной фазы без proof, path validation, anti-amplification
или PMTU reset в плане нет. Оценка полной работы — 20–30 инженерных недель.

1. **Настоящий REALITY** (TLS 1.3-туннель + проксирование чужих на реальный сайт) —
   уровень Xray-REALITY. **Путь A (ACME-серт своего домена) ОТВЕРГНУТ (2026-06-06):**
   это Trojan-модель — свой домен блокируется без collateral, теряется суть REALITY
   («домен слишком большой, чтобы блокировать»). **Принят Путь B — одалживание
   настоящей цепочки сертификата target'а:** probe захватывает реальный серт (напр.
   microsoft), hand-rolled сервер отдаёт его своим клиентам вместо self-signed/dummy
   (подпись своим ключом, клиент не валидирует — как в Xray; серт зашифрован TLS 1.3,
   не-breaking). **✅ РЕАЛИЗОВАНО 2026-06-06** — cert-borrowing + auto-refresh (12ч);
   см. запись «Cert-borrowing (Путь B REALITY)» в разделе «Сделано» выше и `CONFIG.md`
   (`obf.tls.reality_proxy.handrolled`).
   - ✅ **M1 — криптографический REALITY-аутентификатор + ALPN** (2026-06-05):
     `crypto/reality.rs` (seal/open `session_id`: `auth = HKDF(X25519(eph, reality_pub) ‖ short_id)`),
     клиентский ClientHello несёт auth в `session_id` + добавлен ALPN (`tls.rs`),
     сервер опознаёт qeli **криптографически** (открывает `session_id` приватником
     профиля и сверяет с `short_ids`) вместо прежней эвристики «нет ALPN»
     (`server/reality.rs`). Конфиг: server `obf.tls.reality_proxy.short_ids`,
     client `reality_sid`. Лаба: clippy 0, **120 тестов** (юнит покрывает полный путь
     hello→parse→open→short_id + отклонение чужого). **Живой e2e на .10 (2026-06-05):**
     (1) верный токен → `REALITY: Qeli client detected` + `AUTH OK`, IP выдан;
     (2) неверный `reality_sid` (тот же бинарь) → НЕ опознан → проксирование →
     клиент `failed to parse ServerHello`; (3) активный пробинг openssl без токена →
     отдан **настоящий валидный серт** `CN=www.microsoft.com` (issuer Microsoft TLS G2).
     Детект-строка возникает строго при верном токене — токен реально гейтит детект.
   - ✅ **M2 (готов 2026-06-05)** — браузерный настоящий TLS-клиент, pure-Rust `realtls`-core
     (решено 2026-06-05, `docs/*/archive/plans/DESIGN-remaining.md`); интероп с rustls доказан:
     - ✅ **M2.1 (2026-06-05)** — байт-грейд Chrome ClientHello + JA4 (`protocol/realtls/clienthello.rs`):
       JA4 `t13d1516h2_8daaf6152771_…` (JA4_b = канонический хэш cipher-списка Chrome — сверено
       тестом, байт-точность без живой капчи). REALITY-токен в `session_id` + x25519 `key_share`
       восстанавливаются существующим серверным парсером (`extract_key_share` научен обходить
       GREASE-first `client_shares`). Лаба: 125 тестов, clippy 0.
     - ✅ **M2.2 (2026-06-05)** — TLS 1.3 key schedule + AEAD record layer (`realtls/keyschedule.rs`,
       `realtls/record.rs`): HKDF-Expand-Label/Derive-Secret, early→handshake→master + traffic
       keys/iv/finished; record nonce=iv⊕seq, AAD=заголовок, inner=content‖type. Сверено
       **побайтово с RFC 8448 §3** (полный key schedule + KAT записи client Finished) + round-trip
       + tamper-reject. Добавлен крейт `aes-gcm`. Лаба: 130 тестов, clippy 0.
     - ✅ **M2.3 (2026-06-05)** — клиентская TLS 1.3 handshake-машина (`realtls/client.rs`):
       CH→SH→зашифрованный flight (EE/Cert/CertVerify/Finished, серт не валидируем — доверие
       X25519/inner-auth, но server Finished верифицируем)→client Finished→app-ключи. Проверено
       **loopback-интеропом** против минимального spec-точного TLS 1.3-сервера (полный flight,
       coalesced-записи, CCS, двусторонний app-data). Нашёл/починил баг scope transcript для
       app-секретов. Добавлен `hmac`. Лаба: 131 тест, clippy 0.
     - ✅ **M2.4 — gold-интероп (2026-06-05)** — наш realtls-клиент завершает **настоящее TLS 1.3
       рукопожатие против `rustls`** (ring-провайдер, on-the-fly self-signed cert через `rcgen`,
       TLS1.3-only/AES-128-GCM): rustls принял наш Chrome-ClientHello, прислал реальные
       Certificate/CertVerify, мы верифицировали server Finished, rustls принял наш client Finished,
       app-data в обе стороны. Доказывает, что наш hello/handshake — настоящий TLS (loopback это
       доказать не мог). rustls/tokio-rustls/rcgen — dev-deps. Лаба: 132 теста, clippy 0.
   - ✅ **M3 — ПОЛНОСТЬЮ ЗАКРЫТ (2026-06-05)** — настоящий REALITY на Rust-стеке работает e2e:
     - ✅ **M3.1 (2026-06-05)** — серверный building block `realtls/server.rs`: `PrefixedStream`
       (replay буферизованного ClientHello) + `make_server_config` (rustls TLS1.3/AES-128-GCM,
       on-the-fly self-signed cert) + `terminate()`. Тест **peek→replay**: сервер потребляет
       ClientHello (как делает детектор токена), реплеит в rustls — настоящее рукопожатие с нашим
       клиентом завершается. rustls/tokio-rustls/rcgen → прод-зависимости. Лаба: 133 теста, clippy 0.
     - ✅ **M3.2 (2026-06-05)** — клиентский building block `realtls/stream.rs`: `RealTlsStream<S>` —
       `AsyncRead+AsyncWrite` поверх established-TLS (фреймит app-data через `RecordCrypto`, кап
       16384/record, скип non-appdata записей). Тест против rustls (interop + bulk 20КБ round-trip).
       Теперь **обе стороны — потоки** (сервер tokio-rustls `TlsStream`, клиент `RealTlsStream`).
       Лаба: 135 тестов, clippy 0.
     - ✅ **M3.3 — wiring (2026-06-05)**: `SplitStream` для `TlsStream`/`RealTlsStream`; конфиг-флаг
       `obf.tls.reality_proxy.real_tls`; сервер `reality.rs` «свой»+real_tls → `terminate()`+`handle_client`
       ВНУТРИ `TlsStream`; клиент `mode=reality-tls` → `client_handshake`+`RealTlsStream`+`run_tcp_tunnel`.
       Nested (inner fake-TLS+PacketCodec внутри настоящего TLS). Лаба: компилируется, clippy 0, 135 тестов.
     - ✅ **M3.4 — лаба e2e (2026-06-05)**: reality-tls клиент ↔ сервер на .10 — НАСТОЯЩЕЕ TLS-рукопожатие
       (Chrome JA4) → сервер открыл токен из real-ClientHello → `real_tls` терминация rustls → вложенный
       qeli-auth → **`AUTH OK`, IP выдан (10.99.0.2)**. Активный пробер (openssl без токена) → проксирован
       на microsoft (настоящий серт) — «чужой» путь сосуществует с real_tls. JA4=Chrome доказан unit'ом (M2.1).
     - ✅ **M3.5 — доработки + полный e2e (2026-06-05)**: (a) **кеш rustls-cert** на профиле (строится 1×
       при старте, `ProfileRuntime.reality_tls_config`; лог `REALITY real-TLS termination enabled`);
       (b) **полный data-plane на .11**: reality-tls клиент (.11) ↔ сервер (.10), `AUTH OK` IP 10.99.0.2,
       клиент поднял свой TUN `vpn0`, **ping сквозь туннель 4/4 0% loss** ~3.6мс, SENT/RECV двусторонние;
       (c) **tcpdump-проверка провода**: SNI `www.microsoft.com` + record-типы `1603`×2 (CH/SH) `1403`×2 (CCS)
       `1703`×11 (зашифрованный flight+туннель) = эталонный TLS 1.3, серт **зашифрован** (не fake-TLS).
       JA4=`t13d1516h2_8daaf6152771` (Chrome) доказан unit'ом M2.1.
   - ✅ **ПРИЛОЖЕНИЯ — FFI realtls-core** (sans-IO ядро → Android + Windows + macOS; `docs/*/archive/plans/DESIGN-remaining.md`):
     - ✅ **A1 — sans-IO core (2026-06-05)** — `realtls/sansio.rs`: `SansIoClient` byte-in/byte-out
       state-machine (`new`→ClientHello; `recv`→NeedMore/Done(CCS+client Finished); `seal`/`open_push`).
       Тест против настоящего rustls (байты шаттлятся вручную, как сделает FFI-вызыватель). Побочно
       поймал/починил баг `build_client_hello`: дублирующийся GREASE-extension (~6% flaky → rustls reject) —
       теперь grease_first≠grease_last, харденит ВСЕ realtls-рукопожатия. Лаба: 136 тестов, clippy 0.
     - ✅ **A2 — C ABI (2026-06-05)** — `realtls/ffi.rs`: `qeli_realtls_{new,recv,seal,open,free,buf_free}`
       (`#[no_mangle] extern "C"`, opaque handle, буферы ptr+len, `catch_unwind`, `# Safety`-доки). Тест:
       полное рукопожатие + app-обмен через сам C-ABI против rustls (та же последовательность вызовов, что
       сделает JNI/P-Invoke). Лаба: 137 тестов, clippy 0.
     - ✅ **A3 — нативная Android-либа (2026-06-05)**: lib+bin рефактор (`src/lib.rs` `pub mod`, без
       compile_error для non-Linux; client/server/tun/web — cfg-linux; `main.rs`→`use qeli::…`; `[lib]
       crate-type=["rlib","cdylib","staticlib"]`; фикс `impl Default for Obfuscator`). На .11: rust
       android-таргеты + `cargo-ndk` v4.1.2 + NDK r26d (sdkmanager). `cargo ndk -t arm64-v8a -t x86_64
       build --lib` → **`jniLibs/{arm64-v8a,x86_64}/libqeli.so`** (ELF Android 21, NDK r26d), **все 6
       `qeli_realtls_*` экспортированы в обеих ABI**. ring/rustls/tokio/aes-gcm собрались под Android без правок.
       Хост: 137 тестов, clippy 0. (Debug ~30МБ → для APK собрать `--release`+strip; axum/qrcode/clap можно
       feature-gate'нуть из android-сборки — оптимизация позже.)
     - ✅ **A4 — JNI-мост (2026-06-05)**: Rust `realtls/jni.rs` (7 `Java_com_qeli_RealTls_*` поверх `SansIoClient`;
       собрано `cargo ndk`, `nm -D` подтвердил) + Kotlin `RealTls.kt` (`@JvmStatic external` + `System.loadLibrary`)
       + **интеграция в `QeliService`**: reality-tls в `connectTcp` → `RealTlsTransport` оборачивает `TcpTransport`
       (`send`→`tls.seal`, `recvRecord`→`tls.open`+нарезка inner-записей; `doRealTlsHandshake` по сырому сокету);
       `Config.realityShortId` (INI `reality_sid`/JSON `reality_short_id`). **Release-`.so`** (arm64 453КБ,
       x86_64 525КБ — LTO+strip убрал недостижимый server/web) скачаны в `qeli-android/app/src/main/jniLibs/`;
       `Cargo.lock` + исходники — локально. (Kotlin валидируется на сборке APK — A5.)
     - ✅ **A5 — Android e2e РАБОТАЕТ (2026-06-05)**: APK собран на .11 (gradle, Kotlin компилится, `.so`
       упакованы), поставлен на эмулятор; reality-tls профиль → клиент: `REALITY TLS 1.3 established (SNI
       www.microsoft.com)` → `Auth OK, IP 10.99.0.2` → tunnel loop; сервер .10: `REALITY: Qeli client detected
       from 10.66.116.11` → `AUTH OK`; **ping сквозь туннель 4/4 0% loss** ~4мс, SENT/RECV двусторонние.
       Android-клиент теперь шлёт тот же **байт-точный Chrome-TLS** (JA4 `t13d1516h2_8daaf6152771`), что и
       Rust — через общий realtls FFI-core. **Фаза приложений A1→A5 для Android ЗАВЕРШЕНА.**
   - ✅ **qeli-win — REALITY работает (2026-06-05)**: `qeli.dll` кросс-собрана под win-x64 (target
     `x86_64-pc-windows-gnu` + mingw на .10; C-ABI экспорты подтверждены objdump; `transport` scaffolding
     gate'нут под linux — он один не компилился под windows), встроена в exe как `EmbeddedResource` +
     `NativeLoader` (обобщён на qeli.dll). C# `Vpn/RealTls.cs` (P/Invoke поверх `ffi.rs`) + `RealTlsTransport`
     в `VpnTunnel` (nested seal/open) + `Config.RealityShortId`. dotnet build: 0 ошибок. **Headless e2e**:
     `QeliWin.exe handshake <json>` → exit 0; сервер .10 (192.168.50.50): `REALITY: Qeli client detected` →
     `AUTH OK`. **Все 3 клиента (Rust / Android / Windows) шлют один байт-точный Chrome-TLS через общий
     realtls FFI-core** (sans-io → C-ABI для Windows P/Invoke / JNI для Android / нативно для Rust).
   - ✅ **qeli-mac — REALITY работает (2026-06-06)**: `libqeli.dylib` кросс-собрана universal2
     (`cargo-zigbuild`, arm64+x86_64) на .10, встроена в C#/Avalonia-клиент (`Vpn/RealTls.cs`
     P/Invoke + reality-tls проводка). Подписанный universal `Qeli.app` собран ПОЛНОСТЬЮ без Mac
     (dotnet publish osx-arm64+osx-x64 → llvm-lipo → rcodesign ad-hoc) → `qeli-mac/dist/Qeli-macOS-universal.zip`.
     dylib = тот же realtls-core. **Все 4 клиента (Rust / Android / Windows / macOS) согласованы.**
   - 🔵 **Финал проекта — UI-полировка.**
2. ✅ **Унификация TCP/UDP transport в Rust-сервере** — крипто/auth вынесены в
   общие хелперы `handler.rs` (`HandshakeRecords`/`build_handshake_records`,
   `build_server_auth_msg`, `verify_client_auth`); оба транспорта зовут их, дублей
   крипто/auth больше нет (различие только в framing/IO: stream vs datagram).
   Лаба: TCP+UDP вход (AUTH OK, ping 0%), неверный пароль и per-profile-deny
   отрабатывают; 0 warnings, 111 тестов. Мёртвый `get_session_limit` удалён.

### Блок обфускации: настоящий QUIC Initial → пресеты TLS (→ 0.9.x)

Делать именно в этом порядке — оба пункта правят один и тот же код построения ClientHello.

**1. Настоящий QUIC Initial (RFC 9001).** Сейчас `wrap_quic_long`
([quic.rs](../../../qeli/src/protocol/quic.rs)) рисует синтаксическую оболочку long
header, а payload дописывает **открытым текстом**: нет вывода Initial-секретов, нет AEAD,
нет header protection, нет CRYPTO-фрейма. Реальный ClientHello с SNI при этом есть
([client/mod.rs](../../../qeli/src/client/mod.rs)) — он просто едет в самописной
фрагментации ([udp_frag.rs](../../../qeli/src/protocol/udp_frag.rs)).

Для DPI, умеющего разбирать QUIC, это **отличительный признак, а не маскировка**: пакет
объявляет QUIC v1, но защищённые поля структурно невалидны. Пока не сделано — режим стоит
считать экспериментальным.

- Объём ограничить жёстко: корректным должен быть **Initial-пакет**, а не стек QUIC
  (короткий заголовок для остального уже есть). Состав: HKDF от фиксированной соли + DCID,
  AES-128-GCM, header protection, CRYPTO-фрейм (0x06) с существующим ClientHello,
  PADDING до ≥1200.
- **Де-рискер:** в RFC 9001, Appendix A есть готовые тест-векторы. Known-answer тесты в
  Rust, затем теми же векторами валидируем C# и Kotlin — это превращает налог на три
  реализации из отладки вслепую в прогон готовых векторов.
- Приятный побочный эффект: у CRYPTO-фреймов есть смещения, то есть многопакетный
  ClientHello (он большой из-за ML-KEM — ровно поэтому и появился `udp_frag`) становится
  **штатным** механизмом, и один самодельный формат уходит.

**2. Пресеты fake-TLS отпечатков.** Сегодня builder один и жёстко зашит
([tls.rs](../../../qeli/src/protocol/tls.rs)); настраиваемых профилей
Chrome/Firefox/Schannel, `gmt_unix_time` и произвольного состава расширений нет.

- **Сначала — дешёвый шаг:** решить судьбу перемешивания порядка расширений
  ([tls.rs](../../../qeli/src/protocol/tls.rs)). Задумано против JA3-пиннинга, но у
  настоящего Chrome JA3 **стабилен**, и «клиент с новым отпечатком каждое соединение» сам
  по себе аномален. Это анализ на день, и он может изменить постановку задачи.
- Профиль = (шифры, состав и порядок расширений, политика session_id, ALPN, sig-algs,
  GREASE, `gmt_unix_time`). Начать с двух.
- Chrome-образный builder **уже написан** — [realtls/clienthello.rs](../../../qeli/src/protocol/realtls/clienthello.rs),
  и он вдобавок считает JA4: использовать его же для проверочных тестов (пресет обязан
  давать ожидаемый JA4).
- ⚠️ Это **беговая дорожка**: пресет привязывать к версии браузера и датировать, иначе
  через год устаревший «Chrome» станет собственным признаком.

### Бэклог (внутренний аудит 2026-06-18)
- 🔵 **Независимый внешний аудит самописного realtls** (`protocol/realtls/*`, ~3k
  строк) — крупнейшая непроверенная поверхность; блокер доверия для серьёзных
  пользователей. До тех пор — наращивать fuzzing (`qeli/fuzz/`) в непрерывном режиме.
- ✅ **Continuous fuzzing в CI** (2026-06-19) — job `fuzz-nightly` (`schedule`, 03:17
  UTC): по таргету `qeli/fuzz/` 10 мин/прогон, корпус сохраняется между прогонами
  через `actions/cache` (коверидж накапливается), краш-репродьюсер — в артефакты.
  Плюс `fuzz-smoke` (30с на каждый push, build-break check). Репозиторий public →
  Actions бесплатны. (Харнес добавлен в 0.7.2.)
- ✅ **FFI panic-safety: клиентские cdylib собираются с `panic = "unwind"`** (завершено в
  0.7.15, [TRANSPORT-CORE TC-0.1](../reference/TRANSPORT-CORE.md)). Native-рецепты Android/Windows/macOS/iOS
  и CI задают `CARGO_PROFILE_RELEASE_PANIC=unwind`; feature `ffi-cdylib` на этапе компиляции
  запрещает случайную сборку с `panic=abort`, а тест намеренной паники ABI подтверждает возврат
  ошибки. Серверный бинарь намеренно остаётся с `panic=abort`.

### Бэклог (аудиты 2026-07-17: два внешних + собственный)

- 🔵 **Две настройки существуют, но не работают** — оставлены осознанно и помечены
  «не реализовано» в CONFIG.md; остальные 15 мёртвых ключей в 0.7.12 удалены.
  - `dns.upstream_protocol = tls` (DoT) — **`tcp` уже работает** (0.7.14: принудительно
    ходит к апстриму по TCP, а усечённый UDP-ответ в любом случае перезапрашивается по
    TCP), а `tls` ОТВЕРГАЕТСЯ при загрузке конфига, а не понижается молча. Осталась сама
    реализация DoT: апстрим-запросы перестали бы быть видны провайдеру. Пока не
    реализовано, **резолвер не даёт приватности от того, кто видит ваш канал к
    апстриму**.
  - `logging.format` — поле парсится (дефолт `plain`), но `init_logging` его **не читает**:
    лог всегда в жёстко зашитом `{ts} {LEVEL:<5} {target}: {msg}`, причём кастомный
    форматтер стоит под `#[cfg(target_os = "linux")]` → на других платформах формат иной
    (уже рассинхрон). **План (проработан 2026-07-18):** 5 вариантов, единых для
    сервера / Rust-клиента / десктопа / Android:
    `text` (как сейчас, дефолт) · `compact` (без даты, 1-символьный уровень — роутеры,
    мобильные) · `plain` (только уровень+сообщение — когда метку ставит journald /
    logread / logcat; убирает двойные таймстемпы) · `logfmt` (`k=v`, человек+машина) ·
    `json` (NDJSON — Loki/ELK/SIEM; панель сможет рисовать логи таблицей с фильтрами).
    Единая схема полей для `json`/`logfmt`: `v` (версия схемы), `ts` (RFC3339 UTC),
    `level`, **`comp`** (`server|client|panel|gui` — кто написал), `target`, `msg`.
    Override — env `QELI_LOG_FORMAT`.
    **Две фазы:** (1) дёшево — форматтер начинает читать поле, `msg` остаётся собранной
    строкой, call-site'ы не трогаем (даёт 80% пользы: парсится, шиплется, фильтруется);
    (2) позже — перевод горячих мест (auth / сессии / ошибки / NAT) на структурные поля
    (`user`/`profile`/`peer`/`err`), возможно `env_logger` → `tracing`.
    Бонус: в `json` экранирование строк штатное → закрывает log-injection надёжнее
    ручного CRLF-escape (H-8 из 0.7.3).
    NB: формат **времени** вынесен отдельно и уже **сделан** в 0.7.12
    (`[logging] time_format` + выбор в Windows / macOS / Android / LuCI) — осталась
    только форма самой строки, описанная выше.
  - 🔵 **Ротация лог-файла отсутствует** — при `level = debug` файл растёт неограниченно
    (на роутере/VPS это реальный риск забить диск). Либо `[logging] max_size_mb` + `keep`,
    либо явно задокументировать передачу logrotate.

Всё Medium+ из трёх аудитов закрыто в 0.7.12 (**выпущена 2026-07-21** — см. CHANGELOG).
Здесь — сознательно отложенное.

- ✅ **Обратный PMTU-канал (клиент сообщает серверу найденный path-MTU).**
  СДЕЛАНО в 0.7.14. Клиент отправляет найденный MTU аутентифицированным внутритуннельным
  control-кадром сразу после AuthOK, сервер держит `min(профильный tun.mtu, сообщённый)` на
  сессию ([ctrl.rs](../../../qeli/src/protocol/ctrl.rs), [server/mod.rs](../../../qeli/src/server/mod.rs)).
  Слишком крупные нисходящие пакеты обрабатываются как на маршрутизаторе: при выставленном DF —
  ICMP Fragmentation Needed с настоящим next-hop MTU (RFC 1191), без DF — датаграмма
  фрагментируется (RFC 791), а не отбрасывается ([icmp.rs](../../../qeli/src/protocol/icmp.rs)).

  **Одно утверждение из обоснования отсрочки было просто неверным**, и это стоит оставить на
  виду: «сервер на downlink не ставит DF → перебор фрагментируется, а не чёрно-дырится». DF он
  действительно не ставит, но qeli форвардит в ПРОСТРАНСТВЕ ПОЛЬЗОВАТЕЛЯ — ядро этот пакет не
  видит и потому не фрагментирует. Non-DF пакеты сверх MTU просто терялись. Именно эта ошибка
  делала пользу от фичи меньше, чем она есть, — хороший довод в пользу измерения вместо
  рассуждения о пути данных. Аддитивно в обе стороны: клиент, который отчёт не шлёт, оставляет
  сервер на профильном MTU ровно как раньше.

  IPv4-заголовки с ОПЦИЯМИ теперь тоже фрагментируются (2026-08-01): бит «copied» каждой опции
  решает, попадёт ли она в последующие фрагменты (RFC 791 §3.1) — Router Alert копируется,
  Record Route и timestamp остаются только в первом. Раньше такой пакет просто отбрасывался,
  то есть на пути, где отправитель прямо просил фрагментацию, получалась чёрная дыра.
  Для IPv6-форвардинга теперь есть аналог по RFC 4443: если пакет больше сообщённого клиентом
  MTU узкого участка, сервер формирует ограниченный по размеру ICMPv6 Packet Too Big с этим MTU;
  на ICMPv6-ошибку другая ошибка не генерируется.
- 🔵 **`nonce_seed` под resume/роуминг** — см. ⚠️-ограничение в разделе «Роуминг — бесшовная
  смена сети» выше: решать В ДИЗАЙНЕ resume (ре-деривация ключа на resume либо epoch в nonce),
  а не после.
- ⚪ **Информационное, действий не требует** (проверено, влияния нет): запись принимается при
  `record.len() >= declared` без строгого равенства (фрейминг точен, AEAD режет ровно
  объявленное); байты версии TLS `0x03 0x03` не проверяются и заголовок не входит в AAD
  (payload аутентифицирован — модель как у WireGuard); недостижимый чек `payloadLen > 65535`
  в C#/Kotlin-ридерах.

## P2 — качество

3. ✅ **fmt/clippy normalization** — одноразовый `cargo fmt` + clippy-pass по всему
   дереву (33 warning'а: `io_other_error`, `field_reassign_with_default`,
   `inherent_to_string`→`Display`, `unnecessary_cast`, doc-list-indent,
   `type_complexity`→alias, `too_many_arguments`→targeted `#[allow]`). Lint-джоба
   CI теперь гейт: `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings`
   (снят `continue-on-error`); `scripts/ci-check.sh` тоже ужесточён. Лаба: fmt
   clean, clippy 0, 111 тестов, TCP-смоук (ping 0%).
4. ✅ **Web-редактор с сохранением комментариев** (2026-06-05) — третий вид «Raw INI»
   на странице `/config`: `GET /api/config/raw` отдаёт файл дословно, `PUT /api/config/raw`
   валидирует через `parse_server_config` и пишет текст **как есть** (комментарии целы).
   Те же path-whitelist-гарды, что и у структурного PUT (logging.file/users_file). Лаба:
   build + clippy + 114 тестов. Additive (не breaking); прод-бинарь получит при следующем деплое.
5. ✅ **`quic` в Rust** (2026-06-05) — `ClientLink.quic` + `client.rs`
   (`from_link`/`from_ini`/`to_link`/`to_ini_string`) + генераторы `main.rs` (`qeli add-client`)
   и `web/api/share.rs` теперь эмитят/парсят `quic=1`(ссылка)/`quic=true`(INI). udpquic-ссылка
   из CLI/web включает QUIC из коробки. Все три клиента согласованы. Лаба: 114 тестов.
6. 🟨 **Android: подписанные Release APK** — release notes 0.7.16 документируют переход на
   `assembleRelease`, R8/minification и release signing, поэтому прежнее утверждение «сегодня
   выпускается debug APK» больше не является нормативным. Окончательный статус подтверждается
   только attestation конкретного публикуемого артефакта. Для 0.8.0 обязательны непрерывность
   signing key, `debuggable=false`, проверка подписи и smoke minified-сборки с JNI/transport-core;
   migration со старого debug-ключа остаётся caveat для ранних установок.

## P3 — long-term / экспериментальное

7. ✅ **Post-quantum hybrid KEX** (2026-06): **X25519MLKEM768** (ML-KEM-768, FIPS 203).
   Внутренний qeli-туннель выводит ключи плоскости данных из X25519 ⊕ ML-KEM-768
   (`derive_keys_hybrid`, соль `…v2-hybrid`) во ВСЕХ режимах кроме `plain`
   (`fake-tls`/`obfs`/`reality-tls`/UDP) — сервер encapsulate / клиент decapsulate;
   ClientHello несёт РЕАЛЬНУЮ ML-KEM-долю (а не только фингерпринт-паритет с Chrome).
   Сервер ТРЕБУЕТ X25519MLKEM768 для не-`plain` (нет тихого даунгрейда). Крейт `ml-kem`
   (pure-Rust); managed-клиенты (C#/Kotlin) берут ML-KEM из того же ядра через C-ABI/JNI
   (`qeli_mlkem_*` / `Java_com_qeli_MlKem_*`) — BouncyCastle ML-KEM не содержит. Live-
   проверено на лабе (tcp-faketls/obfs/udp, 0 % потерь, 570–700 Мбит/с TCP).
8. ✅ **obfs для UDP** (per-datagram keyed XOR) — `ObfsUdp`-обёртка (nonce(12) +
   ChaCha20-XOR на датаграмму, stateless); pure-Kotlin ChaCha20 на Android
   (javax `Cipher("ChaCha20")` сломан на части рантаймов); qeli-win — `DatagramSeal/Open`
   (BouncyCastle, добавлено 2026-06-05). Лаба: TCP+UDP obfs e2e на всех трёх клиентах.
   ✅ **UDP-obfs энтропия (tell 4.2) закрыта 2026-06-05** — датаграмма приняла форму QUIC
   short-header (`[flag][nonce-as-CID][protected]`), не высокоэнтропийная с байта 0.
   Breaking wire-change — задеплоено 2026-06-05 (прод + dist-клиенты, e2e Auth OK).
9. ✅ **Multipath / stream bonding** — РЕАЛИЗОВАНО (сервер + Rust + Android, все
   TCP-режимы; см. «Сделано 2026-06-08» + «Осталось доделать (multipath)» выше).
   Остаётся: **MASQUE**, **WireGuard-совместимый режим**, **eBPF-fastpath**.
10. ⚪ **Многоядерный data-plane — НЕ планируется (измерено 2026-06-19: упор не в CPU).**
    Уточнение архитектуры: fan-out TUN→клиент **уже многоядерный** — `tun.queues`
    (дефолт = nproc) + IFF_MULTI_QUEUE + RSS ядра по очередям, шифрование N-way
    параллельно, сериализация только per-session codec-локом. Multi-user масштабируется
    по ядрам; single-user high-throughput — через **multipath** (bonding). Остаётся
    единственный случай — одно **не-multipath** соединение: его поток RSS пинит в одну
    очередь + один codec (монотонный счётчик → nonce) = 1 ядро. **Замер 2026-06-19:**
    прод = **1 vCPU** — его data-plane упирается в это **единственное** ядро на ~311 Мбит
    (CPU-bound на 1 ядре, distinct: крипта+фрейминг+оверхед, не raw-AES ~8 Гбит/с); ядер
    больше нет → распараллеливать физически некуда. На лабе (CPU быстрее) single-flow
    ~590 Мбит при qeli ≤ ~0.8 ядра = network/VM-bound. В обоих случаях рычаг — **больше
    ядер (ёмкий VM)**, а их уже используют существующие multi-queue + multipath; код для
    этого не нужен. Распараллеливание одного не-multipath потока = наивысший риск
    (nonce-uniqueness в горячем пути под `panic="abort"`) при near-нулевой выгоде
    (multipath уже закрывает single-user multi-core). **Рычаг = VM + аплинк, не код.** Закрыто.
11. 🔵 **Воспроизводимая сборка + бинари из git** — сейчас нативные ядра
    (`libqeli.so`/`.dylib`/`qeli.dll`) закоммичены для удобства клиентов. Перейти на
    публикацию через Releases + контрольные суммы + reproducible build; убрать блобы из дерева.

## Что НЕ будем делать

- OpenVPN-compat режим (слишком много legacy багажа).
- Свой Web UI на тяжёлом фронтенде (текущий axum + Alpine.js достаточен).
- Не-Linux серверы (TUN/TAP завязан на libc/ядро Linux).
