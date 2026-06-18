# qeli — план доводки до стабильного релиза (аудит 2026-06-06)

Источник: детальный аудит кодовой базы. Документ — рабочий чек-лист: каждый пункт
имеет ID, серьёзность, затронутые файлы, подход и критерий приёмки. Статусы
обновляются по мере выполнения.

Легенда статуса: ⬜ не начато · 🟦 в работе · ✅ сделано · 🧪 ждёт сборки/e2e на лабе.

---

## Сводная таблица

| ID | Серьёзность | Тема | Статус |
|----|:---:|---|:---:|
| F1 | 🟠 Bug | Backoff реконнекта не сбрасывается после успешной сессии (4 клиента) | ✅ |
| F2 | 🟠 Bug | Маска /24 захардкожена; сервер не пушит префикс подсети | ✅ |
| S1 | 🟡 Sec | Тайминг-оракул перечисления юзеров (argon2 только для существующих) | ✅ |
| S2 | 🟡 Sec | Нет отказа на all-zero X25519 shared secret (low-order point) | ✅ |
| S3 | 🟡 Sec | `recv_peek` может усечь ClientHello → ложный bridge легитимного клиента | ✅ |
| H1 | ⚪ Hyg | Случайный бинарь `qeli/local_copy/qeli` в дереве исходников | ✅ |
| H2 | ⚪ Hyg | ~250 одноразовых скриптов в `scripts/` | ✅ (154 → `scripts/archive/`) |
| B1 | 🔴 Blk | Нативные ядра клиентов (.so/.dll/.dylib) старше исходников realtls | ✅ пересобраны+разложены |
| B2 | 🔴 Blk | Артефакты в `release/` устарели относительно кодовой базы | ✅ (APK/exe/app/server; mac — ad-hoc, нотаризация в M3) |
| B3 | 🔴 Blk | Релизное дерево вне VCS (нет .git в рабочей копии) | ⬜ процесс (коммит/тег в канонный репо) |
| S4 | — | `ObfsUdp::recv` → `Ok(0)` на битом кадре | ✅ уже закрыто (`udp_handler.rs:99`) |

> **Текущий статус (2026-06-06): все code-фиксы (F1, F2, S1, S2, S3, E1–E5, H1, H2)
> внесены и собраны; нативные ядра и артефакты всех 4 клиентов + сервер пересобраны
> из свежего источника и разложены по штатным папкам; e2e на лабе (.10↔.11,
> tcp/obfs/udp) — PASS, 0% loss. Открыто: B3 (VCS-тег) и бэклог-харднинг (вкл.
> mac-нотаризацию M3).**

---

## Порядок выполнения (батч: сначала ВСЕ фиксы, потом ОДНА сборка)

Принцип: правки исходников не перемежаются сборками. Все code-фиксы вносятся
сначала; затем — единая фаза сборки/тестов/e2e в конце.

**A. Фикс-фаза (исходники, без промежуточных сборок) — ✅ ЗАКРЫТА:**
- Раунд-1: F1, F2, S1, S2, S3, H1, H2 — ✅ внесены (Rust-часть прогнана гейтом).
- Раунд-2: E1, E2, E3, E4, E5 — ✅ внесены (E6 опровергнут). Клиентский код F1/F2/E1/E2 — внесён.

**B. Сборка-фаза (ОДИН прогон) — ✅ ВЫПОЛНЕНА:**
1. Rust-гейт `lab_sync_build.py` — ✅ PASS (168 тестов, clippy 0).
2. **B1** — клиентские сборки: Android Kotlin compile + `assembleDebug` ✅ / Windows `dotnet` 0/0 ✅ /
   macOS `dotnet` 0/0 ✅; нативные ядра cdylib пересобраны из свежего `realtls` и переразложены ✅.
3. **B2** — `release/qeli-linux-amd64` + APK + Windows exe + mac `Qeli.app` из свежего источника ✅.
4. e2e на лабе — ✅ PASS (.10↔.11, tcp/obfs/udp, 0% loss — см. «e2e на лабе»).

**C. Процесс:** B3 (тег под VCS с актуальными артефактами) — ⬜ осталось.

Смысл батча: каждая правка в Kotlin/C# **не** требовала своей сборки — все клиентские
изменения накопились и скомпилированы один раз в фазе B (сборка клиента = и
валидация, и готовый артефакт). Подробности результата — раздел «Фаза B (сборка)».

---

## F1 — Сброс backoff реконнекта после установленной сессии

**Проблема.** Счётчик попыток инкрементируется и после успешно установленного
туннеля, и никогда не обнуляется. Долгоживущий линк, оборвавшийся (роуминг),
реконнектится с экспоненциальной задержкой, растущей от обрыва к обрыву до
`max_delay`. Системно во всех 4 клиентах.

**Подход.** Считать счётчик *числом подряд идущих неудач*. Обнулять его, как
только сессия установлена (auth OK / соединение вернулось без ошибки коннекта).
Формулу backoff не трогаем — меняется только сброс.

**Файлы и точки:**
- Rust: `qeli/src/client/mod.rs` — `run_client`, `retry_count` (`:68`, инкремент `:91`). Сбрасывать `retry_count = 0` при `result.is_ok()`.
- Android: `qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt` — `connectWithRetry` (`:219`), `attempt` (`:240/:256`). Сбрасывать `attempt = 0` после `runVpnConnection` (сессия установлена).
- Windows: `qeli-win/QeliWin/Vpn/VpnTunnel.cs` — `ConnectWithRetry` (`:113/:134`). Сбрасывать `attempt = 0` когда `_wasConnected` (сессия была установлена).
- macOS: `qeli-mac/QeliMac/Vpn/VpnTunnel.cs` — `ConnectWithRetry` (`:110/:131`). Аналогично win.

**Приёмка.** Healthy-сессия → обрыв → первый реконнект без эскалации; только
подряд идущие неудачи коннекта наращивают задержку. Unit/смоук на Rust;
ручной — на клиентах при сборке.

---

## F2 — Сервер пушит префикс подсети; клиенты применяют его

**Проблема.** Все клиенты задают маску `255.255.255.0` (Rust `:868`, win
`NetworkConfigurator.cs:99`, mac `:58`, Android `addAddress(ip,24)`). Сервер
поддерживает любой CIDR пула (`pool.rs`, до /30), но в `OK:{…}` префикс не
передаётся → не-/24 пул ломает on-link маршрутизацию client↔client.

**Подход (аддитивный, не ломающий).** Сервер кладёт в auth-OK поле `prefix`
(длина префикса пула, int). Клиенты применяют его (default 24, если поля нет —
совместимость со старым сервером; старый клиент игнорирует поле).

**Файлы и точки:**
- Сервер: `qeli/src/server/handler.rs` — `build_auth_ok` (`:749`). Вычислить
  prefix из `pcfg.pool.cidr` (через `pool::parse_cidr`), добавить `"prefix"` в JSON.
- Rust client: `qeli/src/client/mod.rs` — `AuthOk` (+`prefix:u8`), `parse_auth_ok`
  (`:812`, default 24), `setup_tunnel` (`:850`) — заменить хардкод на
  `prefix_to_netmask(prefix)`; добавить хелпер `prefix_to_netmask`.
- Android: `QeliService.kt` — `Session`/`parseOk` (`:336`) добавить `prefix`
  (`optInt("prefix",24)`); `addAddress(clientIp, prefix)` (`:460`).
- Windows: `VpnTunnel.cs` — `Session` (+`Prefix`), `ParseOk` (`:433`),
  `SetAddress` принимает prefix → dotted mask (`NetworkConfigurator.cs:99`).
- macOS: `VpnTunnel.cs` + `NetworkConfigurator.cs:58` аналогично.

**Приёмка.** Пул /24 работает как раньше; пул не-/24 (напр. /23) → клиент
получает верную маску. Unit на `prefix_to_netmask` + парс `prefix`.

---

## S1 — Устранить тайминг-оракул перечисления пользователей

**Проблема.** `verify_client_auth` (`qeli/src/server/handler.rs:650`): для
несуществующего юзера возврат до Argon2; для существующего — дорогой Argon2 →
тайминг выдаёт валидность имени.

**Подход.** Для неизвестного юзера прогонять argon2-верификацию по фиксированному
фиктивному хэшу (выровнять работу), затем всё равно вернуть ошибку. Результат
сравнения игнорируется.

**Файл.** `qeli/src/server/handler.rs` — ветка `None` в `db.find_user`.

**Приёмка.** Время ответа на неизвестного юзера ≈ времени на верный-юзер-неверный-пароль.

---

## S2 — Отвергать вырожденный X25519 shared secret

**Проблема.** `exchange.rs::derive_shared` (`:29`, `:95`) принимает любой
peer-pubkey, включая low-order точки (общий секрет = все нули).

**Подход.** После DH проверять, что результат не all-zero, constant-time
(`subtle`). Вернуть ошибку/пустой результат на вырожденный вход. Поскольку
`derive_shared` сейчас возвращает `SharedSecret` (не Result), добавить
проверяемый вариант либо проверять в местах рукопожатия. Минимально-инвазивно:
добавить `derive_shared_checked() -> Option<SharedSecret>` и использовать его в
обоих рукопожатиях (server/client), оставив `derive_shared` для внутренних мест.

**Файлы.** `qeli/src/crypto/exchange.rs`; точки рукопожатия в
`server/handler.rs`, `client/mod.rs`, `server/udp_handler.rs`.

**Приёмка.** Unit: low-order/identity pubkey → отказ. Обычный обмен — без регресса.

---

## S3 — Робастный `recv_peek` (REALITY-детект)

**Проблема.** `server/reality.rs::recv_peek` (`:250`): ClientHello из множества
мелких сегментов может исчерпать 40 итераций (с `continue` при росте без сна) →
усечённый peek → токен не парсится → легитимный клиент уходит на decoy.

**Подход.** Заменить бюджет «по числу итераций» на бюджет «по времени» (общий
дедлайн через `tokio::time::timeout`/`Instant`), со сном на каждой не-растущей
итерации; либо короткий sleep на каждой итерации независимо от роста. Сохранить
существующий внешний `timeout(1000ms)`.

**Файл.** `qeli/src/server/reality.rs`.

**Приёмка.** Многосегментный медленный ClientHello внутри окна таймаута
собирается полностью; нет ложного bridge. Unit (in-memory сегментированный поток).

---

## H1 — Удалить случайный бинарь из дерева

`qeli/local_copy/qeli` (≈2.5 МБ) — не build-каталог, не в `.gitignore`. Удалить.
**Приёмка.** Файла нет; сборка/инструменты не ссылаются на него.

---

## H2 — Разобрать `scripts/`

~250 одноразовых скриптов. Вынести поддерживаемые (`lab_sync_build.py`,
`ci-check.sh`, `add-client.sh`, deploy-*, lab*.py) — оставить в `scripts/`;
остальное (`check-*`, `debug-*`, `fix-*`, `bench_v*`, `reconnect_*`, probe_* …)
переместить в `scripts/archive/`. Не удалять — заархивировать.
**Приёмка.** Корень `scripts/` содержит только живой инструментарий.

---

## B1 — Пересобрать нативные ядра клиентов (лаба) — ✅ ВЫПОЛНЕНО

> Результат — раздел «Фаза B (сборка)» ниже: все 4 ядра пересобраны из свежего
> `realtls` (Win dll/.10, Android .so×2/.11, mac dylib/.10) и разложены в потребители
> + `native-libs/`. Критерий приёмки (ядро ≥ последнего изменения realtls) выполнен.

Бандлованные `libqeli.so`/`qeli.dll`/`libqeli.dylib` собраны 06-06 15:14–15:38,
исходники realtls правились до 19:36 → клиенты несут старое ядро. После Фазы 1
пересобрать cdylib из текущего источника и переразложить:
- Android: cargo-ndk на .11 (arm64-v8a + x86_64) → `qeli-android/app/src/main/jniLibs/`.
- Windows: `x86_64-pc-windows-gnu` + mingw на .10 → `qeli-win/QeliWin/native/qeli.dll`.
- macOS: cargo-zigbuild universal2 на .10 → `qeli-mac/QeliMac/native/libqeli.dylib`.
Затем пересобрать APK / exe / app.
**Приёмка.** mtime/хеш каждого ядра ≥ последнего изменения `qeli/src/protocol/realtls/**`.
Желательно: CI-проверка «хеш ядра соответствует источнику».

---

## B2 — Пересобрать релизные артефакты (лаба) — ✅ ВЫПОЛНЕНО (кроме mac-нотаризации)

> Результат — раздел «Фаза B (сборка)»: `release/qeli-linux-amd64`, `release/qeli.apk`
> (+`qeli-android/dist/`), Windows `qeli-win/dist/QeliWin.exe`, macOS
> `qeli-mac/dist/Qeli.app`+zip — все из свежего источника. mac подписан ad-hoc;
> нотаризация (Developer ID) — бэклог M3.

`release/qeli-linux-amd64` (06-03) и `release/qeli.apk` (05-31) устарели.
После Фазы 1 + B1: `cargo build --release` (Linux сервер), свежий APK, exe, app
→ заменить в `release/`. Прогнать `scripts/lab_sync_build.py` (build+test+clippy+e2e).
**Приёмка.** Все артефакты собраны из текущего источника; e2e-гейт зелёный.

---

## B3 — Релиз из VCS

Рабочая копия здесь не под git. Убедиться, что правки синхронизированы в канонный
репозиторий (`/opt/qeli-src` на .10), закоммичены, и релиз режется из тега с
включёнными свежими артефактами B1/B2.
**Приёмка.** Тег релиза существует; дерево чистое; артефакты в теге актуальны.

---

## Внешний аудит (второй источник) — разбор (2026-06-06)

Получен второй аудит из стороннего источника. **Проверен по исходникам, не принят
на веру.** Вывод: он **точен по at-rest хранению секретов клиентов и Android IPv6**
(ценные новые находки — в план ниже), но содержит **существенные ошибки по
серверу/вебу/крипто** (опровергнуты по коду). Берём только подтверждённое.

### ✅ Подтверждено по коду — добавлено в план

| ID | Внешн. | Что (с привязкой) | Реальная severity | Подход |
|----|--------|---|:---:|---|
| **E1** | A1/WN1/M1/X1 | Секреты клиентов в plaintext: Android `MainActivity.kt:229/267` (`SharedPreferences`, нет `EncryptedSharedPreferences`); Windows `ProfileStore.cs:29`/`ServiceState.cs:39` (JSON, нет DPAPI); macOS `ProfileStore.cs:28`/`AppSettings.cs:40` (JSON, нет Keychain). Пароль/obfs_key/pubkey на диске открыто. | HIGH (at-rest; root/forensic/мульти-юзер) | Android `EncryptedSharedPreferences`+Keystore; Windows `ProtectedData`(CurrentUser DPAPI) или Credential Manager; macOS Keychain или `NSFileProtectionComplete`. Общий интерфейс `SecureStore`. |
| **E2** | A4 | IPv6-leak в full-tunnel: Android `QeliService.kt:497` (только `AF_INET`); Windows/macOS — full-tunnel маршрутизировал лишь IPv4 (`0.0.0.0/1`+`128.0.0.0/1`/`-inet`). IPv6 уходит мимо туннеля на dual-stack. | HIGH | full-tunnel: заворот `::/1`+`8000::/1` (+ULA) в туннель — Android `addRoute("::",0)`+`allowFamily(AF_INET6)`; Win/mac `NetworkConfigurator.CaptureIPv6()`. IPv4-only сервер блэкхолит. **Все 3 клиента.** |
| **E3** | S2 | `mode=obfs` + пустой `obfs_key`: TCP-сервер (`mod.rs:1204`) деривит **публично вычислимый** константный ключ; UDP (`udp_handler.rs`) тихо отключает obfs. Под обфускацией всё равно X25519+ChaCha20+Argon2 → не пробой auth, а деградация DPI-стойкости. | MED (мисконфиг) | `validate_profiles`: `bail` при `mode=obfs && obfs_key.is_empty()` (оба транспорта); клиент — то же. |
| **E4** | W1 + auth | Веб-панель по HTTP без TLS (`web/mod.rs:94`) и **открыта при пустом** `password_hash` (`auth.rs:27`). Дефолт `bind=127.0.0.1` (НЕ 0.0.0.0 — см. ниже), поэтому критично лишь при публичном bind. | MED (зависит от bind) | startup-warn при `web.bind` ≠ loopback (особенно с пустым паролем); док: публичный доступ — только за TLS-reverse-proxy/SSH-туннелем. |
| **E5** | C3 | Нет `cargo audit`/`cargo deny` в CI (только functional-тесты). | LOW (гигиена) | advisory-джоба в `ci.yml`. |

### 🟧 Бэклог-харднинг — статус раунда 2026-06-07

**✅ Сделано:**
- **A5** — смена ключа сервера = security-событие: Win/mac `catch (SecurityException)` →
  НЕ ретраят + явное предупреждение «идентичность изменилась, возможна MITM, стоп»;
  Android это уже делал (mismatch→SecurityException→stop). Win/mac `dotnet` 0/0.
- **S1-cfg** — new-session `RateLimiter` конфигурируем: `perf.connection.new_session_rate_max`
  (деф 10) / `new_session_rate_window_secs` (деф 60); было хардкод 10/60. Гейт PASS.
- **X2** — явный блок «как выбрать wire-режим» в `CONFIG.md` (fake-tls=D1/D2;
  reality-tls=D3 явно; obfs=энтропийный DPI; plain=доверенные сети).
- **A6 (Android)** — настоящий kill-switch = системный «Always-on VPN + block
  connections without VPN» (Настройки→VPN). Наш `VpnService` совместим — работает
  без доп. кода; пользователю достаточно включить тумблер.

**⛔ Заблокировано объективными причинами (не делаем вслепую):**
- **WN5** (BouncyCastle→native) — полное удаление невозможно: в .NET 8 **нет нативного
  X25519** (BCL нужен именно ради `Rfc7748.X25519`). Миграция на .NET 9 отвергнута
  (STS — EOL раньше .NET 8; и нативный X25519 в 9/10 под вопросом). **НО реальная
  претензия аудита — timing-CVE-2024-30171 на X25519 в BC 2.4.0 — ЗАКРЫТА бампом
  `BouncyCastle.Cryptography 2.4.0 → 2.5.1`** (win+mac, без смены рантайма; API
  совместим, сборки 0/0). То есть безопасная суть WN5 выполнена.
- **WN3** (служба не-`LocalSystem`) — Wintun создаёт адаптер+маршруты → нужен **SYSTEM**
  (сам WireGuard-сервис под SYSTEM). `LocalService` сломает VPN. Нужен Windows-стенд.
- **WN4** (автозапуск) — GUI `requireAdministrator`: Run-key → **UAC каждый логон**
  (хуже); подпись Scheduled Task → нужен **Windows code-signing сертификат** (нет —
  отдельная закупка, как M3). Текущий Scheduled Task `/RL HIGHEST` уже оптимален.
- **A6 (десктоп Win/mac)** — firewall-kill-switch (WFP/pf): нельзя шиппить
  непротестированным (баг очистки правил = пользователь без сети без recovery).
  Безопасный дизайн — WFP **dynamic-session** (авто-очистка при выходе процесса) /
  pf-anchor; требует Windows/macOS-стенда для прогона.

**⏸️ Проговариваем отдельно (по просьбе):** A3 (биометрия), M2 (NetworkExtension),
M3 (mac Developer-ID + нотаризация). Сюда же по сути относятся WN3/WN4/WN5 —
им нужны сертификат / .NET 9 / Windows-стенд.

### ❌ Не подтверждено / неточно (разобрано по коду — в работу НЕ берём)

| Внешн. | Утверждение | Факт по коду |
|--------|---|---|
| **S3** | control-socket на `0.0.0.0`, любой юзер хоста зовёт kick/ban | `control.rs:8,51,55` — **Unix-сокет** `/var/run/qeli/control.sock`, права **0600** (только root). Неверно. |
| **W2** | `PUT /api/config` без валидации = RCE для low-priv админа | `config.rs:42-69` — полная десериализация в `ServerConfig` + path-whitelist (`logging.file`/`users_file`) + `check_auth`. Роли low-priv нет; смена конфига — функция админа. Неверно. |
| **W4** | `/api/logs` без auth, Bearer-token в URL | `logs.rs:28` — `check_auth` + path-whitelist (`ALLOWED_LOG_DIRS`). Bearer-пути нет. Неверно. |
| **W1** | дефолт bind `0.0.0.0:8080` | `config/server.rs:441` `default_web_bind()="127.0.0.1"`. Дефолт — localhost; severity снижена (см. E4). |
| **S1** | конфиг `auth.brute_force` игнорируется, хардкод 10/60 | Lockout = `FailedAuthTracker`, строится из `auth.brute_force.{max_attempts,window,lockout}` (`mod.rs` run_worker). 10/60 — отдельный new-session `RateLimiter`. Неверно по сути; мелочь → бэклог. |
| **C1** | `chacha20poly1305 = "0.5"` без zeroize → ключ не зануляется | В `Cargo.toml` — `"0.10"` (версия неверна). И 0.10 зависит от `zeroize` **неопционально** → ключ зануляется в `Drop` **всегда** (feature-флага нет — попытка добавить `features=["zeroize"]` ломает сборку). Комментарий `cipher.rs` был корректен. Неверно по сути. |
| **C3** | «CVE-2025-XXX ring JIT-bug» | у `ring` нет JIT; номер CVE — плейсхолдер. Фабрикация. (Рекомендация `cargo-audit` оставлена → E5.) |
| **Tell 1.3** | fake-tls без `x25519mlkem768` | `tls.rs build_supported_groups`/`build_key_share` шлют `0x11ec` **первым** (1216 Б). `DPI-AUDIT.md` 1.3 = ✅. Неверно. |
| **A2** | пароль через `Intent.putExtra` | extra с паролём не найден; сервис читает профиль из хранилища (→ это E1, не Intent). Не подтверждено. |
| **C2** | нет «PAKE-связывания» при ротации профиля | В qeli нет PAKE; ключи сессии всегда выводятся из свежего handshake-transcript. Путаница, не баг. |
| **DPI 1.x/2.x** | теллы fake-tls (ALPN/ext/nonce/size) | Точно, но **уже** в `docs/DPI-AUDIT.md` со статусами; закрывается режимом `reality-tls`. Не ново. |

## Сводная таблица — раунд 2 (внешний аудит)

| ID | Серьёзность | Тема | Статус |
|----|:---:|---|:---:|
| E1 | 🟠 HIGH | Секреты клиентов в plaintext (Android/Win/Mac) | ✅ внесено + собрано (3 клиента) |
| E2 | 🟠 HIGH | IPv6-leak в full-tunnel (Android+Windows+macOS) | ✅ все 3 клиента (заворот IPv6 в туннель) |
| E3 | 🟡 MED | `obfs` + пустой `obfs_key` (валидация конфига) | ✅ |
| E4 | 🟡 MED | Web: warn при публичном bind + пустом пароле; док TLS-proxy | ✅ (warn; док — в этом разделе) |
| E5 | ⚪ LOW | `cargo audit`/`deny` в CI | ✅ |
| E6 | — | chacha zeroize | ❌ опровергнуто — 0.10 зануляет ключ всегда (нет feature; claim неверен). Комментарий уточнён. |

## Фаза B (сборка) — прогресс

Локально доступны dotnet 8.0.421 + Android SDK (`C:\Android\Sdk`), поэтому часть B1
выполнена прямо здесь:
- **Windows-клиент** (`dotnet build -c Release`) — **0 ошибок / 0 предупреждений**. Валидирует F1/F2/E1 (Windows), пакет `System.Security.Cryptography.ProtectedData` подтянулся.
  - 🐞 Сборка поймала баг: F2 добавил дубль `PrefixToMask` в `NetworkConfigurator.cs` (метод уже был для `AddRoute`). Дубль удалён, `SetAddress` зовёт существующий.
- **macOS-клиент** (`dotnet build -c Release`, TFM `net8.0`) — **0 / 0** (после guard'а `!OperatingSystem.IsWindows()` вокруг `SetUnixFileMode`). Валидирует F1/F2/E1 (macOS, `SecureKey`/AES-GCM).
- **Android** — `gradlew :app:compileDebugKotlin` — **BUILD SUCCESSFUL** (23s). Валидирует F1/F2/E1/E2 (Kotlin), зависимость `androidx.security:security-crypto` разрешилась.

**Итог компиляц. валидации (батч-сборка):** все компоненты собираются чисто — Rust-ядро
(гейт, 168 тестов) + 3 клиента (Win 0/0, mac 0/0, Android Kotlin OK). Все правки
раундов 1–2 (F1, F2, S1, S2, S3, E1, E2, E3, E4, E5) скомпилированы.

**B1 — нативные ядра пересобраны из свежего `realtls` и положены в дерево (✅):**
- Windows `qeli.dll` — .10 (mingw, `x86_64-pc-windows-gnu`), 3.72 МБ, 6 FFI-символов → `qeli-win/QeliWin/native/qeli.dll`.
- Android `libqeli.so` — .11 (cargo-ndk, NDK 26.3), arm64-v8a 567КБ + x86_64 658КБ, 7 JNI + 6 FFI → `qeli-android/.../jniLibs/`.
- macOS `libqeli.dylib` — .10 (`cargo-zigbuild` + zig 0.13, universal2 x86_64+arm64), 8.83 МБ → `qeli-mac/QeliMac/native/libqeli.dylib`. (zigbuild на .10 ЕСТЬ — ранний probe промахнулся мимо `~/.cargo/bin`.)

**B2 — артефакты собраны (✅, включая mac .app):**
- `release/qeli-linux-amd64` — сервер, 5.95 МБ, из свежей gate-сборки.
- `release/qeli.apk` — 17.13 МБ, упакованы оба свежих `.so` + правки F1/F2/E1/E2 (`assembleDebug` локально, Android SDK).
- Windows exe — `dotnet publish -c Release -r win-x64`, 190 КБ, свежая `qeli.dll` вшита EmbeddedResource (`qeli-win/.../publish/QeliWin.exe`).

**Раскладка по штатным папкам (2026-06-06):**
- Нативные ядра — и в потребителях (`qeli-android/.../jniLibs`, `qeli-win/QeliWin/native`,
  `qeli-mac/QeliMac/native`), и в централизованной копилке `native-libs/`
  (`android/{arm64-v8a,x86_64}/libqeli.so` — папка создана; `windows-x64/qeli.dll`,
  `macos-universal/libqeli.dylib` — обновлены, старые копии заменены).
- Android APK → `qeli-android/dist/app-debug.apk` (17.96 МБ, прошлый ротирован в `app-debug.prev.apk`) И `release/qeli.apk`. `release/qeli-linux-amd64` (5.95 МБ) — сервер.
- Windows-приложение → `qeli-win/dist/` (`QeliWin.exe` + framework-dependent publish, 41 файл).
- macOS `qeli-mac/dist/Qeli.app` — ✅ **ПЕРЕСОБРАН** (universal, свежий C# E1/F1/F2 + свежий
  dylib) + `Qeli-macOS-universal.zip` (56 МБ). Флоу «без Mac»: `dotnet publish
  osx-arm64+osx-x64 --self-contained` (локально) → `llvm-lipo` слияние всех Mach-O в
  universal на .10 → `rcodesign` ad-hoc подпись → zip. Скрипт `scripts/build_mac_universal.py`.
  Проверено: apphost + libqeli.dylib + Skia/HarfBuzz/Avalonia + 15 рантайм-натив = universal (2 арх).

**Остаток (не блокирует фиксы):**
- **mac нотаризация** — `Qeli.app` подписан **ad-hoc**; Developer ID + notarytool — отдельный M3.
- **e2e на лабе** — реконнект без эскалации (F1), не-/24 пул (F2), обычные режимы (регресс). Нужна оркестрация эмулятор(.11)↔сервер(.10) + тест-профиль/креды на .10.

## Журнал выполнения

- 2026-06-07: **WN5 (безопасная часть) — бамп `BouncyCastle.Cryptography 2.4.0 → 2.5.1`**
  в qeli-win + qeli-mac (закрывает timing-CVE-2024-30171 на X25519, без миграции
  рантайма). API совместим, сборки 0/0, dist переупакованы (exe + mac `.app`).
  Сервер (Rust) BouncyCastle не использует → прод не затронут.
- 2026-06-07: **Бэклог-харднинг, раунд 1.** Сделано: **A5** (Win/mac не ретраят смену
  ключа сервера + security-warning; Android уже был), **S1-cfg** (конфигурируемый
  new-session rate limiter, гейт PASS), **X2** (гайд выбора wire-режима в CONFIG.md),
  **A6-Android** (kill-switch через системный always-on/lockdown — работает без кода,
  задокументировано). Заблокировано объективно: **WN5** (нет нативного X25519 в .NET 8),
  **WN3** (Wintun требует SYSTEM), **WN4** (admin-app: Run-key хуже, подпись нужен cert),
  **A6-десктоп** (firewall kill-switch нельзя без стенда — риск lock-out). См. раздел
  «Бэклог-харднинг — статус». S1-cfg — аддитивно (деф 10/60 = прежнее), прод не требует
  передеплоя.
- 2026-06-07: **Прод-деплой свежего серверного бинаря (YOUR_PROD_HOST).** Бэкап
  (`/root/backup/qeli-deploy/20260607-002649/` + `/root/qeli-rollback.bin`, старый
  2.0.0/`5fe1cadf`) → pre-flight (новый бинарь `0.5.6`/`ba1675ac` запускается на
  прод-glibc 2.41, парсит конфиг, identity `7ff1c274` цел, E3 ок — все obfs-профили
  с ключом) → swap `/usr/local/bin/qeli` → `systemctl restart qeli`. Версия 2.0.0→0.5.6
  (унификация; код новее, wire совместим — F2 аддитивен). Проверка: 7 профилей up
  (4 TCP+3 UDP), 0 ошибок/паник, identity цел, **живой e2e .11→прод faketls:8443
  (client1) → Auth OK, IP 10.9.1.2, ping 0%/37мс**. Конфиг не трогал. Откат наготове.
- 2026-06-07: **Серия E добита (полное покрытие).**
  - **E2-desktop** — IPv6-leak закрыт и в **Windows** и **macOS** (раньше только Android):
    `NetworkConfigurator.CaptureIPv6()` в full-tunnel заворачивает `::/1`+`8000::/1` в туннель
    (ULA на адаптер; IPv4-only сервер блэкхолит → нет утечки). Все вызовы `optional`/best-effort.
  - **E3-клиенты** — гард пустого `obfs_key` добавлен в Android (TCP+UDP), Windows (TCP+UDP),
    macOS (TCP+UDP) — симметрично Rust-клиенту и серверной `validate_profiles`.
  - **E1-AppSettings** — проверено: `AppSettings.cs` (Win/mac) секретов НЕ содержит (язык/тема/
    автозапуск/имена профилей) → шифрование не требуется; claim WN2 «CRIT» преувеличен. Реальные
    секреты (профили) уже шифруются в ProfileStore/ServiceState.
  - Сборка: Win `dotnet` 0/0, mac `dotnet` 0/0, Android `assembleDebug` SUCCESS. Артефакты
    переупакованы (exe, APK; mac `.app` пересобран — dylib не менялся, переиспользован).
- 2026-06-06: **Фаза B завершена + e2e PASS.** Нативные ядра ×4 пересобраны из свежего
  realtls (Win dll/.10, Android .so×2/.11, mac dylib/.10) и разложены (потребители +
  `native-libs/`). Артефакты: `release/qeli-linux-amd64`, APK (`qeli-android/dist/` +
  `release/`), Windows `qeli-win/dist/`, macOS `qeli-mac/dist/Qeli.app`+zip (universal,
  ad-hoc) — скрипт `scripts/build_mac_universal.py`. e2e на лабе (.10↔.11) tcp/obfs/udp —
  0% loss, throughput в норме. Лаб-сервис восстановлен (active). Открыто: B3 + бэклог.
- 2026-06-06: документ создан по результатам аудита. Начато выполнение Фазы 1.
- 2026-06-06: **Фикс-фаза ЗАКРЫТА — E2 и E1 внесены (батч, без промежуточных сборок).**
  - **E2** — Android `QeliService.kt` setupTunInterface: в full-tunnel заворот IPv6
    (`addAddress("fd00:71e1::1",128)` + `addRoute("::",0)` + `allowFamily(AF_INET6)`),
    сервер IPv4-only → IPv6 дропается, не утекает.
  - **E1** — шифрование at-rest на всех 3 клиентах (+миграция legacy plaintext):
    Android `EncryptedSharedPreferences` (master-key в Keystore, store `vpn_secure`,
    legacy `vpn` стирается); Windows `ProfileStore` DPAPI CurrentUser + `ServiceState`
    DPAPI LocalMachine (UI↔service кросс-юзер); macOS AES-256-GCM с ключом из Keychain
    (`security` CLI, `SecureKey.cs`) + 0600-fallback. Новые зависимости:
    `androidx.security:security-crypto`, `System.Security.Cryptography.ProtectedData`.
    ⚠️ (на тот момент) клиентские правки F1/F2/E1/E2 ещё не собирались — **с тех пор собраны
    в фазе B**, все 3 клиента компилируются, артефакты пересобраны (см. «Фаза B»).
- 2026-06-06: **Раунд-2 (внешний аудит), серверные/Rust-правки реализованы + гейт PASS**
  (build OK · **168 тестов / 0 failed**, +`obfs_wire_mode_requires_obfs_key`/`_with_key_is_allowed` · clippy 0):
  E3 (валидация непустого obfs_key: `validate_profiles` + клиент TCP/UDP),
  E4 (web warn при non-loopback bind + пустой пароль), E5 (`cargo audit` advisory-джоба в CI).
  E6 **опровергнут** (chacha 0.10 зануляет ключ всегда; попытка добавить feature ломала
  сборку — откатан, комментарий `cipher.rs` уточнён). Осталось из раунда-2: E1, E2 (клиенты).
- 2026-06-06: **Разобран внешний аудит (второй источник)** — см. раздел выше.
  Подтверждённое (E1–E6) добавлено в план; ошибочные/неточные claim'ы (S3, W2, W4,
  W1-default, C1-версия, C3-CVE, Tell 1.3, A2, C2) опровергнуты по коду. Ценность
  внешнего аудита — at-rest хранение секретов клиентов (E1) и Android IPv6 (E2).
- 2026-06-06: **Фаза 1 завершена в исходниках** (требуется сборка/тесты на лабе):
  - **F1** — сброс backoff после установленной сессии: Rust `client/mod.rs`
    (`retry_count=0` при `Ok`); Android `QeliService.kt` (`attempt=0` при
    `liveStatus==CONNECTED`, оба пути); Win/Mac `VpnTunnel.cs` (сброс по
    `_wasConnected`, оба пути).
  - **F2** — сервер пушит `prefix` (`handler.rs::build_auth_ok` из `pool.cidr`);
    применяют: Rust (`AuthOk.prefix` + `prefix_to_netmask` + `setup_tunnel`),
    Android (`addAddress(ip, prefix)`), Win/Mac (`Session.Prefix` +
    `NetworkConfigurator.SetAddress(prefix)` → dotted mask). Default /24.
    Добавлены unit-тесты (`prefix_to_netmask`, парс `prefix`).
  - **S1** — `handler.rs`: throwaway Argon2-верификация для unknown-user
    (`dummy_password_hash()`), время ответа выровнено.
  - **S2** — `exchange.rs::derive_shared_checked` (constant-time отказ на all-zero);
    подключён на ВСЕХ эфемерных DH (server TCP/UDP + client plain/fake-tls/udp).
    Статические-ключевые derive оставлены как есть (auth-proof). + unit-тесты.
  - **S3** — `reality.rs::recv_peek` переписан на бюджет по времени (deadline 900мс +
    stall 200мс, sleep 2мс) вместо 40 итераций. + регресс-тест на сегментированный поток.
  - **H1** — удалён `qeli/local_copy/qeli`.
  - **H2** — 154 одноразовых скрипта → `scripts/archive/` (+ README).
  - ⚠️ Rust-тулчейна на машине разработки нет → `cargo test`/`clippy` и сборки
    клиентов выполнить на лабе (Фаза 2). Правки прошли статическую самопроверку.

## Лабовый гейт — ✅ PASS (2026-06-06)

`scripts/lab_sync_build.py` (синк → `/opt/qeli-src` на .10). Финальный прогон (после E3):
- `cargo build --release` → **OK** (1m36s).
- `cargo test --all` → **OK, 168 passed / 0 failed** (было 161; +7: `recv_peek_reassembles_segmented_window`, `derive_shared_checked_rejects_low_order_point`, `derive_shared_checked_accepts_normal_exchange`, `prefix_to_netmask_known_values`, `parse_auth_ok_reads_prefix_with_default`, `obfs_wire_mode_requires_obfs_key`, `obfs_wire_mode_with_key_is_allowed`).
- `cargo clippy --all-targets -- -D warnings` → **OK** (0 warnings).
- `qeli-server.service` на .10 — `active`/`enabled` после прогона (лаба не оставлена лежащей).

Валидированы Rust-правки: F1(Rust), F2(сервер+Rust-клиент), S1, S2, S3. Правки в
Kotlin/C# клиентах гейтом НЕ покрыты — проверятся при сборке клиентов (B1).

## e2e на лабе — ✅ PASS (2026-06-06)

`scripts/sanity_e2e.py` (свежий release-бинарь на .10 сервер + .11 клиент, два хоста):
- **tcp-faketls** → `Auth OK`, ping **0% loss** (avg 2.0 мс), 562↑/717↓ Mbps.
- **tcp-obfs** (obfs_key=`benchkey`) → `Auth OK`, ping **0% loss**, 500↑/573↓ Mbps. (E3: непустой ключ → ок.)
- **udp-faketls** → `Auth OK`, ping **0% loss**, UDP-свип чисто до 400 Mbps (0.49%), насыщение на 500.

Подтверждает отсутствие регресса: туннели поднимаются и гонят трафик во всех режимах
со всеми правками (S2 DH-проверка не сломала рукопожатие; F2 prefix даёт корректную
адресацию; E3 obfs работает; throughput на уровне прежних бенчмарков). После прогона
`qeli-server.service` на .10 возвращён в `active` (порт 443 слушает). *(Починен сам
`sanity_e2e.py` — отстал от схемы `benchmark.run_mode`: `mode` → `client_mode`/`server_mode`.)*

Не покрыто точечно (требует bespoke-тестов, не блокеры): F1 (тайминг реконнекта при
многократных обрывах), F2 на не-/24 пуле, S2 с реально вредоносным low-order ключом.

## Осталось (открытые пункты)

Все code-фиксы, сборки и e2e-регресс закрыты (см. выше). Реально открыто:

1. **B3** — коммит в канонный репозиторий (`/opt/qeli-src` на .10) + тег релиза с
   актуальными артефактами.
2. **Бэклог-харднинг** (не блокеры релиза, отдельной волной): A3/A5/A6 (UI: биометрия,
   TOFU-warning, kill-switch), WN3/WN4/WN5 (служба/задача/BouncyCastle→native),
   M2 (NetworkExtension), **M3 (mac Developer-ID + нотаризация)**, S1-cfg (RateLimiter),
   X2 (`reality-tls` по умолчанию).
