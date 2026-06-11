# Changelog

Заметные изменения qeli, обратно-хронологически. Версии — единые на все компоненты
(Rust-демон, клиенты Windows / macOS / Android). Бинарные артефакты публикуются во
вкладке **GitHub Releases** (в git не коммитятся — см. `.gitignore`).

## [Unreleased]

## [0.7.0] — 2026-06-11

**Пост-квантовый внутренний туннель** + разбор внешнего аудита (2026-06-11) и фиксы
безопасности/надёжности. **⚠️ Ломающее изменение провода:** во всех режимах кроме
`plain` сервер теперь ТРЕБУЕТ гибридную X25519MLKEM768-долю в ClientHello — нужен
координированный деплой клиент↔сервер (старый клиент к новому серверу не подключится,
и наоборот). Полный трекер аудита (включая ложные срабатывания) —
[docs/AUDIT-2026-06-11.md](docs/AUDIT-2026-06-11.md).

### Пост-квантовая защита
- **Гибридный X25519 + ML-KEM-768 во внутреннем туннеле.** Ключи плоскости данных
  теперь выводятся из X25519 ⊕ ML-KEM-768 (`derive_keys_hybrid`, соль
  `qeli-key-derivation-v2-hybrid`, IKM `x25519‖mlkem` 64 Б) во всех не-`plain`
  режимах (`fake-tls`/`obfs`/`reality-tls`/UDP) — защита от «harvest-now-decrypt-later»
  независимо от обёртки. `plain` остаётся классическим X25519. Сервер отвергает
  не-`plain` клиента без X25519MLKEM768 key_share — **нет тихого PQ-даунгрейда**.
- **ML-KEM для managed-клиентов через нативное ядро.** BouncyCastle 2.6.2 не содержит
  ML-KEM, а `.NET MLKem` привязан к ОС → C#/Kotlin вызывают тот же вердифицированный
  Rust-крейт `ml-kem` по C-ABI / JNI (`qeli_mlkem_keygen/decapsulate/free`,
  `Java_com_qeli_MlKem_*`). Новые `Crypto/Mlkem.cs` и `com/qeli/MlKem.kt`,
  методы `BuildClientHelloPq` / `ParseServerHelloPq` / `DeriveKeysHybrid` во всех
  клиентах; нативные `qeli.dll` / `libqeli.dylib` / `libqeli.so` пересобраны.
- Проверено вживую на лабе: `tcp-faketls` / `tcp-obfs` / `udp-faketls` — гибридный
  handshake + трафик 570–700 Мбит/с TCP, 0 % потерь; Android APK и оба C#-клиента
  собираются, символы `qeli_mlkem_*` экспортированы.

### Безопасность
- **Lockout-DoS по username устранён (L1).** Жёсткий account-lockout (любой IP мог 5
  фейлами выбить чужой логин) заменён на **adaptive tarpit**: жёсткий лок остаётся
  только по source-IP, а username под активным перебором получает ограниченную сверху
  экспоненциальную задержку (200мс→×2, потолок 3с) перед Argon2. Верный пароль всегда
  проходит (в т.ч. с нового IP), распределённый перебор зарезан. `FailedAuthTracker`:
  `check()` → `check_ip()` + `user_tarpit()`; server-key-proof-фейл считается только по
  IP (`record_ip_failure`). Применено и в VPN-auth, и в веб-панели (форма + Basic).
- **Android: constant-time сравнение auth-proof (T1).** `MessageDigest.isEqual` вместо
  `ByteArray.contentEquals()` (Rust/C# уже были constant-time).

### Исправлено
- **TOCTOU на лимитах сессий (T7/T8).** `max_clients` теперь перепроверяется под тем же
  write-локом, что и вставка (с откатом IP при превышении); `max_streams` — атомарный
  `try_add_stream()` (проверка+push под одним локом). Параллельные connect/JOIN больше
  не проскакивают лимит.
- **Poisoned-lock не рушит живую сессию (T6).** Методы `SessionShared` переведены на
  `lock_or_recover` вместо тихой деградации (`unwrap_or(0)` / `Err→teardown`).
- **Утечка сокета при ошибке подключения (T10).** `OpenBondedStream`/`openBondedStream`
  (Win/Mac/Android) обёрнуты в try/catch — сокет закрывается и снимается с учёта при
  фейле connect/JOIN-handshake.
- **Гонка `DeviceId()` (T9, Win/Mac).** Static-кэш + lock — device-id вычисляется один
  раз на процесс, нет двойной генерации при старте bonded-потоков.

### Прочее
- **Портируемость `set_tcp_keepalive`** ([transport/tcp.rs](qeli/src/transport/tcp.rs)) —
  Linux-специфичные `TCP_KEEPIDLE/INTVL/CNT` теперь под `#[cfg(target_os = "linux")]`
  с no-op фолбэком для прочих таргетов (гигиена; крейт собирается под Linux/musl).
- **Единообразие poisoned-lock** — `reality_borrow` читается с recover-from-poison
  (как `lock_or_recover`/T6), а не `expect` (под `panic=abort` это moot, но
  паттерн единый).

### Проверено
- **Rust (.10, `lab_sync_build.py`):** `cargo build --release` OK · `cargo test --all`
  **188 passed / 0 failed** (вкл. новые L1-тесты `…_tarpits_user…`,
  `username_flood_never_hard_blocks_a_clean_ip`) · `clippy --all-targets -D warnings` 0 ·
  `cargo fmt --check` clean.
- **C# (`qeli-shared` + `qeli-win`, `dotnet build -c Release`):** 0 ошибок.
- **Android (.11):** `gradlew clean assembleDebug` BUILD SUCCESSFUL (40 tasks executed —
  T1/T10 перекомпилированы), APK v0.6.0.

## [0.6.0] — 2026-06-10 — релиз рефакторинга

Кодовая реорганизация, унификация и доводка визуала. **Протокол, крипто и провод не
менялись** — релиз сетево совместим с 0.5.6, замеры 0.5.6 остаются актуальными
([docs/BENCHMARK.md](docs/BENCHMARK.md)). Детали C#/Rust-правок —
[docs/REFACTOR-PLAN.md](docs/REFACTOR-PLAN.md).

### Добавлено
- **`qeli-shared`** — общая C#-библиотека (.NET 10) для клиентов Windows и macOS:
  крипто (X25519 / HKDF / ChaCha20-Poly1305), протокол (fake-TLS / obfs / QUIC /
  packet-codec), модель `VpnConfig`, ядро дата-плоскости `VpnTunnelBase` (за
  интерфейсом `ITunDevice`), `RealTls` (P/Invoke к realtls-ядру) и таблица
  локализации `Loc`. Устранено ~2700 строк, ранее дословно скопированных между
  двумя клиентами. Платформенная часть (Wintun ↔ utun, WPF ↔ Avalonia, DPAPI ↔
  AES-GCM) осталась в клиентах.
- **`scripts/lab_common.py`** — общий SSH-хелпер (хосты + `connect`/`run`),
  централизует обвязку, дублировавшуюся в ~100 лаб-скриптах.

### Изменено
- **.NET 10** — оба C#-клиента переведены на единый таргет (`net10.0` / `net10.0-windows`);
  версии общих NuGet сведены: BouncyCastle 2.6.2, QRCoder 1.8.0.
- **UI (`MainWindow`, win + mac)** — выровнены колонки: левый бренд-бэнд по высоте
  равен правой статус-карте, поиск и ряд плиток начинаются на одной линии, нижние
  края панелей «список профилей» и «журнал» совпадают, единый ритм отступов 14px.
- **Rust web-API** — форма ответов сведена к хелперам `err_json` / `ok_json`;
  авторизация защищённых ручек — через axum-extractor `AuthGuard` вместо ручного
  `check_auth(&headers, …)` в каждой (auth-проверка на тип-уровне, нельзя «забыть»).
- **Версии → `0.6.0`** на всех компонентах; Android `versionCode = 600`.

### Проверено
- C#-клиенты: `dotnet build -c Release` — 0 ошибок; mac `MainWindow` отрендерён
  (Avalonia headless, светлая + тёмная темы) — вёрстка симметрична.
- Rust: лаб-гейт `scripts/lab_sync_build.py` на сервере — `cargo build` /
  **179 юнит-тестов** / `cargo clippy --all-targets -- -D warnings` — всё зелёное.

## [0.5.6] — 2026-06-06

Унификация версий на все компоненты; полный бенчмарк 10 wire-режимов (вкл. `plain` и
`reality-tls`); cert-borrowing в `reality-tls` (паритет JA3S/цепочки с Xray-REALITY);
NewSessionTicket; раунд хардненинга. См. [docs/ROADMAP.md](docs/ROADMAP.md) и
[docs/RELEASE-FIXES.md](docs/RELEASE-FIXES.md).

[0.6.0]: https://github.com/litvinovtd/qeli/releases/tag/v0.6.0
[0.5.6]: https://github.com/litvinovtd/qeli/releases/tag/v0.5.6
