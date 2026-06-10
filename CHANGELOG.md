# Changelog

Заметные изменения qeli, обратно-хронологически. Версии — единые на все компоненты
(Rust-демон, клиенты Windows / macOS / Android). Бинарные артефакты публикуются во
вкладке **GitHub Releases** (в git не коммитятся — см. `.gitignore`).

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
