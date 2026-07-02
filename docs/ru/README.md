# Qeli — обфусцированный VPN 

**Qeli** (Quick Easy Link IP) — self-host VPN с собственным L4-протоколом и
встроенной обфускацией, поверх TCP или UDP. Цель — устойчивость к пассивному/
сигнатурному DPI при удобстве классических TUN/TAP-VPN, со встроенной веб-админкой.

- **Язык**: Rust 2021, версия 0.7.6 (бета)
- **Криптостек**: `x25519-dalek`, `ml-kem` (PQ-гибрид X25519MLKEM768), `chacha20poly1305`, `chacha20`, `aes-gcm`, `hkdf`, `sha2`, `argon2`, `zeroize`; `rustls`/`ring` — серверная терминация настоящего TLS 1.3 в `reality-tls`
- **Транспорт**: TCP или UDP; несколько профилей (интерфейсов) в одном демоне
- **Wire-режимы**: `plain` (без обфускации — голый шифрованный туннель, TCP) · `fake-tls` (мимикрия под TLS 1.3) · `obfs` (ChaCha20 stream + WS-fronting) · `reality` (проксирование чужих хендшейков на реальный сайт) · `reality-tls` (настоящий TLS 1.3 несёт туннель; `handrolled` одалживает реальный серт target'а — cert-borrowing, паритет с Xray-REALITY) · QUIC-masking для UDP
- **TUN/TAP**: Linux only (`libc::ioctl(TUNSETIFF)`)
- **Веб-админка**: `axum` + `alpine.js`; встроенный HTTPS (rustls, self-signed или свой серт), пароль Argon2id (fail-closed), IP-allowlist, security-заголовки/HSTS, same-origin CSRF, RU/EN-локализация, выдача `qeli://`-ссылок/QR без ввода пароля; ассеты встроены (без CDN). Гайд — [PANEL.md](PANEL.md)
- **Конфиги**: единый flat-INI (`server.conf` / `client.conf` / `users.conf`); клиент — секция `[qeli]`, разворачивается из `qeli://`-ссылки (QR)

## Зачем это создано

Классические VPN (WireGuard, OpenVPN, IPsec) быстрые, но на проводе имеют
**узнаваемую сигнатуру** — в сетях с DPI (GFW, ТСПУ, корпоративные фаерволы) их
детектят и режут. Прокси-инструменты (V2Ray/Xray) маскируются отлично, но это
**пер-приложенческие прокси** (SOCKS/HTTP), а не системный VPN: не заворачивают
весь трафик/DNS на уровне ОС и тяжелее в эксплуатации.

**Qeli закрывает этот разрыв** — удобство настоящего full-tunnel TUN-VPN (весь
трафик, DNS, маршруты, много клиентов, веб-админка) **плюс** маскировка уровня
Xray-REALITY: трафик выглядит как обычный HTTPS к реальному сайту, что держит и
**пассивный** сигнатурный DPI, и **активное** зондирование.

**Полностью собственный стек — не обёртка.** Протокол, обфускация и
REALITY/настоящий TLS 1.3 написаны **с нуля на Rust**: это **НЕ** использование
готовых REALITY-библиотек и **НЕ** обёртка над Xray/sing-box. Свой fake-TLS, свой
hand-rolled TLS 1.3 (`realtls`) с cert-borrowing (паритет JA3S с Xray-REALITY),
свой крипто-канал (X25519 + ML-KEM-768 PQ-гибрид, ChaCha20-Poly1305,
channel-binding, key-pinning, PRP-nonce). Полный контроль и аудируемость кода,
без зависимости от чужих proxy-ядер.

**Для кого:**
- self-host личного/командного VPN там, где WireGuard/OpenVPN заблокированы;
- один сервер с несколькими профилями маскировки (reality-tls / fake-tls / obfs / QUIC) под разные сценарии;
- кому нужен **системный** VPN, а не пер-приложенческий прокси, но с защитой от DPI.

**Чем отличается:** WireGuard — быстрый, но легко фингерпринтится; Xray/V2Ray —
отличная маскировка, но это прокси, а не TUN, и на сторонних ядрах; коммерческие
VPN — не self-hosted. Qeli = self-host full-TUN VPN + REALITY-grade маскировка на
**собственной реализации** + встроенный мульти-клиент и админка.

## Что реализовано самостоятельно

Никаких сторонних proxy-ядер и REALITY-библиотек — весь протокол и маскировка
написаны в этом репозитории с нуля:

- **`realtls` — настоящий TLS 1.3 руками.** Sans-IO ядро (без привязки к сокету) +
  клиент и сервер: ClientHello/ServerHello, key schedule (HKDF), record-слой, AEAD.
  **Cert-borrowing** — сервер одалживает реальный сертификат target'а, так что JA3S
  совпадает с настоящим сайтом (паритет с Xray-REALITY). Экспортируется в нативные
  клиенты через C-ABI FFI и JNI.
- **fake-TLS** — собственный TLS-1.3-мимикрирующий хендшейк: GREASE, рандомизированный
  порядок расширений (JA3 меняется per-connection), SNI, X25519MLKEM768 key_share
  (PQ-гибрид, как у Chrome ≥124) — несёт реальную ML-KEM-долю для внутреннего туннеля.
- **REALITY-proxy** — peek-and-decide на accept: крипто-токен в `session_id`
  ClientHello + anti-replay guard; «чужие» хендшейки прозрачно мостятся на реальный
  сайт (защита от активного зондирования).
- **Крипто-канал** — X25519 + **ML-KEM-768** (PQ-гибрид X25519MLKEM768), HKDF-SHA256,
  ChaCha20-Poly1305 / AES-GCM, Argon2id для паролей.
- **Channel-binding аутентификация** — proof сервера привязан к транскрипту
  рукопожатия + key-pinning: MITM не перехватит пароль ещё до его отправки.
- **PRP-nonce** — 96-битный Feistel-PRP маскирует счётчик пакетов: на проводе нет
  инкрементного nonce, нечего коррелировать DPI.
- **obfs** — ChaCha20-stream обфускация всего потока + WebSocket-fronting.
- **Дата-плоскость** — multi-queue TUN (параллелизм по ядрам), пул IP,
  DNS-over-tunnel, server-pushed конфиг (MTU/маршруты/DNS), per-profile роутинг.
- **Форматы** — flat-INI конфиг (свой парсер) и `qeli://` share-ссылки/QR (своя схема).
- **Кросс-платформенные клиенты** — Rust-ядро `realtls` собирается в `.so/.dll/.dylib`
  и подключается из Android (Kotlin + JNI), Windows (C# + P/Invoke), macOS (C#/Avalonia);
  остальная часть каждого клиента — нативная.

## Репозиторий

Клонируйте в папку `qeli_vpn/` (`git clone https://github.com/litvinovtd/qeli qeli_vpn`),
чтобы корень репозитория не путался с вложенным Rust-крейтом `qeli/`:

```
qeli_vpn/
├── qeli/                  — Rust-сорцы (демон + realtls-ядро для нативных клиентов)
│   ├── src/
│   │   ├── client/        — TCP/UDP-клиент, маршруты, DNS, reconnect
│   │   ├── server/        — handler.rs (TCP), udp_handler.rs (UDP), web/, control/, reality.rs
│   │   ├── crypto/        — X25519, ML-KEM-768, ChaCha20-Poly1305, HKDF, auth (channel-binding/pinning), PRP-nonce
│   │   ├── protocol/      — fake-tls, obfs (ChaCha20 stream), realtls/ (настоящий TLS 1.3: клиент+сервер+sans-IO/FFI), QUIC-wrap, packet codec
│   │   ├── tun/           — TUN/TAP через libc
│   │   ├── web/           — admin UI + REST API
│   │   └── config/        — serde-структуры + flat-INI загрузчик (format.rs/server_ini.rs)
│   ├── config/            — примеры server.conf / client.conf / users.conf (документированные)
│   └── debian/            — systemd unit + .deb
├── qeli-android/         — Android-клиент (Kotlin + JNI к realtls-ядру)
├── qeli-win/             — Windows-клиент (C#/WPF, .NET 10 + P/Invoke к qeli.dll)
├── qeli-mac/             — macOS-клиент (C#/Avalonia, .NET 10 + libqeli.dylib)
├── qeli-shared/          — общий C#-код win+mac (crypto/protocol/model, ядро VpnTunnel, RealTls, Loc; .NET 10)
├── native-libs/          — собранные нативные realtls-либы (.so/.dll/.dylib)
├── release/              — собранный бинарь + benchmark_results.json + reality-tls/ конфиги
├── scripts/              — paramiko: деплой, бенчмарк, отладка, кросс-сборка либ
└── docs/                 — эта документация
```

## Что протокол делает на проводе

1. **Рукопожатие.** Клиент шлёт fake-TLS ClientHello (SNI, x25519 key_share,
   GREASE, рандомизированный порядок расширений → JA3 меняется per-connection).
   Сервер отвечает ServerHello/Certificate/Finished. Общий ключ — X25519,
   AEAD-ключи — HKDF-SHA256. (В режиме `obfs` весь поток дополнительно
   XOR-ится ChaCha20-keystream; в `reality` «чужие» хендшейки проксируются на
   реальный сайт.)
2. **Аутентификация сервера → клиента.** Сервер доказывает владение
   long-term ключом; proof привязан к **транскрипту рукопожатия** (channel
   binding). Клиент сверяет с запиненным ключом (`auth.server_public_key`).
   **До отправки кред** — MITM не перехватит пароль.
3. **Аутентификация клиента → сервера.** Клиент шлёт (в AEAD-канале) proof
   знания серверного ключа + `username:password` (Argon2id). При
   `require_client_key_proof` непиненные клиенты отвергаются.
4. **Данные.** Каждый IP-пакет → AEAD (ChaCha20-Poly1305; nonce маскируется
   96-битным Feistel-PRP — на проводе нет инкрементного счётчика) → опц. паддинг
   → запись: fake-TLS application_data `0x17`; либо голый `[len][nonce][ct]` в
   режиме `plain` (без TLS-обёртки); либо obfs-поток; либо QUIC-обёртка; либо
   внутри настоящего TLS 1.3 в `reality-tls`.

Подробности безопасности — [AUDIT.md](AUDIT.md). Против **активного** пробинга
работает REALITY: `reality` мостит чужих на реальный сайт, а `reality-tls` несёт
туннель внутри настоящего TLS 1.3 (с `handrolled` — одолженный реальный серт
target'а). PQ-гибрид X25519MLKEM768 теперь и во **внутреннем** qeli-туннеле: ключи
данных = X25519 ⊕ ML-KEM-768 (`derive_keys_hybrid`) во всех режимах кроме `plain`
(`fake-tls`/`obfs`/`reality-tls`/UDP), так что защита от harvest-now-decrypt-later
не зависит от обёртки. Сервер ТРЕБУЕТ PQ-долю для не-`plain` режимов (нет тихого
даунгрейда). Managed-клиенты (C#/Kotlin) берут ML-KEM из общего Rust-ядра через
FFI/JNI. В режимах `fake-tls`/`obfs` сам внешний TLS не настоящий (серт-заглушка) —
они рассчитаны на пассивный/энтропийный DPI.

## Быстрый старт

```bash
cd qeli && cargo build --release

# конфиги (flat-INI) — примеры в qeli/config/
sudo install -Dm644 config/server.conf /etc/qeli/server.conf
sudo /usr/bin/qeli server --config /etc/qeli/server.conf

# публичный ключ сервера для пиннинга на клиенте:
qeli show-identity --config /etc/qeli/server.conf

sudo /usr/bin/qeli client --config /etc/qeli/client.conf
```

Полностью документированные примеры со всеми параметрами:
[server.conf](../../qeli/config/server.conf) (исчерпывающий референс) ·
[server-multiprofile.conf](../../qeli/config/server-multiprofile.conf) (готовый шаблон на 9 режимов) ·
[client.conf](../../qeli/config/client.conf) · [users.conf](../../qeli/config/users.conf).
Справочник по конфигу — [CONFIG.md](CONFIG.md).

> 📘 **Новичку:** пошаговое руководство «с нуля» — от установки сервера до заведения
> пользователей с маршрутами и подключения клиента, и через CLI, и через веб-панель —
> в [GETTING-STARTED.md](GETTING-STARTED.md).

## Команды

Полный список подкоманд CLI (`qeli <команда> --help` — все опции).

### Запуск
| Команда | Что делает |
|---|---|
| `qeli server --config <путь>` | запустить сервер (по умолчанию `/etc/qeli/server.conf`) |
| `qeli client --config <путь>` | запустить клиент (по умолчанию `/etc/qeli/client.conf`) |

### Провижининг (работают с файлами конфига/пользователей)
| Команда | Что делает |
|---|---|
| `qeli add-client <user> [--password … --profiles … --static-ip … --max-sessions N --link --host <host>]` | завести пользователя (Argon2-хэш пароля, дозапись в users-файл); с `--link --host` печатает `qeli://`-ссылку (QR) для импорта на телефоне |
| `qeli set-web-password [--username admin --password … --no-enable]` | задать/сгенерировать логин **веб-панели** на свежей установке: пишет `web.username`/`password_hash` (Argon2id) в секцию `[web]` конфига, сохраняя комментарии, и включает панель. Без `--password` — генерирует случайный (печатается один раз) |
| `qeli show-identity --config <путь>` | показать публичный identity-ключ **каждого профиля** (его пинят на клиентах); создаёт ключи, если их нет |

### Живое управление (через control-сокет, без перезапуска сервера)
| Команда | Что делает |
|---|---|
| `qeli list-clients` | кто сейчас подключён |
| `qeli kick <user>` | отключить пользователя |
| `qeli disable-user <user>` | заблокировать (отключить + запретить реконнект) |
| `qeli enable-user <user>` | снова разрешить вход |
| `qeli set-bandwidth <user> <mbps>` | лимит скорости (0 = без лимита) |
| `qeli show-routes <user>` | маршруты пользователя |
| `qeli rotate-identity <profile>` | сменить identity-ключ профиля (клиентам затем обновить `auth.server_public_key`) |

> Команды живого управления берут путь к сокету из `--socket` (по умолчанию
> `/var/run/qeli/control.sock`); `add-client`/`set-web-password`/`show-identity`/`rotate-identity` —
> путь к конфигу из `--config` (по умолчанию `/etc/qeli/server.conf`).

## Документация

- **Установка и начало работы (пошагово, с нуля)**: [GETTING-STARTED.md](GETTING-STARTED.md)
- **Конфигурация (flat-INI), все параметры**: [CONFIG.md](CONFIG.md)
- **Веб-панель (установка и использование)**: [PANEL.md](PANEL.md)
- **Модель безопасности**: [AUDIT.md](AUDIT.md)
- **DPI-аудит (теллы и их устранение)**: [DPI-AUDIT.md](DPI-AUDIT.md)
- **Бенчмарки (все режимы)**: [BENCHMARK.md](BENCHMARK.md)
- **Сравнение с WireGuard/OpenVPN/V2Ray**: [COMPARISON.md](COMPARISON.md)
- **План развития**: [ROADMAP.md](ROADMAP.md)
- **План рефакторинга (устранение дублей кода)**: [REFACTOR-PLAN.md](REFACTOR-PLAN.md)
- **Клиент на роутеры Keenetic (dual-arch mipsel+aarch64)**: [KEENETIC-PORT.md](KEENETIC-PORT.md) · пошаговый деплой: [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md)

## Статус

Pre-1.0 / experimental, но плоскость данных стабильна. 0.7.0 — пост-квантовый
туннель (гибрид X25519+ML-KEM) + аудит-фиксы 2026-06-11. **0.7.1** — security-
hardening по аудиту 2026-06-12 (replay-окно 2048, atomic resolv.conf, kill-switch
sanitization) и **H-1**: привязка сессионных ключей к статической личности сервера
(Noise-IK), **включена по умолчанию** — см. [ROADMAP.md](ROADMAP.md) и
[AUDIT-2026-06-12.md](AUDIT-2026-06-12.md). **0.7.2–0.7.4**: анти-DPI шейпинг трафика
+ серверный NAT (0.7.2), фиксы Android INI/TUN + Linux kill-switch на iptables + аудит-
гигиена (0.7.3), фрагментация UDP-хендшейка для LTE/мобильных (0.7.4). PQ/H-1 затрагивают только рукопожатие
(разовая стоимость), пропускная способность не изменилась, поэтому замеры ниже
актуальны ([BENCHMARK.md](BENCHMARK.md), 2 vCPU лаба, измерено на v0.5.6):

- **TCP**: ~560–571 ↑ / ~690–717 ↓ Mbps (plain/fake-tls/reality), все режимы стабильны
  без обрывов; obfs −12%; reality-proxy ≈ plain; reality-tls ↓ ~430 (с 0.7.0; цена вложенного
  настоящего TLS — двойной AEAD на клиенте, см. BENCHMARK).
- **UDP**: чисто до 300 Mbps, ~400 Mbps при <1% потерь, насыщение ~500.
- Latency overhead ~1.5–1.9 ms; память worker'а ~7–8 MB; узкое место — CPU
  расшифровки на одном ядре.
- Авто-reconnect, crash-safe DNS, brute-force lockout, channel-binding, пиннинг,
  авторизация по профилям — работают (**225 юнит-тестов** зелёных, e2e всех wire-
  режимов подтверждён на лабе).

## License

Монорепозиторий с **несколькими лицензиями по каталогам** (полная карта —
[LICENSING.md](../../LICENSING.md)):

| Часть | Лицензия |
|---|---|
| Ядро + сервер (`qeli/`) и репозиторий по умолчанию | **AGPL-3.0-only** ([LICENSE](../../LICENSE)) |
| Клиенты (`qeli-android/`, `qeli-win/`, `qeli-mac/`) | **MPL-2.0** (`LICENSE` в каждом каталоге) |
| Сторонние нативные бинари (`native-libs/third-party/`) | по upstream-лицензиям |

> **Важно:** клиенты бандлят нативное ядро `libqeli`, собранное из AGPL-кода.
> Исходники клиента под MPL-2.0 можно переиспользовать отдельно (со своим backend),
> но **распространяемое приложение вместе с ядром `libqeli`** для третьих лиц
> распространяется на условиях **AGPL-3.0**. Двойного лицензирования ядра не ведётся
> (модель монетизации — хостинг + отдельный закрытый control-plane + поддержка);
> подробности — в [LICENSING.md](../../LICENSING.md).

## Contributing

Вклады принимаются через pull request. CLA не требуется — используется лёгкий
**DCO**: подписывайте коммиты `git commit -s` (`Signed-off-by`). Вклад входит под
лицензией соответствующего каталога (inbound = outbound). Подробности —
[CONTRIBUTING.md](../../CONTRIBUTING.md).
