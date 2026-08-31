# Qeli — обфусцированный VPN 

**Qeli** (Quick Easy Link IP) — self-host VPN с собственным L4-протоколом и
встроенной обфускацией, поверх TCP или UDP. Цель — устойчивость к пассивному/
сигнатурному DPI при удобстве классических TUN/TAP-VPN, со встроенной веб-админкой.

- **Язык**: Rust 2021, версия 0.8.0 (бета)
- **Криптостек**: `x25519-dalek`, `ml-kem` (PQ-гибрид X25519MLKEM768), `chacha20poly1305`, `chacha20`, `aes-gcm`, `hkdf`, `sha2`, `argon2`, `zeroize`; `rustls`/`ring` — серверная терминация настоящего TLS 1.3 в `reality-tls`
- **Транспорт**: TCP или UDP; несколько профилей (интерфейсов) в одном демоне
- **Wire-режимы**: `plain` · `fake-tls` · `obfs` · `reality` · `reality-tls` (REALITY TLS 1.3 + настоящий HTTP/2 carrier; `handrolled` одалживает сертификат target) · QUIC-shaped совместимость для UDP, не настоящий QUIC/HTTP3
- **TUN/TAP-бэкенд Rust daemon/CLI**: только Linux (`libc::ioctl(TUNSETIFF)`); нативные
  клиенты используют API своей платформы (Wintun, utun, Android `VpnService`, iOS Network Extension)
- **Веб-админка**: `axum` + `alpine.js`; встроенный HTTPS (rustls, self-signed или свой серт), пароль Argon2id (fail-closed), IP-allowlist, security-заголовки/HSTS, same-origin CSRF, RU/EN-локализация, выдача `qeli://`-ссылок/QR без ввода пароля; ассеты встроены (без CDN). Гайд — [PANEL.md](manuals/PANEL.md)
- **Конфиги**: единый flat-INI (`server.conf` / `client.conf` / `users.conf`); клиент — секция `[qeli]`, разворачивается из `qeli://`-ссылки (QR)

## Зачем это создано

Классические VPN (WireGuard, OpenVPN, IPsec) быстрые, но на проводе имеют
**узнаваемую сигнатуру** — в сетях с DPI (GFW, ТСПУ, корпоративные фаерволы) их
детектят и режут. Прокси-инструменты (V2Ray/Xray) маскируются отлично, но это
**пер-приложенческие прокси** (SOCKS/HTTP), а не системный VPN: не заворачивают
весь трафик/DNS на уровне ОС и тяжелее в эксплуатации.

**Qeli рассчитан закрыть этот разрыв** — удобство настоящего full-tunnel TUN-VPN
(весь трафик, DNS, маршруты, много клиентов, веб-админка) **плюс** маскировка в
стиле REALITY. `reality-tls` стремится быть похожим на обычный HTTPS к настроенному
target и отправляет неавторизованные пробы на этот сайт, снижая известные признаки
**пассивного** DPI и **активного** зондирования. Это не универсальная гарантия
неотличимости или обхода блокировок.

**Полностью собственный стек — не обёртка.** Протокол, обфускация и
REALITY/настоящий TLS 1.3 написаны **с нуля на Rust**: это **НЕ** использование
готовых REALITY-библиотек и **НЕ** обёртка над Xray/sing-box. Свой fake-TLS, свой
hand-rolled TLS 1.3 (`realtls`) с cert-borrowing (сертификат и форма JA3S target'а,
без заявления полного паритета с Xray/браузером),
свой крипто-канал (X25519 + ML-KEM-768 PQ-гибрид, ChaCha20-Poly1305,
channel-binding, key-pinning, PRP-nonce). Полный контроль и аудируемость кода,
без зависимости от чужих proxy-ядер.

**Для кого:**
- self-host личного/командного VPN там, где WireGuard/OpenVPN заблокированы;
- один сервер с несколькими профилями маскировки (reality-tls / fake-tls / obfs / QUIC) под разные сценарии;
- кому нужен **системный** VPN, а не пер-приложенческий прокси, но с защитой от DPI.

**Чем отличается:** WireGuard — быстрый, но легко фингерпринтится; Xray/V2Ray —
отличная маскировка, но это прокси, а не TUN, и на сторонних ядрах; коммерческие
VPN — не self-hosted. Qeli = self-host full-TUN VPN + REALITY-style маскировка на
**собственной реализации** + встроенный мульти-клиент и админка.

## Что реализовано самостоятельно

Никаких сторонних proxy-ядер и REALITY-библиотек — весь протокол и маскировка
написаны в этом репозитории с нуля:

- **`realtls` — настоящий TLS 1.3 руками.** Sans-IO ядро (без привязки к сокету) +
  клиент и сервер: ClientHello/ServerHello, key schedule (HKDF), record-слой, AEAD.
  **Cert-borrowing** — сервер одалживает реальный сертификат target'а, так что форма JA3S
  совпадает с probed target; это одно измерение, а не полный паритет с Xray/браузером. Экспортируется в нативные
  клиенты через C-ABI FFI и JNI.
- **fake-TLS** — собственный TLS-1.3-мимикрирующий хендшейк: GREASE, рандомизированный
  порядок расширений (JA3 меняется per-connection), SNI, X25519MLKEM768 key_share
  (PQ-гибрид, как у Chrome ≥124) — несёт реальную ML-KEM-долю для внутреннего туннеля.
- **REALITY-proxy** — peek-and-decide на accept: крипто-токен в `session_id`
  ClientHello + anti-replay guard; «чужие» хендшейки прозрачно мостятся на реальный
  сайт (защита от активного зондирования).
- **Настоящий HTTP/2 carrier** — аутентифицированный `reality-tls` использует ALPN `h2`, один
  долгоживущий двунаправленный `POST /v1/events/stream`, настоящие SETTINGS/HEADERS/DATA/
  flow-control и случайный batching 2–8 мс. Пользовательского H2-переключателя и второго
  внутреннего fake-TLS handshake больше нет.
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
│   │   ├── protocol/      — fake-tls, obfs, realtls/, h2_carrier.rs, QUIC-shape, packet codec
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

1. **Рукопожатие carrier.** `fake-tls` отправляет TLS-shaped ClientHello qeli; `obfs` выполняет
   выбранный fronting; `plain` начинает приватное рукопожатие напрямую. `reality-tls` вместо
   этого устанавливает аутентифицированный REALITY TLS 1.3 и согласует ALPN `h2`.
2. **Reality/H2 carrier.** Клиент открывает ровно один долгоживущий двунаправленный
   `POST /v1/events/stream`. Приватный поток qeli идёт в настоящих HTTP/2 DATA frames;
   случайный batching 2–8 мс разрушает корреляцию границ сообщений и записей.
3. **Взаимная аутентификация qeli.** Proof сервера привязан к transcript и проверяется по
   pinned-ключу профиля до отправки credentials. Затем клиент доказывает знание ключа и
   аутентифицируется внутри AEAD-канала qeli.
4. **Данные.** PacketCodec остаётся end-to-end ChaCha20-Poly1305 с PRP-маскировкой nonce.
   Legacy-режимы сохраняют своё framing; текущий `reality-tls` несёт raw private qeli records
   внутри H2. Внешний TLS AEAD и внутренний qeli AEAD остаются, но вложенного fake-TLS нет.
Подробности безопасности — [AUDIT.md](reports/AUDIT.md). Против **активного** пробинга
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
cd qeli && cargo build --release --features jemalloc

# конфиги (flat-INI) — примеры в qeli/config/
sudo install -Dm644 config/server.conf /etc/qeli/server.conf
sudo /usr/bin/qeli server --config /etc/qeli/server.conf

# публичный ключ сервера для пиннинга на клиенте:
qeli show-identity --config /etc/qeli/server.conf

sudo /usr/bin/qeli client --config /etc/qeli/client.conf
```

Полностью документированные примеры со всеми параметрами:
[server.conf](../../qeli/config/server.conf) (исчерпывающий референс) ·
[server-multiprofile.conf](../../qeli/config/server-multiprofile.conf) (готовый шаблон на 10 режимов) ·
[server-ipv6.conf](../../qeli/config/server-ipv6.conf) (готовый dual-stack deployment) ·
[client.conf](../../qeli/config/client.conf) · [users.conf](../../qeli/config/users.conf).
Справочник по конфигу — [CONFIG.md](manuals/CONFIG.md).

> 📘 **Новичку:** пошаговое руководство «с нуля» — от установки сервера до заведения
> пользователей с маршрутами и подключения клиента, и через CLI, и через веб-панель —
> в [GETTING-STARTED.md](manuals/GETTING-STARTED.md).

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
| `qeli list-clients` | кто сейчас подключён — включая колонку `CLIENT` со сборкой, которую сообщает сессия (`0.7.14/android`), или `-` если клиент её не сообщает. **Сообщает сам клиент, сервер не проверяет** |
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

**Полная карта документации → [index.md](index.md)** — все документы, сгруппированные по
аудитории (пользователю · администратору · роутеры · безопасность · устройство ·
разработка · архив).

Чаще всего нужны:

- **[GETTING-STARTED.md](manuals/GETTING-STARTED.md)** — установка и начало работы, пошагово.
- **[CONFIG.md](manuals/CONFIG.md)** — конфигурация (flat-INI), все параметры.
- **[IPV6.md](manuals/IPV6.md)** — полная настройка dual-stack/IPv6-only, NAT66/route и диагностика.
- **[CLIENT-CONFIG-MATRIX.md](reference/CLIENT-CONFIG-MATRIX.md)** — актуальные 80 ключей по клиентам и история рефакторинга.
- **[TROUBLESHOOTING.md](manuals/TROUBLESHOOTING.md)** — диагностика и справочник по ошибкам.
- **[PANEL.md](manuals/PANEL.md)** — веб-панель: установка и использование.

## Статус

Pre-1.0 / бета: плоскость данных стабильна и покрыта юнит- и e2e-тестами, но протокол
ещё может меняться между минорными версиями.

> **Что вошло в каждую версию — в [CHANGELOG.md](../../CHANGELOG.md).** История версий
> здесь намеренно не дублируется: раньше этот раздел описывал 0.7.0–0.7.4 и давно
> разошёлся с реальностью.

Подтверждено на лабе: авто-reconnect, crash-safe DNS, brute-force lockout,
channel-binding, пиннинг ключа сервера, авторизация по профилям, e2e всех wire-режимов.

Производительность (2-VM лаба, последний структурированный прогон: v0.8.0 от
2026-08-26, binary SHA-256 `2f69b48f…`). Методика и raw-данные — [BENCHMARK.md](reports/BENCHMARK.md):

- **TCP, текущий 12-mode прогон**: 713,2–1182 ↑ / 647,8–1330 ↓ Мбит/с, server drops 0.
  Настоящий H2 `reality-tls`: 827,9 ↑ / 647,8 ↓ Мбит/с.
- **UDP**: при 100 Мбит/с потери 0–0,01%; при 400 Мбит/с — 0,01–5,05%;
  при 500 Мбит/с — 5,97–19,69%; при 600 Мбит/с — 27,88–33,21%.
- Средний RTT измеренных режимов — 12,553–24,756 ms; TCP RSS qeli — 84,8–90,3 MB.
  Это один снимок лабы, а не гарантия ёмкости; H2 нужно повторить 5× на финальном SHA.

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
