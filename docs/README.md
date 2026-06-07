# Qeli — обфусцированный VPN 

**Qeli** (Quick Easy Link IP) — self-host VPN с собственным L4-протоколом и
встроенной обфускацией, поверх TCP или UDP. Цель — устойчивость к пассивному/
сигнатурному DPI при удобстве классических TUN/TAP-VPN, со встроенной веб-админкой.

- **Язык**: Rust 2021, версия 0.5.6 (бета)
- **Криптостек**: `x25519-dalek`, `ml-kem` (PQ-гибрид X25519MLKEM768), `chacha20poly1305`, `chacha20`, `aes-gcm`, `hkdf`, `sha2`, `argon2`, `zeroize`; `rustls`/`ring` — серверная терминация настоящего TLS 1.3 в `reality-tls`
- **Транспорт**: TCP или UDP; несколько профилей (интерфейсов) в одном демоне
- **Wire-режимы**: `plain` (без обфускации — голый шифрованный туннель, TCP) · `fake-tls` (мимикрия под TLS 1.3) · `obfs` (ChaCha20 stream + WS-fronting) · `reality` (проксирование чужих хендшейков на реальный сайт) · `reality-tls` (настоящий TLS 1.3 несёт туннель; `handrolled` одалживает реальный серт target'а — cert-borrowing, паритет с Xray-REALITY) · QUIC-masking для UDP
- **TUN/TAP**: Linux only (`libc::ioctl(TUNSETIFF)`)
- **Веб-админка**: `axum`, Basic-Auth (Argon2id), same-origin CSRF, REST `/api/*`
- **Конфиги**: единый flat-INI (`server.conf` / `client.conf` / `users.conf`); клиент — секция `[qeli]`, разворачивается из `qeli://`-ссылки (QR)

## Репозиторий

```
VPN_CLAUDE/
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
├── qeli-win/             — Windows-клиент (C#/WPF + P/Invoke к qeli.dll)
├── qeli-mac/             — macOS-клиент (C#/Avalonia + libqeli.dylib)
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
target'а). PQ-гибрид X25519MLKEM768 — в `reality-tls`. В режимах `fake-tls`/`obfs`
TLS не настоящий (серт-заглушка) — они рассчитаны на пассивный/энтропийный DPI.

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
[server.conf](../qeli/config/server.conf) · [client.conf](../qeli/config/client.conf) ·
[users.conf](../qeli/config/users.conf). Справочник по конфигу — [CONFIG.md](CONFIG.md).

## Документация

- **Конфигурация (flat-INI), все параметры**: [CONFIG.md](CONFIG.md)
- **Модель безопасности**: [AUDIT.md](AUDIT.md)
- **DPI-аудит (теллы и их устранение)**: [DPI-AUDIT.md](DPI-AUDIT.md)
- **Бенчмарки (все режимы)**: [BENCHMARK.md](BENCHMARK.md)
- **Сравнение с WireGuard/OpenVPN/V2Ray**: [COMPARISON.md](COMPARISON.md)
- **План развития**: [ROADMAP.md](ROADMAP.md)

## Статус

Pre-1.0 / experimental, но плоскость данных стабильна. По свежим замерам
([BENCHMARK.md](BENCHMARK.md), 2 vCPU лаба, v0.5.6):

- **TCP**: ~560–571 ↑ / ~690–717 ↓ Mbps (plain/fake-tls/reality), все режимы стабильны
  без обрывов; obfs −12%; reality-proxy ≈ plain; reality-tls ↓ ~319 (цена вложенного
  настоящего TLS — двойной AEAD на клиенте, см. BENCHMARK).
- **UDP**: чисто до 300 Mbps, ~400 Mbps при <1% потерь, насыщение ~500.
- Latency overhead ~1.5–1.9 ms; память worker'а ~7–8 MB; узкое место — CPU
  расшифровки на одном ядре.
- Авто-reconnect, crash-safe DNS, brute-force lockout, channel-binding, пиннинг,
  авторизация по профилям — работают (**161 юнит-тест** зелёный, e2e всех wire-
  режимов подтверждён на лабе).
