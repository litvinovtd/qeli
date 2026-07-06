# Qeli — self-hosted anti-censorship VPN with REALITY / anti-DPI obfuscation

**Qeli** — самостоятельно-хостируемый (self-hosted) VPN с современной криптографией
и настраиваемой **обфускацией транспорта**, спроектированный для работы в сетях с
активной **DPI** (Deep Packet Inspection). Один Rust-движок протокола и нативные
клиенты под **Android, Windows и macOS** на общем ядре через FFI; есть
экспериментальный клиент для роутеров **Keenetic** (клиент под **OpenWrt** — в разработке).

**Qeli** is a **self-hosted, censorship-resistant VPN** with modern cryptography and
configurable **transport obfuscation**, built to keep working on networks with active
**Deep Packet Inspection (DPI)**. One Rust protocol engine plus native **Android /
Windows / macOS** clients sharing a native core via FFI, plus an experimental
**Keenetic** router client (an **OpenWrt** client is in development).

Криптография · Cryptography: эфемерный **X25519** + post-quantum **ML-KEM-768**
(гибридный handshake) · **ChaCha20-Poly1305** AEAD · **Argon2id** для паролей.

## Статус · Status

> ⚠️ **Бета.** Все компоненты сейчас в бета-версиях и могут работать нестабильно.
> Стабильной считается линейка начиная с версии **1.0** — она выйдет после
> тестирования и сбора обратной связи от пользователей.
>
> ⚠️ **Beta.** All components are currently beta releases and may be unstable.
> The **1.0** line will be the first stable one — it will ship after testing and
> user feedback.

## Возможности · Features

- **Режимы обфускации (wire modes) · obfuscation/wire modes:** `plain`, `fake-tls`,
  `obfs`, **`reality-tls` (REALITY)**, `quic` — выбираются на профиль, по TCP и UDP.
- **REALITY (`reality-tls`):** настоящий TLS 1.3-handshake к реальному стороннему сайту
  (cert-borrowing / TLS-camouflage) — трафик выглядит как обычный HTTPS к этому сайту,
  устойчив к **active probing** и блокировке по SNI. A genuine TLS 1.3 handshake to a
  real decoy site, so the connection is indistinguishable from ordinary HTTPS and
  resists active probing & SNI-based blocking.
- **Анти-DPI форма потока · traffic flow shaping:** cover-трафик в простое (Poisson) +
  опциональный **stealth**-режим, чтобы поток не выглядел как «bulk-загрузка» для
  статистического DPI.
- **Post-quantum:** гибридный X25519 + **ML-KEM-768** во внутреннем handshake — защита
  от «harvest-now, decrypt-later».
- **Кроссплатформенные клиенты · cross-platform clients:** Android, Windows (WPF),
  macOS (Avalonia), общий нативный core (Rust FFI) + экспериментальный Keenetic
  (OpenWrt — в разработке: procd + UCI + LuCI).
- **Self-hosted сервер · server:** Linux, `.deb`-пакет + systemd, **веб-панель**
  администрирования, CLI, full-tunnel NAT, мульти-профиль (по профилю на режим/порт).
- **Импорт в один шаг · one-tap import:** `qeli://`-ссылки и QR для телефонов.

## Работает при активном DPI · Works under active DPI

Qeli создан для **устойчивости к цензуре** в сетях, где обычный VPN (WireGuard,
OpenVPN, IKEv2) распознаётся и блокируется DPI — например в **Иране**, **Китае**
(Great Firewall / GFW) и **России** (ТСПУ). Режим **REALITY** маскирует туннель под
обычный HTTPS к легитимному сайту, а форма потока сбивает статистические эвристики DPI.

Qeli is designed for **censorship circumvention** on networks where ordinary VPN
protocols are fingerprinted and blocked by DPI — e.g. **Iran**, **China** (the Great
Firewall / GFW) and **Russia** (TSPU). **REALITY** makes the tunnel look like normal
HTTPS to a legitimate site, and traffic shaping defeats statistical DPI heuristics.

> По духу — самохостируемая альтернатива связке Xray/V2Ray/sing-box (REALITY/VLESS),
> но с собственным протоколом, нативными GUI-клиентами и post-quantum handshake.
> In spirit a self-hosted alternative to Xray / V2Ray / sing-box (REALITY/VLESS)
> setups, but with its own protocol, native GUI clients and a post-quantum handshake.

## Быстрый старт · Quick start

**Сервер за одну команду (спросит профиль + порт) · one-command server (asks profile + port):**

```bash
# на чистом Linux-сервере (Debian/Ubuntu), от root · on a clean Linux server, as root:
curl -fsSLO https://raw.githubusercontent.com/litvinovtd/qeli/main/install-reality-server.sh
less install-reality-server.sh   # просмотрите перед запуском · review before running
bash install-reality-server.sh
```

> Скачиваем и запускаем отдельно (а не `curl … | bash`), чтобы скрипт можно было
> просмотреть до выполнения от root. Внутри установщик проверяет `.deb` по SHA256.
> Download-then-run (not `curl … | bash`) so the script can be reviewed before it runs
> as root; the installer itself verifies the `.deb` against SHA256.

Скрипт ставит `.deb` из [Releases](https://github.com/litvinovtd/qeli/releases),
**спрашивает профиль** (reality-tls по умолчанию или fake-tls) **и порт** (по умолчанию
:443), пишет конфиг с full-tunnel NAT, создаёт пользователей и печатает готовые
`qeli://`-ссылки. Для неинтерактивного запуска (или `curl … | bash`) задайте выбор
заранее: `QELI_PROFILE=reality-tls|fake-tls` и/или `QELI_PORT=<1-65535>`. Затем поставьте
клиент из [Releases](https://github.com/litvinovtd/qeli/releases) и
вставьте/отсканируйте ссылку. Подробный разбор «с нуля» (CLI + веб-панель) —
[GETTING-STARTED.md](eng/GETTING-STARTED.md) · [GETTING-STARTED.md (рус)](ru/GETTING-STARTED.md).

The script installs the `.deb` from Releases, **asks for the profile** (reality-tls by
default, or fake-tls) **and the listen port** (default :443), writes the config with
full-tunnel NAT, creates users and prints ready-to-use `qeli://` links. For a
non-interactive run (or `curl … | bash`) set the choice up front:
`QELI_PROFILE=reality-tls|fake-tls` and/or `QELI_PORT=<1-65535>`. Then install a
client from Releases and paste/scan a link. Full from-scratch guide (CLI + web panel) is
in [GETTING-STARTED.md](eng/GETTING-STARTED.md).

## Документация · Documentation

- 🇷🇺 **Русский** — [`docs/ru/README.md`](ru/README.md)
- 🇬🇧 **English** — [`docs/eng/README.md`](eng/README.md)

(Полная документация — конфигурация, дизайн, аудиты, бенчмарки, модель угроз — в
соответствующей локали. The full docs — configuration, design, audits, benchmarks,
threat model — live under each locale.)

## License

Монорепозиторий с **несколькими лицензиями по каталогам** · monorepo with
**per-directory licences**:

- ядро + сервер (`qeli/`) · core + server → **AGPL-3.0-only** ([LICENSE](../LICENSE))
- клиенты (`qeli-android/`, `qeli-win/`, `qeli-mac/`) · clients → **MPL-2.0**

Полная карта и нюансы (`libqeli`/AGPL) · full map and the `libqeli`/AGPL note —
[LICENSING.md](../LICENSING.md). Вклады · contributing (DCO, без CLA) —
[CONTRIBUTING.md](../CONTRIBUTING.md).

---

<sub>**Keywords:** self-hosted VPN, anti-censorship VPN, censorship circumvention,
anti-DPI, DPI bypass, deep packet inspection, REALITY, Reality TLS, TLS camouflage,
SNI, active-probing resistant, traffic obfuscation, fake-TLS, obfs, QUIC VPN,
post-quantum VPN, ML-KEM-768, X25519, ChaCha20-Poly1305, Rust VPN, Android VPN,
Windows VPN, macOS VPN, Keenetic, WireGuard alternative, Xray / V2Ray / sing-box
alternative, VPN for Iran, VPN for China / Great Firewall, VPN for Russia / TSPU.</sub>
