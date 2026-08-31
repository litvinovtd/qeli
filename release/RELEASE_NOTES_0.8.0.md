# qeli 0.8.0 (beta) — roaming, genuine Reality/H2 and PACKET_MUX

> ⚠️ **Beta — may be unstable.** The **1.0** line will be the first stable one.
>
> ⚠️ **Бета — возможна нестабильность.** Стабильной станет линейка **1.0**.

**Release candidate prepared · Кандидат подготовлен:** 2026-08-31

**Language · Язык:** [English](#english) · [Русский](#русский) ·
[Artifacts](#artifacts--артефакты)

This document highlights the user- and operator-visible changes since `v0.7.16`. The canonical
itemised history is [CHANGELOG.md](../CHANGELOG.md).

---

## English

### Before upgrading

- Upgrade the **server first**. A 0.8.0 server accepts the legacy and new Reality carriers, while
  the new Reality client uses genuine HTTP/2 and does not downgrade to the old inner fake-TLS
  carrier.
- For a staged `PACKET_MUX_V1` rollout, set `obf.recordizer.policy = prefer`, reconnect clients,
  and switch to `required` only after the fleet is upgraded. `off` keeps the legacy data plane.
- Existing server profiles do not silently enable roaming: a missing `roaming.enabled` remains
  `false`. Newly generated profiles enable it with bounded defaults; clients use `roaming = auto`.
- Shipped server templates are dual-stack with IPv4 plus a unique IPv6 ULA/NAT66 plan. Existing
  configurations are not rewritten automatically. Validate them with `qeli check-config` before
  restarting and follow the [IPv6 guide](../docs/eng/manuals/IPV6.md) when migrating.
- Reality/H2 must reach qeli through transparent TCP pass-through. TLS termination, H2 conversion
  or HTTP routing in a reverse proxy breaks Reality authentication and the carrier.

### Genuine Reality/H2 and common packet morphology

- `reality-tls` now carries traffic in one authenticated, long-lived, bidirectional HTTP/2 POST
  with ALPN `h2`, standard H2 framing and random 2–8 ms batching. The redundant inner fake-TLS
  handshake/framing has been removed; qeli PacketCodec AEAD remains as defence in depth.
- Authenticated `PACKET_MUX_V1` is available to every TCP and UDP camouflage mode. It batches IP
  packets, changes encrypted record boundaries and fragments when required without changing the
  selected outer carrier.
- Recordizer limits are server-controlled and authenticated during negotiation; no new client key
  or qeli-link field is required. `prefer` retains rolling compatibility with legacy clients.
- Reality/H2 suppresses the redundant qeli heartbeat and shipped Reality templates enable traffic
  shaping. Bare `fake-tls` remains a separate carrier and does not gain real TLS/H2 or Reality
  active-probe protection.

### Session roaming and recovery

- The shared Rust transport core now implements negotiated roaming for ordinary TCP and all UDP
  camouflage modes. Client policy is `off | auto | required`; `required` fails before credentials
  and full authentication when the complete peer/platform contract is unavailable.
- TCP make-before-break uses a two-phase commit. The old carrier remains live until the new
  platform path is applied and acknowledged; ambiguous post-commit failures terminate the
  generation and perform a clean reconnect instead of risking a black hole.
- UDP path migration queues authenticated candidate-path data until commit, bounds that queue,
  rejects stale epochs and handles same-network NAT rebinding without silently losing accepted
  traffic.
- Android and iOS integrate physical-network changes with the common generation state machine.
  Windows, macOS and Linux use the same fail-closed path result contract; an unsupported or stale
  native core falls back to reconnect instead of pretending that migration succeeded.
- Startup and live uplink PMTU probing use an authenticated 128-bit challenge. Route application,
  path refresh and include-family mismatches are fail-closed, while explicit exclusions keep
  priority over local-route capture.

### Clients, routing and administration

- Windows per-app mode continues to route only selected processes through the tunnel; with
  `gateway = false`, those processes receive only explicit/pushed routes and the connected tunnel
  subnet. Other public IPv4 and native IPv6 remain direct. Fragmented IPv4 NAT checksums are now
  updated safely.
- Windows/macOS `route_local`, IPv6 scope handling, persistent TUN reuse, kill-switch recovery and
  generation ownership were tightened. macOS uses an isolated PF anchor and release validation
  loads the production ruleset through real `pfctl` syntax checks.
- Mobile and desktop profile editors expose the same roaming policy and preserve supported INI
  fields not represented by form controls. Invalid imports and incompatible `required` settings
  are rejected before persistence.
- The panel exposes bounded aggregate roaming/transport health counters without session IDs,
  proofs or secrets. Configuration pushes, user ACLs, backup/restore dependencies and lifecycle
  mutations are validated before publication.
- Documentation is reorganised into manuals, references, plans, reports and archives with strict
  English/Russian parity and recursive link checks.

### Build and verification

- Linux portable and Debian binaries passed formatting, strict Clippy, 984 Rust tests plus CLI and
  config suites, fuzz/conformance, dependency policy, jemalloc and glibc 2.28 compatibility gates.
- Android arm64-v8a/x86_64, Windows x64 and macOS universal2 native cores were rebuilt in two
  independent passes and are byte-identical per platform/ABI. Their common source digest is
  `f07f26cc98d5338605bc10edab017ab8c9fe4e77af1fcf99b6c986516e769d58`.
- The signed Android APK is `versionCode 720` / `versionName 0.8.0`; clean offline unit tests,
  lint-vital, R8 and signature verification passed. Windows passed self-test and packetbench.
  The universal macOS bundle contains both architectures and all Mach-O objects are signed.
- OpenWrt SDK 23.05.5 and Keenetic recipes produced four OpenWrt and two Keenetic clients. Matching
  aarch64 and mipsel pairs are intentionally byte-identical.

For configuration details see the [configuration reference](../docs/eng/manuals/CONFIG.md),
[roaming plan and contract](../docs/eng/plans/ROAMING.md) and
[transport-core reference](../docs/eng/reference/TRANSPORT-CORE.md).

---

## Русский

### Перед обновлением

- Сначала обновите **сервер**. Сервер 0.8.0 принимает старый и новый Reality carrier, а новый
  Reality-клиент использует настоящий HTTP/2 и не откатывается к прежнему внутреннему fake-TLS.
- Для поэтапного включения `PACKET_MUX_V1` задайте на сервере
  `obf.recordizer.policy = prefer`, переподключите клиентов и переходите на `required` только после
  обновления всего парка. `off` сохраняет прежний data plane.
- Старые серверные профили не включают роуминг молча: отсутствие `roaming.enabled` означает
  `false`. Новые профили создаются с включёнными ограниченными defaults, клиенты используют
  `roaming = auto`.
- Поставляемые серверные шаблоны стали dual-stack: IPv4 плюс уникальный IPv6 ULA/NAT66-план.
  Существующие конфиги автоматически не переписываются. Перед рестартом выполните
  `qeli check-config`, а для миграции используйте [руководство IPv6](../docs/ru/manuals/IPV6.md).
- Reality/H2 требует прозрачного TCP pass-through до qeli. TLS termination, H2 conversion или HTTP
  routing на промежуточном reverse proxy ломают Reality-аутентификацию и carrier.

### Настоящий Reality/H2 и общая морфология пакетов

- `reality-tls` теперь передаёт трафик через один аутентифицированный долгоживущий двусторонний
  HTTP/2 POST с ALPN `h2`, стандартным H2 framing и случайным batching 2–8 мс. Лишний внутренний
  fake-TLS handshake/framing удалён; PacketCodec AEAD сохранён как дополнительный слой защиты.
- Аутентифицированный `PACKET_MUX_V1` работает во всех TCP- и UDP-режимах маскировки: объединяет
  IP-пакеты, меняет границы зашифрованных записей и при необходимости фрагментирует данные, не
  меняя выбранный внешний carrier.
- Лимиты recordizer задаются сервером и приходят в аутентифицированном согласовании; новые ключи
  на клиенте или в qeli-ссылке не нужны. `prefer` сохраняет rolling-совместимость со старыми
  клиентами.
- Reality/H2 отключает лишний qeli heartbeat, а поставляемые Reality-шаблоны включают shaping.
  Обычный `fake-tls` остаётся отдельным carrier и не получает настоящий TLS/H2 или Reality-защиту
  от active probe.

### Роуминг сессии и восстановление

- Общее Rust-ядро реализует согласованный роуминг для обычного TCP и всех UDP camouflage modes.
  Политика клиента: `off | auto | required`; `required` отказывает до передачи credentials и полной
  аутентификации, если peer или платформа не поддерживает весь контракт.
- TCP make-before-break использует двухфазную фиксацию. Старый carrier живёт, пока новый путь не
  применён и не подтверждён платформой; неоднозначная post-commit ошибка завершает generation и
  запускает чистый reconnect вместо риска blackhole.
- UDP удерживает аутентифицированные данные candidate path до commit, ограничивает очередь,
  отклоняет stale epoch и обрабатывает same-network NAT rebinding без тихой потери уже принятых
  пакетов.
- Android и iOS связывают смену физической сети с общей generation state machine. Windows, macOS
  и Linux используют тот же fail-closed контракт результата; старое или несовместимое native core
  переходит к reconnect, а не изображает успешную миграцию.
- Startup/live PMTU probe использует аутентифицированный 128-битный challenge. Ошибки семейства
  маршрута, path refresh и явного `include` закрываются fail-closed; `exclude` сохраняет приоритет.

### Клиенты, маршрутизация и администрирование

- Windows per-app направляет в VPN только выбранные процессы; при `gateway = false` им доступны
  только явные/pushed routes и связанная подсеть туннеля, а остальной public IPv4 и native IPv6
  остаются прямыми. Исправлена безопасная коррекция checksum для фрагментированного IPv4 NAT.
- На Windows/macOS усилены `route_local`, IPv6 scope, повторное использование persistent TUN,
  восстановление kill switch и владение generation. macOS использует отдельный PF anchor, а
  release gate проверяет production ruleset реальным синтаксисом `pfctl`.
- Мобильные и desktop-редакторы показывают одинаковую политику роуминга и сохраняют поддерживаемые
  INI-поля вне формы. Невалидный импорт и несовместимый `required` отклоняются до сохранения.
- Панель показывает ограниченные агрегированные показатели роуминга/состояния транспорта без CID,
  proof и секретов. Push-параметры, ACL пользователей, зависимости backup/restore и lifecycle
  изменения валидируются до публикации состояния.
- Документация распределена по manuals, reference, plans, reports и archive; проверяются
  рекурсивные ссылки и строгий паритет английской и русской версий.

### Сборка и проверка

- Portable Linux и Debian-пакет прошли formatting, strict Clippy, 984 Rust-теста плюс CLI/config,
  fuzz/conformance, dependency policy, jemalloc и проверку совместимости с glibc 2.28.
- Native cores Android arm64-v8a/x86_64, Windows x64 и macOS universal2 собраны двумя независимыми
  проходами и побайтово воспроизводимы для каждой платформы/ABI. Общий source digest:
  `f07f26cc98d5338605bc10edab017ab8c9fe4e77af1fcf99b6c986516e769d58`.
- Подписанный APK имеет `versionCode 720` / `versionName 0.8.0`; clean offline unit tests,
  lint-vital, R8 и проверка подписи прошли. Windows прошёл self-test и packetbench. Universal
  macOS bundle содержит обе архитектуры, все Mach-O подписаны.
- OpenWrt SDK 23.05.5 и Keenetic recipes собрали четыре OpenWrt- и два Keenetic-клиента.
  Соответствующие aarch64- и mipsel-пары намеренно побайтово совпадают.

Подробности: [справочник конфигурации](../docs/ru/manuals/CONFIG.md),
[план и контракт роуминга](../docs/ru/plans/ROAMING.md) и
[описание transport core](../docs/ru/reference/TRANSPORT-CORE.md).

---

## Artifacts · Артефакты

The local release candidate contains 17 publishable payloads. Every payload is covered by the
accompanying `SHA256SUMS`. Локальный кандидат содержит 17 публикуемых файлов; каждый покрыт
прилагаемым `SHA256SUMS`.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.8.0.apk` | 9.6 MB | `2741450f4e55a84e` |
| `qeli-linux-amd64` | 12.5 MB | `5b7d3a0ba3512516` |
| `qeli_0.8.0_amd64.deb` | 4.0 MB | `4193d1ed182d8036` |
| `Qeli-macOS-universal.zip` | 57.9 MB | `55690faa05f9839c` |
| `QeliWin-net-required.exe` | 7.9 MB | `b5341871f7105124` |
| `QeliWin-standalone.exe` | 72.7 MB | `23f33967dbc9ed6e` |
| `qeli-client-keenetic-aarch64` | 3.9 MB | `0583c37c5e3f7d04` |
| `qeli-client-keenetic-mipsel` | 5.6 MB | `8fc2bfe18038e4c6` |
| `qeli-client-openwrt-aarch64` | 3.9 MB | `0583c37c5e3f7d04` |
| `qeli-client-openwrt-armv7` | 4.1 MB | `82e02f0ffc9744d0` |
| `qeli-client-openwrt-mipsel` | 5.6 MB | `8fc2bfe18038e4c6` |
| `qeli-client-openwrt-x86_64` | 4.6 MB | `641a74ac938b8e8b` |
| `qeli-openwrt-files.tar.gz` | 12.7 KB | `be01d128f7d0c241` |
| `install-keenetic.sh` | 2.3 KB | `fa12354977d6a81e` |
| `Wintun-LICENSE.txt` | 5.3 KB | `9aaf948856ce8845` |
| `WinDivert-LICENSE.txt` | 61.3 KB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.3 KB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полностью совпадающие хеши этих пар являются ожидаемым результатом.

### Install · Установка

See the [README](https://github.com/litvinovtd/qeli/blob/main/README.md) for complete instructions.
Полные инструкции находятся в [README](https://github.com/litvinovtd/qeli/blob/main/README.md).

- Linux DEB: `sudo dpkg -i qeli_0.8.0_amd64.deb`
- Verify downloads · Проверить файлы: `sha256sum -c SHA256SUMS`
- Android is signed with the existing project key and is intended to install over 0.7.16.
- Android подписан существующим ключом проекта и предназначен для установки поверх 0.7.16.
