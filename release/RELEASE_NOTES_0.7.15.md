# qeli 0.7.15 (beta) — one transport core, safer lifecycle, per-app routing

> ⚠️ **Beta — may be unstable.** The **1.0** line will be the first stable one.
> ⚠️ **Бета — возможна нестабильность.** Стабильной станет линейка **1.0**.

**Language · Язык:** [English](#english) · [Русский](#русский) · [Artifacts](#artifacts--артефакты)

This release completes the largest client-side architectural change in qeli so far: Linux,
Android, iOS, Windows and macOS now use the same versioned Rust transport core. The platform
applications keep responsibility for permissions, protected sockets, TUN integration and UI;
handshake, encryption, TCP/UDP/QUIC/REALITY, reconnect policy, shaping and packet processing no
longer have separate implementations that can silently drift apart.

The other theme is lifecycle safety. Disconnect, reconnect, sleep, network changes, crashes and
application removal have been treated as real states rather than variants of a successful stop.
The web panel also gains transactional configuration editing and a Transport Health view based on
structured runtime state rather than log-text guesses.

---

## English

### ⚠️ Before upgrading

- **Run `qeli check-config` before replacing the server.** `tun.netmask` has been removed;
  `pool.cidr` is now the single source of the server and client IPv4 prefix. Remove the old key and
  make sure `tun.address` is a usable address inside that pool.
- **Linux/OpenWrt DNS is now lifecycle-safe and fail-closed.** New connections no longer leave a
  permanent tunnel resolver in `/etc/resolv.conf`. Linux uses the per-link systemd-resolved API;
  when another service owns DNS, configure `dns = off` and manage resolution there.
- **Keep the panel password key separate from an ordinary backup.** The reversible-encryption key
  moves from `/etc/qeli` to `/var/lib/qeli`, so an archive of `/etc/qeli` no longer contains both
  encrypted passwords and the key. Existing installations migrate automatically. A full manual
  disaster-recovery backup must preserve `/var/lib/qeli` separately; without that key the existing
  `password_enc` values cannot be recovered.
- **The public ad-hoc macOS ZIP is full-tunnel only.** Per-app mode requires a Developer ID-signed
  Network Extension. A build without that entitlement rejects a per-app profile instead of
  pretending to apply it. Windows per-app mode is included and uses the bundled WinDivert driver.
- **Logging out of the panel now revokes every issued panel session**, not only the cookie in the
  current browser. This is intentional; other browsers will need to authenticate again.

### 🚀 One transport core on every client

- The additive native ABI reaches **1.10**. The common Rust core owns DNS/connect, authenticated
  handshake, transport crypto, TCP/UDP/QUIC/REALITY, heartbeat, padding, shaping, multipath and the
  packet data plane on all five clients.
- Android and iOS hand an authenticated `NetworkPlan` to their platform VPN APIs and acknowledge
  the actual result before traffic starts. Windows gives the core direct ownership of the Wintun
  session and rings; macOS uses the same packet seam for utun.
- All clients recognise the same 73-key configuration contract. Unsupported platform-specific
  fields round-trip without being lost, while invalid routes, CIDRs and security combinations are
  rejected instead of being weakened silently.
- Connection journals again show the user, endpoint, negotiated transport, applied MTU, DNS,
  routes, padding, heartbeat, shaping and multipath decisions. Passwords, keys and session tokens
  are excluded.

### ✨ Per-app routing on desktop

- Windows can include or exclude selected applications through WinDivert while keeping the same
  encrypted qeli transport. PID/endpoint classification, DNS destination NAT, fragment affinity,
  TCP MSS/MTU handling and bounded flow state are fail-closed across reconnects.
- macOS has the equivalent transparent- and DNS-provider implementation using a Network Extension
  and code-signing identifiers. A guardian lease restores DNS and releases the transparent proxy
  after a crash, power loss or application removal.
- Normal Windows full-tunnel profiles continue to use zero-copy Wintun. Per-app routing is a
  routing policy, not a SOCKS/HTTP proxy and not a second implementation of the protocol.
- The useful foundation from [PR #112](https://github.com/litvinovtd/qeli/pull/112) was adapted to
  the current shared transport, ABI, MTU and configuration contracts rather than merged as an
  obsolete parallel packet engine.

### 🛡 Lifecycle, DNS and recovery

- Android no longer reports `Disconnected` while native workers still own duplicated TUN file
  descriptors. Cancellation interrupts DNS/connect/handshake, teardown waits for both packet
  workers, and a new connect is allowed only after routes and DNS have been released.
- Windows and macOS distinguish service/process autostart from the saved intention to connect.
  A manual disconnect survives reboot, while deleting or moving a running application triggers
  tunnel and DNS cleanup.
- Reconnect reacts promptly to resume and network changes, refreshes DDNS carrier endpoints and
  uses aligned authenticated liveness deadlines. Endpoint recovery cannot leak stale routes, DNS
  or firewall ownership into the next generation.
- The server installs narrow profile-scoped DNS firewall allowances and removes them on teardown.
  Under an `INPUT DROP` policy, failure to install those rules now stops the profile instead of
  handing clients an unreachable resolver.

### 🖥 Web panel and server

- **Transport Health** combines live sessions, streams, traffic and drop counters with the
  effective bind, TUN/MTU, routes, DNS, masking, multipath, buffers and limits for each profile.
  A private structured sidecar replaces fragile log parsing for the Linux client.
- Form, JSON and raw configuration editors use SHA-256 revisions and fail on stale writes. Every
  mutation creates a private rotating snapshot; History can validate and restore it while keeping
  the current state as a rollback snapshot. Quick Start now validates, snapshots and writes in one
  server transaction.
- Session and user views scale to large installations, profile details use a dedicated responsive
  panel, and Windows/macOS settings and profile editors remain usable on small displays.
- `bandwidth.limit_mbps` is enforced symmetrically for TCP and UDP in both directions, with a
  session-wide budget that multipath streams cannot multiply.

### 🔒 Security and packaging

- Replay protection, authenticated liveness, privileged desktop operations, SSH paths, installers,
  updater hooks, backup restore paths and panel sessions were audited and hardened fail-closed.
- Windows kill-switch ownership is transactional and combines persistent WFP policy with a
  WinDivert drop gate. macOS Keychain migration is crash-safe and keeps the existing identity.
- Native Android, Windows and macOS cores are reproducible A/B builds from one source digest. The
  release gate verifies the exact exports, canonical and consumed copies, toolchain versions,
  provenance and SHA-256 manifests before accepting them.
- The OpenWrt package is pinned to a version-specific source archive verified by a real OpenWrt
  23.05.5 SDK. Standalone OpenWrt and Keenetic binaries are built for every advertised architecture.

### ✅ Validation

- 604 Rust tests passed; formatting, strict Clippy, cargo-deny, conformance and fuzz compilation
  gates are green.
- Windows and macOS release builds pass their self-tests and packet benchmarks; Android release APK
  signing and embedded native libraries are verified; iOS builds and unit tests pass in CI.
- Laboratory TCP modes completed without ping loss or session drops. UDP completed without loss up
  to 400 Mbit/s. The retained benchmark report also records the two observations still worth
  watching: a padding loss outlier at 500 Mbit/s and higher RSS than 0.7.14.

The complete technical record and the reasoning behind individual changes are in
[CHANGELOG.md](https://github.com/litvinovtd/qeli/blob/main/CHANGELOG.md). This release contains
**245 commits across 547 files** relative to 0.7.14.

---

## Русский

### ⚠️ Перед обновлением

- **Перед заменой сервера выполните `qeli check-config`.** Параметр `tun.netmask` удалён;
  `pool.cidr` теперь единственный источник IPv4-префикса сервера и клиентов. Удалите старый ключ и
  убедитесь, что `tun.address` является пригодным адресом внутри этого пула.
- **DNS на Linux/OpenWrt теперь управляется безопасно по жизненному циклу и работает fail-closed.**
  Новые подключения больше не оставляют туннельный resolver постоянной записью в
  `/etc/resolv.conf`. Linux использует per-link API systemd-resolved; если DNS принадлежит другой
  службе, задайте `dns = off` и управляйте разрешением имён там.
- **Храните ключ паролей панели отдельно от обычного архива.** Ключ обратимого шифрования перенесён
  из `/etc/qeli` в `/var/lib/qeli`, поэтому архив `/etc/qeli` больше не содержит одновременно
  ciphertext и ключ. Существующая установка мигрирует автоматически. Для полного аварийного
  восстановления отдельно сохраните `/var/lib/qeli`: без этого ключа прежние `password_enc`
  восстановить невозможно.
- **Публичный macOS ZIP с ad-hoc подписью поддерживает только полный туннель.** Для per-app режима
  требуется Network Extension с подписью Developer ID. Сборка без entitlement отклоняет такой
  профиль, а не изображает его применение. Windows per-app входит в комплект и использует
  поставляемый WinDivert.
- **Выход из панели теперь отзывает все выданные панельные сессии**, а не только cookie текущего
  браузера. На остальных устройствах потребуется повторный вход.

### 🚀 Единое транспортное ядро всех клиентов

- Аддитивный native ABI доведён до **1.10**. Общее Rust-ядро владеет DNS/connect,
  аутентифицированным handshake, transport crypto, TCP/UDP/QUIC/REALITY, heartbeat, padding,
  shaping, multipath и пакетным data plane всех пяти клиентов.
- Android и iOS передают аутентифицированный `NetworkPlan` системным VPN API и подтверждают
  фактический результат до запуска трафика. На Windows ядро напрямую владеет Wintun session/rings,
  а macOS использует тот же packet seam для utun.
- Все клиенты распознают единый контракт из 73 ключей. Неприменимые платформенные поля сохраняются
  без потерь, а неверные маршруты, CIDR и комбинации настроек безопасности отклоняются вместо
  скрытого ослабления.
- Журнал подключения снова показывает пользователя, endpoint, согласованный транспорт,
  применённые MTU, DNS, routes, padding, heartbeat, shaping и multipath. Пароли, ключи и session
  token туда не попадают.

### ✨ Маршрутизация отдельных приложений на desktop

- Windows умеет включать или исключать выбранные приложения через WinDivert, сохраняя общий
  зашифрованный транспорт qeli. Классификация PID/endpoint, DNS destination NAT, fragment affinity,
  обработка TCP MSS/MTU и ограниченное состояние flow работают fail-closed при реконнекте.
- На macOS реализован функциональный аналог на Network Extension с transparent- и DNS-provider и
  code-signing identifier приложений. Guardian lease восстанавливает DNS и освобождает transparent
  proxy после crash, потери питания или удаления приложения.
- Обычный полный туннель Windows по-прежнему использует zero-copy Wintun. Per-app — это политика
  маршрутизации, а не SOCKS/HTTP-прокси и не вторая реализация протокола.
- Полезная основа из [PR #112](https://github.com/litvinovtd/qeli/pull/112) адаптирована к текущим
  общему транспорту, ABI, MTU и контракту конфигурации вместо прямого слияния устаревшего
  параллельного packet engine.

### 🛡 Жизненный цикл, DNS и восстановление

- Android больше не сообщает `Disconnected`, пока native workers владеют дубликатами TUN fd.
  Отмена прерывает DNS/connect/handshake, teardown ждёт оба пакетных worker, а новый connect
  разрешается только после полного освобождения маршрутов и DNS.
- Windows и macOS отделяют автостарт службы/процесса от сохранённого желания подключаться. Ручной
  Disconnect переживает перезагрузку, а удаление или перемещение работающего приложения запускает
  очистку туннеля и DNS.
- Реконнект быстро реагирует на пробуждение и смену сети, обновляет DDNS endpoints и использует
  согласованные аутентифицированные liveness deadlines. В следующую generation не переносятся
  устаревшие маршруты, DNS или владение firewall.
- Сервер сам устанавливает узкие профильные DNS-разрешения firewall и удаляет их при teardown.
  При политике `INPUT DROP` ошибка установки правил останавливает профиль вместо выдачи клиентам
  недоступного resolver.

### 🖥 Панель и сервер

- **Transport Health** объединяет фактические sessions, streams, traffic и drop-счётчики с
  эффективными bind, TUN/MTU, routes, DNS, masking, multipath, buffers и limits каждого профиля.
  Для Linux-клиента хрупкий разбор журнала заменён приватным структурированным sidecar.
- Form, JSON и raw редакторы используют SHA-256-ревизии и не затирают более новую правку. Каждое
  изменение создаёт приватный ротационный snapshot; History проверяет и восстанавливает его,
  сохраняя текущее состояние как точку отката. Quick Start выполняет validate, snapshot и write
  одной серверной транзакцией.
- Списки сессий и пользователей масштабируются для крупных установок, подробности профиля вынесены
  в адаптивную панель, а настройки и редакторы Windows/macOS помещаются на небольших экранах.
- `bandwidth.limit_mbps` симметрично применяется к TCP и UDP в обоих направлениях; multipath-потоки
  делят общий session-wide бюджет и не умножают заданную скорость.

### 🔒 Безопасность и сборка

- Replay-защита, аутентифицированный liveness, привилегированные desktop-операции, SSH-пути,
  installers, updater hooks, восстановление backup и сессии панели проверены и усилены fail-closed.
- Windows kill switch транзакционно владеет политикой и сочетает постоянные WFP rules с WinDivert
  drop gate. Миграция macOS Keychain переживает сбой и сохраняет существующую identity.
- Нативные ядра Android, Windows и macOS воспроизводимо собраны независимыми A/B-проходами из
  одного source digest. Release gate проверяет экспорты, canonical/consumed copies, версии
  toolchain, provenance и SHA-256 до принятия файлов.
- OpenWrt package закреплён на version-specific source archive, проверенном настоящим OpenWrt SDK
  23.05.5. Отдельные OpenWrt и Keenetic бинарники собраны для каждой заявленной архитектуры.

### ✅ Проверка

- Пройдены 604 Rust-теста, formatting, строгий Clippy, cargo-deny, conformance и сборка fuzz targets.
- Windows и macOS Release проходят self-test и packet benchmark; проверены подпись Android APK и
  вложенные native-библиотеки; iOS собирается и проходит unit-тесты в CI.
- Все лабораторные TCP-режимы завершились без потерь ping и session drops. UDP прошёл без потерь до
  400 Мбит/с. В сохранённом benchmark-отчёте честно оставлены два наблюдения: выброс потерь padding
  на 500 Мбит/с и более высокий RSS относительно 0.7.14.

Полная техническая история и обоснование отдельных решений находятся в
[CHANGELOG.md](https://github.com/litvinovtd/qeli/blob/main/CHANGELOG.md). Относительно 0.7.14 этот
релиз содержит **245 коммитов и изменения в 547 файлах**.

---

## Artifacts · Артефакты

Every published payload is covered by the accompanying `SHA256SUMS` file.
Каждый публикуемый файл покрыт прилагаемым `SHA256SUMS`.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.7.15.apk` | 8.4 MB | `49ebae602233d1cd` |
| `qeli-linux-amd64` | 10.4 MB | `0837799013709a50` |
| `qeli_0.7.15_amd64.deb` | 3.4 MB | `74cf78189f8917c4` |
| `Qeli-macOS-universal.zip` | 59.3 MB | `f40f643e895c831c` |
| `QeliWin-net-required.exe` | 11.3 MB | `c513972d0cc2853b` |
| `QeliWin-standalone.exe` | 74.6 MB | `c83ddcda7d256a56` |
| `qeli-client-keenetic-aarch64` | 2.9 MB | `50670291113d3ee6` |
| `qeli-client-keenetic-mipsel` | 4.2 MB | `282e9d65aeb7103b` |
| `qeli-client-openwrt-aarch64` | 2.9 MB | `50670291113d3ee6` |
| `qeli-client-openwrt-armv7` | 3.0 MB | `1215461e04ae7124` |
| `qeli-client-openwrt-mipsel` | 4.2 MB | `282e9d65aeb7103b` |
| `qeli-client-openwrt-x86_64` | 3.4 MB | `a46913c8fc509146` |
| `qeli-openwrt-files.tar.gz` | 10.4 KB | `e5db8804dcb0530f` |
| `install-keenetic.sh` | 1.8 KB | `87f1a656d4ff358f` |
| `WinDivert-LICENSE.txt` | 61.3 KB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.3 KB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полностью совпадающие хеши этих пар являются ожидаемым результатом.

### Install · Установка

See the [README](https://github.com/litvinovtd/qeli/blob/main/README.md) for complete instructions.
Полные инструкции находятся в [README](https://github.com/litvinovtd/qeli/blob/main/README.md).

- Linux DEB: `sudo dpkg -i qeli_0.7.15_amd64.deb`
- Verify downloads · Проверить файлы: `sha256sum -c SHA256SUMS`
- Android is signed with the same project key as 0.7.14 and installs over it normally.
- Android подписан тем же проектным ключом, что и 0.7.14, и штатно устанавливается поверх него.
