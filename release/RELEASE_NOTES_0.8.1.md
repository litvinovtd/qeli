# qeli 0.8.1 (beta) — faster UDP, safer routing and more resilient clients

> ⚠️ **Beta — may be unstable.** The **1.0** line will be the first stable one.
>
> ⚠️ **Бета — возможна нестабильность.** Стабильной станет линейка **1.0**.

**Language · Язык:** [English](#english) · [Русский](#русский) ·
[Artifacts](#artifacts--артефакты)

This document highlights the major changes since `v0.8.0`. The complete itemised history is in
[CHANGELOG.md](https://github.com/litvinovtd/qeli/blob/v0.8.1/CHANGELOG.md).

---

## English

qeli 0.8.1 turns the network architecture introduced in 0.8.0 into a faster and more dependable
daily build. The release removes the main syscall bottleneck in the ordinary UDP path, makes mobile
sessions survive real connectivity gaps more cleanly, adds provider-facing IPv6 NDP support and
hardens route import, DHCP, backup, signing and kill-switch edge cases.

### UDP throughput and CPU efficiency

The Linux and Android UDP data plane now receives already queued datagrams with `recvmmsg` and sends
ready Recordizer datagrams with `sendmmsg`, in bounded batches of up to 32. It does not add a
coalescing delay and preserves PacketCodec order, QUIC packet numbers, fragmentation, roaming CIDs,
per-user pacing and PMTU fallback.

In alternating same-window A/B tests, after receive batching was already present, ordinary outbound
batching changed median upload from **320.8 to 694.7 Mbit/s (+116.5%)** and download from **359.8 to
697.5 Mbit/s (+93.9%)**. Relative CPU also fell by 13.2% on the upload client and 7.9% on the download
server worker. Kernel tracepoints confirmed that hundreds of thousands of individual `sendto` calls
were replaced by tens of thousands of `sendmmsg` calls. These figures describe the tested two-core
lab and are not a universal speed guarantee, but they verify both the mechanism and the removal of
the measured bottleneck.

### Roaming and mobile continuity

- Android and iOS no longer spend reconnect backoff while no usable Wi-Fi/LTE carrier exists and
  resume immediately when connectivity returns.
- Android preserves a fail-closed TUN across a native-core restart when the NetworkPlan is unchanged;
  iOS avoids reapplying identical NetworkExtension settings and transfers only bounded, not-yet-
  accepted uplink packets.
- TCP multipath streams use stable logical slot IDs, so losing or restoring one bonded carrier does
  not remap healthy flows. iOS also serialises Packet Tunnel reads across native generations.
- Android keeps up to 1,000 recent diagnostic events in its private no-backup storage across service,
  Activity and UI restarts. Manual disconnect remains authoritative and cannot resurrect a stopped VPN.

### IPv6, DHCP and routed deployments

A session-aware IPv6 NDP proxy is available for providers that treat delegated client prefixes as
on-link and issue Neighbor Solicitations for every address. In routed IPv6 mode, `ndp_proxy = auto`
or `required` answers only for `/128` addresses and non-default client subnets currently owned by
live sessions; disconnect, revoke and session replacement remove ownership immediately. Packet
validation, bounded rate limiting and socket-local multicast membership keep the responder fail-closed.

DHCP handling was also tightened: exact REQUEST/NAK semantics, RELEASE and quarantined DECLINE,
correct relay/broadcast behaviour, full lease renewal and a dedicated expired-lease reaper. Unsafe
or malformed listen addresses are rejected at startup, and DHCP uses configured pushed DNS servers
instead of silently imposing public resolvers.

### Desktop routing and platform reliability

- Windows/macOS `route_file` is repeatable and accepts CIDR, common OpenVPN IPv4 route forms and
  `route-ipv6`. Inputs are canonicalised and deduplicated with a 250,000-route bound; malformed masks,
  unreadable files and limit violations stop the connection fail-closed. Large imports and cleanup can
  be cancelled without flooding the UI log.
- Windows per-app mode now tolerates virtual, WFP/QoS and IPv6-only adapters. One unsupported adapter
  (`NetworkInformationException 10043`) no longer rejects an otherwise valid NetworkPlan.
- Windows per-app socket ownership is now refreshed into a replacement snapshot outside packet
  classification and published atomically. Slow endpoint scans and executable-path lookups no longer
  pause the WinDivert capture path on hosts with many sockets or filter adapters.
- macOS restores DNS, routes and the original `ip.forwarding` state before closing `utun`, eliminating
  the observed roughly 20-second disconnect delay and retaining failed cleanup for a retry.
- Windows kill-switch allow rules and DDNS/roaming allowlist replacement are transactional; failed
  updates roll back firewall state and metadata.

### Security, administration and diagnostics

Backup/restore now verifies the actual tar contents, follows the configured users/config/identity/TLS
paths under `/etc/qeli`, excludes restore history and the legacy panel key, and normalises restored
permissions. Mixed inline plus external user databases keep their precedence and path semantics.
Argon2id generation uses one pinned profile with a fresh salt while existing hashes remain valid.
Telegram/webhook settings, notification caches and desktop profile storage now fail closed on damaged
or unreadable state; macOS profile storage uses a versioned authenticated AES-256-GCM envelope.

Android and iOS connection properties report the modes actually negotiated by the native core,
including Recordizer, roaming, tunnel family and resolved carrier endpoint. Desktop/mobile logs show
the loaded transport ABI (`1.15`) separately from its compatibility floor. The panel received clearer
placeholder styling, responsive IPv6 identity cards and the share QR fix, while iOS gained clearer
profile controls and fail-closed installed-entitlement diagnostics.

### Upgrade notes

1. Update the server first, run `qeli check-config`, then restart it.
2. Update applications together with their bundled native cores; do not mix a 0.8.1 UI with an older
   manually copied core.
3. Leave `routing.ipv6.ndp_proxy = off` unless the provider resolves delegated client addresses with
   NDP. Use `auto` first, or `required` only after verifying the uplink and provider behaviour.
4. Review the expanded [`route_file` documentation](https://github.com/litvinovtd/qeli/blob/v0.8.1/docs/eng/manuals/CONFIG.md#how-to-attach-and-populate-route_file)
   before importing large lists.
5. The universal macOS archive is ad-hoc signed and not Apple-notarised. macOS per-app mode still
   requires a separately Developer-ID-signed system extension and is not enabled by this archive.

IPv6/NDP deployment details are in the
[IPv6 guide](https://github.com/litvinovtd/qeli/blob/v0.8.1/docs/eng/manuals/IPV6.md).

---

## Русский

qeli 0.8.1 доводит сетевую архитектуру 0.8.0 до более быстрой и надёжной повседневной версии.
Устранено основное syscall-ограничение обычного UDP-пути, мобильные сессии лучше переживают реальное
исчезновение сети, добавлен провайдерский IPv6 NDP proxy, а пограничные сценарии маршрутов, DHCP,
резервного копирования, подписи приложений и kill-switch переведены на более строгую fail-closed модель.

### Скорость UDP и эффективность CPU

Linux и Android теперь получают уже ожидающие UDP-датаграммы через `recvmmsg` и отправляют готовые
Recordizer-датаграммы через `sendmmsg` ограниченными пачками до 32 элементов. Дополнительного таймера
накопления нет; сохраняются порядок PacketCodec, QUIC packet number, фрагментация, roaming CID,
per-user pacing и PMTU fallback.

В чередующемся A/B на одном стенде, где receive batching уже присутствовал, медиана upload выросла
с **320,8 до 694,7 Мбит/с (+116,5%)**, а download — с **359,8 до 697,5 Мбит/с (+93,9%)**. Относительная
нагрузка CPU снизилась на 13,2% у upload-клиента и на 7,9% у download worker сервера. Kernel tracepoints
подтвердили замену сотен тысяч одиночных `sendto` десятками тысяч `sendmmsg`. Это результат конкретной
двухъядерной лаборатории, а не обещание одинаковой скорости на любом устройстве, но механизм и снятие
измеренного ограничения подтверждены.

### Roaming и непрерывность мобильных подключений

- Android и iOS не расходуют reconnect-backoff без пригодной Wi-Fi/LTE-сети и сразу возобновляют
  подключение после появления carrier.
- Android сохраняет fail-closed TUN при перезапуске native core, если NetworkPlan не изменился; iOS
  не применяет повторно идентичные NetworkExtension settings и переносит только ограниченную очередь
  пакетов, ещё не принятых ядром.
- TCP multipath использует стабильные logical slot ID: потеря или восстановление одного bonded carrier
  не переназначает здоровые потоки. iOS сериализует чтение Packet Tunnel между поколениями ядра.
- Android хранит до 1000 последних диагностических событий в приватном no-backup файле между
  перезапусками сервиса, Activity и интерфейса. Ручное отключение остаётся окончательным.

### IPv6, DHCP и routed-схемы

Появился session-aware IPv6 NDP proxy для провайдеров, которые считают выделенный клиентский префикс
on-link. В routed IPv6 режимы `ndp_proxy = auto|required` отвечают только за `/128` и non-default
client subnet, реально принадлежащие живым сессиям; disconnect, revoke и замена сессии сразу снимают
ownership. Строгая проверка NS/NA, bounded rate limiter и socket-local multicast membership сохраняют
fail-closed поведение.

DHCP получил точную обработку REQUEST/NAK, RELEASE и DECLINE с quarantine, корректные relay/broadcast,
полноценное продление lease и отдельный reaper истёкших адресов. Небезопасные или неверные listen-
адреса отклоняются при запуске, а клиентам выдаются настроенные `dns.push_servers`.

### Маршруты desktop и надёжность платформ

- `route_file` в Windows/macOS можно повторять. Поддерживаются CIDR, распространённые OpenVPN IPv4
  route и `route-ipv6`; маршруты канонизируются и дедуплицируются с общим лимитом 250 000. Ошибка
  формата, маски, чтения или лимита останавливает подключение fail-closed.
- Windows per-app запускается при наличии виртуальных, WFP/QoS и IPv6-only адаптеров; ошибка 10043
  одного служебного интерфейса больше не отклоняет весь NetworkPlan.
- Windows per-app теперь строит новый снимок принадлежности сокетов вне пути обработки пакетов и
  публикует его атомарно. Медленное чтение endpoint/PID и путей процессов больше не останавливает
  WinDivert-классификацию на системах с большим количеством сокетов или фильтрующих адаптеров.
- macOS восстанавливает DNS, маршруты и прежний `ip.forwarding` до закрытия `utun`, устраняя
  наблюдавшуюся задержку отключения примерно на 20 секунд.
- Начальные правила Windows kill-switch и обновление DDNS/roaming allowlist стали транзакционными.

### Безопасность, управление и диагностика

Backup/restore проверяет реальное содержимое tar, учитывает активные users/config/identity/TLS внутри
`/etc/qeli`, исключает историю восстановления и legacy-ключ панели, нормализует права. Смешанная inline
и внешняя база пользователей сохраняет прежний приоритет. Новые Argon2id-хеши создаются единым
закреплённым профилем с новой солью, а существующие хеши продолжают работать. Telegram/webhook,
notification cache и desktop-хранилища не перезаписывают повреждённое состояние; macOS использует
версионированный аутентифицированный AES-256-GCM envelope.

В свойствах соединения Android/iOS показаны фактически согласованные Recordizer, roaming, семейство
туннеля и внешний carrier endpoint. Логи отдельно показывают загруженный transport ABI `1.15` и его
compatibility floor. В панели улучшены placeholder, IPv6-карточки идентичности и QR-код; iOS получил
более понятное управление профилями и fail-closed диагностику entitlements установленной подписи.

### Как обновляться

1. Сначала обновите сервер, выполните `qeli check-config`, затем перезапустите службу.
2. Обновляйте приложения вместе с вложенными native cores; не подменяйте ядро 0.8.1 старым файлом.
3. Оставьте `routing.ipv6.ndp_proxy = off`, если провайдер не ищет адреса клиентов через NDP. Сначала
   используйте `auto`; `required` включайте только после проверки uplink и поведения провайдера.
4. Перед импортом больших списков прочитайте обновлённый раздел
   [`route_file`](https://github.com/litvinovtd/qeli/blob/v0.8.1/docs/ru/manuals/CONFIG.md#как-подключить-и-заполнить-route_file).
5. Universal-архив macOS подписан ad-hoc и не нотарифицирован Apple. Для macOS per-app по-прежнему
   требуется отдельно подписанное Developer ID system extension; в этот архив оно не входит.

Настройка IPv6/NDP описана в [руководстве IPv6](https://github.com/litvinovtd/qeli/blob/v0.8.1/docs/ru/manuals/IPV6.md).

---

## Artifacts · Артефакты

The qeli 0.8.1 release set contains 17 payloads plus `SHA256SUMS`. Набор релиза qeli 0.8.1
содержит 17 payload-файлов и `SHA256SUMS`.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.8.1.apk` | 9.41 MiB | `9cb1ba592297bd6f` |
| `qeli-linux-amd64` | 12.19 MiB | `c9d35e92b93bf826` |
| `qeli_0.8.1_amd64.deb` | 3.89 MiB | `cee6d7ebf6f3f964` |
| `Qeli-macOS-universal.zip` | 55.33 MiB | `b90d2c5070f8d600` |
| `QeliWin-net-required.exe` | 7.64 MiB | `570ba3b32c323099` |
| `QeliWin-standalone.exe` | 69.37 MiB | `9f2bb61f59a47c5f` |
| `qeli-client-keenetic-aarch64` | 3.82 MiB | `629ce39516bedd6b` |
| `qeli-client-keenetic-mipsel` | 5.47 MiB | `94ff36b7008068af` |
| `qeli-client-openwrt-aarch64` | 3.82 MiB | `629ce39516bedd6b` |
| `qeli-client-openwrt-armv7` | 3.98 MiB | `8299c0028ac6fe2f` |
| `qeli-client-openwrt-mipsel` | 5.47 MiB | `94ff36b7008068af` |
| `qeli-client-openwrt-x86_64` | 4.48 MiB | `40ed98f6706e6bc2` |
| `qeli-openwrt-files.tar.gz` | 12.65 KiB | `b6c9532b15d1d784` |
| `install-keenetic.sh` | 2.26 KiB | `fa12354977d6a81e` |
| `Wintun-LICENSE.txt` | 5.22 KiB | `9aaf948856ce8845` |
| `WinDivert-LICENSE.txt` | 59.91 KiB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.32 KiB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полное совпадение этих пар является ожидаемым: это один client-only musl бинарник
для соответствующей архитектуры.

### Build verification · Проверка сборки

The Rust native cores were rebuilt twice independently and matched byte-for-byte for Android
arm64-v8a/x86_64, Windows x64 and macOS universal2. The Linux release gate passed formatting,
jemalloc, clippy, dependency policy, conformance, **1041 Rust tests** (3 ignored), 4 CLI tests and
8 configuration examples. The signed Android APK, Windows self-tests, 19 ad-hoc signed macOS Mach-O
files and all four OpenWrt targets passed their build/format checks. `SHA256SUMS` covers every payload.

Rust native cores независимо пересобраны дважды и совпали побайтно для Android arm64-v8a/x86_64,
Windows x64 и macOS universal2. Linux release gate прошёл fmt, jemalloc, clippy, dependency policy,
conformance, **1041 Rust-тест** (3 ignored), 4 CLI-теста и 8 примеров конфигурации. Проверены подпись
APK, Windows self-tests, ad-hoc подписи 19 Mach-O и сборка всех четырёх OpenWrt-архитектур.
`SHA256SUMS` покрывает каждый публикуемый файл.