# Qeli 0.8.5 Beta — UDP PMTU, замена TCP-слотов и политики роутеров

## Русский

В 0.8.5 клиент лучше переживает изменения внешнего UDP-пути, а TCP
переключает загруженный ухудшившийся канал только после проверки кандидата.
Для OpenWrt и Keenetic добавлено экспериментальное управление политиками
уже настроенных сетей; существующая ручная схема остаётся режимом по умолчанию.

### Транспорт

- `udp_payload_size = 0` оставляет автоматическую политику. Значение
  `548..65507` задаёт верхний предел полного внешнего UDP-payload с обёртками
  Qeli, но без заголовков UDP/IP; это не MTU внутреннего TUN. Ручной предел
  отключает активные PMTU-пробы в обе стороны, не отключая DATA_FRAG.
  Для ненулевого значения обновите и клиент, и сервер: режим согласуется
  в защищённом AUTH и подтверждается AuthOK; старый сервер вызывает явный отказ
  до настройки сети. Windows/macOS получили поле редактора, другие клиенты
  сохраняют настройку в INI. OpenWrt UCI/LuCI разделяют предел, probing и TUN MTU.
- При локальном `EMSGSIZE` клиент может снизить действующий бюджет на текущем
  сокете и ограниченно повторить незавершённую запись через DATA_FRAG без
  дублирования отправленного префикса batch. Асинхронное PMTU-уведомление
  не останавливает приём; подходящие по размеру записи не требуют лишнего
  снижения бюджета. Ручной предел и запрет probes сохраняются; обычные ошибки
  carrier по-прежнему допускают восстановление пути. Автоочередь кандидата
  прогревается до платформенного COMMIT с учётом общей резервации памяти.
  Потолок, обнаруженный на старте, сохраняется при последующих пробах
  на том же сокете, даже если ядро затем сообщает больший MTU.
  Для нового носителя бюджет определяется заново.
- Совместимые TCP-профили проверяют доставку на кандидате перед заменой слота.
  Подготовка может идти одновременно с подтверждением сильного ухудшения,
  но не заменяет это подтверждение. Есть ограниченная свежая попытка при
  допустимом зависании подготовки, backoff и дренирование старого канала.
  Для отключения — `QELI_EXPERIMENTAL_TCP_SLOT_PROBE=0`. Не обещаем
  одинаковое восстановление или скорость на всех сетях.
- При быстром обратном TCP-переключении сервер ограниченно ждёт, пока
  предыдущий канал освободит слот, вместо немедленного отказа JOIN.
  Проверки подлинности и свежести остаются обязательными, сетевой формат не меняется.

### Клиенты и сервер

- **OpenWrt/Keenetic:** opt-in владельцы маршрутов и firewall, политики
  `direct` / `vpn_only` / `vpn_fallback` по сети, приоритет WAN и откат
  неподтверждённой политики. Состояние процесса и состояние VPN показываются
  отдельно. Нужны совместимые бинарник и шаблоны/LuCI. Для встроенного режима
  отключите offload, проверьте netns и отдельную защиту VPN-only. На Keenetic
  раннюю защиту настраивает прошивка; OpkgTun сам не включает контроллер.
  Сначала обеспечьте резервный доступ и проверьте трафик с клиентской сети.
- **Windows GUI/CLI/служба:** отдельный бюджет и диагностика привязок своего
  Wintun; ограниченные повторы чтения IPv6 при регистрации интерфейса.
  Активное состояние NUD сохраняется вместо принудительного отключения,
  которое могло вызвать Win32 87. Проверки GUID, readback и отмена сохранены.
  В Linux/Keenetic gateway NAT уточнены ошибки и безопасный повтор при
  временной блокировке xtables. Спасибо **@Singijeon** и **@alviv** за [#69](https://github.com/litvinovtd/qeli/issues/69).
- **Десктопная сборка:** для Windows и macOS закреплён .NET **10.0.15**
  с исправлениями безопасности (SDK 10.0.404). Для `net-required` обновите
  установленный .NET 10 Runtime; автономная сборка использует свой runtime.
- **Web-панель сервера:** импорт по умолчанию раздельный, full-tunnel явный.
  Предпросмотр и сохранение используют один сериализатор; скрытые параметры
  и сетевые черновики не теряются, квота не сбрасывает срок действия.
  Quick Start использует серверный preflight. Состояние, трафик и план
  остаются у каждого исходящего профиля; журнал можно скопировать или
  скачать потоком и после отключения. Устаревший снимок не заменяется нулями.
  Можно переименовать интерфейс этого профиля без ложного конфликта с его
  собственными адресами и маршрутами; чужие интерфейсы по-прежнему защищены.
  Средняя нагрузка за 1, 5 и 15 минут видна целиком на узком экране.
- **Серверный журнал:** запись подключения показывает профиль, клиентский
  адрес, адрес прослушивания, фактический локальный IP:порт и идентификатор
  соединения; для UDP — также индекс входного интерфейса, когда его сообщает
  ядро. Логин появляется после авторизации; пароли и ключи не записываются.
- **Android:** отсутствие опубликованного системой MTU больше не вызывает
  ложный таймаут готовности VPN. Явно несовпадающий MTU отклоняется.
  Частичный wake lock держится только во время попытки подключения, не дольше
  60 секунд, и снимается, когда VPN готов или попытка закончилась.
  Журнал показывает параметры готовности, версию приложения и номер сборки.
- Обновлены модели Android/iOS/Windows/macOS, исходные лицензии и их
  проверяемый каталог; Windows/macOS/Android поставляются с согласованными
  нативными ядрами. Эксперимент прогрева и освобождения TUN-пулов не вошёл.
  Обновлены Rust-зависимости, Android Gradle 9.9.1 и lock Kotlin-зависимостей
  для 2.4.21. Подробности — в changelog.

### Скорость в лаборатории

Бинарник Linux amd64 `e5821a1c…` прошёл **96 TCP-замеров** P1/P4 и
**48 двукратно подтверждённых UDP-ступеней** по всем 12 профилям
(IPv4/IPv6 внутри туннеля, upload/download). Стенд: по 2 vCPU / 2 ГиБ,
Recordizer `required`, batching `opportunistic`.

TCP достиг **2,10 Гбит/с P1** и **1,99 Гбит/с P4**. Пик полезной скорости
UDP-трафика **внутри TCP-туннеля** (`tcp-plain-raw`) — **1,861 Гбит/с**
при заданных **1,875 Гбит/с**, с потерями **0,7180% / 0,7230%** в двух окнах.
На внешнем UDP-транспорте максимум — **1,124 Гбит/с** при заданных
**1,125 Гбит/с** (`udp-padding`, IPv6 upload).
Средний TCP P4 на 1,9% ниже ранней 0.8.4; пик UDP практически совпал с
предыдущей 0.8.5. Это раздельные прогоны, не версионный A/B.

В отдельном A/B для UDP-QUIC IPv6 download обе сборки стабильно прошли
нагрузку **1 000 Мбит/с (3/3)**. При 1 125 Мбит/с обе прошли 1/3, при
1 150 Мбит/с — 0/3 и 1/3 соответственно. В этом профиле и направлении
**регрессия не подтверждена**; эквивалентность сборок тест не доказывает.

[Отчёт: матрицы, SHA, параметры стенда и сравнение версий](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/ru/reports/RELEASE-085-SPEED12-2026-11-25.md)

### Установка и границы проверки

Linux: ELF и .deb для amd64 и arm64, glibc 2.28 и jemalloc.
Windows x64: GUI .NET/standalone и два CLI ZIP; распакуйте весь ZIP и используйте
`qeli-cli.cmd`. Для GUI net-required нужен .NET 10 Desktop Runtime, для CLI —
.NET 10 Runtime. macOS: отдельные архивы Apple Silicon и Intel, macOS 15+,
ad-hoc подпись без нотарификации, без per-app расширения. Android APK — API 28+;
отдельная подписанная iOS IPA не входит. Роутеры: standalone-клиенты и шаблоны
OpenWrt/Keenetic; наличие source-экспорта SDK не означает поставку IPK.

Проверяйте файлы по `SHA256SUMS`. CI и лабораторные проверки не заменяют
физические проверки Wintun/PnP, мобильных переходов и конкретной прошивки.
Generic/null `DnsResolver` ENONET на проверенном API34 остаётся принятым
неисправленным ограничением. Результаты отдельных стендов не обещают
универсального улучшения скорости или устойчивости к DPI.

[Ченджлог](https://github.com/litvinovtd/qeli/blob/v0.8.5/CHANGELOG.md) ·
[Настройки клиента](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/ru/manuals/CONFIG.md) ·
[Роутеры](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/ru/manuals/ROUTER-INTEGRATION.md)

## English

Qeli 0.8.5 improves recovery from changes on the outer UDP path and validates
replacement TCP carriers before switching a degraded, loaded slot.
OpenWrt and Keenetic gain experimental policy controls for existing networks;
manual routing and firewall ownership remain the defaults.

- **UDP:** `udp_payload_size = 0` retains automatic policy; `548..65507`
  sets the complete outer UDP-payload ceiling including Qeli wrappers,
  excluding UDP/IP headers. It is independent of inner TUN MTU, disables
  active probes in both directions, and keeps DATA_FRAG. A nonzero value
  requires updated peers: authenticated AUTH/AuthOK negotiates the mode,
  and an older server is refused before network setup. Windows/macOS have
  editor fields, all clients preserve INI settings, and OpenWrt UCI/LuCI
  keep payload/probing controls separate from TUN MTU.
- **PMTU recovery:** a local `EMSGSIZE` can lower the effective budget on
  the live socket and trigger a bounded retry of an unfinished encrypted
  record without resending the accepted batch prefix. Asynchronous PMTU
  advisories do not stop reception.
  The manual ceiling and probe prohibition are retained. Candidate RX queues
  warm before platform COMMIT under the shared memory budget.
  The ceiling learned during startup is retained on the same UDP socket
  even if a route refresh reports a higher MTU; a new carrier starts afresh.
- **TCP:** prepare a candidate while confirming severe loaded-carrier
  degradation, validate authenticated delivery, recheck evidence, then
  commit and drain the old carrier. Fresh-socket preparation retries and
  backoffs are bounded; uncertain legacy JOIN, identity decisions, probes
  and COMMIT are not replayed. Set `QELI_EXPERIMENTAL_TCP_SLOT_PROBE=0`
  to disable quality-triggered replacement.
- During a rapid TCP switch back, the server briefly waits for the previous
  carrier to release its slot rather than immediately rejecting JOIN.
  Authentication and replay protection remain unchanged; no new wire message is needed.
- **Routers:** separate process and tunnel status; opt-in routing/firewall
  ownership, per-network direct/VPN-only/fallback, WAN priority and
  confirmation with rollback. Use matching client and package/templates.
  Disable offload for managed policies and verify fallback administration.
  Keenetic firmware owns early-boot protection; OpkgTun is separate.
- **Windows and gateway NAT:** owned-Wintun binding diagnostics and bounded
  IPv6 registration reads; preserve active NUD to avoid Win32 87.
  Linux/Keenetic NAT retains the original iptables error and only retries
  a verified transient lock safely. Thanks to **@Singijeon** and **@alviv** for [#69](https://github.com/litvinovtd/qeli/issues/69).
- **Desktop build:** Windows and macOS are pinned to the .NET **10.0.15**
  security update (SDK 10.0.404). Update the installed .NET 10 Runtime for
  `net-required` builds; standalone builds use their bundled runtime.
- **Server panel:** explicit full tunnel, unified INI preview/save, preserved
  drafts and independent quota/expiry edits; server-side Quick Start
  preflight and per-profile diagnostics with copy and streaming log download.
  A profile can rename its owned VPN interface without conflicts against its
  own routes; unrelated interfaces remain protected. Load averages no longer
  truncate on narrow screens.
- **Server connection logs:** include the profile, remote and actual local
  endpoint, listen address and connection ID; UDP also logs the ingress
  interface index when available. Usernames appear after authentication;
  passwords and keys are not logged.
- **Android:** an unreported system VPN MTU no longer causes a false
  readiness timeout; explicit mismatches still fail. The partial wake lock
  is limited to each connection attempt (60 seconds maximum) and is
  released once VPN is ready or the attempt ends. Logs include the readiness
  inputs, version and build number.
- **Dependencies and builds:** refreshed locked Rust dependencies, Android
  Gradle 9.9.1 and Kotlin dependency locks for 2.4.21.
  Client models, legal bindings/catalogue and matched native cores were updated.
  The experimental server TUN-pool warmup/idle trim was reverted.

### Lab throughput

The Linux amd64 build (`e5821a1c…`) completed **96 TCP P1/P4 measurements**
and **48 UDP cells confirmed twice** across all 12 profiles (inner IPv4/IPv6,
upload/download). Each VM had 2 vCPUs / 2 GiB, with Recordizer required and
opportunistic batching.

TCP reached **2.10 Gbit/s P1** and **1.99 Gbit/s P4**. UDP traffic **inside a
TCP tunnel** (`tcp-plain-raw`) peaked at **1.861 Gbit/s** at **1.875 Gbit/s**
offered load, with **0.7180% / 0.7230%** loss in the two windows. On an
outer UDP transport, the best goodput was **1.124 Gbit/s** at **1.125 Gbit/s**
offered load (`udp-padding`, IPv6 upload). Mean TCP P4 was 1.9% below the
early 0.8.4 candidate; peak UDP goodput
was effectively unchanged from the previous 0.8.5 build. These were separate
lab runs, not an interleaved version A/B.

In a separate UDP-QUIC IPv6 download A/B, both builds passed
**1,000 Mbit/s of offered load in all three repeats**. Both passed 1/3 at
1,125 Mbit/s; at 1,150 Mbit/s the older and newer builds passed 0/3 and
1/3. No regression was confirmed for this profile and direction; the test
does not establish equivalence.

[Report: matrices, SHA, lab settings and version comparisons](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/eng/reports/RELEASE-085-SPEED12-2026-11-25.md)

Choose Linux amd64/arm64 ELF or .deb (glibc 2.28, jemalloc), Windows x64 GUI
and complete CLI ZIPs in .NET/standalone variants, macOS 15+ Apple Silicon
or Intel ad-hoc-signed archives, Android API 28+ APK, or router binaries and
templates. Extract the complete Windows CLI archive and use `qeli-cli.cmd`.
No signed iOS IPA, macOS per-app extension or OpenWrt IPK is in this set.
Verify downloads against `SHA256SUMS`. Lab/CI results do not establish physical
adapter, device or firmware coverage; the tested API34 generic/null DNS
ENONET limitation is accepted and remains unfixed.

[Changelog](https://github.com/litvinovtd/qeli/blob/v0.8.5/CHANGELOG.md) ·
[Client settings](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/eng/manuals/CONFIG.md) ·
[Router integration](https://github.com/litvinovtd/qeli/blob/v0.8.5/docs/eng/manuals/ROUTER-INTEGRATION.md)
