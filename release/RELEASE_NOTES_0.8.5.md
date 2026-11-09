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
- Совместимые TCP-профили проверяют доставку на кандидате перед заменой слота.
  Подготовка может идти одновременно с подтверждением сильного ухудшения,
  но не заменяет это подтверждение. Есть ограниченная свежая попытка при
  допустимом зависании подготовки, backoff и дренирование старого канала.
  Для отключения — `QELI_EXPERIMENTAL_TCP_SLOT_PROBE=0`. Не обещаем
  одинаковое восстановление или скорость на всех сетях.

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
- **Web-панель сервера:** импорт по умолчанию раздельный, full-tunnel явный.
  Предпросмотр и сохранение используют один сериализатор; скрытые параметры
  и сетевые черновики не теряются, квота не сбрасывает срок действия.
  Quick Start использует серверный preflight. Состояние, трафик и план
  остаются у каждого исходящего профиля; журнал можно скопировать или
  скачать потоком и после отключения. Устаревший снимок не заменяется нулями.
- Обновлены модели Android/iOS/Windows/macOS, исходные лицензии и их
  проверяемый каталог; Windows/macOS/Android поставляются с согласованными
  нативными ядрами. Эксперимент прогрева и освобождения TUN-пулов не вошёл.

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
  requires updated peers: authenticated AUTH/ AuthOK negotiates the mode,
  and an older server is refused before network setup. Windows/macOS have
  editor fields, all clients preserve INI settings, and OpenWrt UCI/LuCI
  keep payload/probing controls separate from TUN MTU.
- **PMTU recovery:** bounded retry of an unfinished encrypted record can
  lower the effective budget on the live socket without resending the
  accepted batch prefix. Asynchronous PMTU advisories do not stop reception.
  The manual ceiling and probe prohibition are retained. Candidate RX queues
  warm before platform COMMIT under the shared memory budget.
- **TCP:** prepare a candidate while confirming severe loaded-carrier
  degradation, validate authenticated delivery, recheck evidence, then
  commit and drain the old carrier. Fresh-socket preparation retries and
  backoffs are bounded; uncertain legacy JOIN, identity decisions, probes
  and COMMIT are not replayed. Set `QELI_EXPERIMENTAL_TCP_SLOT_PROBE=0`
  to disable quality-triggered replacement.
- **Routers:** separate process and tunnel status; opt-in routing/firewall
  ownership, per-network direct/VPN-only/fallback, WAN priority and
  confirmation with rollback. Use matching client and package/templates.
  Disable offload for managed policies and verify fallback administration.
  Keenetic firmware owns early-boot protection; OpkgTun is separate.
- **Windows and gateway NAT:** owned-Wintun binding diagnostics and bounded
  IPv6 registration reads; preserve active NUD to avoid Win32 87.
  Linux/Keenetic NAT retains the original iptables error and only retries
  a verified transient lock safely. Thanks to **@Singijeon** and **@alviv** for [#69](https://github.com/litvinovtd/qeli/issues/69).
- **Server panel:** explicit full tunnel, unified INI preview/save, preserved
  drafts and independent quota/expiry edits; server-side Quick Start
  preflight and per-profile diagnostics with copy and streaming log download.
  Client models, legal bindings/catalogue and matched native cores were updated.
  The experimental server TUN-pool warmup/idle trim was reverted.

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
