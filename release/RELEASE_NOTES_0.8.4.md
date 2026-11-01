# Qeli 0.8.4 — Windows CLI, Linux ARM64 и улучшения транспорта

## Русский

Qeli 0.8.4 расширяет выпуск 0.8.3: добавляет полноценный консольный клиент
Windows и серверные сборки Linux ARM64, улучшает сетевые адаптеры, мобильную
диагностику, UDP и Recordizer. Сохранены отдельные поставки Android, Windows GUI,
macOS, OpenWrt и Keenetic.

Главные направления — автоматизация Windows без GUI, переносимая поставка Linux
для двух архитектур, batching без искусственного ожидания новых пакетов и
гибридный обмен ключами для opt-in compact REALITY. Это не обещание одинакового
ускорения или одинаковой маскировки во всех сетях.

### Основные изменения

- **Windows CLI:** отдельный `qeli-cli.exe` для CMD, batch и PowerShell 5.1/7.
  Запуск VPN в терминале, управление службой, INI validation, status/wait/logs,
  JSON-ответы и коды завершения. GUI, CLI и служба используют общий runtime и
  защиту от одновременного владения сетевым состоянием.
- **Linux ARM64:** серверный бинарник и `.deb` наравне с amd64. Обе архитектуры
  собираются с jemalloc и целевым glibc 2.28; архитектура и содержимое пакета
  проверяются, а не определяются только именем файла.
- **Windows и macOS:** режимы постоянного Wintun в Windows — off, per-profile,
  global; выбор auto/фиксированного `utunN` в macOS. Уточнены восстановление
  сетевого состояния, блокировки и диагностика ошибок; добавлены исправления
  трея, размещения окон, истории трафика и discovery bindings своего Wintun.
- **macOS GUI:** программная отрисовка Avalonia/Skia (`Software`) без выбора
  OpenGL/Metal. Цель — уменьшить память аппаратного рендерера; расход 170 МБ
  не является измеренным результатом или гарантией. Фактические RAM/CPU
  требуют проверки на Mac; транспорт и launchd-служба не меняются.
  Журнал обновляется пакетно, без undo/redo-копий; скрытое окно приостанавливает
  UI-обновления, но не VPN и сбор логов.
- **UDP и Recordizer:** фактическая диагностика RX/TX-буферов; `prefer` и
  `opportunistic` по умолчанию. Linux-пакет настраивает минимальные системные
  UDP-лимиты для auto-режима. Явные off/required/timed остаются доступны.
  `opportunistic` не ждёт новые пакеты ради batching; это не обещание одинаковой
  маскировки трафика или прироста скорости в любой сети.
  Уточнение PMTU до байта учитывает внешний путь отдельно от внутреннего TUN MTU;
  повторная проверка уже известного размера требует меньше служебных echo.
- **Мобильные клиенты:** Android/iOS сохраняют лог неуспешного подключения,
  включая SERVER KEY MISMATCH, после повторного открытия приложения. Обычный Stop
  сохраняет настройку автоматической очистки; отчёт последней ошибки — отдельный
  opt-in. В Android исправлен Ping активного VPN: ICMP RTT через туннель вместо
  проверки порта на внутреннем шлюзе; запрет ICMP означает «RTT недоступен»,
  а не ложный отказ VPN. В iOS добавлены диагностика и выключенная по умолчанию
  автопроверка, исправления DNS/roaming/split tunnel и QR через AVFoundation.
- **REALITY/obfs:** единый обработчик compact/split ClientHello в клиентах,
  отделение WebSocket Host от TLS SNI. Для opt-in compact реализован обязательный
  внутренний гибридный обмен `INNER_PQ_V1` (X25519 + ML-KEM-768) до передачи
  credentials, с привязкой transcript и pinned-идентичности, без автоматического
  downgrade. TCP/UDP pins разделены: разные ключи на одном числовом порту больше
  не конфликтуют, проверка явного ключа и защита старых TOFU-записей сохранены.
- **Сервер и сценарии:** настройки NDP, повтор идемпотентного `post_up` после
  полного Linux reconnect для цепочки A → B, расширенные инструкции сценариев,
  dual-stack, Windows CLI, OpenWrt и iOS MDM. Сохранение usage/fsync вынесено
  из обычного Tokio-пути без отключения долговечности статистики.
- **Keenetic/Entware:** клиентский режим совместимости с ядрами без
  `CONFIG_NET_NS`, с сохранением журнала и блокировок восстановления. DNS остаётся
  у прошивки; чужие глобальные sysctl не меняются, строгие Linux-проверки сохранены.
- **Размер Rust CLI:** оригинальные лицензии хранятся в детерминированном
  LZ4-комплекте; `licenses --file` / `--export` возвращают исходные тексты
  с проверкой SHA-256. В сетевом тракте декодер не вызывается.

### Установка и совместимость

Windows GUI по-прежнему поставляется отдельными EXE: `QeliWin-net-required.exe`
и `QeliWin-standalone.exe`. Новый CLI — в
`qeli-cli-windows-x64-net-required.zip` и `qeli-cli-windows-x64-standalone.zip`:
**распакуйте весь архив**, а не один EXE. CLI net-required требует .NET 10 Runtime,
но не WPF/Desktop Runtime; standalone включает runtime. Устанавливать службу
нужно из защищённого каталога, а `run`/управление службой требуют администратора.

Для compact REALITY сначала обновите сервер, затем клиенты с новым native core.
Новый compact-клиент не подключается к серверу без `INNER_PQ_V1` и не переключается
скрыто на legacy. Обычный noncompact REALITY сохраняет прежний путь. Защита
личности остаётся классической; постквантовая аутентификация и независимый
криптографический аудит реализации не заявляются.

Проверяйте скачанные файлы по `SHA256SUMS`. Автоматические тесты и воспроизводимая
сборка не заменяют физические Windows install/exit/reboot, macOS/iOS и роутерные
испытания; не выполненные аппаратные проверки не считаются успешными.

### Статус черновика

Это описание изменений исходников `dev`, не новая сертификация готовых файлов.
Изменения macOS GUI и Android Ping добавлены после ранее квалифицированного
комплекта: перед публикацией для них нужны актуальные пакеты и проверки.
Датированные результаты ниже относятся только к указанному SHA Linux-бинарника,
а не ко всем приложениям или любому более позднему коммиту. Релиз пока не опубликован.

Подробнее: [изменения](https://github.com/litvinovtd/qeli/blob/v0.8.4/CHANGELOG.md),
[Windows CLI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/manuals/WINDOWS-CLI.md),
[macOS GUI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/manuals/MACOS-GUI.md),
[UDP-буферы](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/manuals/UDP-BUFFERS.md),
[compact REALITY](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/reference/REALITY-INNER-PQ.md),
[сценарии](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/scenarios/README.md).

## English

Qeli 0.8.4 builds on 0.8.3 with a full Windows console client, Linux ARM64 server
packages, adapter controls, mobile diagnostics and UDP/Recordizer improvements.
Android, Windows GUI, macOS, OpenWrt and Keenetic remain separate distributions.

The main themes are Windows automation without a GUI, portable Linux packages
for two architectures, batching without waiting for new packets, and a hybrid
key exchange for opt-in compact REALITY. Universal speed gains or identical
traffic camouflage across networks are not promised.

### Highlights

- **Windows CLI:** a separate `qeli-cli.exe` for CMD, batch and PowerShell 5.1/7:
  foreground VPN, service control, INI validation, status/wait/logs, JSON output
  and exit codes. GUI, CLI and service share the Windows runtime and exclusive
  network-state ownership safeguards.
- **Linux ARM64:** server executable and `.deb`, alongside amd64. Both target
  glibc 2.28 with jemalloc; gates verify ELF architecture and package payloads.
- **Windows/macOS:** off/per-profile/global persistent Wintun policies on Windows,
  auto or fixed `utunN` on macOS; recovery/ownership safeguards and improvements
  to tray information, window positioning, traffic history and Wintun discovery
  bindings.
- **macOS GUI:** Avalonia/Skia software rendering (`Software`) without selecting
  OpenGL/Metal. This aims to reduce hardware-renderer memory; 170 MB is neither
  a measured result nor a guarantee. Actual RAM/CPU require testing on a Mac;
  the transport and launchd service are unchanged.
  Logs are updated in batches without undo/redo copies; a hidden window pauses
  UI updates, not the VPN or log collection.
- **UDP/Recordizer:** actual RX/TX buffer diagnostics, default `prefer` and
  `opportunistic`, Linux package UDP limits supporting auto mode. Explicit
  off/required/timed settings remain available. Opportunistic batching does not
  wait for new packets; equal traffic camouflage or universal speed gains are
  not promised.
  Byte-precise PMTU discovery separates the outer path from the inner TUN MTU;
  rechecking a known size uses fewer maintenance echoes.
- **Mobile clients:** Android/iOS retain failed-connection logs, including
  SERVER KEY MISMATCH, across reopening the app. Normal Stop retains the
  auto-clear preference; last-error reports require separate opt-in. Android
  active-VPN Ping uses tunnel ICMP RTT, not a port check at the internal gateway;
  blocked ICMP means RTT is unavailable, not a false VPN failure. iOS adds
  diagnostics and default-off auto-probing, DNS/roaming/split-tunnel fixes,
  and AVFoundation QR scanning.
- **REALITY/obfs:** shared compact/split ClientHello handling, separate WebSocket
  Host and TLS SNI. Opt-in compact requires the transcript- and identity-bound
  `INNER_PQ_V1` hybrid exchange (X25519 + ML-KEM-768) before credentials, without
  automatic downgrade. TCP/UDP pins are distinct: different keys on the same
  numeric port no longer conflict; explicit-key and legacy TOFU checks remain.
- **Server/docs:** NDP controls, idempotent `post_up` after a full Linux reconnect
  for chained servers, expanded scenarios, dual-stack, CLI, OpenWrt and iOS MDM
  manuals. Usage persistence/fsync moves off the normal Tokio path without
  disabling durability.
- **Keenetic/Entware:** compatibility with kernels lacking `CONFIG_NET_NS`,
  retaining recovery journals and locks. Firmware keeps DNS ownership; unrelated
  global sysctls are not changed, and strict Linux checks remain in place.
- **Rust CLI size:** legal resources use deterministic LZ4 storage with exact,
  SHA-256-verified original-text export, outside the networking path.

### Installation and compatibility

Windows GUI remains two single EXEs, net-required and standalone. The new console
packages are `qeli-cli-windows-x64-net-required.zip` and
`qeli-cli-windows-x64-standalone.zip`: **extract the whole archive**. CLI
net-required needs .NET 10 Runtime, not WindowsDesktop; standalone includes it.
Use a protected directory for service installation; foreground VPN and service
control require Administrator.

Upgrade the server before compact REALITY clients. A new compact client refuses
a server without `INNER_PQ_V1`; noncompact REALITY retains the legacy path.
Server identity authentication remains classical. Post-quantum authentication
and an independent cryptographic audit are not claimed.

Verify downloads using `SHA256SUMS`. Automated tests and reproducible builds do
not substitute for physical Windows install/exit/reboot, Apple-platform or router
qualification; unavailable hardware checks are not reported as passed.

### Draft status

This describes `dev` source changes, not renewed qualification of existing files.
The macOS GUI and Android Ping changes postdate the previously qualified package
set and require current packages and checks before publication. Dated results
below cover only the named Linux binary SHA, not every app or later commit.
The release remains unpublished.

Details: [changelog](https://github.com/litvinovtd/qeli/blob/v0.8.4/CHANGELOG.md),
[Windows CLI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/manuals/WINDOWS-CLI.md),
[macOS GUI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/manuals/MACOS-GUI.md),
[UDP buffers](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/manuals/UDP-BUFFERS.md),
[compact REALITY](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/reference/REALITY-INNER-PQ.md),
[scenarios](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/scenarios/README.md).
