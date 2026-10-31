# Qeli 0.8.4

## Русский

Обновление после 0.8.3: консольный клиент Windows, сервер Linux ARM64,
настройки сетевых адаптеров и изменения UDP/Recordizer. Сохранены отдельные
поставки Android, Windows GUI, macOS, OpenWrt и Keenetic.

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
- **UDP и Recordizer:** фактическая диагностика RX/TX-буферов; `prefer` и
  `opportunistic` по умолчанию. Linux-пакет настраивает минимальные системные
  UDP-лимиты для auto-режима. Явные off/required/timed остаются доступны.
  `opportunistic` не ждёт новые пакеты ради batching; это не обещание одинаковой
  маскировки трафика или прироста скорости в любой сети.
- **REALITY/obfs:** единый обработчик compact/split ClientHello в клиентах,
  отделение WebSocket Host от TLS SNI. Для opt-in compact реализован обязательный
  внутренний гибридный обмен `INNER_PQ_V1` до передачи credentials, с привязкой
  transcript и pinned-идентичности, без автоматического downgrade.
- **Сервер и сценарии:** настройки NDP, повтор идемпотентного `post_up` после
  полного Linux reconnect для цепочки A → B, расширенные инструкции сценариев,
  dual-stack, Windows CLI, OpenWrt и iOS MDM.
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

Подробнее: [изменения](https://github.com/litvinovtd/qeli/blob/v0.8.4/CHANGELOG.md),
[Windows CLI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/manuals/WINDOWS-CLI.md),
[UDP-буферы](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/manuals/UDP-BUFFERS.md),
[compact REALITY](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/reference/REALITY-INNER-PQ.md),
[сценарии](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/ru/scenarios/README.md).

## English

An update after 0.8.3: a Windows console client, Linux ARM64 server packages,
adapter controls and UDP/Recordizer changes. Android, Windows GUI, macOS,
OpenWrt and Keenetic distributions remain available separately.

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
- **UDP/Recordizer:** actual RX/TX buffer diagnostics, default `prefer` and
  `opportunistic`, Linux package UDP limits supporting auto mode. Explicit
  off/required/timed settings remain available. Opportunistic batching does not
  wait for new packets; equal traffic camouflage or universal speed gains are
  not promised.
- **REALITY/obfs:** shared compact/split ClientHello handling, separate WebSocket
  Host and TLS SNI. Opt-in compact requires the transcript- and identity-bound
  `INNER_PQ_V1` hybrid exchange before credentials, without automatic downgrade.
- **Server/docs:** NDP controls, idempotent `post_up` after a full Linux reconnect
  for chained servers, expanded scenarios, dual-stack, CLI, OpenWrt and iOS MDM
  manuals. Rust CLI legal resources use deterministic LZ4 storage with exact,
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

Details: [changelog](https://github.com/litvinovtd/qeli/blob/v0.8.4/CHANGELOG.md),
[Windows CLI](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/manuals/WINDOWS-CLI.md),
[UDP buffers](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/manuals/UDP-BUFFERS.md),
[compact REALITY](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/reference/REALITY-INNER-PQ.md),
[scenarios](https://github.com/litvinovtd/qeli/blob/v0.8.4/docs/eng/scenarios/README.md).
