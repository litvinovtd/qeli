# qeli-mac

Нативный macOS-клиент для VPN **qeli** (Quick Easy Link IP): C# / .NET 10 + Avalonia
как platform/UI слой и общее Rust transport-ядро ABI 1.16 (compatibility floor 1.16). Rust владеет
DNS/connect, handshake, crypto, TCP/UDP/QUIC/Reality, heartbeat/shaping, bonding и
utun payload; C# управляет lifecycle/reconnect, созданием интерфейса,
маршрутами/DNS/pf, trust и UI.

Готовый комплект 0.8.3 требует **macOS 15 или новее**, Intel x86_64 либо Apple Silicon.
Минимум соответствует [поддерживаемым ОС .NET 10](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md).
Он задаётся в `Info.plist`; упаковщик также проверяет deployment target каждого Mach-O.
Это требование совместимости, а не заявление о выполненном физическом тесте на каждой ОС.

Режим **`reality-tls`** использует браузероподобный TLS 1.3 и настоящий HTTP/2 carrier:
один streaming POST с ALPN `h2` и случайным batching, без прежнего внутреннего fake-TLS
handshake/framing. Внешний TLS и внутренний qeli AEAD сохраняются. Transport выполняет общее
Rust-ядро через whole-client FFI. macOS получит эту логику только после пересборки,
упаковки и установки приложения с обновлённой `libqeli.dylib`; сервер не обновляет клиент.

## Память GUI и журнал (0.8.4)

GUI хранит последние 256 Ки символов журнала на профиль. Нативные сообщения
сразу попадают в потокобезопасный ограниченный буфер, без dispatcher-задачи
на каждую строку. Видимый текст обновляется пакетно раз в 250 мс и только при
изменении; undo/redo отключён, поэтому старые полные копии журнала не удерживаются.
Кнопка копирования берёт свежий текст из буфера, а не последнюю отрисованную копию.
Удаление профиля освобождает его журнал.

При скрытии в трей или минимизации останавливаются обновление текста, статистики
и анимация подключения. Сбор логов и сам VPN не останавливаются. В daemon mode
служба продолжает вести файл журнала, а GUI перечитывает его хвост при возвращении
окна. Скорости после возврата считаются с новой временной базой, без скачка из-за
долгого скрытия. История логов остаётся в пределах того же лимита.

Регрессионные проверки буфера входят в `QeliConformance selftest`.
Проверки реального Avalonia TextBox доступны только в build-tools-сборке:

```sh
dotnet build qeli-mac/QeliMac/QeliMac.csproj -c Release -p:QeliBuildTools=true
dotnet qeli-mac/QeliMac/bin/Release/net10.0/QeliMac.dll ui-memory-selftest
```

Этот self-test не читает профили, не запускает VPN или privileged helpers.
Он проверяет пакетное отображение, отсутствие undo-истории, освобождение старых
текстовых снимков и сохранение сообщений при скрытии/переключении окна.
Это функциональная проверка на headless-хосте, а не измерение RSS на macOS:
фактический выигрыш памяти следует сравнивать на одном Mac при одинаковой нагрузке.

## Технологии

| Компонент             | Чем реализовано                                                       |
|-----------------------|----------------------------------------------------------------------|
| TUN-устройство        | macOS `utun` (PF_SYSTEM kernel-control, P/Invoke в libc)             |
| Transport/crypto      | Rust `libqeli.dylib`, ABI 1.16 (`qeli_client_run` + native utun fd)  |
| Conformance/diagnostics | .NET wire/KAT и reachability tools; production fallback отсутствует |
| GUI                   | Avalonia UI 11 (.NET 10) — кросс-платформенный аналог WPF             |
| Логотип / иконки / трей | SkiaSharp (пути, градиенты, текст → PNG)                            |
| Маршруты / DNS / IP   | global: `route`/`ifconfig`/`networksetup`; per-app: transparent+DNS Network Extension |
| Меню-бар (трей)       | Avalonia `TrayIcon` + `NativeMenu`                                   |
| Служба / автозапуск   | launchd: LaunchDaemon (root, до входа) и LaunchAgent (при логине)    |

## Структура

```
qeli-mac/
├── QeliMac/
│   ├── Model/         VpnConfig (flat-INI / qeli://), AppSettings, ProfileStore, Paths (profiles.json — внутреннее хранилище приложения)
│   ├── Vpn/           UtunDevice lifecycle, NetworkConfigurator, ABI 1.16 adapter
│   ├── native/        libqeli.dylib — whole-client core (universal arm64+x86_64)
│   ├── Service/       ServiceState, ServiceManager (launchd daemon), ServiceHost
│   ├── Styles/        Controls.axaml — стили кнопок/инпутов/списка (палитра темы)
│   ├── App.axaml(.cs) точка входа Avalonia (тема, старт)
│   ├── Program.cs     роутинг: --service → демон, CLI-режимы, иначе GUI
│   ├── MainWindow.*   главное окно
│   ├── ConfigEditorWindow / SettingsWindow / AboutWindow / QrShareWindow / InputDialog / Dialogs
│   ├── Branding.cs    логотип + иконки (SkiaSharp)
│   ├── ThemeManager.cs палитра из системной темы macOS + accent
│   ├── Loc.cs         локализация (en/ru) + {l:Loc Key}
│   ├── TrayController.cs / Toast.cs / AutoStartManager.cs / Ui.cs
│   └── ReachabilityToBrushConverter.cs
├── Info.plist.in      шаблон Info.plist для .app
├── build_dylib.sh     сборка libqeli.dylib из ../qeli (Mac: cargo+lipo; Linux: cargo-zigbuild)
├── build_app.sh       сборка Qeli.app (dylib + publish + .icns + бандл + ad-hoc подпись)
├── per-app/           Swift system extension + controller, XcodeGen project и build gate
├── README.md
└── ../qeli-shared/    production lifecycle/model + отдельный QeliConformance runner
```

В комплекте 0.8.3 используются отдельные приложения: `Qeli-macos-arm64.tar.gz`
для Apple Silicon и `Qeli-macos-x86_64.tar.gz` для Intel. Выберите архив для своего
процессора; установка .NET не требуется. Само Rust-ядро `libqeli.dylib` остаётся
universal2, но ReadyToRun DLL и dependency graph .NET зависят от архитектуры.
Их нельзя объединить с помощью `lipo`.

Экспериментальный `python scripts/build_mac_universal.py` (из корня checkout)
отклоняет разные или отсутствующие в паре `.dll`, `.deps.json` и
`.runtimeconfig.json` до замены прежнего bundle. Обычные RID-specific payloads
0.8.3 такую проверку не проходят: распространяйте два отдельных архива.
Для совместимых managed payloads сборщик также проверяет arm64+x86_64 в каждом
Mach-O; отсутствующий Intel-партнёр, ошибка lipo или неполный результат останавливают
упаковку. Canonical libqeli.dylib должна уже содержать обе архитектуры.
Каждый запуск получает собственный /var/tmp/qeli-mac-build.XXXXXXXX на лабе.
Общий mac-build и кэш входных архивов больше не используются. До SSH проверяются
состав TAR и canonical dylib в обоих payloads, после передачи — SHA всех четырёх
входов (оба TAR, Info.plist.in и иконка). SSH/SFTP закрываются и при ошибках.
Каталог запуска сохраняется для диагностики; его путь выводится в журнал.
Готовый ZIP по-прежнему атомарно заменяет локальный dist-файл после проверки SHA.
Параллельные запуски могут заменить этот локальный файл последними; для сохранения
обоих результатов используй отдельные checkout/output directories.

## Сборка (в лабе — Linux, либо на Mac)

Нужен полный checkout с корневыми `global.json`, `Directory.Build.props`,
`Directory.Build.targets` и `NuGet.Config`. `build_app.sh` выбирает SDK из checkout
даже при запуске из другого каталога. Restore/build/publish проверяют reviewed locks:
отдельно по Debug/Release, portable/osx-arm64/osx-x64, headless build tools и
Linux-host Skia assets. Отсутствующий lock не создаётся обычной сборкой.
Обновлять графы нужно явно через `dotnet restore` с
`-p:QeliUpdateDependencyLocks=true --force-evaluate` и соответствующими параметрами;
коммитить lockfiles вместе с изменением зависимостей.
Подробнее: [SDK и dependency locks](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-SDK-LOCKS.md).

`build_app.sh` — кросс-платформенный: собирает **готовый к запуску архив**
`dist/Qeli-macos-<arch>.tar.gz` целиком в лабе (Linux/CI), без macOS под рукой.

```bash
./build_app.sh             # Apple Silicon (arm64) — по умолчанию
./build_app.sh x86_64      # Intel
```

Что нужно на хосте сборки:

- **.NET SDK 10.0.401** — точная версия в корневом `global.json`; публикует self-contained payload (`dotnet publish -r osx-arm64`).
- **Подписант кода** — на Mac это `codesign` (встроен); в лабе на Linux —
  **`rcodesign`** (`cargo install apple-codesign`). Ad-hoc подпись **обязательна**:
  ядро macOS на Apple Silicon не запускает неподписанный arm64-бинарь.
  Скрипт проверяет наличие codesign или rcodesign до сборки native-ядра и publish.
  Без подписанта завершается с ошибкой, сохраняя прежние bundle и архив.
  Ошибка подписанта также останавливает упаковку и сохраняет прежний архив;
  уже подготовленный bundle в dist при этом может остаться неполным.
- Иконка `.icns` рендерится **в самом приложении** (`genicns`, SkiaSharp) —
  macOS-утилиты `sips`/`iconutil` больше **не нужны**.

`build_app.sh` при первом запуске соберёт нативное whole-client ядро `libqeli.dylib`
(вызовом `build_dylib.sh`), если его ещё нет и рядом лежат Rust-исходники `../qeli`:
на Mac — `cargo` + `lipo`, в лабе на Linux — `cargo-zigbuild` в universal2 (Zig несёт
macOS libSystem-стабы, полный Xcode SDK не нужен). Готовая либа лежит в
`QeliMac/native/` и попадает в бандл рядом с экзешником — `DllImport("qeli")` находит
её автоматически.

Шаги скрипта: publish self-contained → render `.icns` → собрать `Qeli.app`
(`Contents/MacOS` + `Resources/Qeli.icns` + `Info.plist`) → ad-hoc подпись
(codesign/rcodesign) → упаковка в `dist/Qeli-macos-<arch>.tar.gz` (tar сохраняет
бит исполняемости и симлинки). Бандл self-contained: рантайм .NET, Avalonia, Skia и
macOS-CoreCLR — внутри, установка .NET на целевой машине не нужна.

Кросс-сборка в лабе полностью пригодна для обычного `apps_mode = all`, но Apple не разрешает
рабочий Network Extension с ad-hoc подписью. Для per-app-релиза нужен Mac с Xcode/XcodeGen,
Developer ID Application, provisioning profiles для host и system extension и разрешённые
`app-proxy-provider-systemextension` + `dns-proxy-systemextension` entitlement. На таком хосте
передайте `QELI_MAC_SIGN_IDENTITY`, `QELI_MAC_HOST_PROFILE` и
`QELI_MAC_EXTENSION_PROFILE` в `build_app.sh`: скрипт соберёт extension, вложит его в
`Contents/Library/SystemExtensions`, подпишет вложения изнутри наружу и проверит bundle.
Для публичного релиза дополнительно задайте `QELI_MAC_NOTARY_PROFILE` — имя keychain-profile,
созданного `xcrun notarytool store-credentials`: скрипт отправит временный ZIP в Apple,
дождётся результата и выполнит `stapler staple/validate` до упаковки `.tar.gz`.
Ad-hoc сборка намеренно не содержит helper и отклоняет per-app-профиль fail-closed.
Для готового комплекта 0.8.3 минимум macOS 15 действует и для per-app, и для
`apps_mode = all`; per-app дополнительно требует корректно подписанного system extension.

На Mac полученный архив:

```bash
tar -xzf Qeli-macos-arm64.tar.gz
xattr -cr Qeli.app                          # снять карантин Gatekeeper (ad-hoc-подпись)
open Qeli.app                               # GUI
```

> Из исходников вручную (для отладки):
> ```bash
> dotnet build QeliMac/QeliMac.csproj -c Debug
> dotnet run   --project QeliMac -c Debug -- selftest
> ```

## Запуск

> ⚠️ **Первый запуск на macOS — сначала снимите карантин Gatekeeper.** Приложение
> подписано **ad-hoc** (не нотаризовано Apple), поэтому Gatekeeper его блокирует —
> двойной клик / `open Qeli.app` молча не срабатывают или выдают «повреждено / из
> неустановленного источника». Один раз выполните в Терминале:
>
> ```bash
> xattr -cr /Applications/Qeli.app
> ```
>
> (укажите свой путь, если приложение лежит не в `/Applications`). После этого приложение
> открывается обычным двойным кликом.

VPN требует **root** (создание `utun`, изменение маршрутов и DNS) — это аналог UAC в
qeli-win. Есть два способа держать туннель:

1. **launchd-демон (рекомендуется, двойной клик)** — открой `Qeli.app` обычным
   двойным кликом (от своего пользователя), в **Настройках** включи «Запускать как
   демон launchd» и выбери профиль. macOS один раз покажет **системное окно пароля /
   Touch ID** (`do shell script … with administrator privileges`), после чего демон
   ставится в `/Library/LaunchDaemons`, работает от root, стартует при загрузке (до
   входа) и сам переподключается. GUI дальше остаётся обычным пользователем — только
   показывает статус/журнал и кнопкой управляет демоном. **sudo не нужен.**
2. **GUI под sudo** — приложение целиком работает от root (быстро для отладки):
   ```bash
   sudo "dist/Qeli.app/Contents/MacOS/QeliMac"
   ```
   Кнопка «Подключить» поднимает туннель прямо в GUI. Запуск двойным кликом /
   `open Qeli.app` тоже работает, но без прав при «Подключить» появится подсказка —
   используй демон (способ 1) или sudo. (`sudo open Qeli.app` **не** годится: `open`
   запускает приложение от пользователя, а не от root.)

Профили сохраняются в `~/Library/Application Support/Qeli/profiles.json`,
настройки — там же в `settings.json`. Файлы обмена с демоном — в
`/Library/Application Support/Qeli/`.

Зашифрованное хранилище и резервная копия профилей ограничены 16 МиБ:
файл большего размера не загружается и остаётся на диске для проверки.

При одновременном запуске двух экземпляров Qeli устаревший список профилей
не сохраняется. Перезапустите этот экземпляр для загрузки актуального списка.
Файл `profiles.json.lock` согласует запись между экземплярами.

Выбор, создание и миграция ключа согласуются отдельно через `.store.key.lock`
(ожидание чужого владельца — до 1 секунды). При ошибке Keychain используется
только уже сохранённый fallback/recovery key. Если ключ недоступен, а архив
зашифрован, Qeli сообщает ошибку и сохраняет архив на месте; другой ключ
автоматически не создаётся. Fallback и migration journal должны содержать
ровно 32 байта. Конфликт ключей или повреждение файла требуют восстановления,
не замены ключа. JSON-файлы — внутреннее хранилище, конфигурация остаётся INI.

`QeliMac storage-selftest` проверяет этот слой в изолированных временных
каталогах, без обращения к пользовательскому Keychain, профилям и сети.
[Результат этапа Q28](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-STORAGE.md).

Импорт: кнопка **Импорт** → вставьте `qeli://`-ссылку или **INI** (`[qeli]`-секция).
Кнопки **Новый/Изм.** открывают прокручиваемую форму с логическими разделами подключения,
транспорта, сети и приложений; полный INI доступен через явную кнопку **«Редактировать INI»**.

### Раздельный туннель по приложениям

`apps_mode = include` направляет в VPN только указанные code-signing identifier (обычно
bundle ID, например `com.apple.Safari`), `exclude` — все приложения, кроме указанных.
Подписанное system extension объединяет `NETransparentProxyProvider` для TCP/UDP и
`NEDNSProxyProvider` для DNS. Выбранные сокеты привязываются через публичные
`IP_BOUND_IF`/`IPV6_BOUND_IF` к активному qeli `utun`, после чего трафик обрабатывает то же
Rust-ядро ABI 1.16. Невыбранные потоки остаются на системном маршруте/DNS. Во время reconnect
выбранные потоки закрыты fail-closed. Flow API не даёт per-app ICMP; глобальный pf
`kill_switch` в per-app-профиле не включается, иначе он заблокировал бы bypass-приложения.

## Соответствие qeli-win

| qeli-win (Windows)                       | qeli-mac (macOS)                                  |
|------------------------------------------|---------------------------------------------------|
| Wintun (`wintun.dll`)                    | `utun` (kernel-control, libc)                     |
| `netsh` / `route` + iphlpapi             | `ifconfig` / `route` / `networksetup`             |
| WPF                                      | Avalonia UI                                       |
| WinForms `NotifyIcon` (трей)             | Avalonia `TrayIcon` + `NativeMenu` (меню-бар)     |
| GDI+ (`System.Drawing`) логотип          | SkiaSharp                                         |
| Windows Service (`QeliWinSvc`, SCM)      | launchd LaunchDaemon (`ru.qeli.app.daemon`)  |
| Автозапуск через `schtasks` (ONLOGON)    | launchd LaunchAgent (`…autostart`)                |
| Тема/accent из реестра                   | `defaults read -g AppleInterfaceStyle / AppleAccentColor` |
| `requireAdministrator` (UAC)             | root (sudo) либо демон от root                    |
| Whole-client `qeli.dll` (ABI 1.16)       | `libqeli.dylib` (universal, тот же ABI 1.16)      |
| WinDivert per-app capture                | transparent + DNS Network Extension               |

Палитра, темизация (светлая/тёмная + accent), тосты, поиск профилей, индикатор
доступности сервера, спидометр/график трафика, QR-шеринг, локализация (English/Русский,
переключение на лету) — сохранены.

## Headless-режимы (отладка/CI)

```bash
QeliMac network-selftest                 # изолированные pf/DNS/routes/utun-lifetime проверки без root
QeliMac control-selftest                 # изолированные daemon/codec/plist/child-process проверки без root
QeliMac storage-selftest                 # изолированные ключи/архивы, без настоящего Keychain
QeliMac selftest                         # DNS/routes/pf/utun platform checks (без root)
QeliMac pf-selftest-rules /tmp/qeli.pf    # CI: production rules для pfctl parse/load/flush
QeliMac handshake <link|ini|file>        # TCP/UDP + полное рукопожатие, печатает выданный IP
sudo QeliMac connect <link|ini|file> [сек]   # поднимает полный туннель на N секунд (нужен root)
QeliMac genassets <dir>                  # рендер брендовых PNG (использует build_app.sh для .icns)
```

`uishot` и зависимость `Avalonia.Headless` не входят в production-сборку. Для снимков UI
соберите отдельный инструмент: `dotnet build QeliMac/QeliMac.csproj -c Release
-p:QeliBuildTools=true`, затем запустите `QeliMac uishot <dir>`.

Portable crypto/codec/config KAT и benchmark вынесены из production-приложения:
`dotnet run --project ../qeli-shared/QeliConformance -c Release -- selftest` и
`... -- packetbench --ci`. Platform `QeliMac selftest` отдельно проверяет DNS journal,
маршруты, pf-правила, cleanup IPv4/IPv6 utun и Skia renderer.

## Замечания по реализации utun

`utun` на macOS — точка-точка L3-интерфейс ядра. Каждый пакет несёт 4-байтовый
big-endian префикс семейства: `AF_INET = 2` для IPv4 или `AF_INET6 = 30` для IPv6.
`UtunDevice` передаёт descriptor общему Rust-ядру, а ядро снимает этот префикс перед
L3-кодеком и восстанавливает его при записи пакета соответствующего семейства.

Для IPv4 full-tunnel ставятся `0.0.0.0/1` и `128.0.0.0/1`. Активный IPv6-план также
ставит `::/1`, `8000::/1`, более специфичные GUA-маршруты `2000::/4` + `3000::/4` и
ULA `fc00::/7`, чтобы router-advertised маршруты не обошли туннель. Внешний маршрут к
серверу пиннится через физический gateway/interface своего семейства, а все изменения
сети транзакционно откатываются при отключении.

## Общее ядро конфигурации

INI/URI, проверки, defaults и переносимые политики теперь выполняет Rust ABI 1.16.
Модель клиента — тонкая проекция без местного парсера. Для разработки сначала выполните
`python scripts/build_client_core.py --debug` из корня и задайте напечатанный
`QeliNativeCorePath` перед `dotnet build`. Релизные библиотеки требуют штатных A/B-сборок.
Подробности: [единая конфигурация](../docs/ru/plans/CLIENT-CONFIG-CORE.md).

Сверка store 2 октября: [Q25-F210](../docs/ru/plans/AUDIT-DEBT.md). Прямая запись внешнего процесса в encrypted store в обход координации не поддерживается; после правки активного INI требуется явное переподключение.

## Daemon: выбранный профиль и ошибки управления

Connect передаёт снимок точно выбранного профиля и явное намерение подключения.
Обычный Save настроек сохраняет Disconnect; смена профиля сначала завершает Stop,
затем публикует зашифрованную DTO и возобновляет подключение согласно намерению.
Ошибки cleanup сохраняются в Error; до рестарта требуется успешная очистка.
Внешние конфиги только INI; JSON файлов обмена — служебные DTO.

Load daemon не генерирует ключ при отсутствии и не скрывает повреждение профиля.
При утраченном ключе требуется явное повторное сохранение выбранного профиля;
повреждённый ключ/чужая регистрация требуют ремонта администратором. Автоматическая
замена неизвестного ключа запрещена. Устаревший статус означает неизвестное состояние,
а не подтверждённое отключение. Изменение текста launchctl может дать безопасный отказ.

[Проверки и границы Q28 daemon/control](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-CONTROL.md).
Windows host selftests не подтверждают launchd, Darwin locks, utun/pf, Keychain или
Swift Network Extension на Mac; runtime исключён пользователем из текущего аудита.

## pf: настройка и восстановление

Kill-switch требует уже загруженную безусловную ссылку anchor qeli либо com.apple/*.
Проверьте активный ruleset через sudo pfctl -sr. Если ссылки нет, добавьте её через
действующий механизм управления firewall; Qeli не перезагружает /etc/pf.conf сам,
поскольку пустой filter не доказывает отсутствие NAT/rdr/scrub. Чужие quick/pass и
порядок anchors требуют оценки администратором. При disconnect очищаются только
Qeli anchors, глобальный pf остаётся включённым для сохранения чужих references.
Чужой живой владелец/повреждённый recovery journal не снимаются автоматически.

DNS journal сериализует recovery/claim/release, сохраняет более новую внешнюю настройку
и допускает повтор cleanup при ошибке. Удаление адресов и carrier routes подтверждает
ownership/отсутствие; ошибка запроса не означает отсутствие.
[Отчёт Q28 network и границы проверки](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-NETWORK.md).
Генератор pf-selftest-rules не выполняет startup recovery и не трогает firewall.

## per-app: ошибки остановки и handoff

Ошибки down/stop и join guardian сохраняют ответственность за cleanup и выходят
наружу; закрытие utun требует успешного stop. Исчезновение QeliPerAppCtl не означает
успешную очистку: восстановите подписанную сборку или вручную отключите Qeli managers.
Временная служебная DTO передаётся через закрытый каталог; конфиги остаются INI.
perapp-selftest проверяет C# controller/fake helper и настоящие локальные child
processes, не запускает NetworkExtension. Для запуска native policy/registry tests
нужен Mac/Xcode; в текущем аудите это USER SKIPPED.
Сборка per-app принимает только точный dist/per-app-ARCH и отказывает при symlink paths.
[Проверки и оставшийся scope](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-PERAPP.md).

## Forwarding: один владелец и recovery

Обычный utun-профиль с forward=true получает эксклюзивный lease на весь Mac.
Сначала сохраняется исходное состояние IPv4/IPv6, затем подтверждаются sysctl changes.
Второй Qeli forward-профиль отказывает до изменения ядра; сначала остановите первый.
При cleanup failure журнал и ответственность сохраняются для повторной остановки;
закрытие utun отказывает. Root startup восстанавливает только мёртвого владельца.
Не удаляйте recovery journal вслепую. Per-app не приобретает этот глобальный lease.
forwarding-selftest проверяет managed coordinator и временный файл с подменённым sysctl;
это не Darwin runtime. [Проверки и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-FORWARDING.md).

## Guardian: подтверждение готовности и generation

Host/helper/extension используют внутренний state v5 и обновляются одним подписанным bundle.
Сначала остановите старые профили/guardian; legacy state v4 автоматически не перехватывается.
Guardian проверяет parent перед claim и публикует exact token acknowledgement. Ожидание
готовности до 5 секунд; живой child без ack не считается готовым. Heartbeat и manager
operations проверяют owner generation; завершённый stop остаётся tombstone. Если join
отказал после stop, retry только завершает child; новое подключение ждёт retirement.
[Upgrade, проверки и ограничения](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-GUARDIAN.md).
Swift/Xcode/runtime текущим C# selftest не подтверждены и остаются USER SKIPPED.

## Per-app relay: sockets и бюджеты I/O

Native fd/source операции сериализованы одной очередью на relay; published fd закрывается
только cancellation handler. Stop отказывает новой публикации/I/O и завершает release
асинхронно. TCP connect с DNS/кандидатами — 10 секунд; TCP send и весь UDP batch — 5;
DNS query — 2 внутри внешнего бюджета; framework-write watchdog — 10 секунд.
Пустые UDP датаграммы сохраняются. После частичной TCP отправки с timeout нужен новый
stream. Новых INI-ключей нет. [Проверка и ограничения](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-SOCKETS.md).
Swift/Xcode/runtime USER SKIPPED: 20 новых native cases добавлены, но не исполнены.


## DNS/PF identity upgrade и TCP half-close

Новые DNS journals используют schema 2 и UTC start ticks; PF stamps — clock=utc.
Legacy state с живым PID сохраняется даже при изменении timezone; сначала остановите
старые профили/guardian. PID reuse для legacy неоднозначен — требуется ручная проверка,
не слепое удаление journal. Downgrade с активным новым state не поддержан.
TCP app EOF передаёт SHUT_WR, сохраняя server response; remote EOF завершает flow write,
сохраняя outbound. Полный stop — оба EOF или error/cancel/write timeout. Idle timeout
не добавлен. [Итог Q28 и проверки](../docs/ru/reports/audit-0.8.2/AUDIT-Q28-MACOS-INTEGRATION.md):
1248 managed PASS;8 новых Swift directional cases добавлены, но не исполнены.
Mac/Xcode/NE runtime USER SKIPPED;managed selftest не подтверждает физический half-close.


## .NET legal resources

Publish includes the common reviewed NuGet graphs/runtime-pack notices in
`Legal/DotNet/`, alongside `Legal/NativeRust/` and the client MPL text.
Keep the complete `Legal` directory when packaging a distribution. macOS app
assembly places it in `Contents/Resources/Legal/` and validates both bundles before
assembly (Python 3.11+, select executable with `PYTHON`). Embedded Inter fonts
have their own SIL OFL 1.1/copyright, separate from Avalonia code MIT.
Validate and update the bundle as described in [LICENSING](../LICENSING.md).
This is a full reviewed dependency superset, not a per-executable linkage list.

The common `Legal/NativeRust/toolchains/` layer also preserves reviewed Rust
stdlib, Zig, NDK and GCC/MinGW resources. Keep the entire native bundle. Its
source/version catalog is checked offline; matching-source publication and
per-binary runtime linkage remain separate qualification. See [maintenance](../LICENSING.md).
