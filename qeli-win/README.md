# qeli-win

Нативный Windows-клиент для VPN **qeli** (Quick Easy Link IP): C# / .NET 10 + WPF
как platform/UI слой и общее Rust transport-ядро через ABI 1.11. Rust владеет
DNS/connect, handshake, crypto, TCP/UDP/QUIC/Reality, heartbeat/shaping, bonding и
Wintun session/rings; C# управляет lifecycle/reconnect, созданием интерфейса,
маршрутами/DNS/kill-switch, trust и UI. Только для per-app-профиля C# передаёт
перехваченные WinDivert-пакеты в то же Rust-ядро через общий packet-device ABI.

Режим **`reality-tls`** использует браузероподобный TLS 1.3 и настоящий HTTP/2 carrier:
один streaming POST с ALPN `h2` и случайным batching, без прежнего внутреннего fake-TLS
handshake/framing. Внешний TLS и внутренний qeli AEAD сохраняются. Весь transport выполняет
общее Rust-ядро через P/Invoke — версия попадёт пользователю только после пересборки и
установки exe с обновлённой `qeli.dll`; сервер не обновляет ядро установленного клиента.

## Технологии

| Компонент            | Чем реализовано                                              |
|----------------------|-------------------------------------------------------------|
| TUN-устройство       | Wintun для `apps_mode=all`; WinDivert capture для `include`/`exclude` (обе пары DLL/драйверов вшиты в exe) |
| Transport/crypto     | Rust `qeli.dll`, ABI 1.11 (`qeli_client_run` + native Wintun rings) |
| Conformance/diagnostics | .NET wire/KAT и reachability tools; production fallback отсутствует |
| GUI                  | WPF (.NET 10)                                                |
| Маршруты / DNS / IP  | `iphlpapi` (LUID→index, gateway, `CreateIpForwardEntry2` для маршрутов) + `netsh` / `route` (fallback) |

## Структура

```
qeli-win/
├── QeliWin/
│   ├── Model/         VpnConfig (flat-INI + qeli://), ProfileStore (profiles.json — внутреннее зашифрованное хранилище приложения)
│   ├── Vpn/           Wintun lifecycle, NetworkConfigurator, ABI 1.11 adapter
│   ├── App.xaml(.cs)  точка входа + headless CLI
│   ├── MainWindow.*   интерфейс
│   ├── InputDialog.cs модальный ввод
│   ├── CliRunner.cs   режимы selftest / handshake / connect / genassets
│   ├── Branding.cs    логотип + иконки (GDI+), NativeLoader (вшитый Wintun)
│   ├── wintun/wintun.dll  (встраивается в exe как ресурс)
│   └── windivert/         WinDivert.dll + WinDivert64.sys (встраиваются в exe)
├── dist/              готовые сборки — QeliWin-standalone.exe / QeliWin-net-required.exe
└── ../qeli-shared/    production lifecycle/model + отдельный QeliConformance runner
```

## Запуск

VPN требует прав администратора (создание Wintun-адаптера, изменение маршрутов/DNS).

Из релиза приходят **два варианта приложения** — выберите один. Рядом лежат общие
`Wintun-LICENSE.txt`, `WinDivert-LICENSE.txt` и `WinDivert-NOTICE.txt`; они являются обязательной частью поставки встроенных драйверов:

| Файл | Размер | Что нужно на машине |
|---|---|---|
| `QeliWin-standalone.exe` | ~77 МБ | **ничего** — рантайм вшит (проще всего) |
| `QeliWin-net-required.exe` | ~11 МБ | **.NET 10 Desktop Runtime** |

1. Только для `net-required`: `winget install Microsoft.DotNet.DesktopRuntime.10`.
   Для `standalone` этот шаг пропускается.
2. Скопируйте выбранный файл куда угодно — он самодостаточный (`wintun.dll` вшита и
   распаковывается при старте в `%LOCALAPPDATA%\QeliWin\native`).
3. Запустите его (по запросу UAC согласитесь на повышение прав).
4. Нажмите **Импорт** → вставьте `qeli://`-ссылку или **INI-конфиг** (`[qeli]`-секция) →
   **Подключить**.

> Оба варианта собираются из одного исходника — см. раздел «Сборка из исходников».

Профили сохраняются в `%APPDATA%\QeliWin\profiles.json`.

### Раздельный туннель по приложениям

В редакторе профиля `apps_mode = include` направляет в VPN только выбранные `.exe`,
а `exclude` — все процессы, кроме выбранных. Полные пути хранятся в `apps`; picker
записывает их без потери Android/macOS-идентификаторов, уже присутствующих в переносимом
профиле. WinDivert перехватывает outbound-пакеты, сопоставляет TCP/UDP endpoints с PID и
исполняемым файлом, а затем передаёт выбранные пакеты в обычное Rust-ядро. DNS destination
NAT и fragment affinity не дают DNS и последующим IPv4-фрагментам обойти решение первого
пакета. При reconnect выбранный трафик остаётся fail-closed. Обычные профили этот путь не
включают и работают через прежние нативные Wintun rings.

Настроенный или полученный от сервера tunnel DNS в per-app-профиле применяется ко всем DNS
запросам: Windows обычно выполняет их из общего системного процесса, поэтому привязка к PID
ошибочно отправляла бы DNS выбранного приложения в обход туннеля. IPv4-запрос поддерживает
IPv6 tunnel resolver и наоборот через семейство-преобразующий DNS NAT. На обычный TCP/UDP
эта оговорка не распространяется — он по-прежнему фильтруется по приложению.

### Логотип

Логотип (Q-кольцо `#4A9EFF` с хвостом + зелёный link-узел `#00E676` на тёмно-синем
поле `#16213E`) перенесён из Android-приложения и рисуется единым кодом
(`Branding.cs`, GDI+): иконка окна и панели задач, иконка `.exe` (`Assets\qeli.ico`,
многоразмерная), а также шапка окна. Менять — только в `Branding.cs`.

### Тема, шрифты, уведомления

- **Тема Windows.** Палитра берётся из системной темы (светлая/тёмная) и акцентного
  цвета — читаются из реестра в `ThemeManager.cs` и публикуются как ресурсы
  (`DynamicResource`). Шрифты — Segoe UI Variable.
- **Toast-уведомления.** При подключении/отключении/ошибке снизу справа выезжает
  аккуратное окошко-тостер с логотипом и цветной полосой статуса (`Toast.cs`).
- **Редактор профиля.** «Новый»/«Изм.» открывают прокручиваемую форму, разбитую на
  логические разделы подключения, транспорта, сети и приложений. Полный INI можно открыть кнопкой **«Редактировать INI»**;
  `qeli://`-ссылки и INI-файлы также принимаются через «Импорт».

#### Обфускация в редакторе

Клиентских wire-режима **четыре**: `plain` (сырой TCP без DPI-маскировки),
`fake-tls` (мимикрия TLS 1.3), `obfs` (поток ChaCha20) и `reality-tls`
(настоящий Chrome-TLS 1.3, туннель внутри). `plain` допустим только с TCP.
В форме доступны все клиентские параметры:

| Параметр | Значения |
|----------|----------|
| Wire-режим | plain / fake-tls / obfs / reality-tls |
| SNI | пресеты доменов + произвольный |
| QUIC-маскировка | вкл/выкл (для UDP) |
| Паддинг (маскировка размера) | выкл / стандартный / усиленный / максимальный |
| Heartbeat (keep-alive) | выкл / 15с / 30с / 60с; Reality/H2 принудительно игнорирует |
| Ключ obfs (PSK) | для режима obfs |

`reality-tls` — полноценный клиентский режим (TLS 1.3 + автоматический настоящий H2
через `qeli.dll`). Отдельного `http2-masking` переключателя нет; REALITY bridge/proxy,
fragmentation, traffic-normalization и anti-fingerprinting настраиваются сервером.

### Значок в трее

Индикатор в трее — буква **Q**, окрашенная по статусу: 🟢 зелёная — подключено,
🟡 жёлтая — подключение, ⚪ серая — отключено, 🔴 красная — ошибка (тонкий контур
для читаемости на светлой и тёмной панели задач).
Правый клик по значку открывает меню: текущий статус, **Подключить/Отключить**,
подменю **Профиль** (выбор активного конфига; при переключении на лету во время
активного соединения происходит переподключение к выбранному), **Открыть окно**,
**Выход**. Двойной клик по значку открывает окно. Кнопка «закрыть» (крестик) и
сворачивание прячут приложение в трей — оно продолжает работать; полностью выйти
можно только через пункт **Выход**.

## Настройки, служба Windows, автозапуск

Доступны через значок-шестерёнку в окне или пункт **«Настройки…»** в меню трея
(`AppSettings` → `%APPDATA%\QeliWin\settings.json`).

### Служба Windows (постоянный VPN до входа в систему)

Настоящая Windows-служба (`ServiceManager` через Win32 SCM / `ServiceController`,
имя `QeliWinSvc`), запускается одним и тем же exe с аргументом `--service`
(`Program.cs` → `Service/ServiceHost.cs`, generic host + `AddWindowsService`):

- Стартует **при загрузке Windows, до входа пользователя**, под учёткой **LocalSystem**
  (Wintun работает в сессии 0, как у WireGuard).
- Сама поднимает выбранный профиль и переподключается (тот же `VpnTunnel`).
- Обмен с GUI — через файлы в `%ProgramData%\QeliWin` (`service-profile.json`,
  `service-status.json`, `service.log`); GUI опрашивает статус и подтягивает лог,
  а кнопка «Подключить» в этом режиме запускает/останавливает службу.

Включается галочкой «Запускать как службу Windows» + выбор профиля. Требуются права
администратора (приложение уже запускается с ними).

### Остальное

- **Язык** — English / Русский (по умолчанию English, выбор сохраняется,
  переключается в Настройках **на лету** без перезапуска). Локализация: `Loc.cs`
  (словарь + `{l:Loc Key}` markup-extension с живыми биндингами).
- **Toast-уведомления** — вкл/выкл.
- **Запуск приложения при входе** (без службы) — задача в Планировщике (`AutoStartManager`,
  `schtasks /SC ONLOGON /RL HIGHEST` — elevated без UAC-запроса), `--autostart`.
- **Автоподключение при запуске** + профиль, **Запускать свёрнутым в трей**.

> Служба и «автозапуск приложения» — взаимоисключающие способы держать VPN всегда
> поднятым; служба надёжнее (работает до логина и для всех пользователей).

## Сборка из исходников

```powershell
# нужен .NET 10 SDK (winget install Microsoft.DotNet.SDK.10)
dotnet build QeliWin\QeliWin.csproj -c Debug

# ── вариант A: framework-dependent (~11 МБ, нужен .NET 10 Desktop Runtime) ──
# Публикуем варианты в разные каталоги. Глобальный -p:AssemblyName использовать нельзя:
# он наследуется QeliShared через ProjectReference, и NuGet видит два проекта с одним именем.
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true -o dist\net-required
Copy-Item dist\net-required\QeliWin.exe dist\QeliWin-net-required.exe
Copy-Item dist\net-required\Wintun-LICENSE.txt dist\
Copy-Item dist\net-required\WinDivert-LICENSE.txt dist\
Copy-Item dist\net-required\WinDivert-NOTICE.txt dist\

# ── вариант B: сжатый self-contained (~77 МБ, без установки .NET) ──
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o dist\standalone
Copy-Item dist\standalone\QeliWin.exe dist\QeliWin-standalone.exe
```

Wintun DLL вшита в exe как ресурс (`EmbeddedResource`), но `Wintun-LICENSE.txt` и notices WinDivert должны распространяться рядом с обоими вариантами приложения.

## Headless-режимы (для отладки/CI)

Запускать через `dotnet QeliWin.dll <verb>` (хост `dotnet` не требует elevation для
`selftest`/`handshake`; полный `connect` всё равно требует админ):

| Команда                                   | Что делает                                            | Админ |
|-------------------------------------------|-------------------------------------------------------|-------|
| `selftest`                                | WinDivert/Wintun/routes/DNS platform checks            | нет   |
| `windivert-smoke`                         | Открывает и сразу закрывает production WinDivert filter | да    |
| `handshake <link\|ini\|file>`             | TCP/UDP + полное рукопожатие, печатает выданный IP    | нет   |
| `connect <link\|ini\|file> [секунды]`     | Поднимает полный туннель на N секунд                  | да    |

Managed crypto/codec/config KAT и benchmark вынесены из production EXE:
`dotnet run --project ../qeli-shared/QeliConformance -c Release -- selftest` и
`... -- packetbench --ci`.

## Состояние сборки и release gate 0.8.0

Исходный Windows-клиент рассчитан на transport-core ABI 1.11. Закоммиченная `qeli.dll`
относится к воспроизводимому ABI 1.10 baseline из `native-libs/PROVENANCE` и не является
релизным артефактом для текущего дерева. Перед выпуском 0.8.0 обязательно:

- пересобрать `qeli.dll` из финального source и синхронизировать canonical/consumed-копии;
- пройти `native-libs/provenance.py --check`, hash/ABI gates и сборку обоих Windows-пакетов;
- прогнать elevated Wintun full-tunnel, IPv4/IPv6/dual-stack, DNS, kill-switch и reconnect.

Публичный ключ сервера не копируют из этого README. Для каждого сервера получите актуальный
pin командой `qeli show-identity` по доверенному каналу; отключение pinning допустимо только
как осознанная временная диагностика, а не как инструкция для рабочего профиля.
