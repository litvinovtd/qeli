# qeli-win

Нативный Windows-клиент для VPN **qeli** (Quick Easy Link IP): C# / .NET 10 + WPF
как platform/UI слой и общее Rust transport-ядро через ABI 1.8. Rust владеет
DNS/connect, handshake, crypto, TCP/UDP/QUIC/Reality, heartbeat/shaping и bonding;
C# управляет lifecycle/reconnect, Wintun, маршрутами/DNS/kill-switch, trust и UI.

Режим **`reality-tls`** несёт туннель внутри *настоящего* браузерного TLS 1.3
(byte-exact Chrome ClientHello, JA4 `t13d1516h2_8daaf6152771`): qeli-протокол
работает **вложенно** внутри этой TLS-сессии, на проводе DPI видит только реальный
Chrome-handshake. Весь transport, включая внешний TLS-слой, выполняет общее Rust-ядро
через P/Invoke — нативная `qeli.dll` с whole-client ABI, вшитая в exe.

## Технологии

| Компонент            | Чем реализовано                                              |
|----------------------|-------------------------------------------------------------|
| TUN-устройство       | [Wintun](https://www.wintun.net) (`wintun.dll` amd64, **вшита** в exe) |
| Transport/crypto     | Rust `qeli.dll`, ABI 1.8 (`qeli_client_run` + packet seam)   |
| Conformance/diagnostics | .NET wire/KAT и reachability tools; production fallback отсутствует |
| GUI                  | WPF (.NET 10)                                                |
| Маршруты / DNS / IP  | `iphlpapi` (LUID→index, gateway, `CreateIpForwardEntry2` для маршрутов) + `netsh` / `route` (fallback) |

## Структура

```
qeli-win/
├── QeliWin/
│   ├── Model/         VpnConfig (JSON + qeli://), ProfileStore
│   ├── Vpn/           Wintun, NetworkConfigurator, ABI 1.8 adapter
│   ├── App.xaml(.cs)  точка входа + headless CLI
│   ├── MainWindow.*   интерфейс
│   ├── InputDialog.cs модальный ввод
│   ├── CliRunner.cs   режимы selftest / handshake / connect / genassets
│   ├── Branding.cs    логотип + иконки (GDI+), NativeLoader (вшитый Wintun)
│   └── wintun/wintun.dll  (встраивается в exe как ресурс)
├── dist/              готовые сборки — QeliWin-standalone.exe / QeliWin-net-required.exe
└── ../qeli-shared/    lifecycle/model + retained conformance diagnostics
```

## Запуск

VPN требует прав администратора (создание Wintun-адаптера, изменение маршрутов/DNS).

Из релиза приходят **два** файла — выберите один:

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
   **Подключить**. JSON тоже принимается (легаси).

> Оба варианта собираются из одного исходника — см. раздел «Сборка из исходников».

Профили сохраняются в `%APPDATA%\QeliWin\profiles.json`.

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
- **Редактор профиля.** «Новый»/«Изм.» открывают форму с выпадающими списками
  (`ConfigEditorWindow`, без прокрутки) — только настраиваемые поля; сырой
  `qeli://`/JSON по-прежнему через «Импорт».

#### Обфускация в редакторе

Клиентских wire-режима **три**: `fake-tls` (мимикрия TLS 1.3), `obfs` (поток
ChaCha20) и `reality-tls` (настоящий Chrome-TLS 1.3, туннель внутри). Обфускация
шире, и в форме доступны все клиентские параметры:

| Параметр | Значения |
|----------|----------|
| Wire-режим | fake-tls / obfs / reality-tls |
| SNI | пресеты доменов + произвольный |
| QUIC-маскировка | вкл/выкл (для UDP) |
| Паддинг (маскировка размера) | выкл / стандартный / усиленный / максимальный |
| Heartbeat (keep-alive) | выкл / 15с / 30с / 60с |
| Ключ obfs (PSK) | для режима obfs |

`reality-tls` — полноценный клиентский режим (см. выше: настоящий Chrome-TLS 1.3
через `qeli.dll`). REALITY-**proxy**, fragmentation, traffic-normalization,
http2-masking, anti-fingerprinting — **серверные** механизмы, для клиента прозрачны.

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

# ── вариант B: сжатый self-contained (~77 МБ, без установки .NET) ──
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o dist\standalone
Copy-Item dist\standalone\QeliWin.exe dist\QeliWin-standalone.exe
```

Wintun вшит в exe как ресурс (`EmbeddedResource`) — отдельный файл рядом не нужен
ни в одном из вариантов.

## Headless-режимы (для отладки/CI)

Запускать через `dotnet QeliWin.dll <verb>` (хост `dotnet` не требует elevation для
`selftest`/`handshake`; полный `connect` всё равно требует админ):

| Команда                                   | Что делает                                            | Админ |
|-------------------------------------------|-------------------------------------------------------|-------|
| `selftest`                                | Проверки крипто/кодека/парсинга (без сети)            | нет   |
| `handshake <link\|json\|file>`            | TCP/UDP + полное рукопожатие, печатает выданный IP    | нет   |
| `connect <link\|json\|file> [секунды]`    | Поднимает полный туннель на N секунд                  | да    |

## Статус тестирования (2026-08-09)

- ✅ `selftest` — все проверки PASS (X25519 симметричен, HKDF совпадает с RFC 5869,
  ChaCha20-Poly1305 round-trip, PacketCodec + anti-replay, obfs, разбор `qeli://`,
  ClientHello c UDP-паддингом).
- ✅ `scripts/e2e_windows_native.py`: встроенная DLL, ABI 1.8, Rust fake-TLS handshake и
  authenticated NetworkPlan против изолированного lab-профиля → IP `10.63.0.2`.
- ✅ `handshake` против **боевого** сервера `YOUR_PROD_HOST` с пиннингом ключа
  `7ff1c274…2057` (клиент `client1`) → IP `10.9.0.2`.
- ⏳ Полный live data-plane acceptance (Wintun + маршруты + DNS) — реализован, требует
  запуска с правами администратора на реальной машине (UAC), автотест headless
  невозможен.

> Прим.: у тестового сервера `10.66.116.10` ключ идентичности отличается от
> боевого, поэтому для него используйте конфиг **без** пиннинга (`key=` опустить)
> либо подставьте его реальный ключ из `qeli show-identity`.
