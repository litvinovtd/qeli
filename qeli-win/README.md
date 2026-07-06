# qeli-win

Нативный Windows-клиент для VPN **qeli** (Quick Easy Link IP). Порт логики
Android-приложения (`qeli-android`) на C# / .NET 8 + WPF. Полностью повторяет
протокол: фейк-TLS 1.3 рукопожатие, X25519, HKDF-SHA256, ChaCha20-Poly1305,
auth-proof v2 с привязкой к транскрипту, padding/heartbeat, обфускация `obfs`,
маскировка под QUIC для UDP. Реализован байт-в-байт с Rust-сервером `qeli`.

Режим **`reality-tls`** несёт туннель внутри *настоящего* браузерного TLS 1.3
(byte-exact Chrome ClientHello, JA4 `t13d1516h2_8daaf6152771`): qeli-протокол
работает **вложенно** внутри этой TLS-сессии, на проводе DPI видит только реальный
Chrome-handshake. Внешний TLS-слой даёт общее чистое Rust-ядро `realtls`
(`qeli/src/protocol/realtls/`) через P/Invoke — нативная либа `qeli.dll` (тот же
C-ABI, что у Android `.so` и macOS `libqeli.dylib`), вшитая в exe.

## Технологии

| Компонент            | Чем реализовано                                              |
|----------------------|-------------------------------------------------------------|
| TUN-устройство       | [Wintun](https://www.wintun.net) (`wintun.dll` amd64, **вшита** в exe) |
| X25519               | BouncyCastle (`Org.BouncyCastle.Math.EC.Rfc7748`)           |
| ChaCha20-Poly1305    | BouncyCastle (managed, без зависимости от ОС)               |
| ChaCha20 (`obfs`)    | BouncyCastle `ChaCha7539Engine`                             |
| HKDF / HMAC / SHA-256| `System.Security.Cryptography`                              |
| GUI                  | WPF (.NET 8)                                                |
| Маршруты / DNS / IP  | `iphlpapi` (LUID→index, gateway, `CreateIpForwardEntry2` для маршрутов) + `netsh` / `route` (fallback) |

## Структура

```
qeli-win/
├── QeliWin/
│   ├── Crypto/        KeyExchange, KeyDerivation, PacketCipher
│   ├── Protocol/      TlsHandshake, PacketCodec, ObfsStream, Quic
│   ├── Model/         VpnConfig (JSON + qeli://), ProfileStore
│   ├── Vpn/           Wintun (P/Invoke), NetworkConfigurator, VpnTunnel
│   ├── App.xaml(.cs)  точка входа + headless CLI
│   ├── MainWindow.*   интерфейс
│   ├── InputDialog.cs модальный ввод
│   ├── CliRunner.cs   режимы selftest / handshake / connect / genassets
│   ├── Branding.cs    логотип + иконки (GDI+), NativeLoader (вшитый Wintun)
│   └── wintun/wintun.dll  (встраивается в exe как ресурс)
└── dist/              готовая сборка — один файл QeliWin.exe (Wintun внутри)
```

## Запуск

VPN требует прав администратора (создание Wintun-адаптера, изменение маршрутов/DNS).

1. Убедитесь, что установлен **.NET 8 Desktop Runtime** (на других машинах):
   `winget install Microsoft.DotNet.DesktopRuntime.8`
2. Скопируйте `dist\QeliWin.exe` — **один файл ~7,5 МБ** (framework-dependent:
   рантайм не вшит — отсюда малый размер; `wintun.dll` вшита и распаковывается при
   старте в `%LOCALAPPDATA%\QeliWin\native`). ~7 МБ из них — это BouncyCastle.
3. Запустите `QeliWin.exe` (по запросу UAC согласитесь на повышение прав).
4. Нажмите **Импорт** → вставьте `qeli://`-ссылку или **INI-конфиг** (`[qeli]`-секция) →
   **Подключить**. JSON тоже принимается (легаси).

> Нужен меньший размер без рантайма? Соберите сжатый self-contained (~73 МБ,
> работает без установки .NET) — см. раздел «Сборка из исходников».

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
# нужен .NET 8 SDK (winget install Microsoft.DotNet.SDK.8)
dotnet build QeliWin\QeliWin.csproj -c Debug

# ── вариант A: framework-dependent (~7,5 МБ, нужен .NET 8 Desktop Runtime) ──
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true -o dist

# ── вариант B: сжатый self-contained (~73 МБ, без установки .NET) ──
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o dist
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

## Статус тестирования (2026-06-04)

- ✅ `selftest` — все проверки PASS (X25519 симметричен, HKDF совпадает с RFC 5869,
  ChaCha20-Poly1305 round-trip, PacketCodec + anti-replay, obfs, разбор `qeli://`,
  ClientHello c UDP-паддингом).
- ✅ `handshake` против **тестового** сервера `10.66.116.10` (TOFU) → IP `10.9.0.3`.
- ✅ `handshake` против **боевого** сервера `YOUR_PROD_HOST` с пиннингом ключа
  `7ff1c274…2057` (клиент `client1`) → IP `10.9.0.2`.
- ⏳ Полный data-plane туннель (Wintun + маршруты + DNS) — реализован, требует
  запуска с правами администратора на реальной машине (UAC), автотест headless
  невозможен.

> Прим.: у тестового сервера `10.66.116.10` ключ идентичности отличается от
> боевого, поэтому для него используйте конфиг **без** пиннинга (`key=` опустить)
> либо подставьте его реальный ключ из `qeli show-identity`.
