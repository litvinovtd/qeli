# qeli-mac

Нативный macOS-клиент для VPN **qeli** (Quick Easy Link IP). Порт Windows-приложения
(`qeli-win`, C#/WPF) на **C# / .NET 10 + Avalonia UI**. Полностью повторяет протокол:
фейк-TLS 1.3 рукопожатие, X25519, HKDF-SHA256, ChaCha20-Poly1305, auth-proof v2 с
привязкой к транскрипту, padding/heartbeat, обфускация `obfs`, маскировка под QUIC для
UDP. Крипто/протокол перенесены **байт-в-байт** из qeli-win и Android-клиента —
совместимы с тем же Rust-сервером `qeli`.

Режим **`reality-tls`** (полноценный REALITY) несёт туннель внутри *настоящего*
браузерного TLS 1.3 (byte-exact Chrome ClientHello, JA4 `t13d1516h2_8daaf6152771`):
qeli-протокол работает **вложенно** внутри этой TLS-сессии, на проводе DPI видит только
реальный Chrome-handshake. Внешний TLS-слой реализован тем же чистым Rust-ядром
`realtls` (`qeli/src/protocol/realtls/`) через FFI — одна нативная либа на все клиенты
(Rust, Android `.so`, Windows `qeli.dll`, macOS `libqeli.dylib`).

## Технологии

| Компонент             | Чем реализовано                                                       |
|-----------------------|----------------------------------------------------------------------|
| TUN-устройство        | macOS `utun` (PF_SYSTEM kernel-control, P/Invoke в libc)             |
| X25519                | BouncyCastle (`Org.BouncyCastle.Math.EC.Rfc7748`)                    |
| ChaCha20-Poly1305     | BouncyCastle (managed, без зависимости от ОС)                        |
| ChaCha20 (`obfs`)     | BouncyCastle `ChaCha7539Engine`                                      |
| HKDF / HMAC / SHA-256 | `System.Security.Cryptography`                                       |
| GUI                   | Avalonia UI 11 (.NET 10) — кросс-платформенный аналог WPF             |
| Логотип / иконки / трей | SkiaSharp (пути, градиенты, текст → PNG)                            |
| Маршруты / DNS / IP   | `route` / `ifconfig` / `networksetup` (с автоматическим откатом)     |
| Меню-бар (трей)       | Avalonia `TrayIcon` + `NativeMenu`                                   |
| Служба / автозапуск   | launchd: LaunchDaemon (root, до входа) и LaunchAgent (при логине)    |

## Структура

```
qeli-mac/
├── QeliMac/
│   ├── Crypto/        KeyExchange, KeyDerivation, PacketCipher   ← перенос 1:1 из qeli-win
│   ├── Protocol/      TlsHandshake, PacketCodec, ObfsStream, Quic ← перенос 1:1
│   ├── Model/         VpnConfig (JSON / qeli:// / INI), AppSettings, ProfileStore, Paths
│   ├── Vpn/           UtunDevice (utun), NetworkConfigurator, VpnTunnel, RealTls (P/Invoke realtls)
│   ├── native/        libqeli.dylib — нативное REALITY-ядро (universal arm64+x86_64)
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
└── README.md
```

## Сборка (в лабе — Linux, либо на Mac)

`build_app.sh` — кросс-платформенный: собирает **готовый к запуску архив**
`dist/Qeli-macos-<arch>.tar.gz` целиком в лабе (Linux/CI), без macOS под рукой.

```bash
./build_app.sh             # Apple Silicon (arm64) — по умолчанию
./build_app.sh x86_64      # Intel
```

Что нужно на хосте сборки:

- **.NET 10 SDK** — публикует self-contained payload (`dotnet publish -r osx-arm64`).
- **Подписант кода** — на Mac это `codesign` (встроен); в лабе на Linux —
  **`rcodesign`** (`cargo install apple-codesign`). Ad-hoc подпись **обязательна**:
  ядро macOS на Apple Silicon не запускает неподписанный arm64-бинарь.
- Иконка `.icns` рендерится **в самом приложении** (`genicns`, SkiaSharp) —
  macOS-утилиты `sips`/`iconutil` больше **не нужны**.

`build_app.sh` при первом запуске соберёт нативное REALITY-ядро `libqeli.dylib`
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

Импорт: кнопка **Импорт** → вставьте `qeli://`-ссылку или **INI** (`[qeli]`-секция);
JSON тоже принимается (легаси). Кнопки **Новый/Изм.** открывают форму редактора с
выпадающими списками (Wire-режим, SNI, QUIC, паддинг, heartbeat и т.д.).

## Соответствие qeli-win

| qeli-win (Windows)                       | qeli-mac (macOS)                                  |
|------------------------------------------|---------------------------------------------------|
| Wintun (`wintun.dll`)                    | `utun` (kernel-control, libc)                     |
| `netsh` / `route` + iphlpapi             | `ifconfig` / `route` / `networksetup`             |
| WPF                                      | Avalonia UI                                       |
| WinForms `NotifyIcon` (трей)             | Avalonia `TrayIcon` + `NativeMenu` (меню-бар)     |
| GDI+ (`System.Drawing`) логотип          | SkiaSharp                                         |
| Windows Service (`QeliWinSvc`, SCM)      | launchd LaunchDaemon (`ru.autocash.qeli.daemon`)  |
| Автозапуск через `schtasks` (ONLOGON)    | launchd LaunchAgent (`…autostart`)                |
| Тема/accent из реестра                   | `defaults read -g AppleInterfaceStyle / AppleAccentColor` |
| `requireAdministrator` (UAC)             | root (sudo) либо демон от root                    |
| REALITY-ядро `qeli.dll` (P/Invoke)       | `libqeli.dylib` (universal, тот же C-ABI realtls) |

Палитра, темизация (светлая/тёмная + accent), тосты, поиск профилей, индикатор
доступности сервера, спидометр/график трафика, QR-шеринг, локализация (English/Русский,
переключение на лету) — сохранены.

## Headless-режимы (отладка/CI)

```bash
QeliMac selftest                         # крипто/кодек/парсинг (без сети, без root) — все PASS
QeliMac handshake <link|json|file>       # TCP/UDP + полное рукопожатие, печатает выданный IP
sudo QeliMac connect <link|json|file> [сек]  # поднимает полный туннель на N секунд (нужен root)
QeliMac genassets <dir>                  # рендер брендовых PNG (использует build_app.sh для .icns)
```

`selftest` проходит все проверки (X25519 симметричен, HKDF совпадает с RFC 5869,
ChaCha20-Poly1305 round-trip, PacketCodec + anti-replay, obfs, разбор `qeli://`/INI,
ClientHello c UDP-паддингом, рендер логотипа Skia).

## Замечания по реализации utun

`utun` на macOS — точка-точка L3-интерфейс ядра. Кадры несут 4-байтовый префикс
семейства адресов (AF_INET = 2, big-endian), который `UtunDevice` срезает при чтении и
добавляет при записи — наружу остаётся «голый» IPv4-пакет, как у Wintun-обёртки.
Полный туннель ставится двумя `/1`-маршрутами (`0.0.0.0/1` + `128.0.0.0/1`) через
интерфейс, как у WireGuard; маршрут к серверу пиннится через физический шлюз, чтобы
зашифрованный трафик не зациклился. Все изменения сети откатываются при отключении.
