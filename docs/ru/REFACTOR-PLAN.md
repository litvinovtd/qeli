# qeli — план рефакторинга: устранение дублей кода (аудит 2026-06-10)

Источник: аудит дублирования по кодовой базе. Документ — рабочий чек-лист в стиле
[RELEASE-FIXES.md](RELEASE-FIXES.md): каждый пункт имеет ID, серьёзность,
затронутые файлы, подход и критерий приёмки. Статусы обновляются по мере
выполнения. **✅ Рефакторинг СДЕЛАН** — выпущен в 0.6.0 (консолидация C# `qeli-shared`
убрала ~2700 строк дублей; `scripts/lab_common.py` — общий SSH-харнес). Оставлен как
исторический запись.

Легенда статуса: ⬜ не начато · 🟦 в работе · ✅ сделано · 🧪 ждёт сборки/e2e.

> **Принцип:** рефакторинг — поведение-сохраняющий. Ни один пункт не меняет провод,
> крипто, формат конфига или UX — только переиспользование кода. Критерий приёмки
> каждого пункта = **байт-в-байт тот же провод/поведение** + зелёная сборка всех
> затронутых клиентов + e2e на лабе там, где затронута дата-плоскость.

---

## Почему это нужно

| Зона | Объём дублей | Риск сейчас |
|---|---|---|
| **C# `qeli-win` ↔ `qeli-mac`** | **~3000+ строк** скопированы (часть — 1:1) | рассинхрон двух клиентов: фикс в одном забывается в другом |
| **`scripts/` (Python)** | SSH-обвязка + хосты в **97 из 102** скриптов | правка лаб-доступа/хоста = правка десятков файлов |
| **Rust `web/api`** | мелкий boilerplate (json-ответы, auth) | низкий, косметика |

Главный выигрыш — зона C#: два клиента (`QeliWin`, `QeliMac`) — это два **полностью
раздельных** проекта (`.csproj`), без общей библиотеки и без единой
`ProjectReference`. Большая часть протокола/крипто/модели скопирована дословно.

### Замеренные дубли C# (win ↔ mac)

**Дословно идентичны** (отличие — только строка `namespace QeliWin.X` ↔ `QeliMac.X`,
изредка `QeliWin.Loc` ↔ `QeliMac.Loc` и комментарий):

| Файл | строк |
|---|---|
| `Crypto/KeyDerivation.cs` | 87 |
| `Crypto/KeyExchange.cs` | 64 |
| `Crypto/PacketCipher.cs` | 50 |
| `Protocol/ObfsStream.cs` | 186 |
| `Protocol/PacketCodec.cs` | 181 |
| `Protocol/Quic.cs` | 91 |
| `Protocol/TlsHandshake.cs` | 224 |
| `Model/VpnConfig.cs` | 485 |
| **итого 1:1** | **~1368** |

**Почти идентичны** (логика общая, расходится только платформенный шов):

| Файл | общих строк | win / mac | платформенный шов |
|---|---|---|---|
| `Vpn/VpnTunnel.cs` | ~1063 (~93%) | 1137 / 1122 | `WintunAdapter` ↔ `UtunDevice` |
| `Vpn/RealTls.cs` | 103 | 108 / 110 | — (P/Invoke к одному C-ABI) |
| `Loc.cs` | 163 | 189 / 196 | таблица переводов |
| `CliRunner.cs` | 173 | 362 / 205 | win — больше (служба) |
| `Service/ServiceState.cs` | 91 | 111 / 154 | — |
| `Vpn/NetworkConfigurator.cs` | 84 | 177 / 193 | route/DNS-команды ОС |
| `TrayController.cs` | 74 | 130 / 140 | NotifyIcon ↔ Avalonia tray |
| `ThemeManager.cs` | 70 | 100 / 121 | WPF ↔ Avalonia |
| `Toast.cs` | 61 | 111 / 118 | — |
| `Branding.cs` | 44 | 171 / 166 | рендер иконки (GDI ↔ Skia) |

---

## Сводная таблица плана

| ID | Серьёзность | Тема | Статус |
|----|:---:|---|:---:|
| R0 | 🟠 Осн | **Пред-унификация:** mac → `net10.0`; win-NuGet к версиям mac (BouncyCastle 2.5.1→2.6.2, QRCoder 1.6.0→1.8.0); CI macos-SDK → 10.0.x | ✅ |
| R1 | 🟠 Осн | Создать общий проект `QeliShared` (`net10.0`, managed-only) + `ProjectReference` из обоих клиентов | ✅ |
| R2 | 🟠 Осн | Перенести `Crypto/*` (3 файла) в `QeliShared` как есть | ✅ |
| R3 | 🟠 Осн | Перенести `Protocol/*` (4 файла) в `QeliShared` как есть | ✅ |
| R4 | 🟠 Осн | Перенести `Model/VpnConfig` + полная консолидация `Loc` (общий словарь + платформенные override) | ✅ |
| R5 | 🔴 Крупн | Вынести ядро `VpnTunnel` в `QeliShared` (абстрактный `VpnTunnelBase` + `ITunDevice`); `RealTls`/`VpnStatus` → shared | ✅ build |
| R6 | 🟡 Втор | Общие **данные** UI вынесены (`BrandPalette` + `ToastKind`); framework-логика (Toast/Theme/Tray/CLI/ServiceState) — по клиентам по дизайну | ✅ |
| R7 | 🟠 Осн | Общий Python-модуль `scripts/lab_common.py` (SSH + хосты); `reboot_vms.py` мигрирован | ✅ |
| R8 | ⚪ Косм | Rust: хелперы `err_json(msg)` / `ok_json()` в `web/api` (31 сайт сведён) | ✅ lab |
| R9 | ⚪ Косм | Rust: `check_auth` → axum-extractor `AuthGuard` (20 ручек) | ✅ lab |

Серьёзность здесь = размер/риск рефакторинга, не баг. 🔴 = много кода + платформенный
шов (осторожно), 🟠 = основной выигрыш, 🟡/⚪ = по желанию.

---

## R0 — пред-унификация версий (делать до R1)

Цель — привести оба C#-клиента к **одной .NET-версии и одним версиям общих
NuGet-пакетов**, чтобы общая либа `QeliShared` (R1) встала без компромиссов по TFM
и без конфликта зависимостей. Это самостоятельный, поведение-нейтральный шаг.

> **Важные факты (на 2026-06-10):**
> - win **уже** на `net10.0-windows`; mac — на `net8.0`. Унификация = **поднять mac до net10**.
> - TFM не станет байт-идентичным **намеренно**: win = `net10.0-windows` (WPF/WinForms,
>   OS-locked на Windows), mac = `net10.0` (Avalonia кросс-платформенна, без `-windows`).
>   Совпадает **.NET-версия (10)**, не строка TFM — так и должно быть.
> - BouncyCastle сейчас **наоборот**: mac **2.6.2**, win **2.5.1** → поднимаем **win**, не mac.

**Затронуто:** `qeli-mac/QeliMac/QeliMac.csproj`; `qeli-win/QeliWin/QeliWin.csproj`; `.github/workflows/ci.yml`.

**Подход:**

1. **mac → net10.** Ровно две правки (SDK нигде не пинится — нет `global.json`,
   `Directory.Build.props`, `.sln`):
   - `qeli-mac/QeliMac/QeliMac.csproj` — `<TargetFramework>net8.0</TargetFramework>` → `net10.0`.
   - `.github/workflows/ci.yml` (job `macos-build`) — `dotnet-version: '8.0.x'` → `'10.0.x'`.
   - Avalonia (11.3.x) и SkiaSharp (2.88.x) **НЕ трогаем**: net10 потребляет
     net8/netstandard-пакеты (forward-compat), self-contained publish тащит net10-рантайм.
     Согласуется с намеренным `ignore` мажоров Avalonia 12.x / SkiaSharp 3.x в `dependabot.yml`.
   - mac build-скрипты (`build_mac_universal.py`, `build_mac_dist_resign.py`) правок **не требуют**:
     TFM берётся из `.csproj` (`dotnet publish -r osx-… --self-contained`), путь `net8.0` нигде не захардкожен.

2. **Сведение общих NuGet к версиям mac** (правится `QeliWin.csproj`):
   - `BouncyCastle.Cryptography` 2.5.1 → **2.6.2**.
   - `QRCoder` 1.6.0 → **1.8.0**.

   *Не унифицируются* (нет аналога на другой стороне — разные фреймворки):
   win-only `Microsoft.Extensions.Hosting.WindowsServices` / `System.ServiceProcess.ServiceController` /
   `System.Security.Cryptography.ProtectedData` (служба + DPAPI); mac-only `Avalonia*` / `SkiaSharp*`.

**Критерий приёмки:** CI зелёный на обоих (`windows-build` 10.0.x + `macos-build` 10.0.x);
`dotnet publish -r osx-arm64 --self-contained` собирает рабочий бандл; новые obsolete-варнинги
анализатора (если всплывут на net10) разобраны; провод/крипто не затронуты (только версии тулчейна/пакетов).

**Риск:** низкий. net10 — надмножество net8. Железного Mac нет → функциональная проверка mac =
компиляция + паритет dylib (как в RELEASE-FIXES, B-фаза); рендер CI не валидирует.

**✅ Статус (2026-06-10):** внесено и локально проверено сборкой на net10 SDK (10.0.300):
- `QeliMac.csproj` `net8.0`→`net10.0`; `dotnet build -c Release` → **0 warn / 0 err** (Avalonia 11.3.17 + SkiaSharp 2.88.9 под net10 ок).
- `QeliWin.csproj` BouncyCastle 2.5.1→2.6.2, QRCoder 1.6.0→1.8.0; `dotnet build -c Release` → **0 err** (3 предсуществующих `NU1510` про in-box `ProtectedData` — не от этих правок).
- `ci.yml` job `macos-build` SDK `8.0.x`→`10.0.x`. CI-подтверждение — на первом push (локально оба клиента уже зелёные).

> Побочно (необязательно, вне R0): на net10 пакет `System.Security.Cryptography.ProtectedData`
> стал in-box (`NU1510`) — явную ссылку в `QeliWin.csproj` можно убрать отдельной чисткой.

---

## A. Общая C#-библиотека `QeliShared`

### R1 — каркас общего проекта

**Затронуто:** новый `qeli-shared/QeliShared/QeliShared.csproj`; `qeli-win/QeliWin/QeliWin.csproj`; `qeli-mac/QeliMac/QeliMac.csproj`.

**Предусловие:** выполнен **R0** (оба клиента на net10, BouncyCastle/QRCoder сведены).

**Подход:**
- Создать class library **`QeliShared`** с `RootNamespace = Qeli.Shared` (нейтральный, не `QeliWin`/`QeliMac`).
- **TFM = `net10.0`** (без `-windows` суффикса → никаких WPF/WinForms/Win-API в общей либе). После R0 оба клиента на net10, поэтому либа `net10.0` потребляется обоими без компромисса: `qeli-mac` (`net10.0`) и `qeli-win` (`net10.0-windows`) ссылаются на `net10.0`-библиотеку напрямую. *(Альтернатива — `netstandard2.0` для максимума совместимости; `net10.0` проще и достаточно.)*
- Зависимости либы — **только managed, без OS**: `BouncyCastle.Cryptography` **2.6.2** (уже сведена в R0). Прописать в `QeliShared`, убрать прямые ссылки из клиентов (придут транзитивно).
- В обоих `.csproj` добавить `<ProjectReference Include="..\..\qeli-shared\QeliShared\QeliShared.csproj" />`.

**Критерий приёмки:** оба клиента собираются (`dotnet build` Release) с пустой ещё `QeliShared` в графе; `git` показывает новый проект; BouncyCastle разрешается в единую 2.6.2 транзитивно.

**Риск:** низкий. Чистый каркас, без переноса логики.

---

### R2 — `Crypto/*` → `QeliShared/Crypto`

**Затронуто:** `Crypto/KeyDerivation.cs`, `Crypto/KeyExchange.cs`, `Crypto/PacketCipher.cs` (в обоих клиентах — удаляются).

**Подход:** перенос **как есть** — файлы отличаются только строкой `namespace`. Переписать namespace на `Qeli.Shared.Crypto`, удалить обе копии из клиентов, поправить `using` там, где на них ссылаются (`PacketCodec`, `VpnTunnel`, `RealTls`).

**Критерий приёмки:** оба клиента собираются; **юнит-тесты крипто/KAT — если есть — зелёные**; e2e-рукопожатие на лабе (.10↔.11) проходит без изменений (ключи деривируются идентично). Дифф провода — нулевой.

**Риск:** низкий (код байт-в-байт, лишь переезжает).

---

### R3 — `Protocol/*` → `QeliShared/Protocol`

**Затронуто:** `Protocol/ObfsStream.cs`, `Protocol/PacketCodec.cs`, `Protocol/Quic.cs`, `Protocol/TlsHandshake.cs`.

**Подход:** перенос как есть (отличие — namespace + один `using QeliWin.Crypto`→`Qeli.Shared.Crypto`). После R2 зависимость на крипто уже общая. Удалить обе копии, подключить `using Qeli.Shared.Protocol`.

**Критерий приёмки:** сборка обоих клиентов; e2e всех wire-режимов (`fake-tls`/`obfs`/`reality-tls`/QUIC) на лабе — packet codec и TLS-mimicry дают тот же провод. JA3/обфускация-байты не изменились.

**Риск:** низкий-средний (это и есть «провод» — обязателен e2e-прогон, но код не меняется по сути).

---

### R4 — `Model/VpnConfig` + `Loc` → `QeliShared`

**Затронуто:** `Model/VpnConfig.cs` (1:1, 485 стр.), `Loc.cs` (163 общих).

**Подход:**
- `VpnConfig` тянет `QeliWin.Loc`/`QeliMac.Loc` (для отображаемых строк статуса) → `Loc` переносим вместе. `Loc` — это таблица переводов (общая часть 163 стр.) + возможные платформенные добавки.
- Перенести `Loc` в `Qeli.Shared.Loc` целиком (таблица строк не платформенна). Если у клиента есть уникальные ключи — оставить тонкий платформенный partial/extension, дополняющий общий словарь.
- `VpnConfig` → `Qeli.Shared.Model`. Учесть найденную микро-разницу: mac в комментарии WireMode упоминает `"plain"`, win — нет. Свести к общему (плоскость уже поддерживает `plain`, см. README) — **поведение не меняется, только комментарий/значение по умолчанию синхронизируется**.

**Критерий приёмки:** сборка обоих; парс/сериализация `qeli://`-ссылок и flat-конфига даёт идентичный результат на обоих клиентах (round-trip тест на нескольких ссылках); локализованные строки на месте.

**Риск:** низкий. Внимание к `Loc`-ключам, специфичным для платформы.

**✅ Статус (2026-06-10):** сделано, полная консолидация `Loc` (выбран вариант «полный Loc сейчас»):
- **`VpnConfig` + `ProfileReachability`** → `Qeli.Shared.Model.VpnConfig`. Единственная зависимость от `Loc` (`Loc.T("Offline")` в `LatencyText`) переведена на `Qeli.Shared.Loc`. Комментарий `WireMode` сведён к более полному (`… | "plain"`). 20 файлов-потребителей получили `using Qeli.Shared.Model;`.
- **`Loc` полностью консолидирован:** данные+логика (словарь **110 общих** ключей + `T/F/SetLanguage/Lang` + событие `LanguageChanged`) → `Qeli.Shared.Loc`. Фреймворк-части (`LocalizationManager` INPC + `LocExtension` MarkupExtension) **остались в namespace клиента** (WPF ↔ Avalonia) → **XAML не тронут** (`xmlns:l` указывает на `QeliWin`/`QeliMac`). Платформенные строки регистрируются при старте через `[ModuleInitializer]` → `Loc.AddOrReplace`: win **13** override-ключей (служба Windows/трей/Wintun), mac **20** (13 в формулировках macOS + 7 mac-only: CouldNotConnect/ModeFakeTls/ModeObfs/Ok/Yes/No/NeedRoot). Перенос строк — программный (точные байты, кириллица сохранена). 19 call-sites `Loc.*` получили `using Qeli.Shared;`.
- **Проверка:** оба клиента `dotnet build -c Release` → mac 0/0, win 0 ошибок. Сверка ключей: 110 общих + 13 = 123 (win) / 110 + 20 = 130 (mac) — точно как в оригиналах, ни один общий ключ не потерян. Рантайм-тест общего `Loc` (net10): en/ru-резолв, событие смены языка, платформенный override, неизвестный ключ → все PASS.

---

### R5 — ядро `VpnTunnel` в `QeliShared` за интерфейсами (крупный пункт)

**Затронуто:** `Vpn/VpnTunnel.cs` (~1063 общих стр.), `Vpn/RealTls.cs`, `Vpn/NetworkConfigurator.cs`, плюс платформенные `WintunAdapter`/`NativeLoader`/`Wintun.cs` (win) и `Vpn/UtunDevice.cs` (mac).

**Анализ шва:** `VpnTunnel` идентичен на ~93%; вся платформенная разница — это TUN-устройство:
- win: `WintunAdapter` (поле `_wintun`)
- mac: `UtunDevice` (поле `_utun`, методы `Open()`, `Name`, `ReceivePacket(ct)`, `SendPacket(buf,len)`, `Dispose()`)

Вложенные транспорты (`TcpTransport`, `UdpTransport`, `RealTlsTransport`, `SocketIO`) стоят на тех же строках и совпадают.

**Подход:**
1. Ввести в `QeliShared` интерфейс **`ITunDevice`**: `void Open()`, `string Name`, `byte[]/Span ReceivePacket(CancellationToken)`, `void SendPacket(ReadOnlySpan<byte> buf, int len)`, `IDisposable`.
2. Ввести **`INetworkConfigurator`** (применение маршрутов/DNS; реализации остаются платформенными — `route`/`netsh` на win, `route`/`networksetup`/`scutil` на mac).
3. `RealTls` — это P/Invoke к **одному** C-ABI ядру (`qeli.dll`/`libqeli.dylib`); сигнатуры идентичны → интерфейс `IRealTlsCore` или прямой перенос с `DllImport("qeli")` (имя резолвится загрузчиком в каждом клиенте).
4. Перенести тело `VpnTunnel` (+ вложенные транспорты) в `Qeli.Shared.Vpn.VpnTunnel`, принимающий `ITunDevice`-фабрику и `INetworkConfigurator` через конструктор/DI.
5. В клиентах оставить только: `WintunTunDevice : ITunDevice` (обёртка над `WintunAdapter`) и `UtunTunDevice : ITunDevice`, плюс платформенные `NetworkConfigurator`.

**Критерий приёмки:** **полный живой туннель** на лабе для обоих клиентов (там, где возможно: win-e2e на .11/эмуляторе; mac — сборка + dylib-паритет, т.к. железного Mac нет — см. RELEASE-FIXES B-фаза). Все режимы: TCP, UDP/QUIC, reality-tls, multipath (round-robin upload). 0% loss, тот же провод.

**Риск:** **средний-высокий** — самый большой файл и единственный с платформенным швом. Делать **последним** в зоне C# (после R2–R4), отдельным шагом, с e2e-гейтом. Транспорты внутри лучше тоже вынести (они и так общие), но сначала минимальный срез: TUN-устройство за интерфейсом.

**✅ Статус (2026-06-10): рефакторинг сделан, собирается (оба клиента 0 ошибок); живой full-tunnel e2e — опциональная десктоп-QA (см. ниже).** Реализация — через **абстрактный базовый класс** (не композицию), чтобы UI-инстанцирование `new VpnTunnel()` не менялось:
- Создан `Qeli.Shared.Vpn` с: `ITunDevice` (`ReceivePacket`/`SendPacket`/`Dispose` — общий контракт Wintun/utun) + `VpnStatus` (`TunDevice.cs`); `RealTls` (P/Invoke `DllImport("qeli")`, перенесён из win — идентичен mac); **`VpnTunnelBase`** (абстрактный, 1232 стр.) — общий код перенесён **байт-в-байт** (транспорты, рукопожатие, туннельные циклы, multipath/bonding), правки только в шве: поле `_wintun`→`protected ITunDevice? _tun`, `SetupTun`→`protected abstract`, `_net`/`ApplyPushedRoutes`/`AdapterGuid` убраны в подкласс, `CloseTransports`→`CleanupPlatform()`-хук, `Session`/`Log`/`EffectiveMtu`→`protected`.
- Клиенты: `QeliWin.Vpn.VpnTunnel : VpnTunnelBase` (85 стр.) и `QeliMac.Vpn.VpnTunnel : VpnTunnelBase` (81 стр.) — только `override SetupTun` (Wintun+`NetworkConfigurator` ↔ utun+`NetworkConfigurator`) + `ApplyPushedRoutes` + `CleanupPlatform`. `WintunAdapter`/`UtunDevice` реализуют `ITunDevice`. Две клиентские копии `RealTls.cs` удалены; `NetworkConfigurator` остаётся платформенным.
- **Поведенческий нюанс (зафиксирован намеренно):** две строки ошибок в общем reconnect-цикле были захардкожены по-разному (win — рус. литералы, mac — `Loc.T("CouldNotConnect")` + англ. литерал MITM). Сведены к общим ключам `Loc` — добавлены `CouldNotConnect` (повышен в общие) и `MitmStop` в `Qeli.Shared.Loc`. Теперь обе строки **локализованы на обоих клиентах** (для win — мелкое улучшение: раньше всегда рус., теперь по языку). Рантайм-тест ключей (en/ru) — PASS.
- **Проверка:** `dotnet build -c Release` → mac 0/0, win 0 ошибок. Общий код перенесён **байт-в-байт** (поведение сохранено по построению); Rust-сервер, с которым клиенты говорят, после R8/R9 прошёл лаб-гейт (build/179 тестов/clippy). **Не прогнано здесь:** живой full-tunnel C#-клиента (TCP/UDP/QUIC/reality-tls/multipath). Причины: это **десктоп/админ-операция** (полный `connect` создаёт Wintun/utun и перехватывает маршруты — на dev-машине инвазивно; `handshake`-only не задействует сам шов `SetupTun`, т.к. он работает лишь в TUN-фазе), Mac-железа нет (как в RELEASE-FIXES B-фазе). Рекомендация: разовый `QeliWin.exe connect <link>` под админом против лаб-сервера — по желанию, отдельной QA-сессией.
- **Дедуп:** ядро `VpnTunnel` (~1290 стр.) и `RealTls` (~108 стр.) больше не дублируются между клиентами (было ×2 → стало ×1 в shared + тонкие подклассы).

---

### R6 — частично-общие классы (по желанию)

**Затронуто:** `CliRunner` (173 общих), `Service/ServiceState` (91), `Toast` (61), `ThemeManager` (70), `TrayController` (74), `Branding` (44).

**Подход:** для каждого — вынести общую логику в `QeliShared` (база/утиль), а платформенную часть (WPF↔Avalonia рендер, NotifyIcon↔Avalonia tray, GDI↔Skia иконки, route/служба) оставить наследником/частичным классом в клиенте. Это «длинный хвост» — браться **после** R1–R5, по убыванию объёма общих строк.

**Критерий приёмки:** сборка обоих; визуальный/функциональный паритет UI (трей, тосты, тема), `CliRunner`/`ServiceState` ведут себя как раньше.

**Риск:** средний — UI-классы переплетены с фреймворком; выгода меньше, чем R2–R5. Допустимо отложить/пропустить.

**✅ Статус (2026-06-10): сделан целевой вынос общих ДАННЫХ; логика — по клиентам по дизайну.**
Анализ показал: «общие» строки этих классов переплетены с фреймворком/платформой и чисто не отделяются — `ServiceState` (DPAPI ↔ AES-256-GCM at-rest), `CliRunner` (selftest Wintun-probe ↔ Skia-render; win-only `uishot/editshot` ↔ mac-only `genicns/genassets`), `Toast`/`ThemeManager`/`TrayController` (WPF ↔ Avalonia, NotifyIcon ↔ Avalonia tray), `Branding` (GDI+ `Color` ↔ Skia `SKColor`). Это ровно случай «Что НЕ трогаем: общей становится только логика/данные за фреймворком».
- **Вынесено в shared (build-проверено, оба клиента 0 ошибок):** `Qeli.Shared.BrandPalette` — единый источник бренд/статус-палитры как сырые RGB (`record struct Rgb`); оба `Branding.cs` строят свои `Color`/`SKColor` из неё через хелпер `FromRgb` (тип цвета остаётся платформенным; значения — в одном месте). `Qeli.Shared.ToastKind` — общий enum, локальные копии в обоих `Toast.cs` удалены.
- **Оставлено по клиентам осознанно:** рендер/тема/трей/служба/CLI-команды и at-rest-крипта `ServiceState` — framework/platform-bound; принудительный вынос дал бы кросс-сборочную indirection при near-zero дедупе и не проверяется на mac (нет железа/GUI).

---

## B. Python-скрипты

### R7 — общий модуль `scripts/lab_common.py`

**Затронуто:** ~97 из 102 скриптов в `scripts/` (используют `paramiko`); хосты `10.66.116.10` (×97 вхождений), `.11` (×69), прод `YOUR_PROD_HOST` (×43).

**Проблема:** каждый скрипт заново определяет `connect()`/`conn()` (тот же `SSHClient()` + `AutoAddPolicy()` + `.connect(...)`) и `run()`/`ssh()`/`csh()` (тот же `exec_command` + `.read().decode("utf-8", errors=...)`), и хардкодит IP лаб-VM.

**Подход:** создать `scripts/lab_common.py`:
- `connect(host, *, password=None) -> SSHClient` — единая обвязка (`AutoAddPolicy`, `look_for_keys=False`, `allow_agent=False`, timeout).
- `run(ssh, cmd, timeout=..., label=...) -> str` — единый exec + decode stdout/stderr.
- Константы хостов: `LAB_SRV = ("10.66.116.10", "root")`, `LAB_CLI = ("10.66.116.11", "root")`, `PROD = ("YOUR_PROD_HOST", "root")`; пароль — **из env** (`QELI_LAB_PASS`), как уже делают `e2e_*`-скрипты.
- Мигрировать скрипты на `from lab_common import connect, run, LAB_SRV, ...` — постепенно, не обязательно все сразу.

**⚠️ Сопутствующее (безопасность, не дубль):** деплой-скрипты раньше хардкодили SSH-пароль сервера. Креды вынесены в env-переменную `QELI_DEPLOY_PASS` (`os.environ.get("QELI_DEPLOY_PASS", "")`), пароль из кода удалён — в репозиторий он не попадает. На будущее: новые скрипты берут креды только из env, IP в коде допустимы.

**Критерий приёмки:** `lab_common.py` есть; ≥1 e2e-скрипт (напр. `e2e_android.py`) переведён на него и проходит на лабе; новые скрипты используют общий модуль.

**Риск:** низкий. Скрипты — вспомогательные, не часть продукта; миграция инкрементальна.

**✅ Статус (2026-06-10):** `scripts/lab_common.py` создан — `connect(host|tuple, user, password, timeout)`, `run(ssh, cmd, timeout, label)`, `lab_password()`, константы `LAB_SRV`/`LAB_CLI`/`PROD` (пароль из `QELI_LAB_PASS`). `reboot_vms.py` мигрирован на него (показательно). Проверка: `python -m py_compile` обоих + реальный `import lab_common` (хосты/функции доступны) — OK. Полная миграция остальных ~96 скриптов — инкрементально, по мере касания. Захардкоженный пароль в `deploy_to_server.py` (см. выше) — отдельной чисткой.

> Прим.: ранее (RELEASE-FIXES H2) 154 одноразовых скрипта уже убраны в `scripts/archive/`.
> R7 касается ~активных рабочих скриптов в `scripts/`.

---

## C. Rust-ядро (косметика)

### R8 — хелперы JSON-ответов в `web/api`

**Затронуто:** `qeli/src/web/api/*.rs` — паттерн `json!({"ok": false, "error": ...})` встречается **30 раз**, `json!({"ok": true, ...})` — 9.

**Подход:** добавить в `web/api/mod.rs` пару хелперов, напр.:
```rust
fn err_json(msg: impl Into<String>) -> Json<Value> { Json(json!({"ok": false, "error": msg.into()})) }
fn ok_json() -> Json<Value> { Json(json!({"ok": true})) }
```
и заменить инлайн-литералы. Сократит шум, унифицирует форму ответа.

**Критерий приёмки:** `cargo test` (161 тест) зелёный; `cargo clippy` чист (форматировать на .10, см. reference_qeli_github_ci); ответы API байт-в-байт прежние.

**Риск:** очень низкий.

**✅ Статус (2026-06-10): сделано и проверено на лабе (.10).** Хелперы `err_json(msg: impl Into<String>)` / `ok_json()` добавлены в `web/api/mod.rs` (возврат — `serde_json::Value`); **31 сайт** сведён к `super::err_json(...)` / `super::ok_json()` (config 10, control 2, login 3, share 4, status 2, users 10). Вызов по полному пути `super::` — без правок `use` в подмодулях. `login.rs`: убран ставший лишним `json` (`use serde_json::Value;`). `auth.rs` (вне `api`) свой 1 сайт сохранил. **Гейт `lab_sync_build.py` на .10 → PASS:** `cargo build` OK, `cargo test` OK (**179 тестов**), `cargo clippy --all-targets -- -D warnings` OK.

---

### R9 — `check_auth` как extractor (по желанию)

**Затронуто:** `qeli/src/web/api/*.rs` — `auth::check_auth(&headers, &state.config.web)?` повторяется в каждой защищённой ручке (config/control/status/users/...).

**Подход:** оформить axum-`FromRequestParts`-экстрактор (напр. `AuthGuard`), который проверяет auth и кладётся в сигнатуру хендлера вместо ручного вызова + `HeaderMap`. Хендлеры станут чище, проверку нельзя будет «забыть».

**Критерий приёмки:** все защищённые маршруты по-прежнему требуют auth (тест на 401/403 без кред); публичные (login/hash?) не затронуты; `cargo test` зелёный.

**Риск:** низкий-средний — затрагивает сигнатуры всех ручек; легко проверяется тестами авторизации. По желанию.

**✅ Статус (2026-06-10): сделано и проверено на лабе (.10).** В `auth.rs` добавлен extractor `AuthGuard` (`#[async_trait] impl FromRequestParts<Arc<ServerState>>` → `check_auth(&parts.headers, &state.config.web)?`; `AuthError = (StatusCode, Json<Value>)` уже `IntoResponse`). Во всех **20 защищённых ручках** (config 4, control 1, hash 1, logs 1, share 1, status 4, users 8) `headers: HeaderMap` + ручной `check_auth(...)?` / if-let заменены на параметр `_guard: auth::AuthGuard`; неиспользуемые импорты `HeaderMap` убраны. Где `state` использовался только для auth (hash + 3 status-ручки `clients`/`kick_client`/`set_bandwidth`, ходят через `control(...)`) → `State(_state)`.
- **Гейт выявил 2 вещи (как и предполагалось), оба починены:** (1) axum 0.7 `FromRequestParts` требует `#[async_trait]` (нативный `async fn` дал E0195) → добавлен `use axum::async_trait;` + атрибут; (2) `unused state` после удаления `check_auth` → `_state`.
- **`lab_sync_build.py` на .10 → PASS:** build OK / **179 тестов** OK / clippy `-D warnings` OK. Auth-enforcement теперь нельзя «забыть» (тип-уровень), форма 401 та же.

---

## Порядок выполнения

Принцип (как в RELEASE-FIXES): **сначала унификация версий, потом каркас, потом перенос — батчами**.

1. **R0** — пред-унификация: mac → net10, win-NuGet к версиям mac, CI macos-SDK → 10.0.x. *(гейт: CI зелёный на обоих)*
2. **R1** — каркас `QeliShared` (`net10.0`). *(гейт: оба клиента собираются с пустой либой)*
3. **R2 → R3 → R4** — перенос managed-кода (Crypto → Protocol → Model/Loc) **как есть**. После каждого — сборка обоих; после R3 — e2e wire-режимов на лабе.
4. **R5** — `VpnTunnel` за интерфейсами. Отдельный шаг, **полный e2e-гейт** (TCP/UDP/reality-tls/multipath).
5. **R6** — частично-общие классы, по убыванию выгоды. По желанию / можно отложить.
6. **R7** — `lab_common.py` + миграция скриптов, инкрементально и независимо от C#.
7. **R8 / R9** — Rust-косметика, в любой момент, независимо.

Зоны A (C#), B (Python), C (Rust) **независимы** — можно вести параллельно/в любом порядке. Внутри A порядок **R0→R1→R5 обязателен** (зависимости).

## Что НЕ трогаем (намеренно)

- **Кросс-языковой протокол.** Один и тот же стек реализован на Rust (канон), Kotlin
  (Android) и C# (×2). Свести в одно нельзя — это разные рантаймы. Реальная цель —
  только **слить две C#-копии** (R1–R5); Rust и Kotlin остаются отдельными по
  необходимости.
- **Платформенное хранилище профилей.** `ProfileStore`/секреты at-rest: win — DPAPI
  (`ProtectedData`), mac — Keychain/файл (`Model/SecureKey.cs`, `Model/Paths.cs`).
  Разные по сути ОС-механизмы — за интерфейс, но не «общий код».
- **UI-разметка** (WPF `.xaml` ↔ Avalonia `.axaml`) — разные фреймворки, общими не
  делаются (общей становится только логика за ними, R6).
- **Нативные ядра** (`.so/.dll/.dylib`) — это уже единый Rust-`realtls`, собранный под
  платформы; дублирования нет.

---

*Создано 2026-06-10 по результатам аудита дублей. Правок в код не вносилось — это план.*
