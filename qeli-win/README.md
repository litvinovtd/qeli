# qeli-win

Консольный клиент для CMD/PowerShell: [CLI (RU)](../docs/ru/manuals/WINDOWS-CLI.md) · [CLI (EN)](../docs/eng/manuals/WINDOWS-CLI.md).

Нативный Windows-клиент для VPN **qeli** (Quick Easy Link IP): C# / .NET 10 + WPF
как platform/UI слой и общее Rust transport-ядро ABI 1.16 (compatibility floor 1.16). Rust владеет
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
| Transport/crypto     | Rust `qeli.dll`, ABI 1.16 (`qeli_client_run` + native Wintun rings) |
| Conformance/diagnostics | .NET wire/KAT и reachability tools; production fallback отсутствует |
| GUI                  | WPF (.NET 10)                                                |
| Маршруты / DNS / IP  | `iphlpapi` (LUID→index, gateway, `CreateIpForwardEntry2` для маршрутов) + `netsh` / `route` (fallback) |

## Структура

```
qeli-win/
├── QeliWin/
│   ├── Model/         VpnConfig (flat-INI + qeli://), ProfileStore (profiles.json — внутреннее зашифрованное хранилище приложения)
│   ├── Vpn/           Wintun lifecycle, NetworkConfigurator, ABI 1.16 adapter
│   ├── App.xaml(.cs)  точка входа + headless CLI
│   ├── MainWindow.*   интерфейс
│   ├── InputDialog.cs модальный ввод
│   ├── CliRunner.cs   режимы selftest / handshake / connect / genassets
│   ├── Branding.cs    логотип + иконки (GDI+), NativeLoader (вшитый Wintun)
│   ├── wintun/wintun.dll  (встраивается в exe как ресурс)
│   └── windivert/         WinDivert.dll + WinDivert64.sys (встраиваются в exe)
├── dist/              publish-каталоги и QeliWin-standalone.exe / QeliWin-net-required.exe
└── ../qeli-shared/    production lifecycle/model + отдельный QeliConformance runner
```

## Запуск

VPN требует прав администратора (создание Wintun-адаптера, изменение маршрутов/DNS).

Для поставки 0.8.3 используются **два single-file EXE** — выберите один.
Оригинальные лицензии Cargo/.NET, MPL/AGPL и Wintun/WinDivert notices встроены
в каждый EXE. Просмотр: **О программе → Лицензии**; там же можно сохранить
комплект текстов в ZIP. Отдельные `Legal/` и license ZIP для запуска не нужны.

| Файл | Что нужно на машине |
|---|---|
| `QeliWin-standalone.exe` | Рантайм включён в EXE |
| `QeliWin-net-required.exe` | **.NET 10 Desktop Runtime** |

1. Только для `net-required`: `winget install Microsoft.DotNet.DesktopRuntime.10`.
   Для `standalone` этот шаг пропускается.
2. Сохраните выбранный EXE в удобный каталог. `wintun.dll` вшита и
   распаковывается перед загрузкой: elevated-приложение и служба используют защищённый
   `%ProgramData%\QeliWin\native\<SHA256-комплекта>`, диагностический запуск без elevation —
   `%LOCALAPPDATA%\QeliWin\native\<SHA256-комплекта>`. Разные комплекты DLL не
   перезаписывают друг друга даже при одинаковом номере версии приложения.
3. Запустите выбранный EXE (по запросу UAC согласитесь на повышение прав).
4. Нажмите **Импорт** → вставьте `qeli://`-ссылку или **INI-конфиг** (`[qeli]`-секция) →
   **Подключить**.

> Оба варианта собираются из одного исходника — см. раздел «Сборка из исходников».

Профили сохраняются в `%APPDATA%\QeliWin\profiles.json`, зашифрованном DPAPI
для текущего пользователя. Это внутренний контейнер приложения; импорт и экспорт
конфигов остаются INI и `qeli://`.

Атомарная перезапись сохраняет предыдущую зашифрованную версию в `.bak`. При
повреждении текущего архива он сначала переносится в `.corrupt-<GUID>`, затем
проверенный backup восстанавливается и вновь шифруется. Если backup также повреждён,
клиент открывает пустой список, сохранив оба файла. Ошибки quarantine, записи миграции
или публикации восстановленного списка останавливают загрузку; исходник не заменяется
пустым архивом. Резервная копия отражает предыдущую запись и может не содержать
последнего изменения.

Зашифрованное хранилище профилей ограничено 16 МиБ: файл большего размера
не загружается и остаётся на диске для ручной проверки или восстановления.

Если открыты два экземпляра Qeli, экземпляр с устаревшим состоянием откажется сохранять
список профилей. Перезапустите его, чтобы заново загрузить актуальные профили.
Файл `profiles.json.lock` используется для согласования записи между экземплярами.

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
- Поднимает выбранный профиль и переподключается (тот же `VpnTunnel`), только если
  сохранено намерение подключения. Отключение записывается до остановки SCM; последующая
  загрузка Windows запускает службу в ожидании, пока пользователь снова не подключится.
- Обмен с GUI — через файлы в `%ProgramData%\QeliWin\service` (`service-profile.json`,
  `service-status.json`, `service.log`); GUI опрашивает статус и подтягивает лог,
  а кнопка «Подключить» меняет сохранённое намерение подключения и запускает/останавливает
  службу. Каталог и файлы проверяются по владельцу, DACL и отсутствию reparse points;
  доступ предназначен только LocalSystem и повышенным администраторам.
- Служебный профиль зашифрован DPAPI LocalMachine; лимит **4 МиБ** включает envelope.
  GUI отказывает до публикации слишком большого или структурно некорректного профиля.
  LocalSystem не загружает plaintext legacy: такой профиль нужно пересохранить через GUI.
  UTF-8 должен быть корректным; status ограничен 64 КиБ, connection flag — 16 байт.

Включается галочкой «Запускать как службу Windows» + выбор профиля. Требуются права
администратора (приложение уже запускается с ними).

### Подготовка старого хранилища при переходе на 0.8.3

Обычный ручной запуск GUI обнаруживает старые служебные файлы в корне
`ProgramData\QeliWin` или недоверенные права и предлагает подготовку с подтверждением.
До согласия штатно отключите VPN, завершите восстановление DNS/маршрутов/firewall,
остановите `QeliWinSvc` и закройте остальные клиенты. При тайм-ауте остановки
продолжать нельзя. GUI требует права администратора; служба и `--autostart`
не выполняют скрытую миграцию.

Старый каталог перемещается без чтения его профиля в уникальную приватную резервную
копию рядом с ним (`QeliWin.backup-<UTC>-<GUID>\legacy`). Новое хранилище создаётся
с закрытыми правами; старые profile/intent/DLL не импортируются. Повторно выберите
доверенный профиль в настройках службы. Пользовательские `%APPDATA%\QeliWin` и
recovery-журналы не перемещаются; автоматическое подключение в этом запуске пропускается.
Резервная копия может содержать секреты — не публикуйте её.

Проверки отказывают при активной службе/другом клиенте/владельце kill-switch,
оставшемся recovery-журнале, правилах `qeli_ks` или Wintun-адаптере; отказ/тайм-аут
проверки тоже блокирует переход. Проверка Wintun консервативна: адаптер другого VPN
также блокирует подготовку; не удаляйте чужие адаптеры и правила ради обхода.
Отсутствие этих объектов не доказывает восстановление произвольных DNS/маршрутов:
пользователь отдельно подтверждает успешное штатное отключение. Старый и новый
клиент не должны одновременно управлять VPN. Тайм-аут завершения за 8 секунд —
отдельный дефект, разнесение каталогов не объявляется его исправлением.

Изолированные регрессии без SCM/сети/реального хранилища:
`dotnet QeliWin.dll selftest-storage`. Полный platform selftest также включает их.

При смене профиля служба сначала останавливается, затем получает проверенный новый
снимок и запускается снова, если до изменения было сохранено намерение подключения.
Обычное сохранение настроек не подключает ранее отключённый VPN. Изменение профиля,
сохранённого для установленной службы, применяет новый снимок с тем же правилом;
изменение другого профиля службу не переключает. Если сохранённый для службы профиль
нужно удалить, сначала отключите службу или выберите другой профиль службы в настройках.

Неудачная остановка запрещает публикацию нового снимка; неудачная публикация оставляет
службу отключённой и сообщает ошибку. Переходы SCM выполняются вне UI-потока;
StartPending и StopPending не считаются подтверждением завершённой остановки.
Это не проверка реального boot/sleep/network runtime.

### Остальное

- **Язык** — English / Русский (по умолчанию English, выбор сохраняется,
  переключается в Настройках **на лету** без перезапуска). Локализация: `Loc.cs`
  (словарь + `{l:Loc Key}` markup-extension с живыми биндингами).
- **Toast-уведомления** — вкл/выкл.
- **Запуск приложения при входе** (без службы) — задача в Планировщике (`AutoStartManager`,
  `schtasks /SC ONLOGON /RL HIGHEST` — elevated без UAC-запроса), `--autostart`.
- **Автоподключение при запуске** + профиль, **Запускать свёрнутым в трей**.

Служба владеет туннелем до входа пользователя. Автозапуск GUI можно включить вместе
с ней: приложение будет показывать состояние службы, а не создавать второй туннель.

Операции автозапуска проверяют код завершения `schtasks` и сообщают ошибки создания
или удаления задачи. Отсутствующая задача допускает повторное отключение. Ошибки
проверки существования не выдаются за отсутствие; сохранение настроек повторяет
применение желаемого состояния после сбоя. Команда имеет бюджет 10 секунд и ограниченный
диагностический вывод; stdout и stderr читаются одновременно. Настройки GUI меняются
в копии и становятся текущими только после успешной атомарной записи файла.
Если применение автозапуска или службы не удалось, сохранённые предпочтения остаются
желаемым состоянием, а предупреждение сообщает о неудаче внешней операции.

## Сборка из исходников

Собирайте из полного checkout: корневые `global.json`, `Directory.Build.props`,
`Directory.Build.targets` и `NuGet.Config` задают SDK, audit и выбор reviewed lockfile.
Обычный restore/build/publish работает в locked mode. Изменение пакетов требует
явного `-p:QeliUpdateDependencyLocks=true --force-evaluate` на restore с теми же
RID и publish-параметрами; изменённые lockfiles проверяются и коммитятся вместе с
исходниками. Single-file варианты используют отдельный lock с SDK ILLink package.
Подробнее: [SDK и dependency locks](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-SDK-LOCKS.md).

```powershell
# нужен .NET SDK 10.0.401: точная версия закреплена в ../global.json
# установка SDK: https://dotnet.microsoft.com/download/dotnet/10.0
dotnet build QeliWin\QeliWin.csproj -c Debug

# ── вариант A: framework-dependent (~11 МБ, нужен .NET 10 Desktop Runtime) ──
# Публикуем варианты в разные каталоги. Глобальный -p:AssemblyName использовать нельзя:
# он наследуется QeliShared через ProjectReference, и NuGet видит два проекта с одним именем.
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained false `
  -p:PublishSingleFile=true -o dist\net-required
if ($LASTEXITCODE -ne 0) { throw "net-required publish failed" }
Copy-Item -LiteralPath dist\net-required\QeliWin.exe -Destination dist\QeliWin-net-required.exe

# ── вариант B: сжатый self-contained (~77 МБ, без установки .NET) ──
dotnet publish QeliWin\QeliWin.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o dist\standalone
if ($LASTEXITCODE -ne 0) { throw "standalone publish failed" }
Copy-Item -LiteralPath dist\standalone\QeliWin.exe -Destination dist\QeliWin-standalone.exe
```

Распространяется только выбранный EXE: полный комплект текстов встроен в сборку.
Просмотр без VPN: `QeliWin-standalone.exe licenses --list` и `licenses --file PATH`.
Экспорт в новый каталог: `QeliWin-standalone.exe licenses --export NEW_DIRECTORY`.
Проверка экспорта из корня: `python scripts/embedded_licenses.py --windows --verify-export NEW_DIRECTORY`.
CI также проверяет точные ресурсы внутри каждого готового EXE, а не только publish-каталог.
См. [обновление комплекта](../LICENSING.md).

## Headless-режимы (для отладки/CI)

Запускать через `dotnet QeliWin.dll <verb>` (хост `dotnet` не требует elevation для
`selftest`/`handshake`; полный `connect` всё равно требует админ):

| Команда                                   | Что делает                                            | Админ |
|-------------------------------------------|-------------------------------------------------------|-------|
| `selftest`                                | DPAPI storage, service ACL/atomic files и WinDivert/Wintun/routes/DNS unit checks | нет |
| `windivert-smoke`                         | Открывает и сразу закрывает production WinDivert filter | да    |
| `handshake <link\|ini\|file>`             | TCP/UDP + полное рукопожатие, печатает выданный IP    | нет   |
| `connect <link\|ini\|file> [секунды]`     | Поднимает полный туннель на N секунд                  | да    |

`selftest` использует собственные временные файлы для DPAPI и не меняет профили
пользователя, SCM или сетевые настройки. Загрузка Wintun DLL не подтверждает установку
драйвера или реальное VPN-подключение.

Managed crypto/codec/config KAT и benchmark вынесены из production EXE:
`dotnet run --project ../qeli-shared/QeliConformance -c Release -- selftest` и
`... -- packetbench --ci`.

## Состояние сборки и release gate 0.8.2

Windows-клиент требует ABI 1.16 и использует типизированные path results для
fail-closed roaming. Текущая `qeli.dll` пересобрана двумя независимыми проходами
из исходника с digest, записанным в `native-libs/reproducibility/desktop.json`; canonical и EmbeddedResource-копии совпадают,
`native-libs/provenance.py --check` проходит. После изменения Rust-исходника
нужна новая A/B-пересборка. Перед публикацией 0.8.2 обязательно:

- пересобрать core только если изменилось Rust-дерево, но всегда заново собрать оба EXE;
- пройти `native-libs/provenance.py --check`, hash/ABI/package/signing gates;
- прогнать elevated Wintun full-tunnel, IPv4/IPv6/dual-stack, DNS, kill-switch, reconnect;
- записать результат и SHA-256 проверенного EXE в release certification manifest.

Публичный ключ сервера не копируют из этого README. Для каждого сервера получите актуальный
pin командой `qeli show-identity` по доверенному каналу; отключение pinning допустимо только
как осознанная временная диагностика, а не как инструкция для рабочего профиля.

## Общее ядро конфигурации

INI/URI, проверки, defaults и переносимые политики теперь выполняет Rust ABI 1.16.
Модель клиента — тонкая проекция без местного парсера. Для разработки сначала выполните
`python scripts/build_client_core.py --debug` из корня и задайте напечатанный
`QeliNativeCorePath` перед `dotnet build`. Релизные библиотеки требуют штатных A/B-сборок.
Подробности: [единая конфигурация](../docs/ru/plans/CLIENT-CONFIG-CORE.md).

Сверка store 2 октября: [Q25-F210](../docs/ru/plans/AUDIT-DEBT.md). Прямая запись внешнего процесса в encrypted store в обход координации не поддерживается; после правки активного INI требуется явное переподключение.

При применении к уже установленной службе проверяются её command, LocalSystem,
тип процесса и права изменения регистрации, затем права установленного EXE и его
каталогов. Используйте GUI из той же защищённой установленной копии; при несовпадении
отключите службу и переустановите её. Qeli не меняет чужую регистрацию молча.
Ошибки чтения SCM/невалидный или устаревший service status означают неизвестное
состояние, а не успешное отключение. Ошибка незавершённой очистки остаётся видимой
после SCM Stopped. Лог и его GUI view ограничены 256 КиБ, длинные строки — 4096 chars;
после rotation отображается текущая история. Детали: [Q27 service observation](../docs/ru/reports/audit-0.8.2/AUDIT-Q27-WINDOWS-OBSERVATION.md).

Остановка адаптера считается завершённой после подтверждённого выхода его потоков
и закрытия принадлежащих Qeli handles. Ошибка/timeout сохраняет ownership для Stop
retry и отображается как Error. Ошибка восстановления DNS или Dispose не снимает
kill-switch. Незавершённый prewarm не применяется как готовый адаптер.
WinDivert strict gate использует DROP (0x0002); журнал восстановления удаляется
после успешного закрытия всех поколений gate. Подробности и ограничения проверки:
[итог Q27](../docs/ru/reports/audit-0.8.2/AUDIT-Q27-WINDOWS-FINAL.md).


## .NET legal resources

Windows single-file EXEs embed the reviewed NuGet/runtime-pack, Cargo, driver and
client/core legal resources. **About → Licenses** reads and exports them offline;
`licenses --export NEW_DIRECTORY` exports their original bytes without starting VPN.
No external `Legal` directory or release license ZIP is needed for Windows. macOS app
assembly places it in `Contents/Resources/Legal/` and validates both bundles before
assembly (Python 3.11+, select executable with `PYTHON`). Embedded Inter fonts
have their own SIL OFL 1.1/copyright, separate from Avalonia code MIT.
Validate and update the bundle as described in [LICENSING](../LICENSING.md).
This is a full reviewed dependency superset, not a per-executable linkage list.

The common native `rust/toolchains/` layer also preserves reviewed Rust
stdlib, Zig, NDK and GCC/MinGW resources. Keep the entire native bundle. Its
source/version catalog is checked offline; matching-source publication and
per-binary runtime linkage remain separate qualification. See [maintenance](../LICENSING.md).
