# Qeli CLI для Windows

Русский · [English](../../eng/manuals/WINDOWS-CLI.md)

Консольный клиент `qeli-cli.exe` для Windows x64. Поддерживаются CMD, `.bat`/`.cmd`,
Windows PowerShell 5.1 и PowerShell 7. Использует тот же Windows runtime, Rust-ядро,
Wintun/WinDivert и INI-парсер, что GUI. Разработка относится к 0.8.4;
наличие исходников не означает публикацию готового релиза.

## Запуск и конфигурация

Пакет `net-required` требует .NET 10 Runtime; `standalone` содержит runtime.
Файлы релиза: `qeli-cli-windows-x64-net-required.zip` и
`qeli-cli-windows-x64-standalone.zip`. Распакуйте выбранный архив целиком.
WPF/Desktop Runtime для CLI не нужен. Копируйте **всю папку** выбранного варианта,
а не только EXE. Windows-службу устанавливайте из защищённого каталога,
например `C:\Program Files\QeliCli`: права его файлов и родителей проверяются.

```cmd
qeli-cli.exe --help
qeli-cli.exe version --json
qeli-cli.exe config validate --config "C:\VPN\office.ini"
qeli-cli.exe run --config "C:\VPN\office.ini"
```

`run` работает в текущем процессе до Ctrl+C/Ctrl+Break. Не имеет неявного лимита
30 секунд. `--timeout 60` ограничивает первоначальное подключение, а
`--duration 300` — время работы после первого подтверждённого подключения.
Терминальные ошибки возвращают ненулевой код. При выходе вызывается штатная
очистка маршрутов/DNS/firewall. Сбой очистки возвращает отдельный код 10.
Принудительное убийство процесса и закрытие окна имеют ограничения Windows:
cleanup нельзя гарантировать, журналы восстановления сохраняются.

Файл — UTF-8 INI, максимум 256 КиБ; BOM допустим. JSON не является форматом
конфига. Пароли и ссылки с паролями не передаются аргументами процесса.
Для unattended-подключений задайте проверенный `key`; правила проверки ключа
и TOFU остаются общими с Windows-клиентом. Доверие/идентичность пользовательского
процесса и службы SYSTEM могут различаться; они не копируются автоматически.

```cmd
qeli-cli.exe config validate --config - --json < "C:\VPN\office.ini"
```

В PowerShell 5.1 для текстового pipeline в stdin сначала задайте
`$OutputEncoding = [System.Text.UTF8Encoding]::new($false)` либо передавайте путь
через `--config`. В PowerShell 7 по умолчанию используется UTF-8.
Пути с пробелами заключайте в кавычки; для CMD batch с кириллицей учитывайте
кодировку самого batch-файла и активную code page оболочки.

Идентификатор файлового CLI-профиля стабилен по абсолютному пути, без хеширования
пароля. Permanent adapter со stdin требует явного `dev_node`/`dev`; это предотвращает
создание нового постоянного интерфейса при каждом запуске.

GUI-предпочтения не меняют CLI-профиль. `windows_persistent_adapter=true`
применяется как режим Per profile; общий адаптер GUI Global не выбирается неявно.
Один machine-wide владелец охватывает GUI/CLI/службу, reconnect и незавершённый cleanup.

## Команды

| Команда | Назначение |
|---|---|
| `--help` | Показать справку по командам |
| `version` | Показать версию клиента |
| `config validate --config FILE` | Проверить INI; `-` читает перенаправленный stdin |
| `run --config FILE` | Запустить VPN в текущем процессе |
| `probe --config FILE` | Проверить authenticated handshake без настройки маршрутов |
| `connect --config FILE` | Подключиться через установленную службу |
| `disconnect` | Остановить подключение службы и проверить очистку |
| `status` | Прочитать состояние подключения службы |
| `wait --state connected` | Дождаться подключения службы |
| `wait --state disconnected` | Дождаться отключения службы |
| `logs` | Прочитать лог службы; `--follow` выводит обновления |
| `service install` | Установить службу; новая установка не подключает VPN |
| `service start` | Запустить worker с сохранённым намерением подключения |
| `service stop` | Остановить службу и отключить подключение при загрузке |
| `service uninstall` | Остановить и удалить службу, сохранив профиль |
| `licenses` | Перечислить встроенные тексты лицензий |
| `licenses --export NEW_DIR` | Экспортировать лицензии в новый каталог |

## Windows-служба и автоматизация

```cmd
qeli-cli.exe service install
qeli-cli.exe connect --config "C:\VPN\office.ini" --timeout 60
qeli-cli.exe status --json
qeli-cli.exe wait --state connected --timeout 60
qeli-cli.exe logs --follow
qeli-cli.exe disconnect --timeout 30
```

Используется существующая служба `QeliWinSvc`: SCM и защищённое DPAPI-хранилище.
Установка новой службы сохраняет intent=disconnected. `service start` запускает
worker с сохранённым intent; `service stop`/`disconnect` отключают boot intent.
Длительное подключение живёт независимо от терминала и пользовательского входа.

`connect` возвращает 0 после свежего Connected именно запрошенного профиля,
а не после старта SCM. Повтор неизменённого профиля не создаёт второй туннель.
Смена профиля использует stop/publish/start. `disconnect` ждёт SCM и проверяет
подтверждение очистки; неизвестный/устаревший Connected не считается успехом.
Команды `status`, `wait`, `logs`, `connect`, `disconnect` относятся к backend службы.
Foreground `run` завершается в его терминале, а не командой управления службой.

Таймаут или Ctrl+C у `connect` прекращает ожидание CLI, но уже опубликованный
intent службы может остаться активным: отменяйте его отдельным `disconnect`.
При таймауте первоначального `run` выполняется cleanup.
Старый service host без нового control metadata получает `service_incompatible`:
остановите/удалите старую регистрацию и установите текущий CLI. Сохранённый профиль
не удаляется uninstall-командой. Legacy/untrusted storage мигрируется только явно
через существующий GUI; CLI не выполняет скрытый quarantine.

Управление службой и `run` требуют администратора. Справка, версия, лицензии,
проверка конфигурации и handshake probe не требуют elevation. EXE имеет asInvoker;
при недостатке прав CLI возвращает ошибку без диалога UAC.

CMD/batch:

```bat
@echo off
qeli-cli.exe connect --config "C:\VPN\office.ini" --timeout 60 --json
if errorlevel 1 exit /b %errorlevel%
qeli-cli.exe status --json
rem Выполните нужную работу через VPN.
qeli-cli.exe disconnect --timeout 30 --json
exit /b %errorlevel%
```

PowerShell:

```powershell
& .\qeli-cli.exe connect --config 'C:\VPN\office.ini' --timeout 60 --json
if ($LASTEXITCODE -ne 0) { throw 'VPN connection failed' }
$status = & .\qeli-cli.exe status --json | ConvertFrom-Json
$status.data.state
```

## Вывод и ошибки

`--json`: один объект schema_version=1 в stdout, без баннеров и примеси логов.
Обычные логи `run` идут в stderr. `--json-lines` доступен для `run`/`logs`;
`logs --follow --json` заменяйте на `--json-lines`. Очередь логов ограничена;
медленный читатель не должен блокировать транспорт, счётчик `logs_dropped`
показывает пропуски в результате foreground-запуска. Ротация service log может
повторно выдать сохранённый ограниченный снимок.

```json
{"schema_version":1,"ok":true,"command":"config validate","data":{"valid":true},"error":null}
```

| Код | Значение |
|---|---|
| 0 | Команда успешно выполнена |
| 2 | Неверные аргументы |
| 3 | Ошибка чтения/валидации INI |
| 4 | Недостаток прав или недоверенное хранилище |
| 5 | Конфликт владельца/операции |
| 6 | Истёк срок ожидания |
| 7 | Ошибка аутентификации |
| 8 | Несовпадение ключа сервера |
| 9 | Ошибка транспорта/операции |
| 10 | Очистка сети не подтверждена |
| 11 | Служба/native core недоступны или несовместимы |
| 12 | Ожидание отменено |

`probe --config FILE` выполняет authenticated handshake без установки маршрутов.
Он не подтверждает работу DNS/маршрутов/передачи данных через полноценный VPN.
`licenses` перечисляет встроенные оригинальные тексты; `licenses --export NEW_DIR`
сохраняет их в новый каталог, не перезаписывая существующий.

## Сборка и проверка

Используйте SDK, закреплённый корневым `global.json`, и согласованный native core.

```powershell
dotnet build .\qeli-win\QeliCliTests\QeliCliTests.csproj -c Release
dotnet exec .\qeli-win\QeliCliTests\bin\Release\net10.0-windows\QeliCliTests.dll
$env:QELI_CLI_REQUIRED = '1'
python -B -m unittest discover -s scripts -p test_windows_cli.py -v
.\qeli-win\build-cli.ps1 -OutputDirectory C:\Build\qeli-cli-candidate
```

`build-cli.ps1` создаёт каталоги net-required/standalone и два ZIP-архива для релиза,
включая все DLL/runtime-файлы (кроме отладочных PDB) и краткую инструкцию. Проверяет оригинальные лицензии,
точные bytes native core и реальную совместимость INI-парсера. Для dev-сборки
можно явно передать `-NativeCorePath`; это не делает DLL квалифицированным релизным
артефактом. Публичная поставка требует обычных проверок provenance/релиза.

После сборки всего комплекта 0.8.4 и генерации `SHA256SUMS` выполните
`python scripts/release_assets.py --directory release/dist/v0.8.4 --version 0.8.4`.
Проверка требует оба Linux ELF/DEB, оба CLI ZIP и остальные файлы релиза;
неполный комплект или лишний старый файл не считается готовой поставкой.

Unit/fault-injection и shell smoke не заменяют проверки реального Windows VPN:
elevated full-tunnel, dual-stack/DNS, reboot/service lifecycle, reconnect, kill switch,
потеря сети и forced kill требуют отдельного изолированного Windows-стенда.
