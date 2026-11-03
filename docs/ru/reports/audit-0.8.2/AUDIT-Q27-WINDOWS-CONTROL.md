# Q27: переходы службы, SCM, автозапуск и settings — этап PASS

5 октября 2026. База `9b6050ca`; Windows, .NET SDK 10.0.300.
Полный Q27 остаётся **IN_PROGRESS**. План: **26/37 (70,3%)**, 11 разделов осталось.

<!-- normative-sync: audit-q27-windows-control-v1 -->

## Находки и исправления

| Находка | Подтверждённое поведение и изменение |
|---|---|
| Q27-F225: старый профиль и потеря намерения | GUI делал SaveProfile → Start; работающая служба продолжала старый туннель, а сохранение любых настроек подключало отключённый VPN. ServiceProfileTransition готовит валидный DPAPI snapshot до stop, сравнивает сохранённый профиль, останавливает изменённую генерацию и публикует новую только после успеха. Подключение возобновляется по прежнему intent либо явному enable. Неизменённый idle профиль не запускается. |
| Q27-F226: Stop без подтверждения | При StartPending/StopPending CanStop=false приводил к обычному return. Теперь Stop ждёт переходы в общем бюджете 20 секунд, проверяет Stopped и отказывает при неподдерживаемом состоянии, timeout или повторном старте после wait. Это подтверждение SCM state, не доказательство полной сетевой cleanup на настоящей VM. |
| Q27-F227: молчаливый scheduler и deadlock | Enable/Disable игнорировали nonzero exit, Run скрывал launch errors и последовательно читал stdout/stderr без срока. Теперь ошибки видимы, оба pipe drain идут одновременно, каждый diagnostic prefix ограничен 4096 символами, process budget — 10 секунд. По timeout выполняется kill собственного process tree; исходная launch error сохраняется. |
| Q27-F228: settings до успешной записи | OnSave менял AppSettings.Current перед сохранением. Сбой оставлял live singleton с незаписанными значениями и выходил как unhandled UI exception. Теперь редактируется Snapshot; ошибка записи показывается в диалоге без публикации singleton. Внешние операции выполняются после durable preferences и отдельно сообщают ошибки. |

GUI применяет service transitions и scheduler вне dispatcher, блокирует повторные
операции и не открывает второй Settings во время первого применения. Перед переходом
из GUI tunnel mode выполняется Stop независимо от отображаемого статуса: это включает
Error/reconnect generation. Изменение сохранённого для службы профиля применяет именно
его stable Id, без переключения на другой профиль из устаревших preferences; logging
snapshot не меняет исходный GUI профиль. Удаление профиля установленной службы
запрещено до её отключения или выбора другого service profile, включая idle mode.
Остальные профили редактируются без переключения службы.

Отсутствующая scheduler task допускает повторное отключение. COM GetTask проверяет
точно именованную задачу; только HRESULT `0x80070002` означает отсутствие, остальные
ошибки передаются вызывающему коду. .NET на этом host отображает его как
FileNotFoundException: первая проверка выявила слишком узкий catch COMException,
исправление проверено реальным read-only GUID probe. Контракт: [Microsoft GetTask](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-gettask),
[Microsoft scheduler error codes](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants).
Настройки сохраняют желаемое состояние после сбоя внешней операции, показывают ошибку
и повторяют применение при следующем Save. Отдельной транзакции между preferences,
SCM и Task Scheduler нет. COM/RPC, файловый I/O и CreateProcess не получают обещания
принудительного прерывания из-за deadline дочерней команды.

## Проверки

- **224/224 Windows selftest PASS**, 0 FAIL/SKIP: **40 новых assertions** к 184.
  Production coordinator, настоящие DPAPI snapshots и stateful service/SCM adapters;
  changed/unchanged/live/idle/first install/explicit enable/disable, ошибки stop,
  publish/install/start/read, malformed old payload, stable Id и snapshot isolation.
- SCM fake transitions: Stopped/Running/Paused/StartPending/StopPending, cannot-stop,
  timeout и restart после wait. Это не управление настоящей установленной службой.
- Настоящий private PowerShell child: одновременно 128 КиБ stdout и stderr,
  bounded diagnostics + exit 7; stalled child deadline 400 мс и проверка фактического
  завершения своего PID; отсутствующий EXE сохраняет Win32 launch error.
- Настоящая atomic settings запись в GUID temp directory: заблокированная replacement
  сохраняет точные прежние байты и исходный live settings объект.
- Baseline: **8/8 ожидаемых FAIL**, exit 1. Прежние тела адаптированы только для
  service/SCM/scheduler dependencies и supplied settings. Реальный старый sequential
  pipe reader завис на собственном child, после 1500 мс harness завершил только его
  и наблюдал task. APPDATA/ProgramData/SCM/tasks не менялись.
- Release Windows build: 0 warnings/errors. Первоначальный compile error неоднозначного
  TimeoutException и первый selftest failure FileNotFoundException сохранены в raw.
- **543/543 shared conformance PASS**, mandatory fixtures, 0 FAIL/SKIP; свежие
  Release shared/Mac builds — 0 warnings/errors. Mac — compile-only на Windows.
  Shared production inputs неизменны, но DLL metadata изменились после предыдущего
  commit (InformationalVersion содержит новый Git SHA). Поэтому conformance повторён,
  все четыре текущие копии Shared DLL совпадают. Не заявляется точная byte identity
  со старой DLL. Rust/native inputs и 14 artifact checksum rows неизменны.
- RU/EN docs, panel, generated bindings, native provenance/checksums и diff проверены.

Evidence: `release/certification/evidence/q27-windows-control-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-control-20261005` в общем workspace.

## Оставшийся Q27

Далее — доверие к уже установленной службе и recovery/status/log/driver adapters;
затем итоговая сверка доступных критериев Q27. GUI modal clicks и настоящий
SCM/profile reload/Task Scheduler registration не выдаются за adapter tests.
Windows VM network/boot/sleep runtime — **SKIPPED пользователем**, не PASS.
Рабочие services/tasks/native binaries и лаба не изменялись, push/deploy не выполнялись.
Конфиги остаются INI; служебный JSON DTO/storage сохранён.
