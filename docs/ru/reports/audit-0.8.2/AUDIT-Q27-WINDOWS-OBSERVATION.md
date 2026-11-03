# Q27: регистрация службы, статус и логи — этап PASS

5 октября 2026. База `741efcb5`; Windows, .NET SDK 10.0.300.
Полный Q27 остаётся **IN_PROGRESS**: **26/37 DONE/PASS (70,3%)**, 11 разделов осталось.

<!-- normative-sync: audit-q27-windows-observation-v1 -->

## Исправления

| Находка | Поведение и исправление |
|---|---|
| Q27-F229: доверие только при установке | Start и Apply уже установленной службы обходили EnsureProtectedLocation; Install принимал ERROR_SERVICE_EXISTS без проверки регистрации. Теперь перед intent/start и перед изменением профиля проверяются SCM command (точно quoted текущий EXE + --service), LocalSystem, отдельный неинтерактивный процесс, owner/DACL службы и реальные ACL/owner/reparse executable/ancestors. Ошибка query или недоверенная запись отказывает до изменения profile/intent. Stop/Uninstall доступны для восстановления. |
| Q27-F230: неверное наблюдение | SCM query error скрывался как Disconnected; numeric Enum.TryParse принимал неизвестные значения; stale Connected оставался действующим. Новый observer отличает pending/unknown, проверяет свежесть Running snapshot (10 секунд, future tolerance 5 секунд), убирает traffic при unknown. Структурный reader требует именованное enum, timestamp, неотрицательные counters и detail ≤2048. При Stopped сохраняется terminal Error, включая незавершённую cleanup. Изменение Extra при том же enum обновляет GUI без повторного toast. Ошибка installed query не допускает конкурирующий GUI tunnel. |
| Q27-F231: доверие и бюджет логов | GUI напрямую читал файл без storage ACL guard и без лимита; cursor=Length после EOF пропускал concurrent append. Теперь reader использует тот же private storage guard, strict UTF-8 и bounded полный snapshot ≤256 КиБ. GUI заменяет ограниченный view, не накапливает бесконечный AppendText. Частичный UTF-8 повторяется следующим poll, rotation/truncate+regrow не полагаются на прежний cursor. |
| Q27-F232: oversized log writer | Старый writer проверял размер до append, одна большая строка или crossing append нарушали 256 КиБ. Строка ограничена 4096 UTF-16 chars (без разрезания surrogate pair), помечается truncated; ротация выполняется до превышения byte budget, атомарно. Reset также атомарен и сериализован с append внутри процесса. |

Start сохраняет исходную ошибку вместе с ошибкой disarm intent в AggregateException,
если обе операции отказали. Best-effort status/log write может потерять диагностическое
сообщение при I/O error; это не журнал восстановления сети. Чтение полного bounded
log snapshot стоит до 256 КиБ за poll (раз в секунду); GUI не обещает полную историю
до rotation. Ошибка чтения сохраняет последний ограниченный view.

SCM read использует CONNECT, QUERY_CONFIG и READ_CONTROL, без write rights. Native
query и маршалинг проверены read-only на EventLog и отсутствующем GUID имени; никакая
служба не устанавливалась, не запускалась и не останавливалась. Контракт и максимальный
8 КиБ buffer: [Microsoft QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
[QUERY_SERVICE_CONFIGW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw).
QueryServiceConfig отражает конфигурацию следующего запуска; это не аттестация уже
работающего процесса. Отдельные service-object mutation rights проверяются отдельно
от filesystem rights; консервативный Allow для недоверенного SID отказывает даже при
наличии Deny. Ошибочная/иная регистрация не перенастраивается молча: отключите её и
переустановите из защищённой установленной копии Qeli.

## Проверки

- **273/273 Windows selftest PASS**, 49 новых assertions к 224, 0 FAIL/SKIP.
- Production validators/controller/observer и private temp file writer/reader:
  foreign/unquoted/extra-argument command, wrong account/type, file trust refusal,
  service owner/null DACL/config-write/delete/DACL/owner/generic rights, no mutations
  при отказе; actual read-only SCM success/absence and unmanaged marshalling.
- Fresh/stale/future/missing/numeric status, negative counters, invalid UTF-8,
  cleanup error после SCM Stopped, pending states и обновление error detail.
- Giant Unicode, surrogate boundary, before-overflow rotation, oversized legacy,
  bounded hostile read, append at EOF, partial UTF-8 retry, настоящий открытый reader
  сохраняет old generation при atomic replacement; только GUID temp directory.
- **7/7 ожидаемых baseline FAIL**, exit 1: прежние тела writer/poll/tail и прежний
  coordinator с injected dependencies. Нативная SCM mutation и ProgramData не нужны.
  Старый tail воспроизводит пропуск дописанных после EOF байтов. Старый статус не
  проверял timestamp вообще; fake supplies тот же stale Connected.
- Release Windows/shared/Mac builds: 0 warnings/errors. **543/543 shared PASS**,
  0 FAIL/SKIP. Mac — compile-only. Текущие четыре Shared DLL byte-equal; новый Git SHA
  меняет InformationalVersion, поэтому текущий артефакт проверен заново.
- RU/EN docs, panel, generated bindings, native provenance, 14 native checksum rows
  и diff PASS. Rust/native inputs не менялись; новая A/B сборка не требуется.
- Первоначальные harness string escaping compile errors и последующая warning
  сохранены в raw; окончательная сборка без ошибок и предупреждений.

Evidence: `release/certification/evidence/q27-windows-observation-20261005.json`.
Raw: `audit-debt-20260924/q27-windows-observation-20261005` в общем workspace.

Осталось в Q27: итоговый проход native loader/driver adapters и сверка всех доступных
критериев. Recovery entrypoint reviewed: service отказывается запускаться после
ошибки startup kill-switch sweep; SCM Stopped не доказывает полную cleanup маршрутов,
DNS/firewall. Новый observer сохраняет явно опубликованную ошибку, но не гарантирует
доставку статуса при disk fault. Windows VM network/boot/sleep runtime — **SKIPPED
пользователем**, не PASS. GUI клики и реальное SCM registration/reload не выдаются за
adapter tests. Рабочие services/tasks/native binaries и лаба не изменялись.
Конфиги INI, служебный JSON DTO/storage остаётся. Push/deploy не выполнялись.
