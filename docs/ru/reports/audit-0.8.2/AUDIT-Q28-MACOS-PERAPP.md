# Q28: per-app bridge, Swift-политика и пути сборки

<!-- normative-sync: audit-q28-macos-perapp-v1 -->

**5 октября 2026: C#/shell этап PASS; Swift — SOURCE REVIEW / USER SKIPPED. Q28 IN_PROGRESS, план 27/37 (73,0%), осталось 10 разделов.**

## Исправления

| ID | Проблема и исправление |
|---|---|
| F256 | down/stop скрывали ошибки; stop/неудачный rollback снимали ownership и убивали guardian до подтверждения cleanup. Ошибки теперь выходят наружу; Started и guardian сохраняются для повторного Stop. BeforeTunDispose отказывает до закрытия utun; CleanupPlatform не забывает активный controller. Guardian освобождается только после kill и подтверждённого join. Исчезновение helper означает неизвестный cleanup, а не успех. |
| F257 | Служебный state лежал прямо в общем temp, вывод helper и pipe EOF не имели общего ограничения. Новый handoff использует эксклюзивный приватный каталог (700 на Unix) и файл 600, лимит payload 1 MiB; recovery пишет в тот же каталог. ToolProcess ограничивает обе трубы по 64 KiB и process/EOF одним бюджетом 190 секунд. |
| F258 | UsesAppFilter принимал INCLUDE без учёта регистра, Swift выбирал include только при точном совпадении. Wire mode теперь приведён к нижнему регистру до запуска helper. |
| F259 | Prefix guard принимал dist/../victim и другие произвольные leaf; rm мог выйти из заданной области. per-app build принимает только точный dist/per-app-ARCH, проверяет symlink parents/leafs; app build отказывает при symlinked dist/outputs. Пути фиксированы до операций сборки/удаления. Это защита trusted workspace от ошибок пути, не от конкурентного вредоносного изменения root. |
| F260 | Swift CIDR пустой строки индексировал пустой массив, ведущий/конечный slash терялся при split. Пустые subsequences сохраняются, пустой address отказывает; неправильный prefix больше не становится host route. Добавлены native policy cases. |
| F261 | Relay мог зарегистрироваться после closeAll старой политики и продолжать её применять. Общий RelayRegistry принимает только поколение snapshot; retire и публикация state согласованы под provider lock, close callbacks идут после освобождения locks. Запоздавший monitor не возрождает stopped provider. Удалены FlowLifetime-дублёр и недостижимый force-cast UDP. |

## Проверки

- perapp-selftest: **22/22 PASS** на рабочих методах controller: отказ down/stop, retry, частичный start/rollback, missing helper, failed update, platform refusal, oversized state, приватный handoff/его удаление. Настоящие локальные процессы проверяют guardian join и лимиты stdout/stderr; NetworkExtension/службы/сеть не запускаются.
- Shell fixture: **10/10 PASS** на настоящем build.sh с подменёнными uname/Xcode/build/copy/rm tools. Ни одного реального recursive delete, Xcode build, signing или publish. Baseline прежнего build.sh воспроизводит **5 ошибок из 10 сценариев**; остальные 5 корректно проходят. Symlink fixture на Windows недоступен: **SKIP**, проверка этого условия по коду.
- Старый C# bridge: **6/6 ожидаемых FAIL**. Подменены только platform/helper/guardian boundary и namespace; прежние transitions сохранены. Исходный Run отдельно исполняется настоящим локальным процессом для overflow.
- Mac network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS** после сборок; C# Release без warnings/errors. Docs/bindings/panel/diff, shell syntax и неизменённые native digest/14 hashes PASS.
- Swift policy/registry: добавлены 10 regression cases; **не исполнялись**. Xcode build/Swift typecheck, реальный app group, entitlements/signing/notarization, Darwin sockets/NE callbacks и Unix permissions остаются **USER SKIPPED**, не PASS. Первое падение тестового harness на неучтённом InvalidDataException сохранено; исправлен harness, затем заново выполнены сборка и 22 проверки.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-perapp-20261005.
Evidence: release/certification/evidence/q28-macos-perapp-20261005.json.

## Остаток и границы

При отказе stop/join или исчезновении helper клиент сохраняет Error/ownership для повторной очистки. Для утраченного helper нужно восстановить подписанную сборку либо вручную отключить Qeli managers; автоматического подтверждения очистки нет. Это преднамеренное изменение прежнего best-effort stop. Служебный JSON state остаётся внутренним DTO; пользовательские конфиги только INI.

Q28 ещё требует forwarding ownership/crash recovery, guardian ready/owner-generation и сериализацию native socket lifetime/ограничение connect/write. Бюджет helper не прерывает произвольный Darwin syscall и не подтверждает поведение SystemExtensions. Runtime Mac исключён пользователем; не заявлены новые Linux/JNI/soak/benchmark результаты. Исторические release evidence и physical rows сохраняются; push/deploy/лабовые службы/пользовательские профили не затронуты.

Первичные контракты: [приватный .NET temp directory](https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createtempsubdirectory?view=net-10.0), [Swift split и пустые subsequences](https://developer.apple.com/documentation/swift/string/split%28separator%3Amaxsplits%3Aomittingemptysubsequences%3A%29).
