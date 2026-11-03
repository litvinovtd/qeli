# Q28: итоговая интеграция macOS

<!-- normative-sync: q28-macos-integration-v1 -->

**5 октября 2026: Q28 DONE в согласованном объёме. План 28/37 (75,7%), осталось 9 разделов; следующий Q29 Android. Реальный Mac и Swift compiler/runtime USER SKIPPED по решению пользователя.**

| Дефект | Изменение и проверка |
|---|---|
| F271 | DNS/PF сравнивали локальное время запуска процесса. Смена часового пояса могла разрешить восстановление DNS или flush PF живого владельца. Новые DNS journals используют schema 2 и UTC ticks; PF — `clock=utc`. Старые DNS v1/PF без clock читаются как legacy: живой PID защищён независимо от ticks; отсутствующий PID допускает recovery. UTC mismatch различает повторное использование PID. Legacy и UTC с одинаковыми числами не дают права claim/release/refresh. Добавлена проверка верхней границы ticks. |
| F272 | TCP EOF немедленно закрывал обе стороны relay и мог обрезать ответ после app FIN. Теперь app EOF вызывает `SHUT_WR`, оставляя server-to-app; remote EOF завершает flow write, оставляя app-to-server. Полное закрытие — после обоих EOF или ошибки/отмены. EOF read source приостановлен до final cancel; published fd по-прежнему закрывает только cancellation handler. State и syscalls находятся на одной очереди. |

## Проверки текущего пакета

- **1248 managed PASS:** macOS storage 54, control 83, network **140**, per-app 39, forwarding 58; Windows 325; shared 549. В network добавлено **23** проверки реального owner probe и production journal/recovery с подменёнными сетевыми границами. Часовой пояс хоста не менялся: в старом stamp моделируется сдвиг 3 часа.
- **4 ожидаемых baseline FAIL** на неизменённых DnsJournal/PfRecovery из предыдущего commit: защита live PID, startup PF sweep, запрет legacy claim и DNS same-numeric identity. Подменены только storage/network boundaries; реальный host PID probe исполнен. Это не Darwin runtime.
- Три Release-сборки без предупреждений/ошибок; три QeliShared DLL совпадают. Native/Rust digest и 14 настоящих artifact hashes неизменны. Docs/bindings/panel/diff и release qualification проверены.
- Добавлены **8 Swift cases** на используемый production RelayDuplex. **Не исполнены**; source review включает обе последовательности EOF, повторный EOF, delayed callback, backpressure, balanced source cancel/resume. Ни новый native baseline, ни физическое получение ответа TCP не заявлены.

## Сверка критериев всего Q28

| Критерий | Основание и граница |
|---|---|
| Review и мёртвый код | [Хранилища](AUDIT-Q28-MACOS-STORAGE.md), [daemon/control](AUDIT-Q28-MACOS-CONTROL.md), [сеть](AUDIT-Q28-MACOS-NETWORK.md), [per-app/build](AUDIT-Q28-MACOS-PERAPP.md), [forwarding](AUDIT-Q28-MACOS-FORWARDING.md), [guardian](AUDIT-Q28-MACOS-GUARDIAN.md), [sockets](AUDIT-Q28-MACOS-SOCKETS.md) и текущие F271/F272. В per-app этапе удалены FlowLifetime-дублёр и недостижимый UDP cast. |
| Штатные, граничные, негативные | 374 свежих Mac managed checks и 874 Windows/shared; предыдущие 10 shell fixture PASS с неизменённым build.sh. Native Swift cases — SOURCE REVIEW, не PASS. |
| Отказы и конкуренция | Key-provider errors, частичные mutations, locks/ownership, retry/checkpoints, настоящий локальный child/PID и изолированные файлы. Kernel/manager boundaries подменены; физический crash recovery исключён. |
| Интеграция | C#/shared ABI и build contracts, release artifacts/provenance. Windows host `qeli.dll` используется для DTO getters; Darwin dylib не выполнялся. |
| Исправления и evidence | F240–F272 с границами предыдущих отчётов, свежая квалификация и неизменяемые raw logs. Исторические formal release cases/artifacts/timestamps и physical rows сохранены. |

Закрытие Q28 означает завершение доступных критериев с явными пользовательскими исключениями. GUI/Keychain Unix permissions, utun/PF/networksetup/sysctl/launchd, NE managers/callbacks, Intel/ARM native execution, entitlements/signing/notarization, DNS leaks, crash/roaming/sleep на Mac **USER SKIPPED**, а не PASS. Сопутствующие managed проверки не исполняют Swift и не подтверждают эти свойства.

## Upgrade и эксплуатация

Перед обновлением остановите старые Qeli-профили и guardians. Новый клиент не забирает legacy DNS/PF state, пока записанный PID существует: часовой пояс и повторное использование PID для старого формата неоднозначны. После завершения процесса recovery может восстановить только принадлежащий Qeli снимок по прежним правилам; PF глобально не отключается. Если PID занят другим процессом, проверьте его и состояние сети вручную; не удаляйте journal вслепую. Старый клиент не понимает новые clock/schema и не является безопасным downgrade на активном профиле. Пользовательские конфиги остаются INI; JSON DNS journal — внутреннее recovery state.

Half-close не устанавливает idle timeout: оставшееся направление может законно работать долго. Ошибка, отмена или write timeout по-прежнему закрывают relay; произвольные OS callbacks/syscalls не получают гарантированного времени teardown.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-integration-20261005.
Evidence: release/certification/evidence/q28-macos-integration-20261005.json.
Лаба, сеть, службы, пользовательские профили и timezone не изменялись; push/deploy не выполнялись.

Контракты: [Apple TCP flow EOF](https://developer.apple.com/documentation/networkextension/neappproxytcpflow/readdata%28completionhandler%3A%29), [Apple directional shutdown](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/shutdown.2.html), [.NET Process.StartTime](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.starttime?view=net-10.0).
