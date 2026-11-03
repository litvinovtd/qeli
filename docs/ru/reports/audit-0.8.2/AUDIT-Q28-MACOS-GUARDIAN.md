# Q28: guardian — готовность и владение поколением

<!-- normative-sync: audit-q28-macos-guardian-v1 -->

**5 октября 2026: C# этап PASS; Swift SOURCE REVIEW, compile/runtime USER SKIPPED. Q28 IN_PROGRESS, план 27/37 (73,0%), осталось 10 разделов.**

## Исправления

| ID | Проблема и исправление |
|---|---|
| F265 | Живой child считался готовым до загрузки state; guard публиковал state до проверки parent PID. Parent проверяется до чтения handoff и повторно перед claim. C# ждёт точный 32-байтовый token после claim (до 5 секунд), отказывает при exit, чужом/пустом/слишком большом ack и не переиспользует unacknowledged child. Handoff удаляется после подтверждения либо завершения обработки ошибки. |
| F266 | Heartbeat/down/stop и cleanup умершего guardian работали с любым текущим state; файловый lock не защищал manager operations от старого поколения. Схема v5 несёт owner PID/token, guardian PID и confirmed release. Все state mutations проверяют generation; manager operations и claims сериализованы отдельно от heartbeat. Старый guardian при смене/retirement выходит без manager mutation. Update сохраняет текущий lease, не возвращает старый handoff timestamp. State read/write ограничены 1 MiB; flock waits ограничены 5/190 секундами. |
| F267 | Join retry повторял stop после подтверждённой очистки; reconfiguration могла возобновиться до join. Controller помнит подтверждённый stop, retry выполняет только join, включая исчезнувший helper. Новый start ждёт retirement; после успеха token меняется. Ошибки log observer больше не заменяют результат activation/recovery. |

## Проверки

- perapp-selftest **39/39 PASS**, из них **17 новых** относительно предыдущих 22. Production controller с fake helper/platform плюс реальные изолированные child processes для readiness/join: delayed exact ack, отсутствие ack, чужой/пустой/oversized token, early exit и stale ack. Проверены token в DTO/down/stop, стабильность при update и смена при новом start, отказ reconfiguration до join, retry без второго stop/без файла helper и observer errors.
- Неизменённый прежний C# controller: **9/9 ожидаемых FAIL**. Transitions исполняются через его исходный injected constructor; настоящий private EnsureGuardian вызывается reflection с owned child без ack. Подменены platform/helper boundaries; Swift ownership не имитируется и не объявляется проверенным этими cases. Девять сценариев не равны девяти независимым дефектам.
- Свежие связанные проверки: forwarding **58**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**. Всего **1225 managed PASS**. Три Release-сборки, baseline и no-ack child build без предупреждений/ошибок; Shared DLLs побайтово равны. Docs/bindings/panel/diff PASS; Rust/native source digest и все 14 native hashes неизменны.
- Swift добавлены **10 owner/policy cases**, выполнен source review helper/store/provider interfaces. Эти cases и Swift compiler/Xcode **не запускались**. Darwin parenthood/flock/app group, manager callbacks, activation/signing, настоящий helper-ready и crash/network cleanup — **USER SKIPPED**, не PASS. C# tests не подтверждают Swift manager serialization/runtime.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-guardian-20261005.
Evidence: release/certification/evidence/q28-macos-guardian-20261005.json.

## Совместимость и границы

Helper, host и extension используют служебную схему v5 и обновляются одним подписанным bundle. Перед обновлением остановите старые профили и дождитесь завершения старых guardian. State v4/неизвестный owner автоматически не перехватываются. Если остался старый per-app-state.json, сначала подтвердите остановку старых Qeli managers/guardian, сохраните его копию и только затем удалите именно этот устаревший state в Qeli app-group container. Не удаляйте state активного/неизвестного владельца. Новый completed tombstone сохраняется: последующий claim разрешён после подтверждённого stop, даже пока предыдущий parent жив.

На Mac действует один активный Qeli per-app owner. Чужой живой PID блокирует takeover; reuse PID может дать консервативный отказ и требует административной проверки. Token и parenthood защищают кооперативные Qeli v5, не старые binaries, независимых writers или компрометацию app-group. При исчезновении state/неизвестной очистке остаётся ошибка; no-state не доказывает остановку managers. Providers сохраняют прежнюю политику истечения lease: fail open после исчезновения owner. Heartbeat не является гарантией непрерывности при lock/I/O stalls.

190 секунд — предел ожидания operation lock и отдельный бюджет короткого helper runner, а не общий deadline всех NetworkExtension callbacks. 5 секунд readiness не гарантируют прерывание произвольного файлового syscall. Callback timeout/смерть процесса не дают гарантии отмены уже принятой OS операции. Реальный Mac исключён пользователем. Пользовательские конфиги только INI; JSON — внутренний DTO.

Остаток Q28: native socket lifetime/connect/write bounds и итоговый integration review, включая UTC identity старых DNS/PF stamps. Исторические release cases, artifacts/timestamps и physical rows сохранены; новых Linux/JNI/native A/B/soak/benchmark результатов нет. Лаба, сеть, службы и пользовательские профили не изменялись; push/deploy не выполнялись.
