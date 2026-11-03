# Q34: полный перечень fuzz-целей в CI

<!-- normative-sync: q34-fuzz-inventory-v1 -->

Дата: 9 октября 2026.

## F484 / Q34-F038

В qeli/fuzz/Cargo.toml зарегистрированы 15 bin targets. Ручные smoke и nightly
перечни содержали 11 и пропускали control_v2, quic_envelope, realtls_client,
websocket_frame. Общий fuzz build мог собирать эти цели, но CI не запускал их
с бюджетом 30/600 секунд. Прежний точный smoke shell с контролируемым cargo
вернул0, сделав только11 вызовов: отсутствие запуска не было отказом CI.

scripts/fuzz_targets.py читает зарегистрированные bins, требует cargo-fuzz
package metadata, непустой список, safe уникальные имена и существующие source
paths внутри package. Неверный TOML, отсутствующий/внешний source и превышение
matrix limit256 дают отказ до stdout/GitHub output. Выход сортируется; GitHub
output содержит тот же список в JSON для CI, это не формат конфигов Qeli.

Smoke получает inventory через проверяемый command substitution и запускает
каждую цель. Process substitution для генератора не используется: его ошибка
иначе могла бы стать пустым успешным циклом. Nightly получает matrix от отдельного
fuzz-targets job через needs/outputs/fromJSON. Оба задания сохраняют прежнюю
schedule/workflow_dispatch границу nightly, corpus keys и crash artifacts.
Shared inventory regression включён в обычный native-libs CI job.
Добавленная зарегистрированная цель автоматически попадает в обе проверки.

Схема dynamic matrix соответствует [документации GitHub](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations).
[Лимит matrix](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstrategymatrix)
проверяется до публикации output. Это проверка схемы и данных, не исполнение
GitHub scheduler локально.

## Проверки и границы

69 методов Windows PASS:10inventory,38native recipes,21release tag/workflow.
Те же10inventory методов повторены на Linux без skips. SHA-квалифицированный
private PyYAML6.0.3 разобрал настоящий workflow, сверены cwd/needs/outputs/if/matrix,
из него извлечены точные baseline и final shell scripts.

На Linux .11 выполнены10 shell-сценариев: старый11-target gap, все15 targets,
ранний cargo exit23 с прекращением последующих запусков, полный nightly output,
missing/malformed manifest без cargo, сохранение старого output при malformed,
новая16-я цель в smoke и matrix, отказ внешнего source symlink. Rust source inputs
после fixtures побайтно восстановлены. Controlled cargo только пишет argument/
status receipts: новые реальные libFuzzer/parsers/ASan/crash/corpus результаты
этим не заявлены. Время30/600 в workflow не было новым длительным прогоном.

Первый локальный input-preparation запуск не нашёл глобальный yaml и завершился
rc1. Использован прежний SHA-qualified parser без global install; диагностика
сохранена отдельно, успешный parser/steps proof повторён. Это ошибка обвязки,
не дефект продукта. Nightly/tool version pinning и hosted Actions остаются OPEN.

Собственный небольшой lab root полностью SHA-архивирован, каждый archive member
проверен локально, затем root и точный sibling backup удалены после /proc fd/cwd/
exe/root и mount guards. Исходные MainPID777/845, service active и CLI SHA сохранены.
Лаба .10 не использовалась. Секрет только stdin; credential scan raw/decoded archive PASS.
Native digest e3fb,14 artifact SHA и protected files неизменны. qeli tree не
менялся: предыдущий точный OpenWrt cut остаётся применим в своём исходном scope.

Q34 IN_PROGRESS;30/37DONE81,1%,7осталось. Q35 остаётся TODO: этот фикс CI inventory
не закрывает full fuzz/concurrency/DoS/soak. Q29 SIGKILL FAIL/ENONET,Q30/Q31,
F459 braces OPEN,D06 ACCEPTED_LIMITATION,USER_EXCLUDED сохранены.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-fuzz-inventory-20261009`: SEALED 108 files / 1459713 bytes; manifest SHA256 `c580a0c3430eb9828987e68c2a9f7e44c35391830e83c6a308371efff076e6f6`.
