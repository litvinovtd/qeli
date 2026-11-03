# Q34: Git trust flags в OpenWrt source gate

<!-- normative-sync: q34-openwrt-source-flags-v1 -->

Дата: 9 октября 2026.

## F482 / Q34-F036

Source gate требовал committed inputs через git status, но Git flags
assume-unchanged/skip-worktree скрывали рабочие изменения. После этого gate читал
committed Makefile/Cargo и мог вернуть PASS при другом working source.
Это обход обещанного clean-source контракта; функция вызывается release_preflight.

В реальных временных Git repositories прежний gate принял все десять комбинаций:
два flags × qeli source, package Makefile, verify-source.sh, source gate и
release_preflight.py. Изменённые файлы действительно были скрыты git status;
полный immutable pin, одинаковый committed qeli tree и fixture archive hash
оставались корректными. Тесты показывают source-admission defect, не SDK build.

Теперь git ls-files -v проверяет те же INPUTS до чтения pin и archive hashing.
Любой lowercase assume-unchanged или S skip-worktree отклоняется. Флаг отклоняется
также на пока неизменённом input: status для него нельзя использовать как
доказательство чистоты. Ни flags, ни файлы не меняются автоматически.
Unrelated notes с такими flags проходят: существующая граница INPUTS сохранена.
OpenWrt README описывает проверку и ручное снятие flags после review.

## Проверки

37 методов PASS: 25 source-gate и 12 whole-preflight. В source suite зарегистрированы
28 методов; три прежних skips — POSIX symlink, FIFO и старый opt-in baseline —
сохранены. Новые три метода выполнялись с настоящим Git: десять отказов скрытых
inputs и два положительных unrelated-flags случая. Два метода на точном прежнем
source воспроизвели десять false-PASS. Archive POSIX APIs не изменялись, прежняя
Linux qualification не объявлена новым запуском. Сеть и лаба не использовались.

Production source-cut проверен read-only: pin dd0b736276b9ad5b89d117abd1bfe324210f3b26
имеет другой qeli tree, чем current HEAD. Pin/hash/SDK recipe не изменялись.
Matching source cut, actual SDK archive/current Actions/publication остаются OPEN;
неподходящий release source не превращён в PASS. Исправлена только отдельная
проверка доверия к Git status. Новый SDK/native/compiler/runtime не заявлен.

Документация, diff, native digest e3fb и 14 artifact SHA проверены. Исторические
qualification cases и их исходные границы сохранены. Q34 IN_PROGRESS;
30/37 DONE (81,1%), 7 осталось. Q29 SIGKILL FAIL/ENONET, Q30/Q31, F459 braces,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED остаются в прежнем статусе.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-openwrt-source-flags-20261009`: SEALED 34 files / 1231613 bytes; manifest SHA256 `1bf2fd09bf340d81a75fc334d07ad07188cac0514d15dc34fa9027837385e190`.
