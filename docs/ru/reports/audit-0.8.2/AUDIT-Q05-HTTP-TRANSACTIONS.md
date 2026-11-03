# Q05: конфигурационные транзакции, live reload и restart

Дата: 3 октября 2026. Статус: **PASS для поддерживаемого Linux-контракта Q05**.

## Результат

Закрыты пять критериев раздела 05. Шесть пакетов реального HTTP/systemd дают
**352 checks PASS** на точном release `8fa8590104ebbceecb78c09d7c146b3ee101719b53820d0d1a1bc3cff664b3b7`. Production Rust не менялся.
Прежние Q05-F001–F008 исправлены в предыдущих пакетах; их unit-регрессии входят
в полный Linux-прогон Q04 (2261 PASS, 60 ignored). Здесь этот прогон, release-матрица
18/327, soak 100 TCP + 100 QUIC/33 и native A/B используются по неизменным входам
и артефактам; новые исполнения этих проверок не заявляются.

## Проверенные слои

| Пакет | Checks | Подтверждённое поведение |
| --- | --- | --- |
| Form / INI / history | 75 | Точная ревизия общая для редакторов; пропущенная/старая ревизия отклонена; секреты сохраняются, INI остаётся 0600, snapshot — точные прежние байты. 8 писателей дают 1 успех и 7 конфликтов. ENOSPC, read-only snapshot, отказ rename и занятый sidecar не меняют рабочий INI; status отзывчив, повторная запись работает. |
| Quick Start / hot reload / worker | 207 | Все 10 режимов preview/apply/reapply; профиль в ответе совпадает с диском, credentials сохраняются, неявного рестарта нет. Новый пароль действует сразу, старый пароль/cookie отвергнуты; allowlist/trusted proxies применены live. Startup-only поля сохраняются с требованием full restart. Невалидный INI/profile/host overlap сохраняет worker; успешный restart меняет worker PID, сохраняя supervisor/cookie. |
| Detached full restart faults | 15 | Приватный systemctl shim: отказ виден в status, повторная проверка изменённого INI предотвращает dispatch. Timeout 15 секунд сообщает неопределённый результат и завершает свой child. Настоящий host manager здесь не вызывается. |
| SIGKILL / fsync | 27 | Тестовый preload только в приватном процессе останавливает save до/после rename. После SIGKILL остаётся целый старый/новый INI и точный rollback snapshot; HTTP не сообщает успех. Ошибка directory fsync явно сообщает неопределённую сохранность уже опубликованного файла; новая ревизия позволяет повторить запись. |
| Non-root / EACCES | 17 | Реальная панель UID 65534 с работающим приватным worker и сетевыми capabilities. Сохранение сохраняет владельца/0600. Чужой недоступный history и запрет записи в parent отклоняют сохранение без изменения INI; после устранения отказа запись восстанавливается. |
| Настоящий systemd | 11 | Два полных рестарта собственного временного unit: supervisor PID меняется, cookie сохраняется, новый listener применяется, старый удаляется. Невалидный disk INI не перезапускает unit. Временный unit остановлен и собран manager. |

Review охватывает Form/INI/Quick Start/history и оба restart handler, общий preflight,
sidecar lease, atomic publication и live_web reload. Учтены имеющиеся unit-проверки
масок секретов, trusted source, stale/external revision, структуры, startup validator,
свежести snapshot, private inode, частичной записи и неопределённого directory sync.
Неиспользуемых production helpers в этих путях не подтверждено.

## Q05-F009: устаревший тест управлял рабочей службой

`test_web_reload.py` содержал остановку/перезапуск `qeli-server.service`, фиксированные
пути `/etc/qeli`, `/root`, `/var/log/qeli` и старый бинарник `/opt/qeli-src/target/release/qeli`.
Его опасный сценарий не запускался. Теперь это совместимый launcher общей изолированной
обвязки: обязательны `--qeli`, `--sha256`, `--output`; выбирается Q05 runtime.
Отсутствие аргументов завершается с кодом 2 до подключения, `--help` — 0.

## Изоляция, воспроизведение и границы

Общая обвязка: `scripts/audit_web_auth_lab.py`; пять адресных сценариев:
`scripts/audit_web_transactions.py`. Пример после задания `QELI_LAB_PASS` в окружении:

```powershell
python scripts/audit_web_auth_lab.py --audit q05 --fixture scripts/audit_web_transactions.py --scenario runtime --qeli /absolute/private/release/qeli --sha256 FULL_SHA256 --output /unique/local/evidence
```

Настоящий manager E2E: `scripts/audit_web_full_restart_lab.py` с теми же обязательными
`--qeli`, `--sha256`, `--output`. Он создаёт только собственный transient unit.
Обычные пакеты используют отдельные NET/mount/PID namespaces. Реальный systemd-пакет
использует отдельные NET/mount namespaces и systemd cgroup, но общий host PID namespace:
он необходим для manager socket credentials. Сеть, INI и session state остаются приватными.
Полные host snapshots, PID/start рабочей `qeli.service` и SHA рабочего бинарника совпали
до/после каждого пакета; temporary unit собран. Рабочие сервисы не заменялись.

Первоначальные ошибки синтаксиса capabilities, недоступные test paths, исправляемый
владельцем mode history и несовместимый с manager socket PID namespace сохранены как
диагностика стенда. Только итоговые канонические результаты учитываются как PASS.

SIGKILL не является тестом внезапного отключения питания. При SIGKILL до rename может
остаться приватный временный inode: тест убирает только точно наблюдавшийся собственный
путь после фиксации доказательств; автоматическая crash-уборка не заявляется.
Directory fsync error не означает откат. Файловый/kernel I/O не получает жёсткий deadline
от async timer. Внешние root-писатели должны соблюдать sidecar протокол; ручная запись
после последней проверки не становится транзакцией. Эти границы описаны в
[мануале](../../manuals/PANEL.md#server-config-writers-v1).

Архивный backup/restore остаётся Q07; VPN users/revoke — Q06. Physical qualification,
новые benchmarks и весь аудит в целом не объявляются завершёнными.
[Итоговые свидетельства](../../../../release/certification/evidence/q05-transactions-20261003.json).
