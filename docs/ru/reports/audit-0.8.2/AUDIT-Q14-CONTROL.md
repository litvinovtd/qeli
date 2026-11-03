# Q14: control socket, границы API и lifecycle hooks

Дата: 23 сентября 2026. Исходная точка: `dc93d50c`. Статус раздела 14: **IN_PROGRESS**.

## Находки и исправления

| ID | Приоритет | Воспроизводимый путь и последствия | Исправление |
|---|---|---|---|
| Q14-F008 | P1 | Второй worker безусловно unlink-ил `control.sock`: активный listener терял имя; обычный файл по указанному пути также удалялся. | Неблокирующий flock на постоянном sidecar до конца worker; проверка типа/владельца, active/stale probe; cleanup только своего dev/inode. |
| Q14-F009 | P1 | `QELI_CONTROL_SOCKET=/tmp/custom.sock` заставлял root-процесс chmod-ить общий `/tmp` в 0700. | Existing parent проверяется без chmod; новый создаётся 0700, опасные предки и symlink parent отвергаются; systemd RuntimeDirectoryMode=0700. |
| Q14-F010 | P2 | `take(limit).lines()` превращал достижение лимита в EOF и принимал валидный JSON-префикс oversized-команды; CLI аналогично возвращал обрезанный ответ. | Общий ограниченный reader с lookahead, явной ошибкой переполнения и LF/CRLF; CLI читает одну строку и не ждёт EOF после неё. |
| Q14-F011 | P2 | Peer, не читающий большой ответ, мог навсегда занять один из 16 handlers; у CLI connect/write также не было deadline. | Запись и CLI connect ограничены 5 с; запрос 64 KiB, ответ 8 MiB, чтение CLI 15 с; размер проверяется до записи. |
| Q14-F012 | P2 | Control API принимал изменения во время teardown профилей; abort внешней задачи не дожидался её handlers. Ошибка startup после spawn также оставляла control task. | Control stop → закрытие listener → join принятых handlers → teardown профилей; socket lease удерживается до конца. Fallible NAT cleanup перенесён до spawn. |
| Q14-F013 | P2 | `post_down` выполнялся для disabled/ещё не поднятого профиля. Snapshot и done-set забирались разными блокировками; fallback мог переопределить фактический WAN. | Единственная атомарная операция remove snapshot одновременно подтверждает готовность и забирает право на hook. Done-set и повторный WAN fallback удалены. |

Control admission закрывается при stop или ошибке accept. Уже принятые команды дожидаются
завершения, чтобы не отменять disk/runtime mutation на произвольном await. Это не гарантия
от SIGKILL: supervisor сохраняет общий grace 60 с. Lease находится у worker, а не только
в control task: другой worker не может начать cleanup NAT, пока прежний завершает профили.
Чужие процессы с тем же uid/root, намеренно заменяющие lock/каталог, не являются отдельной
границей безопасности; исходные права файлов остаются обязательными.

Hook snapshot регистрируется после TUN/routing/NDP setup, перед post_up. Даже если post_up
пустой, завершился ошибкой или был прерван, post_down нужен для готового поколения. Ранняя
ошибка setup и disabled не дают такой регистрации. Проверка trusted file сохранена.
Синтаксис конфигов не меняется: INI; JSON используется только в служебном API.

## Проверки

- 7 host-тестов реального control_io: границы LF/CRLF/EOF, overflow/UTF-8, valid JSON prefix,
  получение ответа без EOF, read/write deadlines, отклонение некорректной исходящей рамки.
  На прежнем алгоритме reader два regression tests FAIL; после исправления все 7 PASS.
- Общий Windows unit-набор: 748 PASS; config editor/policy 52, examples 7, server INI 12:
  **819 Rust-тестов PASS**. Минимальный transport-core-ffi check PASS.
- 12 новых Linux-only tests написаны и скомпилированы, **не выполнены**: 8 filesystem/lease,
  3 control shutdown/admission/drain, 1 hook generations/disabled/early failure/snapshot.
- Linux all-targets Clippy PASS с единственным заранее известным исключением
  `clippy::chunks_exact_to_as_chunks` в неизменённом `ndp_proxy.rs`. Это не strict Clippy PASS.
- Rustfmt, git diff check и 9 docs checks PASS. RU/EN manual, registry и packaged unit обновлены.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/control-audit-20260923` — исходные файлы,
логи before/after, итоговый diff и verification.json. Проверки не трогают TUN/firewall,
не используют внешний SSH-стенд и не подтверждают производительность.

## Открытые проверки и следующий участок

Linux runtime для Unix permissions/flock, второго worker, systemd upgrade, реального
SIGTERM/accept failure и hook shell ещё обязателен. Принудительная отмена внешнего worker
future/panic, потомки hook-процесса, bounded hook stdout/stderr и связь trusted config fd
с распарсенным содержимым остаются отдельными задачами. Следующий проход — hook process
ownership/output limits и startup rollback. Полный Q14 и полный аудит Qeli не закрыты.

Продолжение: [Q14-F037](AUDIT-Q14-WORKER-NETWORK-LEASE.md) закрывает обход control lease через другой путь/namespace файловой системы. Новый kernel lease ограничивает server worker на уровне сети; SIGKILL/deleted-profile recovery проверено для доступных tagged rules. Persistent exact-rule journal и mixed nft остаются открыты.

Позднейшее продолжение: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) добавляет persistent exact server firewall journal и проверяет восстановление при отказе listing. Ограничения клиентского crash recovery и общей mixed nft/firewalld матрицы сохраняются.
