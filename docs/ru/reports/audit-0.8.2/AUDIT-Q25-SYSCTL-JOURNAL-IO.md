# Q25 — безопасное чтение и ожидание sysctl-журнала

<!-- normative-sync: audit-q25-sysctl-journal-io-v1 -->

Дата: 24 сентября 2026. Baseline: `d56bf1ce`. Часть D02/D05 в
[реестре техдолга](../../plans/AUDIT-DEBT.md); эти группы целиком ещё не закрыты.

## Находки и исправления

| ID | Проблема | Исправление |
|---|---|---|
| Q25-F069, P2 | `symlink_metadata` проверял один pathname snapshot, затем `fs::read` повторно открывал путь без ограничения чтения. Растущий файл обходил лимит 128 КиБ; hardlink и group/world-writable журнал могли разрешать stale recovery. | Открытие с O_NOFOLLOW/NONBLOCK/CLOEXEC; regular/single-link/mode/size проверяются на fd. Чтение ограничено limit+1; размер и Stamp открытого файла повторно проверяются. Ошибка не разрешает prune, kernel write или retirement журнала. |
| Q25-F070, P2 | Общий `FileLock` открывал sidecar O_WRONLY: FIFO без reader блокировал поток до обещанной проверки metadata. | NONBLOCK до проверки типа. Обычные файлы по-прежнему используют advisory flock; FIFO не ждёт peer и не получает chown. |
| Q25-F071, P2 | Внутренний mutex и flock sysctl могли ожидаться неограниченно; namespace выбирался уже после ожидания. | Общий бюджет ожидания двух блокировок — 15 с. Новый `FileLock::acquire_timeout` не меняет срок ожидания остальных callers. Контекст net/PID/time фиксируется на входе и сравнивается после lock, до загрузки/prune/persist. |

Проверка snapshot переиспользует `config_source::Stamp`. Формат sysctls.state остаётся
версией 2; изменения INI, ABI и wire format отсутствуют. Ошибки не удаляют сохранённые
значения. Защита не делает путь атомарным относительно привилегированного стороннего writer.

## Проверка

- 12 новых тестов на Linux: 6 file snapshot, 2 отказа stale recovery от недоверенного
  журнала, 2 namespace/local lock, 2 FileLock FIFO/contention. Из них 5 переносимы на Windows.
- Baseline `d56bf1ce` с добавленными regression fixtures: **3 ожидаемых FAIL** — writable
  journal, hardlinked journal и FIFO lock. Старый FIFO-тест принудительно разблокирует
  свой fixture reader после 300 мс, поэтому воспроизведение само не зависает.
- Host: **1426 unit + 71 config integration PASS**. Feature/cross/lint-матрица PASS;
  четыре needless-borrow замечания к новым Unix-тестам исправлены, Clippy повторён.
- Linux: **1874 обычных теста + 18 privileged regressions PASS**; повтор всех
  **8 worker lifecycle E2E PASS**. Результаты: `sysctl-fixed.log` и `lifecycle-sysctl/`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/sysctl-phase/`,
`sysctl-baseline-more.log`, `sysctl-fixed.log`, `linux-source-final-manifest.json`.
Команды окружения и изоляции те же, что в [предыдущем Linux-проходе](AUDIT-Q14-RETAINED-CLEANUP.md).

## Остаток D02/D05

Доказательство исходного интерфейса при per-link restore, внутренняя проверка каждой
sysctl операции, reuse долговременной namespace identity и trust родительского каталога
ещё требуют отдельного закрытия. Ограничено именно ожидание mutex/flock; файловый I/O,
последовательность внешних команд и вся cleanup-транзакция общего deadline не получили.
Синхронный preflight в async handlers также остаётся D05. Эти ограничения не скрываются
успешным unit/cross/native прогоном.

Внутренние I/O-границы позднее защищены в [Q25-F077](AUDIT-Q25-SYSCTL-CONTEXT-IO.md); это не полное закрытие D02.
