# Q14 — точное восстановление серверного firewall после crash

<!-- normative-sync: audit-q14-firewall-journal-v1 -->

24 сентября 2026. База `855d1906`. Частичное закрытие D04/D09/D10.

## Q14-F038, P1 — SIGKILL терял точные спецификации NAT и DNS

Работающий worker сохранял точные правила в RAM. После SIGKILL startup recovery
использовал только поиск комментариев через `iptables -S`. Ошибка перечисления была
предупреждением: новый профиль запускался, а NAT, FORWARD, MSS, DNS INPUT и REDIRECT
удалённого профиля оставались. На baseline воспроизведено **9 → 9 оставшихся правил**;
новый профиль уже слушал, исходного профиля в конфиге не было. `-C/-D` при этом работали.

Добавлен `server-firewall.state` в `STATE_DIRECTORY` (по умолчанию `/var/lib/qeli`).
До каждой попытки `-A/-I` атомарная запись с fsync сохраняет семью, таблицу, цепочку,
точные аргументы и backend (`nft`/`legacy`). Это внутренний журнал восстановления;
пользовательские конфиги остаются INI. Журнал ограничен 8 MiB, 32768 спецификациями и
64 группами network namespace. Проверяются допустимые цепочки, команды/аргументы,
цели и комментарии Qeli; неподдерживаемая версия и повреждение дают ошибку.

Группы разделены по boot ID и `SO_NETNS_COOKIE`. Живой descriptor закрепляет namespace;
обнаруженная смена контекста навсегда инвалидирует текущую session. После другого boot
валидный старый журнал перестаёт быть источником команд. Чужая группа не проверяется
и не стирается. Server worker требует поддержку `SO_NETNS_COOKIE` и безопасный state
каталог, даже если профиль не устанавливает NAT. Недоступность обязательного контекста
не переключает сервер на слабое сравнение inode.

После эксклюзивного worker admission, до sysctl recovery, tagged sweep и запуска
профилей журнал очищает только текущую группу через `-C/-D`, независимо от конфига
и результата `-S`. Отсутствие правила подтверждается отдельно. Ошибка удаления,
неизвестный результат, смена backend или повреждённый файл сохраняют unresolved state
и прерывают startup. Успешные соседние записи удаляются отдельно; повторная попытка
продолжает оставшуюся работу. Живой cleanup использует те же записи. После очистки
сохраняются пустой envelope и стабильный `.lock`: удалять lock-файл нельзя.

Безопасный обход каталогов и bounded read по открытому descriptor вынесены из sysctl
в общий `state_storage`; SO_NETNS_COOKIE также использует общую реализацию. Сохранены
запрет symlink/FIFO/hardlink, политика владельцев, режим 0600, межпроцессный flock и
atomic replace. Очередь и команды входят в существующий срок операции 15 секунд;
непрерываемый filesystem I/O этим не превращается в жёсткий deadline.

## Проверки

- **1501 host + 71 config; 9 feature/cross/lint checks PASS**.
- **2044 Linux + 35 privileged + 8 worker lifecycle PASS**.
- 10 новых portable, 7 Linux и 1 privileged регрессия: reload после неизвестного
  исхода, запись до callback, сохранение failed siblings, namespace/boot/backend,
  повреждение, unsafe file, дедлайн flock и sticky context loss.
- `scripts/audit_firewall_recovery.py`: **27 проверки PASS** в приватных
  net/mount/PID namespaces. Реальный iptables-nft под wrapper, который адресно отказывает
  в `-S`/`-D` или подменяет ответ `--version`. NAT/DNS удалённого профиля восстановлены
  после SIGKILL; отказ удаления, backend mismatch и corrupt journal останавливают
  worker и сохраняют evidence; восстановление после устранения отказа успешно;
  операторские IPv4/IPv6-правила сохранены.
- Тот же финальный runner на baseline: ожидаемый exit 1, новый worker запущен,
  все 9 правил остались. Первичная fixture с включённым `forward_private` в recovery
  профиле исправлена; её неуспешный запуск сохранён как `baseline-v1`, не считается
  воспроизведением дефекта. `baseline-v2` подтверждал дефект; финальный — `baseline-v3`.
- Текущая packet matrix: **17/17 cases, 301 assertions PASS**; реальные resolved/D-Bus и packet checks.

Source snapshot: 333 files, archive SHA256 `c90eac3576017ed63738ff71da850f530494d456088dd413aa85715457d81d34`.
Worker SHA256: `4d08ba79721bd4d9d24439fce16feecc21671d0c8ad6a7ca7c71da1c5d0e59f2`.
Baseline SHA256: `dfcbd8c654a57dd805aa15c3a7fc0feed1b372e66093a5cc251a7f91f9b5a72a`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/firewall-journal-phase/`,
`firewall-journal-final-v1.log`, `firewall-journal-baseline-v3/`, `firewall-journal-fixed-v1/`,
`lifecycle-firewall-journal/`, `packet-matrix-firewall-journal-v2/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Границы и эксплуатация

Для recovery сохраните исходный `STATE_DIRECTORY`, network namespace и backend.
Смена state пути не переносит журнал. Перед обновлением остановите прежний worker:
старый binary не участвует в network lease и не записывал exact state. Его правила
доступны только историческому tagged sweep; недоступный listing не позволяет
восстановить неизвестные спецификации. Wrapper-тест не сертифицирует произвольные
native nft/firewalld правила или одновременную замену backend администратором.

`qeli-nat:*` зарезервирован за сервером Qeli. Это cooperative ownership, не доказательство
принадлежности произвольного правила, которое root намеренно создал с идентичной
спецификацией. Проверка и внешняя kernel-команда не атомарны относительно вмешательства
root. Полные client route/DNS/kill-switch crash recovery и D04 остаются открытыми.
ABI, wire и INI-ключи не менялись. `.10` не изменялся; проверки выполнялись на `.11`.
Windows VM/Mac/iOS/router runtime остаются SKIPPED по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md)

Первый запуск packet matrix остановился до сетевых сценариев из-за неполного архива harness (`release_certification.py` отсутствовал). Архив исправлен; окончательный прогон — `firewall-journal-packet-matrix-v2`, исходный отказ сохранён.

Продолжение 24 сентября: [16 native mixed/firewalld сценариев](AUDIT-Q14-MIXED-FIREWALL.md) подтверждают сохранение правил и журналов. Нативное nft-выражение может сломать подтверждение отсутствия через `-C`, хотя `-D` уже удалил правило: журнал сохраняется до ручного восстановления совместимости. Wrapper, отключавший только `-S`, не закрывал этот случай.
