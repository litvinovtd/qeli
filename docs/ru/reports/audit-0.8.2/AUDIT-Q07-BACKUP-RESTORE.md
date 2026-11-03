# Q07: backup, restore и history — пакеты 1–3

<!-- normative-sync: audit-q07-backup-restore-v3 -->

Дата: 3 октября 2026. **Полный Q07: PASS в согласованном доступном Linux/runtime scope.**
Конфигурации остаются INI; JSON используется для служебных ответов API/evidence.

## Подтверждённые ошибки

| ID | Проблема | Исправление |
| --- | --- | --- |
| Q07-F001, P2 | Portable archive исключает lock-файлы, но exact shape-check требовал вложенный `server.ini.lock`; собственный корректный архив не восстанавливался. | Вложенная проверка допускает сохранённые `.lock`, как publisher и pruner. Inode действующего lock не заменяется. |
| Q07-F002, P1 | Restore принимал отсутствующий identity в overlay и ключ неверной длины; следующий запуск мог создать новый pin или не поднять профиль. | Активные профили требуют обычные 32-byte identity-файлы. Managed paths читаются только из staging даже в overlay; внешние зависимости должны уже существовать. Никакой генерации при проверке. |
| Q07-F003, P1 | Restore принимал HTTPS config без PEM-пары или с невалидными PEM. | Пути remap-ятся в staging, штатный TLS checker проверяет полную согласованную пару без генерации. Внешние пути проверяются по существующим файлам. |
| Q07-F004, P2 | GNU tar сохранял UID/GID загруженного архива; root-сервер затем отвергал custom-path INI как недоверенный. | Extraction использует `--no-same-owner`; содержимое получает владельца пользователя сервера. Прежняя нормализация 0600/0700 сохранена. |

На прежнем release шесть checks FAIL: exact nested lock, отсутствующий identity
в overlay, повреждённый identity, отсутствующая и невалидная TLS-пара, чужой UID.
Missing identity в exact на старом release отказывал по nested lock; этот результат
не считается независимым воспроизведением проверки identity. Все шесть дефектных
случаев прошли на новом release вместе со штатными roundtrip-сценариями.

## Реальная проверка

Финальный release: `d502a58df16f6d86062edaf17d3ee55bc3bb786ae4909bfe9e6d63e56612e7b3`.
38 HTTP/system checks PASS в отдельных NET/mount/PID namespaces:

- Backup с `/etc/qeli/nested/server.ini`, custom users INI и точным profile identity.
- Overlay сохраняет extras; exact удаляет top-level extra и сохраняет nested locks.
- Snapshot не включает предыдущие snapshots/uploads/staging; временные файлы убраны.
- Отказ до публикации при traversal, absolute path, symlink, hardlink, FIFO,
  executable, malformed/missing INI/users/identity/TLS. Прежнее дерево сравнивается
  по SHA, исключая операционные snapshots и sidecars.
- Expanded size >64 MiB и >5000 entries; успешное восстановление после отказов.
- Второй restore сразу получает 409, пока первый ждёт сторонний config FileLock;
  status остаётся отзывчивым, первый успешно заканчивает после unlock.
- Чужой UID/GID становится UID/GID сервера. Custom matching TLS pair проходит
  restore, новый HTTPS-процесс стартует и аутентифицирует администратора.
- Новый обычный worker после roundtrip стартует с тем же identity, без ротации pin.

Дополнительно 75 HTTP checks history/config транзакций PASS на том же release:
точные bytes/revisions/snapshots, 8 writers, ENOSPC, read-only, отказ target rename,
FileLock budget и recovery. Linux: 2265 units PASS / 60 ignored, full/minimal
Clippy и rustfmt PASS. Native и release qualification указаны в evidence ниже.
Это функциональный аудит, не performance benchmark или physical qualification.

## Границы проверки

Оставшиеся после второго пакета сценарии закрыты третьим пакетом ниже. Whole-tree atomicity, автоматический rollback, power loss и несогласованные root writes не заявляются. [Отчёт бюджета](AUDIT-Q05-ARCHIVE-BUDGET.md).

Рабочие службы и binaries не заменялись. Все полные .11 snapshots совпали.
SDK .10 A/B прошёл; default/explicit legacy IPv4 firewall dumps отличаются,
а nft, прочие host-поля, PID/start и binary сохранились. Историческая неатрибутированная
вариативность .10 сохраняется как ограничение: полный network-preservation PASS
для .10 не заявляется. Правила не удалялись/не восстанавливались.
Завершённые исторические debug binaries сохранены losslessly в gzip с проверкой
SHA; завершённый lint cache удалён, исходники и test logs сохранены.

[Свидетельства первого пакета](../../../../release/certification/evidence/q07-backup-restore-20261003.json).

Квалификация этого release: свежие 18/327 matrix, aggregate leak и 100 TCP + 100 QUIC / 33 soak checks PASS. Все четыре native cores прошли A/B и побайтно совпали с Q06; canonical/client copies и ABI/provenance согласованы.

## Второй пакет: publication, recovery и локальное состояние

Финальный release: `771d3a40b11867ce09b7fda0b212bec02a74b8d746e2f7c0b782974c216a13ef`.

| ID | Проблема | Исправление |
| --- | --- | --- |
| Q07-F005, P2 | Неизвестное или пустое `exact` молча означало overlay. | Строгий разбор: HTTP 400 до начала restore. |
| Q07-F006, P1 | Новые клиентские `.ini` обходили file-only проверку `password_command`, действовавшую только для `.conf`. | Оба расширения проходят общий trust checker; notify.ini — отдельный штатный парсер. |
| Q07-F007, P1 | Архив мог заменить локальные rollback/history snapshots. | Операционные пути запрещены в staging на любом уровне. |
| Q07-F008, P2 | Невалидный архив создавал новый snapshot и ротировал прежние до содержательной проверки. | Snapshot после vet/preflight/locks; ротация только после полного успеха. |
| Q07-F009, P2 | Сортировка имени timestamp/PID/sequence удаляла более новый snapshot при переходе 9→10. | Сортировка mtime с path tie-break; текущий snapshot никогда не удаляется. |
| Q07-F010, P1 | Restore игнорировал внешний FileLock users/identity. | Детерминированные locks управляемых зависимостей старого и нового config; canonical aliases дедуплицируются. |
| Q07-F011, P1 | Exact удалял held `.lock` вместе с целиком отсутствующим каталогом, позволяя второму writer захватить другой inode. | Рекурсивная очистка обычных файлов сохраняет вложенные sidecars и их каталоги. |
| Q07-F012, P2 | После частичного rename отказ не указывал recovery snapshot и состояние публикации. | HTTP 500 / ok=false, publication_started=true, rollback_snapshot и инструкция восстановления до рестарта. |
| Q07-F013, P2 | Exact cleanup errors возвращали успех с предупреждением, хотя rollback был неполным. | Неуспех с теми же recovery metadata; snapshot сохраняется. |

На предыдущем точном release: policy **11 FAIL из 14**, publication **6 FAIL из 49**.
Шесть publication failures: три отсутствующих recovery metadata для EIO/ENOSPC/EACCES,
ложный успех prune и два доказательства уничтоженного inode/разделённого flock.
Baseline продолжает независимые probes, но итог FAIL; успешный ручной recovery
старого release не ошибочно объявляется новым исправлением.

Новый release: **14 policy + 49 publication + 38 archive + 75 history = 176 checks PASS**.
EIO/ENOSPC/EACCES второго rename и EACCES prune внедрены process-scoped LD_PRELOAD
только в собственный supervisor внутри проверенных private namespaces; это не
реальное заполнение диска и не замена host syscall/library. Ручной tar recovery
возвращает точные bytes config/users/identity. SIGKILL до/после первого rename
не возвращает ложный HTTP success; свежий worker после recovery аутентифицирует
администратора с прежним identity. Два PIDs проверяются как принадлежащие fixture.

49-check fixture также проверяет отсутствие self-deadlock при canonical aliases,
живой flock после exact и доступность status при отказах. Ошибки снимка/prepare
не трактуются как начало публикации. Power loss и полная атомарность дерева не
заявляются. [Свидетельства второго пакета](../../../../release/certification/evidence/q07-publication-20261003.json).

Квалификация второго пакета: 2265 units / 60 ignored, full/minimal Clippy и rustfmt PASS; свежие 18/327 matrix, aggregate leak и 100 TCP + 100 QUIC / 33 soak PASS. Все четыре native cores прошли A/B и совпали с первым Q07 побайтно; ABI, copies и provenance PASS. .11 snapshots совпали; историческое ограничение .10 legacy IPv4 dumps сохранено, хотя текущая пара совпала.

## Третий пакет и закрытие Q07

Финальный release: `ba7d93afc47c71592e2d1d20e18d2c7c6a6cb0eb4248b674cf713e756aa1c712`.

| ID | Проблема | Исправление |
| --- | --- | --- |
| Q07-F014, P2 | Реальный ENOSPC при распаковке корректного tar возвращал HTTP 400. | Extraction failure возвращает HTTP 500; malformed gzip остаётся HTTP 400. |
| Q07-F015, P2 | Ошибка открытия FileLock на read-only storage возвращала HTTP 409. | Только штатный timeout ожидания FileLock означает 409; ошибки открытия, доверия и IO означают 500. |

На предыдущем точном release оба случая воспроизведены: **2 FAIL из 25** prepare checks. Независимые probes продолжались, общий baseline остался FAIL. Ошибочные промежуточные fixtures не считаются доказательством дефектов.

На финальном release **226 HTTP/system checks PASS**: state 25, prepare 25, policy 14, publication 49, archives 38, history 75. State проверяет объединение inline/external пользователей и групп, приоритет внешнего файла для дубликатов, disabled/лимиты, точные bytes config/users/identity и свежий worker после restore. Реальные inline/external VPN-клиенты аутентифицируются и передают tunnel ping. На новом сервере без panel-secret старый password hash также реально аутентифицирует клиента; выдача прежнего пароля требует отдельного восстановления machine-local state либо явного reset. Неуспешная расшифровка сама пароль не меняет. Same-host reissue, ручное восстановление state key и legacy migration в 0600 проверены. Portable archive исключает оба варианта panel key.

Prepare использует настоящие private tmpfs 128 KiB с ENOSPC и read-only bind mounts: upload, tar write, pre-restore snapshot. Process-scoped LD_PRELOAD только согласует момент операций собственного supervisor; host library не заменяется. До публикации прежние данные и recovery set сохраняются, metadata указывают `publication_started=false` и `rollback_snapshot=null`. Разрыв HTTP во время restore не освобождает guards преждевременно: второй запрос получает 409, status отвечает, первый завершает работу и очищает staging, следующий restore проходит.

Review покрывает источник/структуру архивов, streaming limits и дочерние процессы, staged trust/dependencies, locks и отмену, publication/pruning/recovery, приватность/rotation и history/state. Неиспользуемых runtime-реализаций для удаления в этом пакете не выявлено. Linux: **2266 units PASS / 60 ignored**, full/minimal Clippy и rustfmt PASS. Свежие **18 сценариев / 327 matrix checks**, aggregate leak и **100 TCP + 100 QUIC / 33 soak checks PASS**. Все четыре native cores прошли A/B, ABI/copies/provenance PASS и побайтно совпали с предыдущим Q07. Android disk preflight повторён после освобождения временных unit-link outputs; исходный отказ не скрыт. .11 snapshots совпали; текущая .10 пара совпала, историческое ограничение legacy IPv4 dumps сохраняется.

**Q07: PASS в согласованном доступном Linux/runtime scope.** При read-only после extraction немедленная очистка staging невозможна: оставшиеся файлы приватны (0700/0600), исключены из backups и удаляются вручную после восстановления записи и завершения restore. Это документированное ограничение файловой системы. Публикация остаётся набором per-file rename, без whole-tree atomicity и автоматического rollback; power loss и несогласованные root writes не сертифицированы. Физические advisory-проверки сохраняют согласованные исключения. Рабочие службы не заменялись, push не выполнялся. Следующий раздел плана — Q08.

[Финальные свидетельства Q07](../../../../release/certification/evidence/q07-completion-20261003.json).


Дополнение 8 октября: [Q33/F449](AUDIT-Q33-COMPLETION.md) закрывает обход защиты scripts через path aliases при restore; исходные результаты Q07 выше остаются историческими.

**8 октября,F450/Q33-F053:** [Q33 завершён](AUDIT-Q33-COMPLETION.md): actual baseline два HTTP restore исполняют заменённый harmless marker; фикс хранит hooks startup/последующих worker до завершения supervisor и запрещает exact deletion. Fixed8+later10 runtime, CLI5/backup50/lifecycle1/post_down3/privateIO2/Clippy PASS; свежая native/ABI квалификация и raw seal приведены в отчёте. Q33 5/5 DONE;30/37(81,1%),7осталось. Исторические ограничения Q29/Q30/Q31/Q34/D06 сохраняются; без push/deploy/release.
