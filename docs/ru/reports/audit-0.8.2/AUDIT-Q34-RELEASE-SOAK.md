# Q34/Q25 — память при 100 release handover

<!-- normative-sync: audit-q34-release-soak-v5 -->
Исторический checkpoint24сентября; статусы долгов ниже относятся к той дате. Текущий [реестр](../../plans/AUDIT-DEBT.md) учитывает последующие закрытия; новый Q35 scope приведён в конце.


24 сентября 2026. Rust 1.97.0, Linux x86_64, `release --features jemalloc`;
исходники ядра соответствуют `ea87fd49`. Это developer integration, а не итоговая
сертификация 0.8.2, benchmark пропускной способности или A/B reproducibility.

## Измерения

По 100 переключений TCP fake-tls и UDP quic-shape, sample каждые 10 переключений.
Оба сценария: **15/15 утверждений PASS**, всего **30/30**; exit codes `0/0`.
Сохранены одна аутентифицированная сессия, исходные процессы и TUN, связность,
ровно 100 COMMIT клиента/сервера, один точный carrier bypass.

| Транспорт / процесс | RSS baseline → final, KiB | Прирост final / sampled peak, KiB | fd baseline → final | socket fd baseline → final |
|---|---:|---:|---:|---:|
| TCP client | 47736 → 49496 | 1760 / 1904 | 15 → 15 | 5 → 5 |
| TCP server | 53644 → 56036 | 2392 / 2392 | 18 → 18 | 6 → 6 |
| UDP client | 49592 → 50292 | 700 / 3764 | 15 → 16 | 5 → 6 |
| UDP server | 61668 → 74248 | 12580 / 12580 | 18 → 18 | 6 → 6 |

В UDP один дополнительный клиентский socket остаётся стабильным от первого sample
до конца; это не нулевой прирост. Pending candidate=0, CID aliases=3 после handover;
TCP orphan=0. Прежний критерий роста RSS **32768 KiB не изменён**.
Скрипты теперь печатают baseline, final и sampled peak delta: исходные данные
для расчёта сохраняются. Bash syntax и 6 Python harness tests PASS.

[Предыдущий debug FAIL](AUDIT-Q34-LINUX-MATRIX.md) остаётся в evidence.
У debug и этого release отличаются allocator/build profile и ревизия исходников;
результат не доказывает единственную причину прежнего роста и не переписывает
его в PASS. Он подтверждает критерий именно для измеренного release executable.

## Воспроизводимость и оставшийся объём

Worker SHA256: `93ee5dce2fc0e1066d7a1c5943b02dfaca608c1bee67323cabd6e9b52dc3b027`.
Source archive: `4ac2dbae65e440b872ff4a15222e12e60927c238d955ce02872fd448ff12d3a7`
(320 файлов; gateway fix включён, следующий route deadline fix ещё не включён).
Лаба `.11`, приватные net/mount/PID namespaces; сервер `.10` не изменён.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`release-gateway.log`, `roaming-release-soak-100/` с tcp/udp logs, rc, рабочими
сценариями и worker SHA; `packet-matrix-phase/roaming-scripts-measured-sha256.json`,
`harness-checks/` и `release-soak-phase/evidence.json`.

D13 остаётся IN_PROGRESS: нужны stop/reconnect и отказные/многопрофильные сценарии,
снимки threads/tasks, routes/firewall/journals до/после и итоговый снимок исходников.
D11/D12/D14 также не закрыты. Windows VM/Mac/iOS/router runtime пропущен по решению
пользователя. [Реестр](../../plans/AUDIT-DEBT.md).

## Q35: допуск soak-прогонов, 10 октября 2026

F506 / Q35-F003: проверка положительных целых принимала00/000/08/0100
и произвольно большие строки цифр. Bash по-разному трактует такие значения в
test и арифметике. Точный прежний TCP helper с iterations=00 пропустил цикл и
прошёл8финальных resource checks. В fixture использован настоящий /proc текущего
Bash, контролируемые ip/control-counter/worker-selector ответы; ни одного
реального VPN-переключения этот baseline не утверждает. Нулевой цикл и его
ложный допуск воспроизведены исполнением исходного helper, а не копией условия.

Общий scripts/roaming_soak_parameters.sh теперь требует канонические десятичные
целые1..2147483647, без ведущих нулей, знаков, whitespace и overflow; sample_every
не превышает iterations. TCP/UDP helpers и три wrappers используют одну проверку.
Оба основных netns runners валидируют soak-параметры до mktemp, cleanup и
первой сетевой команды. Standalone helpers также проверяют параметры; отсутствие
общего helper вызывает exit/return2. Дефолты не менялись.

F507 / Q35-F004: прежняя UDP matrix с17QUIC/3adapter switches выдавала полный
ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS; общий endurance wrapper с100TCP также
выдавал TCP_10K_PASS. Это воспроизведено настоящими прежними Bash wrappers с
контролируемыми успешными child receipts; полноценная VPN-работа не заявлена.
Теперь standalone UDP matrix печатает qualification, фактические iteration/sample
counts и *_SMOKE при уменьшении QUIC ниже10000 или adapters ниже1000.
Успешный smoke по-прежнему завершает standalone wrapper с exit0, но не выдаёт
*_PASS marker. При достаточных counts и успешных children остаются прежние
endurance PASS markers. Ошибка child останавливает следующие modes.

roaming_resource_release_gate.sh — полный endurance gate: до первой фазы
отклоняет TCP/QUIC<10000, adapters<1000 и неверную частоту sampling. Он не
принимает укороченный smoke за полный тест. Отдельный обязательный
linux_roaming_release_soak.sh сохраняет minimum100 для TCP и UDP QUIC,
вычисление sample_every=iterations/10 и прежние строгие assertions; лишние
CLI аргументы отклоняются, путь executable с пробелами корректно quoted при
version probe. Таким образом, исправление не вводит10k требование вместо
согласованного короткого release gate.

28Linux методов без skips:14новых admission,4UDP wrapper,4endurance wrapper,
4worker identity и2control stats. Реальные Bash/Python/proc/filesystems;
network/child/counter seams контролируемые. Проверены минимумы/границы/overflow,
до-сетевой отказ parent/helper, missing helper, smoke/full labels, bounded100
dispatch, failure stops и прежние SHA/order guards.57Windows методов:
8IPv6 matrix contracts,38native recipes,11workflow checks; shell suites не
названы Windows PASS. Pinned actionlint принял4workflow, новые3suites включены
в CI; Bash syntax всех перенесённых scripts PASS.

Лаба.11: свой временный root, read-back source TAR и20inputs побайтно/SHA;
21known files удалены после exact-set/SHA/process/fd/mount guards. Service777/845
и CLI75bc сохранены, .10не использовалась. Первый генератор патча имел
IndentationError до записи/подключения; ошибка исправлена. Длительный100/10k,
30–60min/8h VPN-soak, peak между samples, task churn и актуальное hosted CI
этим пакетом не выполнены. Предыдущие core/native/runtime результаты имеют
прежний scope; ядро,14native,e3fb digest,protected/OpenWrt cut неизменны.
Q34/Q35 IN_PROGRESS,Q36TODO;30/37DONE81,1%,7остаётся. Q29SIGKILL/ENONET,
Q30/Q31,F459,D06accepted/USER_EXCLUDED сохранены.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F506-F507 evidence: q35-soak-admission-20261010; SEALED 38 files / 1646848 bytes; manifest SHA256 c3feba0ad1c0e010693765f4142a3011a88ac17afa0ef13f9089b38166109f75.

## Q35: изоляция параллельных netns-прогонов, 10 октября 2026

F508 / Q35-F005: TCP и UDP runner использовали фиксированные имена namespaces
и при начальной очистке уничтожали уже существующие процессы с такими именами.
UDP family-switch также менял общий `/etc/netns/qru-cli/hosts`. Прежнюю очистку
обоих runner выполнили внутри независимого внешнего стенда: она действительно
убила чужие для прогона тестовые sentinel-процессы и удалила их namespaces.
Рабочие namespaces и процессы хоста в воспроизведении не использовались.

Теперь каждый запуск до mktemp, очистки и сетевых действий создаёт отдельные
network/mount/PID namespaces. Общий `roaming_netns_isolation.sh` проверяет
идентификаторы, отключает распространение mount-изменений и создаёт частные
`/run`, представление `/etc` через overlay и `/sys`. Фиксированные имена veth,
namespace registry и family-switch hosts-файл доступны только своему прогону.
Все обёртки, вызывающие эти два runner, наследуют это поведение. Ошибка изоляции,
отсутствие helper/supervisor, недостаточные права или ошибка mount блокируют
запуск; небезопасного запасного пути и отключения через переменную среды нет.

`roaming_netns_supervisor.py` сохраняет код завершения и обрабатывает SIGINT,
SIGTERM и смерть supervisor. Цепочка parent-death SIGKILL завершает unshare,
init частного PID namespace и его потомков. Первый вариант на одном unshare
провалил настоящий SIGTERM-тест; затем обработчик, повторно вызывавший Popen.wait,
заблокировался на его lock. Оба прототипа исправлены до коммита: сигнал прерывает
wait, а остановка и ожидание выполняются после выхода из него. Неудачные прогоны
и первоначальные ошибки списка загружаемых файлов сохранены в evidence.

Проверки: 7 методов на настоящем ядре Linux, включая два параллельных запуска
с одинаковыми именами/veth, отдельные hosts-файлы, сохранность соседних процессов,
передачу exit37, реальный EPERM, ошибку overlay и SIGINT/SIGTERM/SIGKILL без
оставшихся потомков; 35 Linux script methods (7 новых + 28 зависимых), без skips.
Ядро использовалось настоящее; сетевые fixture-процессы контролируемые, бинарник
Qeli в этом блоке не запускался. Новый VPN-soak на100/10k/30мин/8ч не заявляется.
Неизменённая квалификация ядра Qeli и native-артефактов наследуется по SHA.

На .11 сохранены PID777/845 и CLI SHA75bc, маршруты, links, правила firewall,
sysctl, resolver/hosts и mounts. В исходном сравнении изменились только счётчики
пакетов/байтов встроенной NAT-цепочки; для структурной проверки нормализованы
только эти счётчики, исходные snapshots и diff сохранены. Source/TAR прочитаны
обратно с проверкой SHA; точный собственный каталог очищен, отсутствие подтверждено.
.10 не использовался; новые компиляции/SDK-кэши не создавались.

Q34/Q35 IN_PROGRESS,Q36TODO;30/37DONE81,1%,7остаётся. Это закрытие дефекта
изоляции harness, без автоматического завершения всего Q35. Q29SIGKILL/ENONET,
Q30/Q31,F459,D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохраняются.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F508 evidence: q35-isolation-20261010; SEALED 48 files / 3037712 bytes; manifest SHA256 cf6b60799473f333c870bd94b412462b9abac406cee18c6ff92c9b4710f3cd83.

## Q35: реальный bounded soak после изоляции runner, 10 октября 2026

Q35-V001 закрывает проверку обновлённых runner на настоящем VPN: выполнен
`linux_roaming_release_soak.sh` с 100 переключениями TCP fake-tls и 100 QUIC,
при sample_every=10. Весь прогон занял **440,95 секунды**, завершился exit0;
TCP **16/16**, QUIC **17/17** утверждений PASS. Использованы текущие скрипты из
`5d9e792ce4d6e6d2c2635e3cb5c0cdd3ed5c99f1`, включая обязательную изоляцию
F508. Независимая внешняя изоляция и timeout480s ограничивали сам тест.

Исполнен ранее действительно собранный Linux x86_64 release0.8.2 с default
server/client и jemalloc: SHA256
`98335046d0c16b2126b22334102011ecfaff8390e0a3b09be5e6c7df87104bc2`.
Все **318 эффективных compiler inputs Cargo/src** побайтно совпадают с текущим
Git. Архив прежней сборки имеет SHA256
`4e9718ca2bec0434796e1b97eb67eecbdde386f02af381ad281676bab3bd955c`.
Различия более широкого дерева qeli ограничены отдельными fuzz Cargo.lock/README,
не включёнными Docker COPY в эту компиляцию. Это повторное использование
подтверждённого executable; новая сборка текущего Docker recipe не заявляется.
Новые native/SDK кэши не создавались.

| Процесс | RSS baseline → final, KiB | Прирост final / sampled peak, KiB | fd baseline → final | socket fd baseline → final |
|---|---:|---:|---:|---:|
| TCP client | 50192 → 52556 | 2364 / 2660 | 18 → 18 | 6 → 6 |
| TCP server | 58520 → 63184 | 4664 / 4664 | 21 → 21 | 7 → 7 |
| QUIC client | 56324 → 56932 | 608 / 3232 | 18 → 19 | 6 → 7 |
| QUIC server | 66560 → 73932 | 7372 / 8924 | 21 → 21 | 7 → 7 |

Порог RSS32768KiB сохранён. Дополнительный клиентский QUIC socket стабилен
от первого sample. Сохранились одна авторизация, исходные client/server workers
и TUN, туннельная связность и точный carrier bypass; каждый клиент/сервер
выполнил ровно100COMMIT. TCP orphan/grace/failure=0; QUIC candidates=0,
CID aliases=3. Проверены восстановление rp_filter и освобождение sysctl leases.

На .11 первоначальный SSH launcher потерял канал по таймауту чтения, потому что
фоновая shell-группа удерживала descriptors канала. Сам тест продолжал работать
под собственным deadline, что подтвердили отдельные read-only polls. Повторного
запуска не было. Ошибка коллектора в ожидаемом TCP label (пропущен /single)
исправлена по сохранённому журналу до очистки. Оба отказа и первоначальные
source-binding отказы сохранены; они не названы результатом отказа VPN.

Перед удалением 64точных regular files проверены по SHA; исходные inputs
покрыты локальным TAR, все generated regular files сохранены отдельно.
Один оставшийся Unix socket классифицирован через lstat; его удалили только
после проверки отсутствия process/cwd/exe/root/fd/argv владельцев и mounts.
Каталог удалён, отсутствие независимо подтверждено. PID777/845, CLI SHA75bc,
маршруты, links, firewall rules, sysctl, hosts/resolver и mounts сохранились.
Изменились только счётчики встроенной NAT-цепочки; raw snapshots/diff сохранены,
структурное сравнение нормализует только builtin packet/byte counters. .10 не
использовалась; служба и пакеты хоста не менялись.

**Границы:** это200 реальных handover и33 проверки за7мин21с, с измерением
каждых10переключений. Непрерывные пики между samples, tasks/threads churn,
10k endurance,30–60мин/8ч, другие adapters и throughput benchmark этим
не закрыты. Q35 остаётся IN_PROGRESS; общий итог30/37DONE(81,1%),7разделов
осталось. Прежние Q29/Q30/Q31/F459/D06/USER_EXCLUDED ограничения сохранены.
Реализации продукта в этом блоке не изменялись.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q35-V001 evidence: q35-runtime-isolation-20261010; SEALED 68 files / 15738597 bytes; manifest SHA256 02427686f08ea2ce22fcdfea86f3f52c5af979101d9d0a015ef93874a33722a2.

## Q35: отказы, конкуренция и короткие control sockets, 10 октября 2026

F509 / Q35-F006: control socket TCP/UDP runner зависел от длины WORK/TMPDIR.
При глубоком каталоге family-switch серверный worker действительно завершался
с `path must be shorter than SUN_LEN`; исходная сессия не устанавливалась.
Исходный отказ и журналы respawn/client сохранены. Это ограничение адреса
Unix socket, не дефект IPv6 handover или авторизации. Runner теперь использует
`/run/qeli-roaming-control/control.sock` и отдельный `control-secondary.sock`.
Каталог mode0700 создаётся после private tmpfs /run, поэтому фиксированные
короткие имена принадлежат только своему запуску. TCP/UDP soak counters и
bonding set-bandwidth/disable-user используют тот же путь; WORK с журналами
сохраняется в заданном TMPDIR. Правка не меняет ядро или пользовательские INI.

На настоящем release ELF SHA98335046 (318точных Cargo/src inputs, как Q35-V001)
выполнены **14 case executions / 320 assertions**, без отказов, за**331.95с**,
в7парах с максимум2одновременными case. Для каждой пары сохранён live /proc
snapshot двух аутентифицированных client/worker групп с разными PID namespaces.
Повтор использует ещё более длинные WORK-пути, включая family-switch. Native и
SDK сборки не повторялись. Точный исходный архив переиспользован по SHA,
новой локальной копии бинарника/14МБ TAR нет; changed scripts проверены отдельно.

| Case execution | PASS assertions | FAIL |
|---|---:|---:|
| tcp-success-a | 20 | 0 |
| tcp-success-b | 20 | 0 |
| tcp-resume | 20 | 0 |
| udp-rollback | 23 | 0 |
| tcp-grace-expiry | 19 | 0 |
| udp-commit-race | 28 | 0 |
| tcp-starvation | 19 | 0 |
| udp-supersede | 28 | 0 |
| udp-family-switch | 35 | 0 |
| udp-loss-replay | 21 | 0 |
| tcp-soak-smoke | 16 | 0 |
| udp-soak-smoke | 17 | 0 |
| tcp-bonding | 26 | 0 |
| tcp-multinode | 28 | 0 |

Soak здесь — **3переключения/sample1** TCP и QUIC для проверки control consumers,
без объявления нового bounded100 или полного10k endurance. Bonding проверяет
настоящие bandwidth/revoke вызовы, multinode — вторую службу/отдельный socket.
Другие cases проверяют TCP reset/resume, full-AUTH после истечения grace,
carrier starvation, UDP rollback/supersede/platform commit race, потерю challenge/
commit с retry/replay и два family commits IPv4↔IPv6. На ядре выполнены7методов
изоляции, включая два одновременных Unix listeners с одинаковым коротким путём;
35Linuxscriptmethods без skips. Core/native/CI evidence неизменённых inputs
наследуется с проверкой SHA; документы проходят9проверок.

Первый внешний наблюдатель принимал только TCP `connected on profile`, поэтому
не регистрировал UDP `authenticated on profile`. Оба реальных маркера теперь
проверяются. Первый запуск сохранил9успешных cases, SUN_LEN/timeout family-switch
и общий exit1; он не переписан в PASS. Ранний read-only retry отказал до изменений,
поскольку первый запуск ещё не завершился. Повтор после исправлений проверил
все14cases и все7concurrent snapshots. Проблемы внешнего наблюдателя отделены от
F509 в исходниках runner. Все первоначальные журналы остаются в evidence.

Собственные generated files сохранены до exact-set/type/SHA/proc/fd/argv/mount
проверок и очистки; отсутствие root подтверждено. Рабочая служба777/845/CLI75bc,
маршруты, links, firewall rules, sysctl, mounts и hosts/resolver сохранены.
Только builtin packet/byte counters нормализуются для структурного сравнения;
raw snapshots/diff остаются. .10не использовалась; пакеты хоста не менялись.

Q35 остаётся IN_PROGRESS: эти14case executions не закрывают полный failure
injection каждого acquire/apply/save, длительный30–60мин/8ч,10k, непрерывные
RSS/tasks пики или весь DoS/fuzz объём. Итог30/37DONE81,1%,7разделов остаётся;
Q29/Q30/Q31/F459/D06/USER_EXCLUDED ограничения сохранены.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F509 evidence: q35-fault-concurrency-20261010; SEALED 486 files / 2884066 bytes; manifest SHA256 bbc5177343dd68a617e36a48929f6afd9b3dfd6d103329e4fc30ab0feb285c6a.
