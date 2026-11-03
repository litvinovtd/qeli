# Q25-F107/F108: асинхронные операции kill-switch и сохранение DROP при отказе unhook

25 сентября 2026. База `1d066863`. D05/D09, Linux.

## Q25-F107: блокирующие операции firewall и отмена

Установка и обновление kill-switch уже ожидали DNS асинхронно, но затем выполняли
все iptables/ip6tables-команды в async-потоке. `cleanup_routing_features` также
синхронно снимал forwarding и firewall. Задержка команды останавливала соседние задачи
однопоточного runtime. Простой перенос в фоновую задачу был бы недостаточен: прежний
внешний `select` по stop мог бы потерять выполняющуюся сетевую операцию и её ошибку.

Подготовка отделена от изменения firewall. `prepare_engage` и `prepare_refresh`
возвращают владеющую данными операцию: контекст namespace, исходный deadline,
адреса сервера, разрешённые resolvers и параметры. Read-only подготовку разрешено
отменить немедленно; при таком отказе firewall не изменяется. Начатая операция
выполняется через общий присоединяемый worker, наследующий NET/mount-контекст.
Её результат принимается даже после stop: ошибка не превращается в успешную отмену.
При успешной установке/refresh после stop клиент переходит к обычной очистке без
нового подключения. Прежние бюджеты операций и отдельного setup rollback сохранены.

Все шесть терминальных путей вызывают асинхронный `cleanup_routing_features` и ждут
полной последовательности forwarding → kill-switch до post_down и освобождения lease.
Ошибка предыдущей очистки по-прежнему запрещает снятие kill-switch. Отказ создания
потока/контекста/panic также возвращает ошибку; принудительный Drop ждёт worker
синхронно и не оставляет мутацию без владельца. При уничтожении setup/refresh future
готовые firewall-правила остаются для recovery: Drop не снимает защиту автоматически.

Дублирующие алгоритмы не добавлены. Существующие тестовые адаптеры вызывают ту же
подготовленную операцию в своём потоке, сохраняя thread-local модели команд; новый
production-переход между потоками проверяется отдельно. INI и публичный C ABI не менялись.

## Q25-F108: нельзя очищать цепочку с неподтверждённым удалением переходов

`teardown_family` накапливал ошибку после безуспешного удаления OUTPUT/FORWARD jump,
но продолжал `-F` и `-X`. Очистка убирала DROP из цепочки, в которую ещё направлялся
трафик; ошибка удаления самой цепочки не возвращала защиту.

Теперь при ошибке или неизвестном результате unhook функция возвращается до `-F/-X`.
Точная цепочка и её DROP сохраняются для восстановления. Это распространяется на
обычное снятие и rollback setup. Успешная очистка другой семьи не отменяется: отказ
одной IPv4/IPv6-операции не означает, что защита обеих семей всё ещё установлена.
Новый контракт запрещает именно очистку потенциально используемой цепочки; он не
обещает атомарную остановку двух firewall-семейств или защиту от внешнего root.

## Проверки

- **8 новых переносимых регрессий PASS**: отмена до подготовки/во время read-only,
  сохранение результата и поздней ошибки после stop, join при Drop, запрет `-F/-X`
  при оставшемся OUTPUT/FORWARD jump и неизвестном состоянии переходов.
- Сравнение реального клиента в однопоточном runtime: **8 baseline + 12 fixed сценариев**,
  TCP/UDP × setup/refresh/cleanup, нормальный stop и отказы команд. Во время задержки
  baseline дал **0** heartbeat тиков, fixed — **7–8** за каждый интервал около 800 мс,
  в том числе после сигнала остановки. Конкурирующий запуск во всех 20 случаях получил
  отказ `cannot reserve TUN`: сетевой lease оставался у исходного клиента.
- До запуска 60 UDP-проб получили ответы; при удержании firewall **60/60 заблокированы**
  с ростом DROP-счётчиков и нулевой доставкой. После отказа cleanup baseline пропустил
  **6/6**, fixed — **0/6**. После отказа refresh fixed заблокировал ещё **6/6**.
  Отказ setup сохранил `failed`/exit 1 после полного rollback. Refresh/cleanup fault
  сохранили `failed`/exit 1 и recovery; **6/6 повторных явных запусков** завершили очистку.
  Успехи проверены точным сравнением маршрутов/правил, отсутствием TUN и journal state.
- **38/38 hostname network cells**, 34 crash/recovery, **1220 основных + 806 вложенных
  checks PASS**. Обе перестановки IPv4/IPv6 nft/legacy и private firewalld: 1088 прямых
  UDP-попыток под защитой заблокированы, 656 разрешённых получили ответы.
- Полный снимок: **1564 host + 71 config; 2119 Linux + 46 privileged + 8 worker lifecycle
  PASS**. Все 9 host/cross/feature/lint/format команд прошли; прежнее исключение Clippy
  `chunks_exact_to_as_chunks` сохранено. Проверки RU/EN документации и `git diff --check` PASS.

## Доказательства и границы

Лаба: только `10.66.116.11`, Debian/Linux 6.12.105+deb13, Rust 1.97;
локально Windows/Rust 1.98. Рабочий сервер `10.66.116.10` не использовался.
Private NET/mount/PID и `/run`, `/var/lib`, `/var/log`, `/etc/qeli`, `/tmp`.
Матрица: iptables 1.8.11 nft/legacy, nft 1.1.3, private firewalld 2.3.1.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`firewall-task-phase/evidence.json` связывает результаты, архивы и **349 source files**.
`checks.json`/логи сохраняют команды. Манифесты **21 сценарного файла** содержат raw/LF
SHA; матрица использовала v1, новый runtime — v2. Между ними изменился только
`audit_firewall_task.py`: явный серверный адрес вместо wildcard. Rust, driver и остальные
сценарии не менялись; matrix fixture hashes сверены с исходным манифестом.

Запуски: `firewall-task-linux-v1`, `firewall-task-driver-v1`, `firewall-task-matrix-v1`,
`firewall-task-repro-v2`. Итоговые harness exit 0; внутри fault-сценариев ожидаемый client
exit 1. Сохранены before/held/after/recovered, UDP counters/receiver log, конкурентный
запуск, обёртки команд, исходники и Cargo.lock тестового драйвера. Baseline — замороженный
F106 driver. Обёртки задерживают существующие команды и вводят отказ до изменения ядра.

**Исходный `firewall-task-repro-v1` сохранён с FAIL (19/20).** Fixed UDP refresh fault
удержал защиту, но повторный запуск не получил ServerHello за 30 секунд. Сервер слушал
`0.0.0.0`, клиент обращался к второму IP `192.0.2.3`; журнал сервера подтверждает получение
handshake и отправку ответов. Отдельная native-проба `firewall-task-wildcard-source`
подтвердила ответ wildcard UDP-сокета с `192.0.2.1`, явная привязка даёт `192.0.2.3`.
Это объяснение согласуется с наблюдениями, но захват пакетов именно Qeli ещё не выполнен.
В v2 сервер привязан к нужному адресу; все 20 сценариев прошли. **Wildcard UDP на нескольких
локальных IP не исправлен и не объявляется PASS** — отдельный открытый пункт D06/D10.

Повтор: `scripts/audit_firewall_task.py --qeli <worker> --driver <fixed-driver>
--baseline-driver <F106-driver> --artifacts <new-dir>`. Требуются root и изолированный
Linux; driver — тестовая обвязка, не поставляемый клиент. В новых runtime-сценариях DNS
выключен; матрица проверяет свои DNS-комбинации. Времена из debug fixture не являются
бенчмарком или гарантией общего shutdown deadline.
| Artifact | SHA-256 |
|---|---|
| `qeli-firewall-task-v1-worker` | `584d73ff8048be5da5cb5391b462f6dfeea4447f89a0fe86317defc3c808651d` |
| `qeli-firewall-task-driver-v1` | `18f37b0b8b2972cf02a36cc1a8ec052d1bed01e7cca160b91f7a2f28a8ee6388` |
| `qeli-teardown-task-driver-v1 (baseline)` | `5ff88577bf07542d1b947a36800925d15eb2d74ccabc049377233ce5ded2e87f` |
| `linux-source-final.tar.gz` | `dad8570eb9d62a384296405341868e592461f86263c970c7d29cceb47cdb8495` |
| `firewall-task-matrix-v1.tar.gz` | `679a2e687ad292c71c509d7836a3c5be59daf739e01f04be2800e2c66b470a69` |
| `firewall-task-repro-v1.tar.gz` | `17e4440b35e9f94601400db15f8c8606248018333888ab345f2100df8db8c1ad` |
| `firewall-task-repro-v2.tar.gz` | `5ff4573e976259a1130e07184ef56446741e7062805da71d4174032f17e25ef1` |
| `firewall-task-scripts.tar.gz` | `e2cbadd3e2c44d03823a73689ecc02f4418f6152f536b3fd6ad46605727d6248` |
| `firewall-task-driver.tar.gz` | `ac32513cbaf04587a34631ebce51df2fff469829d426623a2baaab99edd87512` |
| `lifecycle-firewall-task-v1.tar.gz` | `bf960a5e4663a901c45d0395d6d53ff777030477104de22a2974f2012a0a7784` |
| `firewall-task-scripts-v2.tar.gz` | `920bbe0aea159f7cdc2555a91c14ab1676ea48a40ae24386df4aa5fce4a57f56` |


D05 остаётся **IN_PROGRESS**: startup recovery routes/DNS, ранние error/Drop-пути,
внутренние locks/I/O, публикация диагностических файлов и общий NetworkPlan/shutdown
deadline ещё требуют работы. Принудительная отмена может синхронно ожидать уже
запущенный syscall; обычный stop не является жёстким прерыванием системной операции.

D06/D10/D11/D12/D13 и итоговый benchmark открыты. Новые разделы полного аудита не
открывались. Windows VM, Mac/iOS и физический роутер — **SKIPPED по решению пользователя**;
свежий Android-пакет здесь не проверяется. Техдолг: **4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO**.
[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/OPERATIONS.md).

Продолжение: [Q15-F002](AUDIT-Q15-UDP-LOCAL-ADDRESS.md) подтвердил источник ответов захватом пакетов Qeli и исправил wildcard UDP. Исходный FAIL выше сохранён; общий D06/D10 остаётся открытым.

Сверка после Q25-F109: startup route/DNS recovery перенесён в joined worker с сохранением lease и поздних ошибок. Этот конкретный долг закрыт; прочие границы D05 выше остаются. [Результат](AUDIT-Q25-STARTUP-RECOVERY-TASK.md).
