# Q25: persistent TUN/TAP после SIGKILL

Дата: 24 сентября 2026. Проверенный код: `25688fe8`.
Это runtime-подтверждение существующей защиты, **новый дефект не обнаружен**.
Persistent TUN часть D04 закрыта в границах безопасного отказа и ручного удаления
подтверждённого остатка. D04 остаётся **IN_PROGRESS** из-за mixed firewall матрицы.

## Проверяемый контракт

Обычный непостоянный интерфейс исчезает после закрытия последнего queue fd.
Persistent TUN/TAP переживает SIGKILL. Новый managed-клиент не вправе считать его
своим только по имени: route recovery отказывает до DNS/handshake, оставляет
устройство, адреса, маршруты и журнал. DNS живого индекса не очищается по маркеру.

После подтверждённой остановки владельцев администратор может удалить ненужный
остаток в исходном namespace. Только затем штатный restart с тем же `dev` выполняет
recovery: снимает подтверждённые физические записи, освобождает DNS-маркер исчезнувшего
link, создаёт новый интерфейс и восстанавливает связь. Это не автоматическое удаление
persistent TUN. Процедура описана в [диагностике §6.82](../../manuals/TROUBLESHOOTING.md#682-linux-persistent-tuntap-пережил-остановку-клиента).

## Сценарий и свидетельства

Добавлены `scripts/audit_persistent_tun_shim.c` и `scripts/audit_persistent_tun.py`;
расширен `scripts/ipv6_netns_case.sh`. Test-only preload на исходном fd после успешного
exclusive `TUNSETIFF` включает persistence и сохраняет PID/name свидетельство.
Последующие запуски клиента используют неизменённый бинарник без preload.

После реального SIGKILL/wait проверяются исходный ifindex и kernel persist flag,
затем запускается новый managed-клиент. Отказ должен завершиться самостоятельно
с ненулевым exit и точной диагностикой; timeout считается FAIL. До/после сравниваются
link, адреса, обе таблицы маршрутов и журнал. DNS-сценарии дополнительно проверяют
DNS-маркер, серверы и catch-all domain настоящего resolved, обе filter-таблицы.
Перед ручным удалением повторно проверяются identity/type; последующие обычные
restart, трафик и clean stop проверяет существующий matrix harness.

- **17/17 строк, 19 сетевых сценариев, 506 основных утверждений PASS**.
- **17 persistent-сценариев, 199 подробных проверок PASS**. Они вложены в 17 агрегатных
  утверждений основной матрицы; суммы не означают 705 независимых тестов.
- 12 outer IPv4/IPv6 × inner IPv4/IPv6 × TCP/UDP fake-TLS/UDP QUIC full-сценариев,
  TAP, две DNS-сети и два MTU/PMTU сценария. Два split-контроля работают без persistence.
- 15 route crash/restart проверяют также сохранение постороннего static-маршрута;
  два DNS crash/restart используют настоящий private resolved/D-Bus и kill-switch.
- Отказ занимал 0.016–0.017 s с exit 1; это наблюдение на стенде, не SLA.
- 8 matrix contract tests, shell syntax и компиляция shim с `-Wall -Wextra -Werror` PASS.

Стенд: Debian, Linux `6.12.105+deb13-amd64`, x86_64, GCC 14.2.0,
iptables/ip6tables 1.8.11 (nf_tables). Клиент и тестовый сервер работают в отдельных
network namespaces внутри private mount/PID окружения; `/var/lib`, `/run`, `/var/log`,
`/tmp`, `/etc/qeli` изолированы. Работающий сервер лабы не заменялся.

Runtime worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
Использован прежний frozen worker: все 340 Rust/conformance файлов совпадают с его
проверенным снимком; remote source сверён до и после прогона. Rust не изменён,
полные Rust-наборы заново не запускались. Новый preload меняет только тестовую очередь.
Harness archive SHA256: `f81d5203b39ce06117ad790ad3ac5f8e368ee7d346b8f4965e1e511bcd3beb50`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/persistent-tun-phase/`,
`persistent-tun-smoke-v1/`, `persistent-tun-matrix-v1/` и одноимённые logs/rc/tar.
Сохранены commands, source/script/binary hashes, JSON snapshots и каждый отказ/restart.
Для повторения есть `persistent-tun-phase/matrix.sh`; в изолированном Linux окружении
он компилирует shim и запускает матрицу с `QELI_PERSIST_TUN_SHIM`,
`QELI_ROUTE_CRASH_CHECK=1`, `QELI_DNS_CRASH_CHECK=1`, `QELI_DNS_KILL_SWITCH=1`.

## Границы

Подтверждён managed full-tunnel crash со старым именем и общим state-каталогом.
Автоматическое усыновление чужого/persistent устройства, переименованные остатки,
конкурентная подмена другим root и ручное восстановление произвольного хоста не
сертифицированы. `dev_attach` с чужим sysfs остаётся D06; mixed nft/legacy/firewalld
остаётся D04/D10. Это не новые результаты benchmark или финального native build.

Общий реестр: **3/15 DONE, 10 IN_PROGRESS, 2 TODO — 20% закрытых групп**.
[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md).

Итоговое продолжение D04: [клиентская mixed packet/recovery матрица и Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) завершены, D04 DONE в текущем реестре. Исторические IN_PROGRESS выше относятся к прежнему снимку. D10 (расширенные политики/топологии) и D13 (рост состояния) остаются открытыми.
