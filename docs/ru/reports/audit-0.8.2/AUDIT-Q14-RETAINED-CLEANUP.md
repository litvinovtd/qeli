# Q14 — точная очистка NAT и результат завершения поколения

<!-- normative-sync: audit-q14-retained-cleanup-v1 -->

Дата: 24 сентября 2026. Baseline: `d85ead10`. Закрывает D01 в
[реестре техдолга](../../plans/AUDIT-DEBT.md); полный аудит остаётся открытым.

## Исправления

**Q14-F027: generic NAT и старые поколения внутри живого worker.** До изменения
ошибки tagged sweep только логировались. После отказа teardown профиль мог уйти
в backoff, затем новый результат затирал ошибку старого поколения. Теперь worker
сохраняет точные IPv4/IPv6 спецификации NAT, FORWARD, MSS и DNS REDIRECT до `-A/-I`.
Неудачный или оборвавшийся вызов не удаляет запись. Очистка проверяет каждое правило
через `-C/-D`, продолжает другие записи после ошибки и освобождает только подтверждённо
отсутствующие. Недоступная утилита оставляет запись для retry. Предел — 32768 уникальных
спецификаций; заполнение запрещает новую неучтённую мутацию, повторы не расходуют место.
DNS INPUT сохраняет свой существующий реестр lease; historical tag sweep остаётся
дополнительным best-effort восстановлением, включая переходы старых конфигураций.

`run_profile` различает ошибку работы и ошибку очистки. Обычная ошибка запуска может
повторяться после успешной очистки. При неполном teardown новый профиль в том же worker
не запускается: ошибка доходит до worker, который завершает остальные задачи и возвращает
отказ. Это сохраняет ошибку очереди TUN, удерживающей fd после трёх секунд ожидания,
и не допускает замены поколения поверх оставшихся ресурсов. Raw fd чужого потока не закрывается.

**Q14-F033, P2: IPv4 forwarding оставался включённым после успешного stop.** Scope
`server-ipv4` приобретался на срок жизни worker, но не освобождался при штатной остановке.
Теперь итоговая очистка освобождает его после всех профилей и exact firewall retry;
ошибка входит в результат stop. Общие владельцы по-прежнему учитываются журналом sysctl.
Остановка одного профиля не отключает forwarding под другим работающим профилем.

## Проверка

- Host: **1421 unit + 71 config integration PASS**; девять команд feature/cross/lint-матрицы PASS.
- Linux, Rust 1.97.0, Debian kernel 6.12.105: **1862 обычных теста PASS**.
- Отдельно **18 privileged tests PASS**: семь route identity, семь TUN/TAP ioctl,
  exact IPv4/IPv6 firewall, bind/source carrier, physical path observation и chown.
  Два ignored child-fixture вызываются родительскими тестами, а не отдельно.
- **8 E2E PASS**: TCP/UDP × `off/manual/route/nat66`. Настоящий `_worker`, INI
  `check-config`, malformed config/reload, запрет второго worker по control lease,
  один post_up/post_down, SIGTERM, исчезновение TUN/socket/правил, восстановление
  forwarding/accept_ra и удаление освобождённого sysctl journal. `manual` запускается
  с NDP `required`; проверяется отсутствие правил IPv6 Qeli и изменения forwarding.
  Передача реальных NDP-пакетов этим сценарием не подтверждается.
- Тот же E2E на бинарнике исходного `d85ead10` падает на первом TCP/off случае:
  `IPv4 forwarding lease leaked`; исправленный снимок проходит все восемь случаев.
- Исправлен старый native rename-fixture: `link down` может удалить маршрут до
  cleanup. Тест теперь повторно задаёт маршрут на переименованном интерфейсе и
  подтверждает его наличие до проверяемой операции.

Воспроизводимый runner: `scripts/audit_worker_lifecycle.py --qeli /path/to/qeli
--artifacts /new/absolute/directory`. Нужны root, unshare, iproute2, iptables/ip6tables,
/dev/net/tun и существующий mount point /etc/qeli. Runner создаёт отдельные network,
mount и PID namespaces, поднимает loopback, монтирует соответствующий sysfs и подменяет
/etc/qeli только внутри своего mount namespace. Для тестового процесса нужен лимит
fd не ниже 8192. Deadline всего E2E — 420 секунд; дочерний namespace привязан к runner.

Локальное evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`checks.json`, `linux-tests-v6.log`, `native-extra-v2.log`, `lifecycle-final/`,
`baseline-build.log`, source manifests и SHA256 бинарников. Первые неуспешные прогоны
сохранены: выключенный loopback, RLIMIT_NOFILE=1024, неверный фильтр child-fixture и
rename-fixture не объявляются успешными проверками продукта.

## Границы

Точные firewall-реестры остаются памятью worker. SIGKILL/crash, прежние worker,
неперечисляемые mixed nft цепочки без сохранённой спецификации и persistent recovery
остаются D04. Не добавлены атомарность при сторонних root-изменениях, общий deadline
всей cleanup, новый benchmark, native release certification или проверки устройств.
Сроки отдельных команд прежние. INI/API/ABI/wire-контракт не изменён.

Следующая фаза: [Q14-F034 — общий срок очистки](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
покрывает admission и команды profile/startup/final cleanup; прежние результаты выше
относятся к своему снимку. NAT setup/rollback, DNS lease Drop/setup admission и
persistent recovery остаются открытыми.

Продолжение: [Q14-F037](AUDIT-Q14-WORKER-NETWORK-LEASE.md) закрывает обход control lease через другой путь/namespace файловой системы. Новый kernel lease ограничивает server worker на уровне сети; SIGKILL/deleted-profile recovery проверено для доступных tagged rules. Persistent exact-rule journal и mixed nft остаются открыты.

Позднейшее продолжение: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) добавляет persistent exact server firewall journal и проверяет восстановление при отказе listing. Ограничения клиентского crash recovery и общей mixed nft/firewalld матрицы сохраняются.
