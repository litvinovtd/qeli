# Q14: mixed nft/legacy/firewalld после SIGKILL

24 сентября 2026. Проверенный код `ab5ccc7d`; Rust не изменён.
**16/16 сценариев, 476 проверок PASS.** Это серверная часть D04/D09/D10.
Новый дефект ядра не обнаружен; уточнены реальные границы автоматического recovery.
D04 остаётся IN_PROGRESS: смешанный firewall ещё требует клиентской packet/recovery матрицы.

## Матрица

| IPv4 backend | IPv6 backend | Сценарии | Проверки |
|---|---|---:|---:|
| nft | nft | 4/4 PASS | 124 |
| nft | legacy | 4/4 PASS | 124 |
| legacy | nft | 4/4 PASS | 124 |
| legacy | legacy | 4/4 PASS | 104 |

В каждой строке отдельно меняется backend IPv4 или IPv6 после SIGKILL; каждый
вариант выполняется без firewalld и с настоящим firewalld 2.3.1 (nftables backend).
Одновременно существуют операторские правила обоих семейств в обоих backend,
отдельная нативная inet-таблица и, при включении, таблица firewalld. Worker создаёт
18 точных NAT/NAT66, FORWARD, MSS, DNS INPUT/REDIRECT правил для двух семейств.

`audit_mixed_firewall.py` создаёт private net/mount/PID окружение и отдельные state,
config, log и control пути. Backend переключается исполнением настоящего nft/legacy
multi-call бинарника через private mount wrapper. Ответы `-C/-D/--version` не подделываются.
Снимки каждого backend выполняются через сохранённые оригинальные executable.
Изолированный firewalld использует отдельную D-Bus-шину, DefaultZone=trusted и
собственный config; reload должен сохранить правила Qeli и конфигурацию оператора.

## Что подтверждено

- Все 18 спецификаций журнала проверяются настоящим `-C` перед SIGKILL. Профиль затем
  удаляется из конфига: recovery не может восстановить список правил из нового INI.
- При смене одного backend startup отказывает до profile hook. Затронутые правила
  остаются в исходном backend. Независимые удаления второго семейства продолжаются;
  журнал освобождает только записи с подтверждённым отсутствием.
- Нативное `meta mark set numgen inc mod 2` делает FORWARD несовместимым с `-S`.
  Присутствующий exact `-C` и `-D` работают, но **после удаления отсутствующий `-C`
  возвращает exit 3: `Parsing nftables rule failed`**. Это не подтверждение отсутствия.
  Qeli оставляет две FORWARD-записи каждого затронутого nft-семейства и отказывает.
- Возврат исходного backend сам по себе не исправляет несовместимую цепочку.
  Тестовый администратор удаляет по точному handle только свои opaque-выражения
  в затронутых цепочках; все другие правила сохраняются. Следующая проверка Qeli
  подтверждает отсутствие и очищает firewall-журнал. Общего flush нет.
- Для NAT66 отдельно срабатывает известная граница D02: потерян live witness WAN
  `accept_ra`. Firewall уже восстановлен, но startup сохраняет sysctl-запись и отказывает.
  В fixture администратор удерживал исходный sysctl fd до crash: через него возвращает
  original, затем снимает только подтверждённую запись. Это явное ручное действие,
  а не новая возможность Qeli угадывать identity по имени/ifindex.
- После этих действий новый worker запускается и штатно останавливается, journal пуст,
  IPv4/IPv6 forwarding возвращены, оставшиеся операторские правила сохранены.

Таким образом, старый wrapper-тест, отключавший только `-S`, не описывал всю нативную
совместимость: `-C` также может стать непригодным. Ослаблять `firewall_check` и считать
parse error отсутствием нельзя. [Процедура §6.83](../../manuals/TROUBLESHOOTING.md#683-linux-mixed-nftlegacyfirewalld-recovery).

## Evidence и воспроизведение

Стенд `.11`: Debian, Linux `6.12.105+deb13-amd64`, x86_64, iptables 1.8.11,
nftables 1.1.3. Firewalld 2.3.1 и зависимости извлечены из Debian packages в приватный
каталог; системная служба не устанавливалась и не запускалась. Рабочий сервер `.10`
не заменялся. Матрица выполняла по два изолированных сценария одновременно.

Worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
Harness SHA256: `a2e482edb7cebd845c11bfe3b02167f6518257b43842d0006374419dd15f41f1`.
Все 340 Rust/conformance файлов совпадают с ранее проверенным worker; remote source
сверён до/после. Полные Rust-наборы и benchmark заново не запускались: код ядра не менялся.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/mixed-firewall-phase/`,
`mixed-firewall-matrix-v3/`, `mixed-firewall-matrix-v3.log/.rc/.tar.gz`.
Сохранены все команды, правила/журналы до и после, диагностические логи и hashes пакетов.
`mixed-firewall-phase/matrix-v3.sh` содержит точный запуск; новый runner принимает
`--qeli`, `--artifacts`, `--ipv4 nft|legacy`, `--ipv6 nft|legacy`, `--drift 4|6`
и необязательный `--firewalld` с путём извлечённых пакетов.

Ранние smoke и matrix v1/v2 сохранены, но не считаются PASS: исправлены сборщик nft
snapshot (JSON не раскрывает payload xt-comment), предположения о подтверждении
отсутствия/восстановлении sysctl и пути control socket (SUN_LEN, private directory).
Окончательное подтверждение — только matrix v3. Ошибки подготовки не объявляются багами Qeli.

## Остаток

Это проверка серверных правил и recovery, а не клиентского packet path. Она не
сертифицирует произвольные firewalld zones/policies, reload с любыми настройками,
конкурентную подмену правил другим root или автоматическую миграцию backend.
Native opaque-правила администратора нельзя автоматически удалять ради запуска Qeli.
Клиентский kill-switch/DNS/route packet recovery в mixed окружении остаётся D04/D10;
полная off/manual/route/nat66 × NDP и multiprofile матрица также остаётся D10.
Общий реестр: **3/15 DONE, 10 IN_PROGRESS, 2 TODO — 20% закрытых групп**.

[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md).

Итоговое продолжение D04: [клиентская mixed packet/recovery матрица и Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) завершены, D04 DONE в текущем реестре. Исторические IN_PROGRESS выше относятся к прежнему снимку. D10 (расширенные политики/топологии) и D13 (рост состояния) остаются открытыми.

Продолжение 2 октября 2026: D13 закрыт [worker churn/lifecycle](AUDIT-Q25-WORKER-RESOURCE-CHURN.md); D10 закрыт в поддерживаемом Linux-объёме Q25-F211/F212/F213 в [текущем реестре](../../plans/AUDIT-DEBT.md). Новый пакет проверил четыре mixed backend с четырьмя IPv6-профилями, public zone/policy firewalld и reload/restart: 416 checks + 19 адресных тестов PASS. [Evidence](../../../../release/certification/evidence/firewalld-profiles-20261002.json). Исторические открытые статусы выше сохранены; произвольные root rewrites/автоматическая миграция backend и все зоны/политики не сертифицированы.
