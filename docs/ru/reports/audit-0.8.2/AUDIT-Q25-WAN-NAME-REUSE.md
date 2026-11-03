# Q25-A125: повторное использование имени WAN

Дата: 25 сентября 2026. База: `37104b1e`. Исходный статус D06: **IN_PROGRESS**.
Приоритет: P2 (выход через невыбранный физический интерфейс; адрес клиента маскируется).

**Решение 3 октября 2026:** пользователь отменил production внедрение BPF.
Q25-A125 остаётся известным P2; D06 урегулирован как **ACCEPTED_LIMITATION**,
не как исправление. Предыдущие разделы ниже — история исследования.


Exit-node устанавливает MARK, MASQUERADE и FORWARD permit с селектором `-o <wan>`.
Запомненный WAN — имя, а не непрерывная идентичность сетевого устройства.
[Документация netfilter](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html)
определяет `-o` как сопоставление имени. Для сравнения,
[руководство nftables](https://netfilter.org/projects/nftables/manpage.html)
различает `meta oif` (индекс интерфейса) и `meta oifname` (имя); для последнего
прямо указано повторное срабатывание при создании нового интерфейса с прежним именем.

На изолированном сервере .11 проверены три состояния в частных network/mount/PID
namespaces. Исходный `wan0` имел ifindex 5 и выпускал пакет с NAT-адресом
`198.51.100.2`. После замены маршрута на `wan1` (ifindex 7) guard блокировал
пакет: его счётчик стал 1, до приёмника пакет не дошёл. Затем **новому**
интерфейсу с ifindex 7 присвоено имя `wan0` и восстановлен default route,
без вызова Qeli refresh. Старые правила MARK/MASQUERADE сработали повторно;
приёмник получил `192.0.2.2 > 203.0.113.9`. Адрес клиента `10.0.0.2`
наружу не вышел, но трафик прошёл через другое физическое устройство без
повторной авторизации WAN. Отдельная проверка живого rename `wan0 → wan-old`
показала, что ifindex и default route сохраняются под новым именем; старый
selector `-o wan0` после rename не подходит.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/wanrename3.log`
и `wanliverename.log`; воспроизводящий скрипт `wan-rename-reuse.sh` там же.
Все изменения сделаны внутри namespace; установленные сервисы лабы не затронуты.

**Контракт до исправления backend:** нельзя переименовывать, удалять или заменять
выбранный WAN, пока активен exit-node. Сначала остановите профиль и подтвердите
успешную очистку правил, затем меняйте интерфейс и запускайте профиль снова.
Смена маршрута на другое имя блокируется guard до успешного refresh, но
повторное использование старого имени после ухода прежнего устройства не
считается защищённым сценарием. Это уточнение внесено в руководство; Rust-код
в этом пункте не менялся.

Полное решение требует связывать egress-допуск с идентичностью устройства на
пути каждого пакета и отдельно проверять reuse идентификатора после удаления.
`nft meta oif` уменьшает риск простого rename/name-reuse, но индекс тоже может
повториться; перенос отдельного правила в nft без общей проверки mixed
iptables/nft/firewalld backend и cleanup нельзя считать готовым исправлением.
Проектирование и packet/recovery матрица остаются D06/D10.


## Продолжение 2 октября 2026: выбор kernel guard

На базе `5bbffe4b` выполнена квалификация кандидатов, **не исправление Qeli**:
[runner](../../../../scripts/audit_wan_identity_candidates.py) и
[evidence](../../../../release/certification/evidence/wan-identity-candidates-20261002.json).
Синтетические exit-shaped MARK/NAT/FORWARD правила проверены настоящими IPv4/IPv6
UDP пакетами на четырёх парах nft/nft, nft/legacy, legacy/nft, legacy/legacy.
Сам worker и VPN в этом пакете не запускаются; прежние рабочие бинарники только
сверены по SHA. Rust и параметры INI не менялись.

Всего **168 проверок ожидаемых результатов**, включая воспроизведение дефектных
вариантов: 88 probes, 264 datagrams, 168 валидных echo replies и 96 ожидаемых
блокировок. В 32 отрицательных проверках счётчик конкретного DROP увеличился на
3. Это не 168 доказательств исправленной безопасности.

| Кандидат / состояние | Пакетный результат на всех четырёх парах |
|---|---|
| Старое имя WAN | Новый интерфейс с прежним именем наследует MARK/NAT и выпускает трафик |
| Заранее установленный native nft `meta oif` | Принудительно созданное устройство с прежними ifindex, именем и MAC также допускается; native counter видит шесть пакетов в каждой ячейке |
| `devgroup --dst-group` с отдельным token | Token сохраняется на исходном устройстве после rename; после удаления новый интерфейс имеет group 0. Повтор имени/index/MAC и неправильная группа блокируются |
| Root копирует token на замену | Новое устройство снова допускается; token не является секретом или защитой от привилегированного администратора |
| Чужое правило `--dst-group 0 -j DROP` | Установка token вместо group 0 выключает это правило для WAN; возврат группы 0 возвращает блокировку |

`devgroup` читает группу выходного устройства в kernel matcher:
[исходник Linux](https://raw.githubusercontent.com/torvalds/linux/master/net/netfilter/xt_devgroup.c).
Но эта группа принадлежит общей сетевой политике хоста. Помимо доказанного firewall
конфликта, её использует `suppress_ifgroup` в
[IPv4](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/fib_rules.c) и
[IPv6](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv6/fib6_rules.c)
RPDB. Влияние RPDB здесь установлено по исходнику, а не отдельным packet runtime.
Поэтому автоматическая смена группы без контракта с администратором не принимается
как прозрачное исправление. Наличие текущей group 0 не доказывает, что она не
используется чужими правилами, масками, sets/maps или подавлением маршрутов.

Сверен клиентский monitor: `ExitWanSnapshot` в
[gateway.rs](../../../../qeli/src/client/gateway.rs) содержит только имена IPv4/IPv6
WAN. [spawn_exit_wan_monitor](../../../../qeli/src/client/mod.rs) сравнивает снимок
раз в пять секунд и после успешного refresh пропускает равный снимок. Повтор имени
сам по себе не меняет снимок. Наблюдение пути carrier в
[roaming_linux.rs](../../../../qeli/src/client/roaming_linux.rs) может учитывать index,
но это другой путь и не даёт непрерывного egress guard. Прежние TCP/UDP доказательства
[Q25-F127](AUDIT-Q25-EXIT-WAN-MONITOR.md) остаются применимыми к смене default WAN
на другое имя; новых monitor E2E здесь нет. Даже добавление index в sampler оставит
окно до следующего наблюдения и возможность index reuse.

Для реализации остаётся один связный пакет: kernel guard и явный контракт владения
его per-device меткой, общий lease для IPv4/IPv6 и нескольких профилей/процессов,
namespace/device witness и уникальный generation token, journal/rollback/cleanup/
crash recovery без восстановления метки на заменённом устройстве. Затем — настоящие
client/server пакеты, established conntrack/mark, mixed backend и recovery. Группа
не должна молча менять чужую политику; токен нельзя восстанавливать только по имени,
ifindex или MAC. Эти требования не объявлены реализованными.

Промежуточные 164 результата r2 сохранены отдельно и не прибавляются к финальным
168: r3 устанавливает ifindex guard ещё на исходном WAN и подтверждает, что правило
не изменилось после удаления/создания устройства.

Первый fixture отказ сохранён: down/up удалил вручную заданный IPv6 и новый default
не установился. В частном namespace добавлен `keep_addr_on_down=1`; production
код не менялся. Во всех попытках внешний host snapshot совпал; финальная сверка
включает link groups, RPDB и отсутствие новых/удалённых kernel modules. Действующие
сервисы и `.10` не затронуты. Успешная матрица не проверяет persistent group lease,
SIGKILL/recovery или настоящий firewalld daemon.

**Q25-A125 / D06 остаётся открытым P2.** D10 закрыт прежней поддерживаемой
firewall-композицией; будущий identity guard потребует её целевых повторных проверок.
Ограничение active WAN rename/delete/recreate в мануале сохраняется.


## Продолжение 3 октября 2026: работающий прототип DEVMAP

Найден kernel guard без изменения device group и без перенаправления пакетов через
TC: [низкоуровневый helper](../../../../scripts/audit_wan_devmap.py),
[packet runner](../../../../scripts/audit_wan_devmap_packets.py),
[evidence](../../../../release/certification/evidence/wan-devmap-20261003.json).
**Это прототип, ещё не production исправление Qeli.** Рабочий Rust, клиентский
monitor, unit-файл и установленные сервисы не изменены.

В `BPF_MAP_TYPE_DEVMAP` помещается исходный WAN, затем `BPF_MAP_FREEZE` запрещает
userspace обновления. Kernel notifier удаляет запись при `NETDEV_UNREGISTER`;
позднее совпадение числового ifindex не создаёт её заново. Это свойство
[реализации Linux 6.12](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/bpf/devmap.c).
Разрешение lookup для DEVMAP есть в
[verifier](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/bpf/verifier.c),
а socket-filter программа исполняется через
[xt_bpf](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/netfilter/xt_bpf.c).

Программа из 16 инструкций ставится в `mangle/POSTROUTING` перед NAT. Она игнорирует
чужой ingress, а для выбранного TUN сравнивает **фактический выходной ifindex пакета**
с живой записью map. Отсутствие записи или другой индекс дают DROP. Дополнительно
правило ограничено выбранным WAN name. Сама по себе непустая map недостаточна:
старый WAN может ещё жить под новым именем, пока другое устройство уже заняло
прежнее имя. Это проверено отдельным отрицательным сценарием.

На **4/4 парах nft/nft, nft/legacy, legacy/nft, legacy/legacy** выполнено по 39,
всего **156 проверок**; 72 packet probes / 216 UDP datagrams / 168 валидных echo
replies / 48 ожидаемых блокировок. Все 16 отрицательных probes увеличили именно
новый mangle DROP на 3; прямые запросы подтверждают живых приёмников.

| Состояние | Проверенный результат IPv4/IPv6 |
|---|---|
| Исходный WAN | Трафик consumer проходит с прежним MASQUERADE source; локальный OUTPUT не затронут |
| Owner FD закрыт и pinned объекты снова открыты | Живая запись и нормальный NAT сохраняются |
| Исходный WAN переименован, другое устройство заняло старое имя | Map ещё жива, но фактический out index другой: DROP |
| Исходный WAN удалён, новое устройство получило прежние name/index/MAC | Map пустая и после reopen; consumer DROP, локальные положительные контроли работают |
| Попытка обновить live или retired map | EPERM; прежняя generation не переавторизует замену |
| Старые guard rules удалены, создана новая generation | Новый выбранный WAN снова допускается с NAT |
| Cleanup | Исходный снимок обоих backend/native nft восстановлен; rules удалены перед unpin/close/unmount |

Дополнительно выполнены **две capability проверки** с настоящим пользователем
`qeli` (UID 103/GID 105) через setpriv. С тремя штатными capabilities юнита
`CapEff=0x3400` MAP_CREATE отказывает EPERM. Добавление только `CAP_BPF` даёт
`CapEff=0x8000003400`: map/program создаются, замораживаются и pin работают без
CAP_SYS_ADMIN у процесса. При этом bpffs и доступный каталог заранее создал
привилегированный fixture. Это не проверка systemd startup/install: её нужно
выполнить при интеграции. Рабочий сервис не получил дополнительных прав.

Не принимается более простой TC обход: привязка mirred к устройству видна в
[исходнике](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/sched/act_mirred.c),
но redirect меняет путь пакета, а фильтр только на WAN не создаёт firewall deny
для заменившего его устройства. TC пакетный сценарий здесь **не выполнялся**:
после source-разбора выбран DEVMAP, сохраняющий обычный routing/NAT путь.

Сохранены fixture отказы: запись обычного verifier.log внутри bpffs, запрос DROP
counter без `-t mangle`, затем неподготовленный пустой native mangle POSTROUTING
hook в baseline. Финальный fixture prime-ит hook до снимка; никакие kernel/чужие
объекты ради совпадения результата после проверки не удаляются. Промежуточные
156 результатов r3 не прибавляются к финальным r4; r4 удаляет неиспользуемую старую
ветку devgroup из runner. AST, hashes runtime fixtures и документация проверены.

Все внешние firewall/routes/addresses/link groups/RPDB/listener/resolver snapshots
совпали до/после. Есть явно сохранённый глобальный эффект: первый вызов xt_bpf
автозагрузил одноимённый kernel module; он оставлен загруженным. В финальном r4
новых модулей нет. Набор модулей за все попытки не называется неизменным. `.10` не
затронут. Полная инвентаризация BPF объектов до/после не выполнялась.

Для закрытия D06 остаётся **интеграция выбранного guard**, а не новый поиск кандидатов:
общий Linux Rust helper с переносимым syscall ABI; trusted bpffs/bootstrap и
минимальные service права; persistent owner/journal для server NAT44/NAT66 и
client exit; установка до допуска пакетов и сохранение pin до подтверждённой
очистки rules; monitor должен различать потерю lease и создавать новую generation,
не заполняя старую map. Далее — настоящий Qeli TUN, multiprofile, established
conntrack, policy/RFC1918/delegated paths, SIGKILL/recovery и отказ без capabilities/
bpffs на mixed backend. Обычные unit/build/Clippy нужны после изменения Rust.

Helper прототипа намеренно только Linux x86_64. Close/reopen FD не равен SIGKILL,
а synthetic veth packet proof не равен authenticated VPN E2E. Политики чужого TC/
mangle/firewalld и старые kernels этим пакетом не сертифицированы. Текущий
контракт запрета active WAN rename/delete/recreate сохраняется до интеграции.
**Q25-A125 / D06 IN_PROGRESS; D15 ожидает конечный production кандидат.**

## Решение 3 октября 2026: production guard отменён

По решению пользователя внедрение BPF и расширение service capabilities не
продолжаются. Незавершённый Rust черновик удалён из рабочей ветки и сборочного
дерева .11; работающий бинарник и unit не менялись. Старые prototype проверки
сохраняются как исследование, а не evidence исправления рабочей системы.

Известное ограничение остаётся: выбранный WAN нельзя переименовывать, удалять
или заменять при активном managed NAT44/NAT66 или client exit-node. Сначала
остановить профиль и подтвердить cleanup; затем изменить интерфейс и снова
запустить профиль. Проверка наличия WAN при старте и monitor по имени не
обеспечивают непрерывную identity и не защищают от повторного имени.

[D06: решение пользователя](../../plans/AUDIT-DEBT.md) ·
[запись отката](../../../../release/certification/evidence/wan-identity-disposition-20261003.json).
Остаток не объявляется исправленным. Последующая работа — D15, затем полный аудит.
