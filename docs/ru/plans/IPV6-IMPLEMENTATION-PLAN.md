# Полная поддержка IPv6 — план реализации

Статус: реализация в исходном коде завершена, релизная сертификация продолжается.
Актуализировано: 2026-08-31.

Runtime-gate и аутентифицированное согласование возможностей включены в ветке разработки.
Native cores ABI 1.14 уже прошли независимую A/B сборку и provenance-проверку. Базовая
автоматическая Linux-матрица прошла 14/14 сценариев для outer IPv4/IPv6, inner
IPv4/IPv6/dual, TCP/UDP/QUIC и full/split routing, включая cross-family leak и cleanup.
Это ещё не утверждение о готовности релиза: на точных финальных артефактах остаются специальные
DNS/PMTU/PTB/TAP/legacy-сценарии и физическая матрица из раздела 14.

Этот документ описывает **полную**, а не частичную поддержку IPv6 в Qeli. Этапы ниже
можно выполнять последовательно внутри разработки, но ни один промежуточный этап нельзя
объявлять поддержкой IPv6 в релизе. Пользовательская возможность считается готовой только
после прохождения всей матрицы серверов, клиентов, транспортов, режимов маршрутизации,
установки и обновления.

Пользовательские и устанавливаемые конфиги Qeli остаются только в формате flat INI
(`.conf`). JSON не является и не должен становиться форматом конфигурации. Внутренняя
структурированная сериализация wire/FFI/API может использовать собственное представление,
но это не пользовательский конфиг и не должна так называться в документации.

## 1. Что означает «полная поддержка»

Релиз должен одновременно поддерживать:

- внутренний IPv4, dual-stack и внутренний IPv6-only;
- внешний адрес сервера IPv4 и IPv6, независимо от семейства адресов внутри туннеля;
- TCP, UDP и QUIC, все варианты обфускации и все встроенные режимы Quick Start;
- full-tunnel и split-tunnel, маршруты включения и исключения, DNS, ACL, изоляцию
  клиентов, site-to-site/`client_subnet`, kill switch и защиту от утечек обоих семейств;
- Linux CLI, OpenWrt, Keenetic/OpkgTun, Android, iOS, Windows и macOS;
- системный режим и per-app режимы Windows/macOS;
- TUN и заявленный продуктом TAP, включая IPv6 EtherType и NDP/RA;
- установщик, `.deb`, Docker, панель, Quick Start, мультипрофильный конфиг и все
  поставляемые примеры;
- совместимость старых и новых клиентов/серверов без молчаливого частичного режима;
- корректный MTU, ICMPv6 Packet Too Big и фрагментацию транспортных UDP-записей.

Полная поддержка не означает, что IPv6-only обязан открывать IPv4-only сайты. Для этого
нужны NAT64/DNS64 или прокси-перевод семейства; это отдельная возможность. Рекомендуемый
универсальный режим — `dual`. NAT64/DNS64 не входит в первую реализацию native IPv6 и не
должен имитироваться через скрытую утечку IPv4.

## 2. Семантика режимов и утечек

Сервер хранит конкретный режим профиля:

| `tun.ip_mode` | Адреса внутри туннеля | Full-tunnel | Split-tunnel |
|---|---|---|---|
| `ipv4` | только IPv4 | IPv4 через Qeli; IPv6 блокируется, если явно не разрешена утечка | только выбранные IPv4-маршруты; обычный IPv6 может идти напрямую, явный IPv6 include отклоняется |
| `dual` | IPv4 и IPv6 атомарно | оба семейства через Qeli | выбранные маршруты обоих семейств через Qeli |
| `ipv6` | только IPv6 | IPv6 через Qeli; IPv4 блокируется, если явно не разрешена утечка | только выбранные IPv6-маршруты; обычный IPv4 может идти напрямую |

Следовательно, при `tun.ip_mode = ipv4` IPv6-трафик **не идёт внутри туннеля**. Это
намеренная и проверяемая семантика. В full-tunnel его безопасное поведение по умолчанию —
блокировка, а не обход VPN.

Клиентская настройка `ipv6` — политика принятия возможностей сервера, а не режим сервера:

- `auto` — использовать IPv6, если сервер и платформа согласовали полную возможность;
- `required` — отказаться от соединения, если полноценный внутренний IPv6 недоступен;
- `off` — не запрашивать внутренний IPv6.

Для симметричной защиты нужны `allow_ipv6_leak = false` и новая
`allow_ipv4_leak = false`. В full-tunnel разрешение утечки всегда должно быть явным. В
split-tunnel трафик вне выбранных маршрутов остаётся прямым, а исключения имеют приоритет
над включениями.

## 3. Flat-INI схема

Отсутствие новых ключей сохраняет текущую IPv4-семантику. Предлагаемая серверная схема:

```ini
[profile:reality-tls]
tun.ip_mode = dual
tun.address = 10.9.0.1
pool.cidr = 10.9.0.0/24
pool.exclude =
pool.reservation.alice = 10.9.0.50

tun.ipv6_address = fd71:e1:1234:1::1
pool.ipv6.cidr = fd71:e1:1234:1::/64
pool.ipv6.exclude =
pool.ipv6.reservation.alice = fd71:e1:1234:1::50

routing.ipv6.mode = nat66
routing.ipv6.interface =
dns.listen_ipv6 = fd71:e1:1234:1::1
dns.push_servers = 10.9.0.1, fd71:e1:1234:1::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

Допустимые значения:

- `tun.ip_mode = ipv4|dual|ipv6`, значение по умолчанию — `ipv4`;
- `routing.ipv6.mode = off|route|nat66`;
- `ipv6 = auto|required|off` в клиентской секции `[qeli]`.

Панель и установщик могут предлагать выбор `auto`, однако должны определить среду один раз
и сохранить в профиль конкретный `tun.ip_mode`. Повторный запуск не должен менять семейство
из-за временного сбоя uplink.

В пользовательском файле требуются IPv6-аналоги:

```ini
[user:alice]
static_ip = 10.9.0.50
static_ipv6 = fd71:e1:1234:1::50
allowed_networks = 10.0.0.0/8, 2001:db8:100::/48
client_subnet = 192.168.50.0/24, 2001:db8:200::/56
route = 2001:db8:300::/48 gateway=fd71:e1:1234:1::50 metric=100
```

Парсер, сериализатор и валидатор должны:

- использовать `IpAddr`/`IpNet` там, где разрешены оба семейства;
- запрещать адреса другого семейства в gateway, reservation и pool;
- обнаруживать пересечения пулов, адрес сервера, исключения и резервации;
- отклонять бессмысленные unspecified, multicast, loopback и IPv4-mapped IPv6;
- трактовать DHCP-настройки как DHCPv4, а в IPv6-only давать явную ошибку/предупреждение;
- сохранять все прочитанные ключи и отклонять неизвестные/неиспользованные ключи в строгой
  проверке;
- проходить parse → serialize → parse без изменения смысла.

## 4. Согласование возможностей и совместимость

Нельзя определять IPv6 только по версии приложения: возможность зависит и от Rust-ядра, и
от платформенного адаптера. До выдачи адреса обе стороны согласуют минимум:

- `INNER_IPV6` — IPv6-пакеты в data plane;
- `NETWORK_PLAN_V2` — двухсемейный план сети;
- `UDP_DATA_FRAG_V1` — фрагментация транспортной UDP-записи;
- семейно-специфичные возможности платформы: IPv6 TUN, маршруты, DNS, kill switch и
  per-app routing.

Согласование добавляется обратно совместимым образом. Сервер может дописать после текущего
proof компактный аутентифицированный capability trailer с magic, версией, длиной и битами.
Размер trailer для proof-only должен оставлять всё сообщение короче 64 байт, чтобы старый
клиент не принял его за full proof. Новый клиент посылает расширенный auth request только
после объявления такой возможности сервером; иначе сохраняет текущий layout побайтно.

Обязательная матрица:

| Сервер | Клиент | Результат |
|---|---|---|
| новый | старый | IPv4 в `ipv4`/`dual`; понятный отказ в IPv6-only |
| старый | новый | legacy IPv4; `ipv6=required` даёт понятный отказ |
| новый | новый, способная платформа | согласованный `ipv4`, `dual` или `ipv6` |
| новый | новый, неполный адаптер | IPv4 либо отказ; нельзя выдавать ложный IPv6 plan |

В `dual` новый IPv6-capable клиент получает оба адреса атомарно либо соединение завершается.
Старый клиент может получить только legacy IPv4. В IPv6-only выделение адреса до проверки
возможностей запрещено. Клиент с `ipv6=off` использует IPv4-часть dual-профиля, но получает
явный отказ от IPv6-only профиля.

## 5. AuthOK, NetworkPlan и ABI

Текущие одиночные IPv4-поля в
[transport_core/session.rs](../../../qeli/src/transport_core/session.rs) и
[transport_core/mod.rs](../../../qeli/src/transport_core/mod.rs) заменяются типизированной
моделью, например:

- `family_mode`;
- `addresses[]`: family, address, prefix length, gateway;
- `routes[]`: family, destination, optional gateway, metric/exclude;
- `dns_servers[]`;
- `inner_mtu`;
- все активные внешние carrier endpoints/families, включая multipath;
- монотонный `generation` плана.

На один переходный ABI-цикл сохраняется legacy IPv4-проекция. Добавление полей и capability
битов требует поднять minor ABI с 1.10 до 1.11; major менять не требуется, пока старые поля
имеют прежнюю семантику. Старому адаптеру новый сервер выдаёт только IPv4-план.

`persist_tun` должен сравнивать канонический fingerprint **всего семантического**
NetworkPlan: режим, адреса обоих семейств, нормализованные маршруты, порядок DNS, MTU и
полный набор carrier/bypass endpoints. Монотонный delivery `generation` нужен для
отбрасывания устаревших событий,
но не входит в fingerprint, иначе одинаковый план нельзя будет переиспользовать после
переподключения. Повторное использование TUN разрешено только при полном совпадении
семантических полей. Иначе сеть перестраивается атомарно. Физическая сигнатура должна
учитывать IPv4/IPv6 адреса, gateways и resolvers; одного client IPv4 недостаточно
([VpnTunnelBase.cs](../../../qeli-shared/QeliShared/Vpn/VpnTunnelBase.cs)).

## 6. Общий IP data plane

Нужен единый безопасный разборщик IPv4/IPv6 с нормализованными метаданными вместо отдельных
проверок по первому nibble. Он обязан:

- проверять IPv4 total length и IPv6 payload length; jumbogram явно не поддерживать;
- ограниченно разбирать Hop-by-Hop, Routing, Destination Options, Fragment и AH;
- ограничивать число и суммарный размер extension headers;
- находить L4 ports только там, где они действительно присутствуют;
- сохранять source/destination/protocol/fragment id для source guard, ACL и flow hash;
- одинаково обрабатывать первый и последующие фрагменты;
- направлять все части одного IPv6 datagram в один flow/worker;
- использовать ограниченный fragment-policy cache по source/destination/id/next-header:
  решение L4 ACL первого фрагмента применяется к остальным; non-first-before-first
  отбрасывается либо кратко буферизуется в жёстком лимите;
- безопасно отбрасывать malformed, overlapping и неоднозначные цепочки.

Нужно обобщить `SessionMap`, source guard, ACL, isolation, route lookup и flow hash, которые
сейчас привязаны к `Ipv4Addr`, `u32` и `/32` в
[server/mod.rs](../../../qeli/src/server/mod.rs),
[server/acl.rs](../../../qeli/src/server/acl.rs) и
[protocol/mod.rs](../../../qeli/src/protocol/mod.rs).

Traffic normalization не должна дописывать случайные байты к готовому IP datagram. Целевой
размер достигается существующим AEAD padding, чтобы объявленная IP-длина всегда совпадала с
пакетом ([protocol/obfuscate.rs](../../../qeli/src/protocol/obfuscate.rs)).

## 7. MTU, PMTU, фрейминг и инкапсуляция

Это блокирующая зависимость до включения inner IPv6:

- `inner_mtu` — MTU интерфейса/внутреннего IP, не менее 1280 при активном IPv6;
- `outer_udp_datagram_budget` — локальный предел одной Qeli UDP-датаграммы на конкретном
  внешнем пути; при multipath budget хранится отдельно для каждого активного пути;
- эти значения нельзя смешивать или выводить одно из другого вычитанием overhead;
- budget асимметричен: клиент измеряет uplink, сервер отдельно измеряет downlink;
- оба отправителя начинают с консервативного **семейно-зависимого** budget и повторяют
  пробу после смены carrier/сети/роуминга: для outer IPv6 он не больше 1232 байт при
  минимальном MTU 1280, а для поддерживаемого outer IPv4 minimum path должен быть задан
  отдельно (например, UDP payload 548 байт для 576-байтного пути), а не заимствован у IPv6;
- TCP использует stream framing, но всё равно применяет корректный `inner_mtu`.

Существующий handshake fragmentation в
[protocol/udp_frag.rs](../../../qeli/src/protocol/udp_frag.rs) не подходит для data plane. Для
UDP/QUIC нужен `DATA_FRAG_V1`:

1. Полный внутренний IP-пакет шифруется как одна обычная AEAD record.
2. Готовая ciphertext record делится ниже AEAD на envelopes с record id, offset/index,
   count, total length и payload.
3. Каждый fragment имеет отдельный keyed MAC из отдельного session KDF key; MAC проверяется
   до выделения большого буфера.
4. Каждый QUIC-wrapped fragment получает уникальный packet number.
5. Reassembly ограничивается по числу records, байтам, размеру record и времени; дубликаты,
   конфликты и переполнения завершаются безопасно.
6. После точной сборки применяется обычный PacketCodec decrypt/replay check.

Новая форма включается только после согласования capabilities. Старому peer новые data
fragments не отправляются.

IPv6 router не фрагментирует transit-пакет. Если внутренний пакет нельзя передать, сервер
или клиент формирует корректный ICMPv6 Packet Too Big с правильным source и checksum. Для
IPv4 сохраняется существующая IPv4 fragmentation/ICMP-логика. Тесты обязаны включать
потерю, reorder, duplicate, conflicting fragments, timeouts, memory DoS, разные MTU по
направлениям и отсутствие внешней IP-фрагментации.

## 8. Пулы, сессии и атомарность

Модель пула становится двухсемейной: optional IPv4 pool и optional IPv6 pool под одной
транзакционной блокировкой. IPv6 `/64` нельзя перечислять в памяти: allocator хранит только
занятые/зарезервированные адреса и использует ограниченный `u128` counter либо keyed hash с
collision probing.

Нужно резервировать subnet-router anycast (нулевой host), gateway сервера, exclusions и
reservations. В IPv6 нет broadcast. Модель плана различает assigned prefix и pool/on-link
prefix. На L3 TUN клиент получает host-route `/128`, а нужные сети направляются напрямую в
point-to-point интерфейс без NDP-зависимого «on-link gateway». На TAP назначенный адрес
находится в L2 `/64`, и gateway достигается через NDP. Нельзя одним `prefix_len` случайно
навязать TUN поведение TAP или наоборот.

Сессии индексируются по session id, optional IPv4 и optional IPv6; token указывает на
session id. `max_clients` считает сессии, а не сумму адресов. Allocate, insert, rollback,
reaper, eviction и release должны атомарно затрагивать оба семейства.

Маршруты и ACL используют longest-prefix match для `IpNet`. Нельзя устанавливать
`client_subnet = ::/0` как host default route через клиента: exit-node маршрут должен жить
во внутренней таблице/явном механизме, иначе сервер перехватит собственный uplink.

## 9. Серверный IPv6 forwarding, DNS и egress

`routing.ipv6.mode` имеет строгую семантику:

- `off` — IPv6 только внутри профиля/LAN, без Internet egress;
- `route` — двунаправленно маршрутизируемый GUA/prefix без NAT;
- `nat66` — ULA/GUA через явный IPv6 uplink и stateful NAT66.

Во всех трёх режимах нужен `ip6tables`. `off` — не отсутствие политики: qeli ставит и
проверяет помеченные профилем DROP для не-TUN транзита в обоих направлениях, чтобы профиль
не унаследовал forwarding от другого активного профиля или глобальной настройки хоста. `route`
двунаправленно следует connected и аутентифицированным динамическим kernel routes профиля,
включая LAN сервера и IPv6 `client_subnet`; `nat66` — только WAN-ответы related/established.

Linux-настройка включает IPv6 forwarding, семейно-корректные FORWARD/NAT правила, MSS
clamp и разрешает обязательный ICMPv6, включая Packet Too Big. Если внешний интерфейс
получает маршрут через RA/SLAAC, включение forwarding не должно отключить принятие RA:
нужно адресно применить `accept_ra=2` к такому uplink и затем восстановить предыдущее
значение. Исходные значения атомарно журналируются до записи в `/proc` и восстанавливаются
после аварийного завершения worker в пределах того же boot-id; journal от предыдущей загрузки
отбрасывается и не перезаписывает заново загруженную политику хоста. Реализация может
использовать nftables или ip6tables, но sysctl/firewall cleanup,
rollback и мультипрофильность должны быть симметричны IPv4.

Если у хоста нет IPv6 default route/рабочего uplink, панель и установщик не должны обещать
Internet IPv6. Разрешены изолированный/LAN `off`, корректно настроенный routed prefix или
явный отказ. ULA сама по себе не создаёт Internet-доступ.

DNS proxy должен слушать UDP и TCP на достижимых адресах обоих семейств, выбирать family-
подходящий local bind для upstream и корректно работать с bracketed `SocketAddr`. Нельзя
push-ить клиенту IPv6 DNS, который недоступен в выбранном режиме. Для IPv6-only full-tunnel
нужен достижимый через туннель IPv6 resolver; ответы A не переводятся в IPv6 без DNS64.

## 10. Внешний IPv6 carrier

Внешнее семейство независимо от внутреннего: должны работать outer4/inner6 и
outer6/inner4. Resolver и transport sockets переходят с `Ipv4Addr` на `IpAddr`/`SocketAddr`,
получают A и AAAA и создают socket под семейство каждого кандидата.

TCP использует family-aware последовательный failover с единым ограниченным deadline,
справедливо разделённым между оставшимися кандидатами: один мёртвый A/AAAA не расходует
полный системный SYN timeout. Для UDP успешный `connect()` не доказывает достижимость:
неудачный аутентифицированный first flight сдвигает ротацию кандидатов следующего bounded
reconnect-поколения, поэтому стабильный порядок DNS не удерживает клиент на одном black-hole
адресе. `local_address` обязан совпадать по семейству; первичный carrier использует
фиксированный `local_port`, а bonded TCP-потоки сохраняют локальный адрес с ephemeral-портами.
На Android каждый candidate socket защищается от VPN loop до
connect.

Выбранный буквальный carrier аутентифицирован в NetworkPlan; поколение также хранит полный
resolved-набор A/AAAA, переданный transport core. Каждый пригодный кандидат точечно
исключается из full-tunnel routes/kill switch до установки capture-маршрутов. Bonded streams
остаются внутри закреплённого набора поколения, а `persist_tun` включает order-independent
набор в fingerprint: изменение DNS-набора вызывает атомарную пересборку NetworkPlan.
Широкое исключение порта или всего IPv6 запрещено. Link-local endpoint без scope id следует
явно отклонять, пока scope id не станет частью конфигурационной модели.

Сервер поднимает предсказуемые отдельные IPv4 и IPv6 listeners. IPv6 listener использует
V6ONLY, чтобы IPv4-mapped addresses не конфликтовали с IPv4 socket. IPv6 host в ссылках и
адресах всегда форматируется в квадратных скобках.

## 11. Платформенные адаптеры

Общие требования для каждого адаптера: реальные IPv6 address/routes/DNS, внешний bypass,
kill switch обоих семейств, атомарный apply/rollback и полный NetworkPlan fingerprint.

- **Linux CLI:** generic address/route setup, IPv6 DNS и firewall. Attach-existing формат
  должен передавать оба адреса, а не один IPv4; формат следует версионировать или сделать
  построчным по семействам. Router/exit sysctl требуют межпроцессный журнал владельцев:
  регистрировать даже уже правильное значение, идентифицировать владельца по PID start-time и
  TUN/профилю, восстанавливать только после последнего живого владельца и отбрасывать stale-
  состояние после перезагрузки ядра.
- **OpenWrt:** UCI/LuCI рендерят новые INI-ключи; fw4 правила используют корректную family,
  routed IPv6 или `masq6`; rollback не оставляет IPv6 route/firewall state.
- **Keenetic/OpkgTun:** hooks и `ndmc` перестают считать адрес/маршрут IPv4-регулярным
  выражением и применяют обе семьи.
- **Android:** вместо dummy `fd00:71e1::1/128` и `::/0` для блокировки добавляются реальные
  address/routes/DNS из плана. Dummy удаляется при активном IPv6. `allowFamily()` остаётся
  только явной leak policy.
- **iOS:** реальные `NEIPv6Settings`, маршруты и DNS; uplink/downlink packet protocol
  выбирается по версии IP; resolver использует AF_UNSPEC.
- **macOS utun:** четырёхбайтный family header — AF_INET для IPv4 и AF_INET6 для IPv6.
- **Windows global:** Wintun получает IPv6 address/routes/DNS и v4/v6 kill switch.
- **Windows per-app:** WinDivert выбранный IPv6 не bypass/drop, а туннелирует; выполняются
  source rewrite к tunnel IPv6, обратный rewrite, TCP/UDP/ICMPv6 checksum и pseudo-header,
  безопасная обработка fragments.
- **macOS per-app:** transparent proxy направляет выбранный IPv6 в tunnel, использует
  family-корректные source/destination/interface binds и A+AAAA tunnel-DNS relay с перебором
  доступных family-кандидатов; обычный split-трафик обходит туннель, а явные routes без своего
  согласованного семейства блокируются. Здесь не нужно копировать raw-NAT модель Windows.

## 12. TUN, TAP, NDP и RA

L3 TUN получает адрес из AuthOK/NetworkPlan и не нуждается в DHCPv6. Это важно не смешивать
с Ethernet-режимом.

Для заявленного TAP требуется:

- принимать и формировать EtherType `0x86DD`, не только `0x0800`;
- выбирать Ethernet header по версии вложенного IP-пакета;
- корректная IPv6 multicast MAC mapping;
- NDP (Neighbor Solicitation/Advertisement), Router Solicitation/Advertisement и нужные
  link-local/multicast пакеты;
- назначенный AuthOK адрес в L2 `/64` и RA для параметров/default router; Autonomous flag
  должен быть выключен, пока allocator/source guard не умеет регистрировать произвольные
  SLAAC/privacy-адреса;
- DAD для назначенного адреса и корректные ответы NDP без принятия адреса другой сессии;
- отсутствие зависимости MAC от четырёх байт IPv4-адреса;
- отдельные тесты TUN и TAP на всех реально поддерживаемых ОС.

Stateful DHCPv6 может быть отдельной функцией и не является условием native IPv6 для L3
TUN. Но существующий `dhcp.enabled` должен оставаться явно DHCPv4; нельзя молча считать его
DHCPv6.

## 13. Панель, Quick Start, установщики и примеры

Quick Start не должен молча менять существующий IPv4-профиль при повторном запуске. Нужны
явное действие «Включить/настроить IPv6» и выбор `auto|off|dual|ipv6`. `auto` проверяет
global IPv6, default route и реальный egress, затем сохраняет конкретный режим.
Независимый внешний listener `[::]` добавляется только когда host snapshot подтверждает
доступность IPv6 socket; IPv4-профиль обязан запускаться и на ядре с полностью отключённым IPv6.
Повторный Quick Start сохраняет вручную настроенный набор listeners существующего профиля.

При создании ULA генерируется стабильный RFC 4193 prefix (случайный `/48`, профильный
`/64`), проверяется пересечение с адресами хоста и другими профилями и результат сохраняется.
Префикс нельзя регенерировать при рестарте или повторном Quick Start.

Обновить и прогнать нужно:

- все 10 встроенных `QUICKSTART_SPECS`, повторное применение и явный IPv4→dual/IPv6 upgrade;
- мультипрофильный конфиг;
- конфиги, которые фактически устанавливает `.deb` в `/etc/qeli`: server, multiprofile,
  users, client и client-reality examples;
- остальные репозиторные примеры, включая max-obfuscation;
- installer-generated config, Docker seed config, OpenWrt UCI/LuCI и Keenetic hooks;
- bracketed IPv6 в public host, share link и panel API;
- все проверки доступности/latency в панелях и приложениях: A+AAAA, тот же transport-aware
  handshake для UDP/QUIC вместо TCP/ICMP-подмены и полное прекращение запросов при
  отключённом polling;
- Docker IPv6 forwarding/sysctls/network prerequisites.

Каждый сгенерированный `.conf` проходит строгий parse, runtime validation/preflight и
parse → serialize → parse. Тест должен проверять именно список файлов в собранном `.deb`, а
не похожую копию в исходниках.

## 14. Обязательные тесты и release gates

### Unit, property и fuzz

- INI defaults, bad family/mode/prefix, неизвестные ключи и round-trip;
- capability trailer, auth compatibility и повреждённые длины;
- NetworkPlan v2 и legacy projection;
- IPv6 extension headers, lengths, fragments, flow hash, ACL и source guard;
- IPv6 pool без перечисления `/64`, reservations и атомарный rollback dual allocation;
- ICMPv6 Packet Too Big и checksums;
- DATA_FRAG reorder/loss/duplicate/conflict/timeout/memory limits/packet-number uniqueness;
- DNS A/AAAA и IPv4/IPv6 upstream combinations;
- persist-TUN fingerprint и смена только одного IPv6 route/DNS/MTU.

### Linux network namespaces

Текущий автоматический результат (2026-08-31): **14/14 базовых сценариев пройдено** на Linux-лабе.
Runner проверил все сочетания outer4/outer6 × inner4/inner6 для TCP, UDP fake-TLS и UDP QUIC
в full tunnel, а также dual-stack TCP/UDP в split tunnel. Проверены адреса и маршруты TUN,
двунаправленный трафик, split bypass, отсутствие cross-family leak и восстановление состояния
после теста. Это доказательство базовой матрицы, а не завершение полной release matrix ниже.

Матрица содержит outer4/inner4, outer4/inner6, outer6/inner4, outer6/inner6, dual и
IPv6-only physical network; TCP/UDP/QUIC; все обфускации/Quick Start modes; full/split;
AAAA и IPv6 upstream DNS; ACL/isolation/`client_subnet`; route/NAT66; MTU 1280;
outer IPv4 MTU 576, асимметричный PMTU; reconnect/persist/roaming; kill switch и leak tests.

Packet capture должен доказать отсутствие внешней IP fragmentation Qeli UDP data,
отсутствие IPv4/IPv6/DNS leaks и корректный ICMPv6 PTB.

### Реальные платформы и совместимость

Обязательны физические/нативные тесты Android, iOS, Windows и macOS, включая оба per-app
режима, а также OpenWrt и Keenetic. Проверяются old-server/new-client,
new-server/old-client и new/new. Перед релизом пересобираются все native libraries и
автоматически сверяются ABI/capability versions приложения и ядра.

Включение runtime-gate в ветке разработки означает, что исходный путь можно тестировать
сквозным образом; оно не сертифицирует релиз. Релизная документация может объявлять IPv6
готовым только после зелёной матрицы, включая IPv6-only, TAP и per-app. Известное исключение
нельзя превращать в слово «полная».

## 15. Порядок реализации и зависимости

1. ✅ Добавлена flat-INI schema, parser/serializer/validation и round-trip tests.
2. ✅ Добавлены ABI/platform capabilities и обратно совместимое auth negotiation.
3. ✅ Введён typed dual AuthOK/NetworkPlan v2 с legacy IPv4 projection.
4. ✅ Введён общий IPv4/IPv6 packet parser и flow hash; normalization перенесён в AEAD padding.
5. ✅ Разделены inner MTU и двунаправленные local UDP budgets.
6. ✅ Реализован `DATA_FRAG_V1` и отдельный `data_frag` fuzz-target.
7. ✅ Сделаны атомарные IPv4/IPv6 pools и session indexes.
8. ✅ Обобщены server forwarding, source guard, ACL, isolation и client routes.
9. ✅ Реализованы ICMPv6 PTB, DNS, routed IPv6/NAT66 и rollback.
10. ✅ Добавлена Linux/OpenWrt/Keenetic и attach-existing поддержка.
11. ✅ Добавлены внешний IPv6 carrier и dual server listeners.
12. ✅ Завершены исходные адаптеры Android и iOS.
13. ✅ Завершены исходные адаптеры Windows/macOS global.
14. ✅ Завершены исходные адаптеры Windows/macOS per-app.
15. ✅ Завершены TAP/NDP/RA.
16. ✅ Обновлены панель, Quick Start, installer, `.deb`, Docker, примеры и документация.
17. ⏳ Native cores и базовая Linux-матрица 14/14 сверены; остались специальные Linux-сценарии и физическая release matrix.

Ранее этапы 1–6 блокировали inner IPv6 даже в экспериментальном профиле: без согласования,
корректного MTU и data fragmentation были возможны несовместимость, black hole и нарушение
IPv6 minimum MTU. Теперь они завершены и runtime-gate ветки разработки включён. Пункт 17
по-прежнему блокирует выпуск релиза.

## 16. Бывшие IPv4-only узлы, закрытые реализацией

Реализация заменила или обобщила исходные IPv4-only пути в следующих местах:

- фильтр inner packet в [client/mod.rs](../../../qeli/src/client/mod.rs);
- одиночные IPv4 AuthOK/NetworkPlan в
  [transport_core/session.rs](../../../qeli/src/transport_core/session.rs),
  [transport_core/network.rs](../../../qeli/src/transport_core/network.rs) и
  [transport_core/mod.rs](../../../qeli/src/transport_core/mod.rs);
- IPv4 resolver/socket carrier в
  [transport_core/carrier.rs](../../../qeli/src/transport_core/carrier.rs) и
  [transport_core/runtime.rs](../../../qeli/src/transport_core/runtime.rs);
- IPv4 pool/session/ACL/preflight в [server/pool.rs](../../../qeli/src/server/pool.rs),
  [server/mod.rs](../../../qeli/src/server/mod.rs),
  [server/acl.rs](../../../qeli/src/server/acl.rs) и
  [server/preflight.rs](../../../qeli/src/server/preflight.rs);
- IPv4-only flow hash в [protocol/mod.rs](../../../qeli/src/protocol/mod.rs);
- handshake-only UDP fragmentation в
  [protocol/udp_frag.rs](../../../qeli/src/protocol/udp_frag.rs);
- IPv4 TUN/TAP assumptions в [tun/iface.rs](../../../qeli/src/tun/iface.rs),
  [tun/tap.rs](../../../qeli/src/tun/tap.rs) и
  [transport_core/linux_tun.rs](../../../qeli/src/transport_core/linux_tun.rs);
- IPv4 defaults/pool/MTU validation в [config/server.rs](../../../qeli/src/config/server.rs);
- Quick Start IPv4 pool generation в [web/api/config.rs](../../../qeli/src/web/api/config.rs).

Эти места исходного кода покрыты unit/cross-build gates. Оставшаяся релизная работа —
физическое сквозное доказательство пути от flat-INI и negotiation до платформенного
интерфейса, реального трафика, PMTU и удаления правил.
