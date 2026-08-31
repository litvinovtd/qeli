# IPv6 в qeli: настройка, эксплуатация и диагностика

**English version → [../eng/IPV6.md](../../eng/manuals/IPV6.md)**

Это пользовательское и операторское руководство по полной поддержке IPv6. Справочник
всех отдельных ключей остаётся в [CONFIG.md](CONFIG.md), а внутреннее устройство и
release gates — в [IPV6-IMPLEMENTATION-PLAN.md](../plans/IPV6-IMPLEMENTATION-PLAN.md).

## 1. Два независимых уровня IPv6

В qeli нужно различать:

1. **Внешний carrier** — TCP/UDP-соединение клиента с сервером. Его определяют серверные
   `bind.address`/`listen` и клиентский `server`. Carrier может быть IPv4 или IPv6.
2. **Внутренний трафик** — IP-пакеты, которые идут внутри шифрованного туннеля. Его
   определяют `tun.ip_mode`, IPv4/IPv6-пулы и результат аутентифицированного согласования.

Эти уровни независимы. IPv4 carrier может переносить IPv6 внутри туннеля, а IPv6 carrier —
IPv4. Внешний IPv6 listener сам по себе не выдаёт клиенту внутренний IPv6-адрес.

IPv6 endpoint в клиентском INI записывается со скобками:

```ini
[qeli]
server = [2001:db8::10]:443
```

Для доменного имени скобки не нужны; qeli рассматривает пригодные A и AAAA-адреса carrier
и сохраняет фактический `carrier_address` вне full-tunnel маршрутов.

## 2. Режимы серверного профиля

| `tun.ip_mode` | Что выдаётся клиенту | Назначение |
|---|---|---|
| `ipv4` | только IPv4 | совместимость и IPv4-only инфраструктура |
| `dual` | IPv4 и IPv6 | рекомендуемый режим для обычного Интернета |
| `ipv6` | только IPv6 | IPv6-only сети; IPv4 без отдельного NAT64 недоступен |

Для L3 TUN клиент получает host-префиксы `/32` и `/128`, а `NetworkPlan v2` отдельно
передаёт allocation/on-link префиксы и gateway. Это исключает ARP/NDP на point-to-point
TUN, но сохраняет корректные connected routes.

Минимальный dual-stack набор полей:

```ini
[profile:dual]
tun.ip_mode = dual
tun.name = vpn0
tun.address = 10.19.0.1
tun.ipv6_address = fd71:e1:8000:102::1
tun.mtu = 1400
tun.device_type = tun

pool.cidr = 10.19.0.0/24
pool.ipv6.cidr = fd71:e1:8000:102::/64

routing.nat.enabled = true
routing.ipv6.mode = nat66

dns.enabled = true
dns.listen = 10.19.0.1
dns.listen_ipv6 = fd71:e1:8000:102::1
dns.push_servers = 10.19.0.1, fd71:e1:8000:102::1
```

Полный runtime-проверяемый исходный пример находится в
[`qeli/config/server-ipv6.conf`](../../../qeli/config/server-ipv6.conf). И DEB-пакет, и
`install-qeli-server.sh` устанавливают его как `/etc/qeli/server-ipv6.conf.example`;
скопируйте или адаптируйте этот пример в активный `/etc/qeli/server.conf`. Не копируйте
один ULA-префикс на несколько независимых площадок: для каждого сайта нужен собственный
RFC4193 `/48`, а каждому профилю — отдельный `/64`.

Для адресов туннеля используйте локально назначаемую половину ULA — `fd00::/8` (внутри
RFC4193 `fc00::/7`). **Не используйте `fe80::/10`**: link-local адрес привязан к интерфейсу,
не маршрутизируется через туннель и отклоняется qeli для общепрофильных полей TUN/pool.
Статические файлы содержат только заметный пример site-prefix; Quick Start и одноразовый
установщик заменяют его 40 случайными битами Global ID.

На обычном VPS NAT66 — это IPv6 MASQUERADE: qeli отправляет ULA-пул через интерфейс,
выбранный IPv6 default route, а ядро подставляет текущий публичный GUA этого интерфейса.
Установщик сохраняет dual-stack, только если одновременно найдены default route, публичный
исходный адрес из `2000::/3` и рабочая NAT-таблица `ip6tables`. Иначе он записывает безопасный
активный IPv4-only профиль. В Debian/Ubuntu обе команды — `iptables` и `ip6tables` — ставятся
одним пакетом `iptables`.

## 3. Политика клиента `ipv6`

```ini
[qeli]
ipv6 = auto
```

| Значение | Поведение |
|---|---|
| `auto` | принимает IPv4/dual/IPv6-план; dual может безопасно понизиться до IPv4, если адаптер не имеет полного IPv6-контракта |
| `required` | требует внутренний IPv6 и завершает подключение ошибкой при старом сервере, IPv4-only профиле, MTU ниже 1280 или неполных возможностях платформы |
| `off` | на dual-профиле запрашивает только IPv4; IPv6-only профиль отклоняется |

`auto` — значение по умолчанию. Для проверки релизной IPv6-функциональности и для сетей,
где IPv6 обязателен, используйте `required`: скрытого downgrade тогда не будет.

Согласование входит в аутентифицированный handshake. Сервер строит один NetworkPlan,
платформа обязана атомарно применить все его адреса, маршруты, DNS и MTU либо отклонить
generation до начала packet flow.

## 4. Выход IPv6 с сервера

`routing.ipv6.mode` имеет три режима:

### `nat66`

qeli включает проверенный forwarding и MASQUERADE через `ip6tables`. Подходит для ULA на
обычном VPS, когда провайдер не маршрутизирует отдельный GUA-префикс к VPN-клиентам.
Нужны публичный IPv6 на WAN и IPv6 default route.

```ini
routing.ipv6.mode = nat66
routing.ipv6.interface =
```

Пустой interface означает автоопределение IPv6 uplink. Если оно неоднозначно, укажите
например `routing.ipv6.interface = ens18`.

### `route`

Сохраняет исходный IPv6 клиента. Используйте с маршрутизируемым GUA-префиксом либо для
site-to-site/LAN маршрутизации. Upstream router обязан знать обратный маршрут к
`pool.ipv6.cidr` через qeli-сервер.

```ini
tun.ipv6_address = 2001:db8:1200:10::1
pool.ipv6.cidr = 2001:db8:1200:10::/64
routing.ipv6.mode = route
routing.ipv6.interface =
```

`2001:db8::/32` предназначен только для документации — замените его реальным
делегированным префиксом. Для LAN-only route пустой interface допустим: qeli использует
kernel routes и не требует публичного default uplink.

#### Публичные IPv6 клиентов без NAT66

`route` позволяет назначить каждому клиенту настоящий глобальный unicast IPv6 (GUA),
сохранить этот адрес на внешнем интерфейсе и принимать инициированные из Интернета
соединения. Для этого провайдер должен маршрутизировать **отдельный префикс** на WAN-адрес
qeli-сервера. Типичная схема выглядит так:

```text
WAN qeli-сервера:                  2001:db8:100::10/64
Префикс, маршрутизируемый серверу: 2001:db8:1200:10::/64
Маршрут у провайдера:              2001:db8:1200:10::/64 via 2001:db8:100::10
Адрес TUN сервера:                 2001:db8:1200:10::1
Адрес клиента alice:               2001:db8:1200:10::100
```

Адреса `2001:db8::/32` в примере являются документационными. В реальной конфигурации
используйте выданные провайдером GUA. Если делегирован `/56` или `/48`, выделяйте каждому
профилю отдельный `/64`.

Дополните профиль сервера:

```ini
[profile:public-v6]
tun.ip_mode = dual
tun.name = vpn-public
tun.ipv6_address = 2001:db8:1200:10::1
pool.ipv6.cidr = 2001:db8:1200:10::/64

# IPv6 передаётся с исходным адресом клиента; MASQUERADE не создаётся.
routing.ipv6.mode = route
routing.ipv6.interface = ens3
```

В dual-stack профиле `routing.nat.enabled = true` может независимо продолжать делать
NAT44 для IPv4: этот ключ не включает NAT66 и не изменяет routed IPv6.

Динамические IPv6 выдаются из всего `pool.ipv6.cidr`. Для постоянного публичного адреса,
DNS-записи или входящих соединений закрепите адрес за пользователем в `users.conf`:

```ini
[user:alice]
static_ipv6 = 2001:db8:1200:10::100
```

То же значение можно задать на странице **Users / Static IPv6**, через
`qeli add-client --static-ipv6 2001:db8:1200:10::100` или профильным ключом
`pool.ipv6.reservation.alice`. Адрес обязан находиться внутри `pool.ipv6.cidr` и быть
уникальным. Фиксированный адрес рассчитан на одну активную сессию: новый сеанс этого
пользователя вытесняет прежнего держателя адреса.

Для строгого IPv6 full-tunnel на клиенте:

```ini
ipv6 = required
gateway = true
```

Перед подключением клиента проверьте сервер и upstream:

```bash
# У провайдера/на upstream должен существовать обратный маршрут через WAN сервера.
ip -6 route show default

# После запуска профиль создаёт connected route к пулу через свой TUN.
ip -6 route show 2001:db8:1200:10::/64

# route не должен создавать IPv6 MASQUERADE для этого пула.
ip6tables -t nat -S POSTROUTING

# qeli включает forwarding и устанавливает проверенные двусторонние FORWARD rules.
sysctl net.ipv6.conf.all.forwarding
ip6tables -S FORWARD
```

Затем с внешнего IPv6-хоста проверьте исходящий адрес клиента и обратную доступность его
фиксированного GUA. Захват `tcpdump -ni ens3 'ip6 and host 2001:db8:1200:10::100'` должен
показывать исходный адрес клиента без подмены.

Обычный WAN `/64`, непосредственно подключённый к `ens3`, нельзя одновременно использовать
как `pool.ipv6.cidr`: такой провайдер ожидает NDP для каждого адреса, а qeli не реализует
upstream NDP proxy на WAN. Preflight также отклоняет пул, пересекающийся с существующим
адресом или маршрутом хоста. Попросите routed `/64` (либо `/56`/`/48`), настройте у
провайдера явный маршрут через сервер или используйте `nat66`.

Routed GUA делает клиент непосредственно адресуемым из Интернета. qeli разрешает
двусторонний forwarding в режиме `route`, поэтому cloud security group, firewall сервера и
firewall самого клиента должны явно определять допустимые входящие протоколы и порты.

### `off`

Клиенты могут получить внутренний IPv6, но qeli fail-closed блокирует его forwarding за
границу профиля. Это осознанный изолированный IPv6-сегмент, а не «ничего не настраивать».
qeli проверяет правила `ip6tables` и отказывается запускать профиль, если изоляцию нельзя
гарантировать.

qeli управляет `net.ipv6.conf.all.forwarding` и, для RA-зависимого WAN, сначала арендует
`accept_ra=2`, чтобы включение forwarding не уничтожило SLAAC-адрес/default route.
Исходные значения восстанавливаются после последнего чисто остановленного владельца.

## 5. IPv6-only профиль

```ini
[profile:v6-only]
enabled = true
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp

tun.ip_mode = ipv6
tun.name = vpn0
tun.ipv6_address = fd71:e1:20::1
tun.mtu = 1400
pool.ipv6.cidr = fd71:e1:20::/64

routing.nat.enabled = false
routing.forward_private = false
routing.ipv6.mode = nat66

dns.enabled = true
dns.listen_ipv6 = fd71:e1:20::1
dns.upstream = 2606:4700:4700::1111
```

На клиенте для строгой проверки:

```ini
ipv6 = required
gateway = true
```

qeli не реализует NAT64/DNS64. IPv6-only туннель не превращает IPv4-only сайты в IPv6.
Если нужны оба семейства, используйте `dual` либо отдельный контролируемый NAT64.

## 6. Full-tunnel и защита отсутствующего семейства

В full-tunnel оба IP-семейства обязаны либо идти через qeli, либо блокироваться. Если сервер
выдал только IPv4, нативный IPv6 клиента по умолчанию захватывается/блокируется. Для
IPv6-only плана симметрично блокируется нативный IPv4.

Только для осознанного исключения существуют:

```ini
allow_ipv4_leak = false
allow_ipv6_leak = false
```

`true` разрешает соответствующему **отсутствующему** семейству идти мимо full-tunnel.
Это не средство включения IPv6 и не требуется dual-stack плану. Оба значения по умолчанию
`false`; включайте их только после отдельной оценки утечки. В split-tunnel назначения вне
маршрутов и так остаются на физической сети.

## 7. DNS

Для встроенного DNS каждый listener должен совпадать с gateway своего семейства:

```ini
dns.enabled = true
dns.listen = 10.19.0.1
dns.listen_ipv6 = fd71:e1:8000:102::1
dns.push_servers = 10.19.0.1, fd71:e1:8000:102::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

Клиент фильтрует DNS по фактически согласованным inner families. Публичный fallback DNS
не подставляется. `dns = off`/`system` оставляет системный resolver; это отдельное решение
от `ipv6 = off`.

## 8. Статические адреса и резервации

Резервация в профиле:

```ini
pool.reservation.alice = 10.19.0.100
pool.ipv6.reservation.alice = fd71:e1:8000:102::100
```

Либо в базе пользователей:

```ini
[user:alice]
static_ip = 10.19.0.100
static_ipv6 = fd71:e1:8000:102::100
```

Адрес обязан быть usable host внутри соответствующего пула, не совпадать с gateway,
exclude или адресом другого разрешённого пользователя. `check-config`, CLI и панель
отклоняют конфликт до записи/старта; runtime не заменяет неверный fixed-адрес динамическим.

## 9. Quick Start веб-панели

Quick Start предлагает `auto`, `ipv4`, `dual`, `ipv6`.

- `auto` выбирает `dual` только если на интерфейсе IPv6 default route обнаружен публичный
  GUA и доступен `ip6tables`; иначе сохраняет рабочий `ipv4`.
- явный `dual`/`ipv6` fail-closed отказывается без публичного IPv6, firewall backend или
  при `tun.mtu < 1280`;
- для IPv6 создаётся collision-checked RFC4193 `/64`, gateway `::1`, IPv6 DNS listener и
  `routing.ipv6.mode = nat66`;
- `dual` сохраняет NAT44 и добавляет NAT66; `ipv6` выключает бессмысленные NAT44 и
  IPv4-forwarding;
- `auto` вычисляется один раз. Повторный Launch существующего профиля сохраняет его
  конкретный режим и ручные настройки; явный выбор режима намеренно переключает и
  нормализует весь egress-контракт.

Quick Start обещает именно Internet IPv6. Для routed GUA или изолированного `off`
используйте Config/Raw INI и ручную инфраструктуру.

## 10. Требования и предварительная проверка хоста

```bash
ip -6 addr show scope global
ip -6 route show default
command -v ip6tables
sudo ip6tables -S
```

Для NAT66 должен быть пригодный публичный IPv6 на том же интерфейсе, где проходит default
route. ULA/link-local сами по себе этого не доказывают. Firewall-политика хоста и облачная
security group должны разрешать нужный внешний TCP/UDP listener; внутренний IPv6 не требует
отдельного публичного listener.

Перед стартом:

```bash
sudo qeli check-config --config /etc/qeli/server.conf
qeli check-config --config ~/qeli-client.conf --client
```

`tun.mtu` для IPv6 должен быть не ниже 1280. Значение 1400 — безопасная стартовая точка
для обычной инкапсуляции; итоговый PMTU зависит от outer transport и сети.

## 11. Проверка после подключения

На Linux-сервере:

```bash
ip -4 addr show dev vpn0
ip -6 addr show dev vpn0
ip -4 route show dev vpn0
ip -6 route show dev vpn0
sudo tcpdump -ni vpn0 'ip or ip6'
```

На клиенте проверьте:

1. в статусе присутствуют все адреса NetworkPlan (`IPv4/32` и/или `IPv6/128`);
2. доступен tunnel gateway обоих семейств;
3. затем доступен публичный адрес;
4. DNS возвращает A и AAAA согласно режиму;
5. full-tunnel не оставляет отсутствующее семейство на физическом интерфейсе.

Пример:

```bash
ping -6 fd71:e1:8000:102::1
ping -6 2606:4700:4700::1111
curl -4 https://ifconfig.co
curl -6 https://ifconfig.co
```

На Windows используйте `Get-NetIPAddress` и `Get-NetRoute -AddressFamily IPv6`; на macOS —
`ifconfig utunN` и `netstat -rn -f inet6`. Android/iOS показывают согласованные адреса в
деталях подключения; системные VPN API владеют интерфейсом и маршрутами.

## 12. TAP и IPv6

Полноценный `device_type = tap` доступен клиенту только на Linux. Серверный Linux TAP
принимает локальные Ethernet-кадры IPv4/IPv6, ARP и NDP, но qeli wire остаётся L3:
произвольные EtherTypes, VLAN/STP/LLDP и прозрачный L2 bridge через протокол не переносятся.
Windows, macOS, Android и iOS сохраняют переносимый ключ, но отклоняют TAP при подключении.

## 13. Матрица платформ

Windows и macOS показывают `ipv6 = auto|required|off` и оба исключения для отсутствующего
семейства как структурированные локализованные поля. Android и iOS намеренно используют
полный raw INI-редактор, а не вторую неполную форму; в шаблоне нового профиля видны
`ipv6 = auto` и два закомментированных leak-исключения. Все четыре приложения разбирают и
валидируют одни и те же ключи до подключения. Поэтому значение из raw INI имеет ту же
семантику, что и выбор в desktop-форме; `allow_ipv4_leak` и `allow_ipv6_leak` остаются
расширенными исключениями full-tunnel, а не обычными переключателями соединения.

| Платформа | IPv6 TUN/routes/DNS | Full-tunnel защита | Особенности |
|---|---:|---:|---|
| Linux CLI | да | iptables/ip6tables | TUN и клиентский TAP |
| Windows | да | Windows Firewall/WinDivert | редактор показывает IPv6 policy/leak controls |
| macOS | да | pf/Network Extension | системный utun |
| Android | да | VpnService + проверенный lockdown | Always-on VPN настраивается системой |
| iOS | да | системная On Demand политика | `kill_switch` не эмулируется внутри PacketTunnel |
| OpenWrt/Keenetic | да | firewall/hooks платформы | router/site-to-site сценарии |

## 14. Частые неисправности

| Симптом | Причина | Что проверить |
|---|---|---|
| Quick Start `auto` создал IPv4 | нет публичного GUA/default route либо `ip6tables` | `ip -6 addr`, `ip -6 route`, `command -v ip6tables` |
| явный dual/IPv6 отклонён | Quick Start не может обещать Internet IPv6 | текст preflight; исправить WAN/firewall или настроить `route/off` вручную |
| `ipv6=required` не подключается | профиль IPv4-only, старый сервер, MTU <1280 или неполный adapter | версия обеих сторон, лог capabilities, MTU |
| адрес есть, Интернета нет | нет NAT66 или обратного маршрута | `routing.ipv6.mode`, WAN interface, upstream route |
| route работает только в одну сторону | upstream не знает VPN `/64` | добавить обратный маршрут к `pool.ipv6.cidr` |
| AAAA есть, соединения нет | маршрут/MTU/firewall, а не DNS | ping gateway, public IPv6, tcpdump, ICMPv6 PTB |
| full-tunnel «сломал» второе семейство | оно отсутствует в плане и намеренно блокируется | использовать dual или осознанно разрешить соответствующий leak |
| внешний IPv6 endpoint недоступен | listener/firewall carrier не настроен | `listen = [::]:port`, socket и security group |
| TAP IPv6 молчит | ожидается прозрачный L2 bridge | проверять IP/ARP/NDP; произвольный Ethernet qeli не переносит |

## 15. Миграция и откат

1. Сначала обновите сервер и клиенты до версии с NetworkPlan v2.
2. Добавьте уникальный IPv6 `/64`, gateway, DNS listener и `routing.ipv6.mode`.
3. Проверьте сервер через `check-config`.
4. Подключите тестовый клиент с `ipv6=required`.
5. Проверьте адреса, оба gateway, DNS, PMTU и утечки.
6. После этого переводите остальных клиентов с `auto`.

Для отката на сервере установите `tun.ip_mode = ipv4`, удалите/очистите IPv6 pool/listener
и установите `routing.ipv6.mode = off`; в Quick Start явный IPv4 делает эту нормализацию
автоматически. На клиентах верните `ipv6 = auto` или `off`. После изменения server data
plane нужен рестарт профиля/сервиса.
