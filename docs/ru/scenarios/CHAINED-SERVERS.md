# Цепочка Qeli: клиент → A → B → Интернет

[← Сценарии использования](README.md)

Клиент подключается к **A**, а в Интернет выходит через **B**.
На A используется встроенный клиент Qeli из вкладки **Клиент** для подключения к B.
Собственные маршруты и DNS обоих серверов остаются прежними.
Ниже — полные конфиги: firewall, NAT и таблица маршрутизации уже включены в INI.

## Поддерживаемая версия

Сначала выполните `qeli --version`:

- **0.8.3:** post_up выполняется один раз на процесс. После полного reconnect маршрут,
  созданный hook, сам не восстановится; приведённая ниже схема автоматического восстановления
  для этой версии не подходит.
- **Планируемая 0.8.4:** post_up будет повторяться после успешного пересоздания TUN.
  Это уже проверено на кандидате, но релиз пока не опубликован. Ниже описан именно этот вариант.

## Оглавление

[Вариант 1: root](#вариант-1-root) · [Вариант 2: User=qeli](#вариант-2-userqeli)

[Вводные данные](#вводные-данные)

1. [Конфиг сервера B](#1-конфиг-сервера-b)
2. [Конфиг сервера A](#2-конфиг-сервера-a)
3. [Подключение A к B](#3-подключение-a-к-b)
4. [Запустить и проверить](#4-запустить-и-проверить)

[Автозагрузка и восстановление связи](#автозагрузка-и-восстановление-связи)

[Откат запуска от root](#откат-запуска-от-root) · [Минимальный чек-лист](#минимальный-чек-лист)

## Выберите вариант запуска

Qeli уже [установлен](../manuals/GETTING-STARTED.md) на A/B. Административные команды выполняются
в root-сеансе, но сама служба может работать от другого пользователя. Проверьте на A/B:

```sh
systemctl show qeli -p User -p Group -p AmbientCapabilities -p CapabilityBoundingSet -p NoNewPrivileges
```

Выберите вариант **для каждого сервера отдельно**:
[вариант 1 — root](#вариант-1-root) или [вариант 2 — User=qeli](#вариант-2-userqeli).
Если не уверены в настройках non-root unit, используйте описанный root-вариант только
после оценки рисков ниже. Non-root требует проверки unit; автозапуск сам по себе root не требует.

Сохраните конфиги, владельцев/права и drop-in службы. Первую настройку выполняйте
без VPN-клиентов: `systemctl stop qeli` на A/B. SSH не закрывайте.

### Вариант 1: root

Сетевые hooks в этой проверке выполнялись **от root**. Пакетная служба обычно работает
от пользователя qeli.

Это повышает последствия ошибки или компрометации Qeli: hooks исполняют shell-команды
с правами процесса. **Не меняйте пользователя службы только ради autostart:** сам флаг
этого не требует. Root здесь относится к варианту с привилегированными сетевыми hooks.
До изменения сохраните конфиги с владельцами/правами и текущие drop-in службы;
существующий chain.conf не перезаписывайте. При ограничивающем unit/sandbox смена одного
User не гарантирует доступ к ключам и каталогам: пакетная миграция UID отдельно не тестировалась.

Если служба уже работает от root, менять её User/Group не нужно. При осознанном
переходе на root создайте на соответствующем сервере
`/etc/systemd/system/qeli.service.d/chain.conf`:

```ini
[Service]
User=root
Group=root
```

Родительский каталог можно создать командой
`install -d /etc/systemd/system/qeli.service.d`. Это меняет пользователя существующей
службы, а не создаёт ещё одну. INI с командами должен редактировать только администратор.
После сохранения конфигов в шагах 1–3, только для root-варианта на A/B:
`chown root:qeli /etc/qeli/server.conf; chmod 640 /etc/qeli/server.conf`.
На A: `chown root:root /etc/qeli/clients/upstream.conf; chmod 600 /etc/qeli/clients/upstream.conf`.

Далее переходите к [вводным данным](#вводные-данные); вариант 2 можно пропустить.

### Вариант 2: User=qeli

Сохраните `User=qeli` / `Group=qeli`; root-override из варианта 1 не применяйте.
Этот вариант требует проверки unit и прав; это не автоматическая замена User=root.
В штатном пакетном unit уже заданы сетевые capabilities. Hooks и встроенный клиент
наследуют права службы, но не получают root автоматически.

1. **CLI запускайте от пользователя службы.** Например, в шаге 1 на B:

   ```sh
   sudo -u qeli qeli add-client upstream --profiles chain --static-ip 10.80.2.2 --config /etc/qeli/server.conf
   sudo -u qeli qeli show-identity --config /etc/qeli/server.conf
   ```

   Аналогично запускайте add-client на A, show-identity, set-web-password и check-config.
   Здесь sudo переключает пользователя, а не повышает права: root-сеанс уже открыт.
   Простой `sudo -u qeli` не воспроизводит capabilities работающей systemd-службы,
   поэтому таким запуском не проверяют сетевые hooks.
2. **Права файлов.** Перед первым CLI-вызовом у qeli должен быть доступ к серверному
   конфигу, users_file, identity-ключу и их каталогам. Новые конфиги этого варианта
   делайте владельцем qeli:qeli с режимом 0600. Для каталога из шага 3 используйте
   `install -d -o qeli -g qeli -m 700 /etc/qeli/clients`; файл upstream.conf также должен
   читаться qeli и быть доверенным для hooks. `/run/qeli`, state/log-каталоги в пакетной
   службе создаёт systemd. Существующие ключи сохраняйте; исправляйте права только
   конкретных нужных файлов, не выполняйте рекурсивный chown всего /etc/qeli.
3. **Права сетевых команд.** Нужен CAP_NET_ADMIN для TUN, ip rule/route и firewall;
   в пакетном unit также есть CAP_NET_RAW и CAP_NET_BIND_SERVICE. Сохраняйте их
   в AmbientCapabilities и CapabilityBoundingSet. При своём unit сверяйте также sandbox
   и доступ к /dev/net/tun. Capabilities не отменяют файловые права: например, запрет
   доступа к /run/xtables.lock требует отдельного решения администратора.
4. **Проверка.** После штатного запуска из шага 4 проверьте журнал hooks и фактические
   правила/маршруты. При Permission denied или Operation not permitted не продолжайте,
   пока не исправлены права/ограничения unit. Не вставляйте sudo в INI: в пакетном unit
   NoNewPrivileges=true запрещает такой способ повышения прав. Не используйте chmod 777,
   общий NOPASSWD sudoers или setcap на shell/ip/iptables.

Для другого служебного UID замените qeli в примерах его пользователем и группой.
**Граница проверки:** эта цепочка тестировалась от root; вариант User=qeli выше описывает
требования и порядок настройки, но не является отдельным подтверждённым лабораторным
прогоном. Не приписывайте ему результаты root-серии.

## Вводные данные

Выполняйте только выбранный выше вариант. Команды `qeli ...` в общих шагах показаны
для root; в варианте 2 добавляйте `sudo -u qeli` и сохраняйте права пользователя qeli.

Подставьте свои значения. Пароли пользователей VPN не являются паролем веб-панели.

| Переменная | Где взять | Где используется |
| --- | --- | --- |
| `A_IP` | Внешний IPv4 сервера A | `server = A_IP:4553` у конечного клиента C |
| `B_IP` | Внешний IPv4 сервера B | `server = B_IP:4553` у встроенного клиента A → B |
| `B_WAN` | На B: имя после `dev` в `ip route get 1.1.1.1` | Все вхождения B_WAN в post_up **и** post_down сервера B |
| `PASSWORD` | Пароль из `add-client upstream` на B, шаг 1 | `pass` у клиента A → B |
| `B_PUBLIC_KEY` | Публичный ключ профиля chain из `show-identity` на B | `key` у клиента A → B |
| `C_PASSWORD` | Пароль из `add-client c` на A, шаг 2 | `pass` у конечного клиента C |
| `A_PUBLIC_KEY` | Публичный ключ профиля chain из `show-identity` на A | `key` у конечного клиента C |

TCP/4553 должен быть доступен на A/B через существующий INPUT firewall и firewall
провайдера; их общие правила здесь не меняются. Приватные identity-ключи не переносите.
Если заменить B_WAN только в post_up, post_down не сможет удалить NAT при остановке.
Проверьте замену в обеих строках.

Сети `10.80.1.0/24` (клиенты A) и `10.80.2.0/24` (A → B) не должны пересекаться
с вашими сетями. Таблица **208**, приоритет **20800** и имена `qeli-in/qeli-out/qeli-b`
должны быть свободны либо принадлежать только этой схеме. Проверьте
`ip -4 rule show` и `ip -4 route show table 208`; отсутствующая таблица — нормально.
Чужие записи не удаляйте.

Примеры — для отдельной настройки, IPv4 внутри туннеля, TCP FakeTLS и Recordizer required.
Если сервер уже настроен, сохраните его глобальные секции, auth и файл пользователей,
а перенесите только новый профиль `[profile:chain]` целиком.
Нужны `ip`, `iptables`, `ip6tables`, `grep`. Команды `nft` не используются.

**Веб-панель необязательна.** В полных примерах `[web] enabled=false` намеренно отключает
только HTTP-интерфейс. Менеджер клиентов внутри основного Qeli всё равно читает
`autostart=true` и запускает A → B. Если панель уже настроена, сохраните её существующий
раздел `[web]`, а не заменяйте его приведённым примером.

## 1. Конфиг сервера B

**Зачем:** B принимает A и выполняет NAT для сети его клиентов.
Полный `/etc/qeli/server.conf` на B:

```ini
[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true

[web]
enabled = false

[logging]
level = info

[profile:chain]
enabled = true
identity_key = /etc/qeli/identity/chain.key
bind.address = 0.0.0.0
bind.port = 4553
bind.transport = tcp
tun.name = qeli-b
tun.address = 10.80.2.1
tun.mtu = 1400
pool.cidr = 10.80.2.0/24
pool.exclude = 10.80.2.1
routing.nat.enabled = false
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = set -e; iptables -w 5 -t nat -C POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE 2>/dev/null || iptables -w 5 -t nat -A POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE
routing.post_down = set -e; if iptables -w 5 -t nat -C POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE 2>/dev/null; then iptables -w 5 -t nat -D POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE; fi
dns.enabled = false
obf.mode = fake-tls
obf.recordizer.policy = required
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 100
```

Создайте пользователя A и получите публичный ключ B:

```sh
qeli add-client upstream --profiles chain --static-ip 10.80.2.2 --config /etc/qeli/server.conf
qeli show-identity --config /etc/qeli/server.conf
```

Сохраните пароль и ключ профиля chain. В `/etc/qeli/users.conf` добавьте строку
`client_subnet` **в существующую** секцию `[user:upstream]`.
Ниже показан только изменяемый фрагмент; остальные строки секции сохраняются.
`EXISTING_HASH` обозначает уже созданный хеш: **не вставляйте это слово вместо него**.

До:

```ini
[user:upstream]
password_hash = EXISTING_HASH
```

После:

```ini
[user:upstream]
password_hash = EXISTING_HASH
client_subnet = 10.80.1.0/24
```

Она сообщает B, что сеть 10.80.1.0/24 находится за A.
Хеш пароля и остальные поля пользователя не меняйте; второй `[user:upstream]` не создавайте.
Если эта подсеть уже указана, повторно её не добавляйте; другие client_subnet сохраните.

## 2. Конфиг сервера A

**Зачем:** A принимает конечных клиентов; отдельная table 208 направит их пакеты в qeli-out.
Полный `/etc/qeli/server.conf` на A:

```ini
[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true

[web]
enabled = false

[logging]
level = info

[profile:chain]
enabled = true
identity_key = /etc/qeli/identity/chain.key
bind.address = 0.0.0.0
bind.port = 4553
bind.transport = tcp
tun.name = qeli-in
tun.address = 10.80.1.1
tun.mtu = 1400
pool.cidr = 10.80.1.0/24
pool.exclude = 10.80.1.1
routing.nat.enabled = false
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = set -e; iptables -w 5 -t mangle -C FORWARD -i qeli-in ! -o qeli-out -j DROP 2>/dev/null || iptables -w 5 -t mangle -I FORWARD 1 -i qeli-in ! -o qeli-out -j DROP; ip6tables -w 5 -t mangle -C FORWARD -i qeli-in -j DROP 2>/dev/null || ip6tables -w 5 -t mangle -I FORWARD 1 -i qeli-in -j DROP; ip -4 route replace blackhole default metric 32767 table 208; ip -4 rule show | grep -q '^20800:' || ip -4 rule add priority 20800 iif qeli-in lookup 208
routing.post_down = set -e; if iptables -w 5 -t mangle -C FORWARD -i qeli-in ! -o qeli-out -j DROP 2>/dev/null; then iptables -w 5 -t mangle -D FORWARD -i qeli-in ! -o qeli-out -j DROP; fi; if ip6tables -w 5 -t mangle -C FORWARD -i qeli-in -j DROP 2>/dev/null; then ip6tables -w 5 -t mangle -D FORWARD -i qeli-in -j DROP; fi; if ip -4 rule show | grep -q '^20800:.*iif qeli-in.*lookup 208'; then ip -4 rule del priority 20800 iif qeli-in lookup 208; fi; if ip -4 route show table 208 2>/dev/null | grep -q '^blackhole default.*metric 32767'; then ip -4 route del blackhole default metric 32767 table 208; fi
dns.enabled = false
obf.mode = fake-tls
obf.recordizer.policy = required
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 100
```

Identity на A своя: приватный ключ B не копируйте. Создайте конечного пользователя:

```sh
qeli add-client c --profiles chain --static-ip 10.80.1.10 --config /etc/qeli/server.conf
qeli show-identity --config /etc/qeli/server.conf
```

**Только если веб-интерфейс на A нужен, но ещё не настроен:** выполните
`qeli set-web-password --config /etc/qeli/server.conf`. Команда **изменяет этот файл**:
сохраняет хеш пароля панели и ставит `[web] enabled=true`. После неё итоговым считается
конфиг на диске — не возвращайте его к блоку enabled=false из примера. Перезапуск в шаге 4
применит изменение. Панель слушает localhost по умолчанию; используйте уже настроенный
SSH-туннель или HTTPS-прокси. Если веб-интерфейс не нужен, пропустите эту команду:
автозапуск клиента продолжит работать.

## 3. Подключение A к B

**Зачем:** настроить подключение к B через уже имеющийся встроенный клиент Qeli на A.
Он поднимает qeli-out и добавляет рабочий маршрут.

Если подключение к B уже есть во вкладке **Клиент**, используйте его существующий профиль:
внесите параметры ниже в его файл, сохранив прежнее имя. **Второй профиль создавать не нужно.**
Hooks редактируются локально в файле, не через форму панели.

`/etc/qeli/clients/upstream.conf` ниже — пример имени файла **на A**. Если ваш профиль
называется иначе, используйте его имя и в последующих путях к конфигу и логу.
Каталог `/etc/qeli/clients` уже используется Qeli; только если его ещё нет, выполните
`install -d -m 700 /etc/qeli/clients`. Дополнительная установка клиента не требуется.

Полный конфиг подключения:

```ini
[qeli]
autostart = true
server = B_IP:4553
proto = tcp
mode = fake-tls
user = upstream
pass = PASSWORD
key = B_PUBLIC_KEY
dev = qeli-out
gateway = false
pull_routes = false
forward = true
gateway_nat = false
kill_switch = false
ipv6 = off
allow_ipv6_leak = false
dns = off
reconnect = true
timeout = 3
post_up = ip -4 route replace default dev qeli-out metric 10 table 208
post_down = if ip -4 route show table 208 2>/dev/null | grep -q '^default dev qeli-out.*metric 10'; then ip -4 route del default dev qeli-out metric 10 table 208; fi
```

`gateway=false`, `pull_routes=false` и `dns=off` сохраняют собственный выход и DNS A.
На A NAT не включается. `autostart=true` запускает клиент вместе с основным Qeli,
а `reconnect=true` поддерживает подключение при временной недоступности B.

Все сетевые действия уже в конфигурации:

- `routing.forward_private=true` — Qeli сам включает IPv4 forwarding и свои разрешения
  FORWARD на A/B. Отдельно добавлять их вручную не требуется.
- Серверные `routing.post_up/post_down` — дополнительные правила firewall/table 208
  на A и помеченный NAT на B.
- Клиентские `post_up/post_down` — только рабочий default через qeli-out в table 208.

**Копирование hooks:** каждая строка `post_up`/`post_down` должна быть одной физической
строкой INI: от имени параметра до последнего символа команды. Визуальный перенос в
браузере допустим; не вставляйте Enter, обратные слеши для переноса или многоточия.
Редактируйте файл на сервере, не вставляйте команды в панель. После сохранения обязательно
выполните обе проверки check-config из шага 4; они не заменяют проверку маршрутов после запуска.

Контроль после вставки: **в секции `[profile:chain]`** должна быть ровно одна строка
`routing.post_up = ...` и одна `routing.post_down = ...`; в клиентской `[qeli]` — по одной
`post_up` и `post_down`. У других серверных профилей могут быть собственные hooks —
их не считайте. Сверьте команды целиком: правильное число строк ещё не доказывает,
что команда скопирована без обрыва.

`-C ... || -I/-A` и `route replace` не создают дубли; post_down проверяет наличие записи перед удалением.
Клиент не удаляет серверные правила, сервер A не удаляет рабочий маршрут клиента.
Нет `iptables -F` или очистки всей таблицы — чужие правила не затрагиваются.
Проверка rule предполагает исключительное владение приоритетом 20800.

`post_down` выполняется при штатной остановке; при SIGKILL или отключении питания
его выполнение не гарантируется. Поэтому post_up допускает оставшиеся записи.
Стандартные FORWARD-правила Qeli убирает сам; собственный default сервера не заменяется.

## 4. Запустить и проверить

**Зачем:** проверить конфиги, поднять A → B и убедиться, что клиенты выходят через B.

Проверьте на A/B (для User=qeli перед qeli добавьте `sudo -u qeli`):

```sh
qeli check-config --config /etc/qeli/server.conf
systemctl daemon-reload
```

На A также выполните `qeli check-config --client --config /etc/qeli/clients/upstream.conf`.
При ошибке сначала исправьте конфиг. Запустите `systemctl start qeli` на B, затем на A.

Основной Qeli на A сам найдёт профиль `upstream` и запустит клиент.
Если веб-панель включена, во вкладке **Клиент** он отображается с отметкой автозапуска
и статусом подключения. Без панели используйте проверки ниже и клиентский лог.
Не запускайте второй экземпляр `qeli client` вручную. После подключения:

- На A: `ip -4 rule show` — одна запись 20800 с `iif qeli-in lookup 208`;
  `ip -4 route show table 208` — default через qeli-out с metric 10 и blackhole с metric 32767.
- На B: `ip route get 10.80.1.10` — через qeli-b.
- На клиенте: подключение к `A_IP:4553`, пользователь c и публичный ключ **A**.

Для конечного клиента C используйте отдельный файл (его пароль и ключ — от **A**, не от B):

```ini
[qeli]
server = A_IP:4553
proto = tcp
mode = fake-tls
user = c
pass = C_PASSWORD
key = A_PUBLIC_KEY
dev = qeli-c
gateway = true
forward = false
kill_switch = true
ipv6 = off
allow_ipv6_leak = false
dns = tunnel
dns_servers = 1.1.1.1
reconnect = true
```

У этого клиента нет пользовательских сетевых hooks: маршруты и DNS настраивает Qeli.
Вместо 1.1.1.1 можно указать свой внешний резолвер. DNS-прокси A не используйте.
На Linux `dns=tunnel` требует рабочего systemd-resolved — см. [CONFIG](../manuals/CONFIG.md).

Проверьте отдельно на A, B и конечном клиенте:

```sh
curl -4 -fsS --max-time 10 --noproxy '*' https://api.ipify.org
```

У A должен остаться IP A, у B — IP B, у клиента — IP B.

## Автозагрузка и восстановление связи

Для A → B используется **встроенный менеджер клиентов Qeli**, тот же, которым управляет
панель, а не отдельная клиентская служба. Работа HTTP-панели для автозапуска не требуется.
На A и B включите автозапуск уже установленного основного Qeli:

```sh
systemctl enable qeli
```

При загрузке A менеджер Qeli читает `/etc/qeli/clients/*.conf` и запускает профиль
с `autostart=true`. Это тот же флаг, что и галочка «подключать автоматически» в панели.
Один основной Qeli управляет и сервером, и дочерним клиентом A → B.

**Важно для конфигов с hooks:** `post_up/post_down` и `autostart=true` задайте локально
в файле из шага 3. Панель/API намеренно не позволяют сохранять shell-команды.
Панель может показывать этот профиль и запускать/останавливать его; не пересохраняйте
его через форму, которая запрещает hooks.

После успешного пересоздания TUN команда `route replace` вернёт рабочий маршрут в table 208.
Повторная обработка того же поколения и восстановление carrier с сохранённым TUN
не вызывают hook лишний раз. Post_down остаётся командой терминальной остановки,
а не парной командой на каждый reconnect. Post_up должен быть идемпотентным.

Если A загрузился до B, клиент с `reconnect=true` будет повторять подключение;
после появления B подключение и маршрут восстановятся при поведении из
[блока версий](#поддерживаемая-версия).
Собственные маршруты и DNS серверов этим клиентом не заменяются.

Галочка автозапуска не является watchdog для аварийно завершившегося процесса.
В таком случае нажмите **Connect** в панели; после reboot запуск снова выполнит основной Qeli.
Если маршрут вручную удалили при живом TUN, используйте **Disconnect → Connect**;
если удалили NAT B — `systemctl restart qeli` на B (перезапустит его профили).

Проверяйте статус во вкладке **Клиент**, клиентский лог —
`/var/log/qeli/client-upstream.log`, серверный — `journalctl -u qeli -n 100 --no-pager`.
После восстановления повторите проверки шага 4.

### Откат запуска от root

На A сначала остановите профиль A → B и отключите его автозапуск. Затем на каждом
изменённом сервере выполните `systemctl stop qeli` (это остановит все его профили). Уберите из конфигов
добавленные hooks или восстановите прежние конфиги. Если chain.conf существовал до
настройки, верните его резервную копию. Если файл создали только по этой инструкции,
отключите **только его**, сохранив для возможного возврата:

```sh
mv -n -- /etc/systemd/system/qeli.service.d/chain.conf /etc/systemd/system/qeli.service.d/chain.conf.disabled
systemctl daemon-reload
systemctl show qeli -p User -p Group
```

Не используйте `systemctl revert qeli`: он может удалить чужие overrides.
Если chain.conf.disabled уже есть, `mv -n` ничего не заменит — сначала проверьте оба файла.
Убедитесь, что User/Group вернулись к исходным значениям (в штатном пакете qeli/qeli).
Восстановите прежних владельцев/права изменённых конфигов, ключей и каталогов из своей
резервной копии: одной смены User недостаточно. После проверки прежнего конфига выполните
`systemctl start qeli` и проверьте `journalctl -u qeli -n 100 --no-pager`.

## Минимальный чек-лист

- [ ] На A/B проверен `qeli --version`; версия соответствует [условиям в начале](#поддерживаемая-версия), выбран вариант запуска.
- [ ] Все значения таблицы подставлены; B_WAN заменён в post_up и post_down, hooks не разбиты на строки.
- [ ] На B прошёл `qeli check-config --config /etc/qeli/server.conf`.
- [ ] На A прошли server check-config и `qeli check-config --client --config /etc/qeli/clients/upstream.conf` (для User=qeli — с `sudo -u qeli` на обоих серверах).
- [ ] `systemctl start qeli` выполнен сначала на B, затем на A; для загрузки ОС включён `systemctl enable qeli`.
- [ ] На A одна rule 20800 и рабочий default qeli-out в table 208; на B маршрут к 10.80.1.10 указывает qeli-b.
- [ ] `curl` из шага 4 выполнен на A/B/C: A сохранил IP A, B — IP B, C показывает IP B.

[Отчёт испытаний кандидата](../reports/CHAINED-SERVERS-084-2026-10-30.md) ·
[Предыдущие проверки](../reports/CHAINED-SERVERS-HOOKS-2026-10-30.md) ·
[Условия по версии](#поддерживаемая-версия).
