# Qeli — установка и начало работы (пошагово)

Полное руководство «с нуля»: от поднятия сервера до заведения пользователей с
маршрутами и подключения первого клиента — **и через CLI, и через веб-панель**.

Рассчитано на чистый **Linux-сервер** (Debian/Ubuntu) с root-доступом. Все команды
сервера — от root (или через `sudo`).

> Справочники, на которые опирается этот гайд:
> [CONFIG.md](CONFIG.md) — все ключи конфига · [PANEL.md](PANEL.md) — веб-панель ·
> примеры конфигов: [`server.conf`](../../qeli/config/server.conf) ·
> [`users.conf`](../../qeli/config/users.conf) · [`client.conf`](../../qeli/config/client.conf).

## Содержание
1. [Что понадобится](#1-что-понадобится)
2. [Установка сервера](#2-установка-сервера)
3. [Первичная настройка сервера (CLI)](#3-первичная-настройка-сервера-cli)
4. [Запуск и проверка](#4-запуск-и-проверка)
5. [Full-tunnel: NAT и форвардинг на уровне ОС](#5-full-tunnel-nat-и-форвардинг-на-уровне-ос)
6. [Заведение пользователей (CLI)](#6-заведение-пользователей-cli)
7. [Маршруты: split/full-tunnel, pushed-маршруты, ACL, статический IP](#7-маршруты)
8. [Подключение клиента](#8-подключение-клиента)
9. [То же самое через веб-панель](#9-то-же-самое-через-веб-панель)
10. [Живое управление и диагностика](#10-живое-управление-и-диагностика)
11. [Wire-режимы — какой выбрать](#11-wire-режимы--какой-выбрать)
12. [Частые проблемы](#12-частые-проблемы)
13. [Полное удаление qeli](#13-полное-удаление-qeli)

---

## 1. Что понадобится

- **Сервер** Linux x86-64 (Debian 11+/Ubuntu 20.04+), root, публичный IP.
- **Открытый порт** под VPN (по умолчанию TCP `443`) и, если включаете панель, её
  порт (по умолчанию `8080`). В облачном файрволе/Security Group откройте их.
- Ядро с поддержкой **TUN** (`/dev/net/tun` — есть почти везде; на некоторых VPS
  включается в панели провайдера).
- Пакеты `iproute2`, `iptables` (тянутся зависимостью .deb).
- **Клиент**: телефон (Android), десктоп (Windows/macOS) или Linux-CLI.

Один бинарь `qeli` совмещает обе роли: `qeli server` и `qeli client`.

---

## 2. Установка сервера

> ⚡ **Самый быстрый путь (всё за одну команду).** В корне репозитория есть готовый
> установщик [`install-reality-server.sh`](../../install-reality-server.sh): ставит
> зависимости и последний `.deb`, **спрашивает профиль** (reality-tls по умолчанию или
> fake-tls) **и порт** (по умолчанию :443), поднимает его с full-tunnel NAT и заводит
> **5 пользователей** с готовыми `qeli://`-строками в `/etc/qeli/client-links/`.
> Запуск от root: `./install-reality-server.sh <публичный-IP-или-домен>` (или
> `sudo ./install-reality-server.sh …`, если `sudo` установлен — он не обязателен и не
> ставится). Для неинтерактивной установки (или `curl … | bash`) задайте выбор заранее:
> `QELI_PROFILE=fake-tls QELI_PORT=8443 ./install-reality-server.sh <IP>`. Дальше
> остаётся только вставить строку подключения в приложение. Ручная установка по шагам —
> ниже.

### Вариант A — .deb-пакет (рекомендуется)

```bash
# из вкладки GitHub Releases или собственной сборки (см. ниже)
sudo apt install ./qeli_0.7.11_amd64.deb
```

Пакет:
- кладёт бинарь в `/usr/bin/qeli` и вешает на него `cap_net_admin` (работает без root в systemd);
- создаёт системного пользователя `qeli`, каталоги `/etc/qeli`, `/var/log/qeli`, `/var/lib/qeli`;
- ставит **примеры** `/etc/qeli/{server,users,client}.conf.example` (рабочие конфиги вы создаёте сами — шаг 3);
- ставит systemd-юнит `qeli.service` (`ExecStart=/usr/bin/qeli server --config /etc/qeli/server.conf`).

### Вариант B — сборка из исходников

Нужен Rust (stable). В корне репозитория:

```bash
cd qeli
cargo build --release          # бинарь → qeli/target/release/qeli

# (опц.) собрать свой .deb из свежего бинаря:
make -C debian deb             # → qeli/debian/qeli_0.7.11_amd64.deb
```

Без пакета можно запускать бинарь напрямую (см. шаг 4), но тогда systemd-юнит,
пользователя и каталоги создаёте вручную.

### Вариант C — Docker

**Мульти-арч** образ (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) несёт **обе роли**
(`qeli server` и `qeli client`) со всеми рантайм-зависимостями внутри (`iproute2`,
`iptables`, CA-сертификаты) — работает на любом Linux-хосте и в контейнерных рантаймах
роутеров (MikroTik RouterOS v7, OpenWrt). Контейнеру нужны `NET_ADMIN` +
`/dev/net/tun`; готовый `docker-compose.yml` (сервер + опц. gateway-клиент) в комплекте.
Сборка/запуск, пример compose и нюансы:

> 🐳 **[release/docker/README.md](../../release/docker/README.md)**

С Docker остальные шаги установки/systemd из этого гайда можно пропустить; управление
профилями и пользователями ниже (CLI или веб-панель) внутри контейнера работает так же.

---

## 3. Первичная настройка сервера (CLI)

### 3.1. Создать рабочий конфиг из примера

```bash
sudo cp /etc/qeli/server.conf.example /etc/qeli/server.conf
sudo nano /etc/qeli/server.conf
```

Формат — **flat-INI**. Файл-пример **исчерпывающий**: каждый ключ перечислен со
значением по умолчанию и пояснением; любой удалённый ключ берёт дефолт. Для старта
достаточно проверить несколько полей в секции `[profile:tcp]`.

### 3.2. Минимально нужные поля профиля

```ini
[profile:tcp]
enabled = true

# на чём слушаем (порт должен быть открыт в файрволе)
bind.address = 0.0.0.0
bind.port    = 443
bind.transport = tcp            # tcp | udp

# виртуальная сеть туннеля
tun.address  = 10.0.0.1         # адрес сервера внутри туннеля (шлюз)
tun.netmask  = 255.255.255.0
tun.mtu      = 1400             # пушится клиентам; для прод-TCP см. §12 и CONFIG.md

# пул адресов, которые раздаются клиентам
pool.cidr    = 10.0.0.0/24
pool.exclude = 10.0.0.1         # никогда не выдавать шлюз

# режим маскировки на проводе (см. §11)
obf.mode = fake-tls
```

Остальное (DNS-прокси, padding, heartbeat, лимиты) уже задано разумными дефолтами в
примере. Полное описание каждого ключа — [CONFIG.md](CONFIG.md).

> **Несколько профилей.** Можно держать рядом второй интерфейс, например UDP на
> `:1443` — добавьте секцию `[profile:udp]` (свой `tun.name`/`tun.address`/`pool.cidr`/
> `bind.port`/`bind.transport = udp`). У каждого профиля — свой identity-ключ и свой пул.
> Готовый шаблон **со всеми 9 режимами сразу** (reality-tls на :443, остальные на
> 8443–8450) — `/etc/qeli/server-multiprofile.conf.example` (его ставит .deb;
> в исходниках — [`config/server-multiprofile.conf`](../../qeli/config/server-multiprofile.conf)):
> скопируйте его в `server.conf`, оставьте нужные профили, замените `CHANGEME`-ключи.

### 3.3. Пользователи: где они живут

По умолчанию пользователи живут в **отдельном файле** — `auth.users_file` (по умолчанию
`/etc/qeli/users.conf`). Примеры конфигов идут **без** инлайн-юзеров; заводите их командой
`qeli add-client` (шаг 6) — она допишет их в этот файл. Больше ничего делать не нужно.

> Можно вместо этого держать пользователей инлайн в `server.conf` секциями `[user:*]`,
> но тогда `auth.users_file` **игнорируется целиком** (инлайн имеет приоритет) — так что
> не задавайте оба, иначе сервер выдаёт предупреждение, а файл молча отбрасывается.
> Рекомендуемый вариант по умолчанию — отдельный файл; `[user:*]` в `server.conf` не держите.

---

## 4. Запуск и проверка

```bash
sudo systemctl enable --now qeli         # запустить + автозапуск при бутe
systemctl status qeli                    # должно быть active (running)
journalctl -u qeli -f                     # живой лог (Ctrl-C — выйти)
```

В логе при старте должны появиться `Profile 'tcp': TUN vpn0 is up`,
`listening on 0.0.0.0:443`, и строка с публичным ключом профиля.

### Получить identity-ключ сервера (для пиннинга на клиенте)

```bash
sudo qeli show-identity --config /etc/qeli/server.conf
```

```
PROFILE   BIND                SERVER PUBLIC KEY (pin on client)
tcp       tcp://0.0.0.0:443   33f399e6d9b8a31a41e5ffa8b1e1ce457f10d8bbf07c145377fcb7917d532450
```

Этот hex-ключ клиент **пинит** (`key = …`). Команда создаёт ключи профилей, если их
ещё нет (`/etc/qeli/identity/<profile>.key`).

> **Почему пиннинг обязателен.** По умолчанию включён **H-1**
> (`auth.bind_static_to_session = true`): сессионные ключи привязаны к статической
> личности сервера, поэтому клиент **обязан** пинить реальный ключ (иначе сервер его
> отвергнет). Ссылка `qeli://`, выданная командой `add-client --link` (шаг 6), уже
> содержит этот ключ — пользователю ничего вручную вписывать не нужно.

После рестарта сервиса меняйте конфиг и применяйте: `sudo systemctl restart qeli`.

---

## 5. Full-tunnel: NAT (масштабируется автоматически)

Нужно, только если хотите гнать **весь интернет-трафик клиента** через сервер
(full-tunnel / «выходная нода»). Для split-tunnel (доступ лишь к подсети туннеля и
ресурсам за сервером) — пропустите.

Достаточно включить один тумблер в профиле — сервер **сам** через `iptables`
включит IP-форвардинг и поставит MASQUERADE + FORWARD + MSS-clamp, а при остановке
снимет правила:

```ini
# в [profile:tcp]
routing.nat.enabled  = true
# WAN-интерфейс наружу. Оставьте пустым/по умолчанию — определится автоматически
# (ip route get 1.1.1.1); либо задайте явно, напр. ens3.
routing.nat.interface =
```

```bash
sudo systemctl restart qeli      # сервер применит NAT при старте профиля
journalctl -u qeli | grep NAT    # "NAT masquerade active via iptables (10.0.0.0/24 -> ens3)"
sudo iptables-save | grep qeli-nat   # увидеть установленные правила
```

Что именно ставит сервер (правила помечены comment'ом `qeli-nat:<профиль>`, чтобы
снять ровно их при выключении/остановке): `net.ipv4.ip_forward=1`; `-t nat POSTROUTING
-s <pool.cidr> -o <wan> -j MASQUERADE`; две `FORWARD … ACCEPT` (tun↔wan); две
`-t mangle FORWARD … TCPMSS --set-mss (tun.mtu−40)` (защита от PMTU-чёрной дыры).

> ⚠️ **Требуется `iptables`** (пакет `iptables`). У .deb он в зависимостях, так что при
> установке пакетом уже стоит. Если `iptables` **не установлен**, NAT применить нельзя:
> в логе сервера будет `ERROR … NAT requested but NOT applied`, а в **веб-панели**
> (Dashboard) — жёлтый баннер с подсказкой. Поставить: `sudo apt install iptables`.
> Используется только классический `iptables` (не `nft`/`ufw`).

> Прод-тюнинг (BBR, буферы, MTU-probing — заметно ускоряет TCP на мобильных) описан в
> [CONFIG.md → «Тюнинг ОС сервера»](CONFIG.md). Для full-tunnel настоятельно примените.
> Чтобы правила NAT пережили перезагрузку без сервиса qeli, можно дополнительно
> сохранить их (`apt install iptables-persistent`), но обычно qeli ставит их сам при
> старте.

---

## 6. Заведение пользователей (CLI)

### 6.1. Простой пользователь

```bash
sudo qeli add-client alice --password 's3cret'
sudo systemctl restart qeli            # перечитать пользователей
```

Команда Argon2id-хеширует пароль и дописывает секцию `[user:alice]` в users-файл.
Без `--password` сгенерирует случайный и **напечатает его один раз**.

### 6.2. С опциями

```bash
sudo qeli add-client bob \
  --password 'pass123' \
  --static-ip 10.0.0.50 \          # фиксированный IP в туннеле
  --max-sessions 3 \               # сколько устройств одновременно (0 = без лимита)
  --profiles tcp                   # доступ только к профилю tcp (изоляция интерфейсов)
```

| Опция | Назначение |
|---|---|
| `--password <P>` | пароль (иначе случайный, печатается один раз) |
| `--static-ip <IP>` | постоянный адрес в туннеле (иначе из пула) |
| `--max-sessions <N>` | лимит одновременных **устройств** (0 = наследовать группу/без лимита) |
| `--profiles a,b` | разрешённые профили (пусто = все) |
| `--link --host <H[:port]>` | сразу напечатать `qeli://`-ссылку + QR (см. ниже) |
| `--link-profile <P>` | для какого профиля строить ссылку (по умолчанию первый) |

### 6.3. Сразу выдать `qeli://`-ссылку / QR

```bash
sudo qeli add-client carol --password 'pw' --link --host vpn.example.com:443 --link-profile tcp
```

Печатает готовую `qeli://…`-ссылку (с уже **вшитым ключом сервера**, режимом, SNI) и
QR-код в терминале — пользователь сканирует его в мобильном клиенте и подключается в
один тап. Ничего вручную вписывать не нужно.

### 6.4. Тонкая настройка вручную (опционально)

Любые поля можно дописать прямо в секцию `[user:*]` (см. комментарии в
[`users.conf`](../../qeli/config/users.conf)):

```ini
[user:bob]
password_hash = $argon2id$v=19$m=...$...   # ставит add-client
enabled = true
static_ip = 10.0.0.50
max_sessions = 3
profiles = tcp
allowed_networks = 10.0.0.0/24, 192.168.1.0/24   # ACL: куда этому юзеру можно (пусто = куда угодно)
bandwidth.limit_mbps = 50                         # лимит скорости (0 = без лимита)
bandwidth.burst_mbps = 100
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100  # персональный pushed-маршрут (повторяемо)
group = premium                                    # унаследовать из [group:premium]
```

Группы — шаблоны для повторяющихся настроек:

```ini
[group:premium]
bandwidth_limit_mbps = 100
max_sessions = 5
allowed_networks = 0.0.0.0/0
```

После правок users-файла — `sudo systemctl restart qeli` (или примените живой командой,
§10, без перезапуска).

---

## 7. Маршруты

### 7.1. Split-tunnel (по умолчанию)

Клиент по умолчанию заворачивает в туннель только **подсеть туннеля** (`pool.cidr`).
Остальной трафик идёт мимо VPN. Ничего настраивать на сервере не нужно.

### 7.2. Full-tunnel (весь трафик через сервер)

Включается **на клиенте** (`gateway = true` в `client.conf` / тумблер в приложении), а
на сервере требует NAT+форвардинг из **§5**. Тогда весь интернет клиента выходит с IP
сервера.

### 7.3. Pushed-маршруты на уровне профиля (всем клиентам профиля)

Чтобы открыть клиентам доступ к сети **за сервером** (напр. офисной `192.168.50.0/24`),
сервер «пушит» маршрут — клиент сам добавит его в таблицу при подключении:

```ini
# в [profile:tcp] — повторяемо
route = 192.168.50.0/24 gateway=10.0.0.1 metric=100
```

`gateway` — адрес сервера в туннеле (`tun.address`). `metric` — приоритет (опц.).
Дополнительно `routing.forward_private = true` форвардит RFC1918-сети за сервером.

### 7.4. Персональные маршруты (конкретному пользователю)

Тот же синтаксис, но в секции `[user:*]` — пушится только этому пользователю:

```ini
[user:bob]
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100
```

### 7.5. ACL назначения (`allowed_networks`)

Ограничивает, **куда** пользователю можно ходить через туннель (whitelist
dst-CIDR). Пусто/нет ключа = без ограничений:

```ini
[user:bob]
allowed_networks = 10.0.0.0/24, 192.168.1.0/24
```

### 7.6. Клиент-клиент и статические адреса

```ini
# в [profile:tcp]
routing.client_to_client = true      # разрешить клиентам видеть друг друга в туннеле
pool.reservation.alice = 10.0.0.100  # закрепить IP за юзером (альтернатива user.static_ip)
```

### 7.7. DNS-через-туннель

По умолчанию сервер поднимает DNS-прокси на `tun.address:53` и пушит его клиентам:

```ini
# в [profile:tcp]
dns.enabled  = true
dns.upstream = 1.1.1.1, 8.8.8.8
# dns.blocklist = ads.example.com, track.example.com   # отдавать 0.0.0.0 (блок рекламы)
```

При `dns.enabled = false` сервер DNS не пушит — клиент оставляет свои резолверы.

---

## 8. Подключение клиента

### 8.1. Мобильный (Android) и десктоп (Windows/macOS)

1. На сервере выдайте ссылку: `qeli add-client <user> --link --host <публичный-host:порт>`
   (§6.3) — получите `qeli://…` + QR.
2. В приложении: **Add profile → Scan QR** (или **Paste qeli:// link**) → профиль
   появится со всеми параметрами и **запиненным ключом сервера**.
3. Нажмите кольцо подключения. Готово.

Full-tunnel и «маршрутизировать локальные сети» переключаются тумблерами в приложении.

> ⚠️ **macOS — первый запуск.** Приложение подписано **ad-hoc** (не нотаризовано Apple),
> поэтому Gatekeeper его блокирует и оно **не откроется** двойным кликом. Один раз снимите
> карантин в Терминале:
> ```bash
> xattr -cr /Applications/Qeli.app
> ```
> (см. [qeli-mac/README.md](../../qeli-mac/README.md)).

### 8.2. Linux CLI-клиент

```bash
sudo cp /etc/qeli/client.conf.example /etc/qeli/client.conf
sudo nano /etc/qeli/client.conf
```

Минимум (см. [`client.conf`](../../qeli/config/client.conf) — описан каждый ключ):

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = alice
pass   = s3cret
key    = 33f399e6…d532450     # из `qeli show-identity` (ОБЯЗАТЕЛЕН при H-1)
mode   = fake-tls             # должен совпадать с obf.mode профиля
sni    = www.cloudflare.com

# локальная маршрутизация (в qeli://-ссылке НЕ передаётся — только в файле):
gateway     = false           # true = full-tunnel (весь трафик через VPN)
route_local = false           # также заворачивать приватные сети + server-pushed
kill_switch = false           # блокировать утечки, пока туннель не поднят (full-tunnel)
dns         = tunnel          # tunnel = управлять /etc/resolv.conf; off = не трогать
```

```bash
sudo qeli client --config /etc/qeli/client.conf
```

> При H-1 (дефолт) `key` обязателен и должен быть **реальным** (не нулевым). Если на
> сервере `bind_static_to_session = false`, можно работать по TOFU (нулевой `key`).

---

## 9. То же самое через веб-панель

Полный гайд — [PANEL.md](PANEL.md). Краткий старт:

### 9.1. Включить панель

```bash
# задать админ-пароль (генерирует/хеширует, прописывает в [web], включает панель)
sudo qeli set-web-password                    # случайный пароль, печатается один раз
# или свой:  sudo qeli set-web-password --password 'PANELPASS'
```

Добейте секцию `[web]` для доступа по внешнему IP и перезапустите:

```ini
[web]
enabled = true
bind = 0.0.0.0            # или 127.0.0.1 для доступа только по SSH-туннелю
port = 8080
tls  = true              # встроенный HTTPS (self-signed авто; браузер предупредит 1 раз)
# allowed_ips = 203.0.113.4        # (рекоменд.) свой IP в белый список
# public_host = vpn.example.com    # дефолтный хост для share-ссылок
```

```bash
sudo systemctl restart qeli
```

> **Fail-closed:** на не-loopback `bind` с пустым `password_hash` панель не стартует
> (VPN `:443` при этом работает — это отдельный процесс). Откройте порт `8080` в файрволе.

### 9.2. Пользоваться

Откройте `https://<bind>:8080`, войдите как `admin`.

- **Dashboard → «Быстрый старт»** — плитки режимов (REALITY / HTTPS-fake-tls /
  Obfuscated / QUIC): один клик создаёт готовый профиль (TUN/NAT/DNS/пул/обфускация),
  применяет и перезапускает сервер.
- **Config** — все поля профиля одной страницей (Bind/TUN/Pool/Routing/DNS/Obfuscation/
  Performance), вкл. pushed-маршруты и NAT; вкладка **Global** — identity-ключи (показ +
  **Rotate**), Web UI, H-1. Сохранение: **Save to Disk** или **Apply & Restart**.
- **Users** — создать пользователя (пароль **открытым текстом** — хешируется сервером),
  задать bandwidth/static-IP/группу/max-sessions/**разрешённые профили**/allowed-networks/
  **персональные маршруты**. Группы — шаблоны.
- **Share / QR** у пользователя — выдаёт `qeli://`-ссылку + QR **без ввода пароля**
  (сервер хранит обратимо-зашифрованную копию; пароль не меняется).

### 9.3. Подключение К другим серверам (вкладка Client)

Панель умеет не только **раздавать** VPN, но и **сама подключаться** к другим qeli-серверам
(этот бокс становится клиентом — релеем, или просто управляемым клиентом). Вкладка **Client**:

- **Добавить профиль** — тремя способами:
  - **Import qeli:// link** — вставить `qeli://`-строку, которую вам дал админ сервера;
  - **Add manually** — форма (server/user/pass/key/mode/sni/rsid/obfs_key, QUIC для UDP,
    split/full-tunnel);
  - **Paste INI config** / переключатель **Raw INI** — полный клиентский INI (любой ключ:
    `dev`/`mtu`/`dns`/`kill_switch`/`bind_static`/`[logging]`…).
- **Каждый профиль управляется НЕЗАВИСИМО.** Создание профиля его **не подключает** — он
  лежит в статусе *Disconnected*. У каждого своя кнопка **Connect** / **Disconnect**; жмёте
  только на нужные. Статус (подключён + хвост лога) обновляется сам.
- **Несколько подключений одновременно** — поднимайте сколько нужно: каждому профилю
  **автоматически выдаётся свой TUN-интерфейс** (`vpn0`/`vpn1`/…, виден в списке), так что
  туннели не конфликтуют. К одному серверу — заведите несколько профилей (один тоннель на
  профиль). Любой режим, не только reality-tls.
- ⚠️ **Full-tunnel и несколько туннелей.** Маршрут по умолчанию в системе один, поэтому
  **несколько одновременных full-tunnel конфликтуют** — для мульти-релея используйте
  split-tunnel (и разные пул-подсети на серверах), либо держите full-tunnel по одному.
  Полный заворот на сервере-боксе может отрезать саму панель/SSH — включайте осознанно.
- **Хранилище:** профили лежат в `/etc/qeli/clients/<name>.conf` (тот же flat-INI). Это
  значит, то же самое можно сделать и **файлами**: положить конфиги туда и запускать
  `qeli client --config /etc/qeli/clients/<name>.conf` (для нескольких — разный `dev` в
  каждом файле). Готовый пример клиента — [`client-reality.conf`](../../qeli/config/client-reality.conf)
  и [`client.conf`](../../qeli/config/client.conf) (все режимы и ключи).
- **Автозапуск при загрузке.** У каждого профиля есть флаг **autostart**: помеченные
  профили `qeli` (supervisor + панель) поднимает сам при старте сервиса — после
  `reboot`/`systemctl restart qeli` нужные тоннели встают без ручного Connect. Задаётся
  **двумя способами, равнозначно**:
  - в панели — галочка **«Auto-connect this profile when the server/panel starts»** в форме
    профиля (в списке такой профиль помечен значком `↻ autostart`);
  - в файле — строкой `autostart = true` в секции `[qeli]` файла
    `/etc/qeli/clients/<name>.conf` (правьте руками — эффект тот же, что и галочка).

  Флаг **независим для каждого профиля** — автозапускаются только помеченные, остальные
  остаются *Disconnected* до явного Connect. Снять автозапуск — снять галочку (или убрать
  строку из файла).

---

## 10. Живое управление и диагностика

Команды через control-сокет — **без перезапуска** сервера
(`--socket`, по умолчанию `/var/run/qeli/control.sock`):

```bash
sudo qeli list-clients               # кто сейчас подключён
sudo qeli kick alice                 # отключить сессии пользователя
sudo qeli disable-user bob           # заблокировать (кик + запрет реконнекта)
sudo qeli enable-user bob            # снова разрешить
sudo qeli set-bandwidth alice 50     # лимит Мбит/с (0 = без лимита)
sudo qeli show-routes alice          # маршруты пользователя
sudo qeli rotate-identity tcp        # сменить ключ профиля (клиентам обновить key=)
sudo qeli list-blocked               # IP, залоченные брутфорс-защитой (неверный пароль)
sudo qeli unblock 1.2.3.4            # снять блок с адреса (или --all — со всех)
```

Диагностика:

```bash
journalctl -u qeli -f                          # лог сервера
sudo qeli list-clients                          # активные сессии + выданные IP
ping 10.0.0.2                                   # пинг клиента из туннеля (с сервера)
ss -tulnp | grep qeli                           # слушает ли :443 / :8080
```

На клиенте проверьте, что появился интерфейс `vpn0` и маршруты (`ip a`, `ip route`).

---

## 11. Wire-режимы — какой выбрать

Задаётся `obf.mode` на сервере и `mode` на клиенте (должны совпадать):

| Режим | Когда |
|---|---|
| `fake-tls` | **по умолчанию.** Мимикрия под TLS 1.3, против пассивного/сигнатурного DPI. Хороший баланс. |
| `reality-tls` | максимальная маскировка: туннель **внутри настоящего TLS 1.3** с одолженным сертом реального сайта (паритет Xray-REALITY). Держит и активное зондирование. Требует `key` + `reality_sid` + `sni`; чуть медленнее. |
| `obfs` | ChaCha20-обфускация всего потока + WS-fronting. Нужен общий `obfs_key`. TCP-only. |
| `plain` | без маскировки — голый шифрованный туннель (макс. скорость, TCP-only). Для доверенных сетей. |
| QUIC-masking | для **UDP**-профилей (`obf.quic.enabled = true`), маскирует под QUIC. |

Подробное сравнение, REALITY-настройка (short_ids, handrolled), multipath-бондинг —
в [CONFIG.md](CONFIG.md). Бенчмарки всех режимов — [BENCHMARK.md](BENCHMARK.md).

---

## 12. Частые проблемы

- **Клиент проходит «identity verified», но сразу отваливается / `AUTH FAIL … not found`.**
  Пользователь не там, где сервер его ищет: в `server.conf` есть инлайн `[user:*]` →
  `users_file` игнорируется (см. §3.3). Держите пользователей в одном месте.
- **Подключается, но интернета нет (full-tunnel).** Проверьте, что в профиле
  `routing.nat.enabled = true` и что на сервере установлен **`iptables`** (`apt install
  iptables`) — без него сервер не сможет поставить MASQUERADE (в логе `NAT requested but
  NOT applied`, в панели — жёлтый баннер). Проверка: `iptables-save | grep qeli-nat`
  должно показывать правила; `journalctl -u qeli | grep NAT` — строку «NAT masquerade
  active». Если WAN-интерфейс определился неверно — задайте `routing.nat.interface` явно.
- **Загрузка зависает / рвётся под нагрузкой (TCP).** Не сделан MSS-clamp под MTU
  туннеля (PMTU-чёрная дыра) — правило `TCPMSS` из §5; для прода ещё BBR (CONFIG.md).
- **Сервер отвергает клиента без понятной причины.** Включён H-1 (дефолт), а клиент не
  пинит ключ. Впишите реальный `key` (из `qeli show-identity`) — проще всего выдать
  профиль ссылкой `add-client --link` (§6.3).
- **Не пускает после нескольких неверных паролей.** Сработал анти-брутфорс по
  source-IP (`auth.brute_force.*`). Подождите окно блокировки или перезапустите сервер
  (`systemctl restart qeli` сбрасывает счётчики в памяти).
- **Веб-панель не стартует.** Fail-closed: на публичном `bind` пуст `password_hash` —
  задайте `qeli set-web-password` (§9.1). VPN `:443` при этом не страдает.
- **403 на любое сохранение в панели за доменом/прокси.** Добавьте домен в
  `web.allowed_origins` (CSRF same-origin); свой IP — в `web.allowed_ips`, иначе
  заблокируете сами себя.

---

## 13. Полное удаление qeli

По ролям — удаляйте только то, что ставили. `<ПОРТ>` ниже = порт вашего профиля (напр. `443`).

### 13.1. Сервер (Linux)

```bash
# 1. Остановить и отключить сервис
sudo systemctl disable --now qeli

# 2a. Ставили из .deb → снять пакет (удалит сервис, /usr/bin/qeli, polkit-правило).
#     purge удалит и conffiles (примеры конфигов):
sudo apt purge qeli

# 2b. Ставили вручную/бинарём → снять руками:
sudo rm -f /usr/bin/qeli /usr/local/bin/qeli
sudo rm -f /etc/systemd/system/qeli.service && sudo systemctl daemon-reload

# 3. Конфиги, ключи идентичности, пользователи, выданные ссылки.
#    ⚠️  identity-ключ пропадёт → клиентам с пиннингом (reality-tls / H-1) придётся
#    ПЕРЕВЫДАТЬ конфиги. Хотите сохранить: sudo cp -a /etc/qeli /root/qeli-backup
sudo rm -rf /etc/qeli

# 4. Состояние, логи, runtime
sudo rm -rf /var/lib/qeli /var/log/qeli /run/qeli

# 5. Системный пользователь сервиса
sudo deluser --system qeli 2>/dev/null; sudo delgroup qeli 2>/dev/null; true
```

Дополнительно — **если ставили через `install-reality-server.sh`** (он трогает ОС):

```bash
# sysctl-тюнинг (BBR / буферы / PMTU)
sudo rm -f /etc/sysctl.d/99-qeli-perf.conf && sudo sysctl --system >/dev/null

# iptables: СВОИ NAT/MASQUERADE-правила qeli снимает сам при чистой остановке (шаг 1).
# Установщик дополнительно ставит MSS-clamp на порт и мог сохранить правила
# (netfilter-persistent). Посмотреть остатки и снять нужное:
sudo iptables-save | grep -iE 'qeli-nat|MASQUERADE|TCPMSS|--dport <ПОРТ>'
sudo iptables -t mangle -D OUTPUT -p tcp --dport <ПОРТ> --tcp-flags SYN,RST SYN \
     -j TCPMSS --set-mss 1340 2>/dev/null; true
sudo netfilter-persistent save 2>/dev/null; true
```

> Если правила НЕ сохранялись в `netfilter-persistent` / `/etc/iptables/rules.v4` — они
> исчезнут сами после перезагрузки.

### 13.2. Клиент — Linux (Rust CLI)

Чистая остановка (Ctrl+C) **сама** восстанавливает `/etc/resolv.conf`, снимает
kill-switch / NAT и удаляет tun. Руками — только если клиент **упал**:

```bash
sudo pkill -f 'qeli client'                    # прибить, если висит
# DNS: оригинал лежит в /var/lib/qeli/dns-backup.json — проще всего запустить и ЧИСТО
#      остановить клиент (он восстановит resolv.conf сам), либо вернуть из бэкапа вручную.
sudo iptables -F 2>/dev/null; true             # снять kill-switch (если был kill_switch=true)
sudo ip link del vpn0 2>/dev/null; true        # tun — имя из `dev = …`
# Удалить бинарь, конфиг, состояние:
sudo rm -f /usr/local/bin/qeli
rm -f ~/qeli-client.conf                        # ваш путь к клиентскому конфигу
sudo rm -rf /var/lib/qeli                       # device-id + dns-backup
```

> На **совмещённом** хосте (сервер + клиент рядом) `/var/lib/qeli` общий — не удаляйте
> его, пока не снесли сервер.

### 13.3. Десктоп — Windows / macOS (GUI)

- **Windows:** закрыть приложение → удалить `QeliWin` (папку portable-сборки или через
  «Приложения и возможности»). Wintun-адаптер эфемерный — создаётся и удаляется на каждый
  сеанс, после «Отключить» в системе не остаётся; маршруты/DNS восстанавливаются там же.
  Данные (профили / настройки / device-id) — удалить папки:
  `%AppData%\QeliWin`, `%LocalAppData%\qeli`, `%ProgramData%\QeliWin`.
- **macOS:** закрыть → удалить `QeliMac.app`. `utun` управляется ядром — исчезает при
  отключении. Данные — удалить `~/.local/share/qeli`; если включали автозапуск — снять
  LaunchAgent из `~/Library/LaunchAgents` (файл с `qeli` в имени).

### 13.4. Android

Настройки → Приложения → **qeli** → Удалить. Сносит всё: профили (в шифрованном хранилище),
device-id, виджет, QS-плитку, автозапуск на буте. Для полной чистоты — отозвать VPN-согласие
и выключить Always-on VPN (если включали): Настройки → Сеть/Подключения → VPN → qeli.

### 13.5. Роутеры

**OpenWrt:**
```sh
/etc/init.d/qeli stop; /etc/init.d/qeli disable
opkg remove luci-app-qeli qeli
rm -f /etc/config/qeli /etc/init.d/qeli /usr/bin/qeli-client
# удалить firewall-зону qeli, которую создавал uci-default при установке:
sec=$(uci show firewall | awk -F. "/\.name='qeli'/{print \$2; exit}")
[ -n "$sec" ] && uci delete firewall.$sec && uci commit firewall && /etc/init.d/firewall restart
```

**Keenetic:** остановить и удалить init-скрипт, бинарь и конфиг — обратно шагам установки
(см. `docs/*/KEENETIC-DEPLOY.md`).

### 13.6. Docker

```bash
docker compose -f release/docker/docker-compose.yml down -v   # контейнер + volume
docker rmi qeli:latest                                        # образ
rm -rf ./data                                                 # смонтированный /etc/qeli (конфиги + ключи)
```

---

> Нашли неточность или есть вопрос по настройке — заводите issue/discussion в
> репозитории. Полная карта документации — в [README](README.md).
