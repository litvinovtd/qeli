# qeli-client на Keenetic — пошаговый деплой

Развёртывание qeli-VPN-клиента на роутере Keenetic (Entware) как шлюза для всего LAN.
Архитектура и обоснование порта — [KEENETIC-PORT.md](KEENETIC-PORT.md). Файлы бандла —
в `release/keenetic/`.

> 🛜 **У тебя OpenWrt?** Нативный OpenWrt-клиент (procd-сервис + UCI-конфиг + LuCI-страница)
> — **в разработке**. Он использует то же клиентское ядро, что и здесь, поэтому
> наследует все фиксы автоматически — iptables kill-switch и фрагментацию UDP-хендшейка,
> которая чинит UDP на LTE/CGNAT-WAN.

> ⚠️ Скрипты бандла — **шаблоны**, на живом Кинетике не тестировались. Команды ниже
> универсальны; имена интерфейсов и взаимодействие с firewall KeeneticOS зависят от
> модели и версии прошивки — проверяй по месту.

---

## Предусловия

- На роутере установлен **Entware** (пакетный менеджер `opkg`, каталог `/opt`).
- Включён **SSH** и есть доступ к шеллу роутера.
- Включён компонент **VPN** в KeeneticOS (любой из WireGuard/OpenVPN/IPsec) — он
  обеспечивает наличие `/dev/net/tun`. Добавляется в веб-морде: *Управление → Общие
  настройки → Изменить набор компонентов*.
- Есть рабочий **сервер qeli** с профилем и заведённым для роутера клиентом.

---

## Шаг 0. Разведка роутера (по SSH на роутер)

```sh
opkg print-architecture | grep -E 'aarch64|mipsel|mips'   # арка пакетов
cat /proc/cpuinfo | grep -E 'cpu model|FPU|system type'   # CPU/FPU
ls -l /dev/net/tun                                         # должен существовать
df -h /opt                                                 # место (нужно ~5-10 МБ)
```

- `mipsel-…` → бинарь `qeli-client-mipsel` (MT7621/7628 и т.п.).
- `aarch64-…` → бинарь `qeli-client-aarch64` (новые ARM-модели).
- Нет `/dev/net/tun` → вернись к предусловиям и включи компонент VPN.

---

## Шаг 1. Собрать бинари (на деве/лабе, не на роутере)

```sh
python scripts/build_keenetic.py
# → release/keenetic/qeli-client-aarch64   (static ARM aarch64)
# → release/keenetic/qeli-client-mipsel    (static-pie MIPS32r2)
```

Можно собрать только нужную арку: `python scripts/build_keenetic.py mipsel`.

---

## Шаг 2. Получить креды клиента от сервера (на сервере qeli)

```sh
# Завести клиента и сразу получить qeli://-ссылку (и пароль — печатается ОДИН раз):
qeli add-client router1 --link --host <публичный_адрес_сервера>

# Публичный ключ сервера для пиннинга (анти-MITM):
qeli show-identity
```

Из ссылки/вывода понадобятся: `server` (host:port), `proto` (tcp/udp), `user`, `pass`,
`key` (server pubkey), `mode` (fake-tls/obfs/plain/…), `sni`.

---

## Шаг 3. Скопировать бандл на роутер (с дева)

```sh
scp -r release/keenetic <user>@<router-ip>:/opt/tmp/keenetic
# <user> — аккаунт роутера с доступом к /opt (обычно admin/root). Альтернатива — USB.
```

---

## Шаг 4. Установка (на роутере)

```sh
cd /opt/tmp/keenetic
sh install-keenetic.sh
```

Скрипт: определит арку → положит нужный бинарь в `/opt/bin/qeli-client`; поставит
`ip-full` и `iptables` (busybox-`ip` Кинетика урезан — нет `tuntap`); проверит
`/dev/net/tun`; разложит `S99qeli` и болванку конфига.

---

## Шаг 5. Заполнить конфиг (на роутере)

```sh
vi /opt/etc/qeli/client.conf
```

Подставь значения из Шага 2. Для роутера-шлюза важны два ключа:

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = router1
pass   = <пароль>
# Пиннинг статического ключа сервера (анти-MITM). Пусто/все нули = TOFU.
key    = <server pubkey из show-identity>
# H-1 (с 0.7.1, ВКЛ по умолчанию): привязка сессионных ключей к статике сервера.
# ДОЛЖНА СОВПАДАТЬ с сервером (у обоих дефолт true). ТРЕБУЕТ реального key. С TOFU-ключом
# (нули) поставь false; с реальным key — оставь по умолчанию (удали строку). Если у клиента
# false, а у сервера дефолт true — коннект упадёт с «decryption failed» после хендшейка.
bind_static = false
# Режим маскировки — должен совпадать с сервером. MIPS: fake-tls | obfs | plain
# (ChaCha20). reality-tls на mipsel очень медленный (двойной AEAD) — только для ARM.
mode   = fake-tls
# SNI для fake-tls (фронт-домен). Для obfs не нужен.
sni    = www.cloudflare.com
# ТОЛЬКО для mode = reality-tls (с 0.7.1 short_id обязателен). reality-tls ТРЕБУЕТ реального key → убери `bind_static = false` (оставь дефолт true), иначе «decryption failed».
# reality_sid = <hex>

# ── Router / шлюз ────────────────────────────────────────────────────────────
# full-tunnel: весь трафик LAN в туннель (+ NAT в S99qeli)
gateway = true
# НЕ трогать резолвер роутера (им владеет прошивка)
dns     = off
# kill_switch: блокировка утечек через iptables (теперь работает на Keenetic, где
# iptables и так есть). На шлюзе firewall делает S99qeli, так что можно оставить выключенным. Дефолт off.
# kill_switch = false

[logging]
level = info
file  = /opt/var/log/qeli-client.log
# метка времени в строке: datetime (дефолт) | rfc3339 | time | epoch | none.
# Здесь лог пишется в свой файл, а не в syslog, поэтому метка нужна; rfc3339
# удобен, если потом сводить этот лог с серверным.
time_format = datetime
```

**H-1 / `bind_static` (важно с 0.7.1):** по умолчанию клиент привязывает сессию к
запиненному статическому ключу сервера. Флаг **должен совпадать на клиенте и сервере**
(у обоих дефолт `true`): при рассинхроне KDF расходится (разные HKDF-соли) и коннект
падает с `Connection error: decryption failed` сразу после `reading server auth proof`.
Два рабочих варианта для роутера:
- **Безопасно (рекомендуется):** впиши реальный `key` (из `qeli show-identity`) и
  оставь `bind_static` по умолчанию (on). TOFU-пин сохраняется в `QELI_KNOWN_HOSTS`
  (в `S99qeli` это `/opt/etc/qeli/known_hosts` — переживает ребут, в отличие от `/var`).
- **TOFU (проще):** `key` = нули и `bind_static = false` — доверие при первом коннекте.
- **`mode = reality-tls`:** реальный `key` + `reality_sid` обязательны (TOFU-нули не
  работают), поэтому `bind_static` тут **обязан быть `true`** — просто убери строку
  `bind_static = false`. Оставленный `false` = гарантированный `decryption failed`.

---

## Шаг 6. Проверить интерфейсы для NAT (на роутере)

```sh
ip a            # найди LAN-бридж (обычно br0) и убедись, что tun будет vpn0
```

Если LAN-бридж не `br0` или tun не `vpn0` — поправь переменные в начале `S99qeli`:

```sh
vi /opt/etc/init.d/S99qeli      # TUN=…, LAN_IF=…, GATEWAY=yes
```

---

## Шаг 7. Запуск

```sh
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log
```

Жди строку `Auth OK, assigned IP: 10.x.x.x` — это успешное подключение к серверу.
Init-скрипт с префиксом `S` Entware запускает **автоматически при загрузке роутера**.

---

## Шаг 8. Проверить туннель

На роутере:

```sh
ip a show vpn0                                  # у tun есть адрес 10.x.x.x
ip route | grep -E 'default|vpn0'               # при gateway=true — default via vpn0
iptables -t nat -L POSTROUTING -n | grep MASQUERADE   # NAT на vpn0 стоит
curl -s https://ifconfig.me ; echo             # внешний IP = адрес VPN-сервера
```

С любого LAN-клиента (телефон/ПК за роутером):

```sh
# внешний IP должен стать адресом VPN-сервера; DNS и сайты открываются
curl -s https://ifconfig.me ; echo
```

---

## Селективный режим (только часть трафика через VPN)

Вместо full-tunnel (`gateway=true`) можно заворачивать лишь нужные адреса:
`gateway = false` в конфиге + `ipset` + `iptables` + DNS-оверрайды на dnsmasq
роутера (подход как у проектов `kvas` / `antizapret` для Keenetic). Это гибче и не
режет скорость на не-VPN трафике, но настройка ручная и вне этого бандла.

---

## OpkgTun — интерфейс в вебморде (KeeneticOS 5.0+)

Опциональный режим: tun отдаётся `ndm` как нативный `OpkgTun`-интерфейс, виден в вебморде
и доступен в «Приоритетах подключений». Это отдельный аддон со своими оговорками (владение
L3, статический IP, ручная регистрация) — вся настройка и разбор в
[`release/keenetic/opkgtun/README.md`](../../release/keenetic/opkgtun/README.md).

## Диагностика

| Симптом | Причина / что делать |
|---|---|
| `нет /dev/net/tun` при старте | Включить компонент VPN в KeeneticOS (предусловия) |
| `ip: ... tuntap` не работает | `opkg install ip-full` (busybox-`ip` урезан) |
| Нет `Auth OK`, `SERVER KEY MISMATCH` | Неверный `key` — сверь с `qeli show-identity` на сервере |
| `decryption failed` сразу после `reading server auth proof` | `bind_static` не совпадает с сервером (у обоих дефолт `true`): убери `bind_static = false` на клиенте (для reality-tls он обязан быть `true`) ИЛИ выстави одинаково на сервере. Также проверь, что версии qeli на роутере и сервере совпадают (`qeli --version`) |
| Нет `Auth OK`, ошибка про `bind_static`/all-zero TOFU | H-1 (0.7.1) ВКЛ по умолчанию: впиши реальный `key` ИЛИ поставь `bind_static = false` для TOFU |
| Нет `Auth OK`, `auth failed` | Неверные `user`/`pass`, либо `mode`/`sni` не совпадают с профилем сервера |
| `kill-switch: iptables is not installed` | Убедись, что `iptables` в PATH (на Keenetic он есть); иначе `kill_switch = false` |
| LAN без интернета, роутер с интернетом | Проверь `ip_forward`, `MASQUERADE`, правильное имя `LAN_IF` в `S99qeli` |
| После ребута сервер видит «новое устройство» / повторный TOFU | `QELI_DEVICE_ID_FILE` и `QELI_KNOWN_HOSTS` должны быть на `/opt` (в `S99qeli` уже так; `/var` — tmpfs) |
| Очень медленно (mipsel) | Потолок CPU без AES-NI; ставь `mode = obfs`/`plain`, не `reality-tls` |
| OpkgTun-режим (вебморда) | Отдельная диагностика — [`release/keenetic/opkgtun/README.md`](../../release/keenetic/opkgtun/README.md) |
| Туннель рвётся | Авто-reconnect включён; смотри `/opt/var/log/qeli-client.log` |

---

## Обновление / удаление

```sh
# обновить бинарь: останови, замени, запусти
/opt/etc/init.d/S99qeli stop
install -m755 qeli-client-<арка> /opt/bin/qeli-client
/opt/etc/init.d/S99qeli start

# удалить полностью
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli /opt/var/log/qeli-client.log
```
