# qeli-client на Keenetic — пошаговый деплой

Развёртывание qeli-VPN-клиента на роутере Keenetic (Entware) как шлюза для всего LAN.
Архитектура и обоснование порта — [KEENETIC-PORT.md](KEENETIC-PORT.md). Файлы бандла —
в `release/keenetic/`.

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
key    = <server pubkey из show-identity>
mode   = fake-tls           # MIPS: fake-tls | obfs | plain (ChaCha20). reality-tls
sni    = www.cloudflare.com #       на mipsel очень медленный — только для ARM
gateway = true              # весь трафик LAN в туннель (full-tunnel)
dns     = off               # НЕ трогать резолвер роутера (им владеет прошивка)

[logging]
level = info
file  = /opt/var/log/qeli-client.log
```

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

## Диагностика

| Симптом | Причина / что делать |
|---|---|
| `нет /dev/net/tun` при старте | Включить компонент VPN в KeeneticOS (предусловия) |
| `ip: ... tuntap` не работает | `opkg install ip-full` (busybox-`ip` урезан) |
| Нет `Auth OK`, `SERVER KEY MISMATCH` | Неверный `key` — сверь с `qeli show-identity` на сервере |
| Нет `Auth OK`, `auth failed` | Неверные `user`/`pass`, либо `mode`/`sni` не совпадают с профилем сервера |
| LAN без интернета, роутер с интернетом | Проверь `ip_forward`, `MASQUERADE`, правильное имя `LAN_IF` в `S99qeli` |
| После ребута сервер видит «новое устройство» | `QELI_DEVICE_ID_FILE` должен быть на `/opt` (в `S99qeli` уже так; `/var` — tmpfs) |
| Очень медленно (mipsel) | Потолок CPU без AES-NI; ставь `mode = obfs`/`plain`, не `reality-tls` |
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
