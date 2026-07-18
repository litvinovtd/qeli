# qeli на Keenetic через OpkgTun (интерфейс в вебморде)

Опциональный режим для **KeeneticOS 5.0+**: qeli-tun отдаётся `ndm` как нативный
интерфейс `OpkgTunN`, который виден в вебморде и доступен в **«Приоритетах подключений»**
и статических маршрутах. Тогда per-device / selective роутинг настраивается мышкой в UI,
без самодельного NAT из `S99qeli`.

Это **аддон**, изолированный в этой папке. Базовый gateway-режим (надёжный, без зависимости
от ndm) — в `release/keenetic/`. Если UI-роутинг не нужен — используй его, он проще и
переживает ребут без нюансов ниже.

> ⚠️ **Честно о зрелости.** OpkgTun-интеграция рабочая, но **хрупкая и полу-ручная**:
> - авто-регистрация через wan.d-хук на раннем бусте **ненадёжна** (ndmc в этом контексте
>   часто не отвечает) — рабочая регистрация делается вручную из ssh-логина;
> - переживание ребута требует **статического IP на сервере** (иначе адрес «уплывает» и
>   сохранённый в ndm конфиг устаревает);
> - нативного тумблера вкл/выкл в «Других подключениях» у OpkgTun нет (фича-реквест Keenetic).
>
> Разумно на ARM-моделях; на mipsel — только лёгкие режимы маскировки.

## Модель владения (ключевое, проверено на устройстве)

На 5.0 устройство `opkgtun0` **создаёт и держит САМ `ndm`**, а приложение к нему
**прицепляется**, и **L3 (адрес + линк) тоже ставит ndm, а не приложение**. Две ловушки:

- qeli сам создаёт `opkgtun0` → `ndm` не заводит интерфейс:
  `Opkg::Interface::Tun error: "OpkgTun0": system failed [0xcffd00a9]`,
  а qeli — `interface 'opkgtun0' already exists … refusing to take it over`.
- qeli сам ставит адрес/поднимает линк → `ndm` навсегда залипает в
  `link: pending / connected: no` и **не маршрутизирует** через интерфейс. Только когда
  адрес ставит ndm (`ip address … /32` + `up`), интерфейс переходит в `connected: yes`.

Поэтому qeli в **attach-режиме** (`dev_attach = true`): открывает существующее
ndm-устройство **только для перекачки пакетов** — не создаёт его, не ставит адрес, не
поднимает линк, не трогает маршруты, не удаляет при выходе. Выданный сервером IP qeli пишет
в `$QELI_TUNIP_FILE`, а адрес/линк/маршруты держит `ndm` (через хук).

> ℹ️ **Про «gvisor only».** Форумные упоминания, что «на OpkgTun разрешён только gvisor»,
> относятся к ВНУТРЕННИМ tun-stack режимам Clash/sing-box (`system`/`gvisor`/`mixed` — опция
> самого приложения), а НЕ к ndm. Обычный kernel-tun через OpkgTun работает (так живёт,
> например, AmneziaWG-Go). Затык `0xcffd00a9` был не в gvisor, а в порядке/владении устройством.

## Файлы в этой папке

- `010-qeli.sh` — wan.d-хук: создаёт `OpkgTun0`, ждёт IP от qeli, ставит L3 через ndmc.
- `S99qeli` — init-скрипт с преднастроенным `OPKGTUN=opkgtun0` (в OpkgTun-режиме свой NAT
  выключен; сигналит хуку и экспортит `QELI_TUNIP_FILE`).
- `client.conf.example` — пример конфига (`dev = opkgtun0`, `dev_attach = true`, `gateway = false`).

## Установка

1. Клиент (общий бинарь) и базовый деплой — по `release/keenetic/README.md`.
2. Скопируй OpkgTun-файлы:
   ```sh
   cp opkgtun/S99qeli            /opt/etc/init.d/S99qeli
   mkdir -p /opt/etc/ndm/wan.d
   cp opkgtun/010-qeli.sh        /opt/etc/ndm/wan.d/010-qeli.sh
   chmod +x /opt/etc/init.d/S99qeli /opt/etc/ndm/wan.d/010-qeli.sh
   ```
3. В `/opt/etc/qeli/client.conf` задай `dev = opkgtun0`, `dev_attach = true`, `gateway = false`
   (см. `opkgtun/client.conf.example`).
4. **Пин статического IP на сервере** для этого пользователя (обязательно для ребута) — см. ниже.
5. `/opt/etc/init.d/S99qeli start`.

## Статический IP (обязательно для переживания ребута)

Сервер по умолчанию выдаёт IP из пула, и после ребута он может смениться → сохранённый в ndm
адрес устареет → маршрутизация сломается. Зафиксируй IP на сервере (сервер это умеет):

- **веб-панель**: пользователь → поле статического IP;
- **CLI (новый юзер)**: `qeli add-client <user> --static-ip 10.9.0.2 …`;
- **конфиг сервера**: `static_ip = "10.9.0.2"` в `[user:<name>]`, либо
  `pool.reservation.<user> = "10.9.0.2"` в профиле (см. `docs/eng/CONFIG.md`).

Применяется на следующем коннекте (user db читается на auth в реальном времени).

## Регистрация вручную (надёжный путь)

wan.d-хук на бусте часто не может выполнить ndmc. Рабочий способ — **из ssh-ЛОГИНА**
(не из `exec sh` — иначе `0xcffd0060`), порядок тот же, что в хуке:

```sh
ndmc -c "interface OpkgTun0"                 # 1. ndm создаёт kernel-device opkgtun0
/opt/etc/init.d/S99qeli start                # 2. qeli цепляется, пишет IP в файл
IP=$(cat /opt/var/run/qeli.tunip)            # 3. берём IP и отдаём L3 целиком ndm (адрес /32!)
ndmc -c "interface OpkgTun0 ip global auto"
ndmc -c "interface OpkgTun0 ip address $IP 255.255.255.255"
ndmc -c "interface OpkgTun0 ip mtu 1400"
ndmc -c "interface OpkgTun0 ip tcp adjust-mss pmtu"
ndmc -c "interface OpkgTun0 security-level public"
ndmc -c "interface OpkgTun0 up"
ndmc -c "ip route default OpkgTun0"
ndmc -c "system configuration save"
ndmc -c "show interface OpkgTun0" | grep -E "connected|global"   # ждём connected: yes, global: yes
```
Снять интерфейс: `ndmc -c "no interface OpkgTun0"`.

## Маршрутизация

- **Весь трафик устройства → VPN**: «Интернет → Приоритеты подключений» → профиль с
  `OpkgTun0` выше WAN → привязать устройство. Работает для любых адресов/CDN, ndm сам NAT'ит.
- **Точечный маршрут**: `ndmc -c "ip route <сеть> <маска> OpkgTun0"` + `system configuration save`.
  UI-статик ненадёжен: маршрут ложится в table `main`, которую трафик клиента не смотрит
  (сначала `from all lookup 4096`), плюс баг вебморды сбрасывает выбор интерфейса на дефолт.
- Интерфейс обязан быть `connected: yes` и `global: yes` — иначе маршруты не активируются.
- НЕ ставь `ip route default OpkgTun0` для роутера в целом — завернётся и соединение qeli с
  сервером → петля. Заворачивай клиентов через Приоритеты.

Проверка exit-IP туннеля (минуя роутинг/DNS): `curl --interface opkgtun0 -s https://api.ipify.org`.

## Диагностика

| Симптом | Причина / что делать |
|---|---|
| `system failed [0xcffd00a9]` + qeli `already exists` | Инверсия владения: поставь `dev_attach = true`, дай ndm создать интерфейс первым |
| Маршрут не идёт; `show interface` = `connected: no` / `link: pending`, `global: no` | L3 должен держать ndm. Проверь `dev_attach = true`, что qeli пишет IP в `/opt/var/run/qeli.tunip`, и что адрес `/32` + `ip global` ставит ndm |
| Хук: `OpkgTun0 недоступен` / `не принял` | ndmc в контексте wan.d (особенно на бусте) не отвечает — зарегистрируй вручную из ssh-логина |
| После ребута маршрут отвалился, IP сменился | Нет статического IP → пин на сервере (см. выше) |
| Файла `/opt/var/run/qeli.tunip` нет | `OPKGTUN=` пуст в S99qeli, либо старый бинарь без `dev_attach` |
| Нет тумблера вкл/выкл в «Других подключениях» | Штатно не поддерживается (фича-реквест Keenetic); управляй через `ndmc interface OpkgTun0 up/down` + стоп qeli |

## Удаление / откат на gateway

```sh
/opt/etc/init.d/S99qeli stop
ndmc -c "no interface OpkgTun0"                 # из ssh-логина
rm -f /opt/etc/ndm/wan.d/010-qeli.sh
cp ../S99qeli /opt/etc/init.d/S99qeli           # базовый gateway-скрипт
# в client.conf: dev = vpn0, gateway = true, убрать dev_attach
```
