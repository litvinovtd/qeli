# qeli-client на Keenetic (Entware) — IPv4/IPv6 деплой

Запуск qeli-VPN-клиента на роутере Keenetic как шлюза для всего LAN.
**Подробный пошаговый гайд (по шагам, с проверкой туннеля) — [docs/KEENETIC-DEPLOY.md](../../docs/ru/KEENETIC-DEPLOY.md).**
План и обоснование порта — [docs/KEENETIC-PORT.md](../../docs/ru/KEENETIC-PORT.md).

> ⚠️ Скрипты в этой папке — **шаблоны**. На живом Кинетике они не тестировались
> (у нас нет устройства); проверь имена интерфейсов и поведение firewall под свою
> модель/прошивку.

## Предусловия на роутере
- Установлен **Entware** (opkg, `/opt`).
- Включён компонент **VPN** в KeeneticOS (чтобы был `/dev/net/tun`).
- Есть SSH-доступ.

## Сборка бинарей (на лабе .10)
```sh
python scripts/build_keenetic.py
# → release/keenetic/qeli-client-aarch64  и  qeli-client-mipsel
```

## Установка (на роутере)
Скопируй всю папку `release/keenetic/` на роутер (scp) и запусти:
```sh
sh install-keenetic.sh      # определит арку, поставит ip-full/iptables, разложит файлы
vi /opt/etc/qeli/client.conf
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log   # ждём 'Auth OK'
```

## Режим шлюза (весь LAN через VPN)
- В `client.conf`: `gateway = true` (full-tunnel) и `dns = off` (не трогать DNS роутера).
- Рекомендуемый конфиг использует `gateway_nat = true`: само ядро qeli ставит и проверяет
  IPv4/IPv6 forwarding, MASQUERADE, FORWARD и MSS clamp, а при остановке восстанавливает
  изменённые sysctl. `S99qeli` сохраняет `GATEWAY=yes` только как fallback для старых
  конфигов без `gateway_nat`/`forward`.
- Legacy fallback ждёт до 60 секунд атомарно опубликованный после AUTH/NetworkPlan файл,
  включает firewall только для реально выданных IPv4/IPv6 и не угадывает семейство по
  `ipv6 = auto`. На RA/SLAAC WAN он сохраняет `accept_ra`, ставит `2` до IPv6 forwarding и
  восстанавливает прежнее значение при остановке.
- Для inner IPv6 оставь `ipv6 = auto`, используй `required` для fail-closed или `off` для
  принудительного IPv4. Для dual-stack router-mode нужен `ip6tables`; без него `auto`
  согласует IPv4, а `required` откажет до настройки интерфейса.
- При необходимости ограничь NAT реальными `lan_subnet` и `lan_subnet_ipv6` своего LAN.
  Имя LAN-бриджа для legacy fallback (`LAN_IF`, обычно `br0`) проверь через `ip a`.

## Выбор режима под железо
- **MIPS** (MT7621/7628, без AES-NI): `fake-tls` / `obfs` / `plain` (ChaCha20). Потолок —
  десятки Мбит. `reality-tls` очень медленный (двойной AEAD).
- **ARM** (Cortex-A53, crypto-ext): можно `reality-tls`; скорость в разы выше.

## Удаление
```sh
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli
```
