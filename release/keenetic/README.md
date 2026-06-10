# qeli-client на Keenetic (Entware) — деплой

Запуск qeli-VPN-клиента на роутере Keenetic как шлюза для всего LAN. Полный план и
обоснование — [docs/KEENETIC-PORT.md](../../docs/KEENETIC-PORT.md).

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
- `S99qeli` при `GATEWAY=yes` ставит `ip_forward` + `MASQUERADE` на tun и FORWARD-правила
  между `LAN_IF` (по умолчанию `br0`) и tun. Проверь имя LAN-бриджа: `ip a`.

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
