# Несколько профилей на одном сервере

Запустите несколько независимых точек входа в одной службе Qeli: например,
`reality-tls` по TCP и `udp-quic` по UDP. Профили разделяют транспорт, TUN, адресные
пулы и identity; пользователи хранятся в общей базе с отдельными разрешениями.

[Каталог и подготовка](README.md) · [English](../../eng/scenarios/MULTI-PROFILE.md)

## План профилей

| Профиль | Listener | TUN | IPv4-пул |
| --- | --- | --- | --- |
| `reality-tls` | TCP `443` | `vpn0` | `10.9.0.0/24` |
| `udp-quic` | UDP `8449` | `vpn7` | `10.9.7.0/24` |

Имена интерфейсов и пулы должны быть уникальны в соответствующем сетевом контексте.
Если включаете IPv6, выделите профилям разные `/64` из собственного ULA или routed
prefix. Один номер TCP/UDP-порта технически относится к разным транспортам, но
разные номера в примере упрощают диагностику и firewall.

## Подготовьте полные профили

Возьмите [server-multiprofile.conf](../../../qeli/config/server-multiprofile.conf),
сохраните только нужные секции и перенесите их в рабочий конфиг. Не заменяйте текущие
`[auth]`, `[web]`, `[logging]` и `users_file` демонстрационными значениями.
Ниже — только структура, не готовый REALITY-конфиг:

```ini
[profile:reality-tls]
bind.transport = tcp
bind.port = 443
tun.name = vpn0
tun.address = 10.9.0.1
pool.cidr = 10.9.0.0/24
obf.mode = reality-tls

[profile:udp-quic]
bind.transport = udp
bind.port = 8449
tun.name = vpn7
tun.address = 10.9.7.1
pool.cidr = 10.9.7.0/24
obf.mode = fake-tls
obf.quic.enabled = true
```

Для REALITY сохраните полный набор `obf.tls.reality_proxy.*`, совпадающий target/SNI,
`real_tls=true` и собственный случайный `short_ids`; публичный примерный short ID
не является production-секретом. У каждого профиля своя identity: не подставляйте
ключ первого профиля во второй.

Для обоих full-tunnel профилей отдельно настройте NAT/DNS по
[FULL-TUNNEL](FULL-TUNNEL.md), включая адрес DNS своего пула. Для split/LAN-профиля
применяется [HOME-LAN](HOME-LAN.md), а не автоматический NAT всего трафика.

## Разрешите доступ и выпустите ссылки

```sh
sudo -u qeli qeli add-client laptop --profiles reality-tls,udp-quic --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile reality-tls --host vpn.example.com:443 --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile udp-quic --host vpn.example.com:8449 --config /etc/qeli/server.conf
```

Для существующего пользователя редактируйте `profiles` в его секции, не создавайте
вторую учётную запись с тем же именем. Отсутствие ограничения `profiles` разрешает
все профили, а не запрещает их. Откройте TCP `443` и UDP `8449` отдельно на VPS и
в облачном firewall. Доступность TCP ничего не доказывает о UDP.

## Запуск и проверка

1. Проверьте полный server config, затем перезапустите службу в согласованное окно.
2. Сверьте listeners (`ss -lntup`), TUN и адреса (`ip address`).
3. Импортируйте обе ссылки как отдельные клиентские профили. По очереди проверьте
   соединение, внешний IP, DNS и MTU каждого.
4. Проверьте пользователя, которому разрешён только один профиль: второй вход
   должен отказать в авторизации, даже если пароль верный.
5. Не считайте два сохранённых профиля двумя одновременно активными VPN на телефоне.

## Откат

Сначала отключите клиентов удаляемого профиля, верните server config и пользовательские
ограничения. После штатной остановки проверьте освобождение его TUN, DNS и правил.
Существующие recovery-журналы не удаляйте. Резервный канал настраивается отдельно:
[PRIMARY-BACKUP](PRIMARY-BACKUP.md).
