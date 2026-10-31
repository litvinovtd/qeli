# Пилот короткого теста: фактические socket buffers, 31 октября 2026

Итог: **обвязка проверена, 40/40 окон завершены, восстановление 300/301 подтверждено**.
Во всех 16 UDP600-окнах — 0% receiver loss и 0 TUN TX drops. Это
`BUFFER_PILOT_ONLY`, не допуск релиза и не доказательство отсутствия регрессии.
Методика: [короткий тест v2](../manuals/RELEASE-SHORT-TEST.md).

## Артефакт, стенд и объём

- Прежний экспериментальный native Linux amd64 Qeli 0.8.4 со сжатыми лицензиями,
  SHA256 `a6da0fa51b53b1efcc88e5d109be7136dd6d666aeccc37b97722e3f80cb2ff6c`.
  Это **не** квалификация portable release/dist и не проверка новой сборки из текущих исходников.
  Бинарник не пересобирался и не изменялся; VM302 не использовалась.
- VM300/server и VM301/client: по 2 vCPU, 2 ГиБ RAM (MemTotal 2020904 КиБ),
  Intel i5-8500, Debian kernel `6.12.111+deb13-amd64`, iperf3 3.18.
  Proxmox не выполнял команды теста/сборки/установки.
- Четыре профиля, только Recordizer required с подтверждённым `PACKET_MUX_V1`;
  Reality-TLS — genuine H2. MTU 1400, обе TUN-очереди 1000; прежние fixtures,
  timed batching, `gateway=false`, `dns=off`. Очереди/qdisc/wmem не менялись.
- На профиль: TCP P4 и UDP600, inner IPv4/IPv6 upload/download, **n=1**,
  `-t 10 -O 2`; UDP payload 1200. Внешний transport IPv4. 32 нагрузочных окна
  и восемь direct TCP P1 baseline до/после. Не выполнялись P1 внутри VPN,
  UDP300, три повтора, все 12 функциональных профилей, compatibility и mixed.
- Явная временная lab policy на обеих ВМ: `rmem_max=rmem_default=4194304`.
  Применена до baseline/создания сокетов и полностью отменена после нагрузки.
  Это изменение условий измерения, а не исправление Qeli или рекомендация
  безусловно менять системные настройки пользователей.

## Что проверено у живых сокетов

| Объект | Фактическое значение | Проверка |
|---|---|---|
| Qeli UDP-FakeTLS/QUIC, обе стороны | `ss rb=8388608` | Нормализованный явный запрос 4 МиБ (`rb/2`); все carrier-сокеты, PID/inode |
| iperf UDP, оба конца, каждое окно | `ss rb=4194304`, `tb=212992` | Приёмник server/upload или client/download; один успешный live snapshot |
| Qeli TCP, начало сессий | `ss rb=131072` | Записано без UDP-нормализации; далее сохранялись оконные снимки |
| iperf TCP receiver, включая baseline | sampled `rb` 1697795–6291456 байт | Живые data-соединения, `rb/tb`; autotuning, не фиксированный floor |

Linux `ss rb/tb` — kernel-accounted bytes, не гарантированная payload capacity.
Для Qeli UDP проверен floor 4 МиБ явного запроса; для iperf UDP без `-w` —
4 МиБ непосредственно в `rb`, без повторного удвоения. TCP не проверяется UDP-порогом.
При разборе raw проверки повторены, SHA helper/controller/checker сверены.

## Результаты

Скорость — receiver Мбит/с. TUN TX drops суммированы по двум сторонам за окно
наблюдения с прогревом; TCP retransmits — iperf без прогрева. Их интервалы различны,
поэтому равенство счётчиков не предполагается. У всех UDP ниже loss=0%, TUN drops=0.

| Профиль | IP | Направление | TCP P4 | Retransmits | TCP TUN TX drops | UDP600 goodput | UDP loss | UDP TUN TX drops |
|---|---|---|---:|---:|---:|---:|---:|---:|
| tcp-faketls | IPv4 | upload | 1931.1 | 1166 | 1303 | 599.74 | 0% | 0 |
| tcp-faketls | IPv4 | download | 1947.9 | 1399 | 1750 | 599.98 | 0% | 0 |
| tcp-faketls | IPv6 | upload | 839.3 | 430 | 918 | 599.59 | 0% | 0 |
| tcp-faketls | IPv6 | download | 2004.4 | 1227 | 1616 | 599.95 | 0% | 0 |
| tcp-reality-tls | IPv4 | upload | 1200.0 | 802 | 1249 | 599.44 | 0% | 0 |
| tcp-reality-tls | IPv4 | download | 1207.0 | 727 | 1104 | 599.96 | 0% | 0 |
| tcp-reality-tls | IPv6 | upload | 1210.8 | 790 | 2164 | 599.28 | 0% | 0 |
| tcp-reality-tls | IPv6 | download | 1297.2 | 633 | 1569 | 599.96 | 0% | 0 |
| udp-faketls | IPv4 | upload | 1128.9 | 1175 | 1175 | 599.83 | 0% | 0 |
| udp-faketls | IPv4 | download | 1216.6 | 508 | 1583 | 599.97 | 0% | 0 |
| udp-faketls | IPv6 | upload | 1118.8 | 449 | 1772 | 599.49 | 0% | 0 |
| udp-faketls | IPv6 | download | 1184.3 | 1154 | 1710 | 599.98 | 0% | 0 |
| udp-quic | IPv4 | upload | 1159.1 | 1036 | 1751 | 599.70 | 0% | 0 |
| udp-quic | IPv4 | download | 1214.2 | 1226 | 2029 | 599.97 | 0% | 0 |
| udp-quic | IPv6 | upload | 1159.9 | 705 | 1777 | 599.57 | 0% | 0 |
| udp-quic | IPv6 | download | 1247.0 | 1429 | 2037 | 599.98 | 0% | 0 |

В UDP600-окнах UDP-FakeTLS/QUIC приращение Qeli carrier socket drops — 0;
inode-состав проверен неизменным. Накопленный `d` после максимального TCP
доходил до 539: его нельзя приписывать следующему UDP600-окну. У iperf
однократно наблюдавшийся UDP socket `d=0` не заменяет итоговую статистику loss.
Проверка достаточных буферов не устраняет оставшиеся TCP drops/retransmits.

Baseline drift по единственному окну до/после: IPv4 up −1.98%, down **−5.16%**;
IPv6 up −0.40%, down −0.25%. IPv4 download превышает ориентир 5%; n=1 не даёт CV.
Этот пилот нельзя брать за принятый скоростной эталон. Низкое одиночное TCP
FakeTLS IPv6 upload также не объяснено этим тестом и требует повторов, если
нужен вывод о скорости. Старые замеры с малыми буферами не переписаны;
сравнивать их с этой таблицей как чистый эффект версии нельзя.

## Raw, первый отказ и восстановление

Raw на обеих ВМ: `/opt/qeli-release-short-buffer-pilot-20261031-r02`.
Время UTC: `2026-10-31T14:29:10`–`14:45:57` (включая хеширование архивов),
method `qeli-release-short-buffer-pilot-v2`. Локальные компактные receipts,
summary и независимый final check: рабочий каталог `short-buffer-pilot-20261031`.
Приватные конфиги и большие raw не публикуются.

Первый `r01` остановлен **до нагрузки и изменения sysctl**: snapshot всех прежних
архивов превысил старый SSH timeout 60 с. FAIL и raw на server сохранены;
client-root тогда не создавался. Подтверждены отсутствие оставшегося snapshot,
исходные буферы и свободные ВМ. Только таймаут snapshot увеличен до 900 с;
повтор выполнен под новым тегом, не как слепой resume.

После r02 все 16 restoration checks на каждой ВМ истинны: boot ID, старые
файлы/бинарники, sysctl, процессы, интерфейсы/адреса, маршруты/правила, qdisc,
iptables/ip6tables. Независимая проверка: исходные `rmem_*`/`wmem_*` по 212992,
нет Qeli/iperf/IRTT/TUN/netns/lock/owned receipts, службы qeli/qeli-client inactive,
candidate и предыдущий бинарник имеют прежние SHA. Reboot не выполнялся.
Релиз не публиковался, артефакты release/dist не заменялись.

Измеренные SHA256 обвязки:

- controller: `c1106c6b270edb1a059b7301f5a28abce7287b485e431ea2a4a97ae15b31e5fd`
- helper: `540d9a1133b3f8e1f98eac429452398e094415efa15a476a1c48be155baa497e`
- buffer checker: `19d1ed5127d8c2fda8a43e24e0e77ef943b465dd8f3f592722d888c6f730098e`

Обвязка имеет 38 локальных unit tests, включая неправильные/чужие/отсутствующие
буферы, учёт Linux, отказ допуска частичного пилота, частичный apply/rollback,
lease expiry и проверку PID перед эскалацией сигнала. Полный v2 и mixed в этом
пилоте не прогонялись; независимая стоимость наблюдателя не установлена.
