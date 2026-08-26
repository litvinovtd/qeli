# Qeli 0.8.0 — лабораторный DPI-анализ

Дата: 2026-08-26  
Ветка/commit сборки: `dev` / `13a8d4834cf9c5ea9e93652fb75b399481cfa058`  
Бинарник: `qeli 0.8.0`, SHA-256 `e0e8257b0a52cc0efcabc8e289d90c34d6e33e0bfffa8fd627119eba6638a5a6`

## Итог

Гипотеза из исходной записки подтверждается: в текущей реализации есть сильный общий
статистический отпечаток, переживающий смену wire-mode. В небольшой контролируемой выборке
оба leave-one-mode-out классификатора распознали 36/36 Qeli-flow, включая режим, которого не
было в обучении, при 0/12 ложных срабатываний на реальных HTTP/2 и HTTP/3 control-flow.

Это не доказывает распознавание промышленным DPI в интернете: corpus мал, взяты три публичных
домена и одна синтетическая внутренняя нагрузка. Но результат достаточен, чтобы отвергнуть
предположение «смена fake-TLS/Reality/UDP/QUIC/AWG сама устраняет общий отпечаток».

Текущий idle-cover полезен против фиксированного маяка, однако ни Poisson-only, ни `stealth`
не убирают основной инвариант «внутренний пакет → отдельная внешняя запись/датаграмма».

## Чистота и воспроизводимость стенда

- Выполнен полный reboot обеих ВМ `.10` и `.11`.
- Android emulator выключен; перед каждым образцом `emulator=0`, `qeli=0`, лишних TUN/TAP и
  искусственных qdisc нет.
- Однократный stability gate без повторов: upload spread 5,7%, download spread 4,6%, порог 8% — PASS.
- На обе ВМ установлен один и тот же бинарник с точным SHA выше.
- Capture point для Qeli и control одинаковый: `.11`, `ens18`.
- Для wire-level capture выключены GRO/GSO/TSO и `rx-gro-hw`; исходное состояние после теста
  восстановлено (`gro/gso/tso/rx-gro-hw=on`, `lro=off`).
- Финальная гигиена: на обеих ВМ `emulator=0`, `qeli=0`, лишних интерфейсов и qdisc нет.

Первый вариант HTTP-control на `speed.cloudflare.com` был отброшен: сервер реально согласовал
HTTP/1.1, а H3 не поднялся. Финальный control-corpus переснят на URL, для которых curl подтвердил
`http=2` или `http=3`, `code=200`. H2 также переснят после устранения hardware-GRO артефакта.

## Что протестировано

- 12 canonical wire-modes × 3 полностью новые сессии: 36 handshake PCAP + 36 load PCAP.
- В каждой сессии: `AUTH OK`, ping через tunnel, внутренний UDP 4 Мбит/с вверх и вниз.
- 36/36 соединений PASS; 0 случаев ненулевой потери в обоих направлениях.
- 6 реальных HTTP/2 + 6 реальных HTTP/3 flow-control.
- Idle: fake-TLS default 96 секунд; Reality-TLS + Poisson cover 20 секунд.
- Дополнительно: Reality-TLS + Poisson-only ×3; Reality-TLS + stealth 2 Мбит/с ×3.
- Цена stealth Reality-TLS: настройки 2/10/25 Мбит/с, TCP iperf вверх/вниз.

| Mode | Сессии | Средний внешний payload, B | Средний gap, ms | gaps ≤2 ms | Handshake-наблюдение |
|---|---:|---:|---:|---:|---|
| tcp-plain-raw | 3/3 | 926 | 1,920 | 99,9% | raw, TLS records 0 |
| tcp-faketls | 3/3 | 930 | 1,926 | 99,7% | ~22 TLS-like records |
| tcp-padding | 3/3 | 1 046 | 1,919 | 99,7% | ~22, размеры сдвинуты padding |
| tcp-frag | 3/3 | 1 049 | 1,919 | 99,9% | ~22, больше TCP-пакетов handshake |
| tcp-obfs | 3/3 | 1 053 | 1,919 | 99,7% | non-TLS framing |
| tcp-reality | 3/3 | 930 | 1,915 | 99,9% | ~22 TLS-like records |
| tcp-reality-tls | 3/3 | 952 | 1,915 | 99,7% | outer TLS + ~30 записей общей choreography |
| udp-faketls | 3/3 | 928 | 1,912 | 99,8% | 58% handshake-датаграмм TLS-like |
| udp-padding | 3/3 | 1 043 | 1,905 | 99,5% | 58% handshake-датаграмм TLS-like |
| udp-quic | 3/3 | 937 | 1,905 | 99,7% | не настоящий QUIC state machine |
| tcp-obfs-awg | 3/3 | 936 | 1,912 | 99,8% | AWG junk не меняет load-invariant |
| udp-faketls-awg | 3/3 | 928 | 1,906 | 99,7% | 52% handshake-датаграмм TLS-like |

Для всех 12 режимов доля смены направления под одинаковой нагрузкой практически одинакова —
около 2,6%. Padding меняет длину записи, Reality-TLS добавляет внешний TLS overhead, но cadence
и соответствие одному внутреннему пакету остаются видимыми.

Контроли отличались формой потока:

| Control | N | Средний payload, B | Full-MTU share | gap, ms | gap CV | gaps ≤2 ms | Direction switch |
|---|---:|---:|---:|---:|---:|---:|---:|
| HTTP/2 | 6 | 1 388 | 93,7% | 1,512 | 12,69 | 96,5% | 1,4% |
| HTTP/3 | 6 | 1 102 | 0% | 1,428 | 9,60 | 96,3% | 5,9% |

Даже после абляции classifier сохраняет 36/36 TPR и 0/12 FPR отдельно на size-only,
relative-timing-only и на shape без абсолютной скорости/pps и без признака TCP/UDP. Ограничение:
это всё ещё сравнение фиксированной VPN-нагрузки с веб-загрузкой, а не с тем же приложением через
другие VPN. Следующий corpus обязан добавить WireGuard/OpenVPN/HTTPS proxy и одинаковые workload.

## Heartbeat и shaping

Конфиг задаёт `interval_ms=15000`, `jitter_ms=20`, но фактический idle timeline такой:

- client→server: 30,050; 60,053; 90,052 с; gaps 30,004 и 29,999 с;
- server→client: 30,044; 60,042; 90,034 с; gaps 29,999 и 29,991 с;
- CV около `0,0001`: практически идеальный 30-секундный метроном.

Причина видна в scheduler: periodic tick привязан к старту writer, а idle-gate сравнивает его с
последней реальной отправкой. Tick на 15 с пропускается; на следующей границе округление часто
видит 14 999 мс и пропускает снова, поэтому heartbeat стабильно уходит раз в 30 с.

Poisson-cover устраняет этот маяк:

- client→server mean gap 0,529 с, CV 0,739;
- server→client mean gap 0,627 с, CV 0,510;
- наблюдаемый диапазон примерно 0,072–1,385 с, размеры разнообразны.

Но под нагрузкой Poisson-only классифицируется как Qeli с вероятностью 0,977–0,987.
Stealth-2 снижает вероятность лишь до 0,936–0,962 (nearest-centroid: 0,791–0,841), то есть общий
отпечаток остаётся. Текущий stealth ограничивает скорость, но не меняет семантику recordization.

Цена stealth Reality-TLS:

| Настройка | Upload | Download |
|---:|---:|---:|
| 2 Мбит/с | 2,05 | 2,10 |
| 10 Мбит/с | 11,08 | 11,11 |
| 25 Мбит/с | 28,00 | 27,86 |

## Предлагаемое решение

Абсолютно «неклассифицируемого» протокола не существует. Практическая цель — сделать wire-flow
неотличимым от конкретного массового target-протокола и не оставлять общего Qeli-инварианта.

### P0 — исправить явные маяки и обещания профилей

1. Убрать fixed heartbeat из stealth-профилей по умолчанию; использовать единый one-shot
   randomized scheduler/cover stream. Отдельно исправить фактический 30-секундный период.
2. Для hostile-DPI рекомендовать только настоящий Reality-TLS; `plain`, fake-TLS, obfs и AWG
   оставить как compatibility/performance режимы, не как максимальную маскировку.
3. Переименовать текущий `udp-quic` в `quic-shape`, пока он не реализует настоящий QUIC.

### P1 — убрать главный общий инвариант

Добавить transport-independent **recordizer** между TUN и carrier:

- короткая адаптивная очередь, ориентир 0–2 мс balanced / до 5–8 мс maximum-stealth;
- объединять несколько внутренних IP-пакетов в одну зашифрованную запись;
- крупный внутренний пакет разрешать делить между несколькими carrier-record;
- внутренние длины хранить в зашифрованном multiplexed payload;
- размер, timing, burst и направление выбирать совместно по target-модели, а не независимым padding;
- TLS write/WS frame/UDP datagram больше не должны совпадать с границей TUN packet.

Это непосредственно ломает единственный признак, который сохранился во всех 12 режимах.
Batching заодно может уменьшить syscall/AEAD overhead; цена — очередь, память и небольшой latency.

### P1 — убрать двойное рукопожатие

Для Reality-TLS после outer TLS не запускать внутреннюю fake-TLS choreography. Аутентификацию и
negotiation включить в первый правдоподобный запрос carrier (например, нормальный HTTP/2
HEADERS/DATA exchange с одноразовым sealed token) или в resumption/PSK-механику. При неверном
токене сервер должен продолжать нормальный decoy-flow, а не отвечать Qeli-специфичной ошибкой.

### P2 — использовать настоящие carrier-протоколы

- TCP: настоящий HTTP/2 поверх rustls с ALPN `h2`, обычными SETTINGS/HEADERS, flow-control,
  несколькими streams и DATA frames; tunnel bytes — содержимое DATA, а не отдельный inner TLS.
- UDP: настоящий QUIC + HTTP/3 на поддерживаемой библиотеке (`quinn`/h3 или эквивалент), включая
  packet number protection, ACK/PTO, congestion control, CID migration и реальные H3 frames.

Ручная имитация нескольких первых байтов TLS/QUIC не воспроизводит state machine и оставляет
пассивные и активные отличия. Реальный carrier существенно дороже в реализации, но это наиболее
сильный путь к target indistinguishability.

### P3 — distribution-matching вместо постоянного rate-cap

Собрать versioned target-corpus и реализовать joint state machine для browsing/video/download:

- распределение DATA-frame sizes;
- burst length и think-time;
- направление и смена направления;
- idle/cover как часть той же модели;
- адаптация к MTU/RTT, без одинаковых констант у всех установок.

`stealth_rate_mbps` оставить как safety ceiling, но не использовать постоянную полку скорости как
саму маскировку: постоянные 2/10/25 Мбит/с тоже классифицируемы.

## Обязательный release-gate после реализации

1. Не менее 50–100 flow на класс, разные дни, RTT/MTU/ASN и несколько public endpoints.
2. Одинаковые workload через Qeli, WireGuard, OpenVPN, HTTPS proxy, настоящий H2 и H3.
3. Leave-one-mode + leave-one-domain + leave-one-day; отдельный unseen-host test.
4. Метрика не accuracy, а TPR при фиксированном FPR 0,1%/1%, ROC-AUC и confidence intervals.
5. Отдельно active probes, replay, malformed handshakes, timeout/reconnect choreography.
6. Релиз не проходит stealth-gate, если held-out Qeli остаётся стабильно отделимым от target.

## Production deployment

Перед DPI-тестами тот же бинарник установлен на production. После переключения:

- `/usr/local/bin/qeli --version` → `qeli 0.8.0`;
- SHA-256 совпал с лабораторным артефактом;
- `qeli.service` active/enabled, `NRestarts=0`;
- сохранены config SHA и 9 identity keys;
- слушатели сохранены: TCP 443/8444/8446, UDP 8448/8449/8450;
- TLS decoy subject Microsoft сохранён;
- pre-deploy backup: `/root/backup/qeli-deploy/20260826-002608-pre-080/qeli.bin.bak`.

Изменений в product source в рамках DPI-анализа не вносилось.
