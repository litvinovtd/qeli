# Лабораторный бенчмарк VPN-протоколов — Qeli 0.8.0

Период прогона: **2026-09-01T17:05:33Z — 2026-09-02T05:20:05Z (UTC)**. Статус данных: **complete**.

Этот документ фиксирует завершённый лабораторный прогон, методику, параметры конфигураций и результаты. Throughput измерен `iperf3`. Признаки H/B/T/A описывают включённые механизмы маскировки и результаты preflight/PCAP, но не измеряют вероятность классификации внешним DPI.

## 1. Фактическая сводка

- Полный `rep1`: **34** доступных режимов. `rep2` и `rep3`: **25** masked-режимов. **9** control-режимов по плану имеют только `n=1`.
- Предварительный dual-stack gate новых профилей: **19/19**.
- Qeli: **12/12** профилей дали runtime-маркер `PACKET_MUX_V1 active ... policy=required`.
- Среднее TCP `P=4` по всем 12 Qeli-профилям: **1220 Mbit/s**. Для каждого режима сначала взяты медианы повторов четырёх направлений, затем рассчитано среднее по режимам.
- Максимальный средний TCP `P=4` всего набора: **WireGuard plain — 3161 Mbit/s**.
- Максимальный средний TCP `P=4` среди masked-режимов: **AmneziaWG full 3.1 — 2820 Mbit/s**.
- Из **100** направлений masked-режимов ставка `rep1` UDP ceiling подтвердилась с loss ≤1% во всех трёх повторах для **54** направлений; для **46** направлений получено меньше 3/3. По Qeli: **24/48** направлений с подтверждением 3/3, суммарно **113/144** чистых окон на ставке `rep1` ceiling.
- Baseline drift после матрицы: upload **+1.48%**, download **-1.71%**. Автоматического порога отбраковки не применялось.

### 1.1. Сводные агрегаты

| Группа | Режимов | TCP P=4, Mbit/s | UDP rep1 ceiling, Mbit/s |
| --- | --- | --- | --- |
| Qeli: быстрые TCP-профили | 5 | 1767 | 1365 |
| Qeli: тяжёлые TCP-профили | 3 | 1274 | 1048 |
| Qeli: нативные UDP-профили | 4 | 496 | 409 |
| AmneziaWG full 3.1 | 1 | 2820 | 1256 |
| Xray VLESS TLS/REALITY + Vision | 2 | 995 | 347 |
| Hysteria 2 QUIC TLS/Salamander | 2 | 947 | 375 |
| OpenVPN с обёртками | 6 | 310 | 289 |
| WireGuard с обёртками | 2 | 452 | 403 |

`TCP P=4` в этой таблице — среднее по входящим режимам, где значение режима является средним четырёх направлений из медиан повторов. `UDP rep1 ceiling` — среднее предложенных ставок, найденных в `rep1`, по IPv4/IPv6 и upload/download; это не средний фактический goodput. Группы не имеют одинаковой глубины H/B/T/A, поэтому таблица фиксирует производительность выбранных конфигураций, а не рейтинг скрытности.

Состав Qeli-групп: быстрые TCP — `tcp-plain-raw`, `tcp-faketls`, `tcp-padding`, `tcp-frag`, `tcp-reality`; тяжёлые TCP — `tcp-obfs`, `tcp-reality-tls`, `tcp-obfs-awg`; нативные UDP — `udp-faketls`, `udp-padding`, `udp-quic`, `udp-faketls-awg`. OpenVPN с обёртками включает stunnel DTLS/TLS, XOR UDP/TCP и Cloak TCP/UDP; WireGuard с обёртками — wg-obfuscator STUN и Cloak experimental.

## 2. Лаборатория и чистота прогона

- VM server: `10.66.116.10`; VM client: `10.66.116.11`.
- Обе VM: Debian, kernel `6.12.105+deb13-amd64`, **2 vCPU**, **2 GiB RAM**.
- Перед числовым проходом выполнен полный синхронный reboot обеих VM. Boot ID server: `cf04df08-770d-4ce9-a32a-222e5dd7c319`; client: `ffbf54d8-6c2d-46ed-89ba-36db7b2b24e7`.
- До baseline остановлены фоновые VPN-службы и системные maintenance timers; runtime-маскированы автозапуски Qeli и Android emulator/ADB.
- На обеих VM доказано отсутствие `qemu-system`, `adb` и `netem`; IPv6 policy INPUT/FORWARD/OUTPUT — `ACCEPT`.
- После очистки оставалось более 21 GiB на каждой VM. Никакие исходники или пользовательские конфиги при очистке не удалялись.
- Runtime sysctl одинаков на обеих сторонах: `rmem_max/wmem_max=16777216`, default buffers `1048576`, `netdev_max_backlog=5000`, UDP min buffers `16384`.
- Egress qdisc внешних virtio-интерфейсов оставлен в штатном состоянии лаборатории: server `fq_codel`, client `fq`. Это состояние неизменно для всех режимов и совпадает с предыдущим циклом, но upload и download следует сравнивать внутри своего направления, а не трактовать их разницу только как свойство VPN.
- Измерения выполнены внутри одного лабораторного Proxmox-стенда между двумя VM. Задержка, jitter и потери WAN не эмулировались; результаты характеризуют пропускную способность и стоимость обработки в этих условиях.

Артефакт полной перезагрузки: `release\competitor_repeat_080_reboot_2026-09-01.json`.

## 3. Алгоритм измерений

1. На новых boot ID выполнен прямой baseline по внешнему адресу `10.66.116.10`: пять повторов upload/download, 12 секунд, TCP, один поток.
2. `rep1` — полный проход 34 режимов в прямом порядке. `rep2` — сокращённый проход 25 masked-режимов в обратном порядке; `rep3` — тот же сокращённый набор в детерминированно перемешанном порядке. Это снижает систематический эффект нагрева и кешей.
3. В каждом предусмотренном политикой повторе режим поднимался заново. Control-режимы выполнялись один раз; masked-режимы — три раза. Перед следующим режимом удалялись процессы, TUN/WG/AWG-интерфейсы, policy routing и XFRM state.
4. После поднятия обязательно проходили IPv4 и IPv6 ping. Для Qeli дополнительно проверялся обязательный runtime-маркер Recordizer.
5. TCP: IPv4/IPv6 × upload/download. В полном `rep1` измерялись `P=1` и `P=4`; в сокращённых `rep2/rep3` — только `P=4`. Окно 15 с, первые 3 с исключены `-O 3`.
6. UDP: payload 1200 bytes, окно 15 с и warm-up 3 с. В `rep1` обязательны 300/450/600 Mbit/s; затем offered load повышается вплоть до фактической границы (safety ceiling 30 Gbit/s), а граница loss ≤1% уточняется до шага 25 Mbit/s. В `rep2/rep3` проверяются ровно две точки каждого направления: найденный в `rep1` clean ceiling и первая не прошедшая ступень.
7. `UDP rep1 ceiling` — найденная в полном проходе offered rate. Формат `[pass/n; median loss]` показывает, сколько проверок этой же точки осталось в пределах loss ≤1%. Для controls это `n=1`, для masked — `n=3`. Если `pass<n`, точный устойчивый потолок ниже этой ставки, но сокращённый план не выполнял повторный поиск более низкой границы.
8. Одновременно с каждым iperf-окном снимались `/proc/stat`, userspace process ticks/RSS, softirq, `/proc/net/softnet_stat`, UDP/TCP SNMP и counters всех интерфейсов.
9. После всей матрицы прямой baseline повторён на тех же boot ID; затем вычислен дрейф.

Инструмент: `iperf3 3.18`, MTU туннелей 1400, TCP/UDP направления обозначены `↑ upload` и `↓ download`. Все скорости — receiver goodput, Mbit/s. UDP 600 в таблице относится к `rep1`; UDP ceiling — offered rate с подтверждением повторов.

## 4. Baseline

| Фаза | Upload median | Upload CV | Download median | Download CV |
| --- | --- | --- | --- | --- |
| До матрицы | 23491 | 1.39 | 25708 | 0.64 |
| После матрицы | 23839 | 1.18 | 25269 | 0.95 |

## 5. Уровни маскировки

Для прозрачного сравнения используется четыре независимых признака:

- **H (Handshake)** — маскируется ли начальное рукопожатие под распространённый TLS/QUIC/STUN-профиль.
- **B (Bulk)** — меняются ли размеры/границы записей длительного потока, чтобы underlying VPN не читался по packet-size fingerprint.
- **T (Timing)** — есть ли управляемое изменение batching/delay/burst, а не только шифрование содержимого.
- **A (Active probe)** — отвечает ли неавторизованному сканеру легитимный target/redirect вместо характерной ошибки VPN.

`част.` означает ограниченное покрытие. Например, XTLS Vision/REALITY хорошо работает на handshake и target/probe, но не является полным аналогом Qeli Recordizer для независимого изменения bulk-размеров и timing.

## 6. Основная таблица результатов

| Продукт / режим | Маскировка | H/B/T/A | Внешний транспорт | TCP P=1 (rep1) v4 ↑/↓ | TCP P=1 (rep1) v6 ↑/↓ | TCP P=4 median v4 ↑/↓ | TCP P=4 median v6 ↑/↓ | UDP 600 (rep1) v4 ↑/↓, goodput (loss) | UDP 600 (rep1) v6 ↑/↓, goodput (loss) | UDP rep1 ceiling v4 ↑/↓ [pass/n; median loss] | UDP rep1 ceiling v6 ↑/↓ [pass/n; median loss] | max CV TCP P=4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WireGuard plain | нет | —/—/—/— | WireGuard/UDP | 2601 / 3266 | 2543 / 3142 | 3147 / 3192 | 3155 / 3150 | 600 (0.00%) / 600 (0.01%) | 600 (0.01%) / 600 (0.00%) | 1400 [1/1; 0.46%] / 1400 [1/1; 0.61%] | 1500 [1/1; 0.91%] / 1425 [1/1; 0.91%] | — |
| WireGuard + wg-obfuscator STUN | да | част./част./—/— | STUN-like/UDP | 529 / 506 | 528 / 497 | 523 / 508 | 517 / 491 | 544 (8.15%) / 541 (9.90%) | 556 (7.31%) / 536 (10.66%) | 450 [3/3; 0.60%] / 450 [2/3; 0.87%] | 450 [3/3; 0.77%] / 425 [3/3; 0.57%] | 3.60 |
| AmneziaWG mask-off | нет (контроль) | —/—/—/— | AWG/UDP | 2643 / 3106 | 3083 / 3121 | 3176 / 3112 | 3080 / 2975 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1500 [1/1; 0.71%] / 1525 [1/1; 0.63%] | 1600 [1/1; 0.93%] / 1575 [1/1; 0.72%] | — |
| AmneziaWG full 3.1 | да | да/да/част./— | AWG3.1/UDP | 2612 / 2639 | 2802 / 2603 | 2917 / 2612 | 3037 / 2715 | 600 (0.02%) / 600 (0.01%) | 600 (0.01%) / 600 (0.00%) | 1150 [3/3; 0.67%] / 1175 [2/3; 0.93%] | 1350 [3/3; 0.72%] / 1350 [2/3; 1.00%] | 8.00 |
| OpenVPN UDP userspace | нет | —/—/—/— | OpenVPN/UDP | 287 / 395 | 319 / 376 | 304 / 383 | 336 / 402 | 400 (33.32%) / 438 (19.34%) | 390 (34.89%) / 461 (23.21%) | 350 [1/1; 0.98%] / 400 [1/1; 0.14%] | 350 [1/1; 0.49%] / 400 [1/1; 0.39%] | — |
| OpenVPN UDP + DCO | нет | —/—/—/— | OpenVPN/UDP | 1384 / 1567 | 1415 / 1573 | 1951 / 1902 | 1824 / 1923 | 599 (0.09%) / 600 (0.07%) | 600 (0.03%) / 600 (0.03%) | 725 [1/1; 0.58%] / 700 [1/1; 0.20%] | 700 [1/1; 0.54%] / 750 [1/1; 0.79%] | — |
| OpenVPN UDP + stunnel DTLS | да | да/част./—/— | DTLS/UDP | 155 / 159 | 152 / 154 | 166 / 154 | 165 / 154 | 183 (69.35%) / 201 (65.57%) | 206 (65.35%) / 199 (63.29%) | 175 [3/3; 0.77%] / 200 [3/3; 0.93%] | 175 [3/3; 0.36%] / 200 [2/3; 0.39%] | 4.77 |
| OpenVPN TCP userspace | нет | —/—/—/— | OpenVPN/TCP | 309 / 401 | 317 / 406 | 355 / 360 | 317 / 363 | 489 (18.75%) / 485 (19.34%) | 517 (14.21%) / 567 (4.53%) | 375 [1/1; 0.47%] / 450 [1/1; 0.09%] | 350 [1/1; 0.15%] / 375 [1/1; 0.07%] | — |
| OpenVPN TCP + stunnel TLS 1.3 | да | да/част./—/— | TLS 1.3/TCP | 437 / 368 | 435 / 420 | 340 / 475 | 408 / 492 | 552 (8.09%) / 564 (5.94%) | 466 (22.36%) / 541 (9.75%) | 275 [2/3; 0.25%] / 300 [3/3; 0.27%] | 275 [3/3; 0.40%] / 250 [3/3; 0.28%] | 10.86 |
| IPsec strongSwan ESP | нет | —/—/—/— | ESP | 914 / 984 | 981 / 1102 | 976 / 1612 | 1009 / 1676 | 600 (0.04%) / 596 (0.73%) | 600 (0.01%) / 600 (0.05%) | 725 [1/1; 0.95%] / 725 [1/1; 0.14%] | 700 [1/1; 0.57%] / 725 [1/1; 0.18%] | — |
| IPsec strongSwan NAT-T | нет | —/—/—/— | ESP-in-UDP/4500 | 944 / 1041 | 973 / 1186 | 934 / 1583 | 1011 / 1573 | 599 (0.16%) / 599 (0.11%) | 600 (0.00%) / 597 (0.49%) | 700 [1/1; 0.73%] / 675 [1/1; 0.25%] | 700 [1/1; 0.77%] / 650 [1/1; 0.57%] | — |
| Xray VLESS + TLS + Vision (TUN) | да | да/част./—/— | TLS 1.3/TCP | 1257 / 904 | 1071 / 1018 | 1043 / 944 | 961 / 1026 | 404 (32.74%) / 560 (6.12%) | 326 (45.61%) / 599 (0.08%) | 200 [3/3; 0.73%] / 575 [2/3; 0.04%] | 175 [3/3; 0.68%] / 600 [1/3; 1.23%] | 2.49 |
| Xray VLESS + REALITY + Vision (TUN) | да | да/част./—/да | REALITY/TCP | 1266 / 907 | 1084 / 954 | 1058 / 939 | 956 / 1033 | 371 (38.09%) / 523 (12.62%) | 332 (44.76%) / 553 (7.86%) | 200 [3/3; 0.77%] / 450 [3/3; 0.83%] | 175 [3/3; 0.58%] / 400 [2/3; 0.86%] | 3.07 |
| Hysteria 2 QUIC TLS (TUN) | частично | да/част./—/— | QUIC/TLS/UDP | 1619 / 811 | 1647 / 898 | 1559 / 692 | 1530 / 755 | 323 (46.11%) / 573 (4.45%) | 324 (46.11%) / 583 (2.85%) | 250 [3/3; 0.73%] / 525 [3/3; 0.63%] | 250 [3/3; 0.67%] / 525 [3/3; 0.77%] | 6.48 |
| Hysteria 2 QUIC + Salamander (TUN) | да | да/да/част./— | Salamander/UDP | 716 / 726 | 719 / 774 | 800 / 720 | 760 / 759 | 307 (48.94%) / 566 (5.64%) | 315 (46.87%) / 566 (5.70%) | 225 [3/3; 0.27%] / 475 [3/3; 0.71%] | 250 [3/3; 0.57%] / 500 [2/3; 0.98%] | 4.64 |
| OpenVPN-XOR build UDP, scramble off | нет (парный контроль) | —/—/—/— | OpenVPN/UDP | 258 / 396 | 322 / 393 | 335 / 432 | 328 / 359 | 399 (33.52%) / 441 (23.61%) | 327 (44.81%) / — (—%) | 350 [1/1; 0.76%] / 375 [1/1; 0.03%] | 350 [1/1; 0.40%] / 350 [1/1; 0.00%] | — |
| OpenVPN UDP + XOR | да, legacy | част./—/—/— | scrambled OpenVPN/UDP | 260 / 313 | 263 / 302 | 247 / 311 | 264 / 319 | 312 (47.38%) / — (—%) | 288 (52.13%) / — (—%) | 300 [1/3; 1.85%] / 300 [3/3; 0.47%] | 275 [3/3; 0.18%] / 325 [3/3; 0.13%] | 8.44 |
| OpenVPN-XOR build TCP, scramble off | нет (парный контроль) | —/—/—/— | OpenVPN/TCP | 335 / 409 | 324 / 336 | 316 / 372 | 335 / 355 | 497 (17.46%) / 475 (9.63%) | 542 (9.81%) / 512 (12.95%) | 350 [1/1; 0.22%] / 525 [1/1; 0.82%] | 450 [1/1; 0.19%] / 450 [1/1; 0.26%] | — |
| OpenVPN TCP + XOR | да, legacy | част./—/—/— | scrambled OpenVPN/TCP | 262 / 251 | 265 / 300 | 239 / 313 | 262 / 282 | 324 (45.42%) / 448 (25.12%) | 354 (40.40%) / 390 (31.83%) | 300 [3/3; 0.32%] / 325 [2/3; 0.09%] | 275 [3/3; 0.02%] / 325 [1/3; 1.76%] | 9.07 |
| OpenVPN TCP + Cloak | да | да/да/част./да | Cloak direct, 4×TCP/443 | 414 / 406 | 424 / 424 | 431 / 492 | 442 / 445 | 543 (9.45%) / 510 (14.72%) | 551 (8.00%) / 543 (9.45%) | 375 [2/3; 0.27%] / 325 [2/3; 0.61%] | 375 [2/3; 0.54%] / 475 [1/3; 8.56%] | 10.58 |
| OpenVPN UDP + Cloak (experimental) | да | да/да/част./да | Cloak direct, 4×TCP/443 | 223 / 277 | 264 / 229 | 263 / 259 | 244 / 265 | 302 (49.77%) / 333 (41.84%) | 307 (48.23%) / 381 (36.57%) | 250 [3/3; 0.75%] / 300 [1/3; 1.75%] | 275 [1/3; 1.60%] / 275 [2/3; 0.71%] | 11.14 |
| WireGuard + Cloak (experimental) | да | да/да/част./да | Cloak direct, 4×TCP/443 | 372 / 421 | 389 / 419 | 389 / 405 | 383 / 402 | 356 (39.96%) / 490 (18.49%) | 356 (39.92%) / 491 (18.05%) | 325 [1/3; 1.22%] / 400 [2/3; 0.71%] | 300 [3/3; 0.27%] / 425 [1/3; 1.63%] | 1.46 |
| Qeli 0.8.0 tcp-plain-raw + Recordizer | да (Recordizer обязателен) | —/да/да/— | Qeli/tcp | 1819 / 1687 | 1664 / 1726 | 1705 / 1689 | 1825 / 1807 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1300 [2/3; 0.99%] / 1450 [1/3; 1.29%] | 1350 [2/3; 0.98%] / 1425 [3/3; 0.62%] | 6.46 |
| Qeli 0.8.0 tcp-faketls + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/tcp | 1839 / 1598 | 1849 / 1777 | 1752 / 1695 | 1823 / 1820 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1225 [3/3; 0.75%] / 1400 [3/3; 0.91%] | 1300 [2/3; 0.90%] / 1475 [3/3; 0.78%] | 2.99 |
| Qeli 0.8.0 tcp-padding + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/tcp | 1801 / 1668 | 1794 / 1744 | 1751 / 1683 | 1841 / 1799 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1175 [3/3; 0.46%] / 1450 [2/3; 0.86%] | 1325 [2/3; 0.92%] / 1500 [2/3; 0.93%] | 4.20 |
| Qeli 0.8.0 tcp-frag + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/tcp | 1834 / 1633 | 1861 / 1682 | 1774 / 1684 | 1834 / 1800 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1350 [1/3; 1.20%] / 1425 [3/3; 0.70%] | 1250 [3/3; 0.43%] / 1500 [2/3; 0.78%] | 2.35 |
| Qeli 0.8.0 tcp-obfs + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/tcp | 1291 / 1372 | 1414 / 1397 | 1256 / 1293 | 1371 / 1386 | 600 (0.00%) / 600 (0.01%) | 599 (0.05%) / 600 (0.00%) | 925 [1/3; 1.07%] / 1200 [1/3; 1.27%] | 925 [2/3; 0.88%] / 1200 [2/3; 0.90%] | 3.54 |
| Qeli 0.8.0 tcp-reality + Recordizer | да (Recordizer обязателен) | да/да/да/да | Qeli/tcp | 1797 / 1636 | 1829 / 1799 | 1741 / 1705 | 1834 / 1786 | 599 (0.05%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1275 [3/3; 0.65%] / 1400 [3/3; 0.66%] | 1275 [2/3; 0.85%] / 1450 [3/3; 0.61%] | 2.21 |
| Qeli 0.8.0 tcp-reality-tls + Recordizer | да (Recordizer обязателен) | да/да/да/да | Qeli/tcp | 1116 / 952 | 1108 / 947 | 1212 / 1066 | 1219 / 1074 | 599 (0.00%) / 600 (0.00%) | 599 (0.04%) / 600 (0.00%) | 925 [3/3; 0.76%] / 1125 [2/3; 0.84%] | 975 [2/3; 0.89%] / 1200 [1/3; 1.18%] | 3.00 |
| Qeli 0.8.0 udp-faketls + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/udp | 490 / 508 | 488 / 509 | 484 / 528 | 458 / 507 | 479 (20.20%) / 516 (13.94%) | 422 (29.71%) / 532 (11.36%) | 350 [3/3; 0.59%] / 450 [3/3; 0.29%] | 325 [3/3; 0.18%] / 450 [3/3; 0.41%] | 4.54 |
| Qeli 0.8.0 udp-padding + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/udp | 452 / 498 | 480 / 496 | 499 / 513 | 468 / 512 | 489 (18.51%) / 520 (13.02%) | 471 (21.43%) / 528 (11.97%) | 375 [2/3; 0.90%] / 450 [3/3; 0.31%] | 375 [2/3; 0.74%] / 500 [1/3; 1.70%] | 5.57 |
| Qeli 0.8.0 udp-quic + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/udp | 472 / 523 | 494 / 528 | 491 / 520 | 473 / 506 | 504 (16.16%) / 522 (12.90%) | 488 (18.70%) / 527 (12.48%) | 350 [3/3; 0.54%] / 475 [2/3; 0.84%] | 325 [3/3; 0.06%] / 475 [3/3; 0.84%] | 5.85 |
| Qeli 0.8.0 tcp-obfs-awg + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/tcp | 1300 / 1367 | 1279 / 1408 | 1312 / 1300 | 1407 / 1389 | 600 (0.01%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 875 [3/3; 0.38%] / 1175 [2/3; 0.96%] | 875 [3/3; 0.43%] / 1175 [3/3; 0.71%] | 4.53 |
| Qeli 0.8.0 udp-faketls-awg + Recordizer | да (Recordizer обязателен) | да/да/да/— | Qeli/udp | 489 / 512 | 481 / 517 | 479 / 509 | 479 / 515 | 414 (31.11%) / 560 (6.48%) | 474 (19.85%) / 532 (11.03%) | 375 [1/3; 1.68%] / 450 [3/3; 0.31%] | 350 [3/3; 0.27%] / 475 [2/3; 0.33%] | 5.63 |

`TCP P=1` и `UDP 600` — полный `rep1`. Для masked-режимов TCP `P=4` — медиана трёх повторов; для controls — единственное измерение. CSV содержит `n/min/median/max/CV/span`. `max CV TCP P=4` показывается только при `n>1`; `—` у controls означает отсутствие повторов, а не нулевой разброс.

## 7. CPU, RSS и kernel drops

| Продукт / режим | TCP P=4 CPU VM S/C, % | UDP ref CPU VM S/C, % | TCP P=4 VPN CPU S/C, % VM | UDP ref VPN CPU S/C, % VM | RSS max S/C, MiB | softnet drops S/C |
| --- | --- | --- | --- | --- | --- | --- |
| WireGuard plain | 80.1 / 82.3 | 76.7 / 78.9 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| WireGuard + wg-obfuscator STUN | 69.9 / 71.5 | 62.3 / 61.6 | 32.2 / 32.6 | 25.6 / 25.1 | 1.1 / 1.1 | 0 / 0 |
| AmneziaWG mask-off | 78.7 / 81.7 | 78.9 / 78.4 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| AmneziaWG full 3.1 | 75.9 / 78.3 | 76.0 / 74.3 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| OpenVPN UDP userspace | 55.5 / 52.2 | 52.2 / 48.8 | 45.7 / 41.7 | 36.5 / 33.0 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + DCO | 57.6 / 54.9 | 38.3 / 38.6 | 0.0 / 0.0 | 0.0 / 0.0 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + stunnel DTLS | 77.7 / 55.9 | 72.4 / 53.8 | 71.3 / 48.7 | 62.9 / 42.3 | 19.9 / 19.5 | 0 / 0 |
| OpenVPN TCP userspace | 55.7 / 57.8 | 57.8 / 58.8 | 45.0 / 43.4 | 37.7 / 38.0 | 9.9 / 9.7 | 0 / 0 |
| OpenVPN TCP + stunnel TLS 1.3 | 85.0 / 85.2 | 69.9 / 69.6 | 73.5 / 74.3 | 56.3 / 54.3 | 20.0 / 19.6 | 0 / 0 |
| IPsec strongSwan ESP | 64.2 / 60.8 | 39.5 / 39.3 | 0.0 / 0.0 | 0.0 / 0.0 | 10.3 / 10.4 | 0 / 0 |
| IPsec strongSwan NAT-T | 64.9 / 60.5 | 37.0 / 36.1 | 0.0 / 0.0 | 0.0 / 0.0 | 10.3 / 10.4 | 0 / 0 |
| Xray VLESS + TLS + Vision (TUN) | 22.1 / 75.8 | 57.4 / 62.3 | 15.2 / 65.7 | 42.1 / 46.5 | 51.3 / 97.9 | 0 / 0 |
| Xray VLESS + REALITY + Vision (TUN) | 21.0 / 76.1 | 59.8 / 62.9 | 15.2 / 65.8 | 44.2 / 47.4 | 55.2 / 99.1 | 0 / 0 |
| Hysteria 2 QUIC TLS (TUN) | 69.1 / 89.8 | 71.1 / 69.4 | 62.7 / 80.0 | 56.9 / 56.1 | 109.9 / 116.7 | 0 / 0 |
| Hysteria 2 QUIC + Salamander (TUN) | 68.1 / 86.4 | 71.5 / 70.0 | 58.7 / 76.6 | 57.2 / 57.3 | 43.0 / 59.6 | 0 / 0 |
| OpenVPN-XOR build UDP, scramble off | 56.3 / 50.8 | 51.6 / 46.4 | 46.6 / 41.6 | 33.7 / 30.5 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + XOR | 54.5 / 53.2 | 52.9 / 51.9 | 46.1 / 43.4 | 40.2 / 35.3 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN-XOR build TCP, scramble off | 55.2 / 55.8 | 60.9 / 61.3 | 44.3 / 43.7 | 39.5 / 42.1 | 9.9 / 9.7 | 0 / 0 |
| OpenVPN TCP + XOR | 53.4 / 54.9 | 58.4 / 58.8 | 43.2 / 44.7 | 41.5 / 41.3 | 10.0 / 9.6 | 0 / 0 |
| OpenVPN TCP + Cloak | 77.3 / 78.0 | 71.5 / 69.8 | 71.5 / 72.6 | 58.4 / 56.6 | 123.7 / 90.6 | 0 / 0 |
| OpenVPN UDP + Cloak (experimental) | 81.4 / 82.0 | 77.6 / 77.4 | 76.3 / 76.6 | 64.9 / 64.0 | 37.4 / 33.7 | 0 / 0 |
| WireGuard + Cloak (experimental) | 81.9 / 83.2 | 73.7 / 75.9 | 47.6 / 51.0 | 36.8 / 41.1 | 25.2 / 61.5 | 0 / 0 |
| Qeli 0.8.0 tcp-plain-raw + Recordizer | 72.7 / 81.6 | 70.8 / 72.5 | 62.8 / 70.6 | 47.5 / 49.5 | 117.5 / 93.6 | 0 / 0 |
| Qeli 0.8.0 tcp-faketls + Recordizer | 74.1 / 82.1 | 69.6 / 70.9 | 64.1 / 70.4 | 46.0 / 48.5 | 118.5 / 94.1 | 0 / 0 |
| Qeli 0.8.0 tcp-padding + Recordizer | 73.8 / 83.1 | 70.2 / 71.1 | 63.6 / 70.6 | 46.2 / 48.6 | 116.7 / 93.9 | 0 / 0 |
| Qeli 0.8.0 tcp-frag + Recordizer | 76.0 / 82.7 | 71.3 / 71.0 | 65.6 / 71.2 | 47.8 / 49.2 | 117.4 / 94.1 | 0 / 0 |
| Qeli 0.8.0 tcp-obfs + Recordizer | 71.5 / 80.1 | 67.5 / 71.8 | 61.9 / 70.5 | 48.3 / 52.3 | 120.4 / 97.7 | 0 / 0 |
| Qeli 0.8.0 tcp-reality + Recordizer | 74.7 / 82.3 | 69.5 / 70.7 | 64.4 / 70.3 | 46.2 / 49.1 | 115.3 / 95.3 | 0 / 0 |
| Qeli 0.8.0 tcp-reality-tls + Recordizer | 62.7 / 70.9 | 70.4 / 71.8 | 54.9 / 61.8 | 50.1 / 52.0 | 123.5 / 106.8 | 0 / 0 |
| Qeli 0.8.0 udp-faketls + Recordizer | 71.7 / 78.5 | 65.7 / 67.5 | 64.8 / 70.3 | 49.7 / 52.2 | 160.9 / 53.0 | 0 / 0 |
| Qeli 0.8.0 udp-padding + Recordizer | 72.1 / 79.4 | 68.0 / 70.2 | 65.3 / 71.1 | 51.4 / 54.6 | 170.9 / 51.8 | 0 / 0 |
| Qeli 0.8.0 udp-quic + Recordizer | 71.8 / 79.6 | 66.6 / 68.4 | 64.7 / 70.9 | 50.1 / 52.6 | 168.7 / 51.5 | 0 / 0 |
| Qeli 0.8.0 tcp-obfs-awg + Recordizer | 70.5 / 80.5 | 66.2 / 70.6 | 62.4 / 71.4 | 47.2 / 50.6 | 122.2 / 97.7 | 0 / 0 |
| Qeli 0.8.0 udp-faketls-awg + Recordizer | 72.2 / 80.8 | 67.5 / 69.0 | 63.9 / 71.7 | 50.8 / 53.5 | 165.2 / 51.8 | 0 / 0 |

CPU VM — общая загрузка двухъядерной VM. Таблица агрегирует повторяемые TCP `P=4` и UDP-окна на `rep1 ceiling`. VPN userspace CPU не отражает kernel datapath WireGuard/AWG; для них основная метрика — CPU VM. RSS суммирует underlying VPN и оболочку. `softnet drops` суммированы по всем TCP-окнам и UDP ceiling; ноль не исключает потерь внутри tunnel protocol, отражённых iperf.

## 8. Парная цена маскировки

| Парное сравнение | Контроль TCP P=1 rep1 avg | Маскированный TCP P=1 rep1 avg | Изменение |
| --- | --- | --- | --- |
| WireGuard: plain → wg-obfuscator STUN | 2888 | 515 | -82.2% |
| AmneziaWG: mask-off → full 3.1 | 2988 | 2664 | -10.8% |
| OpenVPN XOR UDP: patched control → XOR | 342 | 284 | -17.0% |
| OpenVPN XOR TCP: patched control → XOR | 351 | 269 | -23.3% |
| OpenVPN TCP: userspace → stunnel TLS | 358 | 415 | +15.9% |
| Xray: VLESS TLS Vision → REALITY Vision | 1062 | 1053 | -0.9% |
| Hysteria 2: QUIC TLS → Salamander | 1244 | 734 | -41.0% |

Парное сравнение использует только одинаковые окна `rep1`, TCP `P=1`, IPv4/IPv6 и upload/download. Это сохраняет равный `n=1` для controls и masked-профилей; для устойчивости masked-режимов отдельно приведён CV повторяемого TCP `P=4`.

## 9. Конфигурации режимов

### 9.1. Общая криптография

- OpenVPN userspace/XOR/Cloak: TLS 1.3, X25519, data cipher `CHACHA20-POLY1305`, `tun-mtu 1400`, `mssfix 1360`. XOR выполняется поверх нормальной AEAD-защиты; `cipher none` не использовался.
- OpenVPN DCO: тот же согласованный набор cipher/TLS, datapath kernel DCO.
- strongSwan: ChaCha20-Poly1305; режим DTLS исключён после доказанного preflight-дефекта IPv4, а не заменён фиктивным числом.
- Xray: VLESS Vision через TUN; TLS-вариант с TLS 1.3/browser fingerprint, REALITY-вариант с `www.cloudflare.com:443`, одинаковый TUN MTU 1400.
- Hysteria 2: QUIC/TLS и QUIC+Salamander; bandwidth limit поднят до **10 Gbit/s**, то есть выше фактической tunnel capacity стенда.

### 9.2. OpenVPN-XOR и Cloak

- XOR: OpenVPN 2.7.6 с пятью патчами Tunnelblick commit `c9c73dca6c99afbba14b53e291b18f044210a1b5`; `scramble obfuscate`; DCO выключен. Каждая XOR-строка имеет парный контроль на том же patched binary без `scramble`.
- Cloak 2.12.0: `Transport=direct`, `BrowserSig=chrome`, `NumConn=4`, `EncryptionMethod=chacha20-poly1305`, `ServerName=RedirAddr=www.cloudflare.com`, `KeepAlive=0`, внешний TCP/443.
- OpenVPN UDP+Cloak и WireGuard+Cloak помечены experimental. PCAP preflight доказал отсутствие прямого UDP bypass: между `.11` и `.10` были только четыре Cloak TCP-соединения к 443.
- Неавторизованный HTTPS probe всех Cloak-схем получил HTTP 200 от `RedirAddr`, не upstream VPN.

### 9.3. Qeli 0.8.0 и обязательный Recordizer

Во всех 12 Qeli-профилях `obf.recordizer.policy=required`. Если согласование Recordizer не произошло, соединение не должно перейти к измерениям. Preflight подтвердил активацию во всех 12 случаях.

- `obf.recordizer.policy = required`
- `obf.recordizer.batch.delay_min_ms = 2`
- `obf.recordizer.batch.delay_max_ms = 8`
- `obf.recordizer.batch.max_packets = 16`
- `obf.recordizer.batch.max_queue_bytes = 262144`
- `obf.recordizer.record.max_payload_bytes = 0`
- `obf.recordizer.record.small_min_ratio = 0.25`
- `obf.recordizer.record.small_max_ratio = 0.875`
- `obf.recordizer.record.full_probability = 0.72`
- `obf.recordizer.fragment.enabled = true`
- `obf.recordizer.fragment.reassembly_timeout_ms = 3000`
- `obf.recordizer.fragment.max_inflight_packets = 64`
- `obf.recordizer.fragment.max_reassembly_bytes = 4194304`
- `obf.recordizer.fragment.max_fragments_per_packet = 64`

Дополнительные параметры профиля: отдельный padding 32–256 bytes с probability 0.8, если он включён; heartbeat 15 s; AWG `jc=4`, `jmin=40`, `jmax=200`; dual-stack pools `10.9.0.0/24 + fd42:206:1::/64` для TCP и `10.10.0.0/24 + fd42:206:2::/64` для UDP; TUN MTU 1400. Test credentials, identity keys, XOR/Cloak secrets и Qeli obfs key в отчёт не экспортируются.

### 9.4. WireGuard, AmneziaWG, strongSwan, Xray и Hysteria 2

- WireGuard plain: MTU 1400, `PersistentKeepalive=25`. В профиле wg-obfuscator внутренний WireGuard имеет MTU 1380 и локальный endpoint; внешний обфускатор использует UDP/443, client `masking=STUN`, server `masking=AUTO`, `allow-clean=false`, `max-dummy=4`, `idle-timeout=300`.
- AmneziaWG mask-off: MTU 1380, `Jc/Jmin/Jmax=0`, `S1..S4=0`, фиксированные `H1..H4=1..4`, `RandomTrailers=off`, `AdvancedSecurity=off`. Full 3.1: MTU 1360, `Jc=8`, `Jmin=40`, `Jmax=70`, `S1/S2/S3/S4=86/73/64/32`, заданные нестандартные `H1..H4`, `HeaderProtectionKey`, `ContentPaddingAddition=16-64`, `RandomTrailers=on`, `AdvancedSecurity=on`.
- strongSwan: IKEv2, PSK, tunnel mode, `mobike=no`, без reauth/rekey во время теста. Использованы `chacha20poly1305-prfsha256-curve25519` для IKE и `chacha20poly1305-curve25519` для ESP; ESP и NAT-T различаются `encap=no/yes`.
- Xray: VLESS с `xtls-rprx-vision`, transport `raw`, TUN MTU 1400, dual-stack routes. TLS-профиль использует TLS 1.3 и fingerprint Chrome; REALITY — fingerprint Chrome, target/SNI `www.cloudflare.com:443`, short ID и X25519 keypair. Порты стенда: 24443 для TLS и 24444 для REALITY.
- Hysteria 2: TUN MTU 1400, QUIC, окна stream 8 MiB и connection 20 MiB, `maxIncomingStreams=1024`, PMTUD включён, keepalive 10 s на клиенте. Профили различаются наличием Salamander; порты 24445/24446. Во время preflight лимиты `up/down` увеличены с 1 до 10 Gbit/s, чтобы конфигурационный предел не ограничивал измерение. TLS-клиент использовал лабораторный сертификат с `insecure=true`; это параметр тестового стенда, а не рекомендация для production.
- Все WG/AWG, Xray, Hysteria и Qeli конфигурации маршрутизировали одинаковые контрольные IPv4/IPv6 назначения. Секретные ключи и пароли в отчёт не включены.

## 10. PCAP/preflight и ограничения DPI-вывода

- Все 19 новых/изменённых профилей прошли IPv4/IPv6 TCP/UDP smoke: OpenVPN-XOR (4), Cloak (3), Qeli Recordizer (12).
- PCAP Cloak содержал только TCP/443; прямых UDP/11965 или UDP/51850 между VM не было.
- Первые OpenVPN payload bytes в patched-control содержали узнаваемую исходную структуру, а `scramble obfuscate` изменял их; при этом аутентификация и `CHACHA20-POLY1305` оставались включены.
- H/B/T/A — техническая оценка включённых механизмов, а не вероятность обнаружения. Для публикационного утверждения «не определяется DPI» нужны независимые классификаторы, разные сети, длительные потоки и active-probe corpus. Здесь корректно утверждать только, какие поверхности маскируются и какой ценой throughput/CPU.

### 10.1. Ограничения интерпретации

- Control-режимы имеют `n=1`; их межпрогонный разброс не измерен. Masked-режимы имеют `n=3` только для TCP `P=4` и проверочных UDP-точек; TCP `P=1` и UDP 600 относятся к `rep1`.
- Для UDP сокращённые повторы проверяли найденную ставку и первую не прошедшую ступень, но не искали заново более низкий устойчивый потолок. Поэтому `pass<n` нельзя читать как подтверждённый трёхкратный ceiling.
- Стенд не моделирует WAN-задержку, jitter, packet reordering, внешние bottleneck и длительную конкурирующую нагрузку.
- Внешний DPI-классификатор, corpus active probes и многосетевой захват в этот прогон не входили. H/B/T/A — описание конфигурации и наблюдаемого preflight/PCAP, не вероятность обнаружения.
- Групповые средние объединяют разные transports, datapaths и уровни H/B/T/A. Они предназначены для компактной сводки измеренных конфигураций и не заменяют построчное сравнение.

Артефакт preflight: `release\competitor_repeat_080_preflight.json`.

## 11. Ошибки и исключения

- `strongswan/natt-stunnel-dtls`: The fixed strongSwan 6.0.7 + stunnel 5.80 DTLS preflight establishes IKE/CHILD SA and IPv6, but IPv4 traffic does not pass through the wrapper. It remains excluded rather than publishing an invalid number.

`strongswan/natt-stunnel-dtls` не получил скорость: комбинация устанавливала IKE/CHILD SA и IPv6, но не пропускала IPv4 через stunnel 5.80 DTLS. Режим исключён из числового сравнения, поскольку полный dual-stack gate не прошёл.

## 12. Непрерывность прогона и чекпоинты

- Во время полного `rep1` заполнился локальный диск управляющей машины. Процесс прервался в `qeli/udp-quic+recordizer` во время ещё не сохранённого TCP `P=4` IPv6 upload-окна. Атомарный JSON сохранил все предыдущие чекпоинты; после очистки диска незаписанное окно было измерено заново, затем режим и проход завершились.
- Во время сокращённых повторов foreground-launcher достиг внешнего часового лимита команды. Python-процесс некоторое время продолжал работу, затем остановился. Runner был заново запущен в фоне из атомарного чекпоинта: завершённые режимы пропущены, незавершённое окно измерено заново.
- При возобновлениях VM не перезагружались: boot ID server/client остались `cf04df08-770d-4ce9-a32a-222e5dd7c319` / `ffbf54d8-6c2d-46ed-89ba-36db7b2b24e7` от начального baseline до финального. Stderr фонового завершения пуст.

## 13. Выводы по измеренным данным

1. До матрицы baseline имел CV upload **1.39%** и download **0.64%**; после матрицы — **1.18%** и **0.95%**. Дрейф медианы: upload **+1.48%**, download **-1.71%**.
2. Выполнены 34 режима в `rep1`; для 25 masked-режимов выполнены `rep2/rep3`. Все 12 Qeli-профилей измерены с `obf.recordizer.policy=required`, и для всех 12 зафиксирован runtime-маркер активации.
3. Средние значения групп Qeli: быстрые TCP-профили — **1767 Mbit/s TCP P=4** и **1365 Mbit/s UDP rep1 ceiling**; тяжёлые TCP-профили — **1274 / 1048 Mbit/s**; нативные UDP-профили — **496 / 409 Mbit/s**.
4. Максимальное среднее TCP `P=4` среди masked-строк в этом стенде зафиксировано у **AmneziaWG full 3.1: 2820 Mbit/s**. Эта строка, Qeli и userspace-обёртки используют разные datapaths и разные механизмы H/B/T/A; числовой максимум относится только к протестированной конфигурации и стенду.
5. Ставка `rep1` UDP ceiling подтвердилась 3/3 для **54/100** направлений masked-режимов. Для Qeli подтверждение 3/3 получено для **24/48** направлений; в остальных направлениях сокращённый план не определял новый более низкий трёхкратно подтверждённый ceiling.
6. VLESS представлен TLS+Vision и REALITY+Vision; Hysteria 2 — QUIC TLS и QUIC+Salamander; OpenVPN — controls, DCO, stunnel, XOR и Cloak; WireGuard — plain, wg-obfuscator и Cloak; AmneziaWG — mask-off и full 3.1; strongSwan — ESP и NAT-T. `strongswan/natt-stunnel-dtls` исключён по указанному dual-stack preflight-дефекту.
7. Этот прогон не измерял вероятность обнаружения внешним DPI. По его данным можно сравнивать throughput, CPU/RSS, kernel counters, повторяемость TCP, подтверждение UDP-точек и наличие настроенных H/B/T/A-механизмов.

## 14. Артефакты и воспроизводимость

- Сырые результаты: `release\competitor_repeat_080_results_2026-09-01.json`, SHA256 `09cbfdf33ec9bdbfae2f769e0b91d0f7d8144b295a687ea93c362c6df434c435`.
- CSV-сводка: `release\competitor_repeat_080_summary_2026-09-01.csv`.
- Краткая Markdown-сводка: `release\competitor_repeat_080_summary_2026-09-01.md`.
- Runner: `scripts/competitor_bench/repeat_080_benchmark.py`.
- Runtime: `scripts/competitor_bench/repeat_080_runtime_ext.py`.
- Qeli profiles: `scripts/competitor_bench/repeat_080_qeli.py`.
- Reboot evidence: `release\competitor_repeat_080_reboot_2026-09-01.json`.
- Preflight/PCAP evidence: `release\competitor_repeat_080_preflight.json`.
- Preparation and hashes: `release\competitor_repeat_080_prepare.json` и `release\competitor_artifacts_lock.json`.

| Компонент | Версия | ref | SHA256 |
| --- | --- | --- | --- |
| wg-obfuscator | 1.6 | v1.6 | af30264278c70c2e53ad3234e8050686b3bef4f6564edc9fb068ea8c885b8354 |
| amneziawg-kernel | 3.1.20260812 | v3.1.20260812@46803204e7ec3b068199cd671143bec661d3fe21 | a85817876676d5933385712657bd5525a0a2939baaf057f68e3629c7b4553c82 |
| amneziawg-tools | 3.1.20260812 | v3.1.20260812@ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 | dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493 |
| openvpn | 2.7.6 | official-community-release | 10e24a9385f23cc38cc5cf448f3ca0769f939bc4cbecc4f4647d7e006e52db74 |
| stunnel | 5.80 | official-release | 6d0841d48de07cbbaf4a055919065bf7bb5ebc63cc15c97a2c76caa2bf285513 |
| strongswan | 6.0.7 | official-release | e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55 |
| xray | 26.3.27 | v26.3.27 | 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae |
| hysteria | 2.12.2 | app/v2.12.2 | 6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94 |
| Qeli | 0.8.0 | local release/dist/v0.8.0 | e376bc27eaae30591882648bf7556c70587b2f24a393478df0b3d5d3615b2c49 |
| Cloak client | 2.12.0 | official v2.12.0 | ceabde7e13cf0e9dd7f53f811d6f24c1246755911b06aa40fb541041016348e3 |
| Cloak server | 2.12.0 | official v2.12.0 | f2bea92c99195ac26cd5749e80d07339d5582c103f73934b414150c6070dae4e |
| OpenVPN-XOR binary | 2.7.6 | c9c73dca6c99afbba14b53e291b18f044210a1b5 | ec627f24d7f741d4a7553e91a415dbe834374f1c7aabd329fef69c76a889eddd |

Официальные источники конфигураций и ограничений: OpenVPN <https://openvpn.net/community-resources/>, Tunnelblick XOR warning <https://www.tunnelblick.net/cOpenvpn_xorpatch.html>, Cloak <https://github.com/cbeuw/Cloak>, Xray <https://github.com/XTLS/Xray-core>, Hysteria <https://v2.hysteria.network/>, strongSwan <https://docs.strongswan.org/>.
