# Обфускация и PACKET_MUX recordizer

В этом руководстве разобрано, как накладываются уровни маскировки, как настраивать
транспорт-независимый recordizer и какие сочетания безопасны. Полный справочник ключей находится
в [CONFIG.md](CONFIG.md), измеренные ограничения — в [DPI-AUDIT.md](DPI-AUDIT.md).

## 1. Что меняет recordizer

В legacy data-plane один внутренний IPv4/IPv6-пакет обычно превращался в одну зашифрованную
qeli-запись. Стабильная связь границ и размеров может быть одним из признаков статистического
DPI-классификатора. Согласуемый `PACKET_MUX_V1` меняет эту связь до шифрования:

- несколько внутренних пакетов могут попасть в одну зашифрованную запись;
- один внутренний пакет может быть разделён между несколькими зашифрованными записями;
- меняются целевой размер записи и deadline накопления batch;
- все mux-заголовки находятся внутри AEAD `PacketCodec` и на проводе не видны.

Важен порядок обработки:

```text
внутренний IPv4/IPv6-пакет
  -> PACKET_MUX recordizer
  -> padding / traffic normalization
  -> шифрование PacketCodec
  -> выбранный carrier (plain, fake-TLS, Reality/H2, obfs/WS или UDP/QUIC shape)
  -> фрагментация carrier/path при необходимости
```

Recordizer — не транспортный режим и не делает внешние carriers одинаковыми. В частности,
`plain` остаётся заметным high-entropy потоком, fake-TLS не становится настоящим TLS, QUIC shape
не становится настоящим HTTP/3, а неавторизованные active probes мостит на target только Reality.

## 2. Рекомендуемый дефолт

Добавляйте этот блок в каждый новый серверный профиль. Это поставляемые сбалансированные значения:

```ini
obf.recordizer.policy = prefer
obf.recordizer.batch.delay_min_ms = 2
obf.recordizer.batch.delay_max_ms = 8
obf.recordizer.batch.max_packets = 16
obf.recordizer.batch.max_queue_bytes = 262144
obf.recordizer.record.max_payload_bytes = 0
obf.recordizer.record.small_min_ratio = 0.25
obf.recordizer.record.small_max_ratio = 0.875
obf.recordizer.record.full_probability = 0.72
obf.recordizer.fragment.enabled = true
obf.recordizer.fragment.reassembly_timeout_ms = 3000
obf.recordizer.fragment.max_inflight_packets = 64
obf.recordizer.fragment.max_reassembly_bytes = 4194304
obf.recordizer.fragment.max_fragments_per_packet = 64
```

Блоком владеет сервер: эффективная конфигурация приходит клиенту в аутентифицированном ответе
AUTH. Клиентских ключей `obf.recordizer.*` нет, qeli-ссылки менять не нужно. Изменение конфига
начинает действовать после переподключения сессий.

Во время перехода используйте `prefer`: recordizer включится для клиента, объявившего
`PACKET_MUX_V1`, а старый клиент останется на legacy data-plane. Переходите на `required` только
после обновления ядер всех клиентов; старый клиент тогда будет отклонён до выдачи адреса. `off`
явно возвращает legacy-связь «один пакет — одна запись».

## 3. Все параметры

| Ключ | Дефолт | Назначение и ограничения |
|---|---:|---|
| `obf.recordizer.policy` | `off` в схеме; `prefer` в поставляемых шаблонах | `off`, `prefer` или `required`; политика согласования описана выше |
| `obf.recordizer.batch.delay_min_ms` | `2` | нижняя граница случайного flush deadline, запускаемого первым пакетом очереди |
| `obf.recordizer.batch.delay_max_ms` | `8` | верхняя граница deadline; не меньше `delay_min_ms`; `0/0` отправляет сразу |
| `obf.recordizer.batch.max_packets` | `16` | максимум mux-фреймов в одной записи; строго больше нуля |
| `obf.recordizer.batch.max_queue_bytes` | `262144` | жёсткий предел памяти очереди/записи на направление, `64..=4194304` байт |
| `obf.recordizer.record.max_payload_bytes` | `0` | `0` выбирает максимальный безопасный plaintext по активному carrier/path; явное значение ограничивается этим budget и должно быть `64..=MAX_TUNNEL_MTU` |
| `obf.recordizer.record.small_min_ratio` | `0.25` | минимальная случайная неполная цель как доля безопасного payload ceiling |
| `obf.recordizer.record.small_max_ratio` | `0.875` | максимальная неполная цель; должно выполняться `0 < min <= max <= 1` |
| `obf.recordizer.record.full_probability` | `0.72` | вероятность выбрать полный безопасный размер вместо неполной цели, `0..=1` |
| `obf.recordizer.fragment.enabled` | `true` | разрешает одному внутреннему пакету пересекать границы записей; не отключайте, если не гарантировано помещение пакета целиком |
| `obf.recordizer.fragment.reassembly_timeout_ms` | `3000` | время жизни незавершённой сборки внутреннего пакета; строго больше нуля |
| `obf.recordizer.fragment.max_inflight_packets` | `64` | максимум незавершённых packet ID на направление; строго больше нуля |
| `obf.recordizer.fragment.max_reassembly_bytes` | `4194304` | жёсткий общий предел памяти reassembly на направление; не меньше 64 байт |
| `obf.recordizer.fragment.max_fragments_per_packet` | `64` | максимум mux-фрагментов одного внутреннего пакета; строго больше нуля |

Целевой размер — это порог отправки, а не padding сам по себе. Редкий batch может уйти меньше
цели по истечении deadline. Padding и traffic normalization выполняются после recordizer и могут
увеличить зашифрованную запись до безопасного carrier budget.

## 4. Совместимость с остальными параметрами маскировки

| Функция | Совместима? | Взаимодействие |
|---|---|---|
| TCP `plain` | Да | Корреляция границ снижается, но внешний поток остаётся немаскированным high-entropy трафиком. Используйте только в доверенных сетях. |
| TCP `fake-tls` | Да | Внутренняя связь скрыта; синтаксис fake-TLS и поведение при active probe остаются отдельными признаками. |
| TCP `reality-tls` / Reality/H2 | Да | Recordizer работает внутри настоящего TLS/H2. Его batch delay и batching H2 carrier могут складываться на редком трафике. |
| TCP `obfs` с WebSocket или без него | Да | Recordizer находится внутри obfs/WS carrier; WS-сессия от этого не воспроизводит прикладную семантику браузера. |
| UDP `fake-tls` / `obfs` | Да | Payload budget вычисляется из UDP carrier и PMTU. Большой batch усиливает потери: одна потерянная датаграмма может содержать несколько внутренних пакетов. |
| `obf.quic.enabled` | Да, только UDP | Overhead QUIC shape учтён в автоматическом budget. Это по-прежнему форма QUIC, не настоящий QUIC/HTTP/3. |
| `obf.awg.*` | Да | AWG junk работает до handshake, recordizer — только после аутентифицированного согласования. Для TCP obfs по-прежнему нужен одинаковый `jc`. |
| `obf.padding.*` | Да | Padding генерируется после recordization. Он дополняет изменение границ, но расходует трафик. |
| `obf.traffic_normalization.*` | Да | Округление размеров применяется к recordized plaintext. Размеры должны помещаться в реальный carrier/MTU budget. |
| `obf.traffic_shaping.*` | Да | Idle cover независим. `stealth` pacing может снижать скорость; recordizer отдельно добавляет batch delay. |
| `obf.heartbeat.*` | Да | Heartbeat — control/cover, а не исходный пакет для batch. Shaping заменяет фиксированный heartbeat; Reality/H2 отключает qeli heartbeat. |
| `obf.fragmentation.*` | Да, но это другой слой | Legacy-параметр дробит выбранные handshake/carrier writes. Он не собирает внутренние IP-пакеты и не заменяет `obf.recordizer.fragment.*`. |
| согласованные UDP `DATA_FRAG` / PMTU | Да, автоматически | Внешний слой делит уже зашифрованную запись под путь. Recordizer fragment находится внутри шифрования и восстанавливает границу исходного пакета. |
| `obf.multipath.*` | Да, только TCP | У каждого упорядоченного TCP stream своё состояние sender/reassembler. На UDP multipath должен быть выключен. |
| IPv4, IPv6 и dual-stack | Да | Payload обрабатывается как непрозрачные аутентифицированные байты. Обычные проверки family, routing и MTU профиля сохраняются. |
| TUN и TAP | Да | Qeli переносит IPv4/IPv6-пакеты; TAP снимает/восстанавливает Ethernet header на краю. Произвольные L2-фреймы через recordizer не передаются. |

Реальные несовместимости и опасные сочетания:

- `policy = required` со старым клиентским ядром без `PACKET_MUX_V1`;
- `fragment.enabled = false`, если внутренний пакет с mux-заголовком не помещается в одну
  безопасную запись: пакет будет отброшен, а carrier budget не будет нарушен;
- маленький явный `max_payload_bytes` вместе со слишком малым
  `max_fragments_per_packet`: большой внутренний пакет превысит лимит частей;
- запрещённые сочетания transport, которые не работают и без recordizer: Reality на UDP,
  QUIC masking на TCP и multipath на UDP.

## 5. Почему сбалансированные значения именно такие

`2..8 мс` достаточно для объединения коротких всплесков и при этом обычно не доминирует над
интерактивной задержкой. Шестнадцать фреймов смешивают burst без неограниченного числа пакетов в
одной точке потери. `max_payload_bytes = 0` выбран намеренно: budgets TCP, H2, obfs, QUIC и PMTU
различаются, поэтому постоянное число либо теряет ёмкость, либо создаёт лишнюю фрагментацию.
Диапазон неполных целей меняет гистограмму размеров, а вероятность полной цели 0.72 сохраняет
скорость и амортизирует overhead шифрования/carrier. Reassembly limits — защита ресурсов от
аутентифицированного peer, а не ручки DPI.

Не копируйте значения только ради большего числа фрагментов. Фрагментация добавляет заголовки,
CPU, чувствительность к потерям и задержку; это не означает лучшую маскировку автоматически.
Проверяйте изменение на чистом PCAP с control corpus и на benchmark скорости/потерь того же carrier.

## 6. Профили настройки

Начинайте со сбалансированного блока выше и меняйте одно измерение за раз.

### Чувствительный к задержке трафик

```ini
obf.recordizer.batch.delay_min_ms = 0
obf.recordizer.batch.delay_max_ms = 2
obf.recordizer.batch.max_packets = 4
```

Очередь короче, но объединяется меньше пакетов и слабее меняется гистограмма размеров. Оставьте
`fragment.enabled = true` и `max_payload_bytes = 0`.

### UDP с потерями

```ini
obf.recordizer.batch.delay_min_ms = 0
obf.recordizer.batch.delay_max_ms = 2
obf.recordizer.batch.max_packets = 2
obf.recordizer.record.full_probability = 0.85
```

Малый batch снижает усиление потерь. Автоматический payload позволяет аутентифицированному PMTU
увеличить безопасный budget без oversized датаграмм.

### Более сильная экспериментальная морфология

```ini
obf.recordizer.batch.delay_min_ms = 3
obf.recordizer.batch.delay_max_ms = 12
obf.recordizer.record.full_probability = 0.55
```

Будет больше неполных целей и возможностей для batch, но вырастут задержка и overhead. Считайте
это экспериментом, пока PCAP и прикладные тесты не покажут улучшение именно для выбранного
внешнего carrier и сети.

## 7. Переход и проверка

1. Обновите серверное ядро и добавьте сбалансированный блок с `policy = prefer` в каждый профиль.
2. Перезапустите qeli и переподключите актуальный клиент. В логе должен появиться
   `Packet recordizer: PACKET_MUX_V1 active` для TCP или UDP.
3. Проверьте двусторонние IPv4/IPv6, DNS, reconnect, PMTU и длительную нагрузку.
4. Проверьте, что старый клиент при `prefer` продолжает работать на legacy data-plane.
5. Обновите все клиентские приложения/ядра. Только после этого, если нужен fail-closed, замените
   policy на `required` и переподключите сессии.
6. Сравните размеры и тайминги пакетов с настоящим control traffic. Один throughput-тест не
   доказывает маскировку от DPI.

Для отката задайте `obf.recordizer.policy = off`, перезапустите профиль/сервис и переподключитесь.
Откатывать клиентский конфиг или connection link не требуется.

Не существует доказуемой настройки, делающей протокол «полностью невидимым». Recordizer удаляет
одну транспорт-независимую корреляцию границ; carrier, репутация endpoint, active-probe поведение,
долгосрочные тайминги и объём трафика остаются наблюдаемыми.
