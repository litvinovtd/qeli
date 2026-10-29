# Обфускация и PACKET_MUX recordizer

В этом руководстве разобрано, как накладываются уровни маскировки, как настраивать
транспорт-независимый recordizer и какие сочетания безопасны. Полный справочник ключей находится
в [CONFIG.md](CONFIG.md), измеренные ограничения — в [DPI-AUDIT.md](../reports/DPI-AUDIT.md).

Обзор алгоритма — [Recordizer и организация записей](../reference/RECORDIZER.md).
[Замеры required/off на 12 профилях 20 октября 2026](../reports/benchmarks/recordizer_required_off_2026-10-20.md)
содержат инженерные результаты одной сборки, CPU, потери и границы интерпретации;
это не публичный бенчмарк релиза. [Другие технологии и измерения](../reference/TECHNOLOGIES.md).

[A/B задержек 26–29 октября с графиками](../reports/benchmarks/recordizer_latency_2026-10-29.md)
разделяет off/required и timed/opportunistic: почти убрана задержка накопления ценой
около 8–9% TCP upload у FakeTLS, но не у всех профилей. Это не проверка финального dist.

[Пилот временного рисунка 29 октября](../reports/benchmarks/recordizer_masking_pilot_2026-10-29.md)
измерил уменьшение размытия ритма, но не установил процент ухудшения обнаружимости
VPN: контроль синтетический, не браузерный; по размерам/таймингам оба режима
отделялись от него. Не переносите проценты скорости на «проценты маскировки».

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
| `obf.recordizer.policy` | `off` в разреженном schema-baseline; `prefer` в поставляемых и новых профилях | `off`, `prefer` или `required`; политика согласования описана выше |
| `obf.recordizer.batch.mode` | `timed` | `timed` сохраняет случайное ожидание; `opportunistic` объединяет только уже готовые пакеты и сразу отправляет остаток ограниченного batch |
| `obf.recordizer.batch.delay_min_ms` | `2` | нижняя граница случайного flush deadline в режиме `timed` |
| `obf.recordizer.batch.delay_max_ms` | `8` | верхняя граница deadline `timed`; не меньше `delay_min_ms`; `0/0` отправляет каждый push сразу, в отличие от opportunistic batch |
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

`batch.mode` задаётся на сервере и передаётся после аутентификации вместе с Recordizer. В новом клиенте `opportunistic` также убирает дополнительное накопление H2 DATA в Reality-TLS; до аутентификации действует прежний `timed`. Старый клиент может игнорировать новое поле и сохранить старое поведение. QRM1, AEAD, пределы памяти, фрагментация и HTTP/2 flow control не отключаются. Значения `delay_min_ms`/`delay_max_ms` сохраняются для возврата в `timed`.

Низколатентная стратегия меняет временной рисунок маскировки: она не обещает ту же DPI-устойчивость. Уже заданные bandwidth/stealth-паузы остаются в силе. Выигрыш задержки и цена по максимальной скорости должны проверяться отдельным A/B на конкретной сборке; экспериментальный кандидат не является опубликованным релизом.

Для включения измените **существующий серверный профиль**:

```ini
obf.recordizer.policy = required
obf.recordizer.batch.mode = opportunistic
```

Если policy уже согласована как `prefer`, менять её ради batching не обязательно.
Это не полный профиль. Default `timed` сохранён. Новый режим требует поддержки
на сервере **и** клиенте; capability `PACKET_MUX_V1` старого клиента сама по себе
не гарантирует поддержку поля. Примените конфиг штатно и переподключитесь;
проверьте активный mux и лог `Recordizer batching: opportunistic` на обеих сторонах.
Для rollback верните `timed` и переподключитесь. В панели есть переключатель режима;
delay-поля недоступны в opportunistic, но не обнуляются.

`delay_min_ms <= delay_max_ms` требуется и в новом режиме; значения сохраняются
для rollback. Все лимиты, `record.*`, `fragment.*`, MTU, TUN queue, padding и shaping
сохраняются. В `off` режим batching неактивен и H2 самостоятельно не переключает.
Отсутствие намеренного накопления не гарантирует нулевой RTT: backpressure, pacing
и планирование остаются. [Полный алгоритм](../reference/RECORDIZER.md),
[проверка применения](OPERATIONS.md#recordizer-batch-mode).

## 4. Совместимость с остальными параметрами маскировки

| Функция | Совместима? | Взаимодействие |
|---|---|---|
| TCP `plain` | Да | Корреляция границ снижается, но внешний поток остаётся немаскированным high-entropy трафиком. Используйте только в доверенных сетях. |
| TCP `fake-tls` | Да | Внутренняя связь скрыта; синтаксис fake-TLS и поведение при active probe остаются отдельными признаками. |
| TCP `reality-tls` / Reality/H2 | Да | Recordizer работает внутри настоящего TLS/H2. В `timed` его batch delay и накопление H2 могут складываться; `opportunistic` убирает оба ожидания после AUTH при поддержке обоих ядер. |
| TCP `obfs` с WebSocket или без него | Да | Recordizer находится внутри obfs/WS carrier; WS-сессия от этого не воспроизводит прикладную семантику браузера. |
| UDP `fake-tls` / `obfs` | Да | Payload budget вычисляется из UDP carrier и PMTU. Большой batch усиливает потери: одна потерянная датаграмма может содержать несколько внутренних пакетов. |
| `obf.quic.enabled` | Да, только UDP | Overhead QUIC shape учтён в автоматическом budget. Это по-прежнему форма QUIC, не настоящий QUIC/HTTP/3. |
| `obf.awg.*` | Да | AWG junk работает до handshake, recordizer — только после аутентифицированного согласования. Для TCP obfs по-прежнему нужен одинаковый `jc`. |
| `obf.padding.*` | Да | Padding генерируется после recordization. Он дополняет изменение границ, но расходует трафик. |
| `obf.traffic_normalization.*` | Да | Округление размеров применяется к recordized plaintext. Размеры должны помещаться в реальный carrier/MTU budget. |
| `obf.traffic_shaping.*` | Да | Idle cover независим. `stealth` pacing может снижать скорость и добавлять задержку в обоих режимах; отдельный timer batch delay Recordizer есть только в `timed`. |
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

## Общий бюджет и паузы shaping

<!-- normative-sync: shaping-budget-v1 -->

`obf.traffic_shaping.enabled = true` включает idle cover. При `stealth = true`
дополнительно включается pacing полезных данных **только в TCP**. UDP намеренно
оставляет только idle cover, даже если параметр stealth сохранён. `stealth_rate_mbps` должен быть
положительным только при одновременно включённых shaping и stealth. Значение
`0` для выключенного stealth сохраняется при чтении и записи клиентского INI.

Все bonded TCP-потоки клиента резервируют скорость в одном общем бюджете.
Сервер также использует общий бюджет направления сессии. Это не означает
суммарный лимит download + upload: направления независимы. Cover расходует
отдельный общий `budget_bytes_per_sec`; его бюджет не умножается на число потоков.

Pacing выдерживает рассчитанную паузу целиком, включая остаток до 6 мс. На таком
коротком остатке cover не добавляется, но данные ожидают deadline. Время медленной
записи cover засчитывается в паузу. Возможен начальный burst накопленных токенов
за одну секунду; краткий замер не обязан точно равняться заданной скорости.

Размер активного cover должен помещаться в `MAX_TUNNEL_MTU`, а его бюджет должен
быть не меньше `max_size`. UDP дополнительно ограничивает размер реальным
carrier/path budget. Эти проверки общие для локального INI и настроек AuthOK.
Локальный клиент по-прежнему проверяет положительность и порядок сохранённых
диапазонов при выключенном shaping.

`budget_bytes_per_sec` считает запрошенные байты cover-padding; заголовки AEAD и
внешнего carrier увеличивают фактический трафик. Это не полный лимит трафика на
сетевой интерфейс. Shaping и recordizer не дают гарантии обхода DPI.


## Совместное округление padding и обработка повреждённых mux-records

<!-- normative-sync: morphology-contract-v1 -->

`obf.traffic_normalization.round_sizes` задаёт размер **data + всего padding** перед
шифрованием. Сначала создаётся random padding, затем выбирается ближайшая подходящая
цель с учётом этих байт: payload70 + padding3 при цели128 получает ещё55, а не58 байт.
AEAD и внешний carrier добавляют собственный overhead. Если цели под carrier budget
нет, normalization ничего не добавляет; уже созданный padding сохраняется.

`obf.padding.probability = 0` означает точное отсутствие random padding; normalization
может независимо добавить свои байты. NaN/Inf запрещены даже при выключенном padding
или `obf.recordizer.policy = off`: service API/AuthOK не могут сохранить такие значения.
Остальные конечные dormant значения сохраняются, активная функция проверяет свой диапазон.

При ошибке любого frame mux-envelope ни один завершённый пакет этой записи не выдаётся
callback. Внутреннее reassembly-состояние остаётся incremental: принятые частичные
фрагменты могут сохраняться до timeout, конфликтующие удаляются. Это не обещание rollback
всего receiver state и не изменение wire format.
