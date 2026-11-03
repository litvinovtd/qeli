# Q13: recordizer, padding и shaping

<!-- normative-sync: audit-q13-morphology-v3 -->

## 4 октября: завершение Q13

**Q13 DONE/PASS. Общий план: 13/37 (35,1%), осталось 24 раздела.**
Исходник `711782d6d1cb6e41889c7c359f964e7242e314fc`, Linux-кандидат
`5605f4b7867cefb0886f14c943c499693fb41a0d0f767f8675292115d5f27c55`.
Evidence: `release/certification/evidence/q13-close-20261004.json`.

Удалены две недостижимые UDP-ветви stealth/pacing, три лишних параметра внутренних
функций отправки и соответствующие аргументы. Упрощены два условия idle-cover,
исправлены комментарии. Оба участника соединения по-прежнему выключают UDP stealth:
сохранённое `stealth=true` не включает ограничение скорости данных или cover под
нагрузкой. TCP pacing и UDP idle-cover сохранены. INI, ABI и формат протокола
не менялись. Это удаление мёртвого кода, без нового воспроизведённого runtime-дефекта.

Финальные проверки:

- **2365 Linux-тестов PASS / 60 ignored**, full/minimal Clippy и fmt.
- Проверка поставляемой rlib: **714992 утверждения**, 18000 сочетаний padding,
  10000 случаев отклонённого callback и 64 одновременных завершения фрагментов.
  Пиковый RSS **11176 KiB**. Это ограниченный прогон инвариантов, без ASan/libFuzzer.
- **7 сетевых сценариев / 72 проверки**: recordizer required/off на UDP,
  idle-cover и сохранённый stealth=true, TCP stealth 2 Mbps с одним и тремя потоками,
  normalization с padding on/off. UDP передаёт данные быстрее 2 Mbps; оба TCP
  направления остаются ниже допуска 2,6 Mbps, включая сумму трёх потоков.
  Сверены SHA захватов и число потоков; после нагрузки проверены ping и очистка.
- **18/18 сценариев матрицы / 327 проверок**, общий контроль утечек IPv4/IPv6,
  **100 TCP + 100 QUIC / 33 проверки длительного прогона**,
  **24 проверки REALITY-TLS/H2** на том же кандидате.
- Четыре платформенные библиотеки прошли независимые сборки A/B, сверку экспортов,
  копий и происхождения. Рабочие сервисы и исполняемые файлы сохранены.
  Несовпадение desktop snapshot допускается только для записанной точной разницы
  ранее известных legacy-правил firewall; исходный результат сохранён.

Предыдущие воспроизводители baseline/fixed и 17 INI-проверок ниже сохраняют свои
исходные SHA; соответствующие модули recordizer/obfuscate/config совпали побайтно.
Текущие unit-тесты, проверка инвариантов и сетевые пути отправки проверены заново.
Всего исправлены пять дефектов shaping и четыре дефекта padding/mux, удалены оба
выключенных UDP-пути. Все пять критериев раздела закрыты в доступном объёме.

Внутреннее состояние reassembly меняется постепенно и при ошибках; атомарна выдача
callback после успешного разбора целого envelope. Размер целевого bucket включает
data+padding, но исключает заголовки AEAD и транспорта. Времена из PCAP сами по себе
не доказывают размеры открытых записей или устойчивость к DPI. Замеры относятся к
лабораторным нагрузкам. Новый E2E-прогон установленного приложения не заявляется;
недоступные Mac/router/Windows VM runtime исключены пользователем. Далее — Q14.

## Предыдущий пакет padding/normalization/mux



## 4 октября: padding, normalization и обработка ошибок mux

**Новый пакет PASS; Q13 IN_PROGRESS.** Код `97cbe865a8a196e203bc6b3416d2e066ab6e6ebf`,
Linux-кандидат `0e51469f3a879e1c2061bcbf02b5ece223d600fce5fea6cddbc9aba4fa852b68`. Evidence:
`release/certification/evidence/q13-morphology-r2-20261004.json`.
Общий план остаётся **12/37 DONE/PASS (32,4%)**.

| ID | Исправление |
|---|---|
| Q13-M001, P2 | Normalization округлял только payload, затем прибавлял уже созданный random padding: 70+3 байта превращались в 131 вместо цели 128. Общий helper теперь выбирает цель для data+всего padding; вызов выполняется и когда сам payload уже равен одному из размеров. Исправлены TCP client/server и оба UDP client пути; UDP server использует общий server helper. |
| Q13-M002, P2 | Выключенный padding принимал NaN/Inf; AuthOK сериализовал значение в null, после чего клиент не мог разобрать ответ. Вероятности и recordizer ratios должны быть конечными даже при выключенной функции. Конечные dormant значения по-прежнему сохраняются без принудительного сброса. |
| Q13-M003, P2 | decode_with вызывал callback для корректного первого пакета до обнаружения ошибки в следующем frame; клиент мог уже применить management event. Теперь никакой callback не выполняется до успешного разбора всего envelope, включая конфликты и resource errors. |
| Q13-M004, P3 | Сравнение sample > probability допускало padding при probability=0 и draw=0. Теперь используется строгое sample < probability, с отказом для нечисловых значений публичного API. |

Первые три расхождения воспроизведены на прежнем shipping release rlib.
Нулевая вероятность проверена детерминированно на границе RNG; случайный baseline
FAIL для события с крайне малой вероятностью не заявляется.

Reassembly **не является транзакцией внутреннего состояния**: принятые частичные
фрагменты могут остаться после последующей ошибки, конфликт удаляется, завершённые
пакеты отклонённого envelope отбрасываются. Гарантия относится к выдаче callback.
Целые пакеты продолжают заимствовать authenticated record; завершённые фрагменты
передают своё существующее allocation. Single-packet completion не выделяет список.

Проверки этого кандидата:

- **2365 Linux PASS / 60 ignored**, шесть новых тестов, full/minimal Clippy и fmt.
- **17 проверок production INI/profile validator**:NaN/Inf отклоняются и при выключенной функции,конечные dormant значения сохраняются через INI roundtrip.
- Shipping rlib campaign: **714373 assertions**, 10000 roundtrips,
  40000 inner packets, 40000 malformed records, **18000 combined padding cases**,
  **10000 rejected callback cases** и 64 simultaneous fragment completions.
  Peak RSS **11144 KiB**; это bounded invariant campaign, не coverage-guided fuzzing.
- **6 TCP/UDP cases / 62 fixture checks**: legacy и required recordizer,
  normalization с padding on/off и три bonded TCP flows. В каждой стороне одинаковый
  iperf workload и ping после нагрузки; snapshots и рабочий сервис сохранены.
- Свежая матрица **18/18 / 327 assertions**, aggregate IPv4/IPv6 leak,
  **100 TCP + 100 QUIC path flips / 33 checks**, отдельно **24 REALITY-TLS/H2 checks**.
- На .10 raw snapshot=false сохранён: допускается только точно проверенная разница известных legacy firewall rules; сервис и executable не менялись. .11 snapshots совпадают.
- Четыре native A/B артефакта, copies, exports и provenance PASS. Это не новый
  installed-app E2E; Mac/router/Windows VM runtime исключены пользователем.

Plaintext bucket targets включают data+padding, но не AEAD/carrier headers.
Кампания проверяет composition и обратное декодирование; header PCAP сам по себе не
доказывает encrypted plaintext bucket. Предыдущие shaping-rate замеры ниже сохраняют
свой исходный кандидат; новый универсальный benchmark/DPI-resistance не заявляется.

Review sender batching, flush/PMTU raise, caps, duplicate/conflict/expiry, cancellation
на carrier boundaries и общих бюджетов выполнен. Предполагаемый wrap millisecond
таймеров не подтвердился: helper conversions saturate, select-ветви выключенных
scheduler gated. Оставшаяся работа Q13: удаление и проверка двух выключенных в production
UDP stealth ветвей; документированная TCP-only политика должна сохраниться.

## Предыдущий пакет shaping


**4 октября 2026. Пакет: PASS. Раздел Q13: IN_PROGRESS.**
Общий план: **12/37 DONE/PASS (32,4%)**. Полный аудит этим пакетом не завершён.
Исходники: `82c1ad770a6fa43302263babd67dab4e41043e9b`; Linux-кандидат: `d68bb6dab55234454821a22da1342469759a5d39aaa2c6915781acddddf4d10b`.
Точные hashes всех входов сборки сверены с этим commit; исходная pre-build identity
сохранена в evidence. Нативные A/B сборки используют чистый commit исходников.

## Исправления

| ID | Проблема и результат |
|---|---|
| Q13-S001 | P1: pacing прекращал ожидание на остатке до 6 мс. Общий планировщик теперь выдерживает весь deadline; медленная запись cover засчитывается в паузу. Исправлены два активных TCP writer; тот же helper используется в двух сейчас выключенных UDP ветвях. |
| Q13-S002 | P2: потоки брали время до общего lock; запоздавший старый timestamp сдвигал refill clock назад и повторно добавлял токены. Часы общего cover budget теперь монотонны. |
| Q13-S003 | P2: клиент отвергал `shaping_stealth_mbps = 0` при выключенном stealth, хотя AuthOK сохранял это dormant значение. INI теперь сохраняет его; активный stealth по-прежнему требует положительную скорость. |
| Q13-S004 | P2: клиент принимал активный cover размером 65535 байт, не помещающийся в общий формат записи. Клиентский INI и AuthOK теперь используют одну проверку активных параметров и ceilings. |
| Q13-S005 | P1: клиент считал data rate отдельно на каждом bonded TCP-потоке. Все writer теперь резервируют один бюджет направления; server rate budget уже был общим. |

Ошибка записи TCP cover теперь завершает writer, вместо выхода только из внутреннего
цикла pacing с последующей попыткой отправить payload. Wire format и ключи INI не менялись.
Общий cover budget независим от data rate и считает bytes padding, а не весь внешний трафик.

## Проверки

- Пять assertion FAIL на исходном коде; **7 новых тестов**. **2359 Linux PASS / 60 ignored**,
  полный и минимальный Clippy, fmt PASS. Ошибки импорта теста и `Send` обвязки сохранены;
  финальные источники прошли повторный полный запуск.
- Campaign через shipping release `.rlib`: **10000 roundtrips, 40000 внутренних пакетов,
  40000 повреждённых records, 622431 assertions PASS**. Проверены fragment/inflight/byte caps,
  дубликаты, конфликт, освобождение budget и expiry; peak RSS **11128 KiB**.
  Это bounded invariant campaign, не ASan/libFuzzer и не доказательство исчерпывающего покрытия.
- **10 сетевых cases / 102 assertions PASS**: TCP off/prefer/required, idle cover, stealth,
  три bonded TCP потока и UDP с recordizer/legacy. IPv4 ping после одинаковой нагрузки
  проходит без потерь; idle cover имеет изменяющиеся интервалы в обе стороны.
- Свежая **18-case матрица / 327 assertions**, aggregate IPv4/IPv6 leak и
  **100 TCP + 100 QUIC path flips / 33 soak checks PASS**; отдельно **24 REALITY-TLS/H2 checks**.
- Windows x64, macOS universal, Android arm64/x64: независимые A/B, consumer copies,
  exports и provenance PASS. Это не новый E2E установленного приложения;
  Mac/router/Windows VM runtime исключены пользователем.
- Рабочие сервисы и executable не заменялись; полные snapshots .10/.11 сохранены.

## Замер на этом стенде

Одинаковый directional iperf workload: 6 секунд, с отдельной секундой warm-up.
Три bonded потока проверены тремя параллельными внутренними TCP flows.

| Режим | Upload, Мбит/с | Download, Мбит/с |
|---|---:|---:|
| TCP required, shaping off | 1041.93 | 1572.58 |
| TCP required, idle cover | 1480.05 | 1563.94 |
| TCP stealth 2 Мбит/с, один поток | 1.89 | 1.92 |
| TCP stealth 2 Мбит/с, три потока суммарно | 1.81 | 1.75 |

Это локальная виртуальная топология, не WAN benchmark. Скорости без cap меняются с
нагрузкой CPU и захвата; сравнение idle cover не доказывает ускорение. Результат
проверки rate: число потоков не умножает cap; возможен стартовый burst токенов.

UDP **намеренно сохраняет только idle cover**: обе стороны выключают stealth.
Первый стенд ошибочно ожидал UDP cap и остановился; восемь PASS cases сохранены,
два оставшихся повторены с документированным TCP-only критерием. Это ошибка fixture,
не регрессия продукта и не включение новой UDP-функции.

PCAP ограничен headers: timestamps, original wire lengths и headers сохранены,
cryptographic payload не нужен этому анализу. Для первых полных captures сохранены
source/derived hashes преобразования; удалены только проверенные неактивные remote
копии, локальное evidence сохранено. Не заявляется отсутствие периодических признаков
для любого классификатора или сопротивление vendor DPI.

## Evidence и следующий шаг

Реестр: `release/certification/evidence/q13-shaping-20261004.json`.
Raw: `../audit-debt-20260924/q13-shaping-20261004` относительно audit-worktree.

Далее в Q13: семантические границы recordizer/reassembly, взаимодействие padding и
normalization, review dormant UDP stealth и экстремальных таймеров. Пять исправлений
этого пакета проверены сразу; открытые части раздела не помечаются DONE.
