# Q12: транспорты и wire-маскировка

<!-- normative-sync: audit-q12-final-v3 -->

Дата: **4 октября 2026**. **Q12 DONE/PASS**. Текущий код `9d5ae5bb`; полный пакет проверок: `release/certification/evidence/q12-ws-close-20261004.json`. Предыдущие WS writer/read пакеты ниже сохраняют исходные даты и артефакты.

## Close, control и завершение Q12: 4 октября

Код `9d5ae5bb`; evidence `release/certification/evidence/q12-ws-close-20261004.json`.

- **Q12-C001, P2:** Close принимал payload длиной один байт, запрещённые статусы и некорректный UTF-8. Теперь разрешены пустой payload либо статус 1000–1003,1007–1014,3000–4999 и корректная UTF-8 причина. Неправильный кадр завершает транспорт с ошибкой.
- **Q12-C002, P1:** после Close разбирались и выдавались следующие данные, а writer принимал новый plaintext. Close теперь terminal; ранее полученные данные выдаются один раз, следующие кадры отбрасываются, новые данные не принимаются.
- **Q12-C003, P2:** Close терялся за заполненной очередью Pong. Он имеет приоритет; до восьми ожидающих Pong остаются ограниченными, при заполнении сохраняется ответ на последний Ping.
- **Q12-C004, P1:** простаивающее соединение не отвечало на Ping/Close до следующей прикладной записи. Целый поток, существующий writer split-потока сервера/shared client core и pre-auth junk/nonce фазы теперь обслуживают control-ответы. Новых конкурирующих writer-задач нет.
- **Q12-C005, P2:** read мог выдать EOF до отправки Close, после чего владелец останавливал writer. Теперь EOF следует за echo, flush и shutdown; отказ writer будит ожидающий reader. Состояние reader сохраняется между poll без повторного создания reframer/scratch.
- **Q12-C006, P2:** отменённый Pending flush мог забываться после освобождения wire-буфера. Флаг незавершённого flush сохраняется до Ready, включая idle control path; ответ не кодируется повторно.

**8 baseline groups: 0 PASS / 8 FAIL**, **17 новых тестов**. Тесты используют backpressure,
замену входного буфера после Pending, короткий duplex и настоящий TCP split. Порядок
Close, wake reader, idle Pong и обе MASK-направленности handshake проверены отдельно.

Свежие проверки одного артефакта: **2352 Linux PASS / 60 ignored**, full/minimal
Clippy и fmt; **13 wire cases / 267 transport assertions** и **64 Upgrade/frame/control
probes**; отдельный **24-assertion REALITY-TLS/H2 smoke**; **18-case matrix + aggregate
IPv4/IPv6 leak**; **100 TCP + 100 QUIC / 33 soak checks**; четыре independent native
A/B артефакта, клиентские копии, exports и provenance. Live control probes идут
перед nonce и в ожидании PQ ClientHello; post-auth idle split ownership проверяется
TCP-тестом общего адаптера. TCP soak использует fake-TLS, это не отдельный WS soak.

Два bounded **ASan/libFuzzer** прогона по 60 секунд: WebSocket frame — **2177214**,
QUIC envelope — **7714313**, без crash. Проверяются shipping parsers через test-only
feature, отсутствующий в native recipes; исходная pre-commit identity сохранена,
хеши входов сверены с квалифицированным кодом. Это не исчерпывающее fuzz-покрытие.

Требования Close/Pong сверены с [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)
и [реестром статусов IANA](https://www.iana.org/assignments/websocket).
Общий транспорт не является универсальной WS-библиотекой: поддерживается бинарный
carrier с cap16384 и без extensions; generic protocol-error Close1002 не заявляется.

## Матрица конфигов, runtime и Quick Start

| Transport / mode | Дополнительные условия | Реальное поведение |
|---|---|---|
| TCP / plain | Front/AWG/QUIC не выбирают этот carrier | Raw framing с обязательным inner Qeli AEAD |
| TCP / fake-tls | REALITY proxy выключен | TLS-подобный handshake, без real TLS |
| TCP / fake-tls + REALITY proxy | Legacy Quick Start `reality`; short_id | Token recognition, decoy bridge, без real TLS |
| TCP / reality-tls | REALITY proxy и real_tls, short_id, pin, bind_static | Настоящий TLS 1.3/H2; см. Q11 |
| TCP / obfs | Непустой obfs_key; front=websocket/none | Общий ChaCha20 stream и выбранный front; AWG требует совпадения jc |
| UDP / fake-tls или obfs | Для obfs нужен ключ; QUIC optional | Datagram handshake/AEAD, optional camouflage; AWG — junk datagrams |
| UDP / plain или reality-tls | Несовместимые сочетания | Отклоняются общими parser/validator и сервером |

`reality` — имя Quick Start, не новое значение INI `mode`. Front работает только
для TCP obfs; неактивные параметры сохраняются при редактировании. TCP AWG работает
только с obfs; server validator предупреждает о неактивном AWG в других TCP режимах.
Нормализация AWG ограничивает jc128 и jmax1400; junk/accept deadlines и peer byte
budgets сохраняются. UDP не требует зеркального счётчика junk от сервера.

QUIC здесь — строгая unprotected compatibility envelope, а не RFC QUIC/HTTP/3.
Проверены общий KAT, exact flags/version/DCID/SCID/token/declared length, legacy
spelling, truncation и varints; новых дефектов оболочки не найдено. Ссылка на Initial
в комментариях исправлена на [RFC 9000 §17.2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2).
Устаревшие перечисления режимов в config comments и ошибочно прикреплённый rustdoc
удалены; UI/RU текст больше не обещает гарантированного обхода entropy DPI.
Эти проверки не являются новым throughput benchmark или DPI-вендорной сертификацией.

На .11 полные snapshots совпадают. На .10 сохраняется raw snapshot false только
при разнице трёх ранее описанных legacy rules; остальные поля/service/executable
должны совпадать. Рабочие сервисы не заменены. Native cross-build не подтверждает
новый app E2E; Mac/router/Windows VM исключены пользователем.

## HTTP Upgrade и входящие кадры: 4 октября

Пакет **PASS**, код `19fed832`, evidence `release/certification/evidence/q12-ws-read-20261004.json`.
Изменения находятся в общем protocol/obfs и используются сервером и всеми клиентами.

- **Q12-R001, P2:** сервер принимал неполный или некорректный Upgrade. Общий bounded parser теперь требует точную строку GET/HTTP/1.1, непустой единственный Host, версию 13, корректные имена/значения заголовков и единственный 16-байтный base64 key. Дубли критических полей, obs-fold, control bytes и неоднозначное тело не допускаются. Content-Length может отсутствовать либо содержать только десятичный ноль; Transfer-Encoding запрещён.
- **Q12-R002, P2:** клиент принимал неоднозначные ответы 101. Теперь проверяются полная HTTP-голова и строка статуса; дубли Upgrade/Accept и незапрошенные extensions/subprotocol отклоняются. Accept по-прежнему связан с challenge. Несколько полей Connection поддерживаются; неиспользуемые значения могут содержать obs-text.
- **Q12-R003, P2:** head размером 4097 байт проходил, если последний байт завершал CRLFCRLF. Лимит **4096 байт включает terminator** и проверяется до признания головы завершённой; тот же предел применяется при непосредственном разборе головы.
- **Q12-R004, P2:** входящие кадры принимали неминимальное кодирование длины. Форма u16 допустима от 126 байт, u64 — от 65536; существующий предел payload **16384** сохранён. Поэтому u64-кадры не проходят лимит этого бинарного транспорта.
- **Q12-R005, P1:** ошибка последующего кадра могла скрыть уже полученные байты предыдущих корректных кадров. Теперь эти данные выдаются сначала, затем возвращается сохранённая ошибка; дальнейший разбор после неё не возобновляется. Это правило порядка выдачи, а не обход аутентификации: inner PacketCodec по-прежнему проверяет AEAD каждого пакета.
- **Q12-R006, P2:** EOF на границе кадра принимался как чистое завершение даже при незавершённом fragmented message. Теперь такой EOF даёт сохранённый UnexpectedEof. Завершённая фрагментация с Ping между фрагментами сохраняет совместимость.

**9 baseline groups: 0 PASS / 9 FAIL** до исправления; добавлены **11 тестов**.
Свежие проверки: **2335 Linux PASS / 60 ignored**, full/minimal Clippy и fmt;
**40 live Upgrade/frame probes** в двух изолированных WS fixtures, **39 WS** и
**24 REALITY-TLS/H2** assertions; **18-case matrix + aggregate IPv4/IPv6 leak**;
**100 TCP + 100 QUIC / 33 soak checks**; четыре независимые native A/B сборки,
копии, exports и provenance. Рабочие службы и бинарники сохранены.

Bounded **ASan/libFuzzer, 60 секунд**, произвольные запросы и мутации корректного
Upgrade: **1148461 прогонов**, без crash. SHA входов совпадают с квалифицированным
кодом; исходная pre-commit identity сохранена отдельно. Это request-head fuzz,
не ASan-проверка response/frame parser и не доказательство исчерпывающего покрытия.
На .10 raw snapshot false сохраняется только для ранее описанных трёх legacy rules;
остальные поля/службы/executable совпадают. На .11 совпадают полные snapshots.

## Исправления общего транспорта

Пакет WS-записи 3–4 октября: код `10849261`, evidence `release/certification/evidence/q12-ws-write-20261003.json`. Следующие исправления и проверки относятся к тому пакету.

- **Q12-W001, P1:** writer продвигал cipher, сохранял весь вход и мог отправить часть кадра, затем возвращал Pending. После отмены и вызова с другим буфером он отправлял старый кадр и возвращал старую длину, не принимая новый вход. Теперь принятые данные принадлежат адаптеру и учитываются один раз через Ready; Pending следующего вызова не принимает новый вход. Состояние writer одно для целого и split-потока. Ошибка после частичной отправки сохранена: дальнейшие write/flush/shutdown не продолжают повреждённый поток.
- **Q12-W002, P2:** весь переданный write-буфер копировался, шифровался и превращался в кадры до отправки, без верхней границы владения. Теперь за вызов принимаются максимум 16384 байта данных; дополнительно остаётся существующая ограниченная очередь максимум восьми control-ответов.
- **Q12-W003, P1:** flush и shutdown обращались только к внутреннему сокету. Оставшиеся кадры и ожидающие Pong/Close могли не отправиться. Обе формы потока теперь завершают owned bytes и control-очередь до flush/shutdown сокета. Сервер и shared client core используют один write-all-and-flush helper на границах handshake, ACK и data/cover records — до ожидания ответа, публикации доставки или сна.
- **Q12-W004, P2:** пустой read обращался к сети и мог зависнуть. Теперь он сразу завершается, не меняя cipher и parser.

Пять сценариев воспроизведены на исходной реализации: **0 PASS / 5 FAIL**.
Семь новых тестов включают короткую запись, отменённый Pending с заменой входа,
ограничение памяти, control flush/shutdown, пустой read, terminal socket failure
и обмен в обе стороны через duplex-буфер всего **7 байт**. Перенесённые record
границы важны: принятие AsyncWrite не означает, что сокет уже отправил весь кадр.

## Проверки

- **2324 Linux tests PASS**, 60 ignored; полный/minimal Clippy и fmt PASS. Неуспешные промежуточные сборки с диагностикой импортов/Clippy и Windows cfg сохранены; helper перенесён из Linux-only transport в общий protocol; свежий финальный прогон использует исправленные исходники.
- На первом Linux r4 артефакте: **10 private live cases / 199 assertions PASS**, TCP plain/fake-tls/obfs-none/obfs-ws/obfs-awg, WS resume и UDP QUIC/fake-tls/obfs/obfs-awg. После переноса byte-identical helper в portable protocol финальный r5 артефакт прошёл **3 fresh WS success/resume + REALITY-TLS/H2 cases / 63 assertions**. Старые результаты привязаны к исходному SHA; не выдаются за новый прогон.
- Свежая матрица **18 сценариев** и aggregate IPv4/IPv6 leak PASS; **100 TCP + 100 QUIC** смен пути / 33 soak checks PASS.
- Четыре native-библиотеки пересобраны независимо A/B; хеши A/B, копии клиентов, exports и provenance PASS. Нового app E2E этим не заявляется; физические Mac/router/Windows VM исключены пользователем.
- Рабочие службы и бинарники не заменены. На .11 полные snapshots совпадают. На .10 допускается только ранее записанная разница трёх legacy firewall rules с сохранением raw false; остальные поля, служба и executable должны совпадать. Причина этих правил не атрибутирована.

Для этого пакета не заявляются новый ASan fuzz, PCAP, throughput benchmark или
устойчивость к DPI. Функциональный обмен не доказывает неотличимость wire-трафика.
Требования WebSocket сверяются с [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455).

## Следующий раздел

Q12 закрыт в согласованных границах. Общий план: **12/37 DONE/PASS (32,4%)**. Далее — Q13: recordizer, padding и shaping; проверки входят в каждый пакет исправлений.
