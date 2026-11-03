# Q11: REALITY, TLS 1.3 и HTTP/2

<!-- normative-sync: audit-q11-tls-v1 -->

Дата: **3 октября 2026**. **Q11 DONE** в согласованных границах аудита.
Исправления: `e2366a73`. Evidence: `release/certification/evidence/q11-tls-20261003.json`.

## Исправления

- **Q11-F001, P2:** общий клиентский ServerHello parser возвращал первый key_share до проверки остатка сообщения. Принимались повреждённый хвост, неверные длины и версия, отсутствие supported_versions, дубли и ненулевое compression. Серверный разбор формы cover target повторял эту логику. Теперь один decoder проверяет всё сообщение и расширения, длину X25519/hybrid share, TLS 1.3 и session ID echo. Compact-клиент отклоняет не предложенную hybrid-группу. Parser формы target использует тот же decoder.
- **Q11-F002, P2:** RecordCrypto публиковал sequence/byte counter после AEAD, но до проверки TLSInnerPlaintext. Запись из одних нулей сжигала sequence, а слишком большой внутренний plaintext и неизвестный content type принимались. Проверки типа, размера с padding и record version выполняются до публикации counters. Исправлена граница отправки: 16384 байта content + type помещаются в одну запись, а не две.
- **Q11-F003, P2:** RealTlsStream возвращал ошибку следующей записи раньше, чем отдавал уже проверенные application bytes из того же чтения сокета. Теперь они выдаются первыми; затем возвращается сохранённая фатальная ошибка. Следующие записи и новые записи в сокет после такой ошибки не допускаются. Пустой read/write не читает и не создаёт TLS-запись.
- **Q11-F004, P2:** асинхронный клиент требовал целое post-handshake сообщение в одной записи. Разделённый между записями NewSessionTicket ошибочно прерывал соединение. Общий bounded accumulator теперь поддерживает фрагменты заголовка и тела, несколько сообщений и предел тела 128 KiB. Interleaving незавершённого handshake с application/alert отклоняется.
- **Q11-F005, P2:** sans-IO молча пропускал KeyUpdate и alert и оставался установленным после ошибки AEAD. Общий обработчик теперь явно отклоняет неподдерживаемый KeyUpdate, обрабатывает alert/close_notify и фиксирует terminal state. Уже проверенные payload выдаются один раз перед ошибкой следующего вызова. Большой FFI-вход обрабатывается частями с буфером одной ciphertext-записи, а не копируется целиком.

Все пять исходных сценариев воспроизведены до исправлений: 0 PASS / 5 FAIL.
После исправлений добавлено десять тестов, включая отрицательные и совместимые сценарии.
Новых подтверждённых ненужных production-реализаций не осталось: второй ServerHello
walker удалён, async/sans-IO используют один post-handshake policy. Публичные Rust/C
helpers сохранены для совместимости; отсутствие прямого GUI-вызова не считается
достаточным доказательством мёртвого публичного ABI.

## Разбор слоёв

ClientHello builder, X25519/ML-KEM, SHA-256/SHA-384 transcript/key schedule, Finished,
низкопорядковые точки, размер сообщения/транскрипта и rustls/handrolled interop
проверены существующими тестами в свежем Linux-прогоне. ServerHello теперь разбирается
целиком до применения ключей. Certificate/CertificateVerify не проверяются как в
универсальном HTTPS-клиенте: REALITY использует pinned identity/token и внутренний AUTH.
Этот аудит не превращает transport в универсальную X.509 TLS-библиотеку.

RecordCrypto сохраняет независимые бюджеты **2^24 записей / 64 GiB ciphertext на ключ
и направление**, sticky exhaustion и проверку всего encrypt-вызова до выдачи фрагментов.
TLSInnerPlaintext ограничен **16385 байтами вместе с type и padding**; AEAD tag,
header/version, минимальный размер, точная ciphertext-длина и тип проверяются отдельно.
После отказа реальные transport adapters прекращают сеанс; проверка счётчиков в
primitive-тестах не означает разрешение продолжать TLS после плохого MAC.

Tickets читаются как ограниченные opaque post-handshake сообщения, resumption по ним
не реализован. KeyUpdate требует нового сеанса. Async close_notify даёт read EOF после
накопленного plaintext и позволяет обратную запись. Старый sans-IO ABI не имеет
отдельного кода EOF: close_notify завершает handle через существующий `-1`, после выдачи
предшествующих данных. Экспортированные функции и соглашение `0/-1` прежние.
Сохранена совместимость async transport с TCP EOF на границе записи и shutdown
нижнего потока; строгая универсальная TLS closure-conformance не заявляется.

REALITY discriminator использует профильный replay guard, временное окно и строгий
short_id. Обычные пробы и повтор принятого token уходят на cover target. Decoy имеет
отдельный gate, connect/idle/lifetime пределы; pre-auth lease передаётся только после
получения decoy permit. Таймауты TLS, выбора legacy/H2 и inner AUTH остаются отдельными
стадиями, их сумма не выдаётся за один общий deadline. Lifetime/profile owners
отменяют и join-ят вложенные задачи; исключения и приёмник завершают I/O через RAII.

H2 carrier оставляет окна stream/connection 2 MiB, frame 16 KiB и bridge 256 KiB;
capacity возвращается после записи consumer. Проверены zero/small window,
SETTINGS/WINDOW_UPDATE, RST/GOAWAY при заблокированной записи, payload больше окна,
half-close, rejection/дальнейшие streams и отмена владельцев. Pre-auth permit остаётся
занятым до завершения деструктора I/O. Новых подтверждённых shipping-дефектов H2
ownership в этом пакете не найдено; прежние Q14-F022/F023 повторно проходят на Linux.

## Проверки

**2317 Linux units PASS**, 0 failed, 60 ignored; полный и минимальный Clippy/fmt PASS.
В свежем запуске: 51 realtls, 33 H2, 3 server REALITY и 9 crypto REALITY tests.
ASan/libFuzzer: **806899 record** и **38385 sans-IO handshake** входов, по 61 секунде,
configured max_len 16645 и RSS limit 768 MiB. Record fuzz создаёт authenticated
внутренние сообщения в обоих AES suites и проверяет counters/recovery/fragmentation;
handshake fuzz подаёт корректные и повреждённые ServerHello через публичный sans-IO API.
Это ограниченные кампании, а не доказательство полного покрытия/отсутствия ошибок.

**73 живые REALITY-TLS/H2 проверки**: success, resume и grace-expiry; borrowing формы и
сертификата приватного OpenSSL target, стандартная TLS-проба, replay принятого
ClientHello и tampered token без нового Qeli admission. Сохранены **3 PCAP и 6 результатов
wire/probe helpers**, с проверкой SHA при извлечении. Captures подтверждают TLS 1.3
ServerHello, suites/groups/extensions и encrypted records. Сертификат cover target
сгенерирован для стенда; это не проверка публичного Microsoft endpoint, полной JA4/JA3S
эквивалентности или устойчивости к конкретному DPI. H2 функциональность и PCAP отдельно.

Сборщик результатов первоначально запросил не относящийся к TLS case/result.json.
Продуктовые прогоны имели exit 0 и все PASS; ошибка сборщика и исходный raw result
сохранены, существующие PCAP/logs извлечены и проверены без повторного исполнения тестов.

Свежие **18 release cases / 327 assertions**, aggregate IPv4/IPv6 leak и
**100 TCP + 100 QUIC / 33 soak checks** PASS на точном новом candidate. Четыре native
библиотеки пересобраны A/B; равенство, exports, потребляемые копии и provenance PASS.
Native build не выдаётся за новое Android/iOS app E2E; Mac/router/Windows VM исключены
пользователем, платформенные разделы остаются самостоятельными.

Все .11 snapshots совпали, рабочие сервисы/executable не заменялись. На .10 принимается
только прежнее изменение трёх legacy firewall rules; raw host_restored=false сохранён,
причина не установлена, остальные поля и service/executable совпадают. Push/deploy,
новый throughput benchmark и изменения пользовательских WIP не выполнялись.

Основание wire limits: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), §§4.1.3, 5.2, 5.4.
Сырые результаты: `audit-debt-20260924/q11-tls-20261003` рядом с worktree.
Общий план: **11/37 DONE/PASS, 29,7%**. Далее Q12, transports и wire camouflage.
