# Q09: UDP handshake, публикация admission и очистка

<!-- normative-sync: audit-q09-udp-contracts-v2 -->

Дата: **3 октября 2026**. Основной код: `a3029951`, fixture: `f36c4887`.
Пакет Q09-F006–F009 проверен; весь Q09 остаётся **IN_PROGRESS**.
[Evidence](../../../../release/certification/evidence/q09-udp-contracts-20261003.json).
Предыдущие этапы: [UDP AUTH/PMTU](AUDIT-Q09-UDP-AUTH.md), [TCP/parser](AUDIT-Q09-TCP-PARSER.md).

## Находки

| ID | Приоритет | Дефект | Исправление |
|---|---|---|---|
| Q09-F006 | P2 | Повтор AUTH выдавал закешированный AuthOK до завершения admission; ветка cache находилась раньше проверки revoked. Ранние зашифрованные data/control принимались после смены состояния, пока установка iroutes ещё выполнялась | Revocation проверяется до cache; повтор AUTH и authenticated ingress ждут успешной первоначальной отправки AuthOK. Подтверждённые ошибки согласования тоже публикуются только после отправки |
| Q09-F007 | P2 | Серверный reassembler принимал ClientHello под MSG_SERVER_HELLO/MSG_AUTH_OK; повтор ServerHello запускался любым fragment magic, включая пустые/некорректные заголовки | Только MSG_CLIENT_HELLO, count 1–24, idx < count и chunk 1–1200. Общая библиотека фрагментов клиентов сохраняет свой контракт |
| Q09-F008 | P2 | Reaper выбирал адреса под read-lock и удалял их позднее без перепроверки. Между locks мог появиться AUTH lease, новый handshake на том же адресе или свежая активность | Единый expiry predicate повторно проверяет текущее состояние под write-lock непосредственно перед удалением |
| Q09-F009 | P2 | UDP ожидание admission и отправка AuthOK/ошибки согласования выходили за исходный AUTH-дедлайн. Ошибки send_to игнорировались, auth_ok_sent устанавливался даже без отправки | Общий handshake_until для отменяемого ожидания admission и отправки. Отказ AuthOK явно откатывает registry, pool lease, iroutes и directory; неотправленная ошибка согласования удаляет half-open |

## Разбор слоёв

1. **Входные фрагменты:** direction/length/count проверяются до выделения reassembly; неполный пакет молчит. Реальные переставленные фрагменты и точный повтор принимаются; конфликтующий повтор очищает partial.
2. **KE:** структурный ClientHello, обязательный ML-KEM, canonical EK и checked X25519 проходят до AUTH. Live negatives используют настоящий CLI ClientHello, затем меняют EK, обе X25519 offers либо убирают обязательный hybrid group. Legacy camouflage извлекает DH из отдельного classic offer; это не контракт выбора группы внешнего настоящего TLS.
3. **AUTH:** AEAD mutation не вызывает verifier/admission. Wrong password и unknown user не получают AuthOK и registry entry. Proof-only сервер заставляет неприкреплённый/TOFU клиент отказаться до AUTH; это не тест поддельного расшифрованного client proof.
4. **Admission:** cache доступен внутреннему коду, но не опубликован клиенту до завершения маршрутов. Независимые AUTH tasks сохраняют receive loop; живые reservations защищены от eviction/reaper. Предыдущие TCP/UDP permit/deadline проверки сохраняют собственную evidence.
5. **Повторы:** первоначальный ответ следует за admission; последующие пять AuthOK retries возвращают тот же ciphertext. Повторы не обновляют idle activity после исчерпания лимита. Revocation имеет приоритет над ответом из cache.
6. **Anti-amplification:** half-open ServerHello имеет накопительный 3× бюджет; прошедший credential/proof AuthOK имеет счётчик пяти повторов. Counters считают inner/post-obfs bytes с уже документированным небольшим framing slack. Проверка 100 коротких повторов подтверждает этот ограниченный сценарий; точный внешний wire 3× не заявляется.
7. **Ошибки/очистка:** общий исходный deadline охватывает verifier, очередь admission и отправку ответа. Побочные эффекты admission не отменяются целиком; откат ресурсов может завершиться позже deadline. Reaper перепроверяет текущего владельца, а не старый список адресов.

## Проверки

- **2294 Linux units PASS**, 0 failed, 60 ignored; четыре новые регрессии на publication gate, fragment bounds и expiry/lease revalidation. Полный/minimal Clippy и fmt PASS.
- **74 реальные UDP/QUIC проверки PASS**: старый бинарник воспроизводит ранний AuthOK, поздний admission и ServerHello для неверного direction; fixed блокирует их, обычный вход/retransmit остаются доступны. Три iroutes ставятся с ограниченной задержкой, затем реально удаляются при истечении исходного deadline.
- **16 pre-auth PMTU + 35 admission проверок PASS** на том же бинарнике; domain total **125**.
- Fresh **18 сценариев / 327 assertions**, aggregate leak и **100 TCP + 100 QUIC / 33 soak checks PASS**. Release SHA `d4cd369c4418f507daaf0246d14b7913897028c1d010f0bdf0b231e8c10a66ac`.
- Четыре native core A/B совпали; exports, потребляемые копии и provenance проверены. Server-only изменения не изменили байты клиентских библиотек.
- Все .11 snapshots совпали. На .10 те же три прежних legacy-правила меняются между save probes, включая последующее повторное появление; оба tools используют xtables-legacy-multi. Сервис/бинарник и все другие поля четырёх снимков совпали. Причина не установлена; исходное host_restored=false сохранено. Полное восстановление .10 не заявляется.

Первый admission-прогон при параллельных проверках увидел TCP reconnect старой сессии
и UDP ping до применения клиентских маршрутов. Fixture теперь ждёт TUN writer;
отдельный окончательный прогон без native compilers прошёл все 35 checks. Исходные
ошибки сохранены; причина первого TCP terminal-loss не установлена. Успешный
повтор не доказывает доставку terminal event при произвольной нагрузке.

Гонка reaper проверена детерминированно с настоящим UdpAuthLease и review удаления
под write-lock; принудительное попадание в live scheduler window не заявляется.
Live timeout проходит через общую send-error rollback ветку; kernel send_to EIO
специально не навязывался. Новый parser fuzz не запускался; предыдущая ASan evidence
TCP/parser остаётся исторической. Физические Mac/router/Windows VM исключены
пользователем. Push, deployment и новый benchmark не выполнялись.

Сырые результаты: `audit-debt-20260924/q09-udp-contracts-20261003` рядом с worktree.
Проверки исправлений этого пакета выполнены. Остаток Q09: итоговый review, дополнительные
поддельные client-proof/capabilities и contention-сценарии, уточнение первого TCP
terminal-loss наблюдения. План не объявлен завершённым по одному удачному повтору.

**Итог Q09:** дополнительные decrypted proof/capabilities, конкуренция и воспроизводимый TCP KICK/EOF закрыты в [финальном отчёте](AUDIT-Q09-FINAL.md). Q09 DONE; исходные результаты и ограничения этого этапа остаются историческими.
