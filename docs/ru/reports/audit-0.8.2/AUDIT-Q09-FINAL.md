# Q09: итоговый аудит handshake/pre-auth и сохранение KICK

<!-- normative-sync: audit-q09-final-v1 -->

Дата: **3 октября 2026**. Core: `ac921681`; fixtures: `f0d2caf8`.
**Q09 DONE** в согласованных границах аудита; следующий раздел — Q10.
[Evidence](../../../../release/certification/evidence/q09-final-20261003.json).
Предыдущие этапы: [AUTH/PMTU](AUDIT-Q09-UDP-AUTH.md),
[TCP/parser](AUDIT-Q09-TCP-PARSER.md), [UDP contracts](AUDIT-Q09-UDP-CONTRACTS.md).

## Последние исправления

| ID | Приоритет | Дефект | Исправление |
|---|---|---|---|
| Q09-F010 | P2 | Старый TCP-клиент терял KICK при одновременном EOF и переподключался, повторно вытесняя новую сессию. Pipeline мог сообщить о потере stream до расшифровки очереди | Management обрабатывается раньше EOF. Reader закрывает FIFO и ждёт конечную очередь расшифровки перед уведомлением о потере stream; writer запрашивает остановку reader. Ожидание свободного буфера тоже реагирует на остановку |
| Q09-F011 | P2 | Отказ доставки KICK в платформенную очередь превращал typed server error в обычную ошибку и терял `reconnect_allowed=false` | Общий обработчик TCP/UDP сохраняет typed KICK независимо от ошибки доставки. После join проверяется уже опубликованный terminal event, чтобы отмена/TUN-stop не скрывали его |

Это изменение общего клиентского ядра. Установленному GUI нужен обновлённый native core;
обновление одного сервера не меняет старую клиентскую библиотеку. Формат INI, ABI и wire bits не менялись.

## Итоговый разбор слоёв

1. **Вход и framing:** полный ClientHello отделён от partial REALITY peek; длины, векторы, duplicate extensions и точный JOIN проверяются до использования. UDP принимает только bounded client-direction fragments. Незавершённые и конфликтующие сообщения не запускают AUTH.
2. **Крипто и proof:** проверены обязательный ML-KEM, canonical encapsulation key, low-order X25519 и transcript binding. Новая fixture действительно завершает PQ handshake, проверяет proof сервера и отправляет поддельный client proof внутри корректного AEAD, а не только портит ciphertext. Тестовая identity принадлежит отдельному серверу fixture.
3. **Credentials и capabilities:** TCP/UDP используют один порядок проверки pinning → IP lockout → user/tarpit → Argon2 → profile/quota. Known malformed extension не понижается молча до legacy. Верные legacy/current credentials принимаются; IPv6-required на IPv4-only профиле получает отказ.
4. **Ресурсы и конкуренция:** TCP permit берётся до spawn; UDP crypto и partial/pending entries ограничены. AUTH lease исключает дубликат и eviction/reaper активного verifier. Argon2 permit принадлежит blocking job при отмене async waiter. Ожидание admission и отправка ответа используют исходный deadline; rollback освобождает registry/pool/iroutes/directory.
5. **Повторы и amplification:** cached AuthOK публикуется после первой успешной отправки и проверяет revocation; retries ограничены. AwaitingAuth deadline не продлевается повторами. Reaper перепроверяет текущий entry под write lock. Границы carrier accounting указаны ниже.
6. **Клиентский lifecycle:** decoded KICK имеет приоритет перед EOF. В pipeline конечная очередь расшифровывается до уведомления о потере stream; никакого блокирующего TUN I/O в drain нет. Полная отмена поколения продолжает отменять и join всех owned tasks. Ошибка UI delivery не меняет серверную reconnect policy.
7. **Совместимость и review:** capabilities учитывают транспорт, platform bits и explicit rollout. Public legacy proof builder оставлен как совместимый Rust API; inert session metadata в UDP не даёт отдельного пути исполнения. Новых незакрытых критичных находок этого раздела не осталось. Полные transport/packet/session аудиты продолжаются в своих разделах.

## Проверки

- **2301 Linux units PASS**, 0 failed, 60 ignored; полный/minimal Clippy и fmt PASS. Семь дополнительных Linux checks: simultaneous KICK/EOF, ordinary EOF, platform delivery error, inline/pipeline terminal-before-EOF и shutdown ownership.
- **8 живых baseline/fixed проверок TCP PASS**: старый бинарник теряет KICK в 4/4 попытках; новый сохраняет terminal policy и не reconnect в 4/4. Старый клиент остановлен SIGSTOP, сервер вытесняет его и закрывает stream, затем клиент продолжает работу. Так гонка воспроизводится без случайной нагрузки.
- **66 AUTH/proof/capability checks PASS**: TCP, UDP и QUIC; verified server proof, forged client proof, invalid version/length/policy, truncated extension, IPv6-required refusal, legacy/current success. По восемь peers на транспорт одновременно: четыре допустимых, четыре отказа. Отказы не оставляют admitted session.
- **35 admission checks PASS** на том же кандидате, без конкурирующих компиляторов на .11. Свежий domain total — **109**; числа прежних этапов не выдаются за повторные текущие прогоны.
- Fresh **18 сценариев / 327 assertions**, aggregate IPv4/IPv6 leak и **100 TCP + 100 QUIC / 33 soak checks PASS**. Release SHA `1782aeb453f9fe0d95671b145d1cf5578c8abd58d9e877e43be18ea28177b5a6`.
- Четыре native core пересобраны независимыми A/B passes; equality, ABI exports, потребляемые копии и provenance PASS. Это compile/package qualification, не новый физический app E2E.

## Принятые границы

Сохранение terminal policy относится к authenticated decoded events и конечной очереди
уже прочитанных TCP records. Оно не гарантирует доставку потерянного или непрочитанного
пакета и не обещает, что неисправный GUI покажет событие. Случай pipeline проверен
unit fixture; живой paused-client сценарий использует fake-TLS.

Исходные сбои обвязки сохранены: cleanup пытался kick уже удалённой сессии и удалить
уже удалённый veth; первый unit fixture ожидал EOF, не дочитав ACK. После исправления
обвязки baseline и окончательные проверки прошли. Первый concurrent admission FAIL
из предыдущего этапа также сохранён; этот пакет воспроизводит и устраняет соответствующий
механизм потери KICK, без заявления о произвольной нагрузке.

Предыдущие parser ASan/fuzz и UDP timeout/reaper evidence остаются историческими;
server/protocol inputs совпадают с текущими. Exact outer-wire 3×, forced kernel send EIO,
принудительная live reaper scheduler race и неограниченный flood не заявляются.
Carrier overhead учитывается с ранее описанным bounded slack.

Все .11 snapshots совпали. На .10 сервис, executable и остальные поля сохранены,
но legacy save снова различается ровно тремя прежними правилами. Исходный
`host_restored=false` сохранён; причина не приписана сборке, полное восстановление .10
не заявлено. Физические Mac/router/Windows VM исключены пользователем; новый Android/iOS
runtime не заявляется сборкой библиотек. Рабочие сервисы/бинарники не заменялись.
Push, deployment и новый throughput benchmark не выполнялись.

Сырые результаты: `audit-debt-20260924/q09-final-20261003` рядом с worktree.
Обязательства исправлений Q09 закрыты; дальнейший общий аудит продолжается с Q10.
