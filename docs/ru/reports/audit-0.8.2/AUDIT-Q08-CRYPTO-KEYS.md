# Q08: криптография, identity и ключи

<!-- normative-sync: audit-q08-crypto-keys-v2 -->

Дата: 3 октября 2026. **Полный Q08: DONE; оба пакета проверены.**
Конфигурации остаются INI. Формат 32-byte keys, алгоритмы и wire protocol не изменены.

## Найденные проблемы

| ID | Проблема | Исправление |
| --- | --- | --- |
| Q08-F001, P2 | Три загрузчика identity/panel/session keys читали весь файл без ограничения, могли зависнуть на FIFO; dangling identity link считалась отсутствующим ключом и заменялась новой identity. | Общий `crypto/key_file.rs`: проверка открытого regular-file inode и размера, максимум 33 прочитанных байта, nonblocking open FIFO на Unix; dangling link — ошибка, без генерации. Временные секретные буферы — Zeroizing. |
| Q08-F002, P2 | Legacy panel-secret мигрировал до захвата modern FileLock. Повреждённый legacy мог молча привести к новому ключу, несовместимому с прежним password_enc. | Modern load, migration и generation выполняются под одной блокировкой с re-check; современный ключ имеет приоритет, повреждённый/недоступный legacy не заменяется новым. |
| Q08-F003, P2 | Оба client verifiers использовали unchecked X25519 DH для static identity. Для ключей малого порядка proof вычисляется с известным нулевым shared secret. | Checked DH отвергает такие identity до проверки proof и отправки credentials в общем transport core. Правильные nondegenerate pins не имели подтверждённого обхода. |

Read/generation logic трёх загрузчиков объединена; отдельные неограниченные чтения удалены. Запись остаётся штатной atomic-private операцией. Ссылки оператора на существующие обычные файлы сохранены; чтение не изменяет прежние owner/mode, созданные файлы — 0600. Повреждённая identity не ротируется автоматически. Для ошибки session key сохранён прежний fallback на ключ процесса с предупреждением, поэтому такие cookies не переживают restart. CLI reversible password storage остаётся best-effort; Argon2 hash — отдельный механизм входа.

## Воспроизведение и проверки

На предыдущем точном release `ba7d93afc47c71592e2d1d20e18d2c7c6a6cb0eb4248b674cf713e756aa1c712`: **6 FAIL из 19** key-storage checks — FIFO identity, dangling link, migration без lock, замена повреждённого legacy, FIFO panel key и FIFO session key. Независимые probes продолжались, общий baseline FAIL. Исправленная baseline fixture освобождает только собственный FIFO, затем штатно останавливает supervisor; private network и внешние host/service snapshots восстановлены. Первоначальный вариант с принудительным убийством supervisor не принят как baseline из-за orphan-worker cleanup.

На release первого пакета `0fdcb1a4ed45e850b9d7e6cd1b3bc3965f3775c6682ac59bcc0348a028e1a749`: **19 storage + 25 restore/state = 44 HTTP/system checks PASS** в проверенных private NET/mount/PID namespaces. Проверены восемь одновременных identity readers, длины 0/31/33/4 MiB, сохранение inode FIFO и dangling links, обычные operator links, held modern FileLock и приоритет нового ключа, миграция byte-for-byte с 0600, отказ на corrupt legacy, восстановление после отказов и cookie после свежего supervisor. Q07 regression проверяет reissue, legacy migration, mixed users/groups и настоящих VPN-клиентов с tunnel ping после restore, в том числе без panel-secret на новом сервере.

Unit negative vector строит реально вычислимый proof для public points 0 и 1 при DH=0; оба verifiers теперь отказывают, затем штатный proof проходит. Старое unchecked принятие подтверждено кодом и конструкцией proof; live hostile-peer baseline и обход корректного explicit pin не заявлены. Место вызова общего verifier проверено до сборки/отправки credentials в transport core.

Отдельная Python HMAC-SHA256 реализация проверила **5 HKDF wire vectors / 18 checks** всех четырёх схем, направления, порядок IKM и изменение входа. Она не вызывает Rust generator/helper. Это независимая реализация проверки consistency, не внешний криптоаудит или независимая сертификация примитивов.

Linux: **2270 units PASS / 60 ignored**, full/minimal Clippy и rustfmt PASS. Свежие **18/327 matrix**, aggregate leak и **100 TCP + 100 QUIC / 33 soak checks PASS**. Все четыре native cores прошли независимые A/B builds; ABI/canonical-client copies/provenance PASS. .11 snapshots/service/binary сохранены. Текущая .10 пара и её поля записаны в evidence; историческая неатрибутированная вариативность legacy IPv4 dumps остаётся ограничением, общего host-preservation PASS для .10 нет. Рабочие службы не заменялись, push и новый performance benchmark не выполнялись. Физические advisory rows не изменены.

## Завершение Q08

| ID | Проблема | Исправление |
| --- | --- | --- |
| Q08-F004, P2 | `ml-kem` не включал optional zeroize; retained decapsulation key не имел защищённого Drop. | Включены ml-kem/module-lattice/hybrid-array zeroize; compile-time тест требует DecapKey: ZeroizeOnDrop. Временный SharedKey внутри helper тоже Zeroizing. |
| Q08-F005, P3 | Static session binding использовал unchecked DH для pin; точка 1 давала нулевой secret на входе KDF. | Checked DH отклоняет низкопорядковый pin до KDF. Поздний proof verifier уже отказывал, поэтому обход отправки credentials здесь не заявлен. |
| Q08-F006, P3 | Unused helper генерировал PQ-долю и выбрасывал ключ; тест counter_wraps проверял только 100 обычных пакетов. | Helper удалён; tests используют retained keypair. Ложный wrap-тест переименован, добавлена настоящая проверка границы исчерпания. |
| Q08-F007, P2 | Документы обещали обязательный inner PQ для reality-tls, хотя текущий private inner exchange классический. | Уточнены crypto comments, RU/EN README, THREAT-MODEL, AUDIT, ROADMAP и COMPARISON: legacy camouflage требует inner hybrid; REALITY TLS PQ зависит от внешней согласованной группы. |

Review завершён по семи направлениям: primitives/KDF/AEAD; static binding и proof-before-credentials; pin/TOFU; RNG/nonce; rotation/storage/trust; memory; dead code/security claims. Raw/fake-TLS TCP, UDP и JOIN/resume проверены по порядку вызовов verifier → trust admission → credentials/token. Duplex-тест настоящего raw handshake доказывает отсутствие credential bytes при повреждённом proof и при отказе trust callback. Подробная карта review записана в evidence.

Независимые known answers: **60 NIST ML-KEM-768 cases** (25 keygen, 25 encapsulation, 10 decapsulation; пять ciphertext с изменениями), закреплённые upstream commit, полные SHA и tcId/tgId. Выборка byte-for-byte проверена с оригинальными файлами NIST. Invalid full-length ciphertext даёт эталонный implicit-rejection secret; неверная длина даёт None. Проверены canonical modulus и ошибки длины. **RFC 7748 §6.1 X25519**, **RFC 8439 §2.8.2 ChaCha20-Poly1305**, независимый Python cryptography empty-AAD oracle для реальных allocating/detached wrappers; изменение каждого из 130 ciphertext/tag bytes отвергается, detached output остаётся ciphertext. Wrong nonce/AAD и short tags отвергаются. **5 HKDF vectors / 18 Python HMAC checks** повторно PASS. Existing RFC 8448 AES-128 record vector и AES-256 integration/roundtrip просмотрены; полный outer TLS — раздел Q11.

RNG использует OS/getrandom и rand 0.10.2 ChaCha12 с SysRng seed/reseed, без слабого fallback при ошибке entropy. Supervisor запускает worker через exec текущего executable; текущие пути не продолжают скопированное состояние ThreadRng после fork. Проверены контракт fresh ephemeral для REALITY seal и fresh session keys при reconnect, PRP bijection и raw/TLS counter exhaustion до wrap: отказ не расходует counter и очищает прежний record. Это review источников RNG и инвариантов, не статистическая или side-channel сертификация.

На финальном точном release `670729a549217717f774408cf7839f72b09c26679e1acf03c72a65d339c2010e`: **31 keys/rotation + 25 restore/state = 56 HTTP/system checks PASS**. Настоящие pinned-клиенты подключались со старой identity до rotation, со старой identity работающего worker после записи новой, с новой после явного restart; неправильные поколения pin давали именно криптографический отказ. API/CLI generation меняет persisted bytes/public key с 0600; API не рестартит worker, list показывает persisted generation. Restore сохраняет reissue и actual VPN traffic. **2279 Linux units PASS / 60 ignored**, pinned full/minimal Clippy/rustfmt PASS. Свежие **18/327 matrix**, aggregate leak и **100 TCP + 100 QUIC / 33 soak checks PASS**. Четыре native cores: свежие A/B, ABI/copies/provenance PASS. .11 host/service/binary сохранены; текущая .10 пара записана, прежнее ограничение legacy dumps сохранено.

## Границы результата

Ключевые X25519/ML-KEM objects и оговорённые loader/KDF/session buffers обнуляются. Public Vec/array API возвращают копии в собственность callers; гарантии удаления всех временных копий, FFI-буферов, CPU registers, swap и crash dumps нет. Прежнее принятое ограничение AES expanded schedule остаётся. KAT не заменяют внешний криптоаудит или доказательство безопасности.

Operator regular links и существующие owner/mode сохраняются при чтении; созданные keys — 0600, штатный identity directory — 0700. Проверенный atomic writer и sidecar locks не сертифицируют power loss, несогласованные root writes и старые binaries. Bounded bytes/FIFO refusal не обещают hard deadline обычного filesystem IO. Session key fallback, best-effort reversible CLI encryption и ограничения первого TOFU contact сохранены. Physical advisory exclusions не изменены. Working services не заменялись; push, deploy и новый performance benchmark не выполнялись.

**Q08 DONE:** все пять пунктов чек-листа закрыты в заявленных границах, обязательных проверок текущих fixes не осталось. Следующий раздел — Q09, handshake/pre-auth. [Финальные свидетельства](../../../../release/certification/evidence/q08-completion-20261003.json); [первый пакет и baseline](../../../../release/certification/evidence/q08-keys-20261003.json).
