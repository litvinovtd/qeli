# Q28: хранилища macOS и ключ профилей

<!-- normative-sync: audit-q28-macos-storage-v1 -->

**5 октября 2026: этап PASS; Q28 IN_PROGRESS. План 27/37 (73,0%), осталось 10.**

## Исправления

| ID | Проблема и результат |
|---|---|
| F240 | `MacKeychain.Find` возвращал null при любом отказе, а `SecureKey` мог создать другой ключ. Одновременно запущенные экземпляры также могли вернуть разные ключи. `ProfileKeyCoordinator` согласует чтение, выбор, создание и миграцию через `.store.key.lock` с ожиданием не более 1 секунды. Native lookup отличает отсутствие item от ошибки. Первое создание не обновляет duplicate item; проверяется ключ существующего item. Без известного ключа создание запрещено при наличии зашифрованного/невалидного текущего архива или backup. Только полностью разобранный legacy-массив допускает создание первого ключа. |
| F241 | `FileFind` читал файл ключа без ограничения, ошибки и неверный размер выглядели как отсутствие ключа. `ReadChild` проверял fstat.Size, затем делал неограниченный CopyTo. `BoundedStorage` ограничивает чтение, включая рост после fstat и non-seekable потоки: максимум limit+1 байт. Fallback/journal обязаны содержать ровно 32 байта; неправильный или недоступный файл сохраняется, ошибка передаётся вызывающему коду. |
| F242 | Ошибка получения ключа внутри catch обработки архива приводила к quarantine и пустому списку. `MacProfileArchive` получает ключ до обработки повреждённых байтов. Отказы доступа/записи/миграции передаются наружу; валидный архив остаётся на месте. Сохраняются строгий UTF-8, authenticated backup, атомарная запись, защита от stale writer и quarantine действительно повреждённых данных. Буферы расшифрованного текста очищаются после использования. |

Извлечены production-объекты с областью действия конкретного каталога/архива. Отдельного тестового алгоритма шифрования/миграции нет. Убраны небезопасный catch-all native lookup, неограниченное чтение ключа и гонка загрузки Security/CoreFoundation: handles теперь создаются через Lazy один раз на процесс. Fallback создаётся с UnixCreateMode 0600. Согласование ключа и профилей использует отдельные sidecar locks без вложенного захвата.

Если Keychain недоступен, допустим только уже существующий валидный fallback или recovery key миграции; неизвестный ключ не заменяется. Несовпадение Keychain/fallback/journal останавливает операцию. Старый ACL `/usr/bin/security` остаётся мигрируемым через существующий recovery journal. Успешная миграция не меняет 32 байта ключа.

## Проверки и границы результата

- Release QeliMac на Windows/.NET 10: PASS, 0 ошибок и предупреждений.
- `storage-selftest`: **54/54 PASS**: три envelope-проверки и 51 проверка production coordinator/archive/bounded reader. Проверены 16 конкурентных экземпляров, два отдельных процесса, timeout sidecar lock, duplicate item, потерянный/недоступный/повреждённый ключ, несовпадения источников, legacy ACL/base64, interrupted migration, backup/stale writer/UTF-8 и отказы Save/migration.
- Baseline: **5/5 ожидаемых FAIL**, harness exit 1. Механически адаптированы прежние GetOrCreate/FileFind/FileStore и ProfileStore.Load/Save: только пути, static → instance и native Keychain/tool calls заменены зависимостями. Детерминированная гонка задаётся barrier в rejected Store. Growth case использует прежний CopyTo после fstat. Это не запуск старого Darwin/Keychain API.
- Bound-reader cases: seekable 2 ГиБ отклоняется до первого Read; растущий non-seekable поток потребляет ровно 33 байта при лимите 32. Darwin ReadChild использует тот же helper после проверки fd/owner/mode; реальные syscalls не выполнялись.
- Hashes shared/Windows inputs сверены с Q27; Rust/native и 14 checksum rows не менялись. Нет новых Linux/JNI/soak/benchmark результатов.
- Windows native `qeli.dll` в игнорируемом выходном каталоге нужен только для общих computed config properties при сериализации. Это тест C#/AES/storage и host FFI, не подтверждение `libqeli.dylib`, Intel/ARM ABI, launchd, utun, pf, entitlements или настоящего Keychain.

Проверки работают с новыми временными каталогами и удаляют их; пользовательские профили/ключи и состояние daemon не открываются. Секреты тестов не выводятся. Реальные Mac runtime/sleep/wake/Network Extension/Keychain проверки **USER SKIPPED**, по решению пользователя, не PASS. INI остаётся единственным форматом конфигурации; JSON здесь только внутренний DTO/зашифрованный архив.

Lock ограничивает ожидание между сотрудничающими процессами Qeli, но не время native Keychain prompt/I/O внутри владельца и не защищает от прямого изменения каталога тем же пользователем. 0600 проверяется платформенно в selftest на Unix; в этом прогоне Windows Unix-mode assertion не выполняется и не включена в 54. Без Keychain и recovery/fallback ключа архив требует явного восстановления; автоматическое создание нового ключа запрещено. Ручная замена на другой валидный ключ не является поддерживаемым восстановлением.

## Evidence и следующий этап

`release/certification/evidence/q28-macos-storage-20261005.json`; immutable execution snapshots — `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-storage-20261005`. Исходные baseline-файлы, адаптация, raw logs и SHA-256 сохранены отдельно от результатов исправления.

Далее в Q28: daemon/helper и selected profile, доверие plist/IPC/status/log, cleanup utun/pf/DNS, Swift Network Extension и сборочные контракты. Эти критерии пока не закрыты; процент плана не повышен за частичный этап.
