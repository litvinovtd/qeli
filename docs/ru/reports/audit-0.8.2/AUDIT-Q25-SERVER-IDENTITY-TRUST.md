# Q25-F143: доверие к путям identity_key и logging.file

1 октября 2026. База: `7be8bd74`. D07 остаётся **IN_PROGRESS**.

`identity_key` позволяет конфигу направить создание или замену приватного ключа в произвольный путь. При этом worker/supervisor и CLI `show-identity`, `rotate-identity`, `add-client --link`, `share-link` использовали путь даже из group/world-writable или symlink-конфига: запрет выполнения shell-hooks этого не покрывал. Безопасный baseline `check-config` в лабе `.11` вернул `OK` для mode `0666` с явным `identity_key`; запись ключа при baseline не выполнялась. Отдельно `[logging] file` открывался ещё до основной проверки, поэтому недоверенный конфиг мог управлять созданием лог-файла.

Новый `ConfigSourceSnapshot` держит содержимое и решение о доверии из одного открытого inode. Для явного `identity_key` CLI и оба startup-пути требуют обычный файл с владельцем root/эффективным UID, без symlink и group/world write; отказ происходит до записи ключа, а в `add-client --link` — до записи пользователя. `check-config` применяет тот же допуск. Ранний логгер из недоверенного файла игнорирует `logging.file`, предупреждает в stderr и продолжает писать туда; путь к файлу/каталогу не открывается. Обычный путь ключа по имени профиля остаётся доступен без явного `identity_key`.

Проверка: unit-тесты неизменности trust после chmod и раннего логгера; `cargo fmt --check`, строгий Clippy; Linux CLI-матрица отказов `check-config`, `server`, `_worker`, `show-identity`, `rotate-identity`, `add-client --link`, `share-link` для mode `0666`; отсутствие ключа, лога и users-файла; затем положительный `0600` с `check-config` и ключом режима `0600`. Логи: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/identitytrustbaseline.log` и `identitytrustfixed.log`.

Это не общий запрет всех файловых эффектов из недоверенного INI: пути `users_file`, TLS и другие настройки требуют отдельного разбора в D07. Остаются полная матрица полей и гонка внешней записи при сохранении панели.
