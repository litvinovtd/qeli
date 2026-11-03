# Q33: подготовка payload и состояния при установке из бинарника

<!-- normative-sync: q33-binary-installer-v1 -->

8 октября 2026. F417–F421 / Q33-F020–F024. Q33 остаётся IN_PROGRESS. Проверены точный prefix/functions installer и два ранних отказа полного скрипта. Полный config/users/panel/network/service flow и Docker integration этим пакетом не подтверждаются.

## Находки и исправления

- **F417 / Q33-F020:** локальный _pkg_file возвращал0 после ошибки install: условный caller отключает неявный set-e внутри функции. Теперь ошибка копирования явно передаётся вызывающему коду и не считается полученным проверенным файлом.
- **F418 / Q33-F021:** отсутствующий файл явного QELI_SRC заменялся удалённым, смешивая источники; бинарник менялся до проверки примеров/unit/rule. Явный checkout теперь единственный источник. Восемь примеров, unit и polkit rule сначала готовятся в приватном staging до изменения бинарника/аккаунта/state. Ошибки допуска missing/copy/SHA/attestation сохраняют старый бинарник; последующая публикация последовательная, не атомарная транзакция install/rollback. Rule берётся из допущенного payload вместо потенциально другого install-polkit. Для удалённого default tag версия читается из переданного бинарника до его установки.
- **F419 / Q33-F022:** from-binary users creation следовал dangling symlink; linked roots перенаправляли запись/chown. Общий guard installer отклоняет linked/non-directory state roots, включая identity/client-links, и linked/nonregular config/default users до зависимостей и повторно при from-binary entry. Обе точки создания users используют private0600 no-replace публикацию; существующие обычные файлы сохраняют байты/режим. Ownership-команды явно physical/nondereferencing. Pathname guards не закрепляют дескрипторы от конкурентной замены владельцем каталогов/администратором; полный downstream publication ещё открыт.
- **F420 / Q33-F023:** INT/TERM выполнял cleanup, затем установка продолжалась. Trap теперь завершает130/143, EXIT очищает временные файлы. Self-signal проверки подтверждают отсутствие следующей записи. Это не проверка остановки всех внешних children и не SIGKILL/power-loss durability.
- **F421 / Q33-F024:** remote payload выбирал первый .deb, принимал checksum-valid чужой Package и игнорировал обязательную attestation. Теперь выбор по dpkg architecture хоста, metadata qeli/host arch либо all и запрошенная gh attestation проверяются до extraction. Локальный checkout оператора остаётся доверенным input. Суммы получены из релиза; настоящая OIDC/provenance проверка не подменяется заявлением PASS.

## Проверки и границы

Команда: `sudo unshare --mount --net --pid --fork python3 -B scripts/test_binary_installer.py`. Нужны Linux root/chroot, настоящие Bash/coreutils/dpkg-deb и jq. Используется общий updater fixture. QELI_BINARY_INSTALLER_SOURCE/QELI_BINARY_PAYLOAD_SOURCE выбирают snapshot; QELI_BINARY_FIXTURE_RECORDS сохраняет пакеты/prefix, QELI_BINARY_OPERATION_RECORDS — фактические вызовы.

Байты до существующего маркера `# Must run as root.` исполняются без переписывания функций. Итоговые18 методов PASS без skips:23 запуска,21 prefix/function и два ранних отказа полного скрипта.14 старых целевых методов дают19 ожидаемых ошибок с root-link/signal subcases. Покрыты admission/copy failure, изоляция явного source, сохранение layout/state, пустой users0600, опасные roots/config/users, invalid binary до apt, SIGINT/TERM, remote architecture/metadata/CRLF SHA, fresh remote install без старого бинарника и gh missing/failure/success.

Три настоящих .deb payload-fixture содержат точные текущие examples/unit/rule; extraction и SHA реальны. HTTP/байты, account creation, systemctl, инертный qeli/version явно подменены; copy failure вводится детерминированно. Успешный gh только записывает команду, не выполняет криптографическую проверку. Настоящие daemon/ELF/apt installation, identity generation/users creation, panel auth, firewall/sysctl, final restart/health и VPN не запускались.

Точная команда CI независимо проходит18 методов/23 запуска. С изменённым installer также проходят все21 updater regression methods. ShellCheck0.10.0 warning gate и bash syntax PASS. Это локальная проверка команды, не новый Actions run. Ошибок подготовки не было: сохранён первоначальный baseline12/fixed15, затем окончательное расширение attestation. Собственный каталог SHA-backed-up и guarded-cleaned, service777/845 сохранён.

Полный QELI_SRC даёт Qeli payload без HTTP, но весь скрипт пока вызывает apt для системных зависимостей: полностью отключённая от сети first install не подтверждена. Guards/staging не покрывают все последующие secret writes; полный installer publication/tuning/service integration и Docker build/recreation/health открыты.

Evidence: `release/certification/evidence/q33-binary-installer-20261008.json`. Raw: `audit-debt-20260924/q33-binary-installer-20261008`,62 файла/6744559 байт; manifest SHA256 `67021e3c4669fe6bcb08113ffeb616f6e6f3d2c274e0b1d7b1f44fab7f36c331`. Native/Rust/ABI/core inputs не менялись;14SHA/provenance и38 mocked recipe checks PASS без новой тяжёлой сборки.

Общий план29/37 DONE(78.4%),осталось восемь; Q31 bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, USER_EXCLUDED платформы и D06 ACCEPTED сохранены. Без push/deploy/release.
