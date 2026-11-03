# Q33: настоящий CLI установщика и совместимость чтения версии

<!-- normative-sync: q33-installer-cli-v1 -->

8 октября 2026. F437–F438 / Q33-F040–F041. Q33 остаётся IN_PROGRESS.

## Находки и исправления

- **F437 / Q33-F040:** выбор payload tag и updater fallback использовали `qeli version`. Текущий CLI поддерживает команду, но старая установка может иметь только `qeli --version`. Рабочий lab binary0.7.5 принимает --version и отвергает subcommand. Оба скрипта теперь читают номер версии через --version. `qeli version --check` остаётся допустимой current opt-in проверкой обновлений. Binary/updater fixtures теперь отвергают неподдерживаемые команды вместо выдачи версии при любых argv.
- **F438 / Q33-F041:** настоящий CLI создаёт постоянный `.lock` рядом с уникальным INI stage. Публикация удаляла stage, но оставляла его lock в /etc/qeli. Точное соседнее имя зарегистрировано вместе со stage для EXIT cleanup после завершения синхронных writers. Live config/users locks сохраняются. Secret CLI fixture также создаёт stage lock, поэтому обычные failure/success tests проверяют его очистку.

## Выполненные проверки

Version baseline2 methods дают2 ожидаемых assertion failures, fixed2 PASS. Actual CLI initial5 methods дают4 orphan-lock failures; custom-unit override/revert проходит. После исправления все5 PASS без skipped: полный installer flow для UDP, fake TLS и REALITY; настоящий check-config отвергает неверный port в INI stage без изменения live bytes; actual custom systemd-unit override создаётся/удаляется. Каждый успешный flow создаёт5 настоящих users с Argon2 hashes, настоящий panel password hash, identity keys и5 share links; проверяет staged/final INI, config owner234/mode0600, summary/journal/temp cleanup. Создание identity/link не доказывает VPN handshake или password-auth round trip.

Команды: `sudo unshare --mount --net --pid --fork python3 -B scripts/test_installer_cli_version.py`; `sudo env QELI_AUDIT_BINARY=/absolute/provenance-checked/qeli unshare --mount --net --pid --fork python3 -B scripts/test_installer_real_cli.py`. Нужны Linux root/chroot, Bash/coreutils/dpkg fixture tools, jq, openssl и loader/libraries бинарника. Тест не скачивает/не собирает explicit binary; отсутствие binary/platform означает skip, не PASS qualification. Точная локальная CI повторяет2+5 без skipped. Config21/secrets21/admission18/binary18/updater21 regressions PASS (всего99), ShellCheck0.10.0 warning/bash syntax обоих скриптов, recipes38 mocked/native14 SHA-source-A-B/docs9 checks/678 Markdown PASS.

Повторно использован genuine debug artifact из source85ea8fa9adab146d52b6f8908e5f29c89f2d8c20, sealed q32-logs-trace-20261008, SHA256 `37a6e349ed5b72c44cb72ba147e4df7e87e277763c250cfe226173a6e9414b7c`. Current main/CLI/parser/identity/users/web/trust/preflight/helper paths не менялись. Более поздние различия: client/mod, client/plan_publication, config/notify, server/notify. Это scoped reuse, не current full Rust rebuild, release jemalloc qualification или native ABI rerun. Initial installer input реконструирован удалением точного cleanup patch из current bytes, это не независимо измеренный initial-input SHA; final lab input SHA проверен.

Настоящий CLI выполняет parsing, key generation, Argon2 hashing, user persistence, links и custom drop-in updates. Account creation, HTTP, systemctl manager/start/health, kernel/tuning и preflight ip commands — seams. Sockets/TUN/firewall/VPN/Docker не квалифицированы. CI теперь запускает actual-CLI suite после извлечения собранного portable .deb с explicit executable assertion; этот package pipeline/Actions run локально не выполнялся. Дополнительной Rust/native сборки и product Rust changes нет.

Default qeli.service root-to-qeli transition остаётся OPEN: прежний helper рекурсивно chown /etc/qeli, включая root0600 secret receipts/backups; installer default qeli не отменяет прежний root override. Исполнен только revert отдельного custom unit. Whole-install/account rollback, restart-after-publication rollback, fsync/SIGKILL/power-loss durability и ancestor-directory race protection не заявлены.

Evidence: `release/certification/evidence/q33-installer-cli-20261008.json`. Raw `audit-debt-20260924/q33-installer-cli-20261008` SEALED334 файла/41695825 байт; manifest SHA256 `463e8729410b56be06f662e2c3193d78cf3aea1daea6971b320c7395e8f80c17`. Сохранены initial failures, baseline/fixed version logs, final/CI real generated state и recoverable archive с SHA-checked actual binary. Собственный .11 root backed-up/guarded-cleaned; service777/845 сохранены, .10 не затрагивался.

Общий план29/37 DONE(78.4%),осталось8. Q31 3/5/capacity-deferred bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, USER_EXCLUDED платформы и D06 ACCEPTED сохранены. Локальный dev commit, без push/deploy/release.
