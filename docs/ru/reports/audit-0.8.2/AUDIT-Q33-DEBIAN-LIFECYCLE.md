# Q33: lifecycle Debian-пакета и защита рабочего состояния

<!-- normative-sync: q33-debian-lifecycle-v1 -->

8 октября 2026. F412–F416 / Q33-F015–F019. Q33 остаётся IN_PROGRESS. Production packaging и maintainer scripts проверены настоящими make/dpkg в приватных chroot. Бинарник qeli, зависимости и внешние service/debconf/account операции — стендовые подмены; полный installer, настоящий daemon/systemd и Docker image/recreation ещё открыты.

## Находки и исправления

- **F412 / Q33-F015:** прямая настройка пакета при umask022 создавала users.conf0644. Postinst теперь использует umask077, mktemp0600 в том же каталоге и GNU ln -T без замены назначения. Создаётся пустой файл, пример с известным хешем не копируется. Существующий обычный users-файл сохраняет байты/режим; свой временный файл очищается на exit/INT/TERM. fsync/power-loss/SIGKILL durability не заявлена.
- **F413 / Q33-F016:** dangling/regular users symlink и linked state roots перенаправляли root-запись, изменение владельцев и распаковку пакета. Новый preinst отклоняет symlink/не-каталог /etc/qeli, /var/log/qeli, /var/lib/qeli, а также linked/nonregular users.conf до unpack. Postinst повторяет guard для dpkg --configure, явно использует physical/nondereferencing recursive chown и безопасную публикацию. Makefile включает preinst в настоящий пакет. Это pathname guards, не descriptor-pinned защита от привилегированной конкурентной замены; каталог сервисного пользователя по-прежнему доступен его владельцу.
- **F414 / Q33-F017:** ошибка debconf могла использовать старый RET, неизвестный ответ молча превращался в qeli, а ошибка set-service-user скрывалась с сообщением об успехе. Неуспешный lookup теперь даёт qeli; допускаются только root/qeli. На загруженном systemd-хосте ошибка CLI оставляет dpkg half-configured до успешного configure retry. Без /run/systemd/system выводится явное предупреждение и команда повтора; сообщение о применённом пользователе не печатается. Установка в незагруженном container/chroot сохраняется, но применение выбора не объявляется подтверждённым.
- **F415 / Q33-F018:** prerm игнорировал stop failure и позволял dpkg удалить ещё работающий пакет. Теперь при наличии systemd и ошибке stop удаление отклоняется. Незагруженные окружения поддерживаются; disable остаётся best effort. Upgrade сам не останавливает/перезапускает службу: restart делает updater либо администратор.
- **F416 / Q33-F019:** postinst запускает adduser, но зависимость отсутствовала в control. Depends теперь включает adduser.

## Выполненные проверки

`scripts/test_debian_lifecycle.py` использует общий disposable chroot fixture updater; нужны Linux root, make/dpkg и утилиты стенда. Запуск в private mount/network/PID namespaces:

```bash
sudo unshare --mount --net --pid --fork python3 -B scripts/test_debian_lifecycle.py
```

QELI_DEBIAN_SOURCE/QELI_DEBIAN_CONFIG_SOURCE выбирают snapshot, QELI_DEBIAN_FIXTURE_RECORDS сохраняет пакеты, QELI_DEBIAN_OPERATION_RECORDS — результаты настоящих команд. Точная команда добавлена в Linux CI, ShellCheck warning gate теперь включает preinst/postinst/prerm.

Десять старых методов воспроизводят12 ожидаемых ошибок: метод root-link содержит три subcase. Итоговые16 методов PASS без skips: fresh install, upgrade, configure failure/retry, remove/purge, приватный пустой users, сохранение config/users/identity/client-link bytes, ссылки/FIFO, debconf, выбор root и booted/nonbooted failures. Выполнены24 настоящих lifecycle-вызова dpkg и один допуск семи инертных dependency-пакетов. --force-depends не используется. Точная команда CI независимо проходит16 методов/24 lifecycle-вызова. Windows16 skips не подтверждают runtime.

Production Makefile deb-prebuilt/stage собирает две версии .deb с production scripts/unit/polkit/templates/examples. Version0.8.1 — синтетическое изменение control для upgrade, а не старый release artifact. Бинарник qeli инертно записывает команды; зависимости — именные инертные пакеты. Account creation, debconf replies и systemctl явно подменены. Настоящие apt resolution, debconf frontend, account allocation, CLI implementation, ELF/glibc/CPU baseline, daemon/VPN/systemd не подтверждаются этими тестами. Отдельный from-binary installer не покрыт; его подготовка state-files ещё требует переноса.

Две ошибки подготовки (chroot отсутствовал в ограниченном PATH, host TMPDIR проник внутрь chroot) сохранены отдельно и исключены из находок продукта. Итоговые source SHA совпадают с переданными файлами; ShellCheck0.10.0 warning gate и bash syntax PASS. До guarded path/process/fd/mount cleanup собственного каталога получен и проверен recoverable backup. MainPID777/worker845 сохранены; аккаунты/firewall хоста не изменялись.

Evidence: `release/certification/evidence/q33-debian-lifecycle-20261008.json`. Raw: `audit-debt-20260924/q33-debian-lifecycle-20261008`,97 файлов/6721704 байт; manifest SHA256 `0e2e94ded3ab4c39a26641c5689c98375ba9a22e01e94f9cd729da37df562de2`. Native/Rust build inputs и ядра не менялись;14SHA/provenance и38 mocked recipe tests проходят без новой тяжёлой сборки.

Q33 целиком остаётся открытым. Общий план29/37 DONE(78.4%),осталось восемь. Q31 bootstrap/source-cut/current Actions, Q29 SIGKILL/ENONET, Q30 Apple/callback, USER_EXCLUDED платформы и D06 ACCEPTED_LIMITATION сохранены. Без push/deploy/release.
