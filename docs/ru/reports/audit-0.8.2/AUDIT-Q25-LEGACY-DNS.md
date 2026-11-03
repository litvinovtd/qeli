# Q25: безопасный отказ от старого глобального DNS recovery

Дата: 24 сентября 2026. Baseline: `da27ec6b`. Q25-F101 исправлен в описанных пределах.
D04 остаётся **IN_PROGRESS**: live persistent TUN и полная mixed firewall матрица открыты.

## Находка

**Q25-F101, P2 — старый снимок давал право изменить чужой resolver без доказательства владения.**
`dns-backup.json` содержит только kind/target/content/mode. В нём нет boot ID, network
или mount namespace, текущего inode `/etc/resolv.conf` и подтверждения, что его всё ещё
контролирует Qeli. Тем не менее startup автоматически восстанавливал такой снимок.
PID-only `dns-holders` проверялся в текущем PID namespace; блокировка освобождалась до
изменения resolver. Корректные права state каталога не восполняли недостающие сведения.

Настоящий baseline-клиент в приватных namespaces подтвердил четыре изменения файла
администратора: перезапись содержимого, удаление, замену symlink и подстановку
`1.1.1.1`/`8.8.8.8` для `managed-no-original`. Снимок после этого удалялся. Битая ссылка
backup считалась отсутствием; FIFO и занятый `dns-holders.lock` задерживали startup
до принудительного завершения тестом. В сценариях повреждённого снимка старый код
оставлял backup, но успевал создать lock/изменить holder state.

## Решение и удалённый код

Автоматический replay снят: старые записи не позволяют безопасно отличить аварийный
остаток Qeli от уже перенастроенного DNS. В доверенном закреплённом state каталоге
проверяется наличие `dns-backup.json` и `dns-holders` через metadata без следования
конечной symlink. Любой тип записи, включая пустую, повреждённую, каталог или FIFO,
требует ручного восстановления и прекращает запуск клиента до DNS-команд.

Содержимое не читается, PID не интерпретируются, legacy lock не открывается и
не ожидается. `/etc/resolv.conf`, backup, holders и их lock остаются нетронутыми.
Ошибка metadata не считается отсутствием. Один стабильный `dns-holders.lock` без
backup/holders не блокирует новый клиент: сам sidecar не доказывает pending recovery.

Удалены `dns_backup` с автоматическим restore/unlink/symlink/chmod и публичным DNS
fallback, PID refcount helper и неиспользуемые реализации capture/write из tests.
Тесты снятого поведения заменены проверками запрета replay; per-link DNS tests
сохранены. Поэтому число тестов уменьшилось осознанно, а не из-за пропущенного набора.
Конфигурации остаются INI; новый конфиг, команда восстановления или формат legacy
снимка не добавлены. Новые соединения продолжают использовать systemd-resolved.

## Проверки

- **1526 host + 71 config; все 9 feature/cross/lint checks PASS**.
- **2078 Linux + 43 privileged + 8 worker lifecycle PASS**.
- 4 portable и 3 Unix regressions: отсутствие/lock-only, все виды payload и повреждение,
  holder-only/live/stale PID, каталоги, dangling/обычные symlink, FIFO и ошибка metadata.
- Новый `scripts/audit_legacy_dns_recovery.py`: 12 настоящих запусков клиента в отдельных
  network/mount/PID namespaces с приватными `/etc`, `/var/lib`, `/run`, `/var/log`.
  Проверяются содержимое/type/inode resolver, точность сохранения legacy evidence,
  явный отказ и отсутствие зависания. `dns = off` также не разрешает старый replay.
- **Baseline 15/47 PASS, 32 FAIL** по новому контракту; четыре из них проверяют реальные
  изменения resolver. Это 32 проваленные проверки, а не 32 независимых дефекта.
  В file/absent/symlink/fallback сценариях timeout означает продолжение reconnect
  после опасной операции, а не зависание recovery. FIFO/locked-holder останавливаются
  до подключения. Контроль без legacy state доходит до соединения с тестовым адресом.
- **Исправленный клиент: 47/47 PASS**. Контроль без legacy state оставляет
  resolver и доходит до соединения; остальные 11 сценариев отказывают явно и своевременно.
- Linux packet matrix: **17/17 cases, 489 assertions PASS**;
  сохранены DNS через настоящий resolved, его SIGKILL/restart, route crash recovery,
  kill-switch, IPv4/IPv6, TCP/UDP, split/TAP и MTU/PMTU проверки.

Source snapshot: 340 files, archive SHA256 `4df30a4035df14b6fdb6165b51fafddc75690a8588397a7388d276107e909b5b`.
Worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
Baseline worker SHA256: `de18b1b171701704e548c0d4067fbfa7d398f9567f434c95aedc1d97ab228fed`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/legacy-dns-phase/`,
`legacy-dns-baseline-v2/`, `legacy-dns-fixed-v1/`, `legacy-dns-final-v1.log`,
`lifecycle-legacy-dns/`, `packet-matrix-legacy-dns-v1/`. Baseline и fixed используют
одинаковый runtime harness; source проверен до/после Linux и сопоставлен с git index.
Symlink/FIFO fixtures хранятся в исходных tar, на Windows распакованы только обычные
файлы/каталоги и metadata evidence. Первый collect отказался извлекать FIFO; это
ограничение распаковки, не ошибка клиента. Linux Rust 1.97, host Rust 1.98;
прежнее исключение Clippy `chunks_exact_to_as_chunks` сохранено.

## Эксплуатация и границы

Это намеренная граница совместимости: автоматическое восстановление глобальных
снимков старых релизов больше не поддерживается. Штатно остановите старый клиент до
обновления. Если legacy state остался, проверьте исходную сеть/mount view, остановите
его владельцев, восстановите DNS через ответственный network manager либо проверенный
оригинал, затем архивируйте только разобранные backup/holders вне рабочих имён.
Снимок с неизвестным оригиналом не выбирает публичный DNS за администратора.
См. [процедуру §6.20](../../manuals/TROUBLESHOOTING.md#620-linux-восстановление-старого-dns-не-удалось-снимок-сохранён).

Не обещается координация с одновременно запускаемыми старыми бинарниками или другим
root. Метаданные и последующие операции не атомарны; внутренний filesystem I/O не
получает жёсткого wall-clock срока. Эти границы не возвращают автоматический replay.
D04 legacy global DNS закрыт как безопасный отказ и документированная ручная миграция,
а не как автоматическое исправление произвольного старого хоста. Остаются live
persistent TUN и mixed nft/firewalld; всего **3/15 групп DONE (20%)**.
`.10` не изменялся; native проверки выполнялись в изолированных namespaces `.11`.
Windows VM/Mac/iOS/router runtime остаются SKIPPED по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md)

Продолжение 24 сентября: [persistent TUN/TAP проверен в 17 crash-сценариях](AUDIT-Q25-PERSISTENT-TUN.md). Безопасный отказ и ручное удаление подтверждённого остатка закрывают эту часть D04; полная mixed firewall матрица остаётся открытой.

Итоговое продолжение D04: [клиентская mixed packet/recovery матрица и Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) завершены, D04 DONE в текущем реестре. Исторические IN_PROGRESS выше относятся к прежнему снимку. D10 (расширенные политики/топологии) и D13 (рост состояния) остаются открытыми.
