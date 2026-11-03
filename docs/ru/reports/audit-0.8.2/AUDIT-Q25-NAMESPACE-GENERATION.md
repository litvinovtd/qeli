# Q25 — поколение network namespace в sysctl-журнале v4

<!-- normative-sync: audit-q25-namespace-generation-v1 -->

24 сентября 2026. База: `ee2f5b002b6753db993078cdb31a05181a94bfbe`.
Закрытие D02 в [реестре техдолга](../../plans/AUDIT-DEBT.md).

## Q25-F090, P2 — inode namespace не доказывал поколение после crash

Удержание namespace fd защищало текущую транзакцию, но журнал v3 хранил только
boot-id и dev/inode. После смерти последнего владельца inode может использоваться
другим namespace в той же загрузке. Тогда старый global original не имеет достаточного
основания для записи в новый объект. Per-interface fd/witness уже защищены фазой v3.

В v4 группа сохраняет дополнительно `network_cookie`, полученный через `SO_NETNS_COOKIE`
от локального UDP-сокета без bind/connect/передачи пакетов. Значение сверяется перед
pruning владельцев, чтением/записью sysctl и сохранением состояния. Контекст удерживает
прежние namespace fd. Сокет закрывается через OwnedFd. Нулевой, неправильный размер,
ошибка чтения или несовпадение cookie не дают продолжить восстановление.

Выбор cookie основан на реализации Linux: новое net-поколение получает cookie из
общего генератора, а socket option возвращает cookie сети этого сокета.
[Генерация в Linux 6.12](https://github.com/torvalds/linux/blob/v6.12/net/core/net_namespace.c),
[getsockopt](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c).
Это поколение в пределах boot-id, не криптографическая защита от root, меняющего журнал.

При ENOPROTOOPT пустой recovery допускается, но новое управление sysctl отказывает
до записи с `SO_NETNS_COOKIE is required`. Прочие ошибки сокета не скрываются.
Непустой v3 текущей загрузки не мигрирует путём присвоения текущего cookie: это потеряло
бы свидетельство. Требуется подтверждённое завершение старых владельцев в исходной
сети до обновления либо плановый reboot. Валидный прошлый boot и пустой legacy журнал
переходят без replay. Повреждённый v4 отказывает даже с прошлым boot-id.
Старые v1/v2 сохраняют прежние ограничения. Смешивать версии участников нельзя.

## Проверки

Четыре новые portable-регрессии: повторный inode с другим cookie; отсутствие/ошибка
cookie; непустой legacy v3; null/zero/string cookie v4, включая прежнюю загрузку.
Обновлены два старых fixture для новой версии/обязательного cookie.
Один новый native-тест подтверждает стабильность cookie, другое значение после unshare
и исходное значение после возврата через удержанный namespace fd.

**1479 host unit + 71 config**, все **9 feature/cross/lint команд PASS**.
**1995 обычных Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
Дополнительный worker E2E: SIGKILL; журнал с другим cookie отвергается побайтово без
изменения global/per-interface sysctl и без запуска профиля. После возврата настоящего
cookie global original восстанавливаются, а потерянный per-interface witness остаётся
явной ошибкой с сохранением original. Смена inode моделируется в portable-тесте;
реальное принудительное переиспользование inode ядра не заявляется.

Контрольное отключение проверки поколения воспроизводит ошибку (exit 101). После
побайтового восстановления: 36 namespace + 11 target + 1 native PASS.
Первый локальный прогон выявил два устаревших ожидания fixture и Clippy needless_return;
они исправлены, ранние логи сохранены. Linux Rust 1.97, host Rust 1.98, прежнее разрешение
Clippy `chunks_exact_to_as_chunks`. 318 хешей исходников проверены до/после прогонов.
Worker SHA256: `96f96c31d42b501773bd0eeb223f923da966a3d5d6b5420862962c679d03183d`. Archive SHA256: `0908e9bc9fd9aa140470a6cf1e7dfb0b08b58cdf4b3a69750263dac8ee634de4`.
Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/namespace-cookie-phase/`,
`namespace-cookie-final.log`, `namespace-cookie-counterfactual/`, `sysctl-cookie-crash/`,
`lifecycle-namespace-cookie/`. Приватная лаба `.11`, рабочий `.10` не менялся.

## Границы закрытия

D02 закрыт: lock/I/O/context, trusted state directory, fd namespace pin, исходный
per-interface объект и durable global network generation проверены. Это не закрывает
D04: persistent exact firewall/DNS/routes recovery ещё требует работы. Автоматический
per-interface replay без живого witness намеренно отказывает; запись остаётся для
подтверждённого ручного восстановления. Cookie не идентифицирует интерфейс.
Внутренние непрерываемые I/O и общий срок других подсистем остаются D05.
Пользовательские конфиги только INI; `sysctls.state` — служебный журнал, не конфиг.

[Мануал](../../manuals/CONFIG.md) · [Диагностика](../../manuals/TROUBLESHOOTING.md)
