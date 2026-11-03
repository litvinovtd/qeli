# Q25 — проверка системного resolver-конфига

<!-- normative-sync: audit-q25-resolver-config-v1 -->

24 сентября 2026. База `6fd3ef6d`. Частичное закрытие D06/D09.

## Q25-F093, P2 — ложный успех по имени симлинка или подстроке

Проверка `resolved_is_active` принимала ссылку с `systemd/resolve` или
`stub-resolv.conf` в имени, даже если файл отсутствовал или содержал внешние DNS.
Поиск `127.0.0.53` во всём тексте принимал комментарии и смешанный список resolvers.
Клиент мог успешно настроить per-link DNS и сообщить успех при обходе этого пути
приложениями, читающими `resolv.conf`.

Теперь читается содержимое одного открытого regular file: максимум 64 KiB, проверка
metadata до/после, nonblocking open для отказа FIFO. Обычный symlink поддержан,
но его имя не является доказательством. Нужна хотя бы одна фактическая строка
`nameserver`; все такие строки должны указывать только `127.0.0.53` или
`127.0.0.54`. Комментарии игнорируются, неизвестные/fallback адреса, malformed,
NUL, oversized, невалидный UTF-8 и недоступный файл отвергаются.

Файл `/run/systemd/resolve/resolv.conf` содержит реальные upstream DNS и позволяет
клиентам обойти per-link routing resolved; стандартный stub-файл использует
`127.0.0.53`, `127.0.0.54` — proxy listener. Источник: [systemd v257 manual](https://github.com/systemd/systemd/blob/v257/man/systemd-resolved.service.xml).

Для `dns = tunnel` используйте действующий stub resolver либо явно поручите DNS
платформе через `dns = off`/`system`. Qeli по-прежнему не перезаписывает
`/etc/resolv.conf`; новых INI-параметров нет. Отказ происходит до получения DNS lease.

## Проверки и границы

3 новые Linux-регрессии: набор корректных/ложных nameserver строк; dangling и
обманчивый symlink, oversized/UTF-8; настоящий FIFO без writer.
**1491 host + 71 config, 9 feature/cross/lint checks PASS**.
**2012 Linux + 32 privileged + 8 worker E2E PASS**.
Возврат прежних predicates воспроизводит **2 FAIL**; восстановление — **18 DNS PASS**.
Все 323 файла источника проверены до/после прогонов.

Source archive: `08df0d8f509bced3731b180f5913cb8132c00b922d6cb9230894f329e56f42ce`.
Debug worker: `b4e3cf4075f942cd647223bee9218d69139ceaf6d08704e167703fefb6413542`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-context-phase/`,
`dns-context-final.log`, `dns-config-counterfactual/`, `lifecycle-dns-context/`.
Лаба `.11`, приватные namespaces; работающий сервер `.10` не изменялся.
Rust Linux 1.97 / host 1.98, прежнее Clippy-исключение `chunks_exact_to_as_chunks`.

Это проверка файла, а не доказательство identity/liveness DNS-службы. Отдельный
изолированный `resolver-context-probe-v2` подтвердил: команда `resolvectl dns 2`
из другого netns меняет `foreign0` исходной службы с тем же ifindex через общую
шину. После наблюдения изменение отменено в том же приватном стенде.
D06 bus/service context остаётся открытым и требует отдельного исправления;
фиксация этого файла его не закрывает. D04/D05/D09/D10/D13 также целиком не закрыты.
Windows VM/Mac/iOS/router runtime пропущен по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/CONFIG.md)

Продолжение: [Q25-F094/F095](AUDIT-Q25-RESOLVER-CONTEXT.md) фиксирует контекст шины/службы и адресата команд, проверяет реальный resolved и исправляет нестандартный DNS-порт. Исторические результаты выше не пересчитывались.

Продолжение: [Q25-F104](AUDIT-Q25-RESOLVER-FILES.md) переносит чтение DNS-файлов до firewall, делит ограниченную очередь с NSS и объединяет reader/parser с проверкой stub. Исторические результаты выше не изменены.
