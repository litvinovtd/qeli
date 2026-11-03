# Q14 — срок установки NAT, forwarding и DNS REDIRECT

<!-- normative-sync: audit-q14-nat-setup-budget-v1 -->

24 сентября 2026. База: `c2f97aeb469c3ff48e4295c4ea5f0fc5cf17d22c`.
Продолжение D05/D09; [реестр техдолга](../../plans/AUDIT-DEBT.md).

## Q14-F036, P2 — независимые сроки команд и неограниченная очередь setup

NAT44, IPv4 forwarding, управляемая IPv6-маршрутизация и DNS REDIRECT ожидали firewall
mutex без срока, а каждая вставка, проверка и удаление получали новые 15 секунд.
Ошибка установки запускала tag sweep с отдельными командными сроками; точные записи
сохранялись, но неполный немедленный rollback не включался в возвращаемую ошибку.

Теперь каждая граница установки делит 15 секунд между очередью, discovery, чтением WAN,
очисткой старых тегов, реестрами, вставкой и проверкой правил. Проверки срока до/после
sysctl не прерывают его внутреннее I/O. Просроченная проверка не разрешает fallback
FORWARD/ACCEPT или успешное завершение. Точная спецификация сохраняется до мутации.

Общий wrapper обрабатывает любую ошибку после admission и выполняет проверяемый откат
всех сохранённых NAT-правил профиля и его IPv6 sysctl с отдельным общим сроком 15 секунд.
Это границы запуска профиля: после ошибки он продолжать работу не может. Откат сохраняет
firewall mutex до завершения; ошибка admission не запускает очистку чужой операции.
Неполный откат добавляет `NAT rollback incomplete` и оставляет записи для lifecycle retry.
Глобальный IPv4 forwarding по-прежнему принадлежит worker и освобождается в final cleanup.

DNS INPUT и REDIRECT UDP/TCP теперь делят один срок `DNS firewall setup`. При ошибке
REDIRECT выполняется NAT rollback, после него Drop INPUT lease получает свой срок очистки.
Это не обещание 30 секунд на весь DNS teardown: последовательные разные cleanup имеют
разные бюджеты. Manual IPv6 сохраняет управление firewall/forwarding у администратора.
Удалены неиспользуемые bool REDIRECT, IPv4 WAN и cleanup helpers с отдельными сроками.
INI, public C ABI и wire-формат не менялись.

## Проверки

10 новых Linux-регрессий: expired/busy admission, занятый registry до мутации,
общий срок вставок и свежий rollback, очередь, rollback двух семейств, сохранение
неудалённого правила, просроченное чтение FORWARD, поздний успех, REDIRECT IPv4/IPv6
и расход INPUT-временем общего срока DNS. Fixture запускает реальные процессы,
хранит правила в приватных файлах и не меняет firewall хоста.

1475 host unit + 71 config, все 9 команд feature/cross/lint PASS.
**1991 обычный Linux + 31 privileged + 8 worker E2E PASS**.
Семь отключений общего deadline ожидаемо дают exit 101 на целевых assertions;
после побайтового восстановления **10 setup + 7 DNS + 8 cleanup + 2 native PASS**.
Первый контрольный runner остановился до изменения кода из-за CRLF в шаблоне;
В v2 оставшаяся защита registry admission сохранила отказ после очереди; v3 отключает
также общий срок lock, воспроизводя обе прежние границы. Ранние результаты сохранены.

Linux Rust 1.97, host Rust 1.98; прежнее исключение Clippy `chunks_exact_to_as_chunks`.
318 исходных файлов проверены по SHA до/после полного и контрольного прогонов.
Worker SHA256: `c7acda0f71a49029475c4b371b23a56a83256a320009938dc494742f5348c9c9`.
Source archive SHA256: `f81268c81ec758e62365159522f3b39797dd5d68f357e3105212900e20668150`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/nat-setup-phase/`,
`nat-setup-final.log`, `lifecycle-nat-setup/`, `nat-setup-counterfactual-v3/`.
Приватные namespaces на `.11`; рабочий `.10` не менялся.

## Открытые обязательства

D05 не закрыт целиком: client routes/gateway, scheduler isolation и внутренние sysctl/I/O
ещё требуют работы. Срок не прерывает синхронные metadata/spawn/kill/reap и не является
пределом всей последовательности запуска нескольких семейств/профилей. Crash journal,
backend identity и внешние изменения сохраняют ограничения D02/D04/D06. Новый benchmark
и release provenance этим прогоном не получены.

[Мануал](../../manuals/CONFIG.md) · [Диагностика](../../manuals/TROUBLESHOOTING.md)
