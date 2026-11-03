# Q14 — владение worker в network namespace

<!-- normative-sync: audit-q14-worker-network-lease-v1 -->

24 сентября 2026. База `1bbd596c`. Частичное закрытие D04/D06/D09.

## Q14-F037, P1 — другой control socket обходил запрет второго worker

Control lease защищал только конкретный filesystem path. Два worker с разными
`QELI_CONTROL_SOCKET` и `STATE_DIRECTORY`, даже в разных mount/PID namespaces,
могли разделять одну сеть. Второй проходил admission, загружал учёт и выполнял
`nat::cleanup_all`: startup sweep удалял `qeli-nat:*` первого, ещё работающего worker.
Различные имена профилей, TUN и порты не устраняли эту проблему.

В изолированном стенде baseline запустил второй профиль; число IPv4-правил первого
уменьшилось с **9 до 0**, включая NAT, DNS INPUT и REDIRECT. Первый процесс оставался
живым. Это потеря действующего firewall из-за штатного запуска другого экземпляра.

Теперь после валидации конфига, до preflight, users/accounting, control listener,
hooks и сетевых изменений worker занимает abstract AF_UNIX datagram имя
`qeli.server.worker`. Ядро ограничивает его network namespace. Descriptor остаётся
до конца worker, включая завершение profiles/post_down и освобождение учёта.
При штатном выходе, ошибке запуска и SIGKILL закрытие fd освобождает имя. CLOEXEC
не даёт передать lease запускаемым командам и hooks. Файла этого lease нет: удаление
control lock или смена каталога не помогает второму процессу обойти admission.

Один namespace допускает **один server worker со всеми его профилями**. Для нескольких
worker нужны разные network namespaces и отдельные config/state/control пути.
Обычная схема supervisor + worker сохраняется; supervisor сам не занимает это имя.
Клиентские lifetime reservations используют другие имена.

## Проверки

- **1491 host + 71 config, 9 feature/cross/lint checks PASS**.
- **2027 Linux + 34 privileged + 8 worker lifecycle PASS**.
- 4 новые обычные Linux-регрессии: повторный bind/drop, независимые имена,
  CLOEXEC и освобождение после SIGKILL отдельного процесса. Один новый privileged
  тест проверяет независимость одинаковых имён в разных network namespaces.
- Новый `scripts/audit_worker_recovery.py`: **22 проверки PASS**. Второй worker с
  другими control/state путями и отдельными mount/PID namespaces отклонён до hook,
  control bind и учёта; первый отвечает, firewall остаётся неизменным.
- SIGKILL оставляет NAT/DNS и sysctl journal, но удаляет непостоянный TUN и освобождает
  admission. После удаления исходного профиля из конфига новый worker убирает его
  доступные tagged rules; чужие IPv4/IPv6 правила сохраняются. Stop восстанавливает
  forwarding и удаляет освобождённый sysctl journal.
- Во время задержанного `post_down` ещё один worker отклонён. Ошибка users-файла
  после admission освобождает lease; следующий корректный запуск и stop проходят.
- Тот же окончательный runner на baseline даёт **ожидаемый FAIL** на втором worker
  и сохраняет before/after с удалёнными девятью правилами. Первоначальная ошибка
  fixture (`dns.listen` не совпадал с TUN) сохранена отдельно, успехом не считается.

327 source files проверены до/после. Source archive:
`68528120cd890e9723eec8d2bd79b7259e9bd60ca2191048a8facbb103294453`.
Worker SHA256: `dfcbd8c654a57dd805aa15c3a7fc0feed1b372e66093a5cc251a7f91f9b5a72a`.
Baseline SHA256: `6b6f6eda9975cffe5dc52f451ee5b791e6a62a360999be02a0f10b3e2cfda018`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/worker-lease-phase/`,
`worker-lease-final.log`, `worker-admission-baseline-v4/`, `worker-admission-fixed-v2/`,
`lifecycle-worker-lease/`. Предыдущие прогоны сохранены по собственным именам.
Linux Rust 1.97, host 1.98; прежнее исключение Clippy `chunks_exact_to_as_chunks`.
Работающий сервер `.10` не изменялся, `.11` использовался с приватными namespaces.

## Границы D04

Это кооперативная блокировка запуска, **не persistent exact-rule journal**. Старые
бинарники не участвуют: перед обновлением остановите прежний worker. Произвольный
локальный процесс способен первым занять abstract-имя и вызвать отказ запуска;
защита доступности от такого процесса этим механизмом не обеспечивается. Обходить
неизвестного владельца или автоматически завершать его Qeli не пытается.

Crash E2E проверяет существующий tagged sweep на доступных iptables-nft цепочках.
Mixed nft, где listing недоступен, durable спецификации firewall/routes, crash DNS
и произвольные внешние изменения не объявляются закрытыми. D04 переводится в
IN_PROGRESS, остальные долги остаются в реестре. Нового INI-ключа, ABI/wire изменений,
release benchmark или native certification нет. Windows VM/Mac/iOS/router runtime
пропущен по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md)

Позднейшее продолжение: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) добавляет persistent exact server firewall journal и проверяет восстановление при отказе listing. Ограничения клиентского crash recovery и общей mixed nft/firewalld матрицы сохраняются.
