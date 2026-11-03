# Q15: сессии, IP-пулы и лимиты

<!-- normative-sync: audit-q15-sessions-v1 -->

**DONE/PASS. План: 15/37 (40,5%), осталось 22 раздела.** 4 октября 2026.
Core 86dbde48f5c2280f54ad59878f0987b90458b4f1, Linux-кандидат 5e3940eadec0981051006b0a605f7ad79e3b955a44a0cb56843095ebeafe5dcc.
Evidence: release/certification/evidence/q15-sessions-20261004.json.

## Q15-F003, P2: рост истории освобождённых адресов

Повторная выдача фиксированного IP не извлекала адрес из стека динамической выдачи.
Каждое освобождение добавляло копию адреса; то же происходило при DHCP-выдаче из диапазона.
После 100 000 циклов в каждом пуле оставалось по 100 000 записей при нуле выданных адресов.
Транзакционная выдача копирует весь пул: вместе с памятью росла стоимость выдачи адресов.

Множество адресов теперь ограничивает стек одной записью на адрес. При извлечении
маркер удаляется, доступность адреса проверяется заново. Резервные IP, недоступные
динамическому распределению, в стек не попадают. Порядок LIFO сохранён; откат двойной
выдачи восстанавливает стек и множество. Повтор 100 000 циклов оставляет по одной
записи. Два новых теста также проверяют DHCP-диапазон, резервации, исчерпание пула
и отсутствие повторной выдачи занятого IP. INI, API и ABI не менялись.

## Финальные проверки

- **2370 Linux unit PASS / 60 ignored**; full/minimal Clippy и fmt PASS.
  26 тестов пула входят в этот запуск; счётчики, связи адресов и сессий, очистка
  и сроки аутентификации также проверены текущим полным набором тестов.
- **11 runtime-сценариев / 148 проверок**, TCP/UDP/QUIC: устройства, reconnect,
  oldest eviction, шесть конкурентных AUTH, caps пользователя/профиля, exclusions,
  reservation, dual IPv6 exhaustion и освобождение обеих семей. Kick удаляет
  установленный client_subnet и kernel route. Quota/expiry/disable/enable,
  UDP reap при idle_timeout=0, нормализованная очистка сети и удаление TUN PASS.
- **54 проверки реального uplink через TUN**, TCP/UDP/QUIC: PQ/AEAD peers отправляют
  IPv4/UDP на серверный адрес. Quota, expiry и disable прекращают доставку;
  reset/enable восстанавливают её. В приватном sidecar задан 1 GB исторического
  download, лимит включается через production control API. Передача 1 GB и
  throughput benchmark не заявляются.
- Реальные fixed/adaptive bonded clients удерживают одну логическую сессию и
  один IPv4 lease при нескольких carriers и смене пути:
  **51 проверка PASS**.
- **18/18 матрицы / 327 проверок**, агрегат IPv4/IPv6 leak;
  **100 TCP + 100 QUIC / 33 soak-проверки**; **24 REALITY-TLS/H2 проверки**.
- Четыре независимые native A/B сборки, exports/copies/provenance PASS.
  Клиентские библиотеки побайтно равны Q14: pool — server-only модуль.

Review: sparse IPv6 и границы IPv4, fixed/exclude/reservation, atomic dual rollback,
TCP/UDP admission ownership, eviction/reconnect/caps, session/token/address aliases,
guarded reap/kick/quota cleanup, short-session/writer-tail/reset/usage persistence.
В проверенных модулях подтверждённого мёртвого API не найдено; методы DHCP используются.

## Повтор и границы

Точные проверенные fixtures: scripts/audit_session_lifecycle.py +
scripts/audit_session_peer.rs; scripts/audit_session_data_plane.py +
scripts/audit_session_data_peer.rs. Python принимает --qeli, --peer, --root;
нужны root и свежий Linux NET/mount/PID. Создаются отдельные state/control/INI
и shadow /run, /var/lib, /var/log, /etc/qeli. Peer компилируется против shipping rlib
и зависимостей той же сборки. Команды, исходники, SHA и логи сохранены в
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q15-sessions-20261004.

Ранние 142 + 54 проверки сохраняют Q14 binary hash; финальные 148 + 54 исполнены
на новом кандидате. Allocator probe — не 100 000 сетевых reconnect. Квоты и догоняющее
применение policy используют прежний периодический sweep: нет гарантии per-packet
учёта или мгновенного конкурентного обновления policy. Другие ignored-тесты не
объявляются исполненными. Новый installed-app E2E не заявляется; Mac/router/Windows VM
runtime исключены пользователем. Сервисы/ELF и пользовательский WIP сохранены.
Снимки обоих стендов после native-сборок совпали с исходными.
Push/deploy не выполнялись. Далее — Q16: ACL, push routes и site-to-site.
