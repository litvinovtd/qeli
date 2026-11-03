# Q18: IPv6 off/manual/route/nat66 и NDP

<!-- normative-sync: audit-q18-ipv6-v1 -->

**DONE/PASS. План: 18/37 (48,6%), осталось 19.** 4 октября 2026.
Код ядра: `5556a6b921bec30185f4ab8d760afc46f613e81b`.
Linux SHA256: `4c70a6595b6f5a9a9b2809c7975f12212895347fdabc9e05d4135f5a69a8a2f3`.
[Evidence](../../../../release/certification/evidence/q18-ipv6-20261004.json).

## Исправленные дефекты

**Q18-F001, P2 — ответ на недопустимый unicast DAD.** Проверка NS допускала source
`::` с unicast destination. На исходном кандидате три таких запроса получили три NA.
Теперь DAD принимается только для solicited-node multicast целевого адреса, как
требует [RFC 4861 §7.1.1](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1).
На исправленном кандидате во всех четырёх новых пакетных сценариях ответов нет;
корректный DAD по-прежнему получает all-nodes NA с правильными флагами и checksum.

**Q18-F002, P2 — поток предупреждений при ограничении NDP.** Burst из 513 запросов
на исходном кандидате дал 256 ответов и 257 предупреждений. Флаг pending сбрасывался
после каждой записи и сразу выставлялся следующим denied packet. Добавлен флаг
reported на окно; новый burst в каждом из четырёх сценариев даёт 256 ответов и одно
предупреждение. Следующее окно снова допускает ответы. Лимиты 256/MAC, 4096 глобально
за секунду и максимум 4096 отслеживаемых MAC сохранены. Две новые unit-регрессии PASS.

## Разбор слоёв

| Слой | Проверенный контракт |
|---|---|
| INI/валидация | Все 36 family × mode × NDP сочетаний. IPv4-only допускает только off/off; NDP off допускается с четырьмя IPv6-режимами, auto/required только с manual/route. NAT44 отключён в IPv6-only fixture. |
| off/manual | off устанавливает профильные DROP для IPv6-транзита. manual не изменяет IPv6 firewall, forwarding, RA и DNS-правила; настройка администратора сохраняется. |
| route/nat66 | route сохраняет source; nat66 ограничивает MASQUERADE пулом и WAN, использует точные сохранённые selectors для cleanup. IPv4 работает независимо. |
| sysctl/cleanup | Original сохраняется до записи; accept_ra=2 устанавливается до forwarding. Проверяются namespace/generation witnesses и readback; foreign state сохраняется, ошибки оставляют retry ownership. Общие бюджеты setup/cleanup по 15 секунд сохранены. |
| NDP socket/task | AF_PACKET nonblocking/CLOEXEC, проверка Ethernet ifindex/MAC, socket-local ALLMULTI; supervision и закрытие fd при отмене/выходе. |
| NS/NA | Bounded Ethernet/VLAN разбор, IPv6 next-header, hop 255, checksum/code, ненулевые options, ограничения target и DAD. NA без Override, корректные solicited/DAD флаги. |
| Владение адресом | Активная exact lease имеет приоритет; delegated prefix проверяется по session registry, `/0` не становится NDP-владением. Revoked/closing session не разрешает новый ответ. |

Мёртвый production helper не подтверждён; compatibility и recovery ветви сохранены.
Мануалы RU/EN теперь описывают DAD, лимиты и границу in-flight NA при отзыве.

## Проверки и воспроизведение

- 2376 Linux unit PASS, 60 ignored; строгий all-target Clippy и release build PASS.
- 4 свежих NS/NA-сценария: nft/route/TCP, nft/manual/UDP, legacy/route/UDP,
  legacy/manual/TCP — 184 checks PASS. Настоящая аутентификация, exact/delegated
  адреса, default `/0`, upstream достижимость, некорректные NS, disconnect/reconnect,
  control kick, штатная остановка и отдельный SIGKILL responder.
- nft и legacy: 446 checks PASS — четыре одновременных профиля, DNS UDP/TCP
  A/AAAA на обеих семьях, reload/refusal, 36 конфигураций и все 16 ordered mode pairs
  через stop/restart, включая четыре повторных запуска того же режима. Идентичные
  profile/TUN/listener/pool сохраняются между шагами; после каждого проверяется cleanup.
- Итого 630 новых runtime checks на исправленном SHA. Исходный baseline —
  отдельные 35 checks, его ответы на invalid DAD и log flood не считаются исправленным PASS.
- Четыре native target прошли независимые A/B-сборки. Копии/manifest/provenance
  сверены. Это сборки Windows/macOS и Android arm64/x86_64, не installed-app E2E.

Используются scripts/audit_ndp_session_packet.py (--extended; --baseline для исходного
дефекта) и scripts/audit_worker_ipv6_multiprofile.py (--transitions), обязательные
binary SHA и свежие NET/mount/PID. Raw:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q18-ipv6-20261004.

Сохранены предыдущие 248 NDP и 118 multiprofile checks с исходными SHA/датами;
513 raw-файлов сверены, по 32 релевантных неизменённых исходника в каждой записи.
Изменённый NDP получает свежую квалификацию, старое исполнение не переименовано
в запуск нового SHA. Q16 transport/leak/soak evidence сохраняет область применения:
изменения касаются только server NDP; нового бенчмарка нет.

Ошибки подготовки сохранены: slash в имени baseline packet-файла; NAT44 в IPv6-only
fixture; недостаточное свободное место на диске для Android. Исправленные прогоны PASS.
Для сборки удалены только завершённые private unit/Clippy cache. Рабочие службы,
их executables и пользовательский WIP сохранены; допустимый прежними прогонами
ambient legacy firewall delta на desktop-лабе записан отдельно без причинной атрибуции.

## Границы результата

Матрица конфигураций исчерпывающая для трёх семей; переходы runtime проверены на
dual через restart, без обещания live SIGHUP routing mutation или полного произведения
семья × carrier. Прежние IPv6-only проверки сохраняют свой scope. Новый NDP runtime
pairwise, не восемь свежих сочетаний. Physical provider/SG и VLAN trunk не сертифицированы.

Штатная остановка подтверждает restore rules/routes/sysctls. SIGKILL подтверждает
прекращение ответов и release socket-local ALLMULTI; полный firewall/sysctl restore
после SIGKILL этим тестом не заявляется. Потеря interface witness требует подтверждённого
ручного восстановления. После registry removal новые ответы не разрешаются, но
ранее сформированный/очередной NA может выйти позже; UDP process death может сначала
потребовать liveness timeout. Это уточнение контракта, не обещание мгновенного purge.

Q25-A125 — замена WAN с тем же именем — остаётся принятой пользователем границей:
stop/verify cleanup до замены, затем reconfigure/restart; BPF не внедряется. Mac,
роутер и Windows VM runtime исключены пользователем. Все 60 ignored tests не выдаются
за запущенные. Далее Q19 DNS.
