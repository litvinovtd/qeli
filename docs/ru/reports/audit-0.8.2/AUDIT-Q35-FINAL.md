# Q35 — итог fuzz, отказов, конкуренции, DoS и soak

<!-- normative-sync: audit-q35-final-v1 -->

13 октября 2026 года. **Q35 DONE в проверенном конечном объёме.**
План: **33/37 (89,2%)**, остаются Q29/Q31/Q34/Q36.
[Машинная матрица критериев](../../../../release/certification/evidence/q35-final-20261013.json).
Это сопоставление накопленных результатов, а не новый запуск прежних тестов.

| Критерий | Основание завершения |
|---|---|
| Review и мёртвый код | Инвентаризация всех 15 Cargo fuzz bins, общий CI inventory, исправленные пропуски четырёх target; review stability/admission/isolation/SUN_LEN/phase markers и Q37 dead-code dispositions |
| Штатные, граничные и негативные сценарии | 15 реальных ASan-target, затем усиленные fragment/INI oracles; сохранены исходные corpus, sanitizer binaries и даты |
| Отказы и конкуренция | 14 реальных TCP/UDP cases, 320 assertions, семь concurrent pairs; дополняются завершёнными аудитами транзакций Q05, pre-auth Q09, lifecycle Q14, leases/caps Q15 и network rollback Q25 |
| Интеграция и целевая платформа | Одновременные TCP/QUIC 900 cycles за 30 минут; текущий полный восьмиэтапный endurance за 13 ч 4 мин, фиксированные ресурсные и performance бюджеты |
| Исправления, повторная проверка и evidence | Исходные FAIL сохранены; archives/input SHA, фактическая очистка и состояние хоста проверены; исправления runner приняты и проверены |

## Fuzz и применимость исходников

Исходный закреплённый ASan-прогон всех 15 target выполнил **85 930 590**
итераций. Последующие проверки двух fragment target выполнили 246 813
итераций, client_config — 18 494. Эти числа принадлежат исходным исполнениям;
нового ASan-прогона 13 октября нет.

Сверены все 902 входа исходного архива и фактические финальные файлы fragment
и client_config из отдельных архивов. Начальный fragment archive содержит
раннюю версию: для применимости использована исправленная версия, реально
прошедшая финальный прогон. Закреплённый Rustfmt 1.97 воспроизводит текущие
байты всех 15 target из этих проверенных файлов. Изменения четырёх target,
ранее выглядевшие как новый непроверенный код, оказались форматированием.

Fuzz lock изменён: удалены зависимости qeli→mio и mio→log. Все 146 версий,
источников и checksum прежние. Это отдельно сохранено в proof; новый lock
не объявляется побайтно прежним. Parser entrypoints не используют mio/poll/log.
В обфускации изменены gates клиентских batch helpers, а в REALITY client —
server/test fingerprint metadata, owned helper и тестовый HMAC. Общая проверка
ServerHello и record crypto сохранена. Изменения buffer pool, платформенных
потоков и counters относятся к завершённым владельцам; ни один из 15 target
не вызывает transport_core. Fuzz не объявляется покрытием этих новых путей.
Текущий hosted nightly/CI остаётся отдельным пунктом Q34.

Fragment oracles проверяют точные собранные байты, MAC/conflict/replay/recovery,
32 неполные записи и 512 КиБ, до 24 UDP-частей, исторические 1200-байтные части.
Client INI/qeli:// проверяет структурированные допустимые входы и канонический
повторный разбор. Длинные/повреждённые config/archive и admission пределы также
покрыты завершёнными аудитами своих модулей.

## Ресурсы и отказы

DoS-разбор относится к объявленным пределам: framing/partial entries,
TCP/UDP/Argon2 admission, bounded queues, deadlines, quotas, leases, fragment
budgets и освобождению ресурсов при отказе/отмене. Использованы реальные
AUTH/proof/capability и caps/pool проверки Q09/Q15, control/reload/hook pressure
Q14, acquire/apply/save/rollback/cleanup границы Q05/Q25, а также Q35 race matrix.
Это не требование инъекции ошибки в каждый произвольный await и не гарантия
от неограниченного flood или отказа внешней сети.

Дополнительные 24 текущих persistent AUTH-прогона по 60 секунд дали 34 644
admissions при concurrency 4; peak RSS 336 320 КиБ при лимите 512 МиБ.
Это closed-loop ресурсная проверка, не измерение saturation capacity. Её старые
host FAIL и partial-run/refusal сохраняют исходные статусы; общий host PASS
принадлежит отдельному актуальному endurance-пакету.

[Полный endurance](AUDIT-Q35-LONG-SOAK.md) измерил 10k TCP/10k QUIC и по 1k
трёх других UDP adapters, performance и 28 cross-node checks. Сохранены 9 403
снимка и 18 786 наблюдений процессов. Cross-node здесь — два процесса на одной
VM, а не физическая смена сервера. Предельные RSS/fd/socket/thread значения
заданы заранее; cgroup peak/OOM/throttling counters сохранены отдельно.
Старый upload FAIL 6,8627% при пороге 5% остаётся FAIL; его причина относится
к Q36 и не выводится из более позднего PASS.

Открытые владельцы сохранены: Q29 platform-scope решение, Q31 source bootstrap,
Q34 public source cut/hosted CI, Q36 причины асимметрии/потерь и capacity.
Недоступные физические платформы не получили PASS. Закрытие Q35 не означает
завершения всего аудита или квалификации публичного релиза.
`NO_PUSH_DEPLOY_RELEASE`.
