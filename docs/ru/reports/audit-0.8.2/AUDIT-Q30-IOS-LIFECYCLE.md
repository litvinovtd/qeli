# Q30: владение провайдером, stop/start и поздние ответы ОС

<!-- normative-sync: q30-ios-lifecycle-v1 -->

6 октября 2026. Source fixes F295–F297. Q30 IN_PROGRESS; iOS runtime qualification,
join native workers и завершение всего раздела не заявляются.

## F295: отложенный Start мог вернуть path monitor после Stop

Движок ожидал physical DNS, затем запускал lazy roaming controller. Stop мог
пройти во время DNS, отменить controller и отметить движок stopped. Продолжившийся
Start снова запускал monitor до отказа в network settings. Повторный Stop уже
возвращался сразу. Конкурентный доступ к lazy controller также не гарантировал
единственный экземпляр.

Теперь один controller создаётся сразу без self-reference; weak engine привязывается
при Start. Single-use lifecycle делает Stop окончательным, включая stop-before-start.
Поздние path callbacks/arm после Stop отвергаются. Start проверяет cancellation/
stopped ownership до и после suspended этапов. Provider catch всегда останавливает
свой частично запущенный движок, включая старую generation, не очищая чужой.
Завершившийся start task не удерживается после очистки владельца completion.

## F296: локальные проверки не ограждали эффекты всего provider

Network settings проверяли generation, но позже публиковали факты без повторной
проверки в той же транзакции. Constructor и старые stop/stats/terminal callbacks
напрямую писали shared snapshot. Старый движок мог также изменить reasserting,
отменить provider или записать пакеты прежнего подключения после замены.

Provider допускает snapshots, reasserting/cancel, запросы настроек и чтение/запись
пакетов только от текущего движка под lifecycle lock. Recursive lock допускает
синхронный API reentry. Installation читает snapshot до provider lock, избегая
инверсии блокировок. Handoff packet callback выполняется в уже необходимом release
task до освобождения lease: callback ОС не берёт engine lock под provider lock.
Обе ветки network facts проверяют stopped/request generation внутри изменения
фактов; установка activePlan также проверяет native identity. Поздние stats,
Connected publication, установка pumps и downlink writes проверяют текущий native
handle и plan generation внутри engine transaction, включая reconnect одного движка. Start failure/final
stop publication ограждены generation. Constructor до installation не публикует.

Движок удерживает provider до завершения Swift workers; Stop/замена очищают ссылку
provider→engine и разрывают цикл установленного владельца. Старый worker не читает
уничтоженный unowned provider. Cancellation всё ещё отличается от join всех
workers и ответа неотменяемой OS operation.

## F297: gates на экземпляр и освобождение по timeout допускали overlap

Раньше read/settings gates принадлежали отдельному движку. Замена могла запустить
второе чтение до ответа старого. Settings timeout освобождал gate, хотя старый OS
apply мог завершиться позднее и заменить новые routes. Cached successful fingerprint
после позднего apply мог не соответствовать фактическим настройкам.

Два provider-wide operation gates сериализуют настройки и чтение между движками.
Ожидающие задачи отменяемы; settings queue и OS wait делят прежний бюджет 15 секунд.
Lease identity отвергает повторный/старый release. После выдачи OS request отмена/
timeout возобновляют Swift, но gate освобождает только реальный callback. До выдачи
apply fingerprint очищается; только актуальный успешный ответ восстанавливает его.
Старый cache больше не считается доказательством текущих settings после timeout.

Общий AsyncResultCompletion заменяет дублированные settings/DNS completion classes.
При finish-before-park сохраняет исходные success/error: cancellation нового handler
не переименовывается в timeout. Exactly-once completion и отказ от late results явны.

## Проверки и ограничения

Тринадцать новых XCTest: шесть operation-gate cases (FIFO, waiter timeout/cancel,
stale release, zero budget, precancelled admission), три single-use lifecycle и
четыре порядка completion. Проверяют production helpers; NOT_RUN.
Компиляция Swift, реальный PacketTunnel replacement/stop, gates с реальными
readPackets/setTunnelNetworkSettings, synchronous reentry, memory/lifetime,
leak behavior, simulator и signed IPA — NOT_RUN. На Windows нет Swift/Xcode;
read-only probe также не нашёл Swift на Linux-лабе .11. Toolchain не устанавливался,
сервисы/сеть лабы не менялись. Apple runtime исключён пользователем.

Шесть Python IPA-verifier fixture-регрессий, десять XML structural reads,
документация (все девять проверок), generated config bindings и diff checks PASS.
Это не подтверждает Swift syntax или Apple API runtime. Git inputs Rust/native/
Android/других клиентов не изменены; runtime matrices не повторялись.

Если ОС никогда не вернёт callback, gate остаётся занятым: settings waiters получают
timeout, packet-read waiters отменяемы. Drain таких callbacks при реальном iOS
stop/start — OPEN platform qualification, а не принятый успех/автоматический unlock
или скрытое новое ограничение. Stop completion не объявляется join всех runners
или удалением всех pending OS actions. Остаётся source review app/UI/settings/
provider-message ownership и итоговая memory/dead-code сверка всего раздела.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-lifecycle-20261006.
Evidence: release/certification/evidence/q30-ios-lifecycle-20261006.json.
Всего28/37 DONE/PASS(75.7%),осталось9. Q29 SIGKILL FAIL/auto-null ENONET, D06 и
пропуски не изменены. Q30 IN_PROGRESS.
