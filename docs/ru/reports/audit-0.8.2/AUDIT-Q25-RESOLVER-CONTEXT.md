# Q25 — контекст службы DNS и прямые D-Bus-вызовы

<!-- normative-sync: audit-q25-resolver-context-v1 -->

24 сентября 2026. База `76ff2df3`. Частичное закрытие D06/D09/D10.

## Q25-F094, P1 — numeric ifindex мог попасть в другую сеть

Изолированный `resolver-context-probe-v2` воспроизвёл дефект: `resolvectl dns 2`
из дочернего network namespace через общую шину изменил DNS интерфейса `foreign0`
родительской службы, где тоже существовал ifindex 2. Изменение отменено в той же
приватной лабе. Проверка TUN и `/etc/resolv.conf` не доказывала контекст получателя.
Кроме того, `resolvectl` может перенаправить DNS/domain/revert в networkd при
`LinkBusy`; обычная проверка resolved до/после не фиксирует адресата.
Источник поведения CLI: [systemd v257 resolvectl](https://github.com/systemd/systemd/blob/v257/src/resolve/resolvectl.c).

Клиент теперь удерживает namespace fd и контекст resolver вместе с DNS lease:

- локальная Unix-шина (`path` или `abstract`, один адрес), PID namespace брокера
  совпадает с вызывающим процессом; номера PID из чужого PID namespace не принимаются;
- AUTH EXTERNAL проверяет endpoint и сохраняет его GUID; каждый `busctl` получает
  этот GUID в адресе, `--auto-start=no` и конкретное unique name службы;
- отдельно проверяются `GetId`, unique owner, PID и network namespace resolved,
  повторные чтения владельца и контекст вызывающего потока;
- перед/после DNS, domain и revert проверяется тот же контекст. Смена экземпляра
  службы или шины даёт ошибку с сохранением lease; автоматического принятия нового
  владельца и скрытого перехода к networkd нет;
- аутентификация ограничена 128 байтами и оставшимся общим сроком, identity replies —
  1024 байтами после ограниченного command runner. Setup делит прежние 15 секунд,
  cleanup получает отдельные 15 секунд. Внутренний файловый I/O не становится прерываемым.

AUTH GUID и message-bus `GetId` — разные идентификаторы. Проверка GUID при соединении
закрывает повторное использование unique name после перезапуска шины между проверкой
и вызовом. [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html),
[проверка GUID в sd-bus v257](https://github.com/systemd/systemd/blob/v257/src/libsystemd/sd-bus/bus-socket.c).

## Q25-F095, P2 — нестандартный DNS-порт передавался как имя сервера

Для порта из NetworkPlan, отличного от 53, адаптер передавал `address#port` в
`resolvectl`: часть после `#` означает имя DNS/TLS-сервера, а не порт. Теперь адрес
передаётся байтами, порт — отдельным `uint16` через `SetLinkDNSEx`, server name пустой.
Для списка только с портом 53 используется `SetLinkDNS`. Нет отката к API, которое
молча потеряет нестандартный порт. Формат INI и общий NetworkPlan не изменены.
[Контракт CLI](https://github.com/systemd/systemd/blob/v257/man/resolvectl.xml).
В отдельном реальном стенде прежний вызов вернул `DNSEx` с портом 0 и server name `5353`; исправленный адаптер подтверждён чтением `192.0.2.53:5353`. Сервер по-прежнему объявляет клиентам порт 53 и перенаправляет его на свой listener; исправление относится к произвольному допустимому порту NetworkPlan.

## Поддерживаемая конфигурация

Linux `dns = tunnel` требует `busctl`, уже работающий systemd-resolved, его stub в
`/etc/resolv.conf`, доступный procfs, общую сеть клиента/службы и общий PID namespace
клиента/брокера. Шина может находиться по нестандартному локальному
`DBUS_SYSTEM_BUS_ADDRESS`; адрес фиксируется при setup. TCP-шины, списки fallback
адресов и чужой PID namespace отвергаются. Non-53 порт требует `SetLinkDNSEx`.
При `LinkBusy` настройте владение TUN у внешнего менеджера либо поручите DNS платформе
через `dns = off`/`system`. Автоактивация сервисов и изменение постоянного resolver-файла
не выполняются. `resolvectl` остаётся полезен для ручной диагностики.

## Проверки и границы

Добавлены 11 обычных Linux-регрессий, одна privileged проверка чужой сети и
отдельный child-fixture с реальными dbus-daemon/resolved. **1491 host + 71 config,
9 feature/cross/lint checks PASS; 2023 Linux + 33 privileged + 8 worker E2E PASS**.
Реальная служба подтвердила default/custom port, domain/revert и отказ при чужой сети
или неверном AUTH GUID. Дополнительный вложенный PID namespace получил ожидаемый
отказ до DNS-мутации; состояние родительской службы осталось пустым.

Отключение context guards воспроизвело 3 FAIL (замена владельца, новая шина, чужая
сеть), отдельный возврат well-known адресата — ещё 1 FAIL. Исходники восстановлены:
**29 DNS + 1 privileged PASS**. Полная сетевая матрица: **17/17, 301 assertion PASS**,
Bash syntax и 8 Python проверок harness PASS. Все 325 файлов источника проверены
до/после прогонов. После тестов обновлены только комментарии в трёх Rust-файлах и
INI-примере: равенство всех остальных строк проверено отдельно; повторный runtime
прогон этих комментариев не заявляется.

Source archive: `93bec3ea6a769da24ae5156cec57e40e68f7cfd0e76d31f23d2d1f76b8b20912`.
Debug worker: `6b6f6eda9975cffe5dc52f451ee5b791e6a62a360999be02a0f10b3e2cfda018`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/resolver-direct-phase/`,
`resolver-direct-final.log`, `resolver-direct-native/`, `resolver-direct-counterfactual/`,
`resolver-pidns-native/`, `resolver-port-baseline/`, `lifecycle-resolver-direct/`,
`packet-matrix-resolver-direct/`. Изменения комментариев — `post-test-comment-changes.json`.
Rust Linux 1.97 / host 1.98, прежнее Clippy-исключение `chunks_exact_to_as_chunks`.
Промежуточный `resolver-service` снимок и его 17/17 матрица сохранены отдельно;
результаты выше относятся к последующему `resolver-direct` снимку.

Лаба `.11`, приватные network/mount/PID namespaces; рабочий сервер `.10` не менялся.
Матрица больше не считает лог успешной заглушки доказательством применения DNS:
запускает настоящий dbus-daemon/resolved, читает per-link состояние, посылает A/AAAA
через 127.0.0.53 и проверяет исчезновение DNS после stop при живой службе.

Наблюдения не являются атомарной блокировкой против внешнего root, который переносит
живой сервис или заменяет интерфейс после проверки. Per-link состояние внешнего
менеджера не сохраняется для автоматического восстановления. Persistent recovery
остаётся D04; общий NetworkPlan deadline — D05. D06 целиком не закрыт: остаются
process-global DNS/carrier и другие критерии реестра. Прогон не является финальным
release benchmark или платформенной сертификацией. Windows VM/Mac/iOS/router runtime
пропущен по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/CONFIG.md)

Продолжение: [Q25-F096/F097](AUDIT-Q25-DNS-MARKER-STORAGE.md) переводит DNS-маркеры на v2 с SO_NETNS_COOKIE и доверенным открытым каталогом, проверяет SIGKILL/restart с реальным resolved. Исторические цифры и v1-контракт выше описывают прежний снимок; актуальная эксплуатация — в §6.50 TROUBLESHOOTING.
