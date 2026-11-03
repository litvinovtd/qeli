# Q25-F118: привязка NDP proxy вне async executor

Дата: 25 сентября 2026. Исходный коммит: `f52aa083`. D05/D09/D10: частичное закрытие.

## Подтверждённая проблема

`run_profile_generation` запускал NDP proxy синхронно. Проверка сетевого
интерфейса, `AF_PACKET` socket, bind и socket-local multicast membership
выполнялись на async executor. При задержке ядра это тормозило другие профили.
Просто перенести прежний `NdpProxy::bind` в worker нельзя: он создавал
`tokio::io::unix::AsyncFd`, который должен регистрироваться в исходном runtime.

## Исправление

`BoundNdpProxy` создаёт и привязывает обычный nonblocking `OwnedFd` в
присоединяемом worker исходного network namespace. После явного принятия
результата `NdpProxy::register` создаёт `AsyncFd` в Tokio runtime профиля.
При отмене ожидания непринятый fd закрывается в worker до освобождения
внешних ресурсов профиля. Семантика `off`/`auto`/`required`, интерфейс,
условия ошибки и INI-контракт сохранены; ошибка регистрации при `auto`
также остаётся необязательной, при `required` останавливает профиль.
Привилегированный namespace-тест теперь проходит через полный async start.

## Проверка и границы

Лаба `.11`: 5/5 NDP unit, 1/1 привилегированный namespace-тест,
8/8 TCP/UDP × IPv6 `off`/`manual`/`route`/`nat66` lifecycle и 22/22
recovery/ownership/SIGKILL checks PASS в частных NET/mount/PID spaces.
Оба `manual` worker log подтверждают активный responder на `wan0`.
Linux Clippy `--lib --bins -D warnings`, rustfmt и `git diff --check` PASS.
Полный `--all-targets` в частном снимке не применялся: интеграционные
`include_str!` требуют не загруженных туда `release/` fixtures; изменённые
library и binary проверены. Исходник сверялся до и после запуска (362 файла).
Бинарный SHA256:
`d2ddf836a01b4dd1b51df62a11559ad4d27b6f688651326f6899a4fc0706e039`.
Логи и manifest:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-ndp-bind-phase/`.

Остаются общий срок всех фаз установки, непредсказуемые kernel/fs I/O и
принудительный `Drop`, который ждёт завершения worker. D05 IN_PROGRESS.
