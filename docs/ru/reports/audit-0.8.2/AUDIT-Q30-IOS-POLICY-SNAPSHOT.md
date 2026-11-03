# Q30: числовые MDM-политики и асинхронные ответы расширения

<!-- normative-sync: q30-ios-policy-snapshot-v1 -->

6 октября 2026. Q30 IN_PROGRESS. Проверены преобразование MDM-политик и ответы
provider-message в приложении. Это не завершение проверки PacketTunnel, Keychain,
roaming, памяти или всего раздела iOS.

## F290: усечение и неявное преобразование MDM-значений

`ManagedConfigurationReader` использовал `NSNumber.intValue` для логических политик
и версии схемы. Дроби могли усекаться до 0/1, а Boolean — превращаться в целую
версию. Некорректное значение становилось действующей политикой.
Теперь парсер различает CFBoolean, проверяет границы Int до преобразования и
требует точного десятичного round trip. Boolean и совместимые старые числовые
0/1 сохранены; дробные/nonfinite/неверно типизированные логические значения и
Boolean/nonfinite/дробные/overflow версии возвращают nil. Целое значение в
представлении 1.0 допустимо. Новая проверка поддерживаемой версии схемы или
изменение default/fail-closed поведения не вводятся: существующий fallback
необязательных политик остаётся. Неверный activeProfileID по-прежнему fail closed.

Добавлены три XCTest: оба логических поля, точные числовые 0/1, границы Int,
Boolean вместо версии, дроби, NaN/infinity и overflow.

## F291: поздний ответ мог вернуть устаревшее состояние UI

`requestProviderSnapshot` публиковал каждый декодированный ответ. Ответ, отправленный
до Disconnect или смены системного статуса, мог вернуть Connected/privateUpdatePath
после отключения. Перестановка ответов могла перезаписать новые счётчики и факты
соединения старыми. Приложение теперь инвалидирует ответы при Connect, managed
fail-closed, Disconnect и смене системного статуса. Запросы/ответы допускаются для
работающего/reasserting сеанса вне Disconnecting. Epoch/sequence gate отвергает
устаревшие и уже принятые ответы. Старый допустимый ответ принимается, пока новый
запрос ещё ожидает ответа: задержка больше интервала polling не вызывает starvation.
Декодирование до MainActor-проверки владельца; статус и публикация проверяются вместе на MainActor.

Добавлены три XCTest для перестановки/дубликатов, медленного нового запроса и
stop/restart epochs. Проверяется production gate, а не эмуляция VPN.

## Проверки и оставшаяся работа

- Шесть Python-регрессий IPA-verifier PASS на сгенерированных архивах. Это проверка
  структуры verifier, а не подписи или реального candidate IPA.
- Документация, generated config bindings и diff checks PASS.
- Шесть новых Swift XCTest, компиляция Swift, simulator build, signed IPA,
  реальные гонки provider callback и iOS/MDM runtime — NOT_RUN. На Windows нет
  Xcode/Apple runtime; Mac/iOS runtime исключён пользователем. Source fixes
  не объявляются runtime-qualified.
- Rust/native/Android/другие клиенты не изменены относительно предыдущего коммита.
  Старые результаты сохраняют исходные артефакты, даты, отказы и ограничения.
  Android/Linux-матрица для изменений только Swift не повторялась.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-policy-snapshot-20261006.
Evidence: release/certification/evidence/q30-ios-policy-snapshot-20261006.json.
Q29 SIGKILL FAIL/auto-null DnsResolver ENONET открыты; D06 и пропуски не изменены.
Всего 28/37 DONE/PASS (75.7%), осталось 9. Далее Q30 engine/lifecycle/storage review.
