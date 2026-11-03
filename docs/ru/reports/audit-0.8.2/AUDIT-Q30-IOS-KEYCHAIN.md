# Q30: владение первой записью идентификатора и доверенного ключа в Keychain

<!-- normative-sync: q30-ios-keychain-v1 -->

6 октября 2026. Q30 IN_PROGRESS. Source fixes F292–F294 для хранения и TOFU;
проверка движка/lifecycle/roaming/платформы этим не завершается.

## F292: device ID и TOFU могли заменить первую конкурентную запись

`SecureIdentityStore` читал device ID или pin, затем выполнял update/add в Keychain.
Два читателя могли увидеть отсутствие записи, а поздняя запись — заменить первую.
Идентификатор, переданный одной native generation, расходился с сохранённым.
Принятие доверия могло одобрить ключ, пока другой writer сохранял иной pin.
Master key уже обрабатывал duplicate insertion; device ID и TOFU теперь используют
тот же контракт.

`KeychainStore.insertIfAbsent` добавляет запись без обновления. При duplicate
возвращает сохранённого победителя, ошибки чтения/доступа передаются вызывающему.
Создание device ID проверяет и возвращает победившее значение. Повреждённый,
нулевой или не 16-байтовый существующий ID вызывает явную ошибку вместо тихой
замены. Автоматический reset ключей/идентификатора не вводится.

TOFU insertion возвращает победивший pin. Движок сравнивает его с доказанным
ключом peer вне fallback для ошибок сохранения. Другой победивший ключ всегда
вызывает `serverKeyMismatch`, включая `allow_unpinned_tofu`. Эта опция сохраняет
прежнее поведение только для ошибок persistence. Services, account names, access
groups и AfterFirstUnlockThisDeviceOnly не меняются.

После переноса обоих runtime callers метод update/add `KeychainStore.write` остался
без рабочих вызовов и удалён. Fixtures используют уникальные test services и
прямое удаление только в тесте; заменяющий production update API не добавлен.

## F293: неправильная длина ключа попадала в allocation/crypto или decode архива

Создание master key допускает только AES-размеры 16/24/32 до allocation/RNG;
существующий или конкурентно созданный ключ должен соответствовать запрошенной
длине. Чтение архива требует 32-байтового master key, используемого записью,
до AES decrypt. Неверные существующие ключи вызывают понятную ошибку и не
перезаписываются/не регенерируются.

Добавлены семь XCTest с реальными Keychain API в уникальных удаляемых test
services: duplicate/первый победитель, стабильный device ID, повреждённый ID без
rotation, конфликт TOFU и разные endpoints, стабильный/повреждённый master key,
неверные размеры (zero/negative/Int.max), чтение архива с неверной длиной ключа.
Они сохранены, но NOT_RUN. Последовательные contract cases не заявляют наблюдение
межпроцессной гонки или engine handshake.

## F294: явный запрос профиля мог запустить другой профиль

Provider искал сначала requested UUID, затем persisted UUID и выбирал первый
найденный профиль. Неверный explicit option превращался в nil, а удалённый UUID
приводил к fallback на configured profile. Вместо отказа устаревший запрос мог
запустить другой профиль.
Общий Foundation selector выбирает requested значение при наличии, проверяет его
без fallback и использует persisted только при отсутствии запроса. Provider ищет
ровно один UUID; неверный/отсутствующий/удалённый профиль отвергается до создания
движка. Четыре новых selector XCTest: precedence, неверные типы, automatic launch
и удалённый профиль. NOT_RUN; реальные provider launch/managed delivery не заявлены.
Всего в этом пакете одиннадцать новых XCTest.

## Проверки и границы

Шесть Python IPA-verifier fixture-регрессий PASS. Десять текущих iOS XML
plist/mobileconfig/entitlement/privacy разбираются; типы шаблонов сохранены.
Документация (все девять проверок), generated config bindings и diff checks PASS.
Компиляция Swift, одиннадцать новых XCTest, simulator/signed IPA, реальные Keychain/shared
access groups и iOS VPN/TOFU races — NOT_RUN: на Windows нет Swift/Xcode,
Apple runtime исключён пользователем. Signed IPA qualification не заявляется.

Storage source ownership: только приложение публикует зашифрованный архив;
provider не создаёт отсутствующее хранилище; бюджеты archive/config/count/name,
read-only signing probes, duplicate master-key creation и shared settings сверены
с предыдущими Q25 fixes. Engine/provider stop/read/settings callback lifetime
ещё проверяется. Cancellation не объявляется joined native-runner/packet-flow
completion; новый shutdown PASS не заявляется.

Неизменные Git hashes Rust/native/Android/других клиентов сохраняют предыдущие
проверки с исходными артефактами, датами и ограничениями. Linux/Android matrix
не повторялась.
Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-keychain-20261006.
Evidence: release/certification/evidence/q30-ios-keychain-20261006.json.
Всего28/37 DONE/PASS(75.7%),осталось9; Q29 SIGKILL FAIL/auto-null ENONET открыты.
Q30 IN_PROGRESS; D06 и исключённые платформы не изменены.
