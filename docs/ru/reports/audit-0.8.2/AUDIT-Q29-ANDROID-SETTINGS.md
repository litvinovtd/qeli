# Q29 F289: применение LAN-настроек к активному соединению

<!-- normative-sync: q29-android-settings-v1 -->

6 октября 2026. FIXED, границы проверки ниже. Предыдущий source-review пакет обнаружил
ошибку отдельно от F286–F288; его первоначальные результаты и raw seal сохранены.
Q29 остаётся IN_PROGRESS.

Save настроек сохранял глобальный `allow_lan`, показывал reconnect toast, но вызывал
обычный `connect()`. Guard connected/connecting немедленно возвращал управление;
текущий TUN сохранял старую routing policy до независимого переподключения.

Save теперь запрашивает явную reconfiguration. Обычный Connect сохраняет прежний state
guard; reconfiguration может заменить connected/connecting attempt. Оба пути сохраняют
строгий parser сохранённого INI, notification/VPN consent и владение `VpnConnectRequest`.
Disconnecting и ожидающий permission result не допускают нового запроса; `begin` по-прежнему
отклоняет уже принадлежащий запросу config. Первоначальный pending request использует новое
значение prefs при установке TUN после permission completion. Activity сохраняет явную reconfiguration в retained permission request.
Service валидирует обе команды, сохраняет заменяющий config, завершает прежний
native runner/TUN через существующий teardown и запускает замену в том же foreground
controller. Disconnect/revoke/destroy очищают очередь; обычный Connect сохраняет guard
активной генерации. Queued settings intent остаётся redelivery-eligible; это не SIGKILL
recovery PASS. Fingerprint уже включает effective global LAN policy, поэтому изменённая
политика после Auth не переиспользует старый TUN. Конфиги остаются INI.

## Проверки и границы

Один итоговый test APK с тремя cases: старый продукт3/1 ожидаемый restart FAIL и2
контрольных PASS; исправленный3 PASS. Начальные old2/1FAIL и UI-only fix2/1FAIL сохранены
отдельно; итоговые тесты добавляют отмену через Disconnect. Первоначальная ошибка
обнаружила guard службы.

Свежий обычный production R8 Release TCP PASS: настоящий UI INI import/OS lockdown,
два перехода Wi-Fi→Cellular→Wi-Fi,12 ordinary-UID IPv4/IPv6 TCP/UDP полных payloads с
независимыми size/SHA/TUN-source checks,288 sampled sockets с временными потерями при
handover/force-stop,48 блокированных post-stop. Protected physical request leaks0,
capture drop0. Все пять attempts сохраняют host service/routes/firewall/resolver и
исходные AVD userdata SHA/size/mtime; namespace/server cleanup PASS. Успешные итоговые
прогоны не оставляют Qeli service/TUN. Начальные провалы сохраняют abort diagnostics;
их пропущенные final Android cleanup guards не объявлены PASS. .10 не затронута.

Свежие201 JVM PASS (два новых request-mode lifecycle cases), lint0 errors/54 warnings и debug/test/default R8/resource-shrunk
Release builds PASS. JVM test, зеркально повторяющий private UI dispatcher, не
добавлялся. Три новых настоящих Activity/settings/Keystore/service/native pre-auth tests
используют локальный stall peer:

- Save LAN checkbox при настоящем активном native Auth attempt и введённом connected
  Activity state: peer должен получить второй native hello. Проверяется реальный
  posted AlertDialog Save listener и сохранённый LAN flag.
- После Save выполняется Disconnect: service должна завершиться и не восстановить отменённый запрос.
- Вводится pending notification request; Save того же параметра не запускает service,
  сохраняет ownership ожидаемого callback и возвращает исходный config.

Dialog roots/delegate reflection — только тестовые. Connected UI и pending permission
phase введены тестом; это не настоящий опубликованный CONNECTED и не OS permission-dialog
test. Stall peer не публикует Auth/TUN; здесь нет LAN route reachability/physical-network
матрицы. Из-за изменения command/teardown dispatch выполнен один свежий default Release
TCP handover/stop check, результат ниже; UDP/QUIC matrices не повторялись.
Matching Release instrumentation NOT_RUN. Первоначальный UI-only fix тоже провалил
native-restart test: service отклоняла Connect при активной старой генерации. Diagnostic
сохранён и привёл к исправлению очереди/teardown.
Сохранена одна
compile diagnostic нового теста (неверные имена Kotlin constructor fields), исправленная
использованием общего строгого INI parser. Native/server/managed inputs совпадают по SHA.
Проверены15 helper tests,8 CLI invalid-mode guards для settings-ui fixture, RU/EN docs и
генерируемые bindings.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-settings-20261006.
Evidence: release/certification/evidence/q29-android-settings-20261006.json.

[Source review](AUDIT-Q29-ANDROID-SOURCE.md) завершён; подтверждённых продуктовых исправлений
из этого source-review пакета больше не осталось. [SIGKILL automatic recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md)
и [auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) остаются открыты;
причинный JNI defect не доказан. Other API/OEM/arm64 limits, user skips и D06 неизменны.
Q29 IN_PROGRESS; итог28/37(75,7%),9 осталось.
