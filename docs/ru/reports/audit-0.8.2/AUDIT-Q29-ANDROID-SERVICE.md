# Q29: команды и жизненный цикл Android foreground-сервиса

<!-- normative-sync: q29-android-service-v1 -->

**5 октября 2026. Этап PASS; Q29 IN_PROGRESS. План: 28/37 (75,7%), осталось 9 разделов.**

## F278: отклонённая команда заменяла статус текущего подключения

При ACTION_CONNECT без конфигурации или с неверными параметрами rejectForegroundConnect публиковал ERROR до проверки существующего контроллера. Транспорт продолжал работу, но UI получал ошибку, а live connection properties сбрасывались. Это противоречило обещанию сохранить работающий или ожидающий сервис при отклонении новой команды.

Проверка владельца теперь выполняется под общим монитором сервиса до публикации статуса. Активный транспорт/TUN, trusted-WiFi pause и незавершённая остановка сохраняют своё состояние; отказ записывается в журнал. Для первого неверного запуска сохранены foreground promotion, ERROR и остановка сервиса. Новых параметров INI или изменений Rust/JNI нет.

## Проверки

Пять новых тестов запускают **настоящий сервис через Android framework**, без reflection и подмены transport core. Локальный TCP-ответчик принимает ClientHello из JNI и удерживает handshake без ответа. Проверяются:

- сохранение CONNECTING, foreground и connection_desired после отсутствующего/невалидного конфига;
- три цикла start → ручная отмена handshake → завершение сервиса и native socket;
- stopService → настоящий onDestroy, завершение native socket и сохранение намерения подключения; затем новый запуск;
- EOF сервера при выключенном reconnect → завершение сервиса, ERROR и запись причины;
- первый неверный foreground-запуск → ERROR, завершение сервиса, отсутствие желания подключения.

Старый APK с неизменённым product code: **5 тестов, 1 воспроизводимый FAIL** (CONNECTING заменён ERROR), остальные четыре PASS. Исправленный APK: **28/28 instrumented PASS**, включая эти пять и прежние 23. Android14/API34 x86_64, отдельный readonly AVD. 167 JVM PASS; Release/R8/resource shrink собирается; lint: 0 ошибок, 55 прежних предупреждений. Debug runtime не подтверждает Release runtime.

После force-stop нет TUN и активного сервиса приложения; AndroidRuntime не содержит FATAL EXCEPTION. Постоянный userdata AVD сохранён по SHA256/mtime/size, сеть и работающий qeli.service хоста .11 совпадают до/после; .10 не затронут. Библиотеки обоих ABI в APK совпадают с qualified JNI; arm64 не исполнялся. Прежние 1248 .NET результатов используются только для 183 неизменённых managed/Swift входов и 7 DLL, это не новый прогон.

## Границы

Новые тесты подтверждают framework lifecycle **до аутентификации**, без VPN-полезного трафика. stopService не равен убийству процесса, системному revoke или автоматической redelivery. Три перезапуска выполняются после завершения предыдущей остановки и не доказывают обработку конкурирующего start во время teardown. Trusted-WiFi/CONNECTED ветки отказа reviewed, но свежий runtime проверяет CONNECTING. Не закрыты TCP/UDP traffic, roam/protect, always-on, process death/revoke/Doze, Release runtime, старые API и физический LTE/OEM backup. Предыдущий [этап TUN/JNI](AUDIT-Q29-ANDROID-LIFECYCLE.md) сохраняет собственные результаты и ограничения.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-service-20261005.
Evidence: release/certification/evidence/q29-android-service-20261005.json.
