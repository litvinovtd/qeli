# Q29: работа сервиса на доверенном Wi-Fi

<!-- normative-sync: q29-android-trusted-wifi-v1 -->

Три новых instrumented-сценария прошли в изолированном readonly AVD API34 x86_64
лабы .11. Подтверждена ограниченная работа контроллера доверенной сети. Код клиента
не менялся; Q29 остаётся IN_PROGRESS, общий план 28/37 разделов (75,7%).

## Что проверено

Тест читает настоящий SSID Wi-Fi эмулятора после открытия MainActivity. Разрешения
location/nearby Wi-Fi выданы извне до instrumentation; SSID записан в те же локальные
настройки устройства, которые использует UI. Команды запускают настоящий сервис
через framework; reflection сервиса, fake Network callbacks или транспорта нет.
Это проверка адаптеров, а не автоматизация редактора настроек/диалогов разрешений.

- Холодный запуск на доверенном SSID: foreground WAITING без TUN, намерение подключения
  сохранено. Activity переведена в CREATED; ожидание сохраняется через 1,2 секунды.
  Настоящий `svc wifi disable` переключает эмулятор на доступный Cellular; завершаются
  native Auth и установка dual-stack TUN. Возврат Wi-Fi снова включает паузу с join
  очистки. Отключение политики доверенной сети восстанавливает туннель.
- Включение доверенной сети у работающего туннеля: пауза закрывает TUN и очищает live IP;
  отключение политики запускает настоящий отложенный resume250ms. Команда Disconnect
  через framework оставляет сервис/TUN отсутствующими и connection_desired=false
  после дополнительных1,2s. Новое явное подключение работает.
- Доверенный SSID с `kill_switch=true` без OS lockdown: отказ ERROR без TUN,
  вместо перехода в доверенное ожидание.

Четыре активных/восстановленных состояния проверяют полные IPv4/IPv6 TCP16KiB и UDP257
ответы: 16 payload-проб, побайтные утверждения и 16 независимых server receipts
с совпадающими SHA и назначенными TUN-источниками. Тестовые сокеты явно используют
активный VPN Network; это не новая default-socket/ordinary-UID матрица утечек.

## Квалификация и ошибки обвязки

Итоговый runner завершил все три теста и cleanup. Предыдущий запуск тоже прошёл
эти три теста, но runner ошибочно требовал UDP-transport receipts от TCP-only suite;
он сохраняет общий FAIL. Ранний запуск фикстуры остановился до Android: адреса
ответчиков не были установлены. Обе попытки сохранены. Повторное создание уже
существующего каталога отклонено до другого runtime.

Обвязка принимает `--suite trusted-wifi --variant debug --transport tcp`, требует
закреплённые fixed APK/manifest и private NET/MNT/PID namespaces, устанавливает
off-pool ответчики и проверяет правильную TCP-only матрицу. Четыре теста обвязки
и четыре negative CLI-проверки PASS. Все три runtime-попытки сохранили
host/service/firewall/routes и постоянный userdata по SHA/mtime/size; server exit
и восстановление адресов namespace PASS. В конце итогового прогона service/TUN
отсутствуют, AndroidRuntime без FATAL EXCEPTION. Глобальный заголовок dumpsys
сохраняет Last ANR SystemUI Keyguard; список работающих сервисов Qeli пуст. .10 не затронут.

Пересобран только тестовый APK. Product debug APK и оба JNI ABI побайтно совпадают
с F280; native/server/managed inputs не менялись. Прежние179JVM/lint/defaultR8
сохраняют свои области, это не свежий JVM/Release runtime-прогон.
303 source inputs (README изменён, один тест добавлен), 22 auxiliary (одна обвязка
изменена), 14 native и семь managed artifacts закреплены.

Raw: `audit-debt-20260924/q29-android-trusted-wifi-20261006`.
Evidence: `release/certification/evidence/q29-android-trusted-wifi-20261006.json`.

## Оставшиеся границы

Фоновое ожидание здесь1,2s, а не physical suspend или длительная OEM-сессия.
Разрешения выданы до instrumentation; их настоящий отзыв, скрытый SSID,
ошибка регистрации observer, Disconnect во время незавершённой native-паузы
и handover на доверенный SSID с действующим OS lockdown этим набором не подтверждены.
Доступность SSID зависит от разрешений: [контракт Android WifiInfo](https://developer.android.com/reference/android/net/wifi/WifiInfo).
Название SSID само по себе не аутентифицирует точку доступа; доверенная пауза остаётся
явной настройкой пользователя без обоих видов lockdown.

[Прежний SIGKILL FAIL](AUDIT-Q29-ANDROID-SYSTEM.md),
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), оставшиеся
lifecycle/protect гонки и другие API/OEM/arm64 runtime остаются открытыми.
