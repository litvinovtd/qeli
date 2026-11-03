# Q29 F281: доверенный Wi-Fi при включённом lockdown

<!-- normative-sync: q29-android-trusted-lockdown-v1 -->

Доверенный SSID должен подавлять смену carrier только при разрешённой паузе VPN.
`kill_switch` или системный Android lockdown запрещает паузу. F281 убирает безусловный
пропуск roaming из available/capabilities/lost/late-replacement callbacks: используется
конфигурация текущего подключения и фактическое системное состояние lockdown.
Обычная политика паузы на доверенном Wi-Fi сохраняется.

## Дефект и проверка

Старые callbacks считали сеть доверенной и пропускали roaming, тогда как контроллер
паузы отдельно отказывался выключать VPN. При возврате на доверенный Wi-Fi транспорт
мог оставаться на предыдущем carrier. Исправление применяет общий критерий разрешённой
паузы во всех четырёх callbacks. На старом production Release воспроизведён пропуск
активного reconnect при Cellular → доверенный Wi-Fi: уход проходит, возврат не вызывает
запрос переключения carrier, затем ошибка транспорта `rc=-10` приводит к пассивному
retry после отказа транспорта. Неизменённый handover gate падает на отсутствии маркера
активного reconnect; речь о задержке восстановления, а не вечной потере VPN. Три
предварительных запуска упали в harness до этой проверки (external-storage import,
выбор SSID editor, разбор foreground type), они не считаются продуктовым воспроизведением.

Три новых JVM-теста покрывают оба вида lockdown,
решения для доступной сети и замены потерянной, неизвестные и не-Wi-Fi сети.

Результаты runtime и их область закреплены в парном evidence-пакете:
`release/certification/evidence/q29-android-trusted-lockdown-20261006.json`.
Runner импортирует INI через настоящий file picker production Release, включает
Always-on и lockdown через Android Settings, вводит наблюдаемый SSID в редакторе
настроек Qeli, сохраняет и считывает обратно. Permissions выдаются извне;
системный permission-диалог не автоматизируется. Наблюдается location foreground type
активной службы. Нет инъекции preferences или искусственного carrier callback.

`audit_android_data_plane_lab.py --suite handover --variant release --apps-mode all
--trusted-lockdown-handover --leak-bursts --transport tcp` требует закреплённых
APK/manifest и проверенного сервера в private NET/MNT/PID namespaces с временным
readonly AVD. Для UDP/QUIC используется тот же opt-in. Несовместимые варианты/suites
и per-app режимы отвергаются до изменения файлов или стенда. Независимый probe работает
от отдельного UID; matching Release instrumentation NOT RUN. Production R8 rules сохранены.

Свежие JVM, lint, default-R8 build, разбор пакетов и runtime имеют явные исходники/APK
хеши; ошибка тестового сценария не считается воспроизведением продуктового дефекта.
Предварительные fixture failures и подтверждение их очистки сохранены в пакете.

## Подтверждённые результаты 6 октября

| Свежая проверка | Результат |
|---|---|
| JVM / lint / default production R8 | 182 PASS (3 новых); 0 lint errors, 55 warnings; Release/debug build PASS |
| Release TCP / UDP / QUIC masking | 3 полных запуска PASS; 6 настоящих переходов Wi-Fi ↔ Cellular |
| Полный payload независимого UID | 36 PASS: IPv4/IPv6 TCP16KiB и UDP257 после переходов и ручного восстановления; reply bytes/SHA, sink receipts и собранный TUN pcap совпадают |
| Release burst-пробы переходов/остановки | 864 пробы; 144 после остановки заблокированы; физических запросов в защищённом окне 0, capture drops 0 |
| Обычная доверенная пауза на новом debug APK | 3 instrumented теста PASS; 16 полных payload с явным VPN Network и независимыми sink SHA/TUN-source receipts |
| Helpers / CLI / документация / bindings | 15 helper tests, 4 CLI отказа до изменений, docs и bindings PASS |

TCP выполняет новый Auth/NetworkPlan при обоих переходах, сохраняя PID/TUN/адреса.
UDP/QUIC подтверждают новый реальный carrier, сохраняя authentication/session/TUN;
все commits каждого перехода относятся к этому carrier. SHA запросов/ответов всех
36 Release payload независимо восстановлены из tagged payload. Четыре вида физических
сокетов положительно калиброваны capture/receipts до lockdown. Короткие таймауты baseline
и переходов сохранены: на уходе burst replies TCP36/48, UDP36/48, QUIC40/48;
на возврате48/48 каждый. Нулевая потеря при переходах и универсальная готовность первого
пакета не заявляются.

Debug regression повторяет холодное доверенное ожидание, реальный Wi-Fi/Cellular
pause/resume, паузу живого TUN, отмену pending resume, explicit restart и отказ kill-switch
без OS lockdown. Граница adapter прежняя: SSID preferences записаны локально тестом,
permissions выданы извне, сокеты явно используют VPN Network.

Все восемь runtime attempts (три предварительных harness failures, старый продукт,
три исправленных Release и debug regression) прошли проверку host/service/firewall/routes,
persistent userdata hash/mtime/size и server/address cleanup. Отдельно сохранён обрыв
SFTP до dispatch QUIC: runtime в каталоге неполной загрузки не запускался. SSH восстановился
без перезагрузки; host state совпал, QUIC выполнен в новом каталоге. .10 не изменён.
Matching Release instrumentation и новая сборка native/server/managed отсутствуют.
Закреплены 303 source inputs (4 изменены), 23 auxiliary inputs (1 изменён, 1 добавлен),
5 regression inputs, 14 native rows, 7 managed artifacts и все 6 APK файлов.
Повторно используемые standalone Release probe и debug test APK отмечены отдельно
от свежих product APK.

## Границы результата

Ограниченная матрица API34 x86_64 AVD не подтверждает physical/OEM/другие API/arm64
или длительную сессию. Adapter обычной паузы использует явный VPN Network и локальную
инъекцию настроек; он не заменяет Release проверки отдельного UID.
[Прежний SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md),
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md), оставшиеся
lifecycle/protect races и покрытие других Android платформ открыты.
Q29 остаётся IN_PROGRESS; общий план 28/37 (75,7%), осталось девять разделов.

Raw-пакет: `audit-debt-20260924/q29-android-trusted-lockdown-20261006`.
