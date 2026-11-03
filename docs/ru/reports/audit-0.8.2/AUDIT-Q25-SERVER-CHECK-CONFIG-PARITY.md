# Q25-F141: одинаковый допуск серверного INI в CLI, панели и runtime

26 сентября 2026. База: `b3ce4196`. D07 остаётся **IN_PROGRESS**.

Проверка выявила два расхождения. `check-config` загружал внешний `users.conf` строгим helper и отклонял его отсутствие без inline-записей, хотя worker и supervisor считают это допустимым первым запуском с пустой базой. Общая `validate_profiles` пропускала выключенные профили и принимала INI, где выключены все профили; worker затем отказывался стартовать. Supervisor сам эту проверку до запуска панели не вызывал. В baseline на изолированной лабе `.11` первый случай завершился ошибкой «No such file», а all-disabled с существующим пустым `users.conf` получил `OK`.

`check-config` теперь вызывает тот же `load_users_db_for_runtime`, что runtime. Отсутствующий внешний файл разрешён, в том числе при наличии inline-записей; повреждённый или недоступный файл остаётся ошибкой. Общее правило профилей запрещает all-disabled. Его используют `check-config`, панельные сохранения, worker и supervisor; supervisor применяет его до запуска панели. Отдельный повторный check из worker удалён.

Проверка: адресный unit-тест общей валидации, `cargo fmt --check`, строгий Clippy и CLI-матрица в изолированной Linux-лабе `.11`: отсутствующий users-файл при включённом профиле, all-disabled, повреждённый users-файл; отдельно startup-отказ supervisor и worker на all-disabled. Логи: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/disabledfixed.log` и `disabledstartup.log` в той же папке. Рабочие сервисы и сервер `.10` не изменялись.

D07 не закрыт: остаются полная матрица field → parse/validate/runtime/serialize, сочетания save/reload/import и гонка внешней записи между последней проверкой и публикацией.
