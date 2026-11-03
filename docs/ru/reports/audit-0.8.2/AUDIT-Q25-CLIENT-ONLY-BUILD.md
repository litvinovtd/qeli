# Q25-F133: Linux client-only сборка и exit WAN monitor

25 сентября 2026. База: `25488dbd`. D11 остаётся **IN_PROGRESS**.

`cargo check --offline --lib --no-default-features --features client`
на Linux завершался с двумя E0425: `tun_name` не найден в TCP- и UDP-путях
`spawn_exit_wan_monitor`. Монитор включается при `target_os = linux`
независимо от `experimental-roaming`, а оба объявления имени TUN были
ограничены этим feature. Обычная сборка и `client-bin` включают roaming,
поэтому дефект оставался незамеченным.

В обоих местах область объявления `tun_name` теперь совпадает с Linux
монитором. Для обычного бинарника алгоритм и runtime-поведение не менялись;
INI/API/ABI не менялись.

На изолированной `.11` исходный client-only check дал exit **101** и два
E0425. Исправленный check client-only, отдельный server-only check,
`cargo build --offline --bin qeli-client --no-default-features --features client-bin`
и запуск нового бинарника с `--help` дали exit **0**. Rustfmt PASS.
Фактическое VPN-подключение router client в этой проверке не запускалось.
Предупреждение о неиспользуемом поле `terminal_sender` в client-only check
остаётся отдельным кандидатом на чистку dead code, не является ошибкой сборки.

SHA256 клиентского бинарника:
`ca6f5d7b5e940a814c9a43737b053ab4835b48bcd70ff26c73f8e7bfb83b54d2`.
SHA256 проверенного `client/mod.rs`:
`9bbf372803ea3cb20c9737b0f0786316fd70c8f559985f88677a94ce7c6eddb2`.
Baseline и исправленные логи/exit codes:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/client-feature-phase/`.
Установленные службы лабы не менялись. D11 provenance/package и D12
платформенный runtime остаются открытыми.
