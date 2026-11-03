# Q25-F128: собственный exit-TUN не может быть WAN

Дата: 25 сентября 2026. База: `a05b6885`. D06 остаётся **IN_PROGRESS**.

`detect_wan` выбирает интерфейс default route. Если администратор направил default route в тот же TUN, на котором работает exit-node, прежняя проверка принимала корректное имя и начинала устанавливать `-i <tun> -o <tun>` MARK/FORWARD и MASQUERADE. Такой путь не является внешним WAN и не может обеспечить выход клиентского трафика.

`engage_exit_on` и `engage_exit_ipv6_on` теперь отклоняют совпадение с exit-TUN до записи ownership и любых firewall/sysctl изменений. Проверка действует как при начальном setup, так и при roaming/фоновом WAN refresh. После изменения IPv6 forwarding повторная проверка WAN тоже отказывает, если default переключился на TUN. При ошибке старый guard сохраняется, монитор продолжает попытки; оператору нужен отдельный внешний WAN.

Регрессия `exit_rejects_its_own_tun_as_wan_before_mutating` проверяет обе семьи, отсутствие новых мутаций и ownership при setup и при refresh уже активного exit-node. На изолированной Linux-лабе `.11` адресный тест прошёл **1/1**, весь модуль gateway rollback — **102/102**, `cargo fmt --check` и `cargo clippy --lib -- -D warnings` прошли. Лог: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/tun-attach-context-phase/selfwanexact.log`; сервер `.10` и установленные сервисы не затрагивались.

Граница: защита отвергает точное совпадение имени с собственным TUN; она не доказывает физическую независимость другого интерфейса и не решает reuse имени WAN [Q25-A125](AUDIT-Q25-WAN-NAME-REUSE.md). D06/D10 остаются открытыми.
