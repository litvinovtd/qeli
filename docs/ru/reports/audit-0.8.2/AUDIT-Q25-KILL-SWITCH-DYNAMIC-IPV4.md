# Q25-F122: поздний IPv4-маршрут не обходит kill-switch

Дата: 25 сентября 2026. Исходный коммит: `b1cf0ece`. D06: частичное закрытие.

## Проблема и изменение

Когда `iptables` отсутствовал или IPv4-правила не устанавливались, один успешный пустой вывод `ip -4 route show default` разрешал запуск без IPv4-защиты. DHCP, администратор или смена сети могли добавить default route позже; refresh не вооружал ранее незащищённое семейство. IPv4-трафик мог выйти мимо VPN.

Теперь без работающего IPv4 firewall запуск kill-switch отклоняется независимо от текущего маршрута. Пропуск IPv4-защиты возможен только при явном `allow_ipv4_leak = true`. Старый адресный probe и тесты его одноразового снимка удалены. Конфигурационные ключи, API и ABI не менялись; на IPv6-only хосте без `iptables` потребуется явное разрешение IPv4-утечки.

## Проверки и границы

Модель проверяет отказ до появления default route, отсутствие адресного probe, явный override и очистку IPv6-only профиля. Локально: 106 gateway и 17 portable kill-switch тестов PASS. Linux `.11`: 1/1 адресная регрессия, 107/107 gateway и 45/45 kill-switch тестов, Clippy `--lib --bins -D warnings`, 2/2 привилегированных packet-теста PASS. Новый native-тест в приватном network namespace добавляет IPv4-адрес и default route уже после установки dual-family kill-switch и подтверждает рост счётчика IPv4 DROP; соседний тест повторно проверяет поздний IPv6. Сверены 362 исходных файла; SHA256 архива `2f24a3459c70e7715b4dead97c8210f5a308dcd013a2a0d7b08bc86a7029e9dc`. Другие route/WAN-гонки и сетевые backend остаются D06/D10. Исходники и логи: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/kill-switch-dynamic-ipv4-phase/`.
