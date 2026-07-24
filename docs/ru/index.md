# Документация qeli — карта

Единая точка навигации. Документы сгруппированы **по аудитории**: сначала то, что нужно
пользователю и администратору, затем внутреннее и историческое.

> Новичку: начните с **[Установки с нуля](GETTING-STARTED.md)**, затем
> **[Конфигурация](CONFIG.md)**. Если что-то не работает — **[Диагностика](TROUBLESHOOTING.md)**.

**English version → [../eng/index.md](../eng/index.md)**

---

## 👤 Пользователю

| Документ | О чём |
|---|---|
| [GETTING-STARTED.md](GETTING-STARTED.md) | Установка и начало работы, пошагово с нуля |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Диагностика подключения и справочник ошибок |

## 🛠 Администратору сервера

| Документ | О чём |
|---|---|
| [CONFIG.md](CONFIG.md) | Конфигурация (flat-INI): все параметры сервера и клиента |
| [PANEL.md](PANEL.md) | Веб-панель: установка и использование |
| [OPERATIONS.md](OPERATIONS.md) | Эксплуатация: совместимость, обновления и откат, бэкап, firewall |

## 📡 Роутеры (Keenetic / OpenWrt)

| Документ | О чём |
|---|---|
| [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md) | Пошаговый деплой клиента на Keenetic |
| [KEENETIC-PORT.md](KEENETIC-PORT.md) | Порт клиента на Keenetic (dual-arch: mipsel + aarch64) |

## 🔐 Безопасность

| Документ | О чём |
|---|---|
| [AUDIT.md](AUDIT.md) | Модель безопасности и текущее состояние |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Модель угроз |
| [DPI-AUDIT.md](DPI-AUDIT.md) | Аудит обнаружимости DPI: теллы и их устранение |

## 📖 Устройство, сравнение, замеры

| Документ | О чём |
|---|---|
| [README.md](README.md) | Обзор проекта: что это, зачем, режимы обфускации, крипто-стек |
| [COMPARISON.md](COMPARISON.md) | Сравнение с WireGuard / OpenVPN / V2Ray |
| [BENCHMARK.md](BENCHMARK.md) | Нагрузочное тестирование, замеры по режимам |
| [ROAMING.md](ROAMING.md) | Роуминг клиента (бесшовная смена сети) |

## 🧭 Разработка и процесс

> Внутренние документы: планы и статусы, а не руководства для пользователя.

| Документ | О чём |
|---|---|
| [ROADMAP.md](ROADMAP.md) | План развития |
| [REFACTOR-PLAN.md](REFACTOR-PLAN.md) | План рефакторинга: устранение дублей кода |
| [DESIGN-remaining.md](DESIGN-remaining.md) | Стадии разработки REALITY: статус и остаток |
| [RELEASE-FIXES.md](RELEASE-FIXES.md) | План доводки до стабильного релиза |

## 🗄 Архив: исторические аудиты

> Зафиксированные отчёты прошлых проверок. Хранятся для истории — **актуальное состояние
> безопасности смотрите в [AUDIT.md](AUDIT.md)**, а не здесь.

| Документ | Дата |
|---|---|
| [AUDIT-2026-06-10.md](archive/AUDIT-2026-06-10.md) | 2026-06-10 — аудит безопасности и надёжности |
| [AUDIT-2026-06-11.md](archive/AUDIT-2026-06-11.md) | 2026-06-11 — разбор внешнего аудита и фиксы |
| [AUDIT-2026-06-11-external2.md](archive/AUDIT-2026-06-11-external2.md) | 2026-06-11 — разбор второго внешнего аудита |
| [AUDIT-2026-06-12.md](archive/AUDIT-2026-06-12.md) | 2026-06-12 — аудит и фиксы (релиз 0.7.1) |

---

## Документация клиентов (лежит рядом с их кодом)

| Клиент | Документ |
|---|---|
| Windows | [qeli-win/README.md](../../qeli-win/README.md) |
| macOS | [qeli-mac/README.md](../../qeli-mac/README.md) |
| iOS | [qeli-ios/README.md](../../qeli-ios/README.md) · MDM: [qeli-ios/MDM/README.md](../../qeli-ios/MDM/README.md) |
| Роутеры (OpenWrt) | [qeli-openwrt/README.md](../../qeli-openwrt/README.md) · Keenetic: [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md) |
| Android | [qeli-android/README.md](../../qeli-android/README.md) |
| Linux CLI | [GETTING-STARTED §8.2](GETTING-STARTED.md) |

## Вне этого каталога

- **[../../CHANGELOG.md](../../CHANGELOG.md)** — все изменения по версиям.
- **[../../SECURITY.md](../../SECURITY.md)** — политика безопасности и приём отчётов.
- **[../../CONTRIBUTING.md](../../CONTRIBUTING.md)** — как участвовать в разработке.
- **[../../release/docker/README.md](../../release/docker/README.md)** — запуск сервера в Docker.

