namespace Qeli.Shared;

/// <summary>
/// Tiny runtime localization shared by the qeli C# clients (qeli-win, qeli-mac).
/// <see cref="T"/> returns the string for the current language (default English).
/// The common string table lives here; each client registers its platform-specific
/// entries (Windows service vs launchd daemon, tray vs menu bar, Wintun vs utun, …)
/// at startup via <see cref="AddOrReplace"/>. The framework-specific bindable source
/// and {l:Loc} markup extension stay per-client (WPF vs Avalonia); UI layers refresh
/// on the <see cref="LanguageChanged"/> event. See docs/REFACTOR-PLAN.md (R4).
/// </summary>
public static class Loc
{
    public static string Lang { get; private set; } = "en";

    /// <summary>Raised after the language changes so UI bindings can refresh.</summary>
    public static event Action? LanguageChanged;

    public static void SetLanguage(string lang)
    {
        Lang = lang == "ru" ? "ru" : "en";
        LanguageChanged?.Invoke();
    }

    public static string T(string key) =>
        Strings.TryGetValue(key, out var v) ? (Lang == "ru" ? v.ru : v.en) : key;

    /// <summary>Formatted lookup: T(key) then string.Format with args.</summary>
    public static string F(string key, params object[] args) => string.Format(T(key), args);

    /// <summary>Platform layers add or override entries (called once at startup).</summary>
    public static void AddOrReplace(IReadOnlyDictionary<string, (string en, string ru)> entries)
    {
        foreach (var kv in entries) Strings[kv.Key] = kv.Value;
    }

    private static readonly Dictionary<string, (string en, string ru)> Strings = new()
    {
        // ── common actions ──
        ["New"] = ("New", "Новый"),
        ["Import"] = ("Import", "Импорт"),
        ["Edit"] = ("Edit", "Изменить"),
        ["Delete"] = ("Delete", "Удалить"),
        ["Save"] = ("Save", "Сохранить"),
        ["Cancel"] = ("Cancel", "Отмена"),
        ["Connect"] = ("Connect", "Подключить"),
        ["Disconnect"] = ("Disconnect", "Отключить"),
        ["Settings"] = ("Settings", "Настройки"),
        ["SettingsMenu"] = ("Settings…", "Настройки…"),
        ["About"] = ("About", "О программе"),
        ["OpenWindow"] = ("Open window", "Открыть окно"),
        ["Exit"] = ("Exit", "Выход"),

        // ── main window ──
        ["ProfilesHeader"] = ("Profiles", "Профили"),
        ["LogHeader"] = ("Log", "Журнал"),
        ["Profile"] = ("Profile", "Профиль"),
        ["NoProfilesMenu"] = ("No profiles", "Нет профилей"),
        ["SelectProfile"] = ("Select a profile", "Выберите профиль"),
        ["TunnelIp"] = ("Tunnel addresses: {0}", "Адреса туннеля: {0}"),
        ["NoProfilesHint"] = ("No profiles yet.\nClick “Import” or “New”.", "Нет профилей.\nНажмите «Импорт» или «Новый»."),

        // ── statuses ──
        ["StatusDisconnected"] = ("Disconnected", "Отключено"),
        ["StatusConnecting"] = ("Connecting…", "Подключение…"),
        ["StatusConnected"] = ("Connected", "Подключено"),
        ["StatusError"] = ("Error", "Ошибка"),
        // data-plane reconnect-loop errors (shared by both clients via VpnTunnelBase)
        ["CouldNotConnect"] = ("Could not connect to the server", "Не удалось подключиться к серверу"),
        ["MitmStop"] = ("Server identity changed — possible MITM. Connection stopped.",
                        "Идентичность сервера изменилась — возможна MITM-атака. Подключение остановлено."),

        // ── tray ──
        ["TrayDisconnected"] = ("Qeli — disconnected", "Qeli — отключено"),
        ["TrayConnecting"] = ("Qeli — connecting…", "Qeli — подключение…"),
        ["TrayConnected"] = ("Qeli — connected", "Qeli — подключено"),
        ["TrayConnectedIp"] = ("Qeli — connected ({0})", "Qeli — подключено ({0})"),
        ["TrayError"] = ("Qeli — error", "Qeli — ошибка"),
        ["TrayErrorMsg"] = ("Qeli — error: {0}", "Qeli — ошибка: {0}"),

        // ── toasts ──
        ["ToastConnected"] = ("Connected", "Подключено"),
        ["ToastDisconnected"] = ("Disconnected", "Отключено"),
        ["ToastConnError"] = ("Connection error", "Ошибка подключения"),
        ["ToastConnLost"] = ("Connection lost", "Соединение потеряно"),
        ["Reconnecting"] = ("Reconnecting…", "Переподключение…"),

        // ── import / delete dialogs ──
        ["ImportTitle"] = ("Import profile", "Импорт профиля"),
        ["ImportPrompt"] = ("Paste a qeli:// link or INI config:", "Вставьте qeli:// ссылку или INI-конфиг:"),
        ["ImportError"] = ("Could not parse the config:\n{0}", "Не удалось разобрать конфиг:\n{0}"),
        ["DeleteConfirm"] = ("Delete profile “{0}”?", "Удалить профиль «{0}»?"),
        ["DeleteTitle"] = ("Delete", "Удаление"),

        // ── about ──
        ["AboutVersion"] = ("version {0}", "версия {0}"),

        // ── updates (opt-in; notification-only) ──
        ["CheckForUpdates"] = ("Check for updates automatically", "Проверять обновления автоматически"),
        ["CheckForUpdatesNow"] = ("Check for updates", "Проверить обновления"),
        ["ProbeReachability"] = ("Check server reachability", "Проверять доступность серверов"),
        ["AutoProbe"] = ("Poll profiles automatically", "Опрашивать профили автоматически"),
        ["ProbeInterval"] = ("Interval, s", "Интервал, с"),
        ["CheckReachabilityNow"] = ("Check reachability", "Проверить доступность"),
        ["UpdateChecking"] = ("Checking…", "Проверка…"),
        ["UpdateAvailable"] = ("Update available: {0}", "Доступна новая версия: {0}"),
        ["UpToDate"] = ("You have the latest version", "У вас последняя версия"),
        ["UpdateCheckConnect"] = ("Connect first to check for updates privately",
                                  "Сначала подключитесь, чтобы проверить обновления приватно"),
        ["UpdateCheckFailed"] = ("Could not check for updates", "Не удалось проверить обновления"),
        ["UpdateOpenPage"] = ("Open the release page", "Открыть страницу релиза"),

        // ── settings ──
        ["SettingsGeneral"] = ("General", "Основное"),
        ["SettingsConnection"] = ("Connection", "Подключение"),
        ["SettingsStartup"] = ("Startup", "Автозапуск"),
        ["SettingsService"] = ("Background", "Фоновый режим"),
        ["InterfaceSection"] = ("Appearance and logs", "Интерфейс и журнал"),
        ["ConnectionMonitoring"] = ("Server availability", "Доступность серверов"),
        ["ConnectionMonitoringDesc"] = (
            "Periodically checks saved profiles and shows latency on their cards. This does not start the VPN.",
            "Периодически проверяет сохранённые профили и показывает задержку на карточках. VPN при этом не запускается."),
        ["Notifications"] = ("Notifications", "Уведомления"),
        ["ShowToasts"] = ("Show toast notifications", "Показывать toast-уведомления"),
        ["Language"] = ("Language", "Язык"),
        ["Theme"] = ("Theme", "Тема"),
        ["ThemeSystem"] = ("System", "Системная"),
        ["ThemeLight"] = ("Light", "Светлая"),
        ["ThemeDark"] = ("Dark", "Тёмная"),
        // Log timestamp shape — same values as the server's [logging] time_format.
        ["LogTimeFormat"] = ("Log timestamp", "Время в логе"),
        ["LogTimeDatetime"] = ("Date and time", "Дата и время"),
        ["LogTimeRfc3339"] = ("RFC 3339 (UTC)", "RFC 3339 (UTC)"),
        ["LogTimeShort"] = ("Time only", "Только время"),
        ["LogTimeEpoch"] = ("Unix time", "Unix-время"),
        ["LogTimeNone"] = ("No timestamp", "Без времени"),
        ["LogDetail"] = ("Log detail", "Подробность журнала"),
        ["LogCompact"] = ("Compact", "Краткий"),
        ["LogDetailed"] = ("Detailed diagnostics", "Подробная диагностика"),
        // Refused profile switch while a tunnel is up. The body drops the profile name
        // on purpose: an endpoint like "203.0.113.10:8444" overflowed the fixed-width
        // toast, and the running profile is the highlighted one anyway.
        ["SwitchBlocked"] = ("Disconnect first", "Сначала отключитесь"),
        ["SwitchBlockedMsg"] = (
            "Can't switch profiles while connected",
            "Нельзя сменить профиль при подключении"),
        ["AutoConnect"] = ("Connect automatically on start", "Автоматически подключаться при запуске"),
        ["AutoConnectProfile"] = ("Auto-connect profile", "Профиль для автоподключения"),

        // ── config editor ──
        ["SectionAccess"] = ("Server and access", "Сервер и доступ"),
        ["SectionTransport"] = ("Transport and masking", "Транспорт и маскировка"),
        ["SectionNetwork"] = ("Network and DNS", "Сеть и DNS"),
        ["SectionApplications"] = ("Applications", "Приложения"),
        ["NewProfileTitle"] = ("New profile", "Новый профиль"),
        ["EditProfileTitle"] = ("Edit profile", "Изменить профиль"),
        ["FieldName"] = ("Name", "Название"),
        ["FieldServer"] = ("Server address", "Адрес сервера"),
        ["FieldPort"] = ("Port", "Порт"),
        ["FieldProtocol"] = ("Protocol", "Протокол"),
        ["FieldWireMode"] = ("Wire mode", "Wire-режим"),
        // Connection-mode presets: each sets transport + wire mode + fronting + QUIC.
        ["FieldMode"] = ("Connection mode", "Режим подключения"),
        ["PresetFakeTls"] = ("Fake-TLS · TCP", "Fake-TLS · TCP"),
        ["PresetObfsWs"] = ("Obfs · WebSocket · TCP", "Obfs · WebSocket · TCP"),
        ["PresetObfsNone"] = ("Obfs · raw · TCP", "Obfs · raw · TCP"),
        ["PresetUdp"] = ("UDP · Fake-TLS", "UDP · Fake-TLS"),
        ["PresetUdpQuic"] = ("UDP · QUIC masking", "UDP · QUIC-маскировка"),
        ["PresetUdpObfs"] = ("UDP · Obfs", "UDP · Obfs"),
        ["PresetReality"] = ("REALITY-TLS · TCP", "REALITY-TLS · TCP"),
        ["PresetPlain"] = ("Plain · TCP (no obfuscation)", "Plain · TCP (без обфускации)"),
        ["FieldRealityId"] = ("REALITY short_id (hex)", "REALITY short_id (hex)"),
        ["FieldLogin"] = ("Username", "Логин"),
        ["FieldPassword"] = ("Password", "Пароль"),
        ["FieldSni"] = ("SNI (domain masking)", "SNI (маскировка домена)"),
        ["FieldQuic"] = ("QUIC masking (UDP)", "QUIC-маскировка (UDP)"),
        ["FieldPadding"] = ("Padding (size masking)", "Паддинг (маскировка размера)"),
        ["FieldHeartbeat"] = ("Heartbeat (keep-alive)", "Heartbeat (keep-alive)"),
        ["FieldObfsKey"] = ("Obfs key (PSK)", "Ключ obfs (PSK)"),
        ["FieldServerKey"] = ("Server key (pinning)", "Ключ сервера (пиннинг)"),
        ["FieldRouting"] = ("Routing", "Маршрутизация"),
        ["FieldIpv6Policy"] = ("Inner IPv6 policy", "Политика IPv6 внутри туннеля"),
        ["Ipv6Auto"] = ("Automatic (accept server plan)", "Авто (принять план сервера)"),
        ["Ipv6Required"] = ("Required", "Обязателен"),
        ["Ipv6Off"] = ("Disabled inside tunnel", "Отключён внутри туннеля"),
        ["Ipv6PolicyHint"] = (
            "Auto accepts IPv4, dual-stack or IPv6-only. Required refuses a plan without IPv6; Off refuses tunneled IPv6.",
            "Авто принимает IPv4, dual-stack или IPv6-only. «Обязателен» отклоняет план без IPv6; «Отключён» запрещает IPv6 в туннеле."),
        ["FamilyLeakHint"] = (
            "Advanced full-tunnel exceptions. Keep both off to block a missing address family fail-closed.",
            "Дополнительные исключения full-tunnel. Оставьте оба выключенными, чтобы отсутствующее семейство блокировалось fail-closed."),
        ["AllowIpv4Leak"] = ("Allow native IPv4 outside an IPv6-only tunnel", "Разрешить нативный IPv4 вне IPv6-only туннеля"),
        ["AllowIpv6Leak"] = ("Allow native IPv6 outside an IPv4-only tunnel", "Разрешить нативный IPv6 вне IPv4-only туннеля"),
        ["FieldDns"] = ("DNS servers", "DNS-серверы"),
        ["FieldMtu"] = ("MTU (0 = automatic)", "MTU (0 = автоматически)"),
        ["FieldDnsMode"] = ("DNS mode", "Режим DNS"),
        ["DnsTunnel"] = ("Tunnel / server", "Туннель / сервер"),
        ["DnsSystem"] = ("Keep system DNS", "Оставить системный DNS"),
        ["DnsOff"] = ("Do not configure DNS", "Не настраивать DNS"),
        ["DnsPushHint"] = (
            "Leave the server list empty to use DNS received securely from the VPN server.",
            "Оставьте список серверов пустым, чтобы использовать DNS, безопасно полученный от VPN-сервера."),
        ["MtuProbe"] = ("Discover path MTU automatically when MTU is 0", "Автоматически определять MTU маршрута при значении 0"),
        ["KillSwitch"] = ("Block traffic if the tunnel is interrupted (kill switch)", "Блокировать трафик при разрыве туннеля (kill switch)"),
        ["ConnectionBehavior"] = ("Connection behavior", "Поведение подключения"),
        ["FieldTimeout"] = ("Connection timeout, seconds (1–300)", "Таймаут подключения, секунд (1–300)"),
        ["ReconnectAutomatically"] = ("Reconnect automatically", "Переподключаться автоматически"),
        ["ReconnectRetries"] = ("Retry limit", "Лимит попыток"),
        ["RetriesUnlimited"] = ("Unlimited", "Без ограничений"),
        ["Retries3"] = ("3 attempts", "3 попытки"),
        ["Retries5"] = ("5 attempts", "5 попыток"),
        ["Retries10"] = ("10 attempts", "10 попыток"),
        ["RetriesCustom"] = ("{0} attempts", "{0} попыток"),
        ["PersistTun"] = ("Keep the tunnel and routes while reconnecting", "Сохранять туннель и маршруты при переподключении"),
        ["RouteAll"] = ("All traffic", "Весь трафик"),
        ["RouteSplit"] = ("Split", "Раздельная"),
        ["Off"] = ("Off", "Выкл"),
        ["On"] = ("On", "Вкл"),
        ["Custom"] = ("Custom", "Пользовательский"),
        ["PaddingStandard"] = ("Standard", "Стандартный"),
        ["PaddingStrong"] = ("Strong", "Усиленный"),
        ["PaddingMax"] = ("Maximum", "Максимальный"),
        ["Hb15"] = ("15 seconds", "15 секунд"),
        ["Hb30"] = ("30 seconds", "30 секунд"),
        ["Hb60"] = ("60 seconds", "60 секунд"),
        ["RouteLocal"] = ("Route local networks (RFC1918) into the tunnel",
                          "Маршрутизировать локальные сети (RFC1918) в туннель"),
        ["FieldApps"] = ("Applications", "Приложения"),
        ["AppsAll"] = ("All applications", "Все приложения"),
        ["AppsInclude"] = ("Only selected applications", "Только выбранные приложения"),
        ["AppsExclude"] = ("All except selected applications", "Все, кроме выбранных приложений"),
        ["AppsPick"] = ("Select applications…", "Выбрать приложения…"),
        ["AppsPicked"] = ("Selected: {0}", "Выбрано: {0}"),
        ["AppsPickerTitle"] = ("Application routing", "Маршрутизация приложений"),
        ["AppsPickerHint"] = (
            "Choose executable files for this Windows client. App identifiers belonging to other platforms are preserved.",
            "Выберите исполняемые файлы для этого Windows-клиента. Идентификаторы приложений других платформ сохраняются."),
        ["AppsMacHint"] = (
            "macOS bundle signing identifiers, separated by commas (for example: com.apple.Safari). Other-platform identifiers are preserved.",
            "Идентификаторы подписи bundle macOS через запятую (например: com.apple.Safari). Идентификаторы других платформ сохраняются."),
        ["AppsMacPickerHint"] = (
            "Choose installed macOS applications. Their code-signing identifiers are stored; identifiers for other platforms or apps not installed on this Mac remain available.",
            "Выберите установленные приложения macOS. Сохраняются их code-signing identifier; идентификаторы других платформ и не установленных на этом Mac приложений остаются доступными."),
        ["AppsBrowse"] = ("Add executable…", "Добавить программу…"),
        ["NeedApps"] = ("Select at least one application or use “All applications”.",
                         "Выберите хотя бы одно приложение или режим «Все приложения»."),
        ["NeedServer"] = ("Enter the server address.", "Укажите адрес сервера."),
        ["BadPort"] = ("Invalid port (1–65535).", "Некорректный порт (1–65535)."),
        ["BadTimeout"] = ("Invalid connection timeout (1–300 seconds).", "Некорректный таймаут подключения (1–300 секунд)."),
        ["BadMtu"] = ("MTU must be 0 (automatic) or 576–16638.", "MTU должен быть 0 (автоматически) или 576–16638."),
        ["NeedLogin"] = ("Enter the username.", "Укажите логин."),
        ["ManualEdit"] = ("Edit INI configuration", "Редактирование INI-конфига"),
        ["ManualEditPrompt"] = ("Edit the INI configuration:", "Редактирование INI-конфига:"),
        ["EditIni"] = ("Edit INI", "Редактировать INI"),
        ["EditIniHint"] = ("Open the complete INI configuration", "Открыть полный INI-конфиг"),

        // ── service / misc message boxes ──
        ["AutostartError"] = ("Could not change autostart:\n{0}", "Не удалось изменить автозапуск:\n{0}"),
        ["UnhandledError"] = ("Qeli — unhandled error", "Qeli — необработанная ошибка"),

        // ── Studio UI ──
        ["Search"] = ("Search profiles…", "Поиск профилей…"),
        ["Duplicate"] = ("Duplicate", "Дублировать"),
        ["ShareQr"] = ("Share / QR", "Поделиться / QR"),
        ["StatDownload"] = ("Download", "Приём"),
        ["StatUpload"] = ("Upload", "Отдача"),
        ["StatSession"] = ("Session", "Сессия"),
        ["StatTunnelIp"] = ("Tunnel addresses", "Адреса туннеля"),
        ["StatTotal"] = ("total {0}", "всего {0}"),
        ["StatSince"] = ("since {0}", "с {0}"),
        ["LogCopy"] = ("Copy log", "Копировать лог"),
        ["LogClear"] = ("Clear log", "Очистить лог"),
        ["Throughput"] = ("Throughput", "Трафик"),
        ["ChartWindow"] = ("60 s", "60 с"),
        ["Offline"] = ("offline", "офлайн"),
        ["QrTitle"] = ("Share profile", "Поделиться профилём"),
        ["CopyLink"] = ("Copy link", "Копировать ссылку"),
        ["Copied"] = ("Copied", "Скопировано"),
        ["Close"] = ("Close", "Закрыть"),
        ["CopySuffix"] = (" (copy)", " (копия)"),
    };
}
