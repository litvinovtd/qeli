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
        ["TunnelIp"] = ("Tunnel IP: {0}", "IP в туннеле: {0}"),
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

        // ── settings ──
        ["Notifications"] = ("Notifications", "Уведомления"),
        ["ShowToasts"] = ("Show toast notifications", "Показывать toast-уведомления"),
        ["Language"] = ("Language", "Язык"),
        ["Theme"] = ("Theme", "Тема"),
        ["ThemeSystem"] = ("System", "Системная"),
        ["ThemeLight"] = ("Light", "Светлая"),
        ["ThemeDark"] = ("Dark", "Тёмная"),
        ["AutoConnect"] = ("Connect automatically on start", "Автоматически подключаться при запуске"),
        ["AutoConnectProfile"] = ("Auto-connect profile", "Профиль для автоподключения"),

        // ── config editor ──
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
        ["FieldDns"] = ("DNS servers", "DNS-серверы"),
        ["RouteAll"] = ("All traffic", "Весь трафик"),
        ["RouteSplit"] = ("Split", "Раздельная"),
        ["Off"] = ("Off", "Выкл"),
        ["On"] = ("On", "Вкл"),
        ["PaddingStandard"] = ("Standard", "Стандартный"),
        ["PaddingStrong"] = ("Strong", "Усиленный"),
        ["PaddingMax"] = ("Maximum", "Максимальный"),
        ["Hb15"] = ("15 seconds", "15 секунд"),
        ["Hb30"] = ("30 seconds", "30 секунд"),
        ["Hb60"] = ("60 seconds", "60 секунд"),
        ["RouteLocal"] = ("Route local networks (RFC1918) into the tunnel",
                          "Маршрутизировать локальные сети (RFC1918) в туннель"),
        ["NeedServer"] = ("Enter the server address.", "Укажите адрес сервера."),
        ["BadPort"] = ("Invalid port (1–65535).", "Некорректный порт (1–65535)."),
        ["NeedLogin"] = ("Enter the username.", "Укажите логин."),
        ["ManualEdit"] = ("Edit as text", "Редактировать текстом"),
        ["ManualEditPrompt"] = ("Edit the config:", "Редактирование конфига:"),

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
        ["StatTunnelIp"] = ("Tunnel IP", "IP туннеля"),
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