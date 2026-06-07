using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Markup;

namespace QeliWin;

/// <summary>
/// Tiny runtime localization. <see cref="Loc.T"/> returns the string for the current
/// language (default English). XAML uses {l:Loc Key} which binds to the notifying
/// <see cref="LocalizationManager"/> so the UI switches language live.
/// </summary>
public static class Loc
{
    public static string Lang { get; private set; } = "en";

    public static void SetLanguage(string lang)
    {
        Lang = lang == "ru" ? "ru" : "en";
        LocalizationManager.Instance.Refresh();
    }

    public static string T(string key) =>
        Strings.TryGetValue(key, out var v) ? (Lang == "ru" ? v.ru : v.en) : key;

    /// <summary>Formatted lookup: T(key) then string.Format with args.</summary>
    public static string F(string key, params object[] args) => string.Format(T(key), args);

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

        // ── tray ──
        ["TrayDisconnected"] = ("Qeli — disconnected", "Qeli — отключено"),
        ["TrayConnecting"] = ("Qeli — connecting…", "Qeli — подключение…"),
        ["TrayConnected"] = ("Qeli — connected", "Qeli — подключено"),
        ["TrayConnectedIp"] = ("Qeli — connected ({0})", "Qeli — подключено ({0})"),
        ["TrayError"] = ("Qeli — error", "Qeli — ошибка"),
        ["TrayErrorMsg"] = ("Qeli — error: {0}", "Qeli — ошибка: {0}"),
        ["TrayBalloon"] = ("Minimized to tray. Double-click the icon to open.",
                           "Свёрнуто в трей. Двойной клик по значку — открыть."),

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
        ["AboutDesc"] = ("VPN client for Windows. qeli protocol: fake-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN via Wintun.",
                         "VPN-клиент для Windows. Протокол qeli: фейк-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN через Wintun."),

        // ── settings ──
        ["Notifications"] = ("Notifications", "Уведомления"),
        ["ShowToasts"] = ("Show toast notifications", "Показывать toast-уведомления"),
        ["Language"] = ("Language", "Язык"),
        ["Theme"] = ("Theme", "Тема"),
        ["ThemeSystem"] = ("System", "Системная"),
        ["ThemeLight"] = ("Light", "Светлая"),
        ["ThemeDark"] = ("Dark", "Тёмная"),
        ["ServiceSection"] = ("Windows service (always-on VPN, starts before logon)",
                              "Служба Windows (постоянный VPN до входа в систему)"),
        ["RunAsService"] = ("Run as a Windows service", "Запускать как службу Windows"),
        ["ServiceProfileLabel"] = ("Service profile", "Профиль службы"),
        ["ServiceDesc"] = ("The service runs as LocalSystem, starts at Windows boot (before logon), brings up the selected profile and reconnects on its own. The VPN is then managed by the service. Administrator rights required.",
                           "Служба работает под LocalSystem, стартует при загрузке Windows (до входа пользователя), автоматически поднимает выбранный профиль и сама переподключается. Управление VPN при этом идёт через службу. Требуются права администратора."),
        ["AppStartSection"] = ("Application startup (without the service)", "Запуск приложения (без службы)"),
        ["RunAtLogon"] = ("Start the app at Windows logon", "Запускать приложение при входе в Windows"),
        ["AutoConnect"] = ("Connect automatically on start", "Автоматически подключаться при запуске"),
        ["AutoConnectProfile"] = ("Auto-connect profile", "Профиль для автоподключения"),
        ["StartMinimized"] = ("Start minimized to tray", "Запускать свёрнутым в трей"),

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
        ["ServiceWord"] = ("Service", "Служба"),
        ["NoServiceProfile"] = ("No service profile — create a profile first.", "Нет профиля для службы — создайте профиль."),
        ["ServiceApplyError"] = ("Could not apply service settings:\n{0}", "Не удалось применить настройки службы:\n{0}"),
        ["ServiceControlError"] = ("Service control error:\n{0}", "Ошибка управления службой:\n{0}"),
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

/// <summary>Notifying source for {l:Loc} bindings; raised on language change.</summary>
public sealed class LocalizationManager : INotifyPropertyChanged
{
    public static LocalizationManager Instance { get; } = new();
    public event PropertyChangedEventHandler? PropertyChanged;
    public string this[string key] => Loc.T(key);
    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
}

/// <summary>XAML markup extension: {l:Loc Key} → live-updating localized string.</summary>
public sealed class LocExtension : MarkupExtension
{
    public string Key { get; set; } = "";

    public LocExtension() { }
    public LocExtension(string key) => Key = key;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding($"[{Key}]")
        {
            Source = LocalizationManager.Instance,
            Mode = BindingMode.OneWay,
        };
        return binding.ProvideValue(serviceProvider);
    }
}
