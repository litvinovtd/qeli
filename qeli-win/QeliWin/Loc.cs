using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Markup;
using Qeli.Shared;

namespace QeliWin;

/// <summary>Windows-specific localization: platform string overrides (service wording,
/// tray, Wintun, …) plus the WPF bindable source and {l:Loc} markup extension. The
/// shared string table + lookup live in <see cref="Qeli.Shared.Loc"/>.</summary>
internal static class PlatformStrings
{
    [ModuleInitializer]
    public static void Register() => Loc.AddOrReplace(new Dictionary<string, (string en, string ru)>
    {
        ["Licenses"] = ("Licenses", "Лицензии"),
        ["LicensesExport"] = ("Save all license texts…", "Сохранить все тексты лицензий…"),
        ["LicensesSummary"] = ("{0} original license, notice and index files embedded in this EXE. Available offline; export preserves original bytes.", "В этот EXE встроено {0} исходных файлов лицензий, уведомлений и индексов. Доступны без сети; экспорт сохраняет исходные байты."),
        ["TrayBalloon"] = ("Minimized to tray. Double-click the icon to open.",
                           "Свёрнуто в трей. Двойной клик по значку — открыть."),
        ["AboutDesc"] = ("VPN client for Windows. qeli protocol: fake-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN via Wintun.",
                         "VPN-клиент для Windows. Протокол qeli: фейк-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN через Wintun."),
        ["ServiceSection"] = ("Windows service (always-on VPN, starts before logon)",
                              "Служба Windows (постоянный VPN до входа в систему)"),
        ["RunAsService"] = ("Run as a Windows service", "Запускать как службу Windows"),
        ["ServiceProfileLabel"] = ("Service profile", "Профиль службы"),
        ["ServiceDesc"] = ("The service runs as LocalSystem, starts at Windows boot (before logon), brings up the selected profile and reconnects on its own. The VPN is then managed by the service. Administrator rights required.",
                           "Служба работает под LocalSystem, стартует при загрузке Windows (до входа пользователя), автоматически поднимает выбранный профиль и сама переподключается. Управление VPN при этом идёт через службу. Требуются права администратора."),
        ["AppStartSection"] = ("Application startup (without the service)", "Запуск приложения (без службы)"),
        ["RunAtLogon"] = ("Start the app at Windows logon", "Запускать приложение при входе в Windows"),
        ["StartMinimized"] = ("Start minimized to tray", "Запускать свёрнутым в трей"),
        ["ServiceWord"] = ("Service", "Служба"),
        ["StorageMigrationTitle"] = ("Prepare Qeli service storage", "Подготовка служебного хранилища Qeli"),
        ["StorageMigrationManual"] = ("Legacy storage needs preparation. Open Qeli manually as administrator; automatic startup cannot migrate it.", "Старое хранилище требует подготовки. Откройте Qeli вручную от имени администратора: автозапуск не выполняет миграцию."),
        ["StorageMigrationAdmin"] = ("Run Qeli as administrator to prepare legacy storage.", "Для подготовки старого хранилища запустите Qeli от имени администратора."),
        ["StorageMigrationPrompt"] = ("Qeli needs to separate protected service data from its native library cache.\n\nFirst disconnect VPN normally, finish DNS/routes/firewall recovery, stop Qeli VPN Service and close other Qeli clients. Do not proceed after a shutdown timeout.\n\nOK confirms recovery is complete and archives the old directory in a private backup. Old service files are NOT imported. User profiles are unchanged; reselect your trusted profile in service settings afterwards. Cancel makes no storage changes.", "Qeli необходимо разделить защищённые данные службы и кеш нативных библиотек.\n\nСначала штатно отключите VPN, завершите восстановление DNS/маршрутов/firewall, остановите Qeli VPN Service и закройте другие клиенты Qeli. После тайм-аута остановки продолжать нельзя.\n\nНажимая ОК, вы подтверждаете завершение восстановления и сохранение старого каталога в приватную резервную копию. Старые служебные файлы НЕ импортируются. Пользовательские профили сохраняются; затем заново выберите доверенный профиль в настройках службы. Отмена не меняет хранилище."),
        ["StorageMigrationDone"] = ("Storage is ready. Private backup:\n{0}\n\nReapply a trusted profile in service settings. Do not copy old service files back or publish the backup: it may contain credentials.", "Хранилище подготовлено. Приватная резервная копия:\n{0}\n\nЗаново примените доверенный профиль в настройках службы. Не копируйте старые служебные файлы обратно и не публикуйте резервную копию: она может содержать пароли."),
        ["StorageMigrationFailed"] = ("Storage preparation did not complete:\n{0}\n\nDo not delete recovery journals or reset firewall rules to bypass this check.", "Подготовка хранилища не завершена:\n{0}\n\nНе удаляйте recovery-журналы и не сбрасывайте firewall для обхода проверки."),
        ["ServiceProfileDeleteBlocked"] = ("This profile is configured for the Windows service. Disable the service or select another service profile in Settings before deleting it.", "Этот профиль используется службой Windows. Перед удалением отключите службу или выберите другой профиль службы в настройках."),
        ["NoServiceProfile"] = ("No service profile — create a profile first.", "Нет профиля для службы — создайте профиль."),
        ["ServiceApplyError"] = ("Could not apply service settings:\n{0}", "Не удалось применить настройки службы:\n{0}"),
        ["ServiceControlError"] = ("Service control error:\n{0}", "Ошибка управления службой:\n{0}"),
    });
}

/// <summary>Notifying source for {l:Loc} bindings; raised on language change.</summary>
public sealed class LocalizationManager : INotifyPropertyChanged
{
    public static LocalizationManager Instance { get; } = new();
    public event PropertyChangedEventHandler? PropertyChanged;
    public string this[string key] => Loc.T(key);
    private LocalizationManager() => Loc.LanguageChanged += Refresh;
    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
}

/// <summary>XAML markup extension: {l:Loc Key} -> live-updating localized string.</summary>
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
