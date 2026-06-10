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