using System.ComponentModel;
using System.Runtime.CompilerServices;
using Avalonia.Data;
using Avalonia.Markup.Xaml;
using Qeli.Shared;

namespace QeliMac;

/// <summary>macOS-specific localization: platform string overrides (daemon wording,
/// menu bar, utun, generic dialogs, …) plus the Avalonia bindable source and {l:Loc}
/// markup extension. The shared string table + lookup live in <see cref="Qeli.Shared.Loc"/>.</summary>
internal static class PlatformStrings
{
    [ModuleInitializer]
    public static void Register() => Loc.AddOrReplace(new Dictionary<string, (string en, string ru)>
    {
        ["MacUtunLabel"] = ("utun number", "Номер utun"),
        ["MacUtunHint"] = ("Auto (default), or a number 0–65534, e.g. 42 → utun42. A busy number is an error, never an automatic replacement. This does not keep the interface after Quit or reboot.", "Авто (по умолчанию) или номер 0–65534: например, 42 → utun42. Занятый номер — ошибка, без автоматической подмены. Интерфейс не сохраняется после выхода или перезагрузки."),
        ["MacUtunInvalid"] = ("Invalid utun number: use Auto or 0–65534 in the editor; in INI use dev_node = auto or dev_node = utun42.", "Неверный номер utun: в редакторе выберите Авто или 0–65534; в INI укажите dev_node = auto или dev_node = utun42."),
        ["MacUtunBusy"] = ("utun{0} is already in use (errno {1}). Disconnect the VPN using it, choose a different utun number, or select Auto. Qeli will not take over this interface or silently change the number.", "utun{0} уже занят (errno {1}). Отключите использующий его VPN, выберите другой номер utun или Авто. Qeli не присваивает чужой интерфейс и не подменяет номер."),
        ["MacUtunConnectFailed"] = ("Cannot create utun{0} (errno {1}). Check administrator privileges and macOS restrictions. No other interface was selected.", "Не удалось создать utun{0} (errno {1}). Проверьте права администратора и ограничения macOS. Другой интерфейс не выбирался."),
        ["TrayBalloon"] = ("Hidden in the menu bar. Click the icon to open.",
                           "Скрыто в строке меню. Нажмите значок — открыть."),
        ["AboutDesc"] = ("VPN client for macOS. qeli protocol: fake-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN via utun.",
                         "VPN-клиент для macOS. Протокол qeli: фейк-TLS / obfs / REALITY-TLS, X25519 + ChaCha20-Poly1305, TUN через utun."),
        ["ServiceSection"] = ("launchd daemon (always-on VPN, starts at boot before login)",
                              "Демон launchd (постоянный VPN, старт при загрузке до входа)"),
        ["RunAsService"] = ("Run as a launchd daemon", "Запускать как демон launchd"),
        ["ServiceProfileLabel"] = ("Daemon profile", "Профиль демона"),
        ["ServiceDesc"] = ("The daemon runs as root, starts at macOS boot (before login), brings up the selected profile and reconnects on its own. The VPN is then managed by the daemon. Administrator rights required.",
                           "Демон работает от root, стартует при загрузке macOS (до входа пользователя), автоматически поднимает выбранный профиль и сам переподключается. Управление VPN при этом идёт через демон. Требуются права администратора."),
        ["AppStartSection"] = ("Application startup (without the daemon)", "Запуск приложения (без демона)"),
        ["RunAtLogon"] = ("Start the app at login", "Запускать приложение при входе"),
        ["StartMinimized"] = ("Start hidden in the menu bar", "Запускать скрытым в строке меню"),
        ["ServiceWord"] = ("Daemon", "Демон"),
        ["NoServiceProfile"] = ("No daemon profile — create a profile first.", "Нет профиля для демона — создайте профиль."),
        ["ServiceApplyError"] = ("Could not apply daemon settings:\n{0}", "Не удалось применить настройки демона:\n{0}"),
        ["ServiceControlError"] = ("Daemon control error:\n{0}", "Ошибка управления демоном:\n{0}"),
        ["Ok"] = ("OK", "OK"),
        ["Yes"] = ("Yes", "Да"),
        ["No"] = ("No", "Нет"),
        ["NeedRoot"] = ("Connecting requires root. Launch Qeli with sudo, or enable the launchd daemon in Settings.",
                        "Для подключения нужны права root. Запустите Qeli через sudo или включите демон launchd в настройках."),
    });
}

/// <summary>Notifying source for {l:Loc} bindings; raised on language change.</summary>
public sealed class LocalizationManager : INotifyPropertyChanged
{
    public static LocalizationManager Instance { get; } = new();
    public event PropertyChangedEventHandler? PropertyChanged;
    public string this[string key] => Loc.T(key);
    private LocalizationManager() => Loc.LanguageChanged += Refresh;
    // Empty property name tells Avalonia's binding system to re-read every binding.
    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
}

/// <summary>XAML markup extension: {l:Loc Key} -> live-updating localized string.</summary>
public sealed class LocExtension : MarkupExtension
{
    public string Key { get; set; } = "";

    public LocExtension() { }
    public LocExtension(string key) => Key = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]")
        {
            Source = LocalizationManager.Instance,
            Mode = BindingMode.OneWay,
        };
}
