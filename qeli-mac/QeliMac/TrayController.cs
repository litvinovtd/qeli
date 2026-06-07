using Avalonia;
using Avalonia.Controls;
using QeliMac.Model;
using QeliMac.Vpn;

namespace QeliMac;

/// <summary>
/// Menu-bar status icon with a colored "Q" indicator and a menu to switch profiles,
/// connect/disconnect and show/exit. Backed by Avalonia's native <see cref="TrayIcon"/>
/// + <see cref="NativeMenu"/> (the macOS analogue of qeli-win's WinForms NotifyIcon).
/// </summary>
public sealed class TrayController : IDisposable
{
    private readonly TrayIcon _icon;
    private readonly Dictionary<VpnStatus, WindowIcon> _icons = new();

    private readonly Func<IReadOnlyList<VpnConfig>> _getProfiles;
    private readonly Func<VpnConfig?> _getActive;
    private readonly Action<VpnConfig> _onSelectProfile;
    private readonly Action _onToggleConnect;
    private readonly Action _onShowWindow;
    private readonly Action _onSettings;
    private readonly Action _onExit;
    private readonly Func<VpnStatus> _getStatus;

    public TrayController(
        Func<IReadOnlyList<VpnConfig>> getProfiles,
        Func<VpnConfig?> getActive,
        Action<VpnConfig> onSelectProfile,
        Action onToggleConnect,
        Action onShowWindow,
        Action onSettings,
        Action onExit,
        Func<VpnStatus> getStatus)
    {
        _getProfiles = getProfiles;
        _getActive = getActive;
        _onSelectProfile = onSelectProfile;
        _onToggleConnect = onToggleConnect;
        _onShowWindow = onShowWindow;
        _onSettings = onSettings;
        _onExit = onExit;
        _getStatus = getStatus;

        BuildIcons();
        _icon = new TrayIcon
        {
            Icon = _icons[VpnStatus.Disconnected],
            ToolTipText = Loc.T("TrayDisconnected"),
            IsVisible = true,
        };
        _icon.Clicked += (_, _) => _onShowWindow();
        RebuildMenu(VpnStatus.Disconnected);

        TrayIcon.SetIcons(Application.Current!, new TrayIcons { _icon });
    }

    /// <summary>Update icon color + tooltip + menu to reflect the current status.</summary>
    public void Update(VpnStatus status, string? extra)
    {
        _icon.Icon = _icons[status];
        _icon.ToolTipText = Truncate(TooltipFor(status, extra), 120);
        RebuildMenu(status);
    }

    /// <summary>No menu-bar balloon idiom on macOS; kept for API parity (no-op).</summary>
    public void ShowBalloon(string title, string text) { }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private static string TooltipFor(VpnStatus s, string? extra) => s switch
    {
        VpnStatus.Connecting => Loc.T("TrayConnecting"),
        VpnStatus.Connected => string.IsNullOrEmpty(extra) ? Loc.T("TrayConnected") : Loc.F("TrayConnectedIp", extra),
        VpnStatus.Error => string.IsNullOrEmpty(extra) ? Loc.T("TrayError") : Loc.F("TrayErrorMsg", extra),
        _ => Loc.T("TrayDisconnected"),
    };

    private void RebuildMenu(VpnStatus status)
    {
        var menu = new NativeMenu();
        var active = _getActive();

        menu.Add(new NativeMenuItem(TooltipFor(status, null)) { IsEnabled = false });
        menu.Add(new NativeMenuItemSeparator());

        bool busy = status is VpnStatus.Connected or VpnStatus.Connecting;
        var toggle = new NativeMenuItem(busy ? Loc.T("Disconnect") : Loc.T("Connect")) { IsEnabled = active != null };
        toggle.Click += (_, _) => _onToggleConnect();
        menu.Add(toggle);

        var profilesItem = new NativeMenuItem(Loc.T("Profile"));
        var sub = new NativeMenu();
        var profiles = _getProfiles();
        if (profiles.Count == 0)
        {
            sub.Add(new NativeMenuItem(Loc.T("NoProfilesMenu")) { IsEnabled = false });
        }
        else
        {
            foreach (var p in profiles)
            {
                var item = new NativeMenuItem(p.DisplayName)
                {
                    ToggleType = NativeMenuItemToggleType.CheckBox,
                    IsChecked = ReferenceEquals(p, active),
                };
                var captured = p;
                item.Click += (_, _) => _onSelectProfile(captured);
                sub.Add(item);
            }
        }
        profilesItem.Menu = sub;
        menu.Add(profilesItem);

        menu.Add(new NativeMenuItemSeparator());
        var show = new NativeMenuItem(Loc.T("OpenWindow"));
        show.Click += (_, _) => _onShowWindow();
        menu.Add(show);

        var settings = new NativeMenuItem(Loc.T("SettingsMenu"));
        settings.Click += (_, _) => _onSettings();
        menu.Add(settings);

        var exit = new NativeMenuItem(Loc.T("Exit"));
        exit.Click += (_, _) => _onExit();
        menu.Add(exit);

        _icon.Menu = menu;
    }

    private void BuildIcons()
    {
        _icons[VpnStatus.Disconnected] = Ui.Icon(Branding.TrayPng(Branding.StatusDisconnected));
        _icons[VpnStatus.Connecting] = Ui.Icon(Branding.TrayPng(Branding.StatusConnecting));
        _icons[VpnStatus.Connected] = Ui.Icon(Branding.TrayPng(Branding.StatusConnected));
        _icons[VpnStatus.Error] = Ui.Icon(Branding.TrayPng(Branding.StatusError));
    }

    public void Dispose()
    {
        _icon.IsVisible = false;
        try { _icon.Dispose(); } catch { }
        _icons.Clear();
    }
}
