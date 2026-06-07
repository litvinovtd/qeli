using System.Drawing;
using System.Windows.Forms;
using QeliWin.Model;
using QeliWin.Vpn;

namespace QeliWin;

/// <summary>
/// System-tray icon with a colored status indicator and a context menu to switch
/// profiles, connect/disconnect and show/exit. Backed by WinForms NotifyIcon
/// (hosted inside the WPF app — no separate message loop needed).
/// </summary>
public sealed class TrayController : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu;
    private readonly Dictionary<VpnStatus, Icon> _icons = new();

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
        _menu = new ContextMenuStrip();
        _menu.Opening += (_, _) => RebuildMenu();

        _icon = new NotifyIcon
        {
            Visible = true,
            Icon = _icons[VpnStatus.Disconnected],
            Text = "Qeli — отключено",
            ContextMenuStrip = _menu,
        };
        _icon.DoubleClick += (_, _) => _onShowWindow();
        RebuildMenu();
    }

    /// <summary>Update icon color + tooltip + balloon to reflect the current status.</summary>
    public void Update(VpnStatus status, string? extra)
    {
        _icon.Icon = _icons[status];
        _icon.Text = Truncate(TooltipFor(status, extra), 63);
    }

    public void ShowBalloon(string title, string text) =>
        _icon.ShowBalloonTip(3000, title, text, ToolTipIcon.Info);

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private static string TooltipFor(VpnStatus s, string? extra) => s switch
    {
        VpnStatus.Connecting => Loc.T("TrayConnecting"),
        VpnStatus.Connected => string.IsNullOrEmpty(extra) ? Loc.T("TrayConnected") : Loc.F("TrayConnectedIp", extra),
        VpnStatus.Error => string.IsNullOrEmpty(extra) ? Loc.T("TrayError") : Loc.F("TrayErrorMsg", extra),
        _ => Loc.T("TrayDisconnected"),
    };

    private void RebuildMenu()
    {
        _menu.Items.Clear();
        var status = _getStatus();
        var active = _getActive();

        var header = new ToolStripMenuItem(TooltipFor(status, null)) { Enabled = false };
        _menu.Items.Add(header);
        _menu.Items.Add(new ToolStripSeparator());

        bool busy = status is VpnStatus.Connected or VpnStatus.Connecting;
        var toggle = new ToolStripMenuItem(busy ? Loc.T("Disconnect") : Loc.T("Connect"))
        {
            Enabled = active != null,
        };
        toggle.Click += (_, _) => _onToggleConnect();
        _menu.Items.Add(toggle);

        var profilesItem = new ToolStripMenuItem(Loc.T("Profile"));
        var profiles = _getProfiles();
        if (profiles.Count == 0)
        {
            profilesItem.DropDownItems.Add(new ToolStripMenuItem(Loc.T("NoProfilesMenu")) { Enabled = false });
        }
        else
        {
            foreach (var p in profiles)
            {
                var item = new ToolStripMenuItem(p.DisplayName) { Checked = ReferenceEquals(p, active) };
                item.ToolTipText = p.Endpoint;
                var captured = p;
                item.Click += (_, _) => _onSelectProfile(captured);
                profilesItem.DropDownItems.Add(item);
            }
        }
        _menu.Items.Add(profilesItem);

        _menu.Items.Add(new ToolStripSeparator());
        var show = new ToolStripMenuItem(Loc.T("OpenWindow"));
        show.Click += (_, _) => _onShowWindow();
        _menu.Items.Add(show);

        var settings = new ToolStripMenuItem(Loc.T("SettingsMenu"));
        settings.Click += (_, _) => _onSettings();
        _menu.Items.Add(settings);

        var exit = new ToolStripMenuItem(Loc.T("Exit"));
        exit.Click += (_, _) => _onExit();
        _menu.Items.Add(exit);
    }

    private void BuildIcons()
    {
        _icons[VpnStatus.Disconnected] = Branding.TrayIcon(Branding.StatusDisconnected);
        _icons[VpnStatus.Connecting] = Branding.TrayIcon(Branding.StatusConnecting);
        _icons[VpnStatus.Connected] = Branding.TrayIcon(Branding.StatusConnected);
        _icons[VpnStatus.Error] = Branding.TrayIcon(Branding.StatusError);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _menu.Dispose();
        foreach (var ic in _icons.Values) ic.Dispose();
        _icons.Clear();
    }
}
