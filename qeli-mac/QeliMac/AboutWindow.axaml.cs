using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Qeli.Shared;

namespace QeliMac;

public partial class AboutWindow : Window
{
    private string? _updateUrl;

    public AboutWindow()
    {
        InitializeComponent();
        LogoImage.Source = Ui.Png(Branding.AppIconPng(96));
        VersionLabel.Text = Loc.F("AboutVersion", AppVersion());
    }

    public AboutWindow(Window owner) : this() => Icon = owner.Icon;

    public static string AppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "—" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private void OnOk(object? sender, RoutedEventArgs e) => Close();

    /// <summary>Manual, user-initiated update check. Privacy: only runs while the tunnel is
    /// up (so it travels inside the tunnel); when disconnected we ask the user to connect
    /// first rather than leaking the real IP / a "runs qeli" signal on the bare link.</summary>
    private async void OnCheckUpdates(object? sender, RoutedEventArgs e)
    {
        if (Owner is not MainWindow mw || !mw.IsTunnelUp)
        {
            ShowStatus(Loc.T("UpdateCheckConnect"));
            return;
        }

        CheckUpdatesBtn.IsEnabled = false;
        ShowStatus(Loc.T("UpdateChecking"));
        var info = await UpdateChecker.CheckAsync(AppVersion());
        CheckUpdatesBtn.IsEnabled = true;

        if (info == null) ShowStatus(Loc.T("UpdateCheckFailed"));
        else if (info.IsNewer)
        {
            ShowUpdateLink(info);
            mw.ShowUpdateAvailable(info); // also light up the persistent banner on the main window
        }
        else ShowStatus(Loc.T("UpToDate"));
    }

    private void ShowStatus(string text)
    {
        _updateUrl = null;
        UpdateStatus.Text = text;
        UpdateStatus.TextDecorations = null;
        UpdateStatus.IsVisible = true;
    }

    private void ShowUpdateLink(UpdateInfo info)
    {
        _updateUrl = info.ReleaseUrl;
        UpdateStatus.Text = Loc.F("UpdateAvailable", info.LatestVersion);
        UpdateStatus.TextDecorations = TextDecorations.Underline;
        UpdateStatus.IsVisible = true;
    }

    private void OnUpdateStatusClick(object? sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_updateUrl)) MainWindow.OpenUrl(_updateUrl);
    }
}
