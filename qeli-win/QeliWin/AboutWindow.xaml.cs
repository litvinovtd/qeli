using System.Reflection;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Navigation;
using Qeli.Shared;

namespace QeliWin;

public partial class AboutWindow : Window
{
    public AboutWindow(Window owner)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;
        LogoImage.Source = Ui.Png(Branding.AppIconPng(96));
        VersionLabel.Text = Loc.F("AboutVersion", AppVersion());
    }

    public static string AppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "—" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private void OnOk(object sender, RoutedEventArgs e) => Close();

    /// <summary>Manual, user-initiated update check. Privacy: only runs while the tunnel is
    /// up (so it travels inside the tunnel); when disconnected we ask the user to connect
    /// first rather than leaking the real IP / a "runs qeli" signal on the bare link.</summary>
    private async void OnCheckUpdates(object sender, RoutedEventArgs e)
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
        UpdateStatus.Inlines.Clear();
        UpdateStatus.Text = text;
        UpdateStatus.Visibility = Visibility.Visible;
    }

    private void ShowUpdateLink(UpdateInfo info)
    {
        UpdateStatus.Inlines.Clear();
        var link = new Hyperlink(new Run(Loc.F("UpdateAvailable", info.LatestVersion)))
        {
            NavigateUri = new System.Uri(info.ReleaseUrl),
            ToolTip = Loc.T("UpdateOpenPage"),
        };
        link.RequestNavigate += OnNavigate;
        UpdateStatus.Inlines.Add(link);
        UpdateStatus.Visibility = Visibility.Visible;
    }

    private void OnNavigate(object sender, RequestNavigateEventArgs e)
    {
        MainWindow.OpenUrl(e.Uri.ToString());
        e.Handled = true;
    }
}
