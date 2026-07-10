using System.Windows;
using QeliWin.Model;
using QeliWin.Service;
using Qeli.Shared;
using Qeli.Shared.Model;

namespace QeliWin;

/// <summary>
/// Settings dialog: toasts, Windows-service mode (+ its profile), and GUI autostart/
/// auto-connect. Persists to <see cref="AppSettings"/>; the service install/uninstall
/// itself is applied by MainWindow after the dialog closes (it coordinates the tunnel).
/// </summary>
public partial class SettingsWindow : Window
{
    public SettingsWindow(Window owner, IReadOnlyList<VpnConfig> profiles)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;

        var s = AppSettings.Current;
        SelectByTag(LanguageBox, s.Language);
        SelectByTag(ThemeBox, s.Theme);
        ToastsBox.IsChecked = s.ToastsEnabled;
        UpdatesBox.IsChecked = s.CheckForUpdates;
        ProbeBox.IsChecked = s.ProbeReachability;
        ProbeIntervalBox.Text = s.ProbeIntervalSecs.ToString();
        ServiceBox.IsChecked = s.ServiceEnabled || ServiceManager.IsInstalled();
        AutoStartBox.IsChecked = s.AutoStart;
        AutoConnectBox.IsChecked = s.AutoConnect;
        StartMinBox.IsChecked = s.StartMinimized;

        // Each item carries the profile's stable Id in Tag; the visible label is DisplayName.
        // Two accounts on one server share a DisplayName but never an Id, so the saved
        // service/auto-connect selection resolves to the RIGHT one (see VpnConfig.Id).
        foreach (var p in profiles)
        {
            AutoProfileBox.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = p.DisplayName, Tag = p.Id });
            ServiceProfileBox.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = p.DisplayName, Tag = p.Id });
        }
        SelectProfile(AutoProfileBox, s.AutoConnectProfile);
        SelectProfile(ServiceProfileBox, s.ServiceProfile);

        UpdateAutoProfileEnabled();
        UpdateServiceProfileEnabled();
        UpdateProbeIntervalEnabled();
    }

    /// <summary>Returns true if the user saved changes.</summary>
    public static bool Show(Window owner, IReadOnlyList<VpnConfig> profiles)
    {
        var w = new SettingsWindow(owner, profiles);
        return w.ShowDialog() == true;
    }

    // Select the item whose Tag matches the saved profile Id. Fall back to matching the
    // saved string against the visible label — old settings stored a DisplayName, not an
    // Id; re-saving migrates the value to the Id.
    private static void SelectProfile(System.Windows.Controls.ComboBox box, string? saved)
    {
        foreach (var o in box.Items)
            if (o is System.Windows.Controls.ComboBoxItem i && ((i.Tag as string) == saved || (i.Content as string) == saved))
            { box.SelectedItem = i; return; }
        if (box.Items.Count > 0) box.SelectedIndex = 0;
    }

    private static void SelectByTag(System.Windows.Controls.ComboBox box, string? tag)
    {
        foreach (var o in box.Items)
            if (o is System.Windows.Controls.ComboBoxItem i && (i.Tag as string) == tag)
            { box.SelectedItem = i; return; }
        if (box.Items.Count > 0) box.SelectedIndex = 0;
    }

    private static string TagOf(System.Windows.Controls.ComboBox box) =>
        (box.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string ?? "en";

    private void OnAutoConnectChanged(object sender, RoutedEventArgs e) => UpdateAutoProfileEnabled();
    private void OnServiceChanged(object sender, RoutedEventArgs e) => UpdateServiceProfileEnabled();
    private void OnProbeChanged(object sender, RoutedEventArgs e) => UpdateProbeIntervalEnabled();

    private void UpdateProbeIntervalEnabled()
    {
        if (ProbeIntervalPanel == null) return;
        bool on = ProbeBox.IsChecked == true;
        ProbeIntervalPanel.IsEnabled = on;
        ProbeIntervalPanel.Opacity = on ? 1.0 : 0.45;
    }

    private void UpdateAutoProfileEnabled()
    {
        if (AutoProfilePanel == null) return;
        bool on = AutoConnectBox.IsChecked == true;
        AutoProfilePanel.IsEnabled = on;
        AutoProfilePanel.Opacity = on ? 1.0 : 0.45;
    }

    private void UpdateServiceProfileEnabled()
    {
        if (ServiceProfilePanel == null) return;
        bool on = ServiceBox.IsChecked == true;
        ServiceProfilePanel.IsEnabled = on;
        ServiceProfilePanel.Opacity = on ? 1.0 : 0.45;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var s = AppSettings.Current;
        s.Language = TagOf(LanguageBox);
        s.Theme = TagOf(ThemeBox);
        s.ToastsEnabled = ToastsBox.IsChecked == true;
        s.CheckForUpdates = UpdatesBox.IsChecked == true;
        s.ProbeReachability = ProbeBox.IsChecked == true;
        s.ProbeIntervalSecs = int.TryParse(ProbeIntervalBox.Text, out var iv) ? Math.Clamp(iv, 10, 3600) : 30;
        s.ServiceEnabled = ServiceBox.IsChecked == true;
        s.ServiceProfile = (ServiceProfileBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string;
        s.AutoStart = AutoStartBox.IsChecked == true;
        s.AutoConnect = AutoConnectBox.IsChecked == true;
        s.AutoConnectProfile = (AutoProfileBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string;
        s.StartMinimized = StartMinBox.IsChecked == true;
        s.Save();

        Loc.SetLanguage(s.Language);  // live switch (updates all {l:Loc} bindings)
        ThemeManager.Apply();         // live theme switch (updates DynamicResource brushes)
        Toast.Enabled = s.ToastsEnabled;

        try { AutoStartManager.Apply(s.AutoStart); }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("AutostartError", ex.Message),
                Loc.T("Settings"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        DialogResult = true;
    }
}
