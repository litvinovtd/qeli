using Avalonia.Controls;
using Avalonia.Interactivity;
using QeliMac.Model;
using Qeli.Shared;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>
/// Settings dialog: toasts, theme/language, launchd-daemon mode (+ its profile), and
/// login autostart / auto-connect. Persists to <see cref="AppSettings"/>; the daemon
/// install/uninstall itself is applied by MainWindow after the dialog closes.
/// Avalonia port of qeli-win's WPF SettingsWindow.
/// </summary>
public partial class SettingsWindow : Window
{
    private bool _saved;

    public SettingsWindow() => InitializeComponent();

    public SettingsWindow(Window owner, IReadOnlyList<VpnConfig> profiles) : this()
    {
        Icon = owner.Icon;

        var s = AppSettings.Current;
        SelectByTag(LanguageBox, s.Language);
        SelectByTag(ThemeBox, s.Theme);
        ToastsBox.IsChecked = s.ToastsEnabled;
        UpdatesBox.IsChecked = s.CheckForUpdates;
        ProbeBox.IsChecked = s.ProbeReachability;
        ServiceBox.IsChecked = s.ServiceEnabled || Service.ServiceManager.IsInstalled();
        AutoStartBox.IsChecked = s.AutoStart;
        AutoConnectBox.IsChecked = s.AutoConnect;
        StartMinBox.IsChecked = s.StartMinimized;

        // Each item carries the profile's stable Id in Tag; the visible label is DisplayName.
        // Two accounts on one server share a DisplayName but never an Id, so the saved
        // service/auto-connect selection resolves to the RIGHT one (see VpnConfig.Id).
        foreach (var p in profiles)
        {
            AutoProfileBox.Items.Add(new ComboBoxItem { Content = p.DisplayName, Tag = p.Id });
            ServiceProfileBox.Items.Add(new ComboBoxItem { Content = p.DisplayName, Tag = p.Id });
        }
        SelectProfile(AutoProfileBox, s.AutoConnectProfile);
        SelectProfile(ServiceProfileBox, s.ServiceProfile);

        UpdateAutoProfileEnabled();
        UpdateServiceProfileEnabled();
    }

    /// <summary>Returns true if the user saved changes.</summary>
    public static async Task<bool> ShowAsync(Window owner, IReadOnlyList<VpnConfig> profiles)
    {
        var w = new SettingsWindow(owner, profiles);
        await w.ShowDialog(owner);
        return w._saved;
    }

    // Select the item whose Tag matches the saved profile Id. Fall back to matching the
    // saved string against the visible label — old settings stored a DisplayName, not an
    // Id; re-saving migrates the value to the Id.
    private static void SelectProfile(ComboBox box, string? saved)
    {
        foreach (var o in box.Items)
            if (o is ComboBoxItem i && ((i.Tag as string) == saved || (i.Content as string) == saved))
            { box.SelectedItem = i; return; }
        if (box.ItemCount > 0) box.SelectedIndex = 0;
    }

    private static void SelectByTag(ComboBox box, string? tag)
    {
        foreach (var o in box.Items)
            if (o is ComboBoxItem i && (i.Tag as string) == tag) { box.SelectedItem = i; return; }
        if (box.ItemCount > 0) box.SelectedIndex = 0;
    }

    private static string TagOf(ComboBox box) =>
        (box.SelectedItem as ComboBoxItem)?.Tag as string ?? "en";

    private void OnAutoConnectChanged(object? sender, RoutedEventArgs e) => UpdateAutoProfileEnabled();
    private void OnServiceChanged(object? sender, RoutedEventArgs e) => UpdateServiceProfileEnabled();

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

    private void OnCancel(object? sender, RoutedEventArgs e) => Close();

    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        var s = AppSettings.Current;
        s.Language = TagOf(LanguageBox);
        s.Theme = TagOf(ThemeBox);
        s.ToastsEnabled = ToastsBox.IsChecked == true;
        s.CheckForUpdates = UpdatesBox.IsChecked == true;
        s.ProbeReachability = ProbeBox.IsChecked == true;
        s.ServiceEnabled = ServiceBox.IsChecked == true;
        s.ServiceProfile = (ServiceProfileBox.SelectedItem as ComboBoxItem)?.Tag as string;
        s.AutoStart = AutoStartBox.IsChecked == true;
        s.AutoConnect = AutoConnectBox.IsChecked == true;
        s.AutoConnectProfile = (AutoProfileBox.SelectedItem as ComboBoxItem)?.Tag as string;
        s.StartMinimized = StartMinBox.IsChecked == true;
        s.Save();

        Loc.SetLanguage(s.Language);  // live switch (updates all {l:Loc} bindings)
        ThemeManager.Apply();         // live theme switch (updates DynamicResource brushes)
        Toast.Enabled = s.ToastsEnabled;

        try { AutoStartManager.Apply(s.AutoStart); }
        catch (Exception ex)
        {
            await Dialogs.InfoAsync(this, Loc.F("AutostartError", ex.Message), Loc.T("Settings"));
        }

        _saved = true;
        Close();
    }
}
