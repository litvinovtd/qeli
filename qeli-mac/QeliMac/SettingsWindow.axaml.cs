using Avalonia.Controls;
using Avalonia.Interactivity;
using QeliMac.Model;
using Qeli.Shared;

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

    public SettingsWindow(Window owner, IReadOnlyList<string> profileNames) : this()
    {
        Icon = owner.Icon;

        var s = AppSettings.Current;
        SelectByTag(LanguageBox, s.Language);
        SelectByTag(ThemeBox, s.Theme);
        ToastsBox.IsChecked = s.ToastsEnabled;
        ServiceBox.IsChecked = s.ServiceEnabled || Service.ServiceManager.IsInstalled();
        AutoStartBox.IsChecked = s.AutoStart;
        AutoConnectBox.IsChecked = s.AutoConnect;
        StartMinBox.IsChecked = s.StartMinimized;

        foreach (var n in profileNames)
        {
            AutoProfileBox.Items.Add(n);
            ServiceProfileBox.Items.Add(n);
        }
        Select(AutoProfileBox, s.AutoConnectProfile);
        Select(ServiceProfileBox, s.ServiceProfile);

        UpdateAutoProfileEnabled();
        UpdateServiceProfileEnabled();
    }

    /// <summary>Returns true if the user saved changes.</summary>
    public static async Task<bool> ShowAsync(Window owner, IReadOnlyList<string> profileNames)
    {
        var w = new SettingsWindow(owner, profileNames);
        await w.ShowDialog(owner);
        return w._saved;
    }

    private static void Select(ComboBox box, string? value)
    {
        if (value != null && box.Items.Contains(value)) box.SelectedItem = value;
        else if (box.ItemCount > 0) box.SelectedIndex = 0;
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
        s.ServiceEnabled = ServiceBox.IsChecked == true;
        s.ServiceProfile = ServiceProfileBox.SelectedItem as string;
        s.AutoStart = AutoStartBox.IsChecked == true;
        s.AutoConnect = AutoConnectBox.IsChecked == true;
        s.AutoConnectProfile = AutoProfileBox.SelectedItem as string;
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
