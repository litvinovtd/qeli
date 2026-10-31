using System.Windows;
using QeliWin.Model;
using QeliWin.Service;
using Qeli.Shared;
using Qeli.Shared.Model;
using QeliWin.Vpn;

namespace QeliWin;

/// <summary>
/// Settings dialog: toasts, Windows-service mode (+ its profile), and GUI autostart/
/// auto-connect. Persists to <see cref="AppSettings"/>; the service install/uninstall
/// itself is applied by MainWindow after the dialog closes (it coordinates the tunnel).
/// </summary>
public partial class SettingsWindow : Window
{
    private readonly Func<bool> _canChangeAdapterMode;
    private readonly Func<AppSettings,Action?>? _stageAdapterMode;
    public SettingsWindow(Window owner, IReadOnlyList<VpnConfig> profiles,Func<bool>? canChangeAdapterMode=null,
        Func<AppSettings,Action?>? stageAdapterMode=null)
    {
        _canChangeAdapterMode=canChangeAdapterMode ?? (()=>true);
        _stageAdapterMode=stageAdapterMode;
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;
        WindowWorkArea.Attach(this);
        Loaded += (_, _) => FitToWorkArea();
        Closing += (_, e) => { if (_saving) e.Cancel = true; };

        var s = AppSettings.Current;
        SelectByTag(LanguageBox, s.Language);
        SelectByTag(ThemeBox, s.Theme);
        SelectByTag(LogTimeBox, s.LogTimeFormat);
        SelectByTag(LogLevelBox, s.LogLevel);
        SelectByTag(AdapterModeBox,AppSettings.Load().PersistentAdapterMode);
        AdapterModeBox.IsEnabled=_canChangeAdapterMode();
        ToastsBox.IsChecked = s.ToastsEnabled;
        UpdatesBox.IsChecked = s.CheckForUpdates;
        ProbeBox.IsChecked = s.ProbeReachability;
        ProbeIntervalBox.Text = s.ProbeIntervalSecs.ToString();
        // Installation only means the boot-time worker is available. It must not override
        // the user's explicit disabled setting and silently re-enable the connection.
        ServiceBox.IsChecked = s.ServiceEnabled;
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
    public static bool Show(Window owner, IReadOnlyList<VpnConfig> profiles,Func<bool>? canChangeAdapterMode=null,
        Func<AppSettings,Action?>? stageAdapterMode=null)
    {
        var w = new SettingsWindow(owner, profiles,canChangeAdapterMode,stageAdapterMode);
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

    private void FitToWorkArea()
    {
        var handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        var screen = System.Windows.Forms.Screen.FromHandle(handle);
        var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(this);
        double availableWidth = Math.Max(1, screen.WorkingArea.Width / dpi.DpiScaleX - 32);
        MinWidth = Math.Min(MinWidth, availableWidth);
        MaxWidth = availableWidth;
        Width = Math.Min(Width, availableWidth);
        double available = Math.Max(1, screen.WorkingArea.Height / dpi.DpiScaleY - 32);
        MinHeight = Math.Min(MinHeight, available);
        MaxHeight = available;
        Height = Math.Min(Height, available);
        WindowWorkArea.Clamp(this);
    }

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

    private bool _saving;
    private void OnCancel(object sender, RoutedEventArgs e) { if (!_saving) DialogResult = false; }

    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (_saving) return;
        _saving = true;
        var previous = AppSettings.Current;
        var s = previous.Snapshot();
        s.Language = TagOf(LanguageBox);
        s.Theme = TagOf(ThemeBox);
        // Not TagOf(): its no-selection fallback is the language default "en",
        // which would be a nonsense timestamp format.
        s.LogTimeFormat =
            (LogTimeBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string
            ?? Qeli.Shared.LogTime.Default;
        s.LogLevel =
            (LogLevelBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string
            ?? "info";
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
        s.PersistentAdapterMode=(AdapterModeBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string ?? WindowsAdapterPolicy.Off;
        try {
            if(Content is UIElement pendingControls) pendingControls.IsEnabled=false;
            await Task.Run(()=>WindowsAdapterPolicy.SaveMode(previous.PersistentAdapterMode,s.PersistentAdapterMode,
                ()=>Dispatcher.Invoke(s.Save),stage:()=>_stageAdapterMode?.Invoke(s),
                readCurrent:()=>AppSettings.Load().PersistentAdapterMode,
                requireIdle:()=> {if(!Dispatcher.Invoke(_canChangeAdapterMode)) throw new InvalidOperationException(Loc.T("PersistentAdapterStopFirst"));}));
        }
        catch (Exception error)
        {
            _saving = false;
            if(Content is UIElement retryControls) retryControls.IsEnabled=true;
            MessageBox.Show(this, error.Message, Loc.T("Settings"), MessageBoxButton.OK, MessageBoxImage.Error);
            return; // The live singleton and saved preferences are still the previous snapshot.
        }

        Loc.SetLanguage(s.Language);  // live switch (updates all {l:Loc} bindings)
        ThemeManager.Apply();         // live theme switch (updates DynamicResource brushes)
        Toast.Enabled = s.ToastsEnabled;

        if (Content is UIElement controls) controls.IsEnabled = false;
        try
        {
            // Retry desired state after an earlier failure; absent tasks are idempotent disables.
            await Task.Run(() => AutoStartManager.Apply(s.AutoStart));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("AutostartError", ex.Message),
                Loc.T("Settings"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        finally
        {
            _saving = false;
            if (Content is UIElement restoredControls) restoredControls.IsEnabled = true;
        }
        DialogResult = true;
    }
}
