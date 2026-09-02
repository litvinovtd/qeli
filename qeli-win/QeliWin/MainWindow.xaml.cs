using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using QeliWin.Model;
using QeliWin.Service;
using QeliWin.Vpn;
using Qeli.Shared;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliWin;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<VpnConfig> _profiles = new();
    private readonly VpnTunnel _tunnel = new();
    // The profile the tunnel is currently running (last passed to _tunnel.Start). Its
    // reconnect loop lives inside the tunnel, decoupled from the list — so deleting or
    // editing THIS profile must stop/restart the tunnel, or the old loop keeps hammering
    // the stale server IP after the config is gone/changed. Cleared when the tunnel stops.
    private VpnConfig? _activeProfile;
    // Per-profile log buffers (keyed by VpnConfig.Id). The tunnel runs ONE profile at a
    // time, so a log line belongs to the running profile (_activeProfile) — or, when idle,
    // to the selected one. Selecting a profile shows that profile's buffer (separate logs).
    private readonly Dictionary<string, StringBuilder> _logs = new();
    private const int MaxProfileLogChars = 256 * 1024;
    // Set while the app changes the profile selection/list programmatically (startup, edit,
    // import, delete), so the OnProfileSelected auto-restart fires ONLY for a genuine user
    // pick — not for a selection that shifts because the collection was mutated.
    private bool _suppressAutoSwitch;
    private VpnStatus _status = VpnStatus.Disconnected;
    private VpnStatus _prevStatus = VpnStatus.Disconnected;
    private string? _lastExtra;
    private TrayController? _tray;
    private bool _exiting;

    // Update check (opt-in; notification-only): once per app run, only while the tunnel is up.
    private bool _updateChecked;
    private string? _updateUrl;

    // Windows-service mode: the VPN runs in the service; the GUI polls its status/log.
    private bool _serviceMode;
    private DispatcherTimer? _serviceTimer;
    private long _serviceLogPos;

    // Live stats (sampled once a second while connected): speed tiles + sparkline.
    private DispatcherTimer? _statsTimer;
    private long _prevUp, _prevDown, _prevStatsTick;
    private ServiceStatus? _svc;                      // last service snapshot (service mode)
    private ICollectionView? _view;                   // profiles view (for search filtering)

    // Connecting spinner (rotating gradient arc on the status dot).
    private readonly DoubleAnimation _spinAnim =
        new(0, 360, new Duration(TimeSpan.FromSeconds(0.9))) { RepeatBehavior = RepeatBehavior.Forever };

    public MainWindow()
    {
        InitializeComponent();
        _tunnel.LogLevel = AppSettings.Current.LogLevel;
        ProfilesList.ItemsSource = _profiles;

        Icon = Ui.Png(Branding.AppIconPng(64));
        LogoImage.Source = Ui.Png(Branding.LogoPng(64));
        VersionText.Text = $"v{AboutWindow.AppVersion()}";

        // Gradient stroke for the connecting spinner — amber (the StatusConnecting
        // colour), so "connecting / reconnecting / TUN-not-up-yet" reads as a distinct
        // YELLOW light (like OpenVPN / TunSafe), not the blue accent (issue #69).
        var a = Color.FromRgb(0xF0, 0xA9, 0x11);
        StatusSpinner.Stroke = new LinearGradientBrush(
            new GradientStopCollection
            {
                new(a, 0.0),
                new(Color.FromArgb(25, a.R, a.G, a.B), 1.0),
            },
            new Point(0, 0), new Point(1, 1));

        foreach (var p in ProfileStore.Load()) _profiles.Add(p);
        _view = CollectionViewSource.GetDefaultView(_profiles);
        _view.Filter = FilterProfile;
        if (_profiles.Count > 0) Programmatic(() => ProfilesList.SelectedIndex = 0);
        UpdateEmptyHint();
        ApplyTileLabels();
        CheckReachabilityAll();
        ConfigureProbeTimer(); // start auto-poll (no-op when auto is off)

        _tunnel.LogLine += OnLog;
        _tunnel.StatusChanged += OnStatus;
        _tunnel.RunCompleted += OnTunnelRunCompleted;
        _tunnel.ConnectionDropped += _ =>
            Dispatcher.Invoke(() => Toast.Show(ToastKind.Error, Loc.T("ToastConnLost"), Loc.T("Reconnecting")));

        // Proactively cycle the tunnel on resume-from-sleep and on a network change,
        // instead of waiting out the RX-liveness watchdog. ForceReconnect no-ops unless a
        // tunnel is up and is debounced, so idle/duplicate events are harmless. Resume waits
        // for the physical network to come back first (see ForceReconnectWhenNetworkReady).
        Microsoft.Win32.SystemEvents.PowerModeChanged += (_, e) =>
        { if (e.Mode == Microsoft.Win32.PowerModes.Resume) _tunnel.ForceReconnectWhenNetworkReady("Resumed from sleep"); };
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) =>
            _tunnel.OnNetworkChanged();

        _tray = new TrayController(
            getProfiles: () => _profiles.ToList(),
            getActive: () => Selected,
            onSelectProfile: p => Dispatcher.Invoke(() => SelectProfileFromTray(p)),
            onToggleConnect: () => Dispatcher.Invoke(ToggleConnection),
            onShowWindow: () => Dispatcher.Invoke(ShowFromTray),
            onSettings: () => Dispatcher.Invoke(() => _ = OpenSettings()),
            onExit: () => Dispatcher.Invoke(ExitApp),
            getStatus: () => _status);

        Toast.Enabled = AppSettings.Current.ToastsEnabled;

        Closing += OnWindowClosing;
        // Log off / shut down / restart: the OS ends the session and `Closing` is NOT a
        // reliable teardown hook there. It runs with `_exiting == false`, takes the tray
        // branch, sets `e.Cancel = true` (which the shutdown path ignores) and returns —
        // so the process died with the Wintun adapter up, the 0.0.0.0/1 + 128.0.0.0/1
        // routes installed, DNS overridden and, with kill_switch on, egress still blocked.
        // The next boot then started on a machine whose networking qeli had configured and
        // never restored. `SessionEnding` is the event that actually fires here.
        // (Audit 2026-07-27, Z3.)
        if (Application.Current is { } app) app.SessionEnding += OnSessionEnding;
        StateChanged += (_, _) => { if (WindowState == WindowState.Minimized) Hide(); };

        RefreshServiceMode();
        RenderStatus(_status, _lastExtra); // localized initial status
    }

    private VpnConfig? Selected => ProfilesList.SelectedItem as VpnConfig;

    private Brush B(string key) => (Brush)(TryFindResource(key) ?? Brushes.Gray);

    private void StartSpinner()
    {
        StatusDot.Visibility = Visibility.Collapsed;
        StatusSpinner.Visibility = Visibility.Visible;
        SpinnerRotate.BeginAnimation(RotateTransform.AngleProperty, _spinAnim);
    }

    private void StopSpinner()
    {
        SpinnerRotate.BeginAnimation(RotateTransform.AngleProperty, null);
        StatusSpinner.Visibility = Visibility.Collapsed;
        StatusDot.Visibility = Visibility.Visible;
    }

    private void UpdateEmptyHint() =>
        EmptyHint.Visibility = _profiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    // ── window / tray plumbing ──────────────────────────────────────────────────
    private void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (_exiting)
        {
            // ExitApp owns the teardown and has already awaited it OFF the UI thread; this
            // handler runs on the UI thread, so a Stop() here would just re-introduce the
            // Dispatcher deadlock it fixed (Stop joins the tunnel task, whose status callback
            // needs this very thread). Only tray cleanup is left. (Audit 2026-07-27, N4)
            _tray?.Dispose();
            return;
        }
        e.Cancel = true;
        Hide();
        _tray?.ShowBalloon("Qeli", Loc.T("TrayBalloon"));
    }

    /// <summary>
    /// Tear the tunnel down when the OS ends the session (logoff / shutdown / restart).
    /// </summary>
    /// <remarks>
    /// Synchronous ON PURPOSE, unlike <see cref="ExitApp"/>: Windows gives a session-ending
    /// app a limited window and then kills it, so deferring to a continuation would lose the
    /// race. The teardown runs on a worker thread with a bounded wait — `Stop()` joins the
    /// tunnel task, whose status callback marshals to THIS thread, so calling it inline
    /// would deadlock exactly as it did in the exit path (N4). `_exiting` is set first so
    /// the `Closing` handler that follows takes the already-torn-down branch instead of
    /// cancelling the close. (Audit 2026-07-27, Z3.)
    /// </remarks>
    private void OnSessionEnding(object sender, SessionEndingCancelEventArgs e)
    {
        if (_exiting) return;
        _exiting = true;
        try
        {
            // Bounded: never hold up a shutdown longer than the teardown legitimately needs.
            Task.Run(() => { try { _tunnel.Stop(); } catch { } }).Wait(TimeSpan.FromSeconds(10));
        }
        catch { /* shutting down anyway — nothing useful to report */ }
        _tray?.Dispose();
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true; Topmost = false;
        CheckReachabilityAll();
    }

    private void OnAbout(object sender, RoutedEventArgs e) => new AboutWindow(this).ShowDialog();

    private async void OnSettings(object sender, RoutedEventArgs e) => await OpenSettings();

    private async Task OpenSettings()
    {
        bool saved = SettingsWindow.Show(this, _profiles);
        if (saved)
        {
            _tunnel.LogLevel = AppSettings.Current.LogLevel;
            await ApplyServiceSettings();
            ReapplyLanguage(); // language may have changed (live)
            ConfigureProbeTimer(); // auto-poll toggle / interval may have changed
        }
    }

    /// <summary>Resolve a saved profile reference (service / auto-connect) to a live profile.
    /// New settings store the stable <see cref="VpnConfig.Id"/>; older ones stored a
    /// DisplayName — which collides across accounts on one server and silently picked the
    /// wrong one. Match by Id first, then fall back to the legacy string forms so an upgrade
    /// keeps working until the user re-saves Settings (which rewrites it as an Id).</summary>
    private VpnConfig? ResolveProfile(string? saved)
    {
        if (string.IsNullOrEmpty(saved)) return null;
        return _profiles.FirstOrDefault(x => x.Id == saved)
            ?? _profiles.FirstOrDefault(x => x.DisplayName == saved)
            ?? _profiles.FirstOrDefault(x => x.ServerAddress == saved)
            ?? _profiles.FirstOrDefault(x => x.Name == saved);
    }

    /// <summary>Called by App at launch: auto-connect to the configured profile if enabled.</summary>
    public async void RunStartupActions()
    {
        if (_serviceMode) return; // the service owns the VPN
        var s = AppSettings.Current;
        if (!s.AutoConnect) return;
        var p = ResolveProfile(s.AutoConnectProfile) ?? Selected ?? _profiles.FirstOrDefault();
        if (p == null) return;
        Programmatic(() => ProfilesList.SelectedItem = p);
        ClearLog(p);
        await StartTunnel(p);
    }

    // ── Windows-service mode ─────────────────────────────────────────────────────
    private void RefreshServiceMode()
    {
        bool nowService = ServiceManager.IsInstalled();
        _serviceMode = nowService;
        if (nowService)
        {
            ConnectBtn.IsEnabled = true;
            _serviceLogPos = 0;
            LogBox.Clear();
            StartServicePolling();
            ServicePollTick(null, EventArgs.Empty);
        }
        else
        {
            StopServicePolling();
        }
    }

    private void StartServicePolling()
    {
        if (_serviceTimer != null) return;
        _serviceTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _serviceTimer.Tick += ServicePollTick;
        _serviceTimer.Start();
    }

    private void StopServicePolling()
    {
        if (_serviceTimer == null) return;
        _serviceTimer.Stop();
        _serviceTimer.Tick -= ServicePollTick;
        _serviceTimer = null;
    }

    private void ServicePollTick(object? sender, EventArgs e)
    {
        if (!_serviceMode) return;
        var snapshot = ServiceState.ReadStatus();
        _svc = snapshot;
        VpnStatus status = VpnStatus.Disconnected;
        string? extra = snapshot?.Extra;
        if (snapshot != null && Enum.TryParse<VpnStatus>(snapshot.Status, out var parsed)) status = parsed;
        if (!ServiceManager.IsRunning()) { status = VpnStatus.Disconnected; extra = null; }

        if (status != _status) OnStatus(status, extra);
        TailServiceLog();
    }

    private void TailServiceLog()
    {
        try
        {
            var path = ServiceState.LogFile;
            if (!File.Exists(path)) return;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < _serviceLogPos) _serviceLogPos = 0; // log was rotated
            if (fs.Length == _serviceLogPos) return;
            fs.Seek(_serviceLogPos, SeekOrigin.Begin);
            using var sr = new StreamReader(fs);
            var text = sr.ReadToEnd();
            _serviceLogPos = fs.Length;
            if (text.Length > 0) { LogBox.AppendText(text); LogBox.ScrollToEnd(); }
        }
        catch { /* ignore transient IO */ }
    }

    private async Task ApplyServiceSettings()
    {
        var s = AppSettings.Current;
        try
        {
            if (s.ServiceEnabled)
            {
                var p = ResolveProfile(s.ServiceProfile) ?? _profiles.FirstOrDefault();
                if (p == null)
                {
                    MessageBox.Show(this, Loc.T("NoServiceProfile"), Loc.T("ServiceWord"),
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                // Avoid two tunnels fighting over the Wintun adapter.
                if (_status is VpnStatus.Connected or VpnStatus.Connecting)
                    await Task.Run(_tunnel.Stop);
                p.LoggingLevel = s.LogLevel;
                ServiceState.SaveProfile(p);
                if (!ServiceManager.IsInstalled()) ServiceManager.Install();
                ServiceManager.Start();
            }
            else if (ServiceManager.IsInstalled())
            {
                ServiceManager.Uninstall();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("ServiceApplyError", ex.Message),
                Loc.T("ServiceWord"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        RefreshServiceMode();
    }

    private void ToggleService()
    {
        try
        {
            // The auto-started service may be running but intentionally idle. Toggle the
            // persisted connection intent, not the SCM process state.
            if (ServiceState.DesiredConnected()) ServiceManager.Stop();
            else ServiceManager.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("ServiceControlError", ex.Message),
                Loc.T("ServiceWord"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        ServicePollTick(null, EventArgs.Empty);
    }

    /// <summary>Quit: tear the tunnel down, then shut the app down.
    ///
    /// Asynchronous on purpose. Stop() blocks up to ~8 s joining the tunnel task, and that
    /// task reports its final status through StatusChanged, which marshals back with
    /// Dispatcher.Invoke — so calling Stop() straight from the UI thread deadlocked the two
    /// against each other: the window froze for the whole join timeout on every quit, and the
    /// teardown that timed out left the adapter, routes and DNS behind. Run it off the UI
    /// thread (exactly what ToggleConnection already does) and only shut down once it has
    /// actually finished. (Audit 2026-07-27, N4)</summary>
    private async void ExitApp()
    {
        if (_exiting) return;   // a second Exit while the first teardown is still running
        _exiting = true;
        try
        {
            await Task.Run(_tunnel.Stop);
        }
        catch (Exception error)
        {
            _exiting = false;
            MessageBox.Show(this, error.Message, "Qeli",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        _tray?.Dispose();
        Application.Current.Shutdown();
    }

    private void SelectProfileFromTray(VpnConfig p)
    {
        // Setting the selection routes through OnProfileSelected, which — if a tunnel is
        // running on a different profile — restarts it on `p` and clears the log. Single
        // code path with the in-window list pick, so both behave identically.
        ProfilesList.SelectedItem = p;
    }

    // ── tunnel events (marshalled to UI thread) ─────────────────────────────────
    // ── per-profile log ─────────────────────────────────────────────────────────
    private static string LogKey(VpnConfig? p) => p?.Id ?? "";

    private StringBuilder LogBuf(string id)
    {
        if (!_logs.TryGetValue(id, out var sb)) { sb = new StringBuilder(); _logs[id] = sb; }
        return sb;
    }

    /// <summary>Show the selected profile's accumulated log in the box.</summary>
    private void RenderLog(VpnConfig? p)
    {
        LogBox.Text = _logs.TryGetValue(LogKey(p), out var sb) ? sb.ToString() : "";
        LogBox.ScrollToEnd();
    }

    /// <summary>Wipe one profile's log (a fresh connect starts a clean session log).</summary>
    private void ClearLog(VpnConfig? p)
    {
        _logs.Remove(LogKey(p));
        if (LogKey(Selected) == LogKey(p)) LogBox.Clear();
    }

    private void OnLog(string line) =>
        // Logging must never block network setup. Large route_file imports used to perform
        // one synchronous UI round-trip per route, freezing both Connect and Disconnect.
        Dispatcher.BeginInvoke(() =>
        {
            // A line belongs to the RUNNING profile (its reconnect loop is what emits them);
            // when nothing is running it belongs to the selected profile. The stamp shape
            // follows Settings → Log timestamp (default: local date+time+ms, because the
            // old ISO-8601 UTC stamp confused users whose clock differs from Z); it is read
            // per line, so a change applies to new lines without a restart.
            var id = LogKey(_activeProfile ?? Selected);
            var entry = $"{Qeli.Shared.LogTime.Prefix(AppSettings.Current.LogTimeFormat)}{line}\n";
            var buf = LogBuf(id);
            buf.Append(entry);
            bool trimmed = false;
            if (buf.Length > MaxProfileLogChars)
            {
                var s = buf.ToString();
                int cut = s.IndexOf('\n', s.Length - MaxProfileLogChars);
                if (cut >= 0) { buf.Clear(); buf.Append(s, cut + 1, s.Length - cut - 1); trimmed = true; }
            }
            if (LogKey(Selected) == id)   // only touch the box if the user is viewing this profile
            {
                if (trimmed) LogBox.Text = buf.ToString();
                else LogBox.AppendText(entry);
                LogBox.ScrollToEnd();
            }
        });

    private void OnStatus(VpnStatus status, string? extra) =>
        Dispatcher.Invoke(() =>
        {
            RenderStatus(status, extra);
            switch (status)
            {
                case VpnStatus.Connected:
                    Toast.Show(ToastKind.Success, Loc.T("ToastConnected"),
                        $"{Selected?.DisplayName}{(string.IsNullOrEmpty(extra) ? "" : $" · {extra}")}");
                    _ = MaybeCheckForUpdatesAsync();
                    break;
                case VpnStatus.Error:
                    Toast.Show(ToastKind.Error, Loc.T("ToastConnError"), extra ?? "");
                    break;
                case VpnStatus.Disconnected:
                    if (_prevStatus is VpnStatus.Connected or VpnStatus.Connecting)
                        Toast.Show(ToastKind.Info, Loc.T("ToastDisconnected"), Selected?.DisplayName ?? "");
                    if (!_tunnel.IsRunning)
                    {
                        _activeProfile = null; // tunnel is down → no profile is running
                        CheckReachabilityAll();
                    }
                    break;
            }
            _prevStatus = status;
        });

    private void OnTunnelRunCompleted() =>
        Dispatcher.BeginInvoke(new Action(() =>
        {
            // The Error event is emitted from inside the run task, where IsRunning is
            // necessarily still true and the button correctly offers Disconnect. Re-render
            // once task completion is observable, otherwise a terminal failure leaves a
            // dead "Disconnect" button and a stale active-profile lock indefinitely.
            if (_status != VpnStatus.Error || _tunnel.IsRunning) return;
            _activeProfile = null;
            RenderStatus(_status, _lastExtra);
            CheckReachabilityAll();
        }));

    /// <summary>True while the data-plane tunnel is up. Gates the update check so its request
    /// only ever travels inside the tunnel (hides the real IP + the "runs qeli" fingerprint).</summary>
    public bool IsTunnelUp => _status == VpnStatus.Connected;

    /// <summary>Opt-in, notification-only update check. Runs once per app session, only while the
    /// tunnel is up, and fails soft (any error → nothing shown).</summary>
    private async Task MaybeCheckForUpdatesAsync()
    {
        if (!AppSettings.Current.CheckForUpdates || _updateChecked) return;
        _updateChecked = true;
        if (_status != VpnStatus.Connected) return; // privacy: only through the tunnel
        var info = await UpdateChecker.CheckAsync(AboutWindow.AppVersion());
        if (info is { IsNewer: true })
            Dispatcher.Invoke(() => ShowUpdateAvailable(info));
    }

    /// <summary>Reveal the dismissible "update available" link in the log header. Public so the
    /// manual check in <see cref="AboutWindow"/> can light it up too.</summary>
    public void ShowUpdateAvailable(UpdateInfo info)
    {
        _updateUrl = info.ReleaseUrl;
        UpdateText.Text = Loc.F("UpdateAvailable", info.LatestVersion);
        UpdateText.Visibility = Visibility.Visible;
    }

    private void OnUpdateClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!string.IsNullOrEmpty(_updateUrl)) OpenUrl(_updateUrl);
    }

    /// <summary>Open a URL in the default browser (the release page). Fail-soft.</summary>
    public static void OpenUrl(string url)
    {
        try
        {
            using var _ = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { /* no browser / bad url — ignore */ }
    }

    /// <summary>
    /// True while a tunnel is up, so the profile list can grey out every row except the
    /// running one — the visual half of "can't switch profiles while connected". The
    /// functional half is the refusal in <see cref="OnProfileSelected"/>; this just makes
    /// it obvious before the click. Bound from the ProfileItem template in XAML.
    /// </summary>
    public static readonly DependencyProperty SwitchLockedProperty =
        DependencyProperty.Register(nameof(SwitchLocked), typeof(bool), typeof(MainWindow),
            new PropertyMetadata(false));

    public bool SwitchLocked
    {
        get => (bool)GetValue(SwitchLockedProperty);
        set => SetValue(SwitchLockedProperty, value);
    }

    /// <summary>Update the status visuals (no toasts). Re-runnable for live language switch.</summary>
    private void RenderStatus(VpnStatus status, string? extra)
    {
        _status = status;
        if (status is VpnStatus.Connected or VpnStatus.Connecting)
            _profileReachabilityGeneration.Clear();
        _lastExtra = extra;
        _tray?.Update(status, extra);
        // Connecting counts as locked too: the tunnel is already bound to a profile and
        // switching mid-connect would tear it down just the same.
        SwitchLocked = status is VpnStatus.Connected or VpnStatus.Connecting;

        // Live speed readout is only meaningful while connected.
        StopStatsTimer();

        switch (status)
        {
            case VpnStatus.Connecting:
                StartSpinner();
                StatusText.Text = Loc.T("StatusConnecting");
                StatusText.Foreground = B("Fg");
                DetailText.Text = Selected?.Endpoint ?? "";
                ConnectBtn.Content = Loc.T("Disconnect");
                break;

            case VpnStatus.Connected:
                StopSpinner();
                StatusDot.Fill = B("StatusConnected");
                StatusText.Text = Loc.T("StatusConnected");
                StatusText.Foreground = B("Fg");
                ConnectBtn.Content = Loc.T("Disconnect");
                StartStatsTimer();
                break;

            case VpnStatus.Error:
                StopSpinner();
                StatusDot.Fill = B("StatusError");
                StatusText.Text = Loc.T("StatusError");
                StatusText.Foreground = B("Danger");
                if (!string.IsNullOrEmpty(extra)) DetailText.Text = extra;
                ConnectBtn.Content = _tunnel.IsRunning ? Loc.T("Disconnect") : Loc.T("Connect");
                break;

            default: // Disconnected
                StopSpinner();
                StatusDot.Fill = B("StatusDisconnected");
                StatusText.Text = Loc.T("StatusDisconnected");
                StatusText.Foreground = B("Fg");
                DetailText.Text = Selected?.Endpoint ?? Loc.T("SelectProfile");
                ConnectBtn.Content = Loc.T("Connect");
                break;
        }
    }

    private void ReapplyLanguage()
    {
        ApplyTileLabels();
        RenderStatus(_status, _lastExtra);
    }

    private void ApplyTileLabels()
    {
        DownLabel.Text = "↓ " + Loc.T("StatDownload");
        UpLabel.Text = "↑ " + Loc.T("StatUpload");
        SessionLabel.Text = "⏱ " + Loc.T("StatSession");
        IpLabel.Text = Loc.T("StatTunnelIp");
    }

    // ── search filter ────────────────────────────────────────────────────────────
    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        // Placeholder visibility is handled by a pure-XAML trigger on SearchPlaceholder.
        ClearSearchBtn.Visibility = string.IsNullOrEmpty(SearchBox.Text)
            ? Visibility.Collapsed : Visibility.Visible;
        _view?.Refresh();
    }

    private void OnClearSearch(object sender, RoutedEventArgs e)
    {
        SearchBox.Clear();
        SearchBox.Focus();
    }

    // Log toolbar actions (the log now fills the right column and is always open).
    private void OnCopyLog(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(LogBox.Text))
            try { Clipboard.SetText(LogBox.Text); } catch { /* clipboard busy */ }
    }

    private void OnClearLog(object sender, RoutedEventArgs e)
    {
        if (_serviceMode) { LogBox.Clear(); return; }   // service log: single buffer
        ClearLog(Selected);
    }

    private bool FilterProfile(object o)
    {
        if (o is not VpnConfig c) return false;
        var q = SearchBox?.Text?.Trim();
        if (string.IsNullOrEmpty(q)) return true;
        return c.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || c.Endpoint.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    // ── profile UI ──────────────────────────────────────────────────────────────

    /// <summary>Run a selection/list mutation with the auto-switch restart suppressed, so
    /// programmatic selection changes (startup, edit, import, delete) don't restart the
    /// tunnel — only a genuine user pick in <see cref="OnProfileSelected"/> does.</summary>
    private void Programmatic(Action mutate)
    {
        bool prev = _suppressAutoSwitch;
        _suppressAutoSwitch = true;
        try { mutate(); } finally { _suppressAutoSwitch = prev; }
    }

    private async void OnProfileSelected(object sender, SelectionChangedEventArgs e)
    {
        var p = Selected;
        ConnectBtn.IsEnabled = _serviceMode || p != null;
        if (p == null) return;

        // Connected/Connecting: switching profiles is REFUSED — it used to silently tear the
        // live tunnel down and restart it on the newly picked profile. Checked FIRST, before
        // the log is re-rendered below, so a refused pick doesn't even swap the log view.
        //
        // Gate on _status, NOT _activeProfile: on a stable connection _activeProfile is set,
        // but it is null in service mode and after a transient reconnect, and the earlier
        // version keyed off it and so let the switch through. Revert to the row that WAS
        // selected (e.RemovedItems) — that is the running profile while connected — and do it
        // deferred via the dispatcher: setting SelectedItem synchronously inside a
        // SelectionChanged handler is not reliably honored by WPF (the reason the previous
        // revert didn't stick and the selection visibly moved). Per-row actions (Edit /
        // Duplicate / Share / Delete) are unaffected — they come off the kebab's DataContext.
        if (!_suppressAutoSwitch && !_serviceMode
            && _status is VpnStatus.Connected or VpnStatus.Connecting
            && e.RemovedItems.Count > 0 && e.RemovedItems[0] is VpnConfig prev
            && !ReferenceEquals(prev, p) && prev.Id != p.Id)
        {
            _ = Dispatcher.BeginInvoke(new Action(() =>
                Programmatic(() => ProfilesList.SelectedItem = prev)));
            Toast.Show(ToastKind.Info, Loc.T("SwitchBlocked"), Loc.T("SwitchBlockedMsg"));
            return;
        }

        // Show THIS profile's log (separate per-profile buffers). In service mode the box
        // holds the daemon's single log, so leave it be.
        if (!_serviceMode) RenderLog(p);
        // Disconnected: just reflect the endpoint (the status text is owned by OnStatus
        // once a tunnel is up, so don't clobber it here).
        if (_status is VpnStatus.Disconnected) { DetailText.Text = p.Endpoint; return; }
        // Skipped for programmatic selection changes, service mode (the Windows service owns
        // the tunnel), and re-selecting the profile that is already running.
        if (_suppressAutoSwitch || _serviceMode || _activeProfile == null) return;
        if (ReferenceEquals(_activeProfile, p) || _activeProfile.Id == p.Id) return;
        // Error: the tunnel is down but its reconnect loop may still be alive, and picking
        // another profile is a normal way to recover — keep the restart-on-switch behavior.
        ClearLog(p);
        // Restart off the UI thread: Start()->Stop() now fully joins the previous attempt
        // (a full-tunnel teardown can take a few seconds), so run it async to avoid freezing
        // the UI and to serialize with any in-flight switch (VpnTunnelBase._lifecycleLock).
        await StartTunnel(p);
    }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        var text = InputDialog.Show(this, Loc.T("ImportTitle"), Loc.T("ImportPrompt"), "", multiline: true);
        if (string.IsNullOrWhiteSpace(text)) return;
        try
        {
            var cfg = VpnConfig.Parse(text.Trim());
            // IMPORT boundary: run the semantic checks that `FromIni` deliberately
            // skips (it stays lenient so the editor can open a broken profile). A
            // pasted profile is exactly as untrusted as a scanned link — without this,
            // a config Android and iOS reject imported cleanly here.
            // (Audit 2026-08-04, H-07.)
            cfg.Validate(platformCapabilities: false);
            cfg.Name ??= cfg.ServerAddress;
            _profiles.Add(cfg);
            PersistAndSelect(cfg);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("ImportError", ex.Message), Loc.T("ImportTitle"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnNew(object sender, RoutedEventArgs e)
    {
        var cfg = ConfigEditorWindow.Show(this, null);
        if (cfg == null) return;
        _profiles.Add(cfg);
        PersistAndSelect(cfg);
    }

    // Per-card "⋯" menu: Edit / Duplicate / Share-QR / Delete.
    private void OnKebab(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.ContextMenu is { } cm)
        {
            cm.PlacementTarget = b;
            cm.DataContext = b.DataContext; // flow the VpnConfig to the menu items
            cm.IsOpen = true;
        }
    }

    private static VpnConfig? Ctx(object sender) => (sender as FrameworkElement)?.DataContext as VpnConfig;
    private void OnMenuEdit(object sender, RoutedEventArgs e) { if (Ctx(sender) is { } p) EditProfile(p); }
    private void OnMenuDelete(object sender, RoutedEventArgs e) { if (Ctx(sender) is { } p) DeleteProfile(p); }
    private void OnMenuShare(object sender, RoutedEventArgs e) { if (Ctx(sender) is { } p) QrShareWindow.Show(this, p); }

    private void OnMenuDuplicate(object sender, RoutedEventArgs e)
    {
        if (Ctx(sender) is not { } p) return;
        var copy = p.Clone();
        copy.Name = p.DisplayName + Loc.T("CopySuffix");
        _profiles.Add(copy);
        PersistAndSelect(copy);
    }

    /// <summary>True when <paramref name="p"/> is the profile the tunnel is currently
    /// running (matched by stable Id, since editing replaces the object). Used so a
    /// delete/edit of the live profile stops/restarts the tunnel instead of leaving its
    /// reconnect loop hammering the now-stale server IP.</summary>
    private bool IsRunning(VpnConfig p) =>
        _activeProfile != null &&
        _tunnel.IsRunning &&
        (ReferenceEquals(_activeProfile, p) || _activeProfile.Id == p.Id);

    private async Task<bool> StartTunnel(VpnConfig profile)
    {
        bool started = await Task.Run(() => _tunnel.Start(profile));
        if (started)
        {
            _activeProfile = profile;
        }
        else if (!_tunnel.IsRunning)
        {
            _activeProfile = null;
        }
        return started;
    }

    private async void EditProfile(VpnConfig p)
    {
        var edited = ConfigEditorWindow.Show(this, p);
        if (edited == null) return;
        bool wasRunning = IsRunning(p);
        int idx = _profiles.IndexOf(p);
        if (wasRunning && !_serviceMode)
        {
            try
            {
                await Task.Run(_tunnel.Stop);
                _activeProfile = null;
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Qeli",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }
        // Replacing the item + reselecting it both raise SelectionChanged; suppress the
        // auto-switch so it doesn't restart the tunnel here — the wasRunning branch below
        // owns the restart (and only when the LIVE profile was the one edited).
        Programmatic(() =>
        {
            _profiles[idx] = edited;
            ProfilesList.SelectedItem = edited;
        });
        ProfileStore.Save(_profiles);
        CheckReachability(edited);
        // If we just edited the live profile (e.g. changed the server IP), the running
        // tunnel is still on the OLD config — restart it on the edited one so the change
        // takes effect instead of the reconnect loop retrying the stale endpoint.
        if (wasRunning && !_serviceMode)
        {
            ClearLog(edited);
            await StartTunnel(edited);
        }
    }

    private async void DeleteProfile(VpnConfig p)
    {
        if (MessageBox.Show(this, Loc.F("DeleteConfirm", p.DisplayName), Loc.T("DeleteTitle"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        // Tear down the tunnel FIRST if we're deleting the profile it's running on —
        // otherwise its reconnect loop (owned by the tunnel, not the list) keeps trying
        // the deleted server's IP long after the profile is gone.
        if (IsRunning(p) && !_serviceMode)
        {
            try { await Task.Run(_tunnel.Stop); }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Qeli",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            _activeProfile = null;
        }
        // Removing the selected item shifts the selection → SelectionChanged; suppress so a
        // delete of a NON-running profile while connected doesn't restart onto whatever
        // becomes selected. The running-profile case is handled above.
        Programmatic(() => _profiles.Remove(p));
        ProfileStore.Save(_profiles);
        UpdateEmptyHint();
    }

    // ── server reachability probe ────────────────────────────────────────────────
    private const int MinimumProbeIntervalSeconds = 10;
    private static readonly TimeSpan ReachabilitySweepCooldown =
        TimeSpan.FromSeconds(MinimumProbeIntervalSeconds);
    private DateTime _lastReachAll = DateTime.MinValue;
    private bool _reachPending;
    private DispatcherTimer? _probeTimer;
    private long _nextReachabilityGeneration;
    private readonly Dictionary<VpnConfig, long> _profileReachabilityGeneration = new();

    /// <summary>(Re)configure the auto-poll timer from settings. Auto off → no timer
    /// (reachability is then updated only by the manual "check" button / dot click).</summary>
    private void ConfigureProbeTimer()
    {
        _probeTimer ??= new DispatcherTimer();
        _probeTimer.Stop();
        _probeTimer.Tick -= OnProbeTick;
        var s = AppSettings.Current;
        if (!s.ProbeReachability) return;
        _probeTimer.Interval = TimeSpan.FromSeconds(
            Math.Clamp(s.ProbeIntervalSecs, MinimumProbeIntervalSeconds, 3600));
        _probeTimer.Tick += OnProbeTick;
        _probeTimer.Start();
    }
    private void OnProbeTick(object? sender, EventArgs e) => CheckReachabilityAll();

    // Manual reachability checks (work even when auto-poll is off): the header refresh
    // button probes every profile; clicking a profile's status dot re-probes just it.
    private void OnProbeAll(object sender, RoutedEventArgs e) => CheckReachabilityAll(manual: true);
    private void OnProbeOne(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if ((sender as System.Windows.FrameworkElement)?.DataContext is VpnConfig p)
            CheckReachability(p, manual: true);
    }

    // manual=true: an explicit user action — probe even when auto-poll is off, and bypass
    // the debounce. Both paths still skip while the tunnel is up (the result would be moot).
    private async void CheckReachabilityAll(bool manual = false)
    {
        // Auto-poll off: don't auto-probe, and DON'T wipe the dots — a manual "check" result
        // must survive, and connecting fires an internal Disconnected → this method, which
        // otherwise reset every dot to grey. Dots default to Unknown (grey) until a manual
        // check; the distinctive hybrid-PQ ClientHello per profile is opt-in via that action.
        if (!manual && !AppSettings.Current.ProbeReachability) return;
        // Skip while the tunnel is up — traffic would route oddly and the result is moot.
        if (_status is VpnStatus.Connected or VpnStatus.Connecting) return;
        if (!manual)
        {
            // Debounce auto/event sweeps: each opens one connection PER profile; firing on
            // every disconnect / churn floods the server's per-IP new-session rate limit
            // (dots go falsely red AND a real connect right after is throttled). Cap to one
            // sweep per minimum configured interval; a call inside the cooldown is coalesced.
            var since = DateTime.UtcNow - _lastReachAll;
            if (since < ReachabilitySweepCooldown)
            {
                if (_reachPending) return;
                _reachPending = true;
                try { await Task.Delay(ReachabilitySweepCooldown - since); }
                finally { _reachPending = false; }
                if (!AppSettings.Current.ProbeReachability
                    || _status is VpnStatus.Connected or VpnStatus.Connecting) return;
            }
        }
        _lastReachAll = DateTime.UtcNow;
        foreach (var p in _profiles.ToList()) CheckReachability(p, manual);
    }

    private void CheckReachability(VpnConfig p, bool manual = false)
    {
        // Auto-poll off: leave the dot as-is (default Unknown / last manual result), don't wipe it.
        if (!manual && !AppSettings.Current.ProbeReachability) return;
        // A manual dot click must obey the same active-tunnel guard as the all-profile sweep.
        // Probing while connected measures the endpoint through a different routing state and
        // can overwrite a valid pre-connect result with a misleading one.
        if (_status is VpnStatus.Connected or VpnStatus.Connecting) return;
        var generation = ++_nextReachabilityGeneration;
        _profileReachabilityGeneration[p] = generation;
        p.Reachability = ProfileReachability.Checking;
        _ = Task.Run(async () =>
        {
            // A TCP connect can't reach a UDP-only port; UDP needs a real handshake probe.
            bool ok;
            int ms;
            if (p.IsUdp)
            {
                int nativeLatency = 0;
                ok = await Task.Run(() => NativeTransportDiagnostics.TryUdpProbe(
                    p.ToIni(), 1500, out nativeLatency));
                ms = nativeLatency;
            }
            else
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                ok = await TcpProbeAsync(p.ServerAddress, p.Port, 3000);
                sw.Stop();
                ms = (int)sw.ElapsedMilliseconds;
            }
            Dispatcher.Invoke(() =>
            {
                if (_status is VpnStatus.Connected or VpnStatus.Connecting
                    || !_profileReachabilityGeneration.TryGetValue(p, out var current)
                    || current != generation)
                    return;
                _profileReachabilityGeneration.Remove(p);
                if (!_profiles.Contains(p)) return;
                p.LatencyMs = ok ? ms : null;
                p.Reachability = ok ? ProfileReachability.Reachable : ProfileReachability.Unreachable;
            });
        });
    }

    private static async Task<bool> TcpProbeAsync(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            var connect = client.ConnectAsync(host, port);
            var done = await Task.WhenAny(connect, Task.Delay(timeoutMs));
            return done == connect && client.Connected;
        }
        catch { return false; }
    }

    // ── live stats: speed tiles, session, IP + throughput sparkline ───────────────
    private (long up, long down, DateTime? since) StatsSource() => _serviceMode
        ? (_svc?.BytesUp ?? 0, _svc?.BytesDown ?? 0, _svc?.Since)
        : (_tunnel.BytesUp, _tunnel.BytesDown, _tunnel.ConnectedSince);

    private void StartStatsTimer()
    {
        var (up, down, _) = StatsSource();
        _prevUp = up; _prevDown = down; _prevStatsTick = Environment.TickCount64;
        _statsTimer ??= new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _statsTimer.Tick -= StatsTick;
        _statsTimer.Tick += StatsTick;
        _statsTimer.Start();
    }

    private void StopStatsTimer()
    {
        _statsTimer?.Stop();
        ResetTiles();
    }

    private void ResetTiles()
    {
        if (DownVal == null) return;
        DownVal.Text = UpVal.Text = SessionVal.Text = IpVal.Text = "—";
        TotalDownVal.Text = TotalUpVal.Text = "—";
        SessionSubVal.Text = IpSubVal.Text = "";
    }

    private void StatsTick(object? sender, EventArgs e)
    {
        var (up, down, since) = StatsSource();
        long now = Environment.TickCount64;
        double secs = Math.Max(now - _prevStatsTick, 1) / 1000.0;
        long upRate = (long)Math.Max((up - _prevUp) / secs, 0);
        long downRate = (long)Math.Max((down - _prevDown) / secs, 0);
        _prevUp = up; _prevDown = down; _prevStatsTick = now;

        DownVal.Text = FormatRate(downRate);
        UpVal.Text = FormatRate(upRate);
        SessionVal.Text = since is DateTime t ? FormatDuration(DateTime.Now - t) : "—";
        IpVal.Text = string.IsNullOrEmpty(_lastExtra) ? "—" : _lastExtra;

        // Context sub-lines: session totals (since connect), session start, wire mode.
        TotalDownVal.Text = Loc.F("StatTotal", FormatBytes(down));
        TotalUpVal.Text = Loc.F("StatTotal", FormatBytes(up));
        SessionSubVal.Text = since is DateTime s ? Loc.F("StatSince", s.ToString("HH:mm")) : "";
        IpSubVal.Text = Selected?.WireMode ?? "";
    }

    private static string FormatRate(long bytesPerSec)
    {
        if (bytesPerSec < 0) bytesPerSec = 0;
        if (bytesPerSec >= 1024 * 1024) return $"{bytesPerSec / (1024.0 * 1024.0):0.0} MB/s";
        if (bytesPerSec >= 1024) return $"{bytesPerSec / 1024.0:0.0} KB/s";
        return $"{bytesPerSec} B/s";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        if (bytes >= 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):0.00} GB";
        if (bytes >= 1024 * 1024) return $"{bytes / (1024.0 * 1024):0.0} MB";
        if (bytes >= 1024) return $"{bytes / 1024.0:0.0} KB";
        return $"{bytes} B";
    }

    private static string FormatDuration(TimeSpan ts) => ts.TotalHours >= 1
        ? $"{(int)ts.TotalHours}:{ts.Minutes:00}:{ts.Seconds:00}"
        : $"{ts.Minutes:00}:{ts.Seconds:00}";

    private void PersistAndSelect(VpnConfig cfg)
    {
        ProfileStore.Save(_profiles);
        // New/imported/duplicated profile: select it but don't hijack a live tunnel.
        Programmatic(() => ProfilesList.SelectedItem = cfg);
        UpdateEmptyHint();
        CheckReachability(cfg);
    }

    // ── connect/disconnect ───────────────────────────────────────────────────────
    private void OnConnectToggle(object sender, RoutedEventArgs e) => ToggleConnection();

    private bool _toggleBusy;
    private async void ToggleConnection()
    {
        if (_serviceMode) { ToggleService(); return; }
        // Debounce: ignore re-entrant taps while a transition is in flight. This is the
        // fix for the "click once → window froze → clicked again → it disconnected then
        // reconnected" report: the second click used to queue behind the blocked UI
        // thread and fire a fresh connect once Stop() returned.
        if (_toggleBusy) return;
        _toggleBusy = true;
        ConnectBtn.IsEnabled = false;
        try
        {
            if (_tunnel.IsRunning)
            {
                // Stop() blocks up to ~8 s joining the tunnel task; run it OFF the UI
                // thread so the window can't freeze — and so the tunnel's final status
                // event (marshalled back via Dispatcher.Invoke) can't deadlock the join.
                await Task.Run(_tunnel.Stop);
                _activeProfile = null;
                return;
            }
            var p = Selected;
            if (p == null) return;
            ClearLog(p);
            await StartTunnel(p);
        }
        catch (Exception error)
        {
            MessageBox.Show(this, error.Message, "Qeli",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _toggleBusy = false;
            ConnectBtn.IsEnabled = true;
        }
    }
}
