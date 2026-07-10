using System.Collections.ObjectModel;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using QeliMac.Model;
using Qeli.Shared.Protocol;
using QeliMac.Service;
using QeliMac.Vpn;
using Qeli.Shared;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac;

public partial class MainWindow : Window
{
    [DllImport("libc")] private static extern uint geteuid();

    private readonly ObservableCollection<VpnConfig> _profiles = new();
    private readonly VpnTunnel _tunnel = new();
    private VpnStatus _status = VpnStatus.Disconnected;
    private VpnStatus _prevStatus = VpnStatus.Disconnected;
    private string? _lastExtra;
    private TrayController? _tray;
    private bool _exiting;

    // Backing buffer for the log TextBox. Avalonia's TextBox has no AppendText (unlike
    // WPF's), so LogAppend used to do `LogBox.Text = LogBox.Text + text`, which copies the
    // whole accumulated log on every line — O(n^2) over a session and unbounded memory.
    // We append into this builder (amortized O(text)) and cap it to MaxLogChars, trimming
    // whole lines off the front, so a long-running tunnel can't grow the log without bound.
    private readonly System.Text.StringBuilder _logBuffer = new();
    private const int MaxLogChars = 256 * 1024;

    // Update check (opt-in; notification-only): once per app run, only while the tunnel is up.
    private bool _updateChecked;
    private string? _updateUrl;

    // launchd-daemon mode: the VPN runs in the daemon; the GUI polls its status/log.
    private bool _serviceMode;
    private DispatcherTimer? _serviceTimer;
    private long _serviceLogPos;

    // Live stats (sampled once a second while connected): speed tiles + sparkline.
    private DispatcherTimer? _statsTimer;
    private long _prevUp, _prevDown, _prevStatsTick;
    private ServiceStatus? _svc;                      // last daemon snapshot (service mode)

    // Connecting spinner (rotating arc on the status dot).
    private DispatcherTimer? _spinTimer;
    private readonly RotateTransform _spinRotate = new();

    public MainWindow()
    {
        InitializeComponent();
        ProfilesList.ItemsSource = _profiles;

        Icon = Ui.Icon(Branding.AppIconPng(64));
        LogoImage.Source = Ui.Png(Branding.LogoPng(64));
        VersionText.Text = $"v{AboutWindow.AppVersion()}";

        StatusSpinner.RenderTransform = _spinRotate;
        // Amber connecting spinner so "connecting / reconnecting / TUN-not-up-yet" reads
        // as a distinct YELLOW light (like OpenVPN / TunSafe), not the blue accent (#69).
        var a = Color.Parse("#F0A911");
        StatusSpinner.Stroke = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(a, 0.0),
                new GradientStop(Color.FromArgb(25, a.R, a.G, a.B), 1.0),
            },
        };

        foreach (var p in ProfileStore.Load()) _profiles.Add(p);
        if (_profiles.Count > 0)
        {
            // Restore the last-selected profile across launches (5.1); fall back to the
            // first row if nothing was persisted yet or that profile has been deleted.
            var lastId = AppSettings.Current.LastProfile;
            ProfilesList.SelectedItem =
                (lastId != null ? _profiles.FirstOrDefault(x => x.Id == lastId) : null) ?? _profiles[0];
        }
        UpdateEmptyHint();
        ApplyTileLabels();
        CheckReachabilityAll();
        ConfigureProbeTimer(); // start auto-poll (no-op when auto is off)

        _tunnel.LogLine += OnLog;
        _tunnel.StatusChanged += OnStatus;
        _tunnel.ConnectionDropped += _ =>
            Dispatcher.UIThread.Post(() => Toast.Show(ToastKind.Error, Loc.T("ToastConnLost"), Loc.T("Reconnecting")));

        // Proactively cycle the tunnel on a network change (Wi-Fi <-> Ethernet, interface
        // flap). Resume-from-sleep is handled by the data-plane suspend detector in
        // VpnTunnelBase (macOS wake needs no native hook here). Debounced + no-op unless up.
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) =>
            _tunnel.OnNetworkChanged();

        // The menu-bar tray icon is best-effort: a failure to create the native status
        // item must never take the whole app down (the window still works).
        if (!App.ShotMode)
        {
            try
            {
                _tray = new TrayController(
                    getProfiles: () => _profiles.ToList(),
                    getActive: () => Selected,
                    onSelectProfile: p => Dispatcher.UIThread.Post(() => SelectProfileFromTray(p)),
                    onToggleConnect: () => Dispatcher.UIThread.Post(() => ToggleConnection()),
                    onShowWindow: () => Dispatcher.UIThread.Post(ShowFromTray),
                    onSettings: () => Dispatcher.UIThread.Post(() => _ = OpenSettings()),
                    onExit: () => Dispatcher.UIThread.Post(ExitApp),
                    getStatus: () => _status);
            }
            catch (Exception ex) { Program.LogStartupError(new Exception("tray init failed", ex)); }
        }

        Toast.Enabled = AppSettings.Current.ToastsEnabled;

        Closing += OnWindowClosing;

        RefreshServiceMode();
        RenderStatus(_status, _lastExtra); // localized initial status
    }

    /// <summary>Seed sample profiles for an offscreen UI screenshot (uishot verb only).</summary>
    internal void ShotSeed(params VpnConfig[] ps)
    {
        foreach (var p in ps) { p.Reachability = ProfileReachability.Reachable; p.LatencyMs = 38; _profiles.Add(p); }
        ApplyFilter();
        if (_profiles.Count > 0) ProfilesList.SelectedIndex = 0;
        UpdateEmptyHint();
        OnProfileSelected(this, null!);
    }

    private VpnConfig? Selected => ProfilesList.SelectedItem as VpnConfig;

    private IBrush B(string key) => this.FindResource(key) as IBrush ?? Brushes.Gray;

    // ── spinner ──────────────────────────────────────────────────────────────────
    private void StartSpinner()
    {
        StatusDot.IsVisible = false;
        StatusSpinner.IsVisible = true;
        _spinTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(20) };
        _spinTimer.Tick -= SpinTick;
        _spinTimer.Tick += SpinTick;
        _spinTimer.Start();
    }

    private void SpinTick(object? sender, EventArgs e) =>
        _spinRotate.Angle = (_spinRotate.Angle + 8) % 360;

    private void StopSpinner()
    {
        _spinTimer?.Stop();
        StatusSpinner.IsVisible = false;
        StatusDot.IsVisible = true;
    }

    private void UpdateEmptyHint() => EmptyHint.IsVisible = _profiles.Count == 0;

    // ── window / tray plumbing ──────────────────────────────────────────────────
    private void OnWindowClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_exiting)
        {
            try { _tunnel.Stop(); } catch { }
            _tray?.Dispose();
            return;
        }
        e.Cancel = true;
        Hide();
        _tray?.ShowBalloon("Qeli", Loc.T("TrayBalloon"));
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        CheckReachabilityAll();
    }

    private void OnAbout(object? sender, RoutedEventArgs e) => _ = new AboutWindow(this).ShowDialog(this);

    private void OnSettings(object? sender, RoutedEventArgs e) => _ = OpenSettings();

    private async Task OpenSettings()
    {
        bool saved = await SettingsWindow.ShowAsync(this, _profiles);
        if (saved)
        {
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
    public void RunStartupActions()
    {
        if (_serviceMode) return; // the daemon owns the VPN
        var s = AppSettings.Current;
        if (!s.AutoConnect) return;
        var p = ResolveProfile(s.AutoConnectProfile) ?? Selected ?? _profiles.FirstOrDefault();
        if (p == null) return;
        ProfilesList.SelectedItem = p;
        LogClear();
        _tunnel.Start(p);
    }

    // ── launchd-daemon mode ──────────────────────────────────────────────────────
    private void RefreshServiceMode()
    {
        bool nowService = ServiceManager.IsInstalled();
        _serviceMode = nowService;
        if (nowService)
        {
            ConnectBtn.IsEnabled = true;
            _serviceLogPos = 0;
            LogClear();
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
        // Trust the status file's freshness rather than `launchctl list` (which a non-root
        // GUI can't use to see a system daemon). The daemon rewrites it every second, so a
        // stale (or missing) snapshot means it isn't running.
        bool fresh = snapshot != null && (DateTime.Now - snapshot.Time) < TimeSpan.FromSeconds(5);
        if (!fresh) { status = VpnStatus.Disconnected; extra = null; }

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
            if (text.Length > 0) LogAppend(text);
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
                    await Dialogs.InfoAsync(this, Loc.T("NoServiceProfile"), Loc.T("ServiceWord"));
                    return;
                }
                // Avoid two tunnels fighting over the utun device.
                if (_status is VpnStatus.Connected or VpnStatus.Connecting) _tunnel.Stop();

                if (ServiceManager.NeedsElevation)
                {
                    // GUI runs as the ordinary user: hand the profile to a one-shot
                    // root helper (single native admin prompt) that encrypts it into
                    // the shared dir and installs the daemon.
                    if (!await InstallDaemonElevated(p)) return;
                }
                else
                {
                    ServiceState.SaveProfile(p);
                    if (!ServiceManager.IsInstalled()) ServiceManager.Install();
                    ServiceManager.Start();
                }
            }
            else if (ServiceManager.IsInstalled())
            {
                if (ServiceManager.NeedsElevation)
                {
                    var (ok, msg, canceled) = await Task.Run(() => ServiceManager.RunSelfElevated("daemon-uninstall"));
                    if (!ok && !canceled)
                        await Dialogs.InfoAsync(this, Loc.F("ServiceApplyError", msg), Loc.T("ServiceWord"));
                }
                else ServiceManager.Uninstall();
            }
        }
        catch (Exception ex)
        {
            await Dialogs.InfoAsync(this, Loc.F("ServiceApplyError", ex.Message), Loc.T("ServiceWord"));
        }
        RefreshServiceMode();
    }

    /// <summary>
    /// Write the chosen profile to a short-lived user-only temp file and run the root
    /// <c>daemon-install</c> helper through the native admin prompt. The helper encrypts
    /// the profile into the shared dir and (re)installs the daemon, then deletes the temp
    /// file. Returns false (with an error dialog) on failure; silent on user-cancel.
    /// </summary>
    private async Task<bool> InstallDaemonElevated(VpnConfig p)
    {
        var dir = Paths.UserDir;
        Directory.CreateDirectory(dir);
        var tmp = System.IO.Path.Combine(dir, "pending-daemon-profile.json");
        try
        {
            File.WriteAllText(tmp, JsonSerializer.Serialize(p));
            // The temp file carries the server password — keep it user-only.
            if (!OperatingSystem.IsWindows())
                try { File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }

            var (ok, msg, canceled) = await Task.Run(() => ServiceManager.RunSelfElevated("daemon-install", tmp));
            if (!ok)
            {
                if (!canceled)
                    await Dialogs.InfoAsync(this, Loc.F("ServiceApplyError", msg), Loc.T("ServiceWord"));
                return false;
            }
            return true;
        }
        finally
        {
            // The helper deletes it on success; clean up if it never ran (cancel/error).
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private async Task ToggleService()
    {
        // In daemon mode the Connect button starts/stops the launchd daemon. Base the
        // intent on the polled status (privilege-independent), and route the privileged
        // launchctl call through the admin prompt when the GUI runs as a normal user.
        bool running = _status is VpnStatus.Connected or VpnStatus.Connecting;
        try
        {
            if (ServiceManager.NeedsElevation)
            {
                var verb = running ? "daemon-stop" : "daemon-start";
                var (ok, msg, canceled) = await Task.Run(() => ServiceManager.RunSelfElevated(verb));
                if (!ok && !canceled)
                    await Dialogs.InfoAsync(this, Loc.F("ServiceControlError", msg), Loc.T("ServiceWord"));
            }
            else
            {
                if (running) ServiceManager.Stop();
                else ServiceManager.Start();
            }
        }
        catch (Exception ex)
        {
            await Dialogs.InfoAsync(this, Loc.F("ServiceControlError", ex.Message), Loc.T("ServiceWord"));
        }
        ServicePollTick(null, EventArgs.Empty);
    }

    private void ExitApp()
    {
        _exiting = true;
        try { _tunnel.Stop(); } catch { }
        _tray?.Dispose();
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
    }

    private void SelectProfileFromTray(VpnConfig p)
    {
        bool wasBusy = _status is VpnStatus.Connected or VpnStatus.Connecting;
        ProfilesList.SelectedItem = p;
        if (wasBusy)
        {
            LogClear();
            _tunnel.Start(p);
        }
    }

    // ── tunnel events (marshalled to UI thread) ─────────────────────────────────
    private void OnLog(string line) =>
        Dispatcher.UIThread.Post(() => LogAppend($"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}\n"));

    private void OnStatus(VpnStatus status, string? extra) =>
        Dispatcher.UIThread.Post(() =>
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
                    CheckReachabilityAll();
                    break;
            }
            _prevStatus = status;
        });

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
            Dispatcher.UIThread.Post(() => ShowUpdateAvailable(info));
    }

    /// <summary>Reveal the dismissible "update available" link in the log header. Public so the
    /// manual check in <see cref="AboutWindow"/> can light it up too.</summary>
    public void ShowUpdateAvailable(UpdateInfo info)
    {
        _updateUrl = info.ReleaseUrl;
        UpdateText.Text = Loc.F("UpdateAvailable", info.LatestVersion);
        UpdateText.IsVisible = true;
    }

    private void OnUpdateClick(object? sender, Avalonia.Input.PointerPressedEventArgs e)
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

    /// <summary>Update the status visuals (no toasts). Re-runnable for live language switch.</summary>
    private void RenderStatus(VpnStatus status, string? extra)
    {
        _status = status;
        _lastExtra = extra;
        _tray?.Update(status, extra);

        StopStatsTimer(); // live speed readout is only meaningful while connected

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
                ConnectBtn.Content = Loc.T("Connect");
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

    // ── log helpers ───────────────────────────────────────────────────────────────
    private void LogClear() { _logBuffer.Clear(); LogBox.Text = ""; }

    private void LogAppend(string text)
    {
        _logBuffer.Append(text);
        // Bound the buffer: if over the cap, drop from the front on a line boundary so we
        // never leave a torn partial line at the top.
        if (_logBuffer.Length > MaxLogChars)
        {
            int overflow = _logBuffer.Length - MaxLogChars;
            int cut = overflow;
            int nl = -1;
            for (int i = overflow; i < _logBuffer.Length; i++)
                if (_logBuffer[i] == '\n') { nl = i; break; }
            if (nl >= 0) cut = nl + 1;
            _logBuffer.Remove(0, cut);
        }
        LogBox.Text = _logBuffer.ToString();
        LogBox.CaretIndex = _logBuffer.Length; // scroll to end
    }

    // ── search filter ────────────────────────────────────────────────────────────
    private bool _searchFocused;
    private void OnSearchChanged(object? sender, TextChangedEventArgs e)
    {
        bool empty = string.IsNullOrEmpty(SearchBox.Text);
        // Placeholder shows only when empty AND unfocused — otherwise the caret
        // overlaps the hint text. Hidden while typing or focused.
        SearchPlaceholder.IsVisible = empty && !_searchFocused;
        ClearSearchBtn.IsVisible = !empty;
        ApplyFilter();
    }

    private void OnSearchGotFocus(object? sender, GotFocusEventArgs e)
    {
        _searchFocused = true;
        SearchPlaceholder.IsVisible = false;
    }

    private void OnSearchLostFocus(object? sender, RoutedEventArgs e)
    {
        _searchFocused = false;
        SearchPlaceholder.IsVisible = string.IsNullOrEmpty(SearchBox.Text);
    }

    // Collapsible log: hidden by default so the chart gets the space; the header bar
    // (with version/about) stays at the bottom, aligned with New/Import on the left.
    // Log toolbar actions (the log fills the right column and is always open).
    private void OnCopyLog(object? sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(LogBox.Text))
            TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(LogBox.Text);
    }

    private void OnClearLog(object? sender, RoutedEventArgs e) { _logBuffer.Clear(); LogBox.Text = ""; }

    private void OnClearSearch(object? sender, RoutedEventArgs e)
    {
        SearchBox.Text = "";
        SearchBox.Focus();
    }

    private void ApplyFilter()
    {
        var q = SearchBox.Text?.Trim();
        // Capture the STABLE id, not the object reference: an Edit/Duplicate replaces the
        // VpnConfig instance, so restoring `SelectedItem = prev` (the old object) silently
        // loses the selection once ItemsSource is swapped to a new list (the macOS bug).
        var prevId = Selected?.Id;
        if (string.IsNullOrEmpty(q))
        {
            ProfilesList.ItemsSource = _profiles;
        }
        else
        {
            ProfilesList.ItemsSource = _profiles.Where(c =>
                c.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                c.Endpoint.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
        }
        if (prevId != null && ProfilesList.ItemsSource is IEnumerable<VpnConfig> src)
            ProfilesList.SelectedItem = src.FirstOrDefault(x => x.Id == prevId);
    }

    // ── profile UI ──────────────────────────────────────────────────────────────
    private void OnProfileSelected(object? sender, SelectionChangedEventArgs e)
    {
        var p = Selected;
        ConnectBtn.IsEnabled = _serviceMode || p != null;
        if (p != null && _status is VpnStatus.Disconnected) DetailText.Text = p.Endpoint;
        // Persist the pick so the next launch restores it (5.1). Ignore the transient
        // null selection while a filter hides the current row, skip the screenshot verb,
        // and avoid redundant writes when the Id is unchanged.
        if (p != null && !App.ShotMode && AppSettings.Current.LastProfile != p.Id)
        {
            AppSettings.Current.LastProfile = p.Id;
            AppSettings.Current.Save();
        }
    }

    private async void OnImport(object? sender, RoutedEventArgs e)
    {
        var text = await InputDialog.ShowAsync(this, Loc.T("ImportTitle"), Loc.T("ImportPrompt"), "", multiline: true);
        if (string.IsNullOrWhiteSpace(text)) return;
        try
        {
            text = text.Trim();
            VpnConfig cfg;
            if (text.StartsWith("qeli://", StringComparison.OrdinalIgnoreCase))
                cfg = VpnConfig.FromQeliUri(text);
            else if (text.StartsWith("{"))
                cfg = VpnConfig.FromJson(text);   // legacy JSON, still accepted
            else
                cfg = VpnConfig.FromIni(text);     // current flat-INI format
            cfg.Name ??= cfg.ServerAddress;
            _profiles.Add(cfg);
            PersistAndSelect(cfg);
        }
        catch (Exception ex)
        {
            await Dialogs.InfoAsync(this, Loc.F("ImportError", ex.Message), Loc.T("ImportTitle"));
        }
    }

    private async void OnNew(object? sender, RoutedEventArgs e)
    {
        var cfg = await ConfigEditorWindow.ShowAsync(this, null);
        if (cfg == null) return;
        _profiles.Add(cfg);
        PersistAndSelect(cfg);
    }

    // Per-card "⋯" menu: Edit / Duplicate / Share-QR / Delete (built in code).
    private void OnKebab(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button b || b.DataContext is not VpnConfig p) return;
        var flyout = new MenuFlyout();
        void Item(string key, Action act)
        {
            var mi = new MenuItem { Header = Loc.T(key) };
            mi.Click += (_, _) => act();
            flyout.Items.Add(mi);
        }
        Item("Edit", () => _ = EditProfile(p));
        Item("Duplicate", () => DuplicateProfile(p));
        Item("ShareQr", () => _ = QrShareWindow.ShowAsync(this, p));
        flyout.Items.Add(new Separator());
        Item("Delete", () => _ = DeleteProfile(p));
        flyout.ShowAt(b);
    }

    private void DuplicateProfile(VpnConfig p)
    {
        var copy = p.Clone();
        copy.Name = p.DisplayName + Loc.T("CopySuffix");
        _profiles.Add(copy);
        PersistAndSelect(copy);
    }

    private async Task EditProfile(VpnConfig p)
    {
        var edited = await ConfigEditorWindow.ShowAsync(this, p);
        if (edited == null) return;
        int idx = _profiles.IndexOf(p);
        if (idx >= 0) _profiles[idx] = edited;
        ProfileStore.Save(_profiles);
        ApplyFilter();
        ProfilesList.SelectedItem = edited;
        CheckReachability(edited);
    }

    private async Task DeleteProfile(VpnConfig p)
    {
        if (!await Dialogs.ConfirmAsync(this, Loc.F("DeleteConfirm", p.DisplayName), Loc.T("DeleteTitle"))) return;
        _profiles.Remove(p);
        ProfileStore.Save(_profiles);
        ApplyFilter();
        UpdateEmptyHint();
    }

    // ── server reachability probe ────────────────────────────────────────────────
    private DateTime _lastReachAll = DateTime.MinValue;
    private bool _reachPending;
    private DispatcherTimer? _probeTimer;

    /// <summary>(Re)configure the auto-poll timer from settings. Auto off → no timer
    /// (reachability is then updated only by the manual "check" button / dot click).</summary>
    private void ConfigureProbeTimer()
    {
        _probeTimer ??= new DispatcherTimer();
        _probeTimer.Stop();
        _probeTimer.Tick -= OnProbeTick;
        var s = QeliMac.Model.AppSettings.Current;
        if (!s.ProbeReachability) return;
        _probeTimer.Interval = TimeSpan.FromSeconds(Math.Clamp(s.ProbeIntervalSecs, 10, 3600));
        _probeTimer.Tick += OnProbeTick;
        _probeTimer.Start();
    }
    private void OnProbeTick(object? sender, EventArgs e) => CheckReachabilityAll();

    // Manual reachability checks (work even when auto-poll is off): the header refresh
    // button probes every profile; clicking a profile's status dot re-probes just it.
    private void OnProbeAll(object? sender, RoutedEventArgs e) => CheckReachabilityAll(manual: true);
    private void OnProbeOne(object? sender, Avalonia.Input.PointerReleasedEventArgs e)
    {
        if ((sender as Control)?.DataContext is VpnConfig p)
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
        if (!manual && !QeliMac.Model.AppSettings.Current.ProbeReachability) return;
        if (_status is VpnStatus.Connected or VpnStatus.Connecting) return;
        if (!manual)
        {
            // Debounce auto/event sweeps: each opens one connection PER profile; firing on
            // every disconnect / churn floods the server's per-IP new-session rate limit
            // (dots go falsely red AND a real connect right after is throttled). Cap to one
            // sweep per 15s; a call inside the cooldown is coalesced into one deferred sweep.
            var since = DateTime.UtcNow - _lastReachAll;
            if (since < TimeSpan.FromSeconds(15))
            {
                if (_reachPending) return;
                _reachPending = true;
                try { await Task.Delay(TimeSpan.FromSeconds(15) - since); }
                finally { _reachPending = false; }
                if (!QeliMac.Model.AppSettings.Current.ProbeReachability
                    || _status is VpnStatus.Connected or VpnStatus.Connecting) return;
            }
        }
        _lastReachAll = DateTime.UtcNow;
        foreach (var p in _profiles.ToList()) CheckReachability(p, manual);
    }

    private void CheckReachability(VpnConfig p, bool manual = false)
    {
        // Auto-poll off: leave the dot as-is (default Unknown / last manual result), don't wipe it.
        if (!manual && !QeliMac.Model.AppSettings.Current.ProbeReachability) return;
        p.Reachability = ProfileReachability.Checking;
        _ = Task.Run(async () =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool ok = p.IsUdp
                ? await Task.Run(() => UdpProbe(p, 1500))
                : await TcpProbeAsync(p.ServerAddress, p.Port, 3000);
            sw.Stop();
            int ms = (int)sw.ElapsedMilliseconds;
            Dispatcher.UIThread.Post(() =>
            {
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

    /// <summary>
    /// UDP reachability: send the SAME hybrid X25519+ML-KEM ClientHello a real
    /// connection sends. The server requires the X25519MLKEM768 share for the PQ tunnel
    /// and silently drops a non-PQ hello, so the probe MUST carry a real ML-KEM key to
    /// get a ServerHello back — otherwise every UDP profile shows a false red even when
    /// reachable. Treats any reply datagram as reachable; stays red when truly blocked.
    /// </summary>
    private static bool UdpProbe(VpnConfig cfg, int timeoutMs)
    {
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect(cfg.ServerAddress, cfg.Port);
            sock.ReceiveTimeout = timeoutMs;

            var pub = RandomNumberGenerator.GetBytes(32);
            string sni = string.IsNullOrWhiteSpace(cfg.Sni) ? "www.microsoft.com" : cfg.Sni!;
            using var mlkem = Qeli.Shared.Crypto.MlKem.Generate(); // hybrid PQ — server requires it
            byte[] hello = TlsHandshake.BuildClientHelloPq(pub, mlkem.EncapsulationKey, sni, padToMin: 1200);
            byte[] framed = hello;
            if (cfg.QuicEnabled)
                framed = Quic.WrapLong(hello, Quic.GenerateConnectionId(), 0, 0x02);
            else if (cfg.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase) && cfg.ObfsKey.Length > 0)
                framed = ObfsStream.DatagramSeal(ObfsStream.DeriveKey(cfg.ObfsKey), hello);

            var buf = new byte[4096];
            for (int attempt = 0; attempt < 2; attempt++)
            {
                sock.Send(framed);
                try { if (sock.Receive(buf) > 0) return true; }
                catch (SocketException) { /* timeout — retry then fail */ }
            }
            return false;
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
        ApplyFilter();
        ProfilesList.SelectedItem = cfg;
        UpdateEmptyHint();
        CheckReachability(cfg);
    }

    // ── connect/disconnect ───────────────────────────────────────────────────────
    private void OnConnectToggle(object? sender, RoutedEventArgs e) => ToggleConnection();

    private bool _toggleBusy;
    private async void ToggleConnection()
    {
        if (_serviceMode) { await ToggleService(); return; }
        // Debounce re-entrant taps + run the blocking Start/Stop off the UI thread, so a
        // rapid double-tap can't disconnect-then-reconnect and the window can't freeze
        // (parity with qeli-win's fix).
        if (_toggleBusy) return;
        _toggleBusy = true;
        try
        {
            if (_status is VpnStatus.Connected or VpnStatus.Connecting)
            {
                await Task.Run(() => { try { _tunnel.Stop(); } catch { } });
                return;
            }
            var p = Selected;
            if (p == null) return;

            // The data plane (utun + routes) needs root, exactly as qeli-win needs admin.
            if (geteuid() != 0)
            {
                await Dialogs.InfoAsync(this, Loc.T("NeedRoot"), "Qeli");
                return;
            }

            LogClear();
            await Task.Run(() => _tunnel.Start(p));
        }
        finally { _toggleBusy = false; }
    }
}
