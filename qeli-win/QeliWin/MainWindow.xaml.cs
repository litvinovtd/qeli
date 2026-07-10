using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using QeliWin.Model;
using Qeli.Shared.Protocol;
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
        if (_profiles.Count > 0) ProfilesList.SelectedIndex = 0;
        UpdateEmptyHint();
        ApplyTileLabels();
        CheckReachabilityAll();

        _tunnel.LogLine += OnLog;
        _tunnel.StatusChanged += OnStatus;
        _tunnel.ConnectionDropped += _ =>
            Dispatcher.Invoke(() => Toast.Show(ToastKind.Error, Loc.T("ToastConnLost"), Loc.T("Reconnecting")));

        // Proactively cycle the tunnel on resume-from-sleep and on a network change,
        // instead of waiting out the RX-liveness watchdog. ForceReconnect no-ops unless a
        // tunnel is up and is debounced, so idle/duplicate events are harmless.
        Microsoft.Win32.SystemEvents.PowerModeChanged += (_, e) =>
        { if (e.Mode == Microsoft.Win32.PowerModes.Resume) _tunnel.ForceReconnect("Resumed from sleep"); };
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (_, _) =>
            _tunnel.OnNetworkChanged();

        _tray = new TrayController(
            getProfiles: () => _profiles.ToList(),
            getActive: () => Selected,
            onSelectProfile: p => Dispatcher.Invoke(() => SelectProfileFromTray(p)),
            onToggleConnect: () => Dispatcher.Invoke(ToggleConnection),
            onShowWindow: () => Dispatcher.Invoke(ShowFromTray),
            onSettings: () => Dispatcher.Invoke(OpenSettings),
            onExit: () => Dispatcher.Invoke(ExitApp),
            getStatus: () => _status);

        Toast.Enabled = AppSettings.Current.ToastsEnabled;

        Closing += OnWindowClosing;
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
        Topmost = true; Topmost = false;
        CheckReachabilityAll();
    }

    private void OnAbout(object sender, RoutedEventArgs e) => new AboutWindow(this).ShowDialog();

    private void OnSettings(object sender, RoutedEventArgs e) => OpenSettings();

    private void OpenSettings()
    {
        bool saved = SettingsWindow.Show(this, _profiles);
        if (saved)
        {
            ApplyServiceSettings();
            ReapplyLanguage(); // language may have changed (live)
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
        if (_serviceMode) return; // the service owns the VPN
        var s = AppSettings.Current;
        if (!s.AutoConnect) return;
        var p = ResolveProfile(s.AutoConnectProfile) ?? Selected ?? _profiles.FirstOrDefault();
        if (p == null) return;
        ProfilesList.SelectedItem = p;
        LogBox.Clear();
        _tunnel.Start(p);
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

    private void ApplyServiceSettings()
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
                if (_status is VpnStatus.Connected or VpnStatus.Connecting) _tunnel.Stop();
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
            if (ServiceManager.IsRunning()) ServiceManager.Stop();
            else ServiceManager.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("ServiceControlError", ex.Message),
                Loc.T("ServiceWord"), MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        ServicePollTick(null, EventArgs.Empty);
    }

    private void ExitApp()
    {
        _exiting = true;
        try { _tunnel.Stop(); } catch { }
        _tray?.Dispose();
        Application.Current.Shutdown();
    }

    private void SelectProfileFromTray(VpnConfig p)
    {
        bool wasBusy = _status is VpnStatus.Connected or VpnStatus.Connecting;
        ProfilesList.SelectedItem = p;
        if (wasBusy)
        {
            LogBox.Clear();
            _tunnel.Start(p);
        }
    }

    // ── tunnel events (marshalled to UI thread) ─────────────────────────────────
    private void OnLog(string line) =>
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText($"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}\n");
            LogBox.ScrollToEnd();
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

    /// <summary>Update the status visuals (no toasts). Re-runnable for live language switch.</summary>
    private void RenderStatus(VpnStatus status, string? extra)
    {
        _status = status;
        _lastExtra = extra;
        _tray?.Update(status, extra);

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

    private void OnClearLog(object sender, RoutedEventArgs e) => LogBox.Clear();

    private bool FilterProfile(object o)
    {
        if (o is not VpnConfig c) return false;
        var q = SearchBox?.Text?.Trim();
        if (string.IsNullOrEmpty(q)) return true;
        return c.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || c.Endpoint.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    // ── profile UI ──────────────────────────────────────────────────────────────
    private void OnProfileSelected(object sender, SelectionChangedEventArgs e)
    {
        var p = Selected;
        ConnectBtn.IsEnabled = _serviceMode || p != null;
        if (p != null && _status is VpnStatus.Disconnected) DetailText.Text = p.Endpoint;
    }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        var text = InputDialog.Show(this, Loc.T("ImportTitle"), Loc.T("ImportPrompt"), "", multiline: true);
        if (string.IsNullOrWhiteSpace(text)) return;
        try
        {
            var cfg = VpnConfig.Parse(text.Trim());
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

    private void EditProfile(VpnConfig p)
    {
        var edited = ConfigEditorWindow.Show(this, p);
        if (edited == null) return;
        int idx = _profiles.IndexOf(p);
        _profiles[idx] = edited;
        ProfileStore.Save(_profiles);
        ProfilesList.SelectedItem = edited;
        CheckReachability(edited);
    }

    private void DeleteProfile(VpnConfig p)
    {
        if (MessageBox.Show(this, Loc.F("DeleteConfirm", p.DisplayName), Loc.T("DeleteTitle"),
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _profiles.Remove(p);
        ProfileStore.Save(_profiles);
        UpdateEmptyHint();
    }

    // ── server reachability probe ────────────────────────────────────────────────
    private void CheckReachabilityAll()
    {
        // User opt-out: don't probe at all — avoids sending a distinctive hybrid-PQ
        // ClientHello to every profile (a DPI observer could correlate it). Show the
        // dots as Unknown rather than a stale/false state.
        if (!AppSettings.Current.ProbeReachability)
        {
            foreach (var p in _profiles.ToList()) p.Reachability = ProfileReachability.Unknown;
            return;
        }
        // Skip while the tunnel is up — traffic would route oddly and the result is moot.
        if (_status is VpnStatus.Connected or VpnStatus.Connecting) return;
        foreach (var p in _profiles.ToList()) CheckReachability(p);
    }

    private void CheckReachability(VpnConfig p)
    {
        if (!AppSettings.Current.ProbeReachability)
        {
            p.Reachability = ProfileReachability.Unknown;
            return;
        }
        p.Reachability = ProfileReachability.Checking;
        _ = Task.Run(async () =>
        {
            // A TCP connect can't reach a UDP-only port; UDP needs a real handshake probe.
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool ok = p.IsUdp
                ? await Task.Run(() => UdpProbe(p, 1500))
                : await TcpProbeAsync(p.ServerAddress, p.Port, 3000);
            sw.Stop();
            int ms = (int)sw.ElapsedMilliseconds;
            Dispatcher.Invoke(() =>
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
    /// connection sends (mode-framed — raw fake-tls / QUIC-wrapped / obfs-sealed) and
    /// treat ANY reply datagram as "server reachable". The server requires the
    /// X25519MLKEM768 share for the PQ tunnel and silently drops a non-PQ hello, so the
    /// probe MUST carry a real ML-KEM key to get a ServerHello back — otherwise every
    /// UDP profile shows a false red even when reachable. Correctly stays red when UDP
    /// is truly blocked (no reply).
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
            for (int attempt = 0; attempt < 2; attempt++) // one retry — UDP can drop a probe
            {
                sock.Send(framed);
                try
                {
                    if (sock.Receive(buf) > 0) return true;
                }
                catch (SocketException) { /* timeout / port-unreachable — retry then fail */ }
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
        ProfilesList.SelectedItem = cfg;
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
            if (_status is VpnStatus.Connected or VpnStatus.Connecting)
            {
                // Stop() blocks up to ~3 s joining the tunnel task; run it OFF the UI
                // thread so the window can't freeze — and so the tunnel's final status
                // event (marshalled back via Dispatcher.Invoke) can't deadlock the join.
                await Task.Run(() => { try { _tunnel.Stop(); } catch { } });
                return;
            }
            var p = Selected;
            if (p == null) return;
            LogBox.Clear();
            await Task.Run(() => _tunnel.Start(p)); // Start() calls Stop() internally too
        }
        finally
        {
            _toggleBusy = false;
            ConnectBtn.IsEnabled = true;
        }
    }
}
