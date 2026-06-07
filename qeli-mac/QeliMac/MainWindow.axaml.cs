using System.Collections.ObjectModel;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Shapes;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using QeliMac.Model;
using QeliMac.Protocol;
using QeliMac.Service;
using QeliMac.Vpn;

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

    // launchd-daemon mode: the VPN runs in the daemon; the GUI polls its status/log.
    private bool _serviceMode;
    private DispatcherTimer? _serviceTimer;
    private long _serviceLogPos;

    // Live stats (sampled once a second while connected): speed tiles + sparkline.
    private DispatcherTimer? _statsTimer;
    private long _prevUp, _prevDown, _prevStatsTick;
    private readonly Queue<double> _speed = new();   // recent download B/s for the chart
    private readonly Queue<double> _speedUp = new(); // recent upload B/s for the chart
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
        var a = ThemeManager.Accent;
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
        if (_profiles.Count > 0) ProfilesList.SelectedIndex = 0;
        UpdateEmptyHint();
        ApplyTileLabels();
        CheckReachabilityAll();

        _tunnel.LogLine += OnLog;
        _tunnel.StatusChanged += OnStatus;
        _tunnel.ConnectionDropped += _ =>
            Dispatcher.UIThread.Post(() => Toast.Show(ToastKind.Error, Loc.T("ToastConnLost"), Loc.T("Reconnecting")));

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
        bool saved = await SettingsWindow.ShowAsync(this, _profiles.Select(p => p.DisplayName).ToList());
        if (saved)
        {
            await ApplyServiceSettings();
            ReapplyLanguage(); // language may have changed (live)
        }
    }

    /// <summary>Called by App at launch: auto-connect to the configured profile if enabled.</summary>
    public void RunStartupActions()
    {
        if (_serviceMode) return; // the daemon owns the VPN
        var s = AppSettings.Current;
        if (!s.AutoConnect) return;
        var p = _profiles.FirstOrDefault(x => x.DisplayName == s.AutoConnectProfile)
                ?? Selected ?? _profiles.FirstOrDefault();
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
                var p = _profiles.FirstOrDefault(x => x.DisplayName == s.ServiceProfile)
                        ?? _profiles.FirstOrDefault();
                if (p == null)
                {
                    await Dialogs.InfoAsync(this, Loc.T("NoServiceProfile"), Loc.T("ServiceWord"));
                    return;
                }
                // Avoid two tunnels fighting over the utun device.
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
            await Dialogs.InfoAsync(this, Loc.F("ServiceApplyError", ex.Message), Loc.T("ServiceWord"));
        }
        RefreshServiceMode();
    }

    private async Task ToggleService()
    {
        try
        {
            if (ServiceManager.IsRunning()) ServiceManager.Stop();
            else ServiceManager.Start();
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
        Dispatcher.UIThread.Post(() => LogAppend($"{DateTime.Now:HH:mm:ss}  {line}\n"));

    private void OnStatus(VpnStatus status, string? extra) =>
        Dispatcher.UIThread.Post(() =>
        {
            RenderStatus(status, extra);
            switch (status)
            {
                case VpnStatus.Connected:
                    Toast.Show(ToastKind.Success, Loc.T("ToastConnected"),
                        $"{Selected?.DisplayName}{(string.IsNullOrEmpty(extra) ? "" : $" · {extra}")}");
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
    private void LogClear() => LogBox.Text = "";

    private void LogAppend(string text)
    {
        LogBox.Text = (LogBox.Text ?? "") + text;
        LogBox.CaretIndex = LogBox.Text.Length; // scroll to end
    }

    // ── search filter ────────────────────────────────────────────────────────────
    private void OnSearchChanged(object? sender, TextChangedEventArgs e)
    {
        bool empty = string.IsNullOrEmpty(SearchBox.Text);
        SearchPlaceholder.IsVisible = empty;
        ClearSearchBtn.IsVisible = !empty;
        ApplyFilter();
    }

    private void OnClearSearch(object? sender, RoutedEventArgs e)
    {
        SearchBox.Text = "";
        SearchBox.Focus();
    }

    private void ApplyFilter()
    {
        var q = SearchBox.Text?.Trim();
        var prev = Selected;
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
        if (prev != null) ProfilesList.SelectedItem = prev;
    }

    // ── profile UI ──────────────────────────────────────────────────────────────
    private void OnProfileSelected(object? sender, SelectionChangedEventArgs e)
    {
        var p = Selected;
        ConnectBtn.IsEnabled = _serviceMode || p != null;
        if (p != null && _status is VpnStatus.Disconnected) DetailText.Text = p.Endpoint;
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
    private void CheckReachabilityAll()
    {
        if (_status is VpnStatus.Connected or VpnStatus.Connecting) return;
        foreach (var p in _profiles.ToList()) CheckReachability(p);
    }

    private void CheckReachability(VpnConfig p)
    {
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

    private static bool UdpProbe(VpnConfig cfg, int timeoutMs)
    {
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect(cfg.ServerAddress, cfg.Port);
            sock.ReceiveTimeout = timeoutMs;

            var pub = RandomNumberGenerator.GetBytes(32);
            string sni = string.IsNullOrWhiteSpace(cfg.Sni) ? "www.microsoft.com" : cfg.Sni!;
            byte[] hello = TlsHandshake.BuildClientHello(pub, sni, padToMin: 1200);
            byte[] framed = hello;
            if (cfg.QuicEnabled)
                framed = Quic.WrapLong(hello, Quic.GenerateConnectionId(), 0, 0x02);
            else if (cfg.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase) && cfg.ObfsKey.Length > 0)
                framed = ObfsStream.DatagramSeal(ObfsStream.DeriveKey(cfg.ObfsKey), hello);

            var buf = new byte[2048];
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
        _speed.Clear(); _speedUp.Clear();
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
        TotalDownVal.Text = "↓ —";
        TotalUpVal.Text = "↑ —";
        ChartMaxLabel.Text = "";
        _speed.Clear(); _speedUp.Clear();
        RedrawChart();
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

        // Session totals (cumulative bytes since connect).
        TotalDownVal.Text = $"↓ {FormatBytes(down)}";
        TotalUpVal.Text = $"↑ {FormatBytes(up)}";

        _speed.Enqueue(downRate);
        _speedUp.Enqueue(upRate);
        while (_speed.Count > 60) _speed.Dequeue();
        while (_speedUp.Count > 60) _speedUp.Dequeue();
        RedrawChart();
    }

    private void OnChartResize(object? sender, SizeChangedEventArgs e) => RedrawChart();

    private void RedrawChart()
    {
        double w = ChartHost.Bounds.Width, h = ChartHost.Bounds.Height;
        if (w <= 1 || h <= 1 || _speed.Count < 2)
        {
            ChartLine.Points = new List<Point>();
            ChartUpLine.Points = new List<Point>();
            ChartArea.Points = new List<Point>();
            return;
        }
        var down = _speed.ToArray();
        var up = _speedUp.ToArray();
        double max = Math.Max(Math.Max(down.Max(), up.DefaultIfEmpty(0).Max()), 1);
        ChartMaxLabel.Text = FormatRate((long)max);

        List<Point> Build(double[] a)
        {
            var p = new List<Point>(a.Length);
            for (int i = 0; i < a.Length; i++)
                p.Add(new Point(w * i / (a.Length - 1), h - 2 - a[i] / max * (h - 5)));
            return p;
        }

        var dline = Build(down);
        ChartLine.Points = dline;
        ChartUpLine.Points = up.Length >= 2 ? Build(up) : new List<Point>();
        ChartArea.Points = new List<Point>(dline) { new(w, h), new(0, h) };
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

    private async void ToggleConnection()
    {
        if (_serviceMode) { await ToggleService(); return; }

        if (_status is VpnStatus.Connected or VpnStatus.Connecting)
        {
            _tunnel.Stop();
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
        _tunnel.Start(p);
    }
}
