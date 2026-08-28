using System.IO;
using QeliWin.Model;
using QeliWin.Vpn;
using Qeli.Shared.Model;

namespace QeliWin;

/// <summary>
/// Headless command-line modes for testing without the GUI:
///   QeliWin.exe selftest             — WinDivert/Wintun/routes/DNS platform checks
///   QeliWin.exe windivert-smoke       — elevated production-filter smoke test
///   QeliWin.exe handshake &lt;link|ini|file&gt; — connect + full handshake only
///   QeliWin.exe connect   &lt;link|ini|file&gt; [seconds] — full tunnel (needs admin)
/// The EXE manifest requests elevation for every verb. Run the framework-dependent
/// <c>dotnet QeliWin.dll selftest|handshake</c> form when a no-admin diagnostic is required.
/// </summary>
public static class CliRunner
{
    public static int Run(string verb, string[] rest)
    {
        return verb.ToLowerInvariant() switch
        {
            "selftest" => SelfTest(),
            "windivert-smoke" => WinDivertSmoke(),
            "handshake" => Handshake(rest),
            "connect" => Connect(rest),
            "genassets" => GenAssets(rest),
            "uishot" => UiShot(rest),
            "editshot" => EditShot(rest),
            "mainshot" => MainShot(rest),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("Usage: QeliWin.exe [selftest | windivert-smoke | handshake <link|ini|file> | connect <link|ini|file> [seconds]]");
        return 2;
    }

    // ── platform self-test ──────────────────────────────────────────────────────
    private static int SelfTest()
    {
        int failed = 0;
        void Check(string name, bool ok)
        {
            Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}");
            if (!ok) failed++;
        }

        Console.WriteLine("qeli-win platform self-test");
        WinDivertSelfTest.RunUnit(Check);
        WindowsRoamingSocket.RunSelfTest(Check);
        VpnTunnel.RunRoamingCapabilitySelfTest(Check);
        NetworkConfigurator.RunDnsLifecycleSelfTest(Check);
        NetworkConfigurator.RunRouteLifecycleSelfTest(Check);

        bool wintunLoaded;
        uint driverVersion = 0;
        try
        {
            driverVersion = WintunAdapter.ProbeLoad();
            wintunLoaded = true;
        }
        catch (DllNotFoundException)
        {
            wintunLoaded = false;
        }
        Check($"Wintun loads from embedded resource (driver {driverVersion >> 16}.{driverVersion & 0xFFFF})",
            wintunLoaded);

        Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
        return failed == 0 ? 0 : 1;
    }

    private static int WinDivertSmoke()
    {
        Console.WriteLine("qeli-win elevated WinDivert smoke test");
        int failed = WinDivertSelfTest.RunElevatedSmoke((name, ok) =>
            Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}"));
        Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
        return failed == 0 ? 0 : 1;
    }


    // ── live handshake / connect ──────────────────────────────────────────────────
    // Accepts a file path OR an inline config, in any format: flat-INI (current),
    // an INI file/text or a qeli:// link. Retired formats are rejected by VpnConfig.Parse.
    private static VpnConfig LoadConfig(string arg) =>
        VpnConfig.Parse(File.Exists(arg) ? File.ReadAllText(arg) : arg);

    private static int Handshake(string[] rest)
    {
        if (rest.Length < 1) return Usage();
        var cfg = LoadConfig(rest[0]);
        var tunnel = new VpnTunnel();
        tunnel.LogLine += l => Console.WriteLine($"  {l}");
        Console.WriteLine($"Handshake test -> {cfg.ServerAddress}:{cfg.Port} ({cfg.Protocol}/{cfg.WireMode})");
        try
        {
            var ip = tunnel.TestHandshake(cfg);
            Console.WriteLine($"RESULT: OK, server assigned tunnel IP {ip}");
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine($"RESULT: FAILED — {e.GetType().Name}: {e.Message}");
            return 1;
        }
    }

    // Headless render of a profiles ListBox to PNG — to verify the slim scrollbar style.
    private static int UiShot(string[] rest)
    {
        string path = rest.Length >= 1 ? rest[0] : "ui.png";
        ThemeManager.Apply();
        var app = System.Windows.Application.Current;
        System.Windows.Media.Brush R(string k) => (System.Windows.Media.Brush)app.Resources[k];

        var card = BuildChartPreview(R);
        var root = new System.Windows.Controls.Border
        {
            Background = R("Bg"),
            Padding = new System.Windows.Thickness(16),
            Width = 600,
            Height = 200,
            Child = card,
        };
        root.Measure(new System.Windows.Size(600, 200));
        root.Arrange(new System.Windows.Rect(0, 0, 600, 200));
        root.UpdateLayout();
        return SavePng(root, path, 600, 200);
    }

    // Headless render of the profile editor to PNG — verifies the new wire-mode fields
    // (reality-tls short_id, obfs fronting) lay out correctly without showing a window.
    private static int EditShot(string[] rest)
    {
        ThemeManager.Apply();
        var app = System.Windows.Application.Current;
        System.Windows.Media.Brush R(string k) => (System.Windows.Media.Brush)app.Resources[k];
        var owner = new System.Windows.Window
        {
            Left = -10000,
            Top = -10000,
            Width = 1,
            Height = 1,
            ShowInTaskbar = false,
            ShowActivated = false,
            WindowStyle = System.Windows.WindowStyle.None,
            WindowStartupLocation = System.Windows.WindowStartupLocation.Manual,
        };
        owner.Show(); // needs an HWND before it can be used as Owner

        var samples = new (string mode, string file)[]
        {
            ("reality-tls", rest.Length >= 1 ? rest[0] : "editor-reality.png"),
            ("obfs", rest.Length >= 2 ? rest[1] : "editor-obfs.png"),
            ("plain", rest.Length >= 3 ? rest[2] : "editor-plain.png"),
        };

        foreach (var (mode, file) in samples)
        {
            var cfg = new VpnConfig
            {
                Name = $"Test {mode}",
                ServerAddress = "YOUR_PROD_HOST",
                Port = 443,
                Protocol = "tcp",
                Username = "client5",
                Password = "secret",
                WireMode = mode,
                ServerPublicKeyHex = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057",
                Sni = "www.microsoft.com",
                RealityShortId = mode == "reality-tls" ? "0123456789abcdef" : null,
                ObfsKey = mode == "obfs" ? "psk-demo-key" : "",
                ObfsFronting = mode == "obfs" ? "none" : "websocket",
            };
            var ed = new ConfigEditorWindow(owner, cfg);
            var content = (System.Windows.FrameworkElement)ed.Content;
            ed.Content = null; // detach so it can be re-parented for offscreen render
            var root = new System.Windows.Controls.Border
            {
                Background = R("Bg"),
                Child = content,
                Width = 560,
            };
            root.Measure(new System.Windows.Size(560, double.PositiveInfinity));
            int h = (int)Math.Ceiling(root.DesiredSize.Height);
            root.Arrange(new System.Windows.Rect(0, 0, 560, h));
            root.UpdateLayout();
            SavePng(root, file, 560, h);
        }
        owner.Close();
        return 0;
    }

    // Headless render of the live MainWindow to PNG — verifies the studio layout
    // (hero, stat strip, chart, collapsible log) without a visible window/UAC.
    private static int MainShot(string[] rest)
    {
        ThemeManager.Apply();
        string path = rest.Length >= 1 ? rest[0] : "main.png";
        var win = new MainWindow
        {
            WindowStartupLocation = System.Windows.WindowStartupLocation.Manual,
            Left = -4000,
            Top = -4000,
            ShowInTaskbar = false,
            ShowActivated = false,
        };
        win.Show();
        win.UpdateLayout();
        var root = (System.Windows.FrameworkElement)win.Content;
        int w = (int)System.Math.Ceiling(root.ActualWidth);
        int h = (int)System.Math.Ceiling(root.ActualHeight);
        int code = SavePng(root, path, w, h);
        win.Close();
        return code;
    }

    private static int SavePng(System.Windows.UIElement el, string path, int w, int h)
    {
        var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(w, h, 96, 96,
            System.Windows.Media.PixelFormats.Pbgra32);
        rtb.Render(el);
        var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
        enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
        using var fs = File.Create(path);
        enc.Save(fs);
        Console.WriteLine($"Wrote {Path.GetFullPath(path)}");
        return 0;
    }

    private static System.Windows.Controls.Border BuildChartPreview(Func<string, System.Windows.Media.Brush> R)
    {
        double w = 560, h = 84;
        double[] down = new double[] { 2, 4, 3, 6, 5, 9, 7, 11, 8, 12, 10, 13, 9, 12, 11, 14 }
            .Select(v => v * 1024.0 * 1024).ToArray();
        double[] up = new double[] { 1, 1.5, 1, 2, 1.6, 2.4, 2, 2.6, 2.2, 3, 2.5, 3.1, 2.4, 2.9, 2.6, 3.2 }
            .Select(v => v * 1024.0 * 1024).ToArray();
        double max = Math.Max(down.Max(), up.Max());

        System.Windows.Media.PointCollection Pts(double[] a)
        {
            var p = new System.Windows.Media.PointCollection();
            for (int i = 0; i < a.Length; i++)
                p.Add(new System.Windows.Point(w * i / (a.Length - 1), h - 2 - a[i] / max * (h - 5)));
            return p;
        }
        System.Windows.Media.Brush B(string hex) =>
            new System.Windows.Media.BrushConverter().ConvertFromString(hex) as System.Windows.Media.Brush
            ?? System.Windows.Media.Brushes.Gray;

        var dline = Pts(down);
        var chart = new System.Windows.Controls.Grid { Height = h };
        var grid = new System.Windows.Controls.Grid { IsHitTestVisible = false };
        for (int i = 0; i < 4; i++)
        {
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition());
            var ln = new System.Windows.Controls.Border
            {
                BorderBrush = R("PanelBorder"),
                Opacity = i == 3 ? 0.75 : 0.4,
                BorderThickness = new System.Windows.Thickness(0, 0, 0, 1),
            };
            System.Windows.Controls.Grid.SetRow(ln, i);
            grid.Children.Add(ln);
        }
        chart.Children.Add(grid);
        chart.Children.Add(new System.Windows.Shapes.Polygon
        {
            Fill = B("#214D92FF"),
            Points = new System.Windows.Media.PointCollection(dline)
                { new(w, h), new(0, h) },
        });
        chart.Children.Add(new System.Windows.Shapes.Polyline { Stroke = B("#4D92FF"), StrokeThickness = 2, Points = dline });
        chart.Children.Add(new System.Windows.Shapes.Polyline { Stroke = B("#2FBF6B"), StrokeThickness = 2, Points = Pts(up) });
        chart.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "14.0 MB/s",
            FontSize = 10,
            Foreground = R("FgDim"),
            HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
            VerticalAlignment = System.Windows.VerticalAlignment.Top,
        });
        chart.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "60 s",
            FontSize = 10,
            Foreground = R("FgDim"),
            HorizontalAlignment = System.Windows.HorizontalAlignment.Right,
            VerticalAlignment = System.Windows.VerticalAlignment.Bottom,
        });

        var header = new System.Windows.Controls.Grid();
        var legend = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        legend.Children.Add(new System.Windows.Controls.TextBlock { Text = "Throughput", FontSize = 12, Foreground = R("FgDim"), VerticalAlignment = System.Windows.VerticalAlignment.Center });
        legend.Children.Add(new System.Windows.Controls.TextBlock { Text = "  ↓  ↑", FontSize = 12, Foreground = R("FgDim"), VerticalAlignment = System.Windows.VerticalAlignment.Center, Margin = new System.Windows.Thickness(12, 0, 0, 0) });
        var totals = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, HorizontalAlignment = System.Windows.HorizontalAlignment.Right };
        totals.Children.Add(new System.Windows.Controls.TextBlock { Text = "↓ 1.84 GB", FontSize = 12.5, FontWeight = System.Windows.FontWeights.SemiBold, Foreground = R("Fg") });
        totals.Children.Add(new System.Windows.Controls.TextBlock { Text = "↑ 0.42 GB", FontSize = 12.5, FontWeight = System.Windows.FontWeights.SemiBold, Foreground = R("Fg"), Margin = new System.Windows.Thickness(16, 0, 0, 0) });
        header.Children.Add(legend);
        header.Children.Add(totals);

        var stack = new System.Windows.Controls.StackPanel();
        stack.Children.Add(header);
        chart.Margin = new System.Windows.Thickness(0, 12, 0, 0);
        stack.Children.Add(chart);

        return new System.Windows.Controls.Border
        {
            Background = R("Panel"),
            BorderBrush = R("PanelBorder"),
            BorderThickness = new System.Windows.Thickness(1),
            CornerRadius = new System.Windows.CornerRadius(11),
            Padding = new System.Windows.Thickness(16, 12, 16, 12),
            Child = stack,
        };
    }

    private static int GenAssets(string[] rest)
    {
        string icoPath = rest.Length >= 1 ? rest[0] : "qeli.ico";
        var dir = Path.GetDirectoryName(Path.GetFullPath(icoPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        Branding.WriteIco(icoPath, 16, 24, 32, 48, 64, 128, 256);
        Console.WriteLine($"Wrote icon: {Path.GetFullPath(icoPath)}");

        // Optional 2nd arg: a directory to dump PNG previews into (for visual review).
        if (rest.Length >= 2)
        {
            var pdir = rest[1];
            Directory.CreateDirectory(pdir);
            File.WriteAllBytes(Path.Combine(pdir, "appicon.png"), Branding.AppIconPng(256));
            File.WriteAllBytes(Path.Combine(pdir, "logo.png"), Branding.LogoPng(256));
            File.WriteAllBytes(Path.Combine(pdir, "tray_disconnected.png"), Branding.TrayPng(Branding.StatusDisconnected));
            File.WriteAllBytes(Path.Combine(pdir, "tray_connecting.png"), Branding.TrayPng(Branding.StatusConnecting));
            File.WriteAllBytes(Path.Combine(pdir, "tray_connected.png"), Branding.TrayPng(Branding.StatusConnected));
            File.WriteAllBytes(Path.Combine(pdir, "tray_error.png"), Branding.TrayPng(Branding.StatusError));
            Console.WriteLine($"Wrote previews to: {Path.GetFullPath(pdir)}");
        }
        return 0;
    }

    private static int Connect(string[] rest)
    {
        if (rest.Length < 1) return Usage();
        var cfg = LoadConfig(rest[0]);
        int seconds = rest.Length >= 2 && int.TryParse(rest[1], out int s) ? s : 30;
        var tunnel = new VpnTunnel();
        tunnel.LogLine += l => Console.WriteLine($"  {l}");
        tunnel.StatusChanged += (st, extra) => Console.WriteLine($"  [status] {st} {extra}");
        Console.WriteLine($"Connecting full tunnel -> {cfg.ServerAddress}:{cfg.Port} for {seconds}s (needs admin)");

        // Ctrl+C must run the SAME teardown as the timer expiring. Without a handler the
        // default disposition killed the process on the spot, leaving the Wintun adapter up,
        // the 0.0.0.0/1 + 128.0.0.0/1 split-default routes installed, the DNS servers
        // hijacked and — with kill_switch — the host's egress blocked, with nothing left
        // running to undo any of it. Cancel the default, signal the wait, and let the normal
        // path below do the stopping. Mirrors ServiceHostRunner's SIGTERM/SIGINT handling.
        // (Audit 2026-07-27, B7)
        using var stop = new ManualResetEventSlim(false);
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            e.Cancel = true;                     // do not let the runtime kill us mid-tunnel
            Console.WriteLine("  Interrupted — stopping the tunnel…");
            stop.Set();
        };
        Console.CancelKeyPress += onCancel;
        try
        {
            if (!tunnel.Start(cfg))
                throw new InvalidOperationException("Tunnel start was refused; see the preceding log/status detail.");
            stop.Wait(seconds * 1000);
        }
        finally { Console.CancelKeyPress -= onCancel; }

        tunnel.Stop();
        Console.WriteLine("Stopped.");
        return 0;
    }
}
