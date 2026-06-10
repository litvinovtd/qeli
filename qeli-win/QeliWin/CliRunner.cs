using System.IO;
using System.Security.Cryptography;
using System.Text;
using Qeli.Shared.Crypto;
using QeliWin.Model;
using Qeli.Shared.Protocol;
using QeliWin.Vpn;
using Qeli.Shared.Model;

namespace QeliWin;

/// <summary>
/// Headless command-line modes for testing without the GUI:
///   QeliWin.exe selftest             — crypto/codec/parse round-trips (no network, no admin)
///   QeliWin.exe handshake &lt;link|json|file&gt; — connect + full handshake only (no admin)
///   QeliWin.exe connect   &lt;link|json|file&gt; [seconds] — full tunnel (needs admin)
/// </summary>
public static class CliRunner
{
    public static int Run(string verb, string[] rest)
    {
        return verb.ToLowerInvariant() switch
        {
            "selftest" => SelfTest(),
            "handshake" => Handshake(rest),
            "connect" => Connect(rest),
            "genassets" => GenAssets(rest),
            "uishot" => UiShot(rest),
            "editshot" => EditShot(rest),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("Usage: QeliWin.exe [selftest | handshake <link|json|file> | connect <link|json|file> [seconds]]");
        return 2;
    }

    // ── crypto self-test ────────────────────────────────────────────────────────
    private static int SelfTest()
    {
        int failed = 0;
        void Check(string name, bool ok) { Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}"); if (!ok) failed++; }

        Console.WriteLine("qeli-win self-test");

        // X25519 agreement is symmetric.
        var ke = new KeyExchange();
        var a = ke.GenerateKeyPair();
        var b = ke.GenerateKeyPair();
        var ab = ke.ComputeSharedSecret(a.PrivateKey, b.PublicKeyBytes);
        var ba = ke.ComputeSharedSecret(b.PrivateKey, a.PublicKeyBytes);
        Check("X25519 shared secret symmetric", ab.SequenceEqual(ba) && ab.Length == 32);

        // Hand-rolled HKDF matches System.Security.Cryptography.HKDF.
        var shared = ab;
        var (s2c, c2s) = KeyDerivation.DeriveKeys(shared);
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v1");
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, shared, salt);
        var refC2s = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.UTF8.GetBytes("client-to-server-enc-key"));
        var refS2c = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.UTF8.GetBytes("server-to-client-enc-key"));
        Check("HKDF DeriveKeys matches RFC 5869 reference", c2s.SequenceEqual(refC2s) && s2c.SequenceEqual(refS2c));

        // ChaCha20-Poly1305 AEAD round-trip.
        var cipher = new PacketCipher(c2s);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var msg = Encoding.UTF8.GetBytes("the quick brown fox");
        var ct = cipher.Encrypt(msg, nonce);
        Check("ChaCha20-Poly1305 round-trip", cipher.Decrypt(ct, nonce).SequenceEqual(msg) && ct.Length == msg.Length + 16);

        // PacketCodec record encode/decode (two codecs sharing the same key, like the two
        // directions of a session: encoder counter -> decoder replay window).
        var enc = new PacketCodec(new PacketCipher(c2s), paddingEnabled: true, paddingMin: 10, paddingMax: 40);
        var dec = new PacketCodec(new PacketCipher(c2s));
        bool codecOk = true;
        for (int i = 0; i < 5; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(100 + i);
            var rec = enc.Encrypt(payload);
            codecOk &= dec.Decrypt(rec).SequenceEqual(payload);
        }
        Check("PacketCodec encode/decode + counter/replay", codecOk);

        // Empty payload (heartbeat) survives the codec.
        var hbRec = enc.Encrypt(Array.Empty<byte>());
        Check("PacketCodec heartbeat (empty payload)", dec.Decrypt(hbRec).Length == 0);

        // `plain` wire mode: bare length-prefixed records (no TLS header). Round-trips
        // and emits a 2-byte (not 5-byte) header.
        var rawEnc = new PacketCodec(new PacketCipher(c2s), paddingEnabled: false, raw: true);
        var rawDec = new PacketCodec(new PacketCipher(c2s), raw: true);
        var rawPayload = RandomNumberGenerator.GetBytes(120);
        var rawRec = rawEnc.Encrypt(rawPayload);
        int rawHdr = rawRec.Length - (12 + rawPayload.Length + 16 + 8 + 2); // record - (nonce+ct)
        Check("PacketCodec raw framing (plain mode)",
            rawDec.Decrypt(rawRec).SequenceEqual(rawPayload) && rawHdr == 2 && rawRec[0] != 0x17);

        // ObfsStream keystream is symmetric across a crossed in-memory pipe.
        Check("ObfsStream XOR symmetric", TestObfs());

        // qeli:// link parses to the expected fields (a prod link shape).
        var link = "qeli://client1:dLYkV5x6JKBFr6@222.167.246.143:443?proto=tcp&mode=fake-tls" +
                   "&key=7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057&sni=www.microsoft.com#Client%201";
        var cfg = VpnConfig.FromQeliUri(link);
        Check("qeli:// parse",
            cfg.ServerAddress == "222.167.246.143" && cfg.Port == 443 && cfg.Username == "client1" &&
            cfg.Password == "dLYkV5x6JKBFr6" && cfg.Sni == "www.microsoft.com" &&
            cfg.ServerPublicKeyHex == "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057" &&
            cfg.Name == "Client 1");

        // Flat-INI client config parses to the expected fields.
        var ini = "[qeli]\nserver = 222.167.246.143:443\nproto = tcp\nuser = client1\n" +
                  "pass = secret\nmode = obfs\nobfs_key = psk123\nsni = www.apple.com\nroute_local = true\n" +
                  "[logging]\nlevel = info\n";
        var ic = VpnConfig.FromIni(ini);
        Check("INI parse",
            ic.ServerAddress == "222.167.246.143" && ic.Port == 443 && ic.Protocol == "tcp" &&
            ic.Username == "client1" && ic.Password == "secret" && ic.WireMode == "obfs" &&
            ic.ObfsKey == "psk123" && ic.Sni == "www.apple.com" && ic.RouteLocalNetworks &&
            ic.ObfsFronting == "websocket");

        // reality-tls INI (mode + key + reality_sid) parses, matching server-reality.conf.
        var rini = "[qeli]\nserver = host:443\nproto = tcp\nuser = u\npass = p\n" +
                   "key = 7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057\n" +
                   "mode = reality-tls\nreality_sid = 0123456789abcdef\nsni = www.microsoft.com\n";
        var rc = VpnConfig.FromIni(rini);
        Check("reality-tls INI parse",
            rc.WireMode == "reality-tls" && rc.RealityShortId == "0123456789abcdef" &&
            rc.ServerPublicKeyHex == "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057");

        // ToIni → FromIni round-trip preserves the new wire-mode fields (front + reality_sid + quic).
        var obfsRt = new VpnConfig { WireMode = "obfs", ObfsKey = "k", ObfsFronting = "none",
            Protocol = "udp", QuicEnabled = true, ServerAddress = "h", Port = 8448 };
        var obfsBack = VpnConfig.FromIni(obfsRt.ToIni());
        var realRt = new VpnConfig { WireMode = "reality-tls", RealityShortId = "abcdef01",
            ServerAddress = "h", Port = 443 };
        var realBack = VpnConfig.FromIni(realRt.ToIni());
        Check("INI round-trip (front/quic/reality_sid)",
            obfsBack.ObfsFronting == "none" && obfsBack.QuicEnabled &&
            realBack.RealityShortId == "abcdef01" && realBack.WireMode == "reality-tls");

        // ClientHello builds and pads to the UDP minimum.
        var hello = TlsHandshake.BuildClientHello(a.PublicKeyBytes, "www.microsoft.com", padToMin: 1200);
        Check("ClientHello builds + UDP padding (>=1200B, type 0x16)", hello.Length >= 1200 && hello[0] == 0x16);

        // Embedded wintun.dll loads from the resource (no loose DLL beside the exe).
        bool wintunLoaded; uint drv = 0;
        try { drv = WintunAdapter.ProbeLoad(); wintunLoaded = true; }
        catch (DllNotFoundException) { wintunLoaded = false; }
        Check($"Wintun loads from embedded resource (driver {drv >> 16}.{drv & 0xFFFF})", wintunLoaded);

        Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
        return failed == 0 ? 0 : 1;
    }

    private static bool TestObfs()
    {
        var key = ObfsStream.DeriveKey("secret-psk");
        // Wire two streams together through an in-memory nonce exchange.
        byte[]? clientNonce = null, serverNonce = null;
        var client = ObfsStream.Connect(key, false, n => clientNonce = n, _ => { serverNonce = RandomNumberGenerator.GetBytes(12); return serverNonce; });
        var server = ObfsStream.Connect(key, false, n => serverNonce = n, _ => clientNonce!);
        var plain = Encoding.UTF8.GetBytes("obfuscated payload over the wire");
        var onWire = client.TransformWrite(plain);
        var recovered = server.TransformRead(onWire);
        return recovered.SequenceEqual(plain) && !onWire.SequenceEqual(plain);
    }

    // ── live handshake / connect ──────────────────────────────────────────────────
    // Accepts a file path OR an inline config, in any format: flat-INI (current),
    // a qeli:// link, or legacy JSON.
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
            Background = R("Bg"), Padding = new System.Windows.Thickness(16),
            Width = 600, Height = 200, Child = card,
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
            Left = -10000, Top = -10000, Width = 1, Height = 1,
            ShowInTaskbar = false, ShowActivated = false,
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
                Name = $"Test {mode}", ServerAddress = "222.167.246.143", Port = 443, Protocol = "tcp",
                Username = "client5", Password = "secret", WireMode = mode,
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
                Background = R("Bg"), Child = content, Width = 560,
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
                BorderBrush = R("PanelBorder"), Opacity = i == 3 ? 0.75 : 0.4,
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
            Text = "14.0 MB/s", FontSize = 10, Foreground = R("FgDim"),
            HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
            VerticalAlignment = System.Windows.VerticalAlignment.Top,
        });
        chart.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "60 s", FontSize = 10, Foreground = R("FgDim"),
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
            Background = R("Panel"), BorderBrush = R("PanelBorder"),
            BorderThickness = new System.Windows.Thickness(1),
            CornerRadius = new System.Windows.CornerRadius(11),
            Padding = new System.Windows.Thickness(16, 12, 16, 12), Child = stack,
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
        tunnel.Start(cfg);
        Thread.Sleep(seconds * 1000);
        tunnel.Stop();
        Console.WriteLine("Stopped.");
        return 0;
    }
}
