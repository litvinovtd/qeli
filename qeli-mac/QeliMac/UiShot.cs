using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using QeliMac.Model;
using Qeli.Shared;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>
/// Offscreen UI screenshots — the macOS/Avalonia analogue of qeli-win's WPF `uishot`.
/// Renders the real app windows to PNG with the headless Skia backend (no display),
/// so the interface can be reviewed from a build host. Verb: <c>uishot &lt;dir&gt;</c>.
/// </summary>
public static class UiShot
{
    public static int Run(string[] rest)
    {
        string dir = rest.Length >= 1 ? rest[0] : "screens";
        Directory.CreateDirectory(dir);
        App.ShotMode = true;

        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont()
            .SetupWithoutStarting();

        ThemeManager.Apply();
        Loc.SetLanguage(AppSettings.Current.Language);

        int n = 0;
        void Shot(Window w, string name, int width, int height)
        {
            w.Width = width; w.Height = height;
            w.Show();
            for (int i = 0; i < 3; i++) { Dispatcher.UIThread.RunJobs(); AvaloniaHeadlessPlatform.ForceRenderTimerTick(); }
            var frame = w.CaptureRenderedFrame();
            if (frame != null)
            {
                using (var fs = File.Create(Path.Combine(dir, name))) frame.Save(fs);
                Console.WriteLine($"  wrote {name} ({frame.PixelSize.Width}x{frame.PixelSize.Height})");
                n++;
            }
            else Console.WriteLine($"  FAILED {name} (null frame)");
            try { w.Close(); } catch { }
        }

        VpnConfig[] Seed() => new[]
        {
            new VpnConfig { Name = "Client 1", ServerAddress = "YOUR_PROD_HOST", Port = 443, Protocol = "tcp",
                WireMode = "reality-tls", RealityShortId = "0123456789abcdef",
                ServerPublicKeyHex = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057",
                Username = "client1", Sni = "www.microsoft.com" },
            new VpnConfig { Name = "Tokyo UDP", ServerAddress = "198.51.100.7", Port = 8443, Protocol = "udp",
                WireMode = "fake-tls", QuicEnabled = true, Username = "client2" },
            new VpnConfig { Name = "Office obfs", ServerAddress = "203.0.113.42", Port = 443, Protocol = "tcp",
                WireMode = "obfs", ObfsKey = "psk", Username = "client3" },
        };
        VpnConfig RealityCfg() => new()
        {
            Name = "Client 1", ServerAddress = "YOUR_PROD_HOST", Port = 443, Protocol = "tcp",
            WireMode = "reality-tls", RealityShortId = "0123456789abcdef",
            ServerPublicKeyHex = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057",
            Username = "client1", Password = "secret", Sni = "www.microsoft.com",
        };

        // ── light/system theme ──
        var main = new MainWindow();
        main.ShotSeed(Seed());
        Shot(main, "01-main.png", 980, 660);
        Shot(new ConfigEditorWindow(main, RealityCfg()), "02-editor.png", 560, 760);
        Shot(new SettingsWindow(main, Seed()), "03-settings.png", 520, 600);
        Shot(new AboutWindow(main), "04-about.png", 400, 380);

        // ── dark theme (the app follows the macOS appearance; force it for the shot) ──
        AppSettings.Current.Theme = "dark";
        ThemeManager.Apply();
        var mainDark = new MainWindow();
        mainDark.ShotSeed(Seed());
        Shot(mainDark, "05-main-dark.png", 980, 660);
        Shot(new ConfigEditorWindow(mainDark, RealityCfg()), "06-editor-dark.png", 560, 760);

        Console.WriteLine($"Wrote {n} screenshot(s) to {Path.GetFullPath(dir)}");
        return n > 0 ? 0 : 1;
    }
}
