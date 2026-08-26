using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using QeliMac.Model;
using QeliMac.Vpn;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>
/// Headless command-line modes for testing without the GUI:
///   QeliMac selftest                       — DNS/routes/pf/utun platform checks (no root)
///   QeliMac pf-selftest-rules &lt;path&gt;        — emit production pf rules for macOS CI
///   QeliMac handshake &lt;link|ini|file&gt;     — connect + full handshake only (no root)
///   QeliMac connect   &lt;link|ini|file&gt; [s]  — full tunnel (needs root)
///   QeliMac genassets &lt;dir&gt;                — render the brand PNGs into a directory
/// </summary>
public static class CliRunner
{
    public static int Run(string verb, string[] rest)
    {
        return verb.ToLowerInvariant() switch
        {
            "selftest" => SelfTest(),
            "pf-selftest-rules" => PfSelfTestRules(rest),
            "handshake" => Handshake(rest),
            "connect" => Connect(rest),
            "genassets" => GenAssets(rest),
            "genicns" => GenIcns(rest),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("Usage: QeliMac [selftest | pf-selftest-rules <path> | handshake <link|ini|file> | connect <link|ini|file> [seconds] | genassets <dir> | genicns <out.icns>]");
        return 2;
    }

    private static int PfSelfTestRules(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("pf-selftest-rules requires exactly one output path");
            return 2;
        }
        KillSwitch.WriteRuntimeSelfTestRules(args[0]);
        return 0;
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

        Console.WriteLine("qeli-mac platform self-test");
        DnsJournal.RunSelfTests(Check);
        NetworkConfigurator.RunRouteLifecycleSelfTest(Check);
        KillSwitch.RunSelfTests(Check);
        Check("utun cleanup: IPv4 and IPv6 addresses have family-correct undo commands",
            NetworkConfigurator.AddressRemovalArguments("utun7", IPAddress.Parse("10.8.0.2")) ==
                "utun7 inet 10.8.0.2 -alias"
            && NetworkConfigurator.AddressRemovalArguments("utun7", IPAddress.Parse("fd71:e1::2")) ==
                "utun7 inet6 fd71:e1::2 -alias");

        bool brandOk;
        try { brandOk = Branding.AppIconPng(64).Length > 0; }
        catch { brandOk = false; }
        Check("Branding renders app icon PNG (SkiaSharp)", brandOk);

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

    private static int Connect(string[] rest)
    {
        if (rest.Length < 1) return Usage();
        var cfg = LoadConfig(rest[0]);
        int seconds = rest.Length >= 2 && int.TryParse(rest[1], out int s) ? s : 30;
        var tunnel = new VpnTunnel();
        tunnel.LogLine += l => Console.WriteLine($"  {l}");
        tunnel.StatusChanged += (st, extra) => Console.WriteLine($"  [status] {st} {extra}");
        Console.WriteLine($"Connecting full tunnel -> {cfg.ServerAddress}:{cfg.Port} for {seconds}s (needs root)");

        // Ctrl+C (and a plain `kill`) must run the SAME teardown as the timer expiring. With
        // the default signal disposition the process died on the spot, leaving the utun device
        // up, the 0.0.0.0/1 + 128.0.0.0/1 split-default routes installed, the resolvers
        // hijacked and — with kill_switch — the pf `block drop out all` ruleset loaded, with
        // nothing left running to undo any of it. Same pattern the daemon already uses
        // (Service/ServiceHost.cs): cancel the default disposition, wake the wait, and let the
        // normal path below stop the tunnel. (Audit 2026-07-27, B7)
        using var stop = new ManualResetEventSlim(false);
        using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.Set(); });
        using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.Set(); });

        if (!tunnel.Start(cfg))
            throw new InvalidOperationException("Tunnel start was refused; see the preceding log/status detail.");
        if (stop.Wait(seconds * 1000)) Console.WriteLine("  Interrupted — stopping the tunnel…");
        tunnel.Stop();
        Console.WriteLine("Stopped.");
        return 0;
    }

    private static int GenAssets(string[] rest)
    {
        string dir = rest.Length >= 1 ? rest[0] : "assets";
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "appicon.png"), Branding.AppIconPng(1024));
        File.WriteAllBytes(Path.Combine(dir, "logo.png"), Branding.LogoPng(512));
        File.WriteAllBytes(Path.Combine(dir, "tray_disconnected.png"), Branding.TrayPng(Branding.StatusDisconnected));
        File.WriteAllBytes(Path.Combine(dir, "tray_connecting.png"), Branding.TrayPng(Branding.StatusConnecting));
        File.WriteAllBytes(Path.Combine(dir, "tray_connected.png"), Branding.TrayPng(Branding.StatusConnected));
        File.WriteAllBytes(Path.Combine(dir, "tray_error.png"), Branding.TrayPng(Branding.StatusError));
        Console.WriteLine($"Wrote brand PNGs to: {Path.GetFullPath(dir)}");
        return 0;
    }

    private static int GenIcns(string[] rest)
    {
        string path = rest.Length >= 1 ? rest[0] : "Qeli.icns";
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        Branding.WriteIcns(path, Branding.IcnsEntries);
        Console.WriteLine($"Wrote icns: {Path.GetFullPath(path)}");
        return 0;
    }
}
