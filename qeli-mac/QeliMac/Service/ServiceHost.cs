using System.Runtime.InteropServices;
using QeliMac.Vpn;
using Qeli.Shared.Vpn;

namespace QeliMac.Service;

/// <summary>
/// The actual VPN, running headless as root under launchd. Loads the configured
/// profile, brings up the tunnel, self-reconnects, and mirrors status/log into
/// /Library/Application Support/Qeli files the GUI reads. Exits cleanly on the SIGTERM
/// launchd sends at unload. The macOS analogue of qeli-win's QeliWorker.
/// </summary>
public static class ServiceHostRunner
{
    public static void Run()
    {
        ServiceState.ResetLog();
        ServiceState.AppendLog("Daemon starting");

        var stop = new ManualResetEventSlim(false);
        // Cancel the DEFAULT signal disposition (terminate): otherwise the process can exit
        // before the loop reaches tunnel.Stop() below, leaving pf/DNS/route state up. (C-08)
        using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.Set(); });
        using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.Set(); });

        var tunnel = new VpnTunnel();
        VpnStatus last = VpnStatus.Connecting;
        string? lastExtra = null;
        tunnel.LogLine += ServiceState.AppendLog;
        tunnel.StatusChanged += (s, extra) =>
        {
            last = s; lastExtra = extra;
            ServiceState.WriteStatus(s, extra, tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
        };
        tunnel.ConnectionDropped += msg => ServiceState.AppendLog($"Connection lost: {msg}");

        var cfg = ServiceState.LoadProfile();
        if (cfg == null)
        {
            ServiceState.AppendLog("No daemon profile configured — idling until a stop signal");
            // Do NOT return: the plist's KeepAlive would respawn us in a tight restart loop.
            // Block until launchd sends SIGTERM (unload) so an unconfigured daemon idles
            // quietly instead. (C-08)
            //
            // Keep REPUBLISHING the status while idling, rather than writing it once. The GUI
            // treats a status file older than 5 seconds as "the daemon is not running" — it has
            // no other way to tell a stopped daemon from a stale file — so a single write made
            // a live, running, merely-unconfigured daemon indistinguishable from a dead one.
            // The user then saw the Connect button offer to connect again and again, each time
            // asking for the administrator password, with nothing to explain why.
            while (!stop.IsSet)
            {
                ServiceState.WriteStatus(VpnStatus.Disconnected, "no profile configured");
                stop.Wait(1000);
            }
            return;
        }

        ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
        tunnel.Start(cfg);

        // Periodically publish live stats (bytes/session) for the GUI to read.
        while (!stop.IsSet)
        {
            // The GUI's NetworkAddressChanged handler is not the owner of this headless
            // tunnel. Poll the filtered physical signature here so Wi-Fi/Ethernet, DHCP and
            // resolver changes reach the active daemon generation without waiting for a
            // transport liveness timeout.
            try { tunnel.OnNetworkChanged(); }
            catch (Exception e) { ServiceState.AppendLog($"Network-state poll failed: {e.Message}"); }
            ServiceState.WriteStatus(last, lastExtra, tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
            stop.Wait(1000);
        }

        ServiceState.AppendLog("Daemon stopping");
        tunnel.Stop();
        ServiceState.WriteStatus(VpnStatus.Disconnected, null);
    }
}
