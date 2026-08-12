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

        bool tunnelStarted = false;
        bool executableRemoved = false;
        string? executablePath = Environment.ProcessPath;

        bool StopTunnelWithRetry(string reason)
        {
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    ServiceState.AppendLog($"Stopping tunnel ({reason}), attempt {attempt}/3");
                    tunnel.Stop();
                    return true;
                }
                catch (Exception e)
                {
                    ServiceState.AppendLog($"Tunnel cleanup attempt {attempt}/3 failed: {e.Message}");
                    ServiceState.WriteStatus(VpnStatus.Error,
                        "disconnect incomplete: macOS DNS restore will be retried");
                    if (attempt < 3) Thread.Sleep(250);
                }
            }
            return false;
        }

        // Keep the LaunchDaemon process alive even while disconnected: KeepAlive would
        // otherwise respawn it in a tight loop. The separate desired-state file decides
        // whether a tunnel exists. This makes a user Disconnect survive reboot while still
        // allowing launchd to supervise genuine crashes of an enabled connection.
        while (!stop.IsSet)
        {
            // Finder can remove/move Qeli.app while this already-running executable remains
            // mapped in memory. Detect that window and restore DNS before a reboot makes the
            // launchd target unstartable and strands networksetup's persistent override.
            if (!executableRemoved && executablePath != null && !File.Exists(executablePath))
            {
                executableRemoved = true;
                ServiceState.AppendLog($"Application executable disappeared from '{executablePath}'; " +
                    "disabling the connection and restoring host networking");
                try { ServiceState.SetDesiredConnected(false); }
                catch (Exception e) { ServiceState.AppendLog($"Could not persist disabled state: {e.Message}"); }
            }

            bool desired = !executableRemoved && ServiceState.DesiredConnected();
            if (desired && !tunnelStarted)
            {
                var cfg = ServiceState.LoadProfile();
                if (cfg == null)
                {
                    ServiceState.WriteStatus(VpnStatus.Disconnected, "no profile configured");
                }
                else
                {
                    try
                    {
                        ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
                        tunnel.LogLevel = cfg.LoggingLevel;
                        tunnel.Start(cfg);
                        tunnelStarted = true;
                    }
                    catch (Exception e)
                    {
                        ServiceState.AppendLog($"Could not start tunnel: {e.Message}");
                        ServiceState.WriteStatus(VpnStatus.Error, e.Message);
                    }
                }
            }
            else if (!desired && tunnelStarted)
            {
                if (StopTunnelWithRetry(executableRemoved ? "application removed" : "user disconnect"))
                {
                    tunnelStarted = false;
                    last = VpnStatus.Disconnected;
                    lastExtra = null;
                }
            }

            if (tunnelStarted)
            {
                // The GUI's NetworkAddressChanged handler is not the owner of this headless
                // tunnel. Poll the filtered physical signature here so Wi-Fi/Ethernet, DHCP
                // and resolver changes reach the daemon without a transport timeout.
                try { tunnel.OnNetworkChanged(); }
                catch (Exception e) { ServiceState.AppendLog($"Network-state poll failed: {e.Message}"); }
                ServiceState.WriteStatus(last, lastExtra,
                    tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
            }
            else
            {
                ServiceState.WriteStatus(VpnStatus.Disconnected,
                    executableRemoved ? "Qeli.app was removed; connection disabled" :
                    desired ? "no profile configured" : "connection disabled");
            }
            stop.Wait(1000);
        }

        ServiceState.AppendLog("Daemon stopping");
        if (!tunnelStarted || StopTunnelWithRetry("launchd stop"))
            ServiceState.WriteStatus(VpnStatus.Disconnected, null);
        else
            throw new InvalidOperationException(
                "daemon stopped before the original macOS DNS settings could be restored");
    }
}
