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

        using var stop = new ManualResetEventSlim(false);
        // Cancel the DEFAULT signal disposition (terminate): otherwise the process can exit
        // before the loop reaches tunnel.Stop() below, leaving pf/DNS/route state up. (C-08)
        using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.Set(); });
        using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.Set(); });

        var tunnel = new VpnTunnel();
        var lifecycle = new DaemonLifecycle(ServiceState.LoadProfile, cfg =>
        {
            ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
            tunnel.LogLevel = cfg.LoggingLevel;
            return tunnel.Start(cfg);
        }, tunnel.Stop, ServiceState.AppendLog);
        tunnel.LogLine += ServiceState.AppendLog;
        tunnel.StatusChanged += (status, extra) =>
        {
            lifecycle.Observe(status, extra);
            lifecycle.Publish((state, detail) => ServiceState.WriteStatus(state, detail,
                tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince));
        };
        tunnel.ConnectionDropped += msg => ServiceState.AppendLog($"Connection lost: {msg}");
        bool executableRemoved = false;
        string? executablePath = Environment.ProcessPath;

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
            lifecycle.Step(desired);
            if (lifecycle.CanPoll)
            {
                try { tunnel.OnNetworkChanged(); }
                catch (Exception e) { ServiceState.AppendLog($"Network-state poll failed: {e.Message}"); }
            }
            lifecycle.Publish((state, detail) => ServiceState.WriteStatus(state,
                executableRemoved && state == VpnStatus.Disconnected
                    ? "Qeli.app was removed; connection disabled" : detail,
                tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince));
            stop.Wait(1000);
        }

        ServiceState.AppendLog("Daemon stopping");
        try { lifecycle.Shutdown(); }
        finally { lifecycle.Publish((state, detail) => ServiceState.WriteStatus(state, detail)); }
    }
}
