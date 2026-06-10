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
        using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => stop.Set());
        using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, _ => stop.Set());

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
            ServiceState.AppendLog("No daemon profile configured — nothing to do");
            ServiceState.WriteStatus(VpnStatus.Disconnected, null);
            return;
        }

        ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
        tunnel.Start(cfg);

        // Periodically publish live stats (bytes/session) for the GUI to read.
        while (!stop.IsSet)
        {
            ServiceState.WriteStatus(last, lastExtra, tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
            stop.Wait(1000);
        }

        ServiceState.AppendLog("Daemon stopping");
        tunnel.Stop();
        ServiceState.WriteStatus(VpnStatus.Disconnected, null);
    }
}
