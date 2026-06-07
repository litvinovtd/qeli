using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using QeliWin.Vpn;

namespace QeliWin.Service;

/// <summary>Boots the generic host configured as a Windows Service.</summary>
public static class ServiceHostRunner
{
    public static void Run()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddWindowsService(o => o.ServiceName = ServiceManager.ServiceName);
        builder.Services.AddHostedService<QeliWorker>();
        builder.Build().Run();
    }
}

/// <summary>
/// The actual VPN, running headless under LocalSystem. Loads the configured profile,
/// brings up the tunnel (Wintun works in session 0), self-reconnects, and mirrors
/// status/log into %ProgramData% files the GUI reads.
/// </summary>
public sealed class QeliWorker : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceState.ResetLog();
        ServiceState.AppendLog("Service starting");

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
            ServiceState.AppendLog("No service profile configured — nothing to do");
            ServiceState.WriteStatus(VpnStatus.Disconnected, null);
            return;
        }

        ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
        tunnel.Start(cfg);

        // Periodically publish live stats (bytes/session) for the GUI to read.
        while (!stoppingToken.IsCancellationRequested)
        {
            ServiceState.WriteStatus(last, lastExtra, tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
            try { await Task.Delay(1000, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }

        ServiceState.AppendLog("Service stopping");
        tunnel.Stop();
        ServiceState.WriteStatus(VpnStatus.Disconnected, null);
    }
}
