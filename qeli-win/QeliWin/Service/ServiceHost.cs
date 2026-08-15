using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.IO;
using QeliWin.Vpn;
using Qeli.Shared.Vpn;

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
        VpnStatus last = VpnStatus.Disconnected;
        string? lastExtra = null;
        tunnel.LogLine += ServiceState.AppendLog;
        tunnel.StatusChanged += (s, extra) =>
        {
            last = s; lastExtra = extra;
            ServiceState.WriteStatus(s, extra, tunnel.BytesUp, tunnel.BytesDown, tunnel.ConnectedSince);
        };
        tunnel.ConnectionDropped += msg => ServiceState.AppendLog($"Connection lost: {msg}");

        bool started = false;
        bool startRefused = false;
        bool missingProfileLogged = false;
        bool missingExecutableLogged = false;
        try
        {
            // SCM intentionally auto-starts this worker at boot, but the worker is idle
            // until the user's persistent intent says Connect. This separates "daemon is
            // available" from "VPN should be connected" and prevents a stopped tunnel from
            // silently returning after reboot.
            while (!stoppingToken.IsCancellationRequested)
            {
                bool desired = ServiceState.DesiredConnected();
                if (!desired) startRefused = false;
                string? executable = Environment.ProcessPath;
                if (desired && (string.IsNullOrEmpty(executable) || !File.Exists(executable)))
                {
                    if (!missingExecutableLogged)
                    {
                        ServiceState.AppendLog(
                            "Qeli executable disappeared — disabling boot connection and cleaning up");
                        missingExecutableLogged = true;
                    }
                    ServiceState.SetDesiredConnected(false);
                    desired = false;
                }

                if (desired && !started && !startRefused)
                {
                    var cfg = ServiceState.LoadProfile();
                    if (cfg == null)
                    {
                        if (!missingProfileLogged)
                        {
                            ServiceState.AppendLog(
                                "No service profile configured — staying disconnected");
                            missingProfileLogged = true;
                        }
                        ServiceState.WriteStatus(VpnStatus.Disconnected, null);
                    }
                    else
                    {
                        missingProfileLogged = false;
                        ServiceState.AppendLog($"Connecting profile '{cfg.DisplayName}'");
                        tunnel.LogLevel = cfg.LoggingLevel;
                        started = tunnel.Start(cfg);
                        startRefused = !started;
                    }
                }
                else if (!desired && started)
                {
                    started = !StopWithRetry(tunnel);
                    if (!started)
                    {
                        last = VpnStatus.Disconnected;
                        lastExtra = null;
                        ServiceState.WriteStatus(last, null);
                    }
                }

                if (started)
                {
                    // In service mode the GUI has no in-process tunnel and its
                    // NetworkAddressChanged/PowerModeChanged handlers cannot reach this instance.
                    try { tunnel.OnNetworkChanged(); }
                    catch (Exception e)
                    {
                        ServiceState.AppendLog($"Network-state poll failed: {e.Message}");
                    }
                    ServiceState.WriteStatus(last, lastExtra, tunnel.BytesUp, tunnel.BytesDown,
                        tunnel.ConnectedSince);
                }
                else if (desired && last == VpnStatus.Error)
                    ServiceState.WriteStatus(last, lastExtra);
                else ServiceState.WriteStatus(VpnStatus.Disconnected, null);

                try { await Task.Delay(1000, stoppingToken); }
                catch (TaskCanceledException) { break; }
            }
        }
        finally
        {
            ServiceState.AppendLog("Service stopping");
            if (started) StopWithRetry(tunnel);
            ServiceState.WriteStatus(VpnStatus.Disconnected, null);
        }
    }

    private static bool StopWithRetry(VpnTunnel tunnel)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try { tunnel.Stop(); return true; }
            catch (Exception error)
            {
                ServiceState.AppendLog(
                    $"Tunnel cleanup attempt {attempt}/3 failed: {error.Message}");
                if (attempt < 3) Thread.Sleep(250);
            }
        }
        ServiceState.AppendLog(
            "SECURITY: tunnel cleanup remains incomplete; service stays in Error for retry");
        return false;
    }
}
