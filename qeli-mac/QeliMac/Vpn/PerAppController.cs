using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliMac.Vpn;

/// <summary>
/// Bridge to the signed macOS transparent-proxy system extension. The extension classifies
/// flows by source-app signing identifier and relays selected TCP/UDP sockets through the
/// active utun using Darwin's public IP_BOUND_IF/IPV6_BOUND_IF socket options.
///
/// The .NET client deliberately does not emulate this with pf process polling: that has a
/// first-packet leak race and PF is not a supported application API. If the signed helper is
/// absent or the extension is not approved, an app-filtered profile is refused rather than
/// silently widening to a system-wide tunnel.
/// </summary>
internal sealed class PerAppController
{
    internal const string HelperName = "QeliPerAppCtl";
    private readonly Action<string> _log;
    private bool _started;
    private Process? _guardian;

    public PerAppController(Action<string> log) => _log = log;

    /// <summary>Ask macOS to activate/approve the embedded system extension from the
    /// interactive GUI session before a root LaunchDaemon attempts to start the profile.</summary>
    public static void PrepareInstallation()
    {
        string helper = Path.Combine(AppContext.BaseDirectory, HelperName);
        if (!OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("macOS per-app routing can only run on macOS");
        if (!OperatingSystem.IsMacOSVersionAtLeast(13))
            throw new PlatformNotSupportedException("macOS per-app routing requires macOS 13 or newer");
        if (!File.Exists(helper))
            throw new InvalidOperationException(
                "per-app routing is unavailable in this ad-hoc build; install the signed "
                + "Developer-ID Qeli build containing the Network Extension");
        Run(helper, "prepare");
    }

    public void StartOrUpdate(
        VpnConfig config,
        string interfaceName,
        IPAddress carrierIp,
        IReadOnlyList<string> dnsServers,
        IReadOnlyList<string> includeRoutes,
        IReadOnlyList<string> excludeRoutes,
        IReadOnlyList<string> pushedRoutes,
        bool tunnelUp)
    {
        string helper = Path.Combine(AppContext.BaseDirectory, HelperName);
        if (!OperatingSystem.IsMacOS())
            throw new PlatformNotSupportedException("macOS per-app routing can only run on macOS");
        if (!OperatingSystem.IsMacOSVersionAtLeast(13))
            throw new PlatformNotSupportedException("macOS per-app routing requires macOS 13 or newer");
        if (!File.Exists(helper))
            throw new InvalidOperationException(
                "per-app routing requires the signed Qeli transparent-proxy system extension; "
                + $"{HelperName} is not present in this build. Use the Developer-ID macOS build.");
        if (!config.Apps.Any(IsMacSigningIdentifier))
            throw new InvalidOperationException(
                "per-app profile contains no macOS bundle signing identifiers; add at least "
                + "one value such as com.apple.Safari (foreign identifiers are preserved)");

        var state = new RoutingState
        {
            Version = 2,
            TunnelUp = tunnelUp,
            // The guardian installs this state before activation and then renews it to a
            // rolling five-second lease, including while macOS waits for user approval.
            LeaseExpiresAtUnixMs = DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeMilliseconds(),
            InterfaceName = interfaceName,
            Mode = config.AppsMode,
            Apps = config.Apps.Distinct(StringComparer.Ordinal).ToArray(),
            DnsServers = dnsServers.ToArray(),
            CarrierAddress = carrierIp.ToString(),
            CarrierPort = config.Port,
            CarrierProtocol = config.Protocol,
            AllowIpv6Leak = config.AllowIpv6Leak,
            FullTunnel = config.IsFullTunnel,
            RouteLocalNetworks = config.RouteLocalNetworks,
            IncludeRoutes = includeRoutes.ToArray(),
            ExcludeRoutes = excludeRoutes.ToArray(),
            PushedRoutes = pushedRoutes.ToArray(),
            AlwaysBypassApps = new[] { "ru.qeli.app", "ru.qeli.app.perapp" },
        };

        string json = JsonSerializer.Serialize(state, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        string stateFile = Path.Combine(Path.GetTempPath(),
            $"qeli-per-app-{Environment.ProcessId}-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(stateFile, json);
            bool wasStarted = _started;
            try
            {
                // Pass the pending state to a new guardian so it can start renewing before
                // activation blocks on System Settings approval. No multi-minute stale lease
                // is needed even if power is lost in that window.
                EnsureGuardian(helper, stateFile);
                Run(helper, _started ? "update" : "start", stateFile);
                if (_guardian is not { HasExited: false })
                    throw new InvalidOperationException(
                        $"{HelperName} guardian exited before activation completed");
                _started = true;
            }
            catch
            {
                if (wasStarted)
                {
                    // An update failure must not disable the already-installed transparent
                    // proxy: selected applications would immediately fall back to the physical
                    // network. Publish the pending policy as tunnel-down instead. Providers
                    // monitor the shared state file even when their explicit refresh message
                    // fails, and the guardian keeps the fail-closed lease alive for retries.
                    state.TunnelUp = false;
                    try
                    {
                        File.WriteAllText(stateFile, JsonSerializer.Serialize(state,
                            new JsonSerializerOptions
                            {
                                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                            }));
                        Run(helper, "update", stateFile);
                    }
                    catch (Exception recoveryError)
                    {
                        _log("WARN: could not publish fail-closed per-app recovery state: "
                            + recoveryError.Message);
                    }
                    try { EnsureGuardian(helper, stateFile); }
                    catch (Exception guardianError)
                    {
                        _log("WARN: could not restart the per-app guardian: "
                            + guardianError.Message);
                    }
                    _started = true;
                }
                else
                {
                    _started = false;
                    try { Run(helper, "stop"); } catch { }
                    StopGuardian();
                }
                throw;
            }
            _log($"macOS per-app proxy {(wasStarted ? "updated" : "ACTIVE")}: "
                + $"mode={config.AppsMode}, apps={config.Apps.Count}, interface={interfaceName}");
        }
        finally
        {
            try { File.Delete(stateFile); } catch { }
        }
    }

    private static bool IsMacSigningIdentifier(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains('\\')
        && !value.Contains('/')
        && value.Contains('.');

    public void SetTunnelDown()
    {
        if (!_started) return;
        string helper = Path.Combine(AppContext.BaseDirectory, HelperName);
        if (!File.Exists(helper)) return;
        try { Run(helper, "down"); }
        catch (Exception error) { _log($"WARN: could not fail-close per-app proxy: {error.Message}"); }
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;
        string helper = Path.Combine(AppContext.BaseDirectory, HelperName);
        try
        {
            if (File.Exists(helper)) Run(helper, "stop");
            else _log("WARN: per-app helper disappeared; expiring its guardian lease");
        }
        catch (Exception error) { _log($"WARN: could not stop per-app proxy: {error.Message}"); }
        finally
        {
            // Even if NetworkExtension preferences could not be disabled, providers fail
            // open within five seconds once this process stops renewing their lease.
            StopGuardian();
        }
    }

    private void EnsureGuardian(string helper, string stateFile)
    {
        if (_guardian is { HasExited: false }) return;
        _guardian?.Dispose();
        string executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("could not locate the qeli executable");
        var psi = new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        psi.ArgumentList.Add("guard");
        psi.ArgumentList.Add(Environment.ProcessId.ToString());
        psi.ArgumentList.Add(executable);
        psi.ArgumentList.Add(stateFile);
        _guardian = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start {HelperName} guardian");
    }

    private void StopGuardian()
    {
        var guardian = _guardian;
        _guardian = null;
        if (guardian == null) return;
        try { if (!guardian.HasExited) guardian.Kill(entireProcessTree: true); } catch { }
        guardian.Dispose();
    }

    private static void Run(string helper, params string[] arguments)
    {
        var psi = new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        foreach (string argument in arguments) psi.ArgumentList.Add(argument);
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"could not start {HelperName}");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        // First activation may wait while the user approves the system extension in
        // System Settings. Subsequent start/update calls normally finish immediately.
        if (!process.WaitForExit(190_000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"{HelperName} timed out");
        }
        string output = stdout.GetAwaiter().GetResult().Trim();
        string error = stderr.GetAwaiter().GetResult().Trim();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"{HelperName} failed ({process.ExitCode}): " + (error.Length > 0 ? error : output));
    }

    private sealed class RoutingState
    {
        public int Version { get; init; }
        public bool TunnelUp { get; set; }
        public long LeaseExpiresAtUnixMs { get; init; }
        public string InterfaceName { get; init; } = "";
        public string Mode { get; init; } = "all";
        public string[] Apps { get; init; } = Array.Empty<string>();
        public string[] DnsServers { get; init; } = Array.Empty<string>();
        public string CarrierAddress { get; init; } = "";
        public int CarrierPort { get; init; }
        public string CarrierProtocol { get; init; } = "tcp";
        public bool AllowIpv6Leak { get; init; }
        public bool FullTunnel { get; init; }
        public bool RouteLocalNetworks { get; init; }
        public string[] IncludeRoutes { get; init; } = Array.Empty<string>();
        public string[] ExcludeRoutes { get; init; } = Array.Empty<string>();
        public string[] PushedRoutes { get; init; } = Array.Empty<string>();
        public string[] AlwaysBypassApps { get; init; } = Array.Empty<string>();
    }
}
