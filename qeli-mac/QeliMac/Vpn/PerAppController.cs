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
    private const int RoutingStateVersion = 5;
    private readonly Action<string> _log;
    private bool _started;
    private bool _proxyStopped;
    private Process? _guardian;
    private bool _guardianReady;
    private string _ownerToken = Guid.NewGuid().ToString("N");

    private readonly string _helperPath;
    private readonly Action _validatePlatform;
    private readonly Action<string[]> _invoke;
    private readonly Action<string> _ensureGuardian;
    private readonly Func<bool> _guardianAlive;
    private readonly Action _stopGuardian;
    internal bool Started => _started;
    internal const int MaximumStateBytes = 1024 * 1024;

    public PerAppController(Action<string> log)
    {
        _log = log; _helperPath = Path.Combine(AppContext.BaseDirectory, HelperName);
        _validatePlatform = ValidatePlatform;
        _invoke = args => Run(_helperPath, args);
        _ensureGuardian = state => EnsureGuardian(_helperPath, state);
        _guardianAlive = () => _guardianReady && _guardian is { HasExited: false };
        _stopGuardian = StopGuardian;
    }

    internal PerAppController(Action<string> log, string helperPath, Action validatePlatform,
        Action<string[]> invoke, Action<string> ensureGuardian, Func<bool> guardianAlive,
        Action stopGuardian)
    {
        _log = log; _helperPath = helperPath; _validatePlatform = validatePlatform;
        _invoke = invoke; _ensureGuardian = ensureGuardian;
        _guardianAlive = guardianAlive; _stopGuardian = stopGuardian;
    }

    private static void ValidatePlatform()
    {
        if (!OperatingSystem.IsMacOS() || !OperatingSystem.IsMacOSVersionAtLeast(13))
            throw new PlatformNotSupportedException("macOS per-app routing requires macOS 13 or newer");
    }

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
        IReadOnlyList<string> tunnelSubnets,
        IReadOnlyList<string> physicalLocalRoutes,
        bool tunnelIpv4,
        bool tunnelIpv6,
        bool tunnelUp)
    {
        if (_proxyStopped) throw new InvalidOperationException("Join the retiring per-app guardian before reconfiguration");
        string helper = _helperPath;
        _validatePlatform();
        if (!File.Exists(helper)) throw new InvalidOperationException(
            $"per-app routing requires the signed {HelperName} helper");
        if (!config.Apps.Any(IsMacSigningIdentifier))
            throw new InvalidOperationException(
                "per-app profile contains no macOS bundle signing identifiers; add at least "
                + "one value such as com.apple.Safari (foreign identifiers are preserved)");

        var state = new RoutingState
        {
            Version = RoutingStateVersion,
            OwnerToken = _ownerToken,
            OwnerPid = Environment.ProcessId,
            TunnelUp = tunnelUp,
            // The guardian installs this state before activation and then renews it to a
            // rolling five-second lease, including while macOS waits for user approval.
            LeaseExpiresAtUnixMs = DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeMilliseconds(),
            InterfaceName = interfaceName,
            Mode = config.AppsMode.ToLowerInvariant(),
            Apps = config.Apps.Distinct(StringComparer.Ordinal).ToArray(),
            DnsServers = dnsServers.ToArray(),
            CarrierAddress = carrierIp.ToString(),
            CarrierPort = config.Port,
            CarrierProtocol = config.Protocol,
            TunnelIpv4 = tunnelIpv4,
            TunnelIpv6 = tunnelIpv6,
            AllowIpv4Leak = config.AllowIpv4Leak,
            AllowIpv6Leak = config.AllowIpv6Leak,
            FullTunnel = config.IsFullTunnel,
            RouteLocalNetworks = config.RouteLocalNetworks,
            IncludeRoutes = includeRoutes.ToArray(),
            ExcludeRoutes = excludeRoutes.ToArray(),
            PushedRoutes = pushedRoutes.ToArray(),
            TunnelSubnets = tunnelSubnets.ToArray(),
            PhysicalLocalRoutes = physicalLocalRoutes.ToArray(),
            AlwaysBypassApps = new[] { "ru.qeli.app", "ru.qeli.app.perapp" },
        };

        string json = JsonSerializer.Serialize(state, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        // Unix shared temp is not a handoff trust boundary: use an exclusive owner-only
        // directory and file. Keep recovery rewrites in that same private directory.
        byte[] payload = System.Text.Encoding.UTF8.GetBytes(json);
        if (payload.Length > MaximumStateBytes) throw new InvalidDataException("per-app state exceeds its budget");
        var stateDirectory = Directory.CreateTempSubdirectory("qeli-per-app-");
        string stateFile = Path.Combine(stateDirectory.FullName, "state.json");
        try
        {
            WriteState(stateFile, payload, createNew: true);
            bool wasStarted = _started;
            try
            {
                // Pass the pending state to a new guardian so it can start renewing before
                // activation blocks on System Settings approval. No multi-minute stale lease
                // is needed even if power is lost in that window.
                _ensureGuardian(stateFile);
                _invoke(new[] { _started ? "update" : "start", stateFile });
                if (!_guardianAlive())
                    throw new InvalidOperationException(
                        $"{HelperName} guardian exited before activation completed");
                _started = true;
            }
            catch (Exception startError)
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
                        WriteState(stateFile, JsonSerializer.SerializeToUtf8Bytes(state,
                            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }), false);
                        _invoke(new[] { "update", stateFile });
                    }
                    catch (Exception recoveryError)
                    {
                        Note("WARN: could not publish fail-closed per-app recovery state: "
                            + recoveryError.Message);
                    }
                    try { _ensureGuardian(stateFile); }
                    catch (Exception guardianError)
                    {
                        Note("WARN: could not restart the per-app guardian: "
                            + guardianError.Message);
                    }
                    _started = true;
                }
                else
                {
                    // Activation may have succeeded partially. Retain cleanup ownership
                    // and the lease until both proxy stop and guardian join are confirmed.
                    _started = true;
                    try { Stop(); }
                    catch (Exception cleanupError) {
                        throw new AggregateException("per-app start and rollback failed", startError, cleanupError);
                    }
                }
                throw;
            }
            Note($"macOS per-app proxy {(wasStarted ? "updated" : "ACTIVE")}: "
                + $"mode={config.AppsMode}, apps={config.Apps.Count}, interface={interfaceName}");
        }
        finally
        {
            try { File.Delete(Path.Combine(stateDirectory.FullName, "ready")); File.Delete(stateFile); stateDirectory.Delete(); }
            catch (Exception error) { Note("WARN: could not remove private per-app handoff: " + error.Message); }
        }
    }

    private void Note(string message) { try { _log(message); } catch { /* Observer is not lifecycle control. */ } }

    private static bool IsMacSigningIdentifier(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains('\\')
        && !value.Contains('/')
        && value.Contains('.');

    public void SetTunnelDown()
    {
        if (!_started) return;
        RequireHelper();
        _invoke(new[] { "down", _ownerToken }); // A refusal must stop reconnect before TUN mutation.
    }

    public void Stop()
    {
        if (!_started) return;
        if (!_proxyStopped)
        {
            RequireHelper();
            _invoke(new[] { "stop", _ownerToken });
            _proxyStopped = true; // A join retry must not stop a later owner.
        }
        _stopGuardian();
        _started = false; _proxyStopped = false; // Failed join stays active and can be retried.
        _ownerToken = Guid.NewGuid().ToString("N"); // Never reuse a retired generation.
    }

    private void RequireHelper()
    {
        if (!File.Exists(_helperPath)) throw new IOException(
            "per-app helper disappeared; cleanup cannot be confirmed");
    }

    private static void WriteState(string path, byte[] payload, bool createNew)
    {
        if (payload.Length > MaximumStateBytes) throw new InvalidDataException("per-app state exceeds its budget");
        var options = new FileStreamOptions { Mode = createNew ? FileMode.CreateNew : FileMode.Create,
            Access = FileAccess.Write, Share = FileShare.Read };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var file = new FileStream(path, options); file.Write(payload); file.Flush(true);
    }

    private void EnsureGuardian(string helper, string stateFile)
    {
        if (_guardian is { HasExited: false })
        {
            if (!_guardianReady) throw new IOException("Retire the unacknowledged per-app guardian before retry");
            return;
        }
        _guardian?.Dispose();
        _guardian = null; _guardianReady = false;
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
        WaitGuardianReady(_guardian, Path.Combine(Path.GetDirectoryName(stateFile)!, "ready"), _ownerToken);
        _guardianReady = true;
    }

    // A live child is not proof that it consumed the handoff. The helper publishes the
    // exact generation token only after parent validation and an exclusive state claim.
    internal static void WaitGuardianReady(Process guardian, string readyFile, string token, int budgetMs = 5_000)
    {
        if (budgetMs <= 0 || !Guid.TryParseExact(token, "N", out var id) || id.ToString("N") != token)
            throw new ArgumentException("Invalid guardian readiness request");
        var watch = Stopwatch.StartNew();
        Span<byte> bytes = stackalloc byte[33];
        while (watch.ElapsedMilliseconds < budgetMs)
        {
            if (guardian.HasExited) throw new IOException("per-app guardian exited before readiness");
            try
            {
                using var file = new FileStream(readyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                int count = 0, read;
                while (count < bytes.Length && (read = file.Read(bytes[count..])) > 0) count += read;
                if (count != 32 || System.Text.Encoding.UTF8.GetString(bytes[..count]) != token)
                    throw new InvalidDataException("Invalid per-app guardian readiness token");
                if (guardian.HasExited) throw new IOException("per-app guardian exited after readiness");
                return;
            }
            catch (FileNotFoundException) { }
            Thread.Sleep(20);
        }
        throw new TimeoutException("per-app guardian did not acknowledge readiness");
    }

    private void StopGuardian()
    {
        var guardian = _guardian;
        if (guardian == null) return;
        JoinGuardian(guardian);
        guardian.Dispose();
        _guardian = null; _guardianReady = false;
    }

    internal static void JoinGuardian(Process guardian)
    {
        if (!guardian.HasExited) guardian.Kill(entireProcessTree: true);
        if (!guardian.WaitForExit(5_000)) throw new TimeoutException("per-app guardian did not exit");
    }

    internal static void Run(string helper, params string[] arguments)
    {
        var start = new ProcessStartInfo(helper) { WorkingDirectory = AppContext.BaseDirectory };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        // Activation may await user approval. Pipe EOF shares this deadline and both
        // streams are capped; a descendant cannot keep an exited helper waiting forever.
        ToolProcess.RequireSuccess(ToolProcess.Run(start, 190_000), HelperName);
    }

    private sealed class RoutingState
    {
        public int Version { get; init; }
        public string OwnerToken { get; init; } = "";
        public int OwnerPid { get; init; }
        public bool OwnerReleased { get; init; }
        public bool TunnelUp { get; set; }
        public long LeaseExpiresAtUnixMs { get; init; }
        public string InterfaceName { get; init; } = "";
        public string Mode { get; init; } = "all";
        public string[] Apps { get; init; } = Array.Empty<string>();
        public string[] DnsServers { get; init; } = Array.Empty<string>();
        public string CarrierAddress { get; init; } = "";
        public int CarrierPort { get; init; }
        public string CarrierProtocol { get; init; } = "tcp";
        public bool TunnelIpv4 { get; init; }
        public bool TunnelIpv6 { get; init; }
        public bool AllowIpv4Leak { get; init; }
        public bool AllowIpv6Leak { get; init; }
        public bool FullTunnel { get; init; }
        public bool RouteLocalNetworks { get; init; }
        public string[] IncludeRoutes { get; init; } = Array.Empty<string>();
        public string[] ExcludeRoutes { get; init; } = Array.Empty<string>();
        public string[] PushedRoutes { get; init; } = Array.Empty<string>();
        public string[] TunnelSubnets { get; init; } = Array.Empty<string>();
        public string[] PhysicalLocalRoutes { get; init; } = Array.Empty<string>();
        public string[] AlwaysBypassApps { get; init; } = Array.Empty<string>();
    }
}
