using System.Net;
using System.Text.Json;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Vpn;

public sealed partial class VpnTunnel
{
    private readonly Dictionary<ulong, RoamingObservation> _roamingObservations = new();
    private readonly Dictionary<ulong, RoamingCandidate> _roamingCandidates = new();

    private sealed record RoamingObservation(
        ulong Generation,
        string PathIdentity,
        VpnConfig Config,
        string[] CarrierAddresses);

    private sealed class RoamingCandidate
    {
        public required ulong Generation { get; init; }
        public required ulong CandidateId { get; init; }
        public required ulong UpdateId { get; init; }
        public required string PathIdentity { get; init; }
        public required VpnConfig Config { get; init; }
        public required string[] OldCarriers { get; init; }
        public required string[] NewCarriers { get; init; }
        public required string[] UnionCarriers { get; init; }
        public required NetworkConfigurator.RoamingRouteLease Routes { get; init; }
        public bool Bound { get; set; }
    }

    // A fixed source address/port is an explicit user routing contract. The candidate
    // factory intentionally uses a fresh ephemeral socket, so such profiles retain the
    // reconnect fallback. Every ordinary TCP and UDP camouflage mode shares this executor.
    protected override ulong NativeRoamingCapabilities(VpnConfig config) =>
        AllowsNativePathRoaming(config)
            ? NativeRoamingPathCapabilities | NativePathRefreshCapability
            : 0;

    internal static bool AllowsNativePathRoaming(VpnConfig config) =>
        !config.RoamingPolicy.Equals("off", StringComparison.OrdinalIgnoreCase)
        && string.IsNullOrWhiteSpace(config.LocalAddress) && config.LocalPort == 0;

    internal static void RunRoamingCapabilitySelfTest(Action<string, bool> check)
    {
        var ordinaryProfiles = new[]
        {
            new VpnConfig { Protocol = "tcp", WireMode = "fake-tls" },
            new VpnConfig { Protocol = "tcp", WireMode = "plain" },
            new VpnConfig { Protocol = "udp", WireMode = "fake-tls" },
            new VpnConfig { Protocol = "udp", WireMode = "fake-tls", QuicEnabled = true },
            new VpnConfig { Protocol = "udp", WireMode = "obfs" },
        };
        check("macOS native path roaming covers TCP and every UDP camouflage mode",
            ordinaryProfiles.All(AllowsNativePathRoaming));
        check("macOS fixed local address or port stays on reconnect fallback",
            !AllowsNativePathRoaming(new VpnConfig { LocalAddress = "192.0.2.10" })
            && !AllowsNativePathRoaming(new VpnConfig { LocalPort = 41000 }));
        check("macOS roaming = off disables the native path executor",
            !AllowsNativePathRoaming(new VpnConfig { RoamingPolicy = "off" }));
    }

    protected override NativePathUpdate? CaptureNativeRoamingPath(VpnConfig config,
        IReadOnlyList<string> carrierAddresses, ulong generation, ulong updateId, string reason)
    {
        IPAddress[] carriers = carrierAddresses
            .Select(IPAddress.Parse)
            .Distinct()
            .ToArray();
        NativePathUpdate update = (_net ?? throw new InvalidOperationException(
            "macOS network configurator is not active")).CaptureRoamingPath(
                carriers, generation, updateId, reason);
        if (_roamingObservations.Count >= 16)
            _roamingObservations.Remove(_roamingObservations.Keys.Min());
        _roamingObservations[updateId] = new RoamingObservation(
            generation, PathIdentity(update), config,
            carriers.Select(item => item.ToString()).ToArray());
        return update;
    }

    protected override void ApplyNativeRoamingCommand(NativePathCommand command)
    {
        switch (command.Action)
        {
            case "prepare_path": PrepareRoamingCandidate(command); break;
            case "bind_socket": BindRoamingCandidate(command); break;
            case "commit_path": CommitRoamingCandidate(command); break;
            case "abort_path": AbortRoamingCandidate(command); break;
            default:
                throw new InvalidOperationException(
                $"unsupported macOS roaming action {command.Action}");
        }
    }

    protected override void ResetNativeRoamingPath()
    {
        var failures = new List<string>();
        foreach (RoamingCandidate candidate in _roamingCandidates.Values.ToArray())
        {
            try
            {
                AbortCandidate(candidate);
                _roamingCandidates.Remove(candidate.CandidateId);
            }
            catch (Exception error) { failures.Add(error.Message); }
        }
        _roamingObservations.Clear();
        if (failures.Count != 0)
            throw new InvalidOperationException(
                "macOS roaming cleanup failed: " + string.Join("; ", failures));
    }

    private void PrepareRoamingCandidate(NativePathCommand command)
    {
        if (_roamingCandidates.Count != 0)
            throw new InvalidOperationException("another macOS roaming candidate is already active");
        if (!_roamingObservations.TryGetValue(command.Path.UpdateId, out var observation)
            || observation.Generation != command.Generation
            || observation.PathIdentity != PathIdentity(command.Path))
            throw new InvalidOperationException("macOS roaming PREPARE does not match an observation");

        string[] next = command.Path.ResolvedAddresses
            .Select(item => IPAddress.Parse(item.Address).ToString())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        string[] union = observation.CarrierAddresses.Concat(next)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        NetworkConfigurator.RoamingRouteLease routes = (_net
            ?? throw new InvalidOperationException("macOS network configurator is not active"))
            .PrepareRoamingRoutes(command.Path);
        var candidate = new RoamingCandidate
        {
            Generation = command.Generation,
            CandidateId = command.CandidateId,
            UpdateId = command.Path.UpdateId,
            PathIdentity = observation.PathIdentity,
            Config = observation.Config,
            OldCarriers = observation.CarrierAddresses,
            NewCarriers = next,
            UnionCarriers = union,
            Routes = routes,
        };
        try
        {
            SetCandidatePolicy(candidate, union);
        }
        catch (Exception setupError)
        {
            var rollbackFailures = new List<Exception>();
            try { routes.Abort(); }
            catch (Exception error) { rollbackFailures.Add(error); }
            try { SetCandidatePolicy(candidate, candidate.OldCarriers); }
            catch (Exception error) { rollbackFailures.Add(error); }
            if (rollbackFailures.Count != 0)
            {
                rollbackFailures.Insert(0, setupError);
                throw new NativeRoamingPlatformStateUnknownException(
                    "macOS roaming PREPARE and rollback both failed",
                    new AggregateException(rollbackFailures));
            }
            throw;
        }
        _roamingCandidates.Add(command.CandidateId, candidate);
        Log($"macOS roaming PREPARE {command.CandidateId}: interface "
            + $"{command.Path.NetworkToken}, carriers {string.Join(", ", union)}");
    }

    private void BindRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        if (candidate.Bound)
            throw new InvalidOperationException("macOS roaming candidate socket is already bound");
        uint interfaceIndex = command.Path.InterfaceIndex
            ?? throw new InvalidOperationException("macOS roaming BIND has no interface index");
        long socket = command.SocketHandle
            ?? throw new InvalidOperationException("macOS roaming BIND has no socket handle");
        MacRoamingSocket.Bind(socket, interfaceIndex,
            command.Path.LocalAddresses.Select(IPAddress.Parse).ToArray());
        candidate.Bound = true;
        Log($"macOS roaming BIND {command.CandidateId}: fd {socket} -> if {interfaceIndex}");
    }

    private void CommitRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        if (!candidate.Bound)
            throw new InvalidOperationException("macOS roaming COMMIT arrived before BIND");
        SetCandidatePolicy(candidate, candidate.NewCarriers);
        try
        {
            (_net ?? throw new InvalidOperationException(
                "macOS network configurator is not active"))
                .CommitRoamingServerRoutes(command.Path);
            candidate.Routes.Commit();
        }
        catch (Exception routeError)
        {
            try { SetCandidatePolicy(candidate, candidate.UnionCarriers); }
            catch (Exception policyError)
            {
                throw new NativeRoamingPlatformStateUnknownException(
                    "macOS roaming route commit and policy rollback both failed",
                    new AggregateException(routeError, policyError));
            }
            throw;
        }
        _roamingCandidates.Remove(candidate.CandidateId);
        _roamingObservations.Remove(candidate.UpdateId);
        Log($"macOS roaming COMMIT {candidate.CandidateId}: "
            + string.Join(", ", candidate.NewCarriers));
    }

    private void AbortRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        AbortCandidate(candidate);
        _roamingCandidates.Remove(candidate.CandidateId);
        _roamingObservations.Remove(candidate.UpdateId);
        Log($"macOS roaming ABORT {candidate.CandidateId}");
    }

    private void AbortCandidate(RoamingCandidate candidate)
    {
        var failures = new List<Exception>();
        try { candidate.Routes.Abort(); }
        catch (Exception error) { failures.Add(error); }
        try { SetCandidatePolicy(candidate, candidate.OldCarriers); }
        catch (Exception error) { failures.Add(error); }
        if (failures.Count != 0)
            throw new AggregateException("macOS roaming rollback failed", failures);
    }

    private RoamingCandidate GetCandidate(NativePathCommand command)
    {
        if (!_roamingCandidates.TryGetValue(command.CandidateId, out var candidate)
            || candidate.Generation != command.Generation
            || candidate.PathIdentity != PathIdentity(command.Path))
            throw new InvalidOperationException("macOS roaming command is stale or mismatched");
        return candidate;
    }

    private void SetCandidatePolicy(RoamingCandidate candidate, string[] next)
    {
        if (EgressGuardEngaged && !candidate.Config.UsesAppFilter)
            KillSwitch.UpdateServerAddresses(next, Log);
    }

    private static string PathIdentity(NativePathUpdate path) =>
        JsonSerializer.Serialize(path);
}
