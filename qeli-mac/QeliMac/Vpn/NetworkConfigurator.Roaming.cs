using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Qeli.Shared.Vpn;

namespace QeliMac.Vpn;

public sealed partial class NetworkConfigurator
{
    internal sealed record RoamingRouteKey(
        string Address, string Interface, string NextHop);

    internal sealed class RoamingOwnedRoute
    {
        public required RoamingRouteKey Key { get; init; }
        public required string Description { get; init; }
        public required Func<bool> Delete { get; init; }
        public bool Active { get; set; } = true;
    }

    private readonly List<RoamingOwnedRoute> _roamingRoutes = new();

    /// <summary>Exact interface-scoped routes created for one prepared candidate. Darwin's
    /// RTF_IFSCOPE permits old and new routes for the same carrier to coexist until COMMIT.</summary>
    internal sealed class RoamingRouteLease
    {
        private readonly NetworkConfigurator _owner;
        private readonly HashSet<RoamingRouteKey> _desired;
        private readonly List<RoamingOwnedRoute> _created;
        private bool _finished;

        internal RoamingRouteLease(NetworkConfigurator owner,
            HashSet<RoamingRouteKey> desired, List<RoamingOwnedRoute> created)
        {
            _owner = owner;
            _desired = desired;
            _created = created;
        }

        internal void Commit()
        {
            if (_finished) throw new InvalidOperationException("roaming route lease is already finished");
            _owner.CommitRoamingRoutes(_desired, _created);
            _finished = true;
        }

        internal void Abort()
        {
            if (_finished) return;
            var failures = new List<string>();
            foreach (RoamingOwnedRoute route in _created.AsEnumerable().Reverse())
            {
                if (!route.Active) continue;
                try
                {
                    if (!DeleteRoamingRoute(route)) failures.Add(route.Description);
                }
                catch { failures.Add(route.Description); }
            }
            if (failures.Count != 0)
                throw new InvalidOperationException("macOS roaming route rollback is incomplete: "
                    + string.Join(", ", failures));
            _finished = true;
        }
    }

    internal NativePathUpdate CaptureRoamingPath(
        IReadOnlyList<IPAddress> carrierAddresses,
        ulong generation,
        ulong updateId,
        string reason)
    {
        if (carrierAddresses.Count == 0)
            throw new InvalidOperationException("roaming has no last-known carrier addresses");

        var locals = new List<(string name, uint index, IPAddress address)>();
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up
                || adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback
                    or NetworkInterfaceType.Tunnel
                || adapter.Name.StartsWith("utun", StringComparison.Ordinal)
                || adapter.Name.StartsWith("lo", StringComparison.Ordinal))
                continue;
            IPInterfaceProperties properties;
            try { properties = adapter.GetIPProperties(); }
            catch { continue; }
            foreach (UnicastIPAddressInformation item in properties.UnicastAddresses)
            {
                IPAddress address = item.Address.IsIPv4MappedToIPv6
                    ? item.Address.MapToIPv4() : item.Address;
                if (!UsableRoamingAddress(address)) continue;
                int signedIndex;
                try
                {
                    signedIndex = address.AddressFamily == AddressFamily.InterNetwork
                        ? properties.GetIPv4Properties()?.Index ?? -1
                        : properties.GetIPv6Properties()?.Index ?? -1;
                }
                catch { continue; }
                if (signedIndex > 0)
                    locals.Add((adapter.Name, unchecked((uint)signedIndex), address));
            }
        }

        string? defaultIpv4 = DefaultPhysicalPath(AddressFamily.InterNetwork).iface;
        string? defaultIpv6 = DefaultPhysicalPath(AddressFamily.InterNetworkV6).iface;
        var choices = new List<(string name, uint index, IPAddress source,
            IPAddress remote, int preference)>();
        foreach (var local in locals)
            foreach (IPAddress remote in carrierAddresses)
            {
                if (local.address.AddressFamily != remote.AddressFamily) continue;
                var path = PathToServerOnInterface(remote, local.name);
                if (!string.Equals(path.iface, local.name, StringComparison.Ordinal)) continue;
                string? preferred = remote.AddressFamily == AddressFamily.InterNetwork
                    ? defaultIpv4 : defaultIpv6;
                choices.Add((local.name, local.index, local.address, remote,
                    string.Equals(preferred, local.name, StringComparison.Ordinal) ? 0 : 1));
            }
        var selected = choices
            .OrderBy(item => item.preference)
            .ThenBy(item => item.name, StringComparer.Ordinal)
            .ThenBy(item => item.source.ToString(), StringComparer.Ordinal)
            .ThenBy(item => item.remote.ToString(), StringComparer.Ordinal)
            .FirstOrDefault();
        if (selected.index == 0)
            throw new InvalidOperationException(
                "macOS found no live physical interface that can route a carrier address");

        List<string> selectedLocals = OrderRoamingLocalAddresses(
            locals.Where(item => item.name == selected.name)
                .Select(item => item.address).Distinct(),
            selected.source);
        IPAddress[] reachableRemotes = choices
            .Where(item => item.name == selected.name)
            .Select(item => item.remote)
            .Distinct()
            .OrderBy(item => item.Equals(selected.remote) ? 0 : 1)
            .ThenBy(item => item.ToString(), StringComparer.Ordinal)
            .ToArray();
        return new NativePathUpdate
        {
            Generation = generation,
            UpdateId = updateId,
            PlatformPathId = $"macos-if:{selected.index}:{selected.name}",
            Reason = reason,
            NetworkToken = selected.name,
            InterfaceIndex = selected.index,
            LocalAddresses = selectedLocals,
            ResolvedAddresses = reachableRemotes.Select(item => new NativePathResolution
            {
                Address = item.ToString(),
                TtlSecs = 0,
            })
                .ToList(),
            Flags = new NativePathFlags
            {
                DefaultRouteChanged = reason is "network_changed" or "default_route_changed",
                Wake = reason == "wake",
                SameNetworkNatFailure = reason == "same_network_nat_failure",
            },
        };
    }

    internal RoamingRouteLease PrepareRoamingRoutes(NativePathUpdate path)
    {
        string interfaceName = path.NetworkToken
            ?? throw new InvalidOperationException("macOS roaming path has no interface name");
        uint interfaceIndex = path.InterfaceIndex
            ?? throw new InvalidOperationException("macOS roaming path has no interface index");
        var locals = path.LocalAddresses.Select(IPAddress.Parse).ToArray();
        if (!InterfaceMatches(interfaceName, interfaceIndex, locals))
            throw new InvalidOperationException(
                $"macOS roaming interface {interfaceName}/{interfaceIndex} no longer owns the path source");

        var desired = new HashSet<RoamingRouteKey>();
        var created = new List<RoamingOwnedRoute>();
        try
        {
            foreach (NativePathResolution resolution in path.ResolvedAddresses)
            {
                IPAddress remote = IPAddress.Parse(resolution.Address);
                if (!locals.Any(local => local.AddressFamily == remote.AddressFamily)) continue;
                var route = PathToServerOnInterface(remote, interfaceName);
                if (!string.Equals(route.iface, interfaceName, StringComparison.Ordinal)) continue;
                string nextHop = route.gateway != null
                    ? RouteGatewayArgument(route.gateway, interfaceName)
                    : $"-interface {interfaceName}";
                var key = new RoamingRouteKey(remote.ToString(), interfaceName, nextHop);
                desired.Add(key);

                ExistingRoute? existing = ExistingScopedHostRouteFor(remote, interfaceName);
                if (existing != null)
                {
                    bool matches = route.gateway != null
                        ? existing.Gateway != null
                          && SameAddressIgnoringScope(existing.Gateway, route.gateway)
                          && existing.Interface == interfaceName
                        : existing.Gateway == null && existing.Interface == interfaceName;
                    if (!matches)
                        throw new InvalidOperationException(
                            $"operator-owned scoped route {remote} on {interfaceName} conflicts with roaming");
                    continue;
                }

                string add = ScopedHostRouteArguments("add", remote, route.gateway, interfaceName);
                string delete = ScopedHostRouteArguments("delete", remote, route.gateway, interfaceName);
                Run("/sbin/route", add);
                created.Add(new RoamingOwnedRoute
                {
                    Key = key,
                    Description = $"roaming scoped carrier route {remote} on {interfaceName}",
                    Delete = () => Run("/sbin/route", delete, optional: true)
                        || ExistingScopedHostRouteFor(remote, interfaceName) == null,
                });
            }
            if (desired.Count == 0)
                throw new InvalidOperationException("macOS roaming path has no family-compatible carrier route");
            _log($"Prepared {desired.Count} scoped roaming route(s) on {interfaceName}");
            return new RoamingRouteLease(this, desired, created);
        }
        catch (Exception prepareError)
        {
            var rollbackFailures = new List<Exception>();
            foreach (RoamingOwnedRoute route in created.AsEnumerable().Reverse())
            {
                try
                {
                    if (!DeleteRoamingRoute(route))
                        rollbackFailures.Add(new InvalidOperationException(route.Description));
                }
                catch (Exception error) { rollbackFailures.Add(error); }
            }
            if (rollbackFailures.Count != 0)
            {
                rollbackFailures.Insert(0, prepareError);
                throw new NativeRoamingPlatformStateUnknownException(
                    "macOS roaming route PREPARE and rollback both failed",
                    new AggregateException(rollbackFailures));
            }
            throw;
        }
    }

    /// <summary>After the candidate is authenticated, move Qeli's ordinary host routes as
    /// well as retaining its scoped route. The bound candidate socket uses the scoped route;
    /// later bonded TCP replacements use the ordinary route and must see the same carrier.</summary>
    internal void CommitRoamingServerRoutes(NativePathUpdate path)
    {
        string interfaceName = path.NetworkToken
            ?? throw new InvalidOperationException("macOS roaming path has no interface name");
        var locals = path.LocalAddresses.Select(IPAddress.Parse).ToArray();
        var transitions = new List<(PinnedServerRoute state, string nextHop,
            IPAddress? gateway, string? iface, bool wasOwned)>();
        try
        {
            foreach (NativePathResolution resolution in path.ResolvedAddresses)
            {
                IPAddress remote = IPAddress.Parse(resolution.Address);
                if (!locals.Any(local => local.AddressFamily == remote.AddressFamily)) continue;
                if (!_pinnedServerRoutes.TryGetValue(remote.ToString(), out var state))
                    throw new InvalidOperationException(
                        $"macOS roaming cannot replace an untracked server route {remote}");
                var route = PathToServerOnInterface(remote, interfaceName);
                if (!string.Equals(route.iface, interfaceName, StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        $"macOS roaming path for {remote} no longer uses {interfaceName}");
                string nextHop = route.gateway != null
                    ? RouteGatewayArgument(route.gateway, interfaceName)
                    : $"-interface {interfaceName}";
                if (PinnedPathMatches(state, nextHop, route.gateway, interfaceName)
                    && RouteMatches(ExistingHostRouteFor(remote), route.gateway, interfaceName))
                    continue;

                bool wasOwned = state.Owned;
                string oldNextHop = state.CurrentNextHop;
                IPAddress? oldGateway = state.CurrentGateway;
                string? oldInterface = state.CurrentInterface;
                MovePinnedServerRoute(state, nextHop, route.gateway, interfaceName);
                transitions.Add((state, oldNextHop, oldGateway, oldInterface, wasOwned));
            }
        }
        catch (Exception commitError)
        {
            var failures = new List<Exception> { commitError };
            foreach (var transition in transitions.AsEnumerable().Reverse())
            {
                try
                {
                    MovePinnedServerRoute(transition.state, transition.nextHop,
                        transition.gateway, transition.iface);
                    transition.state.Owned = transition.wasOwned;
                }
                catch (Exception rollbackError) { failures.Add(rollbackError); }
            }
            if (failures.Count > 1)
                throw new NativeRoamingPlatformStateUnknownException(
                    "macOS roaming server-route commit and rollback both failed",
                    new AggregateException(failures));
            throw;
        }
        _log($"Committed {transitions.Count} ordinary roaming server route(s)");
    }

    private void MovePinnedServerRoute(PinnedServerRoute state,
        string nextHop, IPAddress? gateway, string? interfaceName)
    {
        if (PinnedPathMatches(state, nextHop, gateway, interfaceName)
            && RouteMatches(ExistingHostRouteFor(state.Address), gateway, interfaceName))
            return;
        string oldNextHop = state.CurrentNextHop;
        IPAddress? oldGateway = state.CurrentGateway;
        string? oldInterface = state.CurrentInterface;
        if (!RemovePinnedServerRoute(state))
            throw new InvalidOperationException(
                $"could not remove previous server route {state.Address} via {oldNextHop}");
        try
        {
            Run("/sbin/route", OrdinaryHostRouteArguments(
                "add", state.Address, nextHop));
            if (!RouteMatches(ExistingHostRouteFor(state.Address), gateway, interfaceName))
                throw new InvalidOperationException(
                    $"server route {state.Address} did not move to {interfaceName}");
        }
        catch (Exception addError)
        {
            var failures = new List<Exception> { addError };
            try
            {
                if (!RemoveExactServerRoute(state.Address, state.Family,
                        nextHop, gateway, interfaceName))
                    failures.Add(new InvalidOperationException(
                        $"could not remove failed server route {state.Address} via {nextHop}"));
            }
            catch (Exception cleanupError) { failures.Add(cleanupError); }
            try
            {
                Run("/sbin/route", OrdinaryHostRouteArguments(
                    "add", state.Address, oldNextHop));
                if (!RouteMatches(ExistingHostRouteFor(state.Address),
                        oldGateway, oldInterface))
                    throw new InvalidOperationException(
                        $"server route {state.Address} did not roll back to {oldInterface}");
            }
            catch (Exception restoreError) { failures.Add(restoreError); }
            if (failures.Count > 1)
                throw new NativeRoamingPlatformStateUnknownException(
                    $"server route {state.Address} move and rollback both failed",
                    new AggregateException(failures));
            throw;
        }
        state.CurrentNextHop = nextHop;
        state.CurrentGateway = gateway;
        state.CurrentInterface = interfaceName;
        if (!state.Owned)
        {
            state.Owned = true;
            RegisterPinnedServerRouteUndo(state);
        }
    }

    private static bool PinnedPathMatches(PinnedServerRoute state,
        string nextHop, IPAddress? gateway, string? interfaceName) =>
        state.CurrentNextHop == nextHop
        && state.CurrentInterface == interfaceName
        && (gateway == null
            ? state.CurrentGateway == null
            : state.CurrentGateway != null
              && state.CurrentGateway.GetAddressBytes().SequenceEqual(gateway.GetAddressBytes()));

    private void CommitRoamingRoutes(
        HashSet<RoamingRouteKey> desired, List<RoamingOwnedRoute> created)
    {
        _roamingRoutes.AddRange(created);
        created.Clear();
        foreach (RoamingOwnedRoute stale in _roamingRoutes
                     .Where(route => route.Active && !desired.Contains(route.Key)).ToArray())
        {
            try
            {
                if (!DeleteRoamingRoute(stale))
                    _log($"WARN: could not remove stale {stale.Description}; cleanup retains ownership");
            }
            catch (Exception error)
            {
                _log($"WARN: could not remove stale {stale.Description}: {error.Message}");
            }
        }
        _roamingRoutes.RemoveAll(route => !route.Active);
        _log("Committed macOS scoped roaming routes");
    }

    private ExistingRoute? ExistingScopedHostRouteFor(IPAddress address, string interfaceName)
    {
        try
        {
            string family = address.AddressFamily == AddressFamily.InterNetworkV6
                ? "-inet6" : "-inet";
            var (output, code) = RunOut("/sbin/route",
                $"-n get {family} -ifscope {interfaceName} {address}");
            return code == 0 ? ParseExactRoute(output, address,
                address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32) : null;
        }
        catch (Exception error)
        {
            _log($"could not inspect scoped route {address} on {interfaceName}: {error.Message}");
            return null;
        }
    }

    private (string? iface, IPAddress? gateway) PathToServerOnInterface(
        IPAddress serverIp, string interfaceName)
    {
        string family = serverIp.AddressFamily == AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        var (output, code) = RunOut("/sbin/route",
            $"-n get {family} -ifscope {interfaceName} {serverIp}");
        return code == 0 ? ParseRoamingPath(output) : (null, null);
    }

    private (string? iface, IPAddress? gateway) DefaultPhysicalPath(AddressFamily family)
    {
        string selector = family == AddressFamily.InterNetworkV6 ? "-inet6" : "-inet";
        try
        {
            var (output, code) = RunOut("/sbin/route", $"-n get {selector} default");
            return code == 0 ? ParseRoamingPath(output) : (null, null);
        }
        catch { return (null, null); }
    }

    private static (string? iface, IPAddress? gateway) ParseRoamingPath(string output)
    {
        string? iface = null;
        IPAddress? gateway = null;
        foreach (string raw in output.Split('\n'))
        {
            string line = raw.Trim();
            if (line.StartsWith("interface:", StringComparison.Ordinal))
                iface = line["interface:".Length..].Trim();
            else if (line.StartsWith("gateway:", StringComparison.Ordinal))
                gateway = ParseRouteGateway(line["gateway:".Length..].Trim());
        }
        return (iface, gateway);
    }

    private static bool InterfaceMatches(
        string name, uint index, IReadOnlyList<IPAddress> localAddresses)
    {
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up || adapter.Name != name) continue;
            IPInterfaceProperties properties;
            try { properties = adapter.GetIPProperties(); }
            catch { return false; }
            foreach (IPAddress requested in localAddresses)
            {
                bool assigned = properties.UnicastAddresses.Any(item =>
                    NormalizeRoamingAddress(item.Address).Equals(
                        NormalizeRoamingAddress(requested)));
                if (!assigned) continue;
                try
                {
                    int actual = requested.AddressFamily == AddressFamily.InterNetwork
                        ? properties.GetIPv4Properties()?.Index ?? -1
                        : properties.GetIPv6Properties()?.Index ?? -1;
                    if (actual > 0 && unchecked((uint)actual) == index)
                        return true;
                }
                catch { }
            }
            return false;
        }
        return false;
    }

    private static string ScopedHostRouteArguments(
        string verb, IPAddress address, IPAddress? gateway, string interfaceName)
    {
        string family = address.AddressFamily == AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        string nextHop = gateway != null
            ? RouteGatewayArgument(gateway, interfaceName)
            : $"-interface {interfaceName}";
        return $"-n {verb} {family} -host -ifscope {interfaceName} {address} {nextHop}";
    }

    private static string OrdinaryHostRouteArguments(
        string verb, IPAddress address, string nextHop)
    {
        string family = address.AddressFamily == AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        return $"-n {verb} {family} -host {address} {nextHop}";
    }

    private static List<string> OrderRoamingLocalAddresses(
        IEnumerable<IPAddress> addresses, IPAddress selectedSource) => addresses
        .OrderBy(address => address.Equals(selectedSource) ? 0 : 1)
        .ThenBy(address => address.ToString(), StringComparer.Ordinal)
        .Select(address => address.ToString())
        .ToList();

    private static bool UsableRoamingAddress(IPAddress address) =>
        address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6
        && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any)
        && !address.Equals(IPAddress.Broadcast) && !IPAddress.IsLoopback(address)
        && !address.IsIPv6Multicast && !address.IsIPv6LinkLocal
        && (address.AddressFamily != AddressFamily.InterNetworkV6 || address.ScopeId == 0);

    private static IPAddress NormalizeRoamingAddress(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool DeleteRoamingRoute(RoamingOwnedRoute route)
    {
        if (!route.Active) return true;
        if (!route.Delete()) return false;
        route.Active = false;
        return true;
    }

    private void CleanupRoamingRoutes(List<string> failures)
    {
        foreach (RoamingOwnedRoute route in _roamingRoutes.AsEnumerable().Reverse())
        {
            if (!route.Active) continue;
            try
            {
                if (!DeleteRoamingRoute(route)) failures.Add(route.Description);
            }
            catch (Exception error)
            {
                failures.Add(route.Description);
                _log($"route cleanup error ({route.Description}): {error.Message}");
            }
        }
        _roamingRoutes.RemoveAll(route => !route.Active);
    }

    internal static void RunRoamingRouteSelfTest(Action<string, bool> check)
    {
        string onLink = ScopedHostRouteArguments(
            "add", IPAddress.Parse("203.0.113.8"), null, "en0");
        string ipv6 = ScopedHostRouteArguments("delete", IPAddress.Parse("2001:db8::8"),
            IPAddress.Parse("fe80::1"), "en1");
        check("macOS roaming routes: candidate host route is exact and interface-scoped",
            onLink == "-n add -inet -host -ifscope en0 203.0.113.8 -interface en0"
            && ipv6 == "-n delete -inet6 -host -ifscope en1 2001:db8::8 fe80::1%en1");

        IPAddress selected = IPAddress.Parse("192.0.2.20");
        List<string> ordered = OrderRoamingLocalAddresses(new[]
        {
            IPAddress.Parse("192.0.2.10"), selected, IPAddress.Parse("2001:db8::10"),
        }, selected);
        check("macOS roaming path: selected source stays first for BIND",
            ordered.SequenceEqual(new[] { "192.0.2.20", "192.0.2.10", "2001:db8::10" }));

        var parsed = ParseRoamingPath(
            "gateway: fe80::1%en7\ninterface: en7\nflags: <UP,GATEWAY>\n");
        check("macOS roaming path: scoped route output preserves interface and gateway",
            parsed.iface == "en7" && parsed.gateway?.ToString() == "fe80::1");
        check("macOS roaming routes: ordinary route switch uses exact host commands",
            OrdinaryHostRouteArguments("delete", IPAddress.Parse("203.0.113.8"),
                "192.0.2.1") ==
                "-n delete -inet -host 203.0.113.8 192.0.2.1"
            && OrdinaryHostRouteArguments("add", IPAddress.Parse("2001:db8::8"),
                "fe80::1%en1") ==
                "-n add -inet6 -host 2001:db8::8 fe80::1%en1");

        var sameGateway = new PinnedServerRoute
        {
            Address = IPAddress.Parse("203.0.113.8"),
            Family = "-inet",
            Previous = null,
            CurrentNextHop = "192.0.2.1",
            CurrentGateway = IPAddress.Parse("192.0.2.1"),
            CurrentInterface = "en0",
        };
        check("macOS roaming routes: identical gateway on another interface is a new path",
            PinnedPathMatches(sameGateway, "192.0.2.1",
                IPAddress.Parse("192.0.2.1"), "en0")
            && !PinnedPathMatches(sameGateway, "192.0.2.1",
                IPAddress.Parse("192.0.2.1"), "en1"));

        int staleDeletes = 0;
        int candidateDeletes = 0;
        var owner = new NetworkConfigurator(_ => { });
        var stale = new RoamingOwnedRoute
        {
            Key = new RoamingRouteKey("203.0.113.7", "en0", "192.0.2.1"),
            Description = "stale",
            Delete = () => { staleDeletes++; return true; },
        };
        var candidate = new RoamingOwnedRoute
        {
            Key = new RoamingRouteKey("203.0.113.7", "en1", "198.51.100.1"),
            Description = "candidate",
            Delete = () => { candidateDeletes++; return true; },
        };
        owner._roamingRoutes.Add(stale);
        var lease = new RoamingRouteLease(owner,
            new HashSet<RoamingRouteKey> { candidate.Key },
            new List<RoamingOwnedRoute> { candidate });
        lease.Commit();
        check("macOS roaming routes: COMMIT transfers candidate and prunes stale Qeli scope",
            staleDeletes == 1 && owner._roamingRoutes.Contains(candidate) && candidate.Active);
        owner.Dispose();
        check("macOS roaming routes: committed candidate stays owned until disconnect",
            candidateDeletes == 1);

        int abortDeletes = 0;
        var aborted = new RoamingOwnedRoute
        {
            Key = new RoamingRouteKey("198.51.100.8", "en2", "198.51.100.1"),
            Description = "aborted",
            Delete = () => { abortDeletes++; return true; },
        };
        new RoamingRouteLease(new NetworkConfigurator(_ => { }),
            new HashSet<RoamingRouteKey> { aborted.Key },
            new List<RoamingOwnedRoute> { aborted }).Abort();
        check("macOS roaming routes: ABORT removes candidate-only scope", abortDeletes == 1);
    }
}
