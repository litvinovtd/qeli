using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using QeliMac.Model;
using QeliMac.Service;

namespace QeliMac.Vpn;

/// <summary>
/// Configures the utun interface (IP/MTU/DNS/routes) and the system routing table on
/// macOS. The analogue of qeli-win's NetworkConfigurator (which drove netsh/route) and
/// of Android's VpnService.Builder. Uses <c>ifconfig</c>, <c>route</c> and
/// <c>networksetup</c>. Every change is recorded as an undo action and reverted on
/// <see cref="Dispose"/>, so a disconnect leaves the machine exactly as it was — no
/// leaked default route, no broken DNS. Requires root.
/// </summary>
public sealed partial class NetworkConfigurator : IDisposable
{
    private readonly Action<string> _log;
    private readonly List<Action> _undo = new();
    private readonly List<OwnedRoute> _ownedRoutes = new();
    private readonly List<string> _degraded = new();
    private Action? _dnsRelease;
    private readonly Dictionary<string, PinnedServerRoute> _pinnedServerRoutes =
        new(StringComparer.Ordinal);

    private sealed class PinnedServerRoute
    {
        public required IPAddress Address { get; init; }
        public required string Family { get; init; }
        public required ExistingRoute? Previous { get; init; }
        public required string CurrentNextHop { get; set; }
        public required IPAddress? CurrentGateway { get; set; }
        public required string? CurrentInterface { get; set; }
        public bool Owned { get; set; }
        public bool UndoRegistered { get; set; }
    }

    private sealed class OwnedRoute
    {
        public required string Network { get; init; }
        public required int Prefix { get; init; }
        public required string Description { get; init; }
        public required Func<bool> Delete { get; init; }
        public bool Active { get; set; } = true;
    }

    private static readonly string DnsStatePath = Path.Combine(Paths.ServiceDir, "dns-override.json");

    [DllImport("libc")] private static extern uint geteuid();

    /// <summary>
    /// Network setup steps that FAILED without aborting the connect. `optional: true`
    /// swallowed these while the success line was logged anyway and the UI went green —
    /// so a tunnel with no DNS applied (queries leaking to the system resolver) or with
    /// pushed routes missing looked healthy. Surfaced so "Connected" can be qualified. (C-17)
    /// </summary>
    public IReadOnlyList<string> Degraded => _degraded;

    /// <summary>True when any network step silently failed — the tunnel is up but not
    /// configured as intended.</summary>
    public bool IsDegraded => _degraded.Count > 0;

    /// True when a DNS apply FAILED (not merely a route). Kept separate from the general
    /// degraded list because that distinction decides whether the tunnel is torn down
    /// under a kill-switch: DNS leaking to the physical resolver is exactly what the
    /// kill-switch exists to prevent, a missing secondary route is not. (Р2)
    public bool DnsFailed => _degraded.Exists(d => d.StartsWith("DNS ", StringComparison.Ordinal)
                                               || d.StartsWith("secondary DNS", StringComparison.Ordinal));


    private void Degrade(string what)
    {
        _degraded.Add(what);
        _log($"WARNING: {what}");
    }

    public NetworkConfigurator(Action<string> log) => _log = log;

    /// <summary>
    /// Restore a DNS override left by a crashed prior process. Safe to call on every app
    /// start; only a privileged macOS process can mutate the network service. SetDns repeats
    /// this check immediately before acquisition, so non-standard/test entry points are
    /// protected too.
    /// </summary>
    public static void SweepDns(Action<string>? log = null, bool requireReleased = false)
    {
        if (!OperatingSystem.IsMacOS() || geteuid() != 0 || !File.Exists(DnsStatePath)) return;
        ServiceState.EnsureDir();
        var journal = SystemDnsJournal(log ?? (_ => { }));
        DnsJournal.RecoveryResult result = DnsJournal.RecoveryResult.NothingToDo;
        int attempts = requireReleased ? 20 : 3;
        for (int attempt = 1; attempt <= attempts; attempt++)
        {
            result = journal.RecoverStale();
            bool retry = result == DnsJournal.RecoveryResult.Failed ||
                         (requireReleased && result == DnsJournal.RecoveryResult.LiveOwner);
            if (!retry) break;
            if (attempt < attempts) Thread.Sleep(250);
        }
        if (result == DnsJournal.RecoveryResult.Failed ||
            (requireReleased && result == DnsJournal.RecoveryResult.LiveOwner))
            throw new InvalidOperationException(
                result == DnsJournal.RecoveryResult.LiveOwner
                    ? "a live qeli process still owns the system DNS override"
                    : $"the system DNS could not be restored; recovery state remains at {DnsStatePath}");
    }

    private static DnsJournal SystemDnsJournal(Action<string> log) => new(
        DnsStatePath,
        ReadSystemDns,
        WriteSystemDns,
        DnsJournal.IsOwnerAlive,
        DnsJournal.CurrentOwner(),
        log);

    /// <summary>The physical path used to reach <paramref name="serverIp"/>: (interface, gateway).</summary>
    public (string? iface, IPAddress? gateway) PathToServer(IPAddress serverIp)
    {
        string? iface = null; IPAddress? gw = null;
        try
        {
            var (outp, _) = RunOut("/sbin/route", $"-n get {serverIp}");
            foreach (var raw in outp.Split('\n'))
            {
                var line = raw.Trim();
                if (line.StartsWith("interface:", StringComparison.Ordinal))
                    iface = line["interface:".Length..].Trim();
                else if (line.StartsWith("gateway:", StringComparison.Ordinal))
                {
                    string literal = line["gateway:".Length..].Trim();
                    gw = ParseRouteGateway(literal);
                }
            }
        }
        catch (Exception e) { _log($"route get error: {e.Message}"); }
        return (iface, gw);
    }

    /// <summary>Resolve a bypass prefix before full-tunnel routes replace its best path.</summary>
    public (string? iface, IPAddress? gateway) PhysicalPathForRoute(string cidr)
    {
        var (addr, _) = ParseCidr(cidr);
        if (addr == null || !IPAddress.TryParse(addr, out var destination)) return (null, null);
        if (destination.Equals(IPAddress.Any)) destination = IPAddress.Parse("1.1.1.1");
        else if (destination.Equals(IPAddress.IPv6Any))
            destination = IPAddress.Parse("2606:4700:4700::1111");
        return PathToServer(destination);
    }

    private sealed record ExistingRoute(string? Gateway, string? Interface);

    /// <summary>
    /// Existing exact HOST (/32 or /128) route, or null when lookup resolved through a
    /// broader/default prefix. `route get` is safe here because its `destination:` field is
    /// required to equal the requested address; merely receiving a gateway is not enough.
    /// Preserve interface routes as well as gateway routes so scoped/on-link IPv6 policy is
    /// restored byte-for-byte at disconnect.
    /// </summary>
    private ExistingRoute? ExistingHostRouteFor(IPAddress ip)
    {
        int prefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return ExistingExactRouteFor(ip, prefix);
    }

    private ExistingRoute? ExistingExactRouteFor(IPAddress address, int prefix)
    {
        try
        {
            bool v6 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            var (outp, code) = RunOut(
                "/sbin/route", $"-n get {(v6 ? "-inet6" : "-inet")} {address}");
            return code == 0 ? ParseExactRoute(outp, address, prefix) : null;
        }
        catch (Exception e)
        {
            _log($"could not read the existing route {address}/{prefix}: {e.Message}");
            return null;
        }
    }

    private static ExistingRoute? ParseExactRoute(
        string output, IPAddress requestedAddress, int requestedPrefix)
    {
        string? destination = null, mask = null, gateway = null, iface = null, flags = null;
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.Trim();
            if (line.StartsWith("destination:", StringComparison.Ordinal))
                destination = line["destination:".Length..].Trim();
            else if (line.StartsWith("mask:", StringComparison.Ordinal))
                mask = line["mask:".Length..].Trim();
            else if (line.StartsWith("gateway:", StringComparison.Ordinal))
                gateway = line["gateway:".Length..].Trim();
            else if (line.StartsWith("interface:", StringComparison.Ordinal))
                iface = line["interface:".Length..].Trim();
            else if (line.StartsWith("flags:", StringComparison.Ordinal))
                flags = line["flags:".Length..].Trim();
        }
        if (destination == null) return null;

        int maxPrefix = requestedAddress.AddressFamily ==
            System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        int actualPrefix;
        IPAddress actualAddress;
        if (destination.Equals("default", StringComparison.OrdinalIgnoreCase))
        {
            actualAddress = requestedAddress.AddressFamily ==
                System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? IPAddress.IPv6Any : IPAddress.Any;
            actualPrefix = 0;
        }
        else
        {
            string literal = destination;
            int slash = literal.IndexOf('/');
            int? embeddedPrefix = null;
            if (slash >= 0)
            {
                if (!int.TryParse(literal[(slash + 1)..], out int parsedPrefix)) return null;
                embeddedPrefix = parsedPrefix;
                literal = literal[..slash];
            }
            int zone = literal.IndexOf('%');
            if (zone >= 0) literal = literal[..zone];
            if (!IPAddress.TryParse(literal, out actualAddress!) ||
                actualAddress.AddressFamily != requestedAddress.AddressFamily)
                return null;
            actualPrefix = embeddedPrefix
                ?? PrefixFromMask(mask, maxPrefix)
                ?? (flags?.Contains("HOST", StringComparison.OrdinalIgnoreCase) == true
                    ? maxPrefix : -1);
        }
        if (actualPrefix != requestedPrefix || actualPrefix < 0) return null;
        if (!NetworkAddress(actualAddress, actualPrefix).GetAddressBytes().SequenceEqual(
                NetworkAddress(requestedAddress, requestedPrefix).GetAddressBytes()))
            return null;
        return gateway != null && gateway.StartsWith("link#", StringComparison.Ordinal)
            ? new ExistingRoute(null, iface)
            : new ExistingRoute(gateway, iface);
    }

    private static int? PrefixFromMask(string? mask, int maxPrefix)
    {
        if (string.IsNullOrWhiteSpace(mask)) return null;
        if (mask.Equals("default", StringComparison.OrdinalIgnoreCase)) return 0;
        byte[] bytes;
        if (maxPrefix == 32 && mask.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            uint.TryParse(mask[2..], System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out uint value))
            bytes = new[] { (byte)(value >> 24), (byte)(value >> 16),
                (byte)(value >> 8), (byte)value };
        else
        {
            int zone = mask.IndexOf('%');
            string literal = zone >= 0 ? mask[..zone] : mask;
            if (!IPAddress.TryParse(literal, out var parsed) ||
                parsed.GetAddressBytes().Length * 8 != maxPrefix) return null;
            bytes = parsed.GetAddressBytes();
        }
        int prefix = 0;
        bool sawZero = false;
        foreach (byte b in bytes)
            for (int bit = 7; bit >= 0; bit--)
            {
                bool one = (b & (1 << bit)) != 0;
                if (one && sawZero) return null;
                if (one) prefix++; else sawZero = true;
            }
        return prefix;
    }

    private static bool SameAddressIgnoringScope(string literal, IPAddress expected)
    {
        int zone = literal.IndexOf('%');
        if (zone >= 0) literal = literal[..zone];
        return IPAddress.TryParse(literal, out var parsed)
               && parsed.AddressFamily == expected.AddressFamily
               && parsed.GetAddressBytes().SequenceEqual(expected.GetAddressBytes());
    }

    private static IPAddress? ParseRouteGateway(string literal)
    {
        literal = literal.Trim();
        int zone = literal.IndexOf('%');
        if (zone > 0) literal = literal[..zone];
        return IPAddress.TryParse(literal, out var parsed) ? parsed : null;
    }

    private static string RouteGatewayArgument(IPAddress gateway, string? physicalInterface)
    {
        string literal = gateway.ToString();
        return gateway.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
               && gateway.IsIPv6LinkLocal
               && !literal.Contains('%')
               && !string.IsNullOrWhiteSpace(physicalInterface)
            ? $"{literal}%{physicalInterface}"
            : literal;
    }

    /// <summary>Pin a /32 or /128 host route to the VPN server through the physical gateway so
    /// the encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(
        IPAddress serverIp, IPAddress? gateway, string? physicalInterface)
    {
        if (gateway != null && serverIp.AddressFamily != gateway.AddressFamily)
            throw new InvalidOperationException(
                $"server route family mismatch: server {serverIp}, gateway {gateway}");
        string? nextHop = gateway != null
            ? RouteGatewayArgument(gateway, physicalInterface)
            : !string.IsNullOrWhiteSpace(physicalInterface)
                ? $"-interface {physicalInterface}"
                : null;
        if (nextHop == null)
            throw new InvalidOperationException($"server route {serverIp} has no physical path");
        string s = serverIp.ToString();
        // Remember any PRE-EXISTING host route for this IP before we replace it. The undo
        // only ever deleted ours, so a host that had its own /32 for the server (a second
        // link, a management route) lost it permanently on the first connect — the delete
        // below is destructive and nothing put it back. (C-18)
        bool v6 = serverIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        string family = v6 ? "-inet6" : "-inet";
        ExistingRoute? previous = ExistingHostRouteFor(serverIp);
        bool alreadyMatches = RouteMatches(previous, gateway, physicalInterface);
        var state = new PinnedServerRoute
        {
            Address = serverIp,
            Family = family,
            Previous = previous,
            CurrentNextHop = nextHop,
            CurrentGateway = gateway,
            CurrentInterface = physicalInterface,
        };
        if (alreadyMatches)
        {
            _pinnedServerRoutes[s] = state;
            _log($"Preserving an existing exact server route {s} via {nextHop}");
            return;
        }

        if (previous != null &&
            !Run("/sbin/route", $"-n delete {family} -host {s}", optional: true))
            throw new InvalidOperationException(
                $"could not temporarily replace the existing server route {s}");
        try
        {
            Run("/sbin/route", $"-n add {family} -host {s} {nextHop}");
        }
        catch (Exception addError)
        {
            try { RestoreServerRoute(serverIp, family, previous); }
            catch (Exception restoreError)
            {
                _undo.Add(() => RestoreServerRoute(serverIp, family, previous));
                throw new AggregateException(
                    $"server route {s} failed and its previous route was not restored",
                    addError, restoreError);
            }
            throw;
        }
        state.Owned = true;
        _pinnedServerRoutes[s] = state;
        RegisterPinnedServerRouteUndo(state);
        _log($"Pinned server route {s} via {nextHop}"
             + (previous != null ? " (temporarily replacing an existing exact host route)" : ""));
    }

    private void RegisterPinnedServerRouteUndo(PinnedServerRoute state)
    {
        if (state.UndoRegistered) return;
        state.UndoRegistered = true;
        _undo.Add(() =>
        {
            if (!state.Owned) return;
            if (!RemovePinnedServerRoute(state))
                throw new InvalidOperationException(
                    $"could not remove Qeli-owned server route {state.Address}");
            RestoreServerRoute(state.Address, state.Family, state.Previous);
            state.Owned = false;
        });
    }

    private bool RemovePinnedServerRoute(PinnedServerRoute state) =>
        RemoveExactServerRoute(state.Address, state.Family, state.CurrentNextHop,
            state.CurrentGateway, state.CurrentInterface);

    private bool RemoveExactServerRoute(IPAddress address, string family,
        string nextHop, IPAddress? gateway, string? interfaceName)
    {
        if (Run("/sbin/route", OrdinaryHostRouteArguments(
                "delete", address, nextHop), optional: true))
            return true;
        ExistingRoute? current = ExistingHostRouteFor(address);
        return current == null || !RouteMatches(current, gateway, interfaceName);
    }

    private void RestoreServerRoute(
        IPAddress address, string family, ExistingRoute? previous)
    {
        string literal = address.ToString();
        if (previous?.Gateway != null)
        {
            if (!Run("/sbin/route",
                    $"-n add {family} -host {literal} {previous.Gateway}", optional: true))
            {
                var current = ExistingHostRouteFor(address);
                var expected = ParseRouteGateway(previous.Gateway);
                if (expected == null || current?.Gateway == null ||
                    !SameAddressIgnoringScope(current.Gateway, expected) ||
                    (previous.Interface != null && current.Interface != previous.Interface))
                    throw new InvalidOperationException(
                        $"could not restore server route {literal}");
            }
            _log($"restored the pre-existing host route {literal} via {previous.Gateway}");
        }
        else if (previous?.Interface != null)
        {
            if (!Run("/sbin/route",
                    $"-n add {family} -host {literal} -interface {previous.Interface}",
                    optional: true))
            {
                var current = ExistingHostRouteFor(address);
                if (current?.Gateway != null || current?.Interface != previous.Interface)
                    throw new InvalidOperationException(
                        $"could not restore on-link server route {literal}");
            }
            _log($"restored the pre-existing host route {literal} on {previous.Interface}");
        }
    }

    private static bool RouteMatches(
        ExistingRoute? route, IPAddress? gateway, string? interfaceName) =>
        gateway != null
            ? route?.Gateway != null && SameAddressIgnoringScope(route.Gateway, gateway)
              && (interfaceName == null || route.Interface == interfaceName)
            : route?.Gateway == null && route?.Interface == interfaceName;

    /// <summary>Assign the client IP to the point-to-point utun interface and bring it up,
    /// using the server-pushed subnet prefix.</summary>
    public void SetAddress(string dev, string clientIp, int prefix = 24)
    {
        if (!IPAddress.TryParse(clientIp, out var address))
            throw new InvalidOperationException($"invalid tunnel address {clientIp}");
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (prefix is < 1 or > 128)
                throw new InvalidOperationException($"invalid IPv6 tunnel prefix {prefix}");
            Run("/sbin/ifconfig", $"{dev} inet6 {clientIp} prefixlen {prefix} alias up");
            _undo.Add(() => Run("/sbin/ifconfig", AddressRemovalArguments(dev, address), optional: true));
            _log($"Set {dev} address {clientIp}/{prefix}");
            return;
        }
        // utun is point-to-point: local == dest, server-pushed mask for the tunnel subnet.
        int p = (prefix is >= 1 and <= 32) ? prefix : 24;
        string mask = PrefixToMask(p);
        Run("/sbin/ifconfig", $"{dev} inet {clientIp} {clientIp} netmask {mask} up");
        // A retained per-app utun outlives this transaction. Without an IPv4 undo action,
        // reconnecting from dual/IPv4 to IPv6-only leaves the old primary address and its
        // connected route on the live interface.
        _undo.Add(() => Run("/sbin/ifconfig", AddressRemovalArguments(dev, address), optional: true));
        _log($"Set {dev} address {clientIp}/{p}");
    }

    internal static string AddressRemovalArguments(string dev, IPAddress address) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"{dev} inet6 {address} -alias"
            : $"{dev} inet {address} -alias";

    /// <summary>CIDR prefix length → dotted IPv4 netmask (out-of-range falls back to /24).</summary>
    private static string PrefixToMask(int prefix)
    {
        int p = (prefix is >= 1 and <= 32) ? prefix : 24;
        uint mask = p == 32 ? 0xFFFFFFFFu : ~0u << (32 - p);
        return $"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}";
    }

    public void SetMtu(string dev, int mtu) =>
        Run("/sbin/ifconfig", $"{dev} mtu {mtu}");

    /// <summary>Override the default route via the tunnel using two /1 routes (WireGuard-style),
    /// which beat the existing default without deleting it.</summary>
    public void SetFullTunnelRoutes(string dev)
    {
        Run("/sbin/route", $"-n add -inet -net 0.0.0.0/1 -interface {dev}");
        OwnRoute(IPAddress.Any, 1, "full-tunnel route 0.0.0.0/1",
            () => Run("/sbin/route", $"-n delete -inet -net 0.0.0.0/1 -interface {dev}", optional: true));
        Run("/sbin/route", $"-n add -inet -net 128.0.0.0/1 -interface {dev}");
        OwnRoute(IPAddress.Parse("128.0.0.0"), 1, "full-tunnel route 128.0.0.0/1",
            () => Run("/sbin/route", $"-n delete -inet -net 128.0.0.0/1 -interface {dev}", optional: true));
        _log("Default route now via tunnel (0.0.0.0/1 + 128.0.0.0/1)");
    }

    public void SetFullTunnelRoutesV6(string dev)
    {
        string[] nets = { "::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7" };
        foreach (var net in nets)
        {
            Run("/sbin/route", $"-n add -inet6 -net {net} -interface {dev}");
            var (literal, prefix) = ParseCidr(net);
            string captured = net;
            OwnRoute(IPAddress.Parse(literal!), prefix, $"full-tunnel route {net}",
                () => Run("/sbin/route",
                    $"-n delete -inet6 -net {captured} -interface {dev}", optional: true));
        }
        _log($"IPv6 default route now via tunnel ({string.Join(", ", nets)})");
    }

    /// <summary>Legacy fail-closed capture used only when a full-tunnel NetworkPlan has no
    /// IPv6 address. A dual/IPv6 plan uses SetFullTunnelRoutesV6 with its real assignment.
    /// `::/1 + 8000::/1` beat the default `::/0`, but a router-advertised `2000::/3`
    /// (GUA) is MORE specific and would still win by longest-prefix — so we ALSO add
    /// `2000::/4 + 3000::/4` (= all of `2000::/3`) and `fc00::/7` (ULA), like OpenVPN's
    /// redirect-gateway. A total route failure is tolerated only when the host has no usable
    /// native IPv6 address; a partial capture or a live native path fails the plan closed.</summary>
    public void CaptureIPv6(string dev)
    {
        bool nativeIpv6Present = HasUsableNativeIpv6(dev);
        bool addrOk = Run("/sbin/ifconfig", $"{dev} inet6 fd71:e1::1 prefixlen 64 up", optional: true);
        string[] nets = { "::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7" };
        var failed = new List<string>();
        foreach (var net in nets)
        {
            if (!Run("/sbin/route", $"-n add -inet6 -net {net} -interface {dev}", optional: true))
                failed.Add(net);
            else
            {
                var (literal, prefix) = ParseCidr(net);
                string captured = net;
                OwnRoute(IPAddress.Parse(literal!), prefix, $"IPv6 capture route {net}",
                    () => Run("/sbin/route",
                        $"-n delete -inet6 -net {captured} -interface {dev}", optional: true));
            }
        }
        _undo.Add(() => Run("/sbin/ifconfig", $"{dev} inet6 fd71:e1::1 -alias", optional: true));

        // A partial route set is never safe: longest-prefix routing can still send the
        // uncovered classes to a physical interface. A total failure is harmless only on
        // a host that genuinely has no usable native IPv6 address at apply time.
        if (failed.Count != 0 && (failed.Count != nets.Length || nativeIpv6Present))
            throw new InvalidOperationException(
                $"IPv6 fail-closed capture failed ({nets.Length - failed.Count}/{nets.Length} " +
                $"routes installed; failed: {string.Join(", ", failed)}; " +
                $"native IPv6 present: {nativeIpv6Present})");
        if (failed.Count == 0)
            _log($"IPv6 captured into tunnel ({string.Join(", ", nets)})");
        else
            _log("IPv6 is disabled on every non-tunnel interface; no native family exists to capture");
        if (!addrOk && failed.Count != nets.Length)
            _log("note: the tunnel's IPv6 address could not be added; IPv6 capture may be incomplete.");
    }

    private static bool HasUsableNativeIpv6(string tunnelDevice)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                string.Equals(ni.Name, tunnelDevice, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(ni.Id, tunnelDevice, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                foreach (var unicast in ni.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;
                    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                        !address.Equals(IPAddress.IPv6Any) &&
                        !address.Equals(IPAddress.IPv6Loopback) &&
                        !address.IsIPv6LinkLocal &&
                        !address.IsIPv6Multicast &&
                        !address.IsIPv4MappedToIPv6)
                        return true;
                }
            }
            catch { /* an interface can disappear while the snapshot is being read */ }
        }
        return false;
    }

    public bool AddRoute(string cidr, string dev, bool logSuccess = true)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return false; }
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        string net = $"{network}/{prefix}";
        string family = network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        // Logging "via tunnel" after a failed add was simply untrue. (C-17)
        if (!Run("/sbin/route", $"-n add {family} -net {net} -interface {dev}", optional: true))
        {
            Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
            return false;
        }
        OwnRoute(network, prefix, $"tunnel route {cidr}",
            () => Run("/sbin/route",
                $"-n delete {family} -net {net} -interface {dev}", optional: true));
        if (logSuccess) _log($"route {cidr} via tunnel");
        return true;
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        int removed = DeleteOwnedRoutes(network, prefix);
        _log(removed == 0
            ? $"exclude {cidr}: no Qeli-owned tunnel route existed; preserving system routes"
            : $"exclude {cidr}: removed {removed} Qeli-owned tunnel route(s)");
    }

    /// <summary>Route a subnet AROUND the tunnel via the physical gateway, so an excluded
    /// destination reaches the network directly even in full-tunnel (where a plain
    /// DeleteRoute is a no-op — the two-halves splits still cover it). The specific prefix
    /// beats the /1 halves by longest-prefix match. Undone on disconnect.</summary>
    public void PinBypassRoute(string cidr, IPAddress? gateway, string? physicalInterface)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null)
            throw new InvalidOperationException($"invalid exclude route {cidr}");
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        string net = $"{network}/{prefix}";
        bool v6 = network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        string family = v6 ? "-inet6" : "-inet";
        if (gateway != null && gateway.AddressFamily != (v6
                ? System.Net.Sockets.AddressFamily.InterNetworkV6
                : System.Net.Sockets.AddressFamily.InterNetwork))
            gateway = null;
        DeleteOwnedRoutes(network, prefix); // never delete an operator-owned route
        ExistingRoute? existing = ExistingExactRouteFor(network, prefix);
        if (existing != null)
        {
            _log($"exclude {cidr}: preserving an existing exact route " +
                 $"via {existing.Gateway ?? existing.Interface ?? "unknown path"}");
            return;
        }
        // In full-tunnel the /1 halves cover this prefix, so a failed pin leaves the
        // destination INSIDE the tunnel — the opposite of the requested exclude, and for
        // the server-IP bypass that is exactly what wedges a reconnect. (C-17)
        string? nextHop = gateway != null ? RouteGatewayArgument(gateway, physicalInterface)
            : !string.IsNullOrWhiteSpace(physicalInterface) ? $"-interface {physicalInterface}"
            : null;
        if (nextHop == null || !Run("/sbin/route", $"-n add {family} -net {net} {nextHop}", optional: true))
            throw new InvalidOperationException(
                $"exclude route {cidr} has no usable physical path or was not programmed");
        string ownedNextHop = nextHop;
        OwnRoute(network, prefix, $"bypass route {cidr}",
            () => Run("/sbin/route",
                $"-n delete {family} -net {net} {ownedNextHop}", optional: true));
        _log($"exclude {cidr} via physical path {nextHop}");
    }

    /// <summary>
    /// After every route is in place, confirm the carrier traffic still leaves through the
    /// PHYSICAL interface and not through the utun we just created. (C-17)
    /// </summary>
    /// <remarks>
    /// The one invariant a tunnel cannot survive breaking: if the route to the server
    /// resolves to utun, the encrypted carrier is fed back into the tunnel it is supposed
    /// to carry and the link deadlocks. Everything checked before this only proved a
    /// command was ISSUED; this asks the OS what the routing table actually decided.
    ///
    /// An unresolved path remains degraded because the OS supplied no answer. A path that
    /// resolves to the exact utun is definitive and fatal: ACKing that plan would start a
    /// carrier whose packets are routed back into itself.
    /// </remarks>
    public void VerifyCarrierPath(IPAddress serverIp, string tunDev)
    {
        var (iface, _) = PathToServer(serverIp);
        if (iface == null)
        {
            Degrade($"could not resolve the outgoing interface for {serverIp} after applying " +
                    "routes — cannot confirm the carrier bypasses the tunnel");
            return;
        }
        if (iface == tunDev)
        {
            throw new InvalidOperationException(
                $"the route to the server {serverIp} resolves to the TUNNEL interface " +
                $"({tunDev}); the encrypted carrier would loop back into itself. " +
                "The server-route pin did not take effect");
        }
        _log($"carrier path verified: {serverIp} leaves via {iface} (tunnel is {tunDev})");
    }

    /// <summary>Point the primary network service's resolvers at the tunnel DNS, saving the
    /// previous setting for restore on disconnect.</summary>
    public bool SetDns(IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return true;
        // Validate every resolver is a literal IP before splicing it into the networksetup
        // argument string. DNS values come from the profile / server-push and — unlike routes,
        // which go through strict ParseCidr — were used unchecked; a crafted value could add
        // stray argv tokens (no shell, so token-confusion not RCE) and make the DNS-apply fail.
        // Drop non-IP entries; if nothing valid remains, don't touch DNS. (client-audit LOW)
        servers = servers.Where(s => IPAddress.TryParse(s.Trim(), out _)).Select(s => s.Trim()).ToList();
        if (servers.Count == 0)
        {
            Degrade("DNS NOT applied — no valid resolver IP in the configured DNS list; " +
                    "queries will use the system resolver, not the tunnel's");
            return false;
        }
        var service = PrimaryNetworkService();
        if (service == null)
        {
            // Not a cosmetic log line: with no service found, DNS is never pointed at the
            // tunnel and every query goes to the system resolver. (C-17)
            Degrade("DNS NOT applied — could not find the primary network service; " +
                    "queries will use the system resolver, not the tunnel's");
            return false;
        }

        // networksetup changes the PHYSICAL service, not the disposable utun. Persist the
        // exact previous list before applying the override so SIGKILL/native crash
        // can be recovered by the next privileged qeli start. The journal also refuses a
        // second live owner and preserves a newer user/system DNS change after a crash.
        ServiceState.EnsureDir();
        var journal = SystemDnsJournal(_log);
        if (!journal.TryTakeOver(service, servers, out var release, out var error))
        {
            Degrade($"DNS NOT applied to “{service}” — queries will use the system resolver, " +
                    $"not the tunnel's ({string.Join(", ", servers)}): {error}");
            return false;
        }
        _dnsRelease = release;
        _log($"DNS set to {string.Join(", ", servers)} on “{service}”");
        return true;
    }

    public void Dispose()
    {
        var failedRoutes = new List<string>();
        CleanupRoamingRoutes(failedRoutes);
        for (int i = _ownedRoutes.Count - 1; i >= 0; i--)
        {
            var route = _ownedRoutes[i];
            if (!route.Active) continue;
            try
            {
                if (!DeleteOwnedRoute(route)) failedRoutes.Add(route.Description);
            }
            catch (Exception e)
            {
                failedRoutes.Add(route.Description);
                _log($"route cleanup error ({route.Description}): {e.Message}");
            }
        }
        _ownedRoutes.RemoveAll(route => !route.Active);

        // DNS was the last host-wide change during setup, so restore it first. Its release
        // keeps the on-disk journal when networksetup fails, allowing this process and the
        // next privileged start to retry. A failed restore is NOT silently converted into a
        // successful disconnect: callers must know the host resolver is still owned by qeli.
        Exception? dnsError = null;
        var release = _dnsRelease;
        if (release != null)
        {
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    release.Invoke();
                    if (ReferenceEquals(_dnsRelease, release)) _dnsRelease = null;
                    dnsError = null;
                    break;
                }
                catch (Exception e)
                {
                    dnsError = e;
                    _log($"DNS restore attempt {attempt}/3 failed: {e.Message}");
                    if (attempt < 3) Thread.Sleep(250);
                }
            }
        }

        // Undo the remaining changes in reverse order. Remove an action only after it
        // succeeds so a failed restoration remains owned and a later Stop can retry it.
        var failedUndo = new List<string>();
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try
            {
                _undo[i]();
                _undo.RemoveAt(i);
            }
            catch (Exception e)
            {
                failedUndo.Add(e.Message);
                _log($"undo error: {e.Message}");
            }
        }

        if (dnsError != null || failedRoutes.Count != 0 || failedUndo.Count != 0)
            throw new InvalidOperationException(
                "Disconnect was incomplete; cleanup will be retried. " +
                (dnsError == null ? "" :
                    $"The original macOS DNS settings were not restored; the journal remains at {DnsStatePath}. ") +
                (failedRoutes.Count == 0 ? "" :
                    $"Routes still owned by Qeli: {string.Join(", ", failedRoutes)}. ") +
                (failedUndo.Count == 0 ? "" :
                    $"Host-network restoration still failing: {string.Join("; ", failedUndo)}."),
                dnsError);
    }

    private static DnsJournal.ReadResult ReadSystemDns(string service)
    {
        var (stdout, stderr, code) = Exec("/usr/sbin/networksetup",
            new[] { "-getdnsservers", service });
        if (code != 0)
            return new(false, Array.Empty<string>(),
                $"exit {code}: {(stdout + stderr).Trim()}");

        // With DHCP/no explicit resolver networksetup prints a sentence rather than an IP;
        // an empty list is the exact state restored with the special `empty` argument.
        var servers = stdout.Split('\n')
            .Select(line => line.Trim())
            .Where(line => IPAddress.TryParse(line, out _))
            .ToList();
        return new(true, servers, "");
    }

    private static DnsJournal.WriteResult WriteSystemDns(
        string service,
        IReadOnlyList<string> servers)
    {
        var args = new List<string> { "-setdnsservers", service };
        if (servers.Count == 0) args.Add("empty");
        else args.AddRange(servers);
        var (stdout, stderr, code) = Exec("/usr/sbin/networksetup", args);
        return code == 0
            ? new(true, "")
            : new(false, $"exit {code}: {(stdout + stderr).Trim()}");
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    /// <summary>The macOS network service (e.g. "Wi-Fi") bound to the default-route device.</summary>
    private string? PrimaryNetworkService()
    {
        try
        {
            // device behind the default route (e.g. en0)
            string? defDev = null;
            var (rt, _) = RunOut("/sbin/route", "-n get default");
            foreach (var raw in rt.Split('\n'))
            {
                var line = raw.Trim();
                if (line.StartsWith("interface:", StringComparison.Ordinal))
                    defDev = line["interface:".Length..].Trim();
            }

            // map device → service name via the service order listing
            var (order, _) = RunOut("/usr/sbin/networksetup", "-listnetworkserviceorder");
            // Blocks look like: "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)"
            var blocks = Regex.Split(order, @"\n(?=\(\d+\))");
            foreach (var block in blocks)
            {
                var m = Regex.Match(block, @"\(\d+\)\s*(.+?)\r?\n.*Device:\s*([^\)\s,]+)");
                if (m.Success && defDev != null && m.Groups[2].Value.Trim() == defDev)
                    return m.Groups[1].Value.Trim();
            }

            // Fallback: first enabled service.
            var first = Regex.Match(order, @"\(\d+\)\s*(.+)");
            return first.Success ? first.Groups[1].Value.Trim() : "Wi-Fi";
        }
        catch { return "Wi-Fi"; }
    }

    /// <summary>Run a tool, bounded. Returns true iff it exited 0, so callers can report
    /// what actually happened instead of assuming success.</summary>
    private bool Run(string exe, string args, bool optional = false)
    {
        var (stdout, stderr, code) = Exec(exe, args);
        if (code != 0 && !optional)
            throw new InvalidOperationException($"{exe} {args} -> exit {code}: {stdout}{stderr}".Trim());
        return code == 0;
    }

    /// <summary>Run a tool and return (stdout, exitCode); stderr is folded into the log on failure.</summary>
    private (string stdout, int code) RunOut(string exe, string args)
    {
        var (stdout, _, code) = Exec(exe, args);
        return (stdout, code);
    }

    /// <summary>Upper bound for one ifconfig/route/pfctl/networksetup call. These finish in
    /// well under a second normally; the bound only exists so a wedged child can never hang
    /// a connect/disconnect (or kill-switch removal) forever.</summary>
    private const int CommandTimeoutMs = 30_000;

    /// <summary>Run a tool to completion, bounded, and return (stdout, stderr, exitCode).
    ///
    /// Both pipes are drained ASYNCHRONOUSLY before waiting: a sequential
    /// ReadToEnd(stdout) then ReadToEnd(stderr) deadlocks if the child fills the stderr
    /// buffer while the parent is still blocked on stdout EOF (the same trap
    /// ServiceManager.cs already documents). A timeout kills the child and reports a
    /// non-zero code rather than hanging the caller forever.</summary>
    private static (string stdout, string stderr, int code) Exec(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(CommandTimeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            return ("", $"{exe} {args} -> timed out after {CommandTimeoutMs} ms", -1);
        }
        return (Drain(outTask), Drain(errTask), p.ExitCode);
    }

    /// <summary>ArgumentList overload for network service names and resolver arrays. Unlike
    /// a preformatted argument string it cannot reinterpret quotes/spaces in a user-renamed
    /// macOS network service as additional networksetup arguments.</summary>
    private static (string stdout, string stderr, int code) Exec(
        string exe,
        IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var p = Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(CommandTimeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            return ("", $"{exe} -> timed out after {CommandTimeoutMs} ms", -1);
        }
        return (Drain(outTask), Drain(errTask), p.ExitCode);
    }

    /// <summary>Collect an already-exited child's pipe text without ever blocking
    /// indefinitely (the process is gone, so EOF is imminent; the bound is paranoia).</summary>
    private static string Drain(Task<string> t)
    {
        try { return t.Wait(5_000) ? t.Result : ""; }
        catch { return ""; }
    }

    private static (string? addr, int prefix) ParseCidr(string cidr)
    {
        // Server-pushed / config routes are spliced into `route add ...` argument lines,
        // so an unvalidated addr token is an argument-injection vector (parity with the
        // Windows configurator). Accept only a strict IP literal (no whitespace, only
        // [0-9A-Fa-f:.]) with an in-range prefix; anything else returns (null, ..) so
        // AddRoute logs "bad route" and drops it.
        int slash = cidr.IndexOf('/');
        if (slash < 0)
        {
            if (!IsStrictIp(cidr) || !IPAddress.TryParse(cidr, out var bare)) return (null, 0);
            return (cidr, bare.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32);
        }
        string addr = cidr[..slash];
        if (!IsStrictIp(addr) || !IPAddress.TryParse(addr, out var parsed)) return (null, 0);
        int maxPrefix = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return int.TryParse(cidr[(slash + 1)..], out int prefix) && prefix >= 0 && prefix <= maxPrefix
            ? (addr, prefix) : (null, 0);
    }

    internal static void RunRouteLifecycleSelfTest(Action<string, bool> check)
    {
        const string ipv4 = "destination: 198.51.100.0\n" +
                            "mask: 255.255.255.0\n" +
                            "gateway: 192.0.2.1\n" +
                            "interface: en0\n" +
                            "flags: <UP,GATEWAY,STATIC>\n";
        var v4 = ParseExactRoute(ipv4, IPAddress.Parse("198.51.100.77"), 24);
        check("macOS route parser distinguishes an exact IPv4 prefix from a broader route",
            v4?.Gateway == "192.0.2.1" && v4.Interface == "en0" &&
            ParseExactRoute(ipv4, IPAddress.Parse("198.51.100.77"), 25) == null);

        const string ipv6 = "destination: 2001:db8:20::\n" +
                            "mask: ffff:ffff:ffff:ffff::\n" +
                            "gateway: fe80::1%en0\n" +
                            "interface: en0\n" +
                            "flags: <UP,GATEWAY,STATIC>\n";
        var v6 = ParseExactRoute(ipv6, IPAddress.Parse("2001:db8:20::beef"), 64);
        check("macOS route parser preserves exact IPv6 gateway/interface routes",
            v6?.Gateway == "fe80::1%en0" && v6.Interface == "en0");

        var scopedGateway = ParseRouteGateway("fe80::1%en0");
        check("macOS route commands restore a named scope on link-local IPv6 gateways",
            scopedGateway != null &&
            scopedGateway.ToString() == "fe80::1" &&
            RouteGatewayArgument(scopedGateway, "en0") == "fe80::1%en0");

        const string host = "destination: 203.0.113.7\n" +
                            "gateway: link#4\n" +
                            "interface: en0\n" +
                            "flags: <UP,HOST,DONE,LLINFO>\n";
        var onLink = ParseExactRoute(host, IPAddress.Parse("203.0.113.7"), 32);
        check("macOS route parser preserves an exact on-link host route",
            onLink?.Gateway == null && onLink?.Interface == "en0");
    }

    private static bool IsStrictIp(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (char c in s)
            if (!(char.IsAsciiDigit(c) || char.IsAsciiHexDigit(c) || c == ':' || c == '.'))
                return false;
        return IPAddress.TryParse(s, out _);
    }

    private static IPAddress NetworkAddress(IPAddress address, int prefix)
    {
        byte[] bytes = address.GetAddressBytes();
        if (prefix < 0 || prefix > bytes.Length * 8)
            throw new ArgumentOutOfRangeException(nameof(prefix));
        int whole = prefix / 8;
        int bits = prefix % 8;
        if (bits != 0)
        {
            bytes[whole] &= (byte)(0xff << (8 - bits));
            whole++;
        }
        Array.Clear(bytes, whole, bytes.Length - whole);
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? new IPAddress(bytes, address.ScopeId)
            : new IPAddress(bytes);
    }

    private void OwnRoute(IPAddress address, int prefix, string description, Func<bool> delete)
    {
        _ownedRoutes.Add(new OwnedRoute
        {
            Network = NetworkAddress(address, prefix).ToString(),
            Prefix = prefix,
            Description = description,
            Delete = delete,
        });
    }

    private bool DeleteOwnedRoute(OwnedRoute route)
    {
        if (!route.Active) return true;
        if (!route.Delete()) return false;
        route.Active = false;
        return true;
    }

    private int DeleteOwnedRoutes(IPAddress address, int prefix)
    {
        string network = NetworkAddress(address, prefix).ToString();
        int removed = 0;
        foreach (var route in _ownedRoutes.Where(route => route.Active &&
                     route.Prefix == prefix && route.Network == network).ToArray())
        {
            if (!DeleteOwnedRoute(route))
                throw new InvalidOperationException($"could not remove Qeli-owned {route.Description}");
            removed++;
        }
        return removed;
    }
}
