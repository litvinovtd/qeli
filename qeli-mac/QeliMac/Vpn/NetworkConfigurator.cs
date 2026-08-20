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
public sealed class NetworkConfigurator : IDisposable
{
    private readonly Action<string> _log;
    private readonly List<Action> _undo = new();
    private readonly List<string> _degraded = new();
    private Action? _dnsRelease;

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
                else if (line.StartsWith("gateway:", StringComparison.Ordinal) &&
                         IPAddress.TryParse(line["gateway:".Length..].Trim(), out var g))
                    gw = g;
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

    private sealed record ExistingHostRoute(string? Gateway, string? Interface);

    /// <summary>
    /// Existing exact HOST (/32 or /128) route, or null when lookup resolved through a
    /// broader/default prefix. `route get` is safe here because its `destination:` field is
    /// required to equal the requested address; merely receiving a gateway is not enough.
    /// Preserve interface routes as well as gateway routes so scoped/on-link IPv6 policy is
    /// restored byte-for-byte at disconnect.
    /// </summary>
    private ExistingHostRoute? ExistingHostRouteFor(IPAddress ip)
    {
        try
        {
            bool v6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            var (outp, _) = RunOut("/sbin/route", $"-n get {(v6 ? "-inet6" : "-inet")} {ip}");
            string? destination = null, gateway = null, iface = null;
            foreach (var raw in outp.Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith("destination:", StringComparison.Ordinal))
                    destination = line["destination:".Length..].Trim();
                else if (line.StartsWith("gateway:", StringComparison.Ordinal))
                    gateway = line["gateway:".Length..].Trim();
                else if (line.StartsWith("interface:", StringComparison.Ordinal))
                    iface = line["interface:".Length..].Trim();
            }
            if (destination == null || !SameAddressIgnoringScope(destination, ip)) return null;
            // link#N is a kernel interface next-hop, not a gateway accepted by route(8).
            return gateway != null && gateway.StartsWith("link#", StringComparison.Ordinal)
                ? new ExistingHostRoute(null, iface)
                : new ExistingHostRoute(gateway, iface);
        }
        catch (Exception e) { _log($"could not read the existing host route for {ip}: {e.Message}"); }
        return null;
    }

    private static bool SameAddressIgnoringScope(string literal, IPAddress expected)
    {
        int zone = literal.IndexOf('%');
        if (zone >= 0) literal = literal[..zone];
        return IPAddress.TryParse(literal, out var parsed)
               && parsed.AddressFamily == expected.AddressFamily
               && parsed.GetAddressBytes().SequenceEqual(expected.GetAddressBytes());
    }

    /// <summary>Pin a /32 or /128 host route to the VPN server through the physical gateway so
    /// the encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(IPAddress serverIp, IPAddress gateway)
    {
        if (serverIp.AddressFamily != gateway.AddressFamily)
            throw new InvalidOperationException(
                $"server route family mismatch: server {serverIp}, gateway {gateway}");
        string s = serverIp.ToString();
        // Remember any PRE-EXISTING host route for this IP before we replace it. The undo
        // only ever deleted ours, so a host that had its own /32 for the server (a second
        // link, a management route) lost it permanently on the first connect — the delete
        // below is destructive and nothing put it back. (C-18)
        bool v6 = serverIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        string family = v6 ? "-inet6" : "-inet";
        ExistingHostRoute? previous = ExistingHostRouteFor(serverIp);
        Run("/sbin/route", $"-n delete {family} -host {s}", optional: true);
        Run("/sbin/route", $"-n add {family} -host {s} {gateway}");
        _undo.Add(() =>
        {
            Run("/sbin/route", $"-n delete {family} -host {s}", optional: true);
            if (previous?.Gateway != null)
            {
                Run("/sbin/route", $"-n add {family} -host {s} {previous.Gateway}", optional: true);
                _log($"restored the pre-existing host route {s} via {previous.Gateway}");
            }
            else if (previous?.Interface != null)
            {
                Run("/sbin/route", $"-n add {family} -host {s} -interface {previous.Interface}", optional: true);
                _log($"restored the pre-existing host route {s} on {previous.Interface}");
            }
        });
        _log($"Pinned server route {s} via {gateway}"
             + (previous != null ? " (temporarily replacing an existing exact host route)" : ""));
    }

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
            _undo.Add(() => Run("/sbin/ifconfig", $"{dev} inet6 {clientIp} -alias", optional: true));
            _log($"Set {dev} address {clientIp}/{prefix}");
            return;
        }
        // utun is point-to-point: local == dest, server-pushed mask for the tunnel subnet.
        int p = (prefix is >= 1 and <= 32) ? prefix : 24;
        string mask = PrefixToMask(p);
        Run("/sbin/ifconfig", $"{dev} inet {clientIp} {clientIp} netmask {mask} up");
        _log($"Set {dev} address {clientIp}/{p}");
    }

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
        Run("/sbin/route", $"-n add -inet -net 128.0.0.0/1 -interface {dev}");
        _undo.Add(() => Run("/sbin/route", "-n delete -inet -net 0.0.0.0/1", optional: true));
        _undo.Add(() => Run("/sbin/route", "-n delete -inet -net 128.0.0.0/1", optional: true));
        _log("Default route now via tunnel (0.0.0.0/1 + 128.0.0.0/1)");
    }

    public void SetFullTunnelRoutesV6(string dev)
    {
        string[] nets = { "::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7" };
        foreach (var net in nets)
        {
            Run("/sbin/route", $"-n add -inet6 -net {net} -interface {dev}");
            string captured = net;
            _undo.Add(() => Run("/sbin/route",
                $"-n delete -inet6 -net {captured}", optional: true));
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
            if (!Run("/sbin/route", $"-n add -inet6 -net {net} -interface {dev}", optional: true))
                failed.Add(net);
        foreach (var net in nets)
        {
            string n = net; // capture per-iteration for the undo closure
            _undo.Add(() => Run("/sbin/route", $"-n delete -inet6 -net {n}", optional: true));
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

    public bool AddRoute(string cidr, string dev)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return false; }
        string net = $"{addr}/{prefix}";
        string family = IPAddress.Parse(addr).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        // Logging "via tunnel" after a failed add was simply untrue. (C-17)
        if (!Run("/sbin/route", $"-n add {family} -net {net} -interface {dev}", optional: true))
        {
            Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
            return false;
        }
        _undo.Add(() => Run("/sbin/route", $"-n delete {family} -net {net}", optional: true));
        _log($"route {cidr} via tunnel");
        return true;
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        string family = IPAddress.Parse(addr).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "-inet6" : "-inet";
        Run("/sbin/route", $"-n delete {family} -net {addr}/{prefix}", optional: true);
        _log($"exclude {cidr} from tunnel");
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
        string net = $"{addr}/{prefix}";
        bool v6 = IPAddress.Parse(addr).AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        string family = v6 ? "-inet6" : "-inet";
        if (gateway != null && gateway.AddressFamily != (v6
                ? System.Net.Sockets.AddressFamily.InterNetworkV6
                : System.Net.Sockets.AddressFamily.InterNetwork))
            gateway = null;
        Run("/sbin/route", $"-n delete {family} -net {net}", optional: true);  // clear any tunnel copy
        // In full-tunnel the /1 halves cover this prefix, so a failed pin leaves the
        // destination INSIDE the tunnel — the opposite of the requested exclude, and for
        // the server-IP bypass that is exactly what wedges a reconnect. (C-17)
        string? nextHop = gateway != null ? gateway.ToString()
            : !string.IsNullOrWhiteSpace(physicalInterface) ? $"-interface {physicalInterface}"
            : null;
        if (nextHop == null || !Run("/sbin/route", $"-n add {family} -net {net} {nextHop}", optional: true))
            throw new InvalidOperationException(
                $"exclude route {cidr} has no usable physical path or was not programmed");
        _undo.Add(() => Run("/sbin/route", $"-n delete {family} -net {net}", optional: true));
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

        // Undo the remaining changes in reverse order, best-effort.
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try { _undo[i](); } catch (Exception e) { _log($"undo error: {e.Message}"); }
        }
        _undo.Clear();

        if (dnsError != null)
            throw new InvalidOperationException(
                "Disconnect was incomplete because the original macOS DNS settings could not be restored. " +
                $"The recovery journal was kept at {DnsStatePath} and the next privileged cleanup will retry.",
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

    private static bool IsStrictIp(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (char c in s)
            if (!(char.IsAsciiDigit(c) || char.IsAsciiHexDigit(c) || c == ':' || c == '.'))
                return false;
        return IPAddress.TryParse(s, out _);
    }
}
