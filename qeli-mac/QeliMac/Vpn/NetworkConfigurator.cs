using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

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

    public NetworkConfigurator(Action<string> log) => _log = log;

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

    /// <summary>Pin a /32 host route to the VPN server through the physical gateway so the
    /// encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(IPAddress serverIp, IPAddress gateway)
    {
        string s = serverIp.ToString();
        Run("/sbin/route", $"-n delete -host {s}", optional: true);
        Run("/sbin/route", $"-n add -host {s} {gateway}");
        _undo.Add(() => Run("/sbin/route", $"-n delete -host {s}", optional: true));
        _log($"Pinned server route {s} via {gateway}");
    }

    /// <summary>Assign the client IP to the point-to-point utun interface and bring it up,
    /// using the server-pushed subnet prefix.</summary>
    public void SetAddress(string dev, string clientIp, int prefix = 24)
    {
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
        Run("/sbin/ifconfig", $"{dev} mtu {mtu}", optional: true);

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

    /// <summary>Capture IPv6 into the tunnel in full-tunnel mode so dual-stack traffic
    /// can't bypass it (the classic VPN IPv6 leak). The server is IPv4-only, so these
    /// packets are blackholed inside the tunnel rather than leaked — apps fall back to
    /// IPv4. Assigns a ULA to the utun and routes ::/1 + 8000::/1 through it (two /1s
    /// beat the existing default without deleting it). Optional: a host with IPv6
    /// disabled simply has nothing to capture. See RELEASE-FIXES E2.</summary>
    public void CaptureIPv6(string dev)
    {
        Run("/sbin/ifconfig", $"{dev} inet6 fd71:e1::1 prefixlen 64 up", optional: true);
        Run("/sbin/route", $"-n add -inet6 -net ::/1 -interface {dev}", optional: true);
        Run("/sbin/route", $"-n add -inet6 -net 8000::/1 -interface {dev}", optional: true);
        _undo.Add(() => Run("/sbin/route", "-n delete -inet6 -net 8000::/1", optional: true));
        _undo.Add(() => Run("/sbin/route", "-n delete -inet6 -net ::/1", optional: true));
        _log("IPv6 captured into tunnel (::/1 + 8000::/1) — no dual-stack leak");
    }

    public void AddRoute(string cidr, string dev)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return; }
        string net = $"{addr}/{prefix}";
        Run("/sbin/route", $"-n add -inet -net {net} -interface {dev}", optional: true);
        _undo.Add(() => Run("/sbin/route", $"-n delete -inet -net {net}", optional: true));
        _log($"route {cidr} via tunnel");
    }

    /// <summary>Point the primary network service's resolvers at the tunnel DNS, saving the
    /// previous setting for restore on disconnect.</summary>
    public void SetDns(IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return;
        var service = PrimaryNetworkService();
        if (service == null) { _log("DNS: could not find primary network service"); return; }

        string previous = "empty";
        try
        {
            var (cur, _) = RunOut("/usr/sbin/networksetup", $"-getdnsservers \"{service}\"");
            var ips = cur.Split('\n').Select(l => l.Trim())
                .Where(l => IPAddress.TryParse(l, out _)).ToList();
            if (ips.Count > 0) previous = string.Join(" ", ips);
        }
        catch { /* default to clearing on restore */ }

        Run("/usr/sbin/networksetup", $"-setdnsservers \"{service}\" {string.Join(" ", servers)}", optional: true);
        _undo.Add(() => Run("/usr/sbin/networksetup", $"-setdnsservers \"{service}\" {previous}", optional: true));
        _log($"DNS set to {string.Join(", ", servers)} on “{service}”");
    }

    public void Dispose()
    {
        // Undo in reverse order, best-effort.
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try { _undo[i](); } catch (Exception e) { _log($"undo error: {e.Message}"); }
        }
        _undo.Clear();
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

    private void Run(string exe, string args, bool optional = false)
    {
        var (stdout, stderr, code) = Exec(exe, args);
        if (code != 0 && !optional)
            throw new InvalidOperationException($"{exe} {args} -> exit {code}: {stdout}{stderr}".Trim());
    }

    /// <summary>Run a tool and return (stdout, exitCode); stderr is folded into the log on failure.</summary>
    private (string stdout, int code) RunOut(string exe, string args)
    {
        var (stdout, _, code) = Exec(exe, args);
        return (stdout, code);
    }

    private static (string stdout, string stderr, int code) Exec(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (stdout, stderr, p.ExitCode);
    }

    private static (string? addr, int prefix) ParseCidr(string cidr)
    {
        // Server-pushed / config routes are spliced into `route add ...` argument lines,
        // so an unvalidated addr token is an argument-injection vector (parity with the
        // Windows configurator). Accept only a strict IP literal (no whitespace, only
        // [0-9A-Fa-f:.]) with an in-range prefix; anything else returns (null, ..) so
        // AddRoute logs "bad route" and drops it.
        int slash = cidr.IndexOf('/');
        if (slash < 0) return IsStrictIp(cidr) ? (cidr, 32) : (null, 0);
        string addr = cidr[..slash];
        if (!IsStrictIp(addr)) return (null, 0);
        return int.TryParse(cidr[(slash + 1)..], out int prefix) && prefix is >= 0 and <= 32
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
