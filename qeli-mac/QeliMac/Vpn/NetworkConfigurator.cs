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
    private readonly List<string> _degraded = new();

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

    private void Degrade(string what)
    {
        _degraded.Add(what);
        _log($"WARNING: {what}");
    }

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
    /// IPv4. `::/1 + 8000::/1` beat the default `::/0`, but a router-advertised `2000::/3`
    /// (GUA) is MORE specific and would still win by longest-prefix — so we ALSO add
    /// `2000::/4 + 3000::/4` (= all of `2000::/3`) and `fc00::/7` (ULA), like OpenVPN's
    /// redirect-gateway. Optional: a host with IPv6 disabled has nothing to capture.</summary>
    public void CaptureIPv6(string dev)
    {
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

        // Report what ACTUALLY happened. These commands are optional by design — a host
        // with IPv6 disabled has nothing to capture and every add fails harmlessly, so a
        // failure is NOT proof of a leak and must not abort the connection. But claiming
        // "captured" unconditionally hid the opposite case (IPv6 present, capture partly
        // or wholly failed → traffic leaves outside the tunnel while the log said it was
        // covered). Say which ranges are actually covered and flag the leak risk.
        if (failed.Count == 0)
            _log($"IPv6 captured into tunnel ({string.Join(", ", nets)})");
        else if (failed.Count == nets.Length)
            _log("IPv6 NOT captured: every route add failed. If this host has IPv6 disabled " +
                 "there is nothing to capture and nothing leaks; if it does have IPv6, that " +
                 "traffic is leaving OUTSIDE the tunnel — check that qeli runs as root.");
        else
            _log($"WARNING: IPv6 only partially captured — {nets.Length - failed.Count}/{nets.Length} " +
                 $"ranges; failed: {string.Join(", ", failed)}. IPv6 matching the failed ranges may " +
                 "leave OUTSIDE the tunnel.");
        if (!addrOk && failed.Count != nets.Length)
            _log("note: the tunnel's IPv6 address could not be added; IPv6 capture may be incomplete.");
    }

    public void AddRoute(string cidr, string dev)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return; }
        string net = $"{addr}/{prefix}";
        // Logging "via tunnel" after a failed add was simply untrue. (C-17)
        if (!Run("/sbin/route", $"-n add -inet -net {net} -interface {dev}", optional: true))
        {
            Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
            return;
        }
        _undo.Add(() => Run("/sbin/route", $"-n delete -inet -net {net}", optional: true));
        _log($"route {cidr} via tunnel");
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        Run("/sbin/route", $"-n delete -inet -net {addr}/{prefix}", optional: true);
        _log($"exclude {cidr} from tunnel");
    }

    /// <summary>Route a subnet AROUND the tunnel via the physical gateway, so an excluded
    /// destination reaches the network directly even in full-tunnel (where a plain
    /// DeleteRoute is a no-op — the two-halves splits still cover it). The specific prefix
    /// beats the /1 halves by longest-prefix match. Undone on disconnect.</summary>
    public void PinBypassRoute(string cidr, IPAddress gateway)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        string net = $"{addr}/{prefix}";
        Run("/sbin/route", $"-n delete -inet -net {net}", optional: true);  // clear any tunnel copy
        // In full-tunnel the /1 halves cover this prefix, so a failed pin leaves the
        // destination INSIDE the tunnel — the opposite of the requested exclude, and for
        // the server-IP bypass that is exactly what wedges a reconnect. (C-17)
        if (!Run("/sbin/route", $"-n add -inet -net {net} {gateway}", optional: true))
        {
            Degrade($"bypass route {cidr} via {gateway} NOT programmed — it stays inside the tunnel");
            return;
        }
        _undo.Add(() => Run("/sbin/route", $"-n delete -inet -net {net}", optional: true));
        _log($"exclude {cidr} via physical gateway {gateway}");
    }

    /// <summary>Point the primary network service's resolvers at the tunnel DNS, saving the
    /// previous setting for restore on disconnect.</summary>
    public void SetDns(IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return;
        var service = PrimaryNetworkService();
        if (service == null)
        {
            // Not a cosmetic log line: with no service found, DNS is never pointed at the
            // tunnel and every query goes to the system resolver. (C-17)
            Degrade("DNS NOT applied — could not find the primary network service; " +
                    "queries will use the system resolver, not the tunnel's");
            return;
        }

        string previous = "empty";
        try
        {
            var (cur, _) = RunOut("/usr/sbin/networksetup", $"-getdnsservers \"{service}\"");
            var ips = cur.Split('\n').Select(l => l.Trim())
                .Where(l => IPAddress.TryParse(l, out _)).ToList();
            if (ips.Count > 0) previous = string.Join(" ", ips);
        }
        catch { /* default to clearing on restore */ }

        if (!Run("/usr/sbin/networksetup",
                 $"-setdnsservers \"{service}\" {string.Join(" ", servers)}", optional: true))
        {
            Degrade($"DNS NOT applied to “{service}” — queries will use the system resolver, " +
                    $"not the tunnel's ({string.Join(", ", servers)})");
            return;
        }
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
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
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
