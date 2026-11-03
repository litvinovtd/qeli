using System.Diagnostics;
using System.IO;
using System.Text;
using QeliMac.Service;

namespace QeliMac.Vpn;

/// <summary>
/// macOS firewall kill-switch (pf / pfctl). While engaged, pf is loaded with a
/// "block out all" ruleset that PASSES only: loopback, the VPN utun interface(s),
/// the server IP(s), DNS and DHCP. So when the tunnel drops, nothing of substance
/// leaks onto the physical NIC during the reconnect window.
///
/// FAIL-SAFE: the ruleset stays loaded across reconnects and is restored only on a
/// clean Stop(). A crash leaves it (the host stays locked — no leak) until qeli runs
/// again: <see cref="Sweep"/> at startup restores pf from the saved state. To clear
/// manually, flush the anchor — NOT <c>pfctl -f /etc/pf.conf</c>, which reloads the FILE
/// rather than whatever the host actually had loaded:
/// <c>sudo pfctl -a com.apple/qeli -F rules ; sudo pfctl -a qeli -F rules</c>
/// Global pf stays enabled to preserve other tools' references/policies.
///
/// REQUIRES root (the tunnel already does). Before loading the fail-closed rules, the
/// system-TUN path reserves the real utun device and passes that exact name here. During
/// an atomic persisted-plan replacement both the old and replacement names are allowed;
/// after the swap only the live device remains. CI parses, loads, reads back and flushes the
/// production-generated rules in a disposable, unreferenced pf anchor on macOS. A full traffic-
/// blocking exercise remains a physical release gate because intentionally referencing that
/// anchor would sever the hosted runner's control connection.
/// </summary>
public static class KillSwitch
{
    /// <summary>pf anchor our rules live in. Everything is scoped to this name so engaging
    /// and clearing the kill-switch never touches another tool's pf rules. (Р3)</summary>
    private const string AnchorName = "qeli";

    /// <summary>Anchor path used when the main ruleset carries the stock macOS wildcard
    /// reference <c>anchor "com.apple/*"</c>: a child anchor under <c>com.apple</c> is
    /// evaluated by that existing reference, so our rules take effect without the main
    /// ruleset being touched at all. See <see cref="ResolveAnchorPath"/>.</summary>
    private const string AppleAnchorPath = "com.apple/" + AnchorName;
    private const string AppleWildcardRef = "anchor \"com.apple/*\"";

    // Use the canonical shared dir (Paths.ServiceDir = ".../Qeli"). Was a hardcoded lowercase
    // ".../qeli", which on a case-SENSITIVE volume split kill-switch state into a second dir
    // from the daemon's (harmless on the default case-insensitive APFS). (client-audit LOW)
    private static readonly string Dir = QeliMac.Model.Paths.ServiceDir;
    private static readonly string RulesPath = Path.Combine(Dir, "killswitch.pf.conf");
    private static PfRecovery Recovery() => new(
        () => ServiceState.ReadProtected("killswitch.state", 4096),
        () => { Pf($"-a {AnchorName} -F rules", true); Pf($"-a {AppleAnchorPath} -F rules", true); },
        () => ServiceState.DeleteProtected("killswitch.pf.conf"),
        () => ServiceState.DeleteProtected("killswitch.state"),
        DnsJournal.IsOwnerAlive, DnsJournal.CurrentOwner());
    private static bool HasState() => ServiceState.ReadProtected("killswitch.state", 4096) is not null;
    private static void WriteRules(string rules) => ServiceState.WriteProtected("killswitch.pf.conf", Encoding.UTF8.GetBytes(rules));
    // Access is serialized by OperationLockPath. These are the exact live ownership set
    // reused when DDNS or a persisted-plan replacement atomically reloads the anchor.
    private static IReadOnlyList<string> _activeTunnelInterfaces = Array.Empty<string>();
    private static IReadOnlyList<string> _activeServerIps = Array.Empty<string>();

    /// <summary>Raise the kill-switch. Throws if the server can't be resolved, so the
    /// caller fails closed rather than locking the host out with no path to it.</summary>
    public static void Engage(
        string serverAddress, IReadOnlyList<string> tunnelInterfaces, Action<string> log)
    {
        var tunnels = NormalizeTunnelInterfaces(tunnelInterfaces);
        var ips = ResolveIps(serverAddress);
        if (ips.Count == 0)
            throw new InvalidOperationException(
                $"kill-switch: cannot resolve server '{serverAddress}' to an IP to allow through");

        ServiceState.EnsureDir();
        using var operation = AcquireOperation();
        if (HasState())
        {
            if (OwnerAlive())
                throw new InvalidOperationException(
                    "kill-switch is owned by another live Qeli process; stop that tunnel first");
            log("Found a stale kill-switch before engage — restoring pf first");
            DisengageLocked(log);
        }
        // Save whether pf was enabled before, so Disengage/Sweep can restore it.
        bool wasEnabled = Pf("-s info", critical: true).Contains("Status: Enabled");
        try
        {
            // Stamp the state with THIS process's identity so the startup Sweep can tell a
            // genuine crash (owner gone) from a still-live tunnel owned by ANOTHER qeli
            // instance — a second launch must NOT sweep away an active kill-switch. (C-04)
            // The enabled flag is diagnostic; cleanup never disables global pf.
            if (!ServiceState.WriteProtected("killswitch.state", PfRecovery.Encode(DnsJournal.CurrentOwner(), wasEnabled), replace: false))
                throw new InvalidOperationException("Kill-switch recovery state was claimed by another writer");

            // DNS: scope the port-53 pass to the system's configured resolvers, NEVER `to any`.
            // A blanket `pass 53 to any` let every app's DNS query egress in cleartext on the
            // physical NIC during the tunnel-down window — the metadata leak the kill-switch is
            // meant to stop. DNS is still allowed on the physical path solely so qeli can
            // RE-RESOLVE the server hostname on reconnect, so we permit it only to the resolvers
            // macOS is actually using. Fails CLOSED: if no resolver can be read, no 53 rule is
            // emitted and reconnect relies on the already-allowed cached server IP(s) below.
            // RUNTIME-UNVERIFIED: validate reconnect with a hostname (not IP) server on a real Mac.
            // Residual (accepted): an app querying those same resolvers still leaks its query
            // metadata; removing that entirely would break server re-resolution while down.
            var dnsResolvers = ResolveSystemDnsServers();
            WriteRules(BuildRules(ips, dnsResolvers, tunnels));

            // ANCHOR-BASED (Р3 / C-09). Loading these as the GLOBAL ruleset replaced whatever
            // pf was already enforcing — corporate MDM rules, Little Snitch, Docker/vmnet
            // anchors — and "restoring" by reloading /etc/pf.conf gave back the FILE, not what
            // was actually loaded. An anchor is additive: our rules live in their own namespace
            // and are removed by flushing just that namespace, leaving everything else alone.
            //
            // Pick an anchor point that is ALREADY referenced by the loaded main ruleset, then
            // load the rules into it. We no longer rewrite the main ruleset. (N3)
            string anchor = ResolveAnchorPath(log);
            Pf($"-a {anchor} -f \"{RulesPath}\"", critical: true);
            // Calling -e only when needed avoids pfctl's already-enabled warning. A failure
            // here is critical: a loaded anchor in disabled pf provides no protection.
            if (!wasEnabled) Pf("-e", critical: true);
            _activeTunnelInterfaces = tunnels;
            _activeServerIps = ips.ToArray();

            log($"Kill-switch ENGAGED (pf anchor '{anchor}'): egress restricted to lo0, " +
                $"{string.Join(", ", tunnels)}, " +
                $"{string.Join(", ", ips)}, DHCP, and DNS to {(dnsResolvers.Count > 0 ? string.Join(", ", dnsResolvers) : "<none — physical DNS blocked>")}. " +
                $"Other pf rules on this host are left intact. " +
                $"Stays up across reconnects; a crash leaves it (no leak) — clear with: " +
                $"sudo pfctl -a {anchor} -F rules");
        }
        catch (Exception engageError)
        {
            // Loading an anchor can succeed before a later step fails. Roll back every
            // app-owned candidate and restore the prior pf enabled state before reporting
            // failure; otherwise the tunnel never records ownership and cannot lift a
            // partially engaged, host-blocking ruleset.
            try
            {
                DisengageLocked(log);
            }
            catch (Exception restoreError)
            {
                throw new AggregateException(
                    "kill-switch engage failed and pf restoration also failed; " +
                    "egress may remain fail-closed and the recovery state was retained",
                    engageError,
                    restoreError);
            }
            throw;
        }
    }

    /// <summary>Atomically reload this process's private anchor with a refreshed DDNS
    /// allowlist. The owner stamp and the host's prior pf state are deliberately unchanged.</summary>
    public static void UpdateServerAddresses(IReadOnlyList<string> ips, Action<string> log)
    {
        using var operation = AcquireOperation();
        Recovery().RequireCurrentOwner();
        if (ips.Count == 0)
            throw new InvalidOperationException("kill-switch: refusing an empty server allowlist");
        if (!HasState())
            throw new InvalidOperationException("kill-switch: cannot refresh an allowlist that is not engaged");
        if (_activeTunnelInterfaces.Count == 0)
            throw new InvalidOperationException("kill-switch: no owned utun interface is recorded");

        var dnsResolvers = ResolveSystemDnsServers();
        WriteRules(BuildRules(ips, dnsResolvers, _activeTunnelInterfaces));
        string anchor = ResolveAnchorPath(log);
        // pfctl parses the complete file before replacing the anchor; a parse/load failure
        // leaves the already active fail-closed rules available to the caller's fallback.
        Pf($"-a {anchor} -f \"{RulesPath}\"", critical: true);
        _activeServerIps = ips.ToArray();
        log($"Kill-switch server allowlist refreshed in '{anchor}': {string.Join(", ", ips)}");
    }

    /// <summary>Atomically change only the exact utun ownership set while preserving the
    /// current carrier allowlist. A system-plan replacement moves the allowlist to the
    /// reserved new interface before releasing the old descriptor.</summary>
    public static void UpdateTunnelInterfaces(
        IReadOnlyList<string> tunnelInterfaces, Action<string> log)
    {
        using var operation = AcquireOperation();
        Recovery().RequireCurrentOwner();
        if (!HasState() || _activeServerIps.Count == 0)
            throw new InvalidOperationException(
                "kill-switch: cannot refresh tunnel interfaces before engage");
        var tunnels = NormalizeTunnelInterfaces(tunnelInterfaces);
        if (_activeTunnelInterfaces.SequenceEqual(tunnels))
            return;
        var dnsResolvers = ResolveSystemDnsServers();
        WriteRules(BuildRules(_activeServerIps, dnsResolvers, tunnels));
        string anchor = ResolveAnchorPath(log);
        Pf($"-a {anchor} -f \"{RulesPath}\"", critical: true);
        _activeTunnelInterfaces = tunnels;
        log($"Kill-switch tunnel allowlist refreshed in '{anchor}': " +
            string.Join(", ", tunnels));
    }

    private static string BuildRules(
        IReadOnlyList<string> ips,
        IReadOnlyList<string> dnsResolvers,
        IReadOnlyList<string> tunnelInterfaces)
    {
        ips = NormalizeAddresses(ips);
        dnsResolvers = NormalizeAddresses(dnsResolvers, resolver: true);
        tunnelInterfaces = NormalizeTunnelInterfaces(tunnelInterfaces);
        // Rules for OUR ANCHOR only — no `set block-policy`, no global directives: an
        // anchor ruleset may not carry them, and they belong to the main ruleset anyway.
        var sb = new StringBuilder();
        sb.AppendLine("block drop out all");
        sb.AppendLine("pass out quick on lo0 all");
        foreach (string tunnelInterface in tunnelInterfaces)
            sb.AppendLine($"pass out quick on {tunnelInterface} all");
        foreach (var resolver in dnsResolvers)
        {
            sb.AppendLine($"pass out quick proto udp to {resolver} port 53");
            sb.AppendLine($"pass out quick proto tcp to {resolver} port 53");
        }
        sb.AppendLine("pass out quick proto udp to any port 67");
        foreach (var ip in ips)
            sb.AppendLine($"pass out quick to {ip}");
        return sb.ToString();
    }

    private static IReadOnlyList<string> NormalizeAddresses(IReadOnlyList<string> values, bool resolver = false)
    {
        return values.Select(value =>
        {
            if (!System.Net.IPAddress.TryParse(value, out var address))
                throw new InvalidOperationException("kill-switch: invalid address in rules");
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            bool unicast = !address.Equals(System.Net.IPAddress.Any) && !address.Equals(System.Net.IPAddress.IPv6Any)
                && (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? !address.IsIPv6Multicast : address.GetAddressBytes()[0] < 224);
            if (!unicast || (resolver && !UsableResolver(address)))
                throw new InvalidOperationException("kill-switch: unusable address in rules");
            return address.ToString();
        }).Distinct().ToArray();
    }

    private static IReadOnlyList<string> NormalizeTunnelInterfaces(
        IReadOnlyList<string> tunnelInterfaces)
    {
        var result = tunnelInterfaces
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (result.Length == 0 || result.Any(name => !UtunDevice.ValidName(name)))
            throw new InvalidOperationException(
                "kill-switch: tunnel allowlist must contain only actual utunN interface names");
        return result;
    }

    /// <summary>Emit the exact production ruleset used by the macOS CI pf runtime gate.</summary>
    internal static void WriteRuntimeSelfTestRules(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("pf self-test rules path is empty", nameof(path));
        File.WriteAllText(path, BuildRules(
            new[] { "203.0.113.7", "2001:db8::7" },
            new[] { "1.1.1.1", "2606:4700:4700::1111" },
            new[] { "utun27" }));
    }

    internal static void RunSelfTests(Action<string, bool> check)
    {
        string rules = BuildRules(
            new[] { "203.0.113.7" }, new[] { "1.1.1.1" }, new[] { "utun27" });
        check("macOS kill-switch allows only the actual utun interface",
            rules.Contains("pass out quick on utun27 all", StringComparison.Ordinal) &&
            !rules.Contains("utun0", StringComparison.Ordinal) &&
            !rules.Contains("utun15", StringComparison.Ordinal));
        check("macOS kill-switch server endpoint rules use valid pf selectors",
            rules.Contains($"pass out quick to 203.0.113.7{Environment.NewLine}", StringComparison.Ordinal) &&
            !rules.Contains("pass out quick to 203.0.113.7 all", StringComparison.Ordinal));
        bool rejected = false;
        try { NormalizeTunnelInterfaces(new[] { "en0" }); }
        catch (InvalidOperationException) { rejected = true; }
        check("macOS kill-switch rejects non-utun interface aliases", rejected);
        check("macOS server endpoint accepts loopback without weakening physical DNS", BuildRules(new[] { "127.0.0.1" }, Array.Empty<string>(), new[] { "utun7" }).Contains("to 127.0.0.1"));
        check("macOS server endpoint preserves unicast link-local", BuildRules(new[] { "169.254.1.1" }, Array.Empty<string>(), new[] { "utun7" }).Contains("to 169.254.1.1"));
        foreach (string malformed in new[] { "1.1.1.1\npass out all", "224.0.0.1" })
        {
            bool invalid = false;
            try { _ = BuildRules(new[] { malformed }, Array.Empty<string>(), new[] { "utun7" }); } catch (InvalidOperationException) { invalid = true; }
            check("macOS pf rules refuse malformed/nonunicast endpoint", invalid);
        }
    }

    /// <summary>Flush owned Qeli anchors, preserving global pf and foreign rules.
    /// Throws unless all cleanup succeeds; a live foreign owner is refused.</summary>
    public static void Disengage(Action<string>? log = null)
    {
        using var operation = AcquireOperation();
        DisengageLocked(log);
    }

    private static void DisengageLocked(Action<string>? log)
    {
        if (!Recovery().Release(staleOnly: false)) return;
        _activeTunnelInterfaces = Array.Empty<string>();
        _activeServerIps = Array.Empty<string>();
        log?.Invoke("Kill-switch disengaged; Qeli anchors removed, global pf remains enabled");
    }

    /// <summary>Startup sweep: if a state file is present, a previous run crashed
    /// without restoring pf — restore it now. Call once at app start.</summary>
    public static void Sweep(Action<string>? log = null)
    {
        using var operation = AcquireOperation();
        if (!HasState()) return;
        // Only a CRASHED run's kill-switch should be swept. If the state's owning process
        // is still alive, it is an active tunnel (possibly another qeli instance) — leave
        // its kill-switch engaged rather than tearing down its protection. (C-04)
        if (OwnerAlive())
        {
            log?.Invoke("Kill-switch is owned by another live qeli process — leaving it engaged");
            return;
        }
        log?.Invoke("Found a stale kill-switch from a crashed run — restoring pf");
        DisengageLocked(log);
    }

    /// <summary>Owning process's pid + start-time recorded in the state file, if any.</summary>
    private static bool OwnerAlive()
    {
        var bytes = ServiceState.ReadProtected("killswitch.state", 4096);
        return bytes is not null && DnsJournal.IsOwnerAlive(PfRecovery.Decode(bytes).Owner);
    }

    // Filter-only output cannot prove absence of NAT/rdr/scrub or foreign anchors.
    private static string ResolveAnchorPath(Action<string> log) =>
        PfRecovery.Anchor(Pf("-sr", critical: true));

    private static IDisposable AcquireOperation()
    {
        return ServiceState.EnterOperation("killswitch.lock");
    }

    private static string Pf(string args, bool critical)
    {
        var result = ToolProcess.Run(new ProcessStartInfo("/sbin/pfctl", args));
        if (critical) ToolProcess.RequireSuccess(result, $"kill-switch pfctl {args}");
        return result.Output + result.Error;
    }

    private static List<string> ResolveIps(string serverAddress)
    {
        try
        {
            return System.Net.Dns.GetHostAddresses(serverAddress)
                .Select(ip => ip.ToString()).Distinct().ToList();
        }
        catch { return new List<string>(); }
    }

    /// <summary>The system's configured DNS resolver IPs, read from /etc/resolv.conf (macOS
    /// keeps it populated from the active network service). Used to SCOPE the kill-switch's
    /// port-53 allowance to these resolvers instead of `to any`, so arbitrary DNS cannot
    /// egress on the physical path while the tunnel is down. Empty on any read/parse failure
    /// (caller then emits no 53 rule — fail closed).</summary>
    /// <summary>Is this address a resolver worth opening a hole for? Mirrors the Windows
    /// client's filter, so all three platforms agree on what counts as an upstream.
    ///
    /// Nothing was filtered here at all. A loopback stub (which `/etc/resolv.conf` carries
    /// whenever a local resolver is in front) passed straight through: harmless as a rule —
    /// lo0 is allowed anyway — but it made the list look non-empty, which is what decides
    /// between "DNS allowed to these servers" and the fail-closed "physical DNS blocked".
    /// Link-local and the deprecated `fec0::/10` site-local range are phantoms in the same
    /// way; see the Windows counterpart for the full reasoning.</summary>
    private static bool UsableResolver(System.Net.IPAddress address) =>
        Qeli.Shared.Vpn.PhysicalDnsPolicy.IsUsableResolver(address);

    private static List<string> ResolveSystemDnsServers()
    {
        var list = new List<string>();
        try
        {
            foreach (var line in File.ReadAllLines("/etc/resolv.conf"))
            {
                var t = line.Trim();
                if (!t.StartsWith("nameserver", StringComparison.Ordinal)) continue;
                var parts = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && System.Net.IPAddress.TryParse(parts[1], out var ip)
                    && UsableResolver(ip))
                    list.Add(parts[1]);
            }
        }
        catch { /* no resolvers -> no physical DNS allowance (fail closed) */ }
        return list.Distinct().ToList();
    }
}
