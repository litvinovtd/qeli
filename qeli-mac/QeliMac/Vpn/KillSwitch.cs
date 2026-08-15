using System.Diagnostics;
using System.IO;
using System.Text;

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
/// (and <c>sudo pfctl -d</c> if pf was off before).
///
/// REQUIRES root (the tunnel already does). The utun name is dynamic and unknown
/// before the device is created, so we pass utun0..15 (mirrors the Linux `oifname`
/// matching once the device appears). RUNTIME-UNVERIFIED in this build — exercise on
/// a real Mac before shipping, since a bug here can block the machine's outbound.
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
    private static readonly string StatePath = Path.Combine(Dir, "killswitch.state");
    private static readonly string RulesPath = Path.Combine(Dir, "killswitch.pf.conf");
    private static readonly string OperationLockPath = Path.Combine(Dir, "killswitch.lock");

    /// <summary>Raise the kill-switch. Throws if the server can't be resolved, so the
    /// caller fails closed rather than locking the host out with no path to it.</summary>
    public static void Engage(string serverAddress, Action<string> log)
    {
        var ips = ResolveIps(serverAddress);
        if (ips.Count == 0)
            throw new InvalidOperationException(
                $"kill-switch: cannot resolve server '{serverAddress}' to an IP to allow through");

        Directory.CreateDirectory(Dir);
        using var operation = AcquireOperation();
        if (File.Exists(StatePath))
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
            // The pid/start lines are ignored by Disengage's `enabled=0` check.
            var self = Process.GetCurrentProcess();
            File.WriteAllText(StatePath,
                $"pid={self.Id}\nstart={self.StartTime.Ticks}\n" + (wasEnabled ? "enabled=1\n" : "enabled=0\n"));

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
            File.WriteAllText(RulesPath, BuildRules(ips, dnsResolvers));

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

            log($"Kill-switch ENGAGED (pf anchor '{anchor}'): egress restricted to lo0, utun0..15, " +
                $"{string.Join(", ", ips)}, DHCP, and DNS to {(dnsResolvers.Count > 0 ? string.Join(", ", dnsResolvers) : "<none — physical DNS blocked>")}. " +
                $"Other pf rules on this host are left intact. " +
                $"Stays up across reconnects; a crash leaves it (no leak) — clear with: " +
                $"sudo pfctl -a {anchor} -F rules" + (wasEnabled ? "" : " ; sudo pfctl -d"));
        }
        catch (Exception engageError)
        {
            // Loading an anchor can succeed before a later step fails. Roll back every
            // app-owned candidate and restore the prior pf enabled state before reporting
            // failure; otherwise the tunnel never records ownership and cannot lift a
            // partially engaged, host-blocking ruleset.
            try
            {
                Pf($"-a {AnchorName} -F rules", critical: true);
                Pf($"-a {AppleAnchorPath} -F rules", critical: true);
                if (!wasEnabled && Pf("-s info", critical: true).Contains("Status: Enabled"))
                    Pf("-d", critical: true);
                if (File.Exists(StatePath)) File.Delete(StatePath);
                if (File.Exists(RulesPath)) File.Delete(RulesPath);
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
        if (ips.Count == 0)
            throw new InvalidOperationException("kill-switch: refusing an empty server allowlist");
        if (!File.Exists(StatePath))
            throw new InvalidOperationException("kill-switch: cannot refresh an allowlist that is not engaged");

        var dnsResolvers = ResolveSystemDnsServers();
        File.WriteAllText(RulesPath, BuildRules(ips, dnsResolvers));
        string anchor = ResolveAnchorPath(log);
        // pfctl parses the complete file before replacing the anchor; a parse/load failure
        // leaves the already active fail-closed rules available to the caller's fallback.
        Pf($"-a {anchor} -f \"{RulesPath}\"", critical: true);
        log($"Kill-switch server allowlist refreshed in '{anchor}': {string.Join(", ", ips)}");
    }

    private static string BuildRules(
        IReadOnlyList<string> ips, IReadOnlyList<string> dnsResolvers)
    {
        // Rules for OUR ANCHOR only — no `set block-policy`, no global directives: an
        // anchor ruleset may not carry them, and they belong to the main ruleset anyway.
        var sb = new StringBuilder();
        sb.AppendLine("block drop out all");
        sb.AppendLine("pass out quick on lo0 all");
        // utun is dynamic; cover the usual range so the tunnel's interface is allowed
        // once it appears on (re)connect.
        sb.Append("pass out quick on {");
        for (int i = 0; i <= 15; i++) sb.Append($" utun{i}");
        sb.AppendLine(" } all");
        foreach (var resolver in dnsResolvers)
        {
            sb.AppendLine($"pass out quick proto udp to {resolver} port 53");
            sb.AppendLine($"pass out quick proto tcp to {resolver} port 53");
        }
        sb.AppendLine("pass out quick proto udp to any port 67");
        foreach (var ip in ips)
            sb.AppendLine($"pass out quick to {ip} all");
        return sb.ToString();
    }

    /// <summary>Restore pf to its pre-engage state (flush our anchors, and disable pf
    /// if it was off before). Throws unless every security-relevant step succeeds.</summary>
    public static void Disengage(Action<string>? log = null)
    {
        using var operation = AcquireOperation();
        DisengageLocked(log);
    }

    private static void DisengageLocked(Action<string>? log)
    {
        // Flush ONLY our anchor. The old code reloaded /etc/pf.conf, which wiped any rules
        // another tool had loaded and restored the file's contents rather than the state we
        // replaced. Flushing the anchor removes exactly what we added. (Р3)
        //
        // BOTH candidate paths, unconditionally: Engage picks between `qeli` and
        // `com.apple/qeli` depending on what the main ruleset references (see
        // ResolveAnchorPath), and a Sweep after a crash — or after an upgrade from a build
        // that only ever used the top-level anchor — must not leave the other one loaded and
        // still blocking. Flushing an anchor that holds nothing is a no-op.
        // (Audit 2026-07-27, N3)
        Pf($"-a {AnchorName} -F rules", critical: true);
        Pf($"-a {AppleAnchorPath} -F rules", critical: true);
        bool wasEnabled = true;
        try
        {
            foreach (var line in File.ReadAllLines(StatePath))
                if (line.Trim() == "enabled=0") wasEnabled = false;
        }
        catch { /* no state -> assume pf was on, leave it on */ }
        if (!wasEnabled && Pf("-s info", critical: true).Contains("Status: Enabled"))
            Pf("-d", critical: true); // pf was off before us -> turn it back off
        if (File.Exists(StatePath)) File.Delete(StatePath);
        if (File.Exists(RulesPath)) File.Delete(RulesPath);
        log?.Invoke("Kill-switch disengaged (pf restored)");
    }

    /// <summary>Startup sweep: if a state file is present, a previous run crashed
    /// without restoring pf — restore it now. Call once at app start.</summary>
    public static void Sweep(Action<string>? log = null)
    {
        using var operation = AcquireOperation();
        if (!File.Exists(StatePath)) return;
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
    private static (int pid, long start)? ReadOwner()
    {
        try
        {
            int pid = -1; long start = -1;
            foreach (var line in File.ReadAllLines(StatePath))
            {
                int i = line.IndexOf('=');
                if (i <= 0) continue;
                var k = line[..i].Trim();
                var v = line[(i + 1)..].Trim();
                if (k == "pid") int.TryParse(v, out pid);
                else if (k == "start") long.TryParse(v, out start);
            }
            if (pid > 0 && start >= 0) return (pid, start);
        }
        catch { }
        return null;
    }

    /// <summary>True if the state file's owning process is still running (same pid AND
    /// start-time). Legacy state without owner info is treated as crashed (swept).</summary>
    private static bool OwnerAlive()
    {
        var owner = ReadOwner();
        if (owner is null) return false;
        try
        {
            using var p = Process.GetProcessById(owner.Value.pid);
            return p.StartTime.Ticks == owner.Value.start;
        }
        catch { return false; }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Choose the anchor path to load our rules into: one the loaded main ruleset ALREADY
    /// references, because an anchor nothing references is inert — a kill-switch that
    /// silently protects nothing. Throws if there is no such reference, so Engage fails
    /// closed and the caller refuses to connect unprotected.
    ///
    /// WHY THIS NO LONGER WRITES THE MAIN RULESET (N3). The previous version read the main
    /// ruleset with `pfctl -sr`, appended `anchor "qeli"` and reloaded the result. `-sr`
    /// prints FILTER rules only, so that reload silently dropped every `nat`, `rdr`, `scrub`
    /// and `set` line the host had loaded — and `Disengage` restored none of it, because it
    /// only flushes our anchor. On a machine running Docker/vmnet (or an enterprise agent)
    /// that permanently broke port forwarding, and the damage outlived the VPN session.
    /// Restoring a faithful copy of the full ruleset is not achievable from pfctl's
    /// per-class output either, so the fix is to stop rewriting it altogether:
    ///
    ///  1. `anchor "qeli"` already referenced (a hand-edited /etc/pf.conf, or a main ruleset
    ///     a previous build of this code rewrote) → use the top-level `qeli` anchor.
    ///  2. Stock macOS: /etc/pf.conf ends with `anchor "com.apple/*"`, a WILDCARD reference
    ///     that evaluates every child anchor of `com.apple`. Loading into `com.apple/qeli`
    ///     is therefore live immediately, with zero changes to the main ruleset — the same
    ///     mechanism other macOS network tools use. It is also the last filter directive in
    ///     the stock file, so our non-quick `block drop out all` is still the last match,
    ///     exactly as when we appended the reference ourselves.
    ///  3. Neither present → refuse. Adding the reference means rewriting the main ruleset,
    ///     which is the bug. The message tells the operator the one-line fix.
    /// </summary>
    private static string ResolveAnchorPath(Action<string> log)
    {
        string current = Pf("-sr", critical: false);
        if (current.Contains($"anchor \"{AnchorName}\"", StringComparison.Ordinal))
            return AnchorName;
        if (current.Contains(AppleWildcardRef, StringComparison.Ordinal))
        {
            log($"pf: loading kill-switch rules into '{AppleAnchorPath}' " +
                $"(covered by the existing `{AppleWildcardRef}` reference — main ruleset untouched)");
            return AppleAnchorPath;
        }
        // NOTHING is loaded — the stock state of a Mac that has never enabled pf, which is
        // the default. Refusing here was wrong and made the client unusable: with
        // `kill_switch = true` the caller fails closed and never connects at all, so a
        // perfectly ordinary Mac simply stopped working on upgrade (0.7.12 got away with it
        // because it reloaded /etc/pf.conf outright).
        //
        // Loading the system's own /etc/pf.conf is safe in exactly this case and only this
        // case: the reason we refuse to touch the main ruleset is that it may carry another
        // tool's nat/rdr/scrub rules — and here there are none to lose. /etc/pf.conf is
        // Apple's file, it already carries `anchor "com.apple/*"`, and loading it is what
        // macOS's own tooling does. A NON-empty ruleset without our anchors still refuses:
        // there we would be destroying someone's live rules to make room for ours.
        if (current.Trim().Length == 0)
        {
            log("pf: no ruleset is loaded — loading the system /etc/pf.conf so an anchor can "
                + "be evaluated (nothing to overwrite: the ruleset was empty)");
            Pf("-f /etc/pf.conf", critical: false);
            current = Pf("-sr", critical: false);
            if (current.Contains(AppleWildcardRef, StringComparison.Ordinal))
                return AppleAnchorPath;
            if (current.Contains($"anchor \"{AnchorName}\"", StringComparison.Ordinal))
                return AnchorName;
        }

        throw new InvalidOperationException(
            "kill-switch: the loaded pf ruleset references neither `anchor \"com.apple/*\"` " +
            $"nor `anchor \"{AnchorName}\"`, so rules loaded into an anchor would never be " +
            "evaluated. Add `anchor \"" + AnchorName + "\"` to /etc/pf.conf and reload it " +
            "(`sudo pfctl -f /etc/pf.conf`). Refusing to engage rather than rewriting the " +
            "host's main ruleset, which would drop its nat/rdr/scrub rules.");
    }

    private static FileStream AcquireOperation()
    {
        Directory.CreateDirectory(Dir);
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (true)
        {
            try
            {
                return new FileStream(OperationLockPath, FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(100);
            }
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException(
                    "kill-switch: timed out waiting for another pf operation to finish");
        }
    }

    private static string Pf(string args, bool critical)
    {
        var psi = new ProcessStartInfo("/sbin/pfctl", args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        // Drain both pipes CONCURRENTLY and bound the call. Reading stdout to the end and
        // only then reading stderr deadlocks whenever pfctl fills the stderr buffer first
        // (it writes status there even on success): pfctl blocks on a full pipe nobody is
        // reading, we block on a stdout EOF that never comes. And with no timeout on
        // WaitForExit, a wedged pfctl hung the connect — or, worse, the kill-switch
        // TEARDOWN — forever. Same shape ServiceManager.Run2 already uses. (C-24)
        var so = p.StandardOutput.ReadToEndAsync();
        var se = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(20_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            if (critical)
                throw new InvalidOperationException(
                    $"kill-switch: pfctl {args} timed out after 20s and was killed");
            return "timed out";
        }
        string o = so.GetAwaiter().GetResult();
        string e = se.GetAwaiter().GetResult();
        if (critical && p.ExitCode != 0)
            throw new InvalidOperationException(
                $"kill-switch: pfctl {args} failed (exit {p.ExitCode}): {e.Trim()}");
        // pfctl writes status to stderr even on success, so merge both streams.
        return o + e;
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
    private static bool UsableResolver(System.Net.IPAddress a)
    {
        if (System.Net.IPAddress.IsLoopback(a)) return false;
        if (a.Equals(System.Net.IPAddress.Any) || a.Equals(System.Net.IPAddress.IPv6Any)) return false;
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return !a.IsIPv6LinkLocal && !a.IsIPv6SiteLocal && !a.IsIPv6Multicast;
        var b = a.GetAddressBytes();
        return !(b[0] == 169 && b[1] == 254);   // APIPA
    }

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
