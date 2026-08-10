using System.Diagnostics;
using System.IO;
using System.Text;

namespace QeliWin.Vpn;

/// <summary>
/// Windows firewall kill-switch (Windows Filtering Platform via the NetSecurity
/// PowerShell cmdlets). While engaged, the profile DefaultOutboundAction is set to
/// Block and a small "qeli_ks" rule group ALLOWS only: the VPN tun adapter, the
/// server IP(s), DNS and DHCP (loopback is always permitted by Windows). So when
/// the tunnel drops, nothing of substance leaks onto the physical NIC during the
/// reconnect window. Explicit Allow rules beat the Block default, so this is true
/// allow-list egress (no "block rule vs allow rule" precedence trap).
///
/// FAIL-SAFE: the rules + default-block stay up across reconnects and are lifted
/// only on a clean Stop(). A crash leaves them in place (the host stays locked — no
/// leak) until qeli runs again: <see cref="Sweep"/> at startup restores egress from
/// the saved state. To clear manually:
///   Remove-NetFirewallRule -Group qeli_ks; Set-NetFirewallProfile -All -DefaultOutboundAction Allow
///
/// REQUIRES admin (the VPN already does, for Wintun). RUNTIME-UNVERIFIED in this
/// build — exercise on a disposable Windows box before shipping, since a bug here
/// can block the machine's outbound.
/// </summary>
public static class KillSwitch
{
    private const string Group = "qeli_ks";

    private static string StatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "qeli", "killswitch.state");

    /// <summary>Raise the kill-switch: allow only <paramref name="tunAlias"/>, the
    /// resolved server IP(s), DNS and DHCP; block the rest. Idempotent. Throws if the
    /// server can't be resolved (so the caller fails closed rather than locking the
    /// host out with no path to the server).</summary>
    public static void Engage(string serverAddress, string tunAlias, Action<string> log)
    {
        var ips = ResolveIps(serverAddress);
        if (ips.Count == 0)
            throw new InvalidOperationException(
                $"kill-switch: cannot resolve server '{serverAddress}' to an IP to allow through");

        // Save the current per-profile outbound actions so Disengage/Sweep can
        // restore them, BEFORE we change anything.
        var prior = GetOutboundActions();
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
        // Stamp the state with THIS process's identity (pid + start-time) so the startup
        // Sweep can tell a genuine crash (owner gone) from a still-live tunnel owned by
        // ANOTHER qeli instance — a second launch must NOT sweep away an active
        // kill-switch. (C-04) The `pid=`/`start=` lines are ignored by ReadState (they are
        // not valid profile names), so the restore path is unaffected.
        var self = Process.GetCurrentProcess();
        var stateLines = new List<string> { $"pid={self.Id}", $"start={self.StartTime.Ticks}" };
        stateLines.AddRange(prior.Select(kv => $"{kv.Key}={kv.Value}"));
        File.WriteAllText(StatePath, string.Join("\n", stateLines));

        // Clear any leftovers from a crashed run, then add the allow rules FIRST so
        // they already exist when the default flips to Block (no lockout window).
        // All of this runs in ONE PowerShell invocation (was ~7 process launches per
        // connect — each powershell.exe cold-start is ~100-300ms). Behaviour is
        // unchanged: the script has $ErrorActionPreference='Stop' (see Ps), so any
        // failing New-NetFirewallRule terminates the script BEFORE the default flips
        // to Block — same fail-closed guarantee as the per-command version, and
        // Remove-NetFirewallRule keeps its own -ErrorAction SilentlyContinue so a
        // missing group is still a no-op.
        var script = new StringBuilder();
        script.AppendLine($"Remove-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue");
        foreach (var ip in ips)
            script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: server {ip}' -Group '{Group}' " +
               $"-Direction Outbound -RemoteAddress {ip} -Action Allow -Profile Any | Out-Null");
        // tunAlias can be a user-set config.DevNode: escape single-quotes (PowerShell
        // doubles them inside a '...' literal) so a `'` can't break out of the argument.
        script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: tun' -Group '{Group}' " +
           $"-Direction Outbound -InterfaceAlias '{(tunAlias ?? "").Replace("'", "''")}' -Action Allow -Profile Any | Out-Null");
        // DNS: scope port 53 to the system's configured resolvers, NEVER to any remote
        // address. An unrestricted `RemotePort 53` rule let every app's DNS query egress in
        // cleartext on the physical NIC during the tunnel-down window — the metadata leak the
        // kill-switch is meant to stop. DNS is still permitted on the physical path only so the
        // server hostname can be RE-RESOLVED on reconnect, so we allow it only to the resolvers
        // in use. Fail closed: no resolvers -> no rule, reconnect uses the allowed cached
        // server IP(s) above. Residual (accepted): an app querying those same resolvers still
        // leaks its query; removing that would break re-resolution while down. (client-audit LOW)
        var dnsServers = ResolveDnsServers();
        foreach (var r in dnsServers)
        {
            script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dns-udp {r}' -Group '{Group}' " +
               $"-Direction Outbound -Protocol UDP -RemotePort 53 -RemoteAddress {r} -Action Allow -Profile Any | Out-Null");
            script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dns-tcp {r}' -Group '{Group}' " +
               $"-Direction Outbound -Protocol TCP -RemotePort 53 -RemoteAddress {r} -Action Allow -Profile Any | Out-Null");
        }
        script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dhcp' -Group '{Group}' " +
           $"-Direction Outbound -Protocol UDP -RemotePort 67 -Action Allow -Profile Any | Out-Null");
        // Now flip the default outbound action to Block — the allow rules above let
        // the permitted traffic through. Reached only if every rule above succeeded.
        script.AppendLine("Set-NetFirewallProfile -All -DefaultOutboundAction Block");
        try { Ps(script.ToString(), critical: true); }
        catch
        {
            // The default outbound action is flipped by the LAST line, so a failure here means
            // it was never applied and there is nothing to restore — egress is untouched. But
            // the allow rules created before the failure, and the state file written above,
            // would linger; and because THIS process is still alive, the next startup Sweep
            // would read that state, see a live owner and deliberately leave the leftovers in
            // place (C-04). Undo our own partial work before failing closed.
            try { Ps($"Remove-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue", critical: false); } catch { }
            try { File.Delete(StatePath); } catch { }
            throw;
        }

        log($"Kill-switch ENGAGED: egress restricted to tun '{tunAlias}', {string.Join(", ", ips)}, DHCP, and " +
            $"DNS to {(dnsServers.Count > 0 ? string.Join(", ", dnsServers) : "<none — physical DNS blocked>")}. " +
            $"Stays up across reconnects; lifted only on a clean stop. A crash leaves it " +
            $"(no leak) — clear with: Remove-NetFirewallRule -Group {Group}; " +
            $"Set-NetFirewallProfile -All -DefaultOutboundAction Allow");
    }

    /// <summary>Replace only the server-IP portion of an already engaged allowlist. New
    /// addresses are added before obsolete ones are removed, so DDNS refresh never creates
    /// a window in which neither generation can reach the server. The saved pre-qeli firewall
    /// state and every non-server rule remain untouched.</summary>
    public static void UpdateServerAddresses(
        IReadOnlyList<string> previous, IReadOnlyList<string> refreshed, Action<string> log)
    {
        var oldSet = previous.ToHashSet(StringComparer.Ordinal);
        var newSet = refreshed.ToHashSet(StringComparer.Ordinal);
        if (newSet.Count == 0)
            throw new InvalidOperationException("kill-switch: refusing an empty server allowlist");

        var added = newSet.Except(oldSet).ToArray();
        var removed = oldSet.Except(newSet).ToArray();
        if (added.Length == 0 && removed.Length == 0) return;

        var script = new StringBuilder();
        foreach (var ip in added)
            script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: server {ip}' -Group '{Group}' " +
                $"-Direction Outbound -RemoteAddress {ip} -Action Allow -Profile Any | Out-Null");
        foreach (var ip in removed)
            script.AppendLine($"Remove-NetFirewallRule -DisplayName 'qeli kill-switch: server {ip}' " +
                "-ErrorAction SilentlyContinue");
        Ps(script.ToString(), critical: true);
        log($"Kill-switch server allowlist refreshed: {string.Join(", ", refreshed)}");
    }

    /// <summary>Lift the kill-switch: remove our rules and restore the saved
    /// per-profile outbound actions. Best-effort; safe to call when not engaged.</summary>
    public static void Disengage(Action<string>? log = null)
    {
        Ps($"Remove-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue", critical: false);
        var prior = ReadState();
        if (prior.Count > 0)
            foreach (var kv in prior)
                Ps($"Set-NetFirewallProfile -Name {kv.Key} -DefaultOutboundAction {kv.Value}", critical: false);
        else
            // No saved state (shouldn't happen) — restore the NEUTRAL Windows default
            // (NotConfigured), NOT an explicit Allow that could weaken a pre-existing
            // firewall policy we have no record of. (C-05)
            Ps("Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured", critical: false);
        try { File.Delete(StatePath); } catch { }
        log?.Invoke("Kill-switch disengaged (egress restored)");
    }

    /// <summary>Startup sweep: if a state file is present, a previous run crashed
    /// without lifting the kill-switch — restore egress now so the host isn't left
    /// firewalled. Call once at app start.</summary>
    public static void Sweep(Action<string>? log = null)
    {
        if (!File.Exists(StatePath)) return;
        // Only a CRASHED run's kill-switch should be swept. If the state's owning process
        // is still alive, it is an active tunnel (possibly another qeli instance) — leave
        // its kill-switch engaged rather than tearing down its protection. (C-04)
        if (OwnerAlive())
        {
            log?.Invoke("Kill-switch is owned by another live qeli process — leaving it engaged");
            return;
        }
        log?.Invoke("Found a stale kill-switch from a crashed run — restoring egress");
        Disengage(log);
    }

    /// <summary>Parse the owning process's pid + start-time recorded in the state file.</summary>
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
                if (k.Equals("pid", StringComparison.OrdinalIgnoreCase)) int.TryParse(v, out pid);
                else if (k.Equals("start", StringComparison.OrdinalIgnoreCase)) long.TryParse(v, out start);
            }
            if (pid > 0 && start >= 0) return (pid, start);
        }
        catch { }
        return null;
    }

    /// <summary>True if the state file's owning process is still running (same pid AND
    /// start-time, so a reused pid doesn't count). Legacy state without owner info is
    /// treated as crashed (swept), preserving the old behaviour for pre-upgrade files.</summary>
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

    private static Dictionary<string, string> GetOutboundActions()
    {
        var outp = Ps(
            "Get-NetFirewallProfile -All | ForEach-Object { \"$($_.Name)=$($_.DefaultOutboundAction)\" }",
            critical: false);
        var d = new Dictionary<string, string>();
        foreach (var raw in outp.Split('\n'))
        {
            var t = raw.Trim();
            int i = t.IndexOf('=');
            if (i <= 0) continue;
            var name = t[..i].Trim();
            var act = t[(i + 1)..].Trim();
            // Preserve the ACTUAL prior value (NotConfigured/Allow/Block): coercing
            // NotConfigured → an explicit Allow would weaken a pre-existing firewall
            // posture on restore. Only an unknown value falls back to the safe Allow. (C-05)
            if (act.Equals("Block", StringComparison.OrdinalIgnoreCase)) act = "Block";
            else if (act.Equals("NotConfigured", StringComparison.OrdinalIgnoreCase)) act = "NotConfigured";
            else act = "Allow";
            if (name.Length > 0) d[name] = act;
        }
        return d;
    }

    /// <summary>
    /// Read the saved per-profile outbound actions, accepting ONLY the values
    /// Windows can actually have.
    /// </summary>
    /// <remarks>
    /// This file lives in %LOCALAPPDATA% — writable by the user and by anything
    /// running as them — and its contents are interpolated into a PowerShell script
    /// that runs from an elevated process at startup (see Sweep / Program.Main).
    /// Read verbatim, a planted line such as <c>Domain=Allow; calc.exe</c> executed
    /// as administrator: -EncodedCommand solves argv quoting, not script-level
    /// injection, so the payload ran as part of the script body.
    ///
    /// Escaping would be fragile here. There are exactly three firewall profiles and
    /// two actions, so an allow-list is both simpler and total: anything not on it is
    /// not data we wrote, and is dropped. Nothing that reaches the script can carry a
    /// separator, a quote or a newline.
    /// </remarks>
    private static Dictionary<string, string> ReadState()
    {
        // The only profile names Set-NetFirewallProfile -Name accepts.
        string[] validProfiles = { "Domain", "Private", "Public" };
        var d = new Dictionary<string, string>();
        try
        {
            foreach (var line in File.ReadAllLines(StatePath))
            {
                int i = line.IndexOf('=');
                if (i <= 0) continue;
                var name = line[..i].Trim();
                var act = line[(i + 1)..].Trim();

                var profile = Array.Find(validProfiles,
                    p => p.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (profile is null) continue;   // not a profile we ever wrote

                // Same rule as the writer: preserve NotConfigured verbatim; only an
                // unknown value falls back to Allow. (C-05)
                var action = act.Equals("Block", StringComparison.OrdinalIgnoreCase) ? "Block"
                    : act.Equals("NotConfigured", StringComparison.OrdinalIgnoreCase) ? "NotConfigured"
                    : "Allow";
                d[profile] = action;
            }
        }
        catch { /* missing/unreadable -> caller falls back */ }
        return d;
    }

    /// <summary>Run a PowerShell command via -EncodedCommand (no quoting pitfalls).
    /// When <paramref name="critical"/>, a terminating error / non-zero exit throws,
    /// so Engage fails closed if a rule can't be applied.</summary>
    private static string Ps(string command, bool critical)
    {
        // $ErrorActionPreference=Stop makes cmdlet errors terminate the process with
        // a non-zero exit code, which we can detect for the critical steps.
        //
        // powershell.exe serializes its ERROR stream as CLIXML whenever stderr is redirected
        // (which it always is here), so a failure used to surface as an unreadable `#< CLIXML`
        // blob — the one place where the message actually matters. For the critical steps,
        // catch in-script and echo the message on STDOUT as plain text instead. Non-critical
        // calls are left alone: their stdout is PARSED (GetOutboundActions), and an extra line
        // there would be misread as data.
        var full = critical
            ? "$ErrorActionPreference='Stop'; try {\n" + command +
              "\n} catch { [Console]::Out.WriteLine('QELI_ERR: ' + $_.Exception.Message); exit 1 }"
            : "$ErrorActionPreference='Stop'; " + command;
        var enc = Convert.ToBase64String(Encoding.Unicode.GetBytes(full));
        // Absolute path, not a bare name: CreateProcessW searches the calling image's
        // directory before System32, and this runs elevated. (Audit 2026-08-04, H-05.)
        var psi = new ProcessStartInfo(SystemPaths.PowerShell,
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = SystemPaths.SystemDirectory,
        };
        using var p = Process.Start(psi)!;
        // Drain both pipes ASYNCHRONOUSLY before waiting: a sequential ReadToEnd(stdout)
        // then ReadToEnd(stderr) deadlocks if PowerShell fills the stderr buffer while we
        // are still blocked on stdout EOF. And bound the wait — an unbounded WaitForExit
        // on a wedged powershell.exe would hang Engage (tunnel never comes up) or, worse,
        // Disengage (the kill-switch rules stay installed and the machine stays locked).
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(PsTimeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            var timedOut = $"kill-switch: PowerShell step timed out after {PsTimeoutMs} ms";
            if (critical) throw new InvalidOperationException(timedOut);
            return timedOut;
        }
        string o = Drain(outTask), e = Drain(errTask);
        if (critical && p.ExitCode != 0)
            throw new InvalidOperationException(
                $"kill-switch: PowerShell step failed (exit {p.ExitCode}): {ErrorDetail(o, e)}");
        return o + e;
    }

    /// <summary>The readable reason a critical step failed: the message our in-script catch
    /// echoed on stdout, falling back to stderr. A raw CLIXML blob is named rather than
    /// dumped — pasting it into a log tells the reader nothing.</summary>
    private static string ErrorDetail(string stdout, string stderr)
    {
        const string marker = "QELI_ERR: ";
        foreach (var line in stdout.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith(marker, StringComparison.Ordinal)) return t[marker.Length..];
        }
        var s = stderr.Trim();
        return s.StartsWith("#< CLIXML", StringComparison.Ordinal)
            ? "(PowerShell returned a serialized CLIXML error and no message reached stdout)"
            : s;
    }

    /// <summary>Upper bound for one PowerShell step. Generous — a firewall cmdlet can be
    /// slow on a loaded machine — but never unbounded.</summary>
    private const int PsTimeoutMs = 60_000;

    /// <summary>Collect an already-exited child's pipe text without blocking indefinitely.</summary>
    private static string Drain(Task<string> t)
    {
        try { return t.Wait(5_000) ? t.Result : ""; }
        catch { return ""; }
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

    /// <summary>The system's configured DNS resolver IPs across all up interfaces. Used to
    /// SCOPE the kill-switch's port-53 allowance instead of opening 53 to any remote address.
    /// Loopback and link-local are excluded (not real upstream resolvers / can't be a valid
    /// -RemoteAddress); IPv6 scope ids are stripped. Empty on failure -> caller emits no DNS
    /// rule (fail closed).</summary>
    /// <summary>Is this address a resolver worth opening a hole for?
    ///
    /// Windows reports `fec0:0:0:ffff::1/2/3` as DNS servers on virtually every IPv6-enabled
    /// interface — they are hardcoded defaults in a prefix (`fec0::/10`) that RFC 3879
    /// deprecated in 2004, and nothing routes there. They used to sail through: the filter
    /// skipped IPv6 LINK-local but not SITE-local. Two costs. Six pointless firewall rules
    /// per connect, and — the one that matters — they make the resolver list look non-empty,
    /// so on a machine whose only listed servers are these phantoms the code believes it has
    /// allowed DNS while every real query is blocked. The fail-closed branch that would have
    /// said "physical DNS blocked, reconnects use the cached server IP" is skipped, and a
    /// hostname reconnect just fails with nothing in the log to explain it.
    ///
    /// Loopback is skipped for the same reason it is on the other platforms: a local stub is
    /// reachable regardless, and counting it as "we have a resolver" hides that the real
    /// upstreams are unknown. IPv4 link-local (169.254/16, APIPA) is the same class of
    /// phantom as fec0::.</summary>
    private static bool UsableResolver(System.Net.IPAddress a)
    {
        if (System.Net.IPAddress.IsLoopback(a)) return false;
        if (a.Equals(System.Net.IPAddress.Any) || a.Equals(System.Net.IPAddress.IPv6Any)) return false;
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            return !a.IsIPv6LinkLocal && !a.IsIPv6SiteLocal && !a.IsIPv6Multicast;
        var b = a.GetAddressBytes();
        return !(b[0] == 169 && b[1] == 254);   // APIPA
    }

    private static List<string> ResolveDnsServers()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var dns in ni.GetIPProperties().DnsAddresses)
                {
                    if (!UsableResolver(dns)) continue;
                    // Strip any IPv6 scope id (%N) — New-NetFirewallRule -RemoteAddress rejects it.
                    var s = dns.ToString();
                    int pct = s.IndexOf('%');
                    if (pct >= 0) s = s[..pct];
                    list.Add(s);
                }
            }
        }
        catch { /* no resolvers -> no physical DNS allowance (fail closed) */ }
        return list.Distinct().ToList();
    }
}
