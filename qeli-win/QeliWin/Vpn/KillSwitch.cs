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
        script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dns-udp' -Group '{Group}' " +
           $"-Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Any | Out-Null");
        script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dns-tcp' -Group '{Group}' " +
           $"-Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow -Profile Any | Out-Null");
        script.AppendLine($"New-NetFirewallRule -DisplayName 'qeli kill-switch: dhcp' -Group '{Group}' " +
           $"-Direction Outbound -Protocol UDP -RemotePort 67 -Action Allow -Profile Any | Out-Null");
        // Now flip the default outbound action to Block — the allow rules above let
        // the permitted traffic through. Reached only if every rule above succeeded.
        script.AppendLine("Set-NetFirewallProfile -All -DefaultOutboundAction Block");
        Ps(script.ToString(), critical: true);

        log($"Kill-switch ENGAGED: egress restricted to tun '{tunAlias}', {string.Join(", ", ips)}, " +
            $"DNS and DHCP. Stays up across reconnects; lifted only on a clean stop. A crash leaves it " +
            $"(no leak) — clear with: Remove-NetFirewallRule -Group {Group}; " +
            $"Set-NetFirewallProfile -All -DefaultOutboundAction Allow");
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
        var full = "$ErrorActionPreference='Stop'; " + command;
        var enc = Convert.ToBase64String(Encoding.Unicode.GetBytes(full));
        var psi = new ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
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
                $"kill-switch: PowerShell step failed (exit {p.ExitCode}): {e.Trim()}");
        return o + e;
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
}
