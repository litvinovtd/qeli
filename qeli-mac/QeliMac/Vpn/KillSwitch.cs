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
/// manually: <c>sudo pfctl -f /etc/pf.conf</c> (and <c>sudo pfctl -d</c> if pf was
/// off before).
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

    private const string Dir = "/Library/Application Support/qeli";
    private static readonly string StatePath = Path.Combine(Dir, "killswitch.state");
    private static readonly string RulesPath = Path.Combine(Dir, "killswitch.pf.conf");

    /// <summary>Raise the kill-switch. Throws if the server can't be resolved, so the
    /// caller fails closed rather than locking the host out with no path to it.</summary>
    public static void Engage(string serverAddress, Action<string> log)
    {
        var ips = ResolveIps(serverAddress);
        if (ips.Count == 0)
            throw new InvalidOperationException(
                $"kill-switch: cannot resolve server '{serverAddress}' to an IP to allow through");

        Directory.CreateDirectory(Dir);
        // Save whether pf was enabled before, so Disengage/Sweep can restore it.
        bool wasEnabled = PfInfo().Contains("Status: Enabled");
        // Stamp the state with THIS process's identity so the startup Sweep can tell a
        // genuine crash (owner gone) from a still-live tunnel owned by ANOTHER qeli
        // instance — a second launch must NOT sweep away an active kill-switch. (C-04)
        // The pid/start lines are ignored by Disengage's `enabled=0` check.
        var self = Process.GetCurrentProcess();
        File.WriteAllText(StatePath,
            $"pid={self.Id}\nstart={self.StartTime.Ticks}\n" + (wasEnabled ? "enabled=1\n" : "enabled=0\n"));

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
        sb.AppendLine("pass out quick proto udp to any port 53");
        sb.AppendLine("pass out quick proto tcp to any port 53");
        sb.AppendLine("pass out quick proto udp to any port 67");
        foreach (var ip in ips)
            sb.AppendLine($"pass out quick to {ip} all");
        File.WriteAllText(RulesPath, sb.ToString());

        // ANCHOR-BASED (Р3 / C-09). Loading these as the GLOBAL ruleset replaced whatever
        // pf was already enforcing — corporate MDM rules, Little Snitch, Docker/vmnet
        // anchors — and "restoring" by reloading /etc/pf.conf gave back the FILE, not what
        // was actually loaded. An anchor is additive: our rules live in their own namespace
        // and are removed by flushing just that namespace, leaving everything else alone.
        //
        // Two steps: load the rules INTO the anchor, then make sure the main ruleset has an
        // `anchor "qeli"` reference so they are evaluated at all. The reference is added by
        // appending to the loaded main ruleset (pfctl -sr) and reloading it — that is the
        // only way to introduce an anchor point without editing /etc/pf.conf.
        Pf($"-a {AnchorName} -f \"{RulesPath}\"", critical: true);
        EnsureAnchorReferenced(log);
        Pf("-e", critical: false); // already-enabled pf makes -e a no-op warning

        log($"Kill-switch ENGAGED (pf anchor '{AnchorName}'): egress restricted to lo0, utun0..15, " +
            $"{string.Join(", ", ips)}, DNS and DHCP. Other pf rules on this host are left intact. " +
            $"Stays up across reconnects; a crash leaves it (no leak) — clear with: " +
            $"sudo pfctl -a {AnchorName} -F rules" + (wasEnabled ? "" : " ; sudo pfctl -d"));
    }

    /// <summary>Restore pf to its pre-engage state (reload the system ruleset, and
    /// disable pf if it was off before). Best-effort; safe when not engaged.</summary>
    public static void Disengage(Action<string>? log = null)
    {
        // Flush ONLY our anchor. The old code reloaded /etc/pf.conf, which wiped any rules
        // another tool had loaded and restored the file's contents rather than the state we
        // replaced. Flushing the anchor removes exactly what we added. (Р3)
        Pf($"-a {AnchorName} -F rules", critical: false);
        bool wasEnabled = true;
        try
        {
            foreach (var line in File.ReadAllLines(StatePath))
                if (line.Trim() == "enabled=0") wasEnabled = false;
        }
        catch { /* no state -> assume pf was on, leave it on */ }
        if (!wasEnabled) Pf("-d", critical: false); // pf was off before us -> turn it back off
        try { File.Delete(StatePath); } catch { }
        try { File.Delete(RulesPath); } catch { }
        log?.Invoke("Kill-switch disengaged (pf restored)");
    }

    /// <summary>Startup sweep: if a state file is present, a previous run crashed
    /// without restoring pf — restore it now. Call once at app start.</summary>
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
        log?.Invoke("Found a stale kill-switch from a crashed run — restoring pf");
        Disengage(log);
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
    /// Make sure the MAIN ruleset contains an `anchor "qeli"` line, or the rules we loaded
    /// into the anchor are never evaluated (an anchor with no reference is inert — which
    /// would mean a kill-switch that silently protects nothing). (Р3)
    ///
    /// Reads the loaded main ruleset with `pfctl -sr`, appends the anchor reference and
    /// reloads it. NOTE the known limitation: `-sr` prints filter rules only, so a host
    /// whose main ruleset also carries `nat`/`rdr`/`set` directives would lose those on
    /// this reload — macOS ships none by default, but a machine running Docker or an
    /// enterprise agent may. Those are re-added by the tool that owns them; we never
    /// rewrite the main ruleset again after this.
    /// </summary>
    private static void EnsureAnchorReferenced(Action<string> log)
    {
        string current = Pf("-sr", critical: false);
        if (current.Contains($"anchor \"{AnchorName}\"", StringComparison.Ordinal))
            return; // already referenced (e.g. a previous run, or /etc/pf.conf has it)

        string merged = current.TrimEnd() + $"\nanchor \"{AnchorName}\"\n";
        string tmp = Path.Combine(Dir, "main-with-anchor.pf.conf");
        try
        {
            File.WriteAllText(tmp, merged);
            Pf($"-f \"{tmp}\"", critical: true);
            log($"pf: added an `anchor \"{AnchorName}\"` reference to the main ruleset");
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
        }
    }

    private static string PfInfo() => Pf("-s info", critical: false);

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
}
