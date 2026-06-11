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
        File.WriteAllText(StatePath, wasEnabled ? "enabled=1\n" : "enabled=0\n");

        var sb = new StringBuilder();
        sb.AppendLine("set block-policy drop");
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

        // Load our ruleset and enable pf.
        Pf($"-f \"{RulesPath}\"", critical: true);
        Pf("-e", critical: false); // already-enabled pf makes -e a no-op warning

        log($"Kill-switch ENGAGED (pf): egress restricted to lo0, utun0..15, {string.Join(", ", ips)}, " +
            $"DNS and DHCP. Stays up across reconnects; restored only on a clean stop. A crash leaves it " +
            $"(no leak) — clear with: sudo pfctl -f /etc/pf.conf" + (wasEnabled ? "" : " ; sudo pfctl -d"));
    }

    /// <summary>Restore pf to its pre-engage state (reload the system ruleset, and
    /// disable pf if it was off before). Best-effort; safe when not engaged.</summary>
    public static void Disengage(Action<string>? log = null)
    {
        // Reload the system default ruleset (drops our block-all).
        Pf("-f /etc/pf.conf", critical: false);
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
        if (File.Exists(StatePath))
        {
            log?.Invoke("Found a stale kill-switch from a previous run — restoring pf");
            Disengage(log);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

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
        string o = p.StandardOutput.ReadToEnd();
        string e = p.StandardError.ReadToEnd();
        p.WaitForExit();
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
