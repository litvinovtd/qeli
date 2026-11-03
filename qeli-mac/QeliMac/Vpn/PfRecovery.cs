using System.Text;
using QeliMac.Model;

namespace QeliMac.Vpn;

// Production cleanup decisions with injected kernel/storage boundaries for host tests.
internal sealed class PfRecovery(Func<byte[]?> read, Action flush, Action deleteRules,
    Action deleteState, Func<DnsJournal.Owner, bool> ownerAlive, DnsJournal.Owner self)
{
    internal readonly record struct Stamp(DnsJournal.Owner Owner, bool WasEnabled);
    internal static byte[] Encode(DnsJournal.Owner owner, bool enabled)
    {
        if (owner.LegacyLocalTime) throw new InvalidDataException("New pf owners must use UTC");
        return Encoding.UTF8.GetBytes($"pid={owner.Pid}\nstart={owner.StartTicks}\nenabled={(enabled ? 1 : 0)}\nclock=utc\n");
    }

    internal static Stamp Decode(byte[] bytes)
    {
        if (bytes.Length is 0 or > 4096) throw new InvalidDataException("Invalid pf recovery size");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in new UTF8Encoding(false, true).GetString(bytes).Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var pair = line.Trim().Split('=', 2);
            if (pair.Length != 2 || pair[0] is not ("pid" or "start" or "enabled" or "clock") || !fields.TryAdd(pair[0], pair[1]))
                throw new InvalidDataException("Invalid/duplicate pf recovery field");
        }
        if (fields.Count is not (3 or 4) || (fields.ContainsKey("clock") && fields["clock"] != "utc")
            || !int.TryParse(fields.GetValueOrDefault("pid"), out int pid) || pid <= 0
            || !long.TryParse(fields.GetValueOrDefault("start"), out long start) || start <= 0 || start > DateTime.MaxValue.Ticks
            || fields.GetValueOrDefault("enabled") is not ("0" or "1"))
            throw new InvalidDataException("Invalid pf recovery owner/state; administrator repair required");
        return new(new(pid, start, !fields.ContainsKey("clock")), fields["enabled"] == "1");
    }

    internal void RequireCurrentOwner()
    {
        var bytes = read() ?? throw new InvalidOperationException("Kill-switch is not engaged");
        if (Decode(bytes).Owner != self) throw new InvalidOperationException("Kill-switch belongs to another Qeli generation");
    }
    internal bool Release(bool staleOnly)
    {
        var bytes = read();
        if (bytes is null) return false; // No journal is not authorization to flush arbitrary anchors.
        var stamp = Decode(bytes);
        bool alive = ownerAlive(stamp.Owner);
        if (staleOnly && alive) return false;
        if (!staleOnly && stamp.Owner != self && alive)
            throw new InvalidOperationException("Cannot remove another live Qeli process's kill-switch");
        flush();
        // Never globally disable pf: another tool may have enabled/acquired it after Qeli.
        // Delete the last ownership journal only after all cleanup actions succeeded.
        deleteRules();
        deleteState();
        return true;
    }
    internal static string Anchor(string rules)
    {
        foreach (string target in new[] { "qeli", "com.apple/*" })
            foreach (string line in rules.Split('\n').Select(line => line.Trim()))
                if (line == $"anchor \"{target}\"" || line == $"anchor \"{target}\" all")
                    return target == "qeli" ? "qeli" : "com.apple/qeli";
        throw new InvalidOperationException("kill-switch: no unconditional Qeli/com.apple wildcard anchor is loaded. Configure the host pf rules explicitly; Qeli will not reload /etc/pf.conf or replace foreign nat/rdr/scrub rules.");
    }
}
