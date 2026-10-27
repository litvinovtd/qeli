namespace QeliWin.Vpn;

internal static class TunnelIpv6PolicySelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        var current = new TunnelIpv6Policy.Row {
            Family = 23, Luid = 123, Advertising = 1, NeighborUnreachability = 1,
            RouterDiscovery = 1, DadTransmits = 1, Metric = 37,
        };
        int writes = 0;
        int Read(ref TunnelIpv6Policy.Row row) { row = current; return 0; }
        int Write(ref TunnelIpv6Policy.Row row) { current = row; writes++; return 0; }
        using var adapter = new WintunAdapter((_, _) => new IntPtr(1), _ => 123, _ => { });
        bool identityAccepted = false;
        try { adapter.WithOwnedIdentity((_, _) => identityAccepted = true); }
        catch (InvalidOperationException) { }
        check("IPv6 policy: requires a created owned adapter", !identityAccepted);
        adapter.Open("QeliPolicyTest", Guid.NewGuid());
        adapter.WithOwnedIdentity((luid, _) => TunnelIpv6Policy.Apply(luid, Read, Write));
        check("IPv6 policy: disables only local discovery and preserves metric",
            writes == 1 && current.Luid == 123 && current.Family == 23 && current.Metric == 37
            && current.Advertising == 0 && current.NeighborUnreachability == 0
            && current.RouterDiscovery == 0 && current.DadTransmits == 0);
        bool rejected = false;
        current.Luid = 456;
        try { TunnelIpv6Policy.Apply(123, Read, Write); }
        catch (InvalidOperationException) { rejected = true; }
        check("IPv6 policy: a mismatching interface is never written", rejected && writes == 1);
        current.Luid = 123;
        current.NeighborUnreachability = 1;
        rejected = false;
        int Ignore(ref TunnelIpv6Policy.Row row) => 0;
        try { TunnelIpv6Policy.Apply(123, Read, Ignore); }
        catch (InvalidOperationException) { rejected = true; }
        check("IPv6 policy: failed readback refuses setup", rejected);
    }
}
