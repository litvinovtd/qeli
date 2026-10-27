using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>The server assigns addresses and routes on this owned, MAC-less L3 link.</summary>
internal static class TunnelIpv6Policy
{
    // Preserve all unrelated bytes from GetIpInterfaceEntry. BOOLEAN fields are one byte.
    [StructLayout(LayoutKind.Explicit, Size = 200)]
    internal struct Row
    {
        [FieldOffset(0)] internal ushort Family;
        [FieldOffset(8)] internal ulong Luid;
        [FieldOffset(40)] internal byte Advertising;
        [FieldOffset(45)] internal byte NeighborUnreachability;
        [FieldOffset(52)] internal int RouterDiscovery;
        [FieldOffset(56)] internal uint DadTransmits;
        [FieldOffset(148)] internal uint Metric;
    }

    internal delegate int InterfaceCall(ref Row row);
    [DllImport("iphlpapi.dll")] private static extern int GetIpInterfaceEntry(ref Row row);
    [DllImport("iphlpapi.dll")] private static extern int SetIpInterfaceEntry(ref Row row);

    internal static void Apply(WintunAdapter adapter) => adapter.WithOwnedIdentity(
        (luid, _) => Apply(luid, GetIpInterfaceEntry, SetIpInterfaceEntry));

    internal static void Apply(ulong luid, InterfaceCall read, InterfaceCall write)
    {
        if (luid == 0) throw new InvalidOperationException("No owned IPv6 tunnel interface");
        var row = new Row { Family = 23, Luid = luid };
        int error = read(ref row);
        if (error != 0) throw new Win32Exception(error, "Cannot read owned tunnel IPv6 policy");
        CheckIdentity(row, luid);
        row.Advertising = 0;
        row.NeighborUnreachability = 0;
        row.RouterDiscovery = 0; // RouterDiscoveryDisabled
        row.DadTransmits = 0;
        error = write(ref row);
        if (error != 0) throw new Win32Exception(error, "Cannot configure owned tunnel IPv6 policy");
        row = new Row { Family = 23, Luid = luid };
        error = read(ref row);
        if (error != 0) throw new Win32Exception(error, "Cannot verify owned tunnel IPv6 policy");
        CheckIdentity(row, luid);
        if (row.Advertising != 0 || row.NeighborUnreachability != 0
            || row.RouterDiscovery != 0 || row.DadTransmits != 0)
            throw new InvalidOperationException("Owned tunnel IPv6 discovery policy was not applied");
    }

    private static void CheckIdentity(Row row, ulong luid)
    {
        if (row.Family != 23 || row.Luid != luid)
            throw new InvalidOperationException("IPv6 policy resolved a different tunnel interface");
    }
}
