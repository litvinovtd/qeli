using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>The server assigns addresses and routes on this owned, MAC-less L3 link.</summary>
internal static class TunnelIpv6Policy
{
    internal const ushort Ipv6Family = 23;
    internal const int ReadAttempts = 5;
    internal const int RetryDelayMs = 100;

    // Preserve all unrelated bytes from GetIpInterfaceEntry. BOOLEAN fields are one byte.
    [StructLayout(LayoutKind.Explicit, Size = 200)]
    internal struct Row
    {
        [FieldOffset(0)] internal ushort Family;
        [FieldOffset(8)] internal ulong Luid;
        [FieldOffset(16)] internal uint InterfaceIndex;
        [FieldOffset(40)] internal byte Advertising;
        [FieldOffset(45)] internal byte NeighborUnreachability;
        [FieldOffset(52)] internal int RouterDiscovery;
        [FieldOffset(56)] internal uint DadTransmits;
        [FieldOffset(148)] internal uint Metric;
        [FieldOffset(152)] internal uint Mtu;
        [FieldOffset(158)] internal byte SupportsNeighborDiscovery;
        [FieldOffset(159)] internal byte SupportsRouterDiscovery;
    }

    internal delegate int InterfaceCall(ref Row row);
    internal delegate int GuidCall(in ulong luid, out Guid guid);
    [DllImport("iphlpapi.dll")] private static extern int GetIpInterfaceEntry(ref Row row);
    [DllImport("iphlpapi.dll")] private static extern int SetIpInterfaceEntry(ref Row row);
    [DllImport("iphlpapi.dll")] private static extern int ConvertInterfaceLuidToGuid(in ulong luid, out Guid guid);

    internal static void Apply(WintunAdapter adapter, CancellationToken cancellationToken, Action<string> log) =>
        ApplyOwned(adapter, GetIpInterfaceEntry, SetIpInterfaceEntry, ConvertInterfaceLuidToGuid, cancellationToken, log);

    // Keep the creator handle alive. Never resolve a mutable alias or fall back to
    // another interface when an IPv6 binding has not appeared yet.
    internal static void ApplyOwned(WintunAdapter adapter, InterfaceCall read, InterfaceCall write,
        GuidCall resolveGuid, CancellationToken cancellationToken = default, Action<string>? log = null,
        Action<CancellationToken>? wait = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        adapter.WithOwnedIdentity((luid, expectedGuid) =>
        {
            void VerifyOwner()
            {
                int error = resolveGuid(in luid, out var actualGuid);
                if (error != 0)
                    throw NativeError(error, "verify-owner", "ConvertInterfaceLuidToGuid", luid,
                        new Row { Family = Ipv6Family, Luid = luid });
                if (actualGuid != expectedGuid)
                    throw new InvalidOperationException($"Owned tunnel IPv6 identity changed; stage=verify-owner; luid=0x{luid:X16}; expected_guid={expectedGuid:D}; actual_guid={actualGuid:D}");
            }
            Apply(luid, read, write, cancellationToken, log, VerifyOwner, wait);
        });
    }

    internal static void Apply(ulong luid, InterfaceCall read, InterfaceCall write,
        CancellationToken cancellationToken = default, Action<string>? log = null,
        Action? verifyOwner = null, Action<CancellationToken>? wait = null)
    {
        if (luid == 0) throw new InvalidOperationException("No owned IPv6 tunnel interface");
        void Admit()
        {
            cancellationToken.ThrowIfCancellationRequested();
            verifyOwner?.Invoke();
        }
        Row Read(string stage)
        {
            for (int attempt = 1; ; attempt++) {
                Admit();
                var current = new Row { Family = Ipv6Family, Luid = luid };
                int status = read(ref current);
                if (status == 0) {
                    Admit();
                    CheckIdentity(current, luid, stage);
                    Report(log, $"IPv6 policy: stage={stage}; {Describe(current)}");
                    return current;
                }
                var failure = NativeError(status, stage, "GetIpInterfaceEntry", luid, current, attempt);
                // Registration of a fresh Wintun IPv6 family can lag behind its LUID.
                // Only reads are retried; access/parameter errors and writes fail immediately.
                if (attempt >= ReadAttempts || status is not (2 or 1168)) throw failure;
                Report(log, $"IPv6 policy: transient interface lookup; retry in {RetryDelayMs}ms; {failure.Message}");
                Admit();
                if (wait != null) wait(cancellationToken);
                else if (cancellationToken.WaitHandle.WaitOne(RetryDelayMs)) cancellationToken.ThrowIfCancellationRequested();
            }
        }

        var row = Read("read");
        Admit();
        if (Configured(row)) {
            Report(log, "IPv6 policy: already configured; no SetIpInterfaceEntry call needed");
            Admit();
            return;
        }
        string before = Describe(row);
        row.Advertising = 0;
        row.NeighborUnreachability = 0;
        row.RouterDiscovery = 0; // RouterDiscoveryDisabled
        row.DadTransmits = 0;
        var requested = row;
        Report(log, $"IPv6 policy: stage=write; before=[{before}]; requested=[{Describe(requested)}]");
        Admit();
        int error = write(ref row);
        if (error != 0) throw NativeError(error, "write", "SetIpInterfaceEntry", luid, requested, before: before);
        Admit();
        CheckIdentity(row, luid, "write");
        row = Read("verify");
        Admit();
        if (!Configured(row))
            throw new InvalidOperationException($"Owned tunnel IPv6 discovery policy was not applied; stage=verify; API calls returned win32=0 but readback differs; expected=[{Describe(requested)}]; actual=[{Describe(row)}]");
    }

    private static bool Configured(Row row) => row.Advertising == 0 && row.NeighborUnreachability == 0
        && row.RouterDiscovery == 0 && row.DadTransmits == 0;

    private static string Describe(Row row) =>
        $"family={row.Family}; luid=0x{row.Luid:X16}; ifindex={row.InterfaceIndex}; advertising={row.Advertising}; nud={row.NeighborUnreachability}; router_discovery={row.RouterDiscovery}; dad_transmits={row.DadTransmits}; mtu={row.Mtu}; metric={row.Metric}; supports_nd={row.SupportsNeighborDiscovery}; supports_rd={row.SupportsRouterDiscovery}";

    private static Win32Exception NativeError(int error, string stage, string api, ulong luid, Row row,
        int attempt = 1, string? before = null)
    {
        string hint = error switch {
            5 => "Windows denied access; check elevation and interface security policy",
            2 or 1168 => "the owned IPv6 interface/family is not present or not ready; check its IPv6 binding",
            87 => "Windows rejected interface parameters; unrelated settings were not reset as a fallback",
            50 => "Windows does not support this operation on the interface",
            _ => "no automatic fallback or write retry was attempted",
        };
        string system = new Win32Exception(error).Message.Replace('\r', ' ').Replace('\n', ' ');
        string description = stage switch { "read" => "read", "write" => "configure", "verify" => "verify", _ => "identify" };
        return new Win32Exception(error,
            $"Cannot {description} owned tunnel IPv6 policy; stage={stage}; api={api}; win32={unchecked((uint)error)} (0x{unchecked((uint)error):X8}); system=\"{system}\"; expected_luid=0x{luid:X16}; attempt={attempt}; row=[{Describe(row)}]" +
            (before == null ? "" : $"; before=[{before}]") + $"; hint={hint}");
    }

    private static void CheckIdentity(Row row, ulong luid, string stage)
    {
        if (row.Family != Ipv6Family || row.Luid != luid)
            throw new InvalidOperationException($"IPv6 policy resolved a different tunnel interface; stage={stage}; expected_family={Ipv6Family}; expected_luid=0x{luid:X16}; actual=[{Describe(row)}]");
    }

    private static void Report(Action<string>? log, string message)
    {
        try { log?.Invoke(message); }
        catch { /* A log consumer must not replace the original Win32 failure. */ }
    }
}
