using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>P/Invoke surface for WinDivert 2.2 (NETWORK layer). Process ID is not on the
/// network-layer address — <see cref="ProcessAppMap"/> resolves local endpoint → PID → exe;
/// <see cref="WinDivertFlowTable"/> tracks per-flow NAT/interface state.</summary>
internal static class WinDivertNative
{
    public const string Dll = "WinDivert.dll";
    public const int WINDIVERT_LAYER_NETWORK = 0;

    // Matching packets are discarded in the driver without being queued to userspace.
    public const ulong WINDIVERT_FLAG_DROP = 0x0001;

    // Recalculate all checksums (pass 0).
    public const ulong WINDIVERT_HELPER_CHECKSUM_ALL = 0;
    public const ulong WINDIVERT_HELPER_NO_ICMP_CHECKSUM = 0x0002;
    public const ulong WINDIVERT_HELPER_NO_TCP_CHECKSUM = 0x0008;
    public const ulong WINDIVERT_HELPER_NO_UDP_CHECKSUM = 0x0010;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, uint packetLen,
        out uint recvLen, ref WinDivertAddress pAddr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, uint packetLen,
        out uint sendLen, ref WinDivertAddress pAddr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertHelperCalcChecksums(byte[] pPacket, uint packetLen,
        ref WinDivertAddress pAddr, ulong flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern bool WinDivertHelperCompileFilter(string filter, int layer,
        IntPtr objectBuf, uint objectLen, out IntPtr errorStr, out uint errorPos);

    public const int WINDIVERT_PARAM_QUEUE_LENGTH = 0;
    public const int WINDIVERT_PARAM_QUEUE_TIME = 1;
    public const int WINDIVERT_PARAM_QUEUE_SIZE = 2;

    /// <summary>WINDIVERT_ADDRESS (2.2) — 80 bytes. Only Network (IfIdx/SubIfIdx) is used at
    /// NETWORK layer; ProcessId lives on FLOW/SOCKET layers.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertAddress
    {
        public long Timestamp;
        public byte Layer;       // packed bitfields flattened — see note below
        public byte Event;
        public byte Flags;       // Sniffed|Outbound|Loopback|Impostor|IPv6|IPChecksum|TCPChecksum|UDPChecksum
        public byte Reserved1;
        public uint Reserved2;
        public uint IfIdx;
        public uint SubIfIdx;
        // Remaining union padding to 64 bytes of union + alignment = keep total ~80.
        public uint Pad0, Pad1, Pad2, Pad3, Pad4, Pad5, Pad6, Pad7;
        public uint Pad8, Pad9, Pad10, Pad11, Pad12, Pad13;

        public bool Outbound
        {
            get => (Flags & 0x02) != 0;
            set { if (value) Flags |= 0x02; else Flags = (byte)(Flags & ~0x02); }
        }

        public bool IPv6
        {
            get => (Flags & 0x10) != 0;
            set { if (value) Flags |= 0x10; else Flags = (byte)(Flags & ~0x10); }
        }
    }
}
