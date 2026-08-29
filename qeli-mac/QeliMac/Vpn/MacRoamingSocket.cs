using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace QeliMac.Vpn;

/// <summary>Applies the Darwin half of roaming BIND_SOCKET to a borrowed Rust fd.
/// Rust retains ownership; managed code only selects the physical interface and exact
/// local source before the core connects the candidate.</summary>
internal static class MacRoamingSocket
{
    private const int SocketError = -1;
    private const byte AfInet = 2;
    private const byte AfInet6 = 30;
    private const int IpProtoIp = 0;
    private const int IpProtoIpv6 = 41;
    private const int IpBoundIf = 25;
    private const int Ipv6BoundIf = 125;

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockname(int socket, byte[] name, ref uint nameLength);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int socket, int level, int optionName,
        ref uint optionValue, uint optionLength);

    [DllImport("libc", SetLastError = true)]
    private static extern int bind(int socket, byte[] name, uint nameLength);

    internal static void Bind(long socketHandle, uint interfaceIndex,
        IReadOnlyList<IPAddress> localAddresses)
    {
        int socket = ToFileDescriptor(socketHandle);
        byte socketFamily = SocketFamily(socket);
        AddressFamily family = socketFamily == AfInet
            ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        IPAddress localAddress = localAddresses.FirstOrDefault(address =>
                address.AddressFamily == family
                && AddressBelongsToInterface(interfaceIndex, address))
            ?? throw new InvalidOperationException(
                $"roaming path has no live local address for Darwin socket family {socketFamily}");
        Bind(socket, socketFamily, interfaceIndex, localAddress);
    }

    private static void Bind(int socket, byte socketFamily,
        uint interfaceIndex, IPAddress localAddress)
    {
        if (interfaceIndex == 0)
            throw new ArgumentOutOfRangeException(nameof(interfaceIndex));
        if (localAddress.AddressFamily is not (AddressFamily.InterNetwork
            or AddressFamily.InterNetworkV6))
            throw new ArgumentException("roaming source must be IPv4 or IPv6", nameof(localAddress));
        if (!AddressBelongsToInterface(interfaceIndex, localAddress))
            throw new InvalidOperationException(
                $"roaming source {localAddress} is no longer assigned to interface {interfaceIndex}");

        byte expectedFamily = localAddress.AddressFamily == AddressFamily.InterNetwork
            ? AfInet : AfInet6;
        if (socketFamily != expectedFamily)
            throw new InvalidOperationException(
                $"roaming socket family {socketFamily} does not match source {localAddress}");

        var option = InterfaceOption(localAddress.AddressFamily);
        uint index = interfaceIndex;
        if (setsockopt(socket, option.level, option.name, ref index, sizeof(uint)) == SocketError)
            throw new SocketException(Marshal.GetLastPInvokeError());

        byte[] address = BuildSockaddr(localAddress);
        if (bind(socket, address, checked((uint)address.Length)) == SocketError)
            throw new SocketException(Marshal.GetLastPInvokeError());
    }

    private static byte SocketFamily(int socket)
    {
        var address = new byte[28];
        uint length = checked((uint)address.Length);
        if (getsockname(socket, address, ref length) == SocketError)
            throw new SocketException(Marshal.GetLastPInvokeError());
        if (length < 2)
            throw new InvalidOperationException("getsockname returned a truncated address");
        byte family = address[1];
        if (family is not (AfInet or AfInet6))
            throw new InvalidOperationException($"unsupported Darwin roaming socket family {family}");
        return family;
    }

    private static bool AddressBelongsToInterface(uint interfaceIndex, IPAddress localAddress)
    {
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
            IPInterfaceProperties properties;
            try { properties = adapter.GetIPProperties(); }
            catch { continue; }
            uint index;
            try
            {
                index = localAddress.AddressFamily == AddressFamily.InterNetwork
                    ? unchecked((uint)(properties.GetIPv4Properties()?.Index ?? -1))
                    : unchecked((uint)(properties.GetIPv6Properties()?.Index ?? -1));
            }
            catch { continue; }
            if (index != interfaceIndex) continue;
            return properties.UnicastAddresses.Any(item =>
                Normalize(item.Address).Equals(Normalize(localAddress)));
        }
        return false;
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static int ToFileDescriptor(long socketHandle)
    {
        if (socketHandle is < 0 or > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(socketHandle));
        return checked((int)socketHandle);
    }

    private static (int level, int name) InterfaceOption(AddressFamily family) => family switch
    {
        AddressFamily.InterNetwork => (IpProtoIp, IpBoundIf),
        AddressFamily.InterNetworkV6 => (IpProtoIpv6, Ipv6BoundIf),
        _ => throw new ArgumentException(
            "interface option family must be IPv4 or IPv6", nameof(family)),
    };

    private static byte[] BuildSockaddr(IPAddress address)
    {
        bool ipv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        if (!ipv6 && address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("sockaddr family must be IPv4 or IPv6", nameof(address));
        var sockaddr = new byte[ipv6 ? 28 : 16];
        sockaddr[0] = checked((byte)sockaddr.Length);
        sockaddr[1] = ipv6 ? AfInet6 : AfInet;
        // Port and IPv6 flow-info stay zero. Darwin sockaddr starts with one-byte len/family.
        address.GetAddressBytes().CopyTo(sockaddr, ipv6 ? 8 : 4);
        if (ipv6)
        {
            uint scope = checked((uint)address.ScopeId);
            if (BitConverter.IsLittleEndian)
                BinaryPrimitives.WriteUInt32LittleEndian(sockaddr.AsSpan(24), scope);
            else
                BinaryPrimitives.WriteUInt32BigEndian(sockaddr.AsSpan(24), scope);
        }
        return sockaddr;
    }

    internal static void RunSelfTest(Action<string, bool> check)
    {
        check("macOS roaming socket: IPv4 uses IP_BOUND_IF",
            InterfaceOption(AddressFamily.InterNetwork) == (IpProtoIp, IpBoundIf));
        check("macOS roaming socket: IPv6 uses IPV6_BOUND_IF",
            InterfaceOption(AddressFamily.InterNetworkV6) == (IpProtoIpv6, Ipv6BoundIf));

        byte[] sockaddr4 = BuildSockaddr(IPAddress.Parse("192.0.2.44"));
        check("macOS roaming socket: IPv4 sockaddr has Darwin len/family and exact source",
            sockaddr4.Length == 16 && sockaddr4[0] == 16 && sockaddr4[1] == AfInet
            && sockaddr4.AsSpan(2, 2).SequenceEqual(new byte[2])
            && sockaddr4.AsSpan(4, 4).SequenceEqual(new byte[] { 192, 0, 2, 44 }));
        byte[] sockaddr6 = BuildSockaddr(IPAddress.Parse("2001:db8::44"));
        check("macOS roaming socket: IPv6 sockaddr has Darwin len/family and exact source",
            sockaddr6.Length == 28 && sockaddr6[0] == 28 && sockaddr6[1] == AfInet6
            && sockaddr6.AsSpan(8, 16).SequenceEqual(
                IPAddress.Parse("2001:db8::44").GetAddressBytes()));

        bool negativeRejected = false;
        bool wideRejected = false;
        try { _ = ToFileDescriptor(-1); }
        catch (ArgumentOutOfRangeException) { negativeRejected = true; }
        try { _ = ToFileDescriptor((long)int.MaxValue + 1); }
        catch (ArgumentOutOfRangeException) { wideRejected = true; }
        check("macOS roaming socket: borrowed fd is range-checked before libc",
            negativeRejected && wideRejected);
    }
}
