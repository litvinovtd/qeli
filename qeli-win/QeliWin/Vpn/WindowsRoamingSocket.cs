using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>Applies the Windows half of roaming BIND_SOCKET to a borrowed Rust socket.
/// The socket remains owned by Rust; managed code changes only its egress interface and
/// exact local source before Rust connects it.</summary>
internal static class WindowsRoamingSocket
{
    private const int SocketError = -1;
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int IpProtoIp = 0;
    private const int IpProtoIpv6 = 41;
    private const int IpUnicastIf = 31;
    private const int Ipv6UnicastIf = 31;

    [DllImport("Ws2_32.dll", SetLastError = true)]
    private static extern int getsockname(UIntPtr socket, byte[] name, ref int nameLength);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    private static extern int setsockopt(UIntPtr socket, int level, int optionName,
        byte[] optionValue, int optionLength);

    [DllImport("Ws2_32.dll", SetLastError = true)]
    private static extern int bind(UIntPtr socket, byte[] name, int nameLength);

    [DllImport("Ws2_32.dll")]
    private static extern int WSAGetLastError();

    internal static void Bind(long socketHandle, uint interfaceIndex, IPAddress localAddress)
    {
        UIntPtr socket = ToSocket(socketHandle);
        int socketFamily = SocketFamily(socket);
        Bind(socket, socketFamily, interfaceIndex, localAddress);
    }

    internal static void Bind(long socketHandle, uint interfaceIndex,
        IReadOnlyList<IPAddress> localAddresses)
    {
        UIntPtr socket = ToSocket(socketHandle);
        int socketFamily = SocketFamily(socket);
        AddressFamily family = socketFamily == AfInet
            ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        IPAddress localAddress = localAddresses.FirstOrDefault(address =>
                address.AddressFamily == family)
            ?? throw new InvalidOperationException(
                $"roaming path has no local address for socket family {socketFamily}");
        Bind(socket, socketFamily, interfaceIndex, localAddress);
    }

    private static void Bind(UIntPtr socket, int socketFamily,
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

        int expectedFamily = localAddress.AddressFamily == AddressFamily.InterNetwork
            ? AfInet : AfInet6;
        if (socketFamily != expectedFamily)
            throw new InvalidOperationException(
                $"roaming socket family {socketFamily} does not match source {localAddress}");

        var option = BuildInterfaceOption(localAddress.AddressFamily, interfaceIndex);
        if (setsockopt(socket, option.level, option.name, option.value, option.value.Length)
            == SocketError)
            throw new SocketException(WSAGetLastError());

        byte[] address = BuildSockaddr(localAddress);
        if (bind(socket, address, address.Length) == SocketError)
            throw new SocketException(WSAGetLastError());
    }

    private static int SocketFamily(UIntPtr socket)
    {
        var address = new byte[28];
        int length = address.Length;
        if (getsockname(socket, address, ref length) == SocketError)
            throw new SocketException(WSAGetLastError());
        if (length < 2)
            throw new InvalidOperationException("getsockname returned a truncated address");
        int family = BinaryPrimitives.ReadUInt16LittleEndian(address);
        if (family is not (AfInet or AfInet6))
            throw new InvalidOperationException($"unsupported roaming socket family {family}");
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

    private static UIntPtr ToSocket(long socketHandle)
    {
        if (socketHandle < 0)
            throw new ArgumentOutOfRangeException(nameof(socketHandle));
        ulong value = unchecked((ulong)socketHandle);
        if (UIntPtr.Size == 4 && value > uint.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(socketHandle));
        return UIntPtr.Size == 8 ? new UIntPtr(value) : new UIntPtr((uint)value);
    }

    private static (int level, int name, byte[] value) BuildInterfaceOption(
        AddressFamily family, uint interfaceIndex)
    {
        var value = new byte[sizeof(uint)];
        if (family == AddressFamily.InterNetwork)
        {
            // IP_UNICAST_IF is the unusual Winsock exception: its DWORD interface index
            // is passed in network byte order.
            BinaryPrimitives.WriteUInt32BigEndian(value, interfaceIndex);
            return (IpProtoIp, IpUnicastIf, value);
        }
        if (family == AddressFamily.InterNetworkV6)
        {
            // IPV6_UNICAST_IF consumes a host-order DWORD.
            if (BitConverter.IsLittleEndian)
                BinaryPrimitives.WriteUInt32LittleEndian(value, interfaceIndex);
            else
                BinaryPrimitives.WriteUInt32BigEndian(value, interfaceIndex);
            return (IpProtoIpv6, Ipv6UnicastIf, value);
        }
        throw new ArgumentException("interface option family must be IPv4 or IPv6", nameof(family));
    }

    private static byte[] BuildSockaddr(IPAddress address)
    {
        bool ipv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        if (!ipv6 && address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("sockaddr family must be IPv4 or IPv6", nameof(address));
        var sockaddr = new byte[ipv6 ? 28 : 16];
        BinaryPrimitives.WriteUInt16LittleEndian(sockaddr, ipv6 ? (ushort)AfInet6 : (ushort)AfInet);
        // Port and IPv6 flow-info stay zero: Rust handed us an unconnected candidate and
        // owns connect()/the optional configured local-port policy.
        address.GetAddressBytes().CopyTo(sockaddr, ipv6 ? 8 : 4);
        if (ipv6)
            BinaryPrimitives.WriteUInt32LittleEndian(sockaddr.AsSpan(24), checked((uint)address.ScopeId));
        return sockaddr;
    }

    internal static void RunSelfTest(Action<string, bool> check)
    {
        var ipv4 = BuildInterfaceOption(AddressFamily.InterNetwork, 0x01020304);
        check("roaming socket: IPv4 interface index uses network byte order",
            ipv4 == (IpProtoIp, IpUnicastIf, ipv4.value)
            && ipv4.value.SequenceEqual(new byte[] { 1, 2, 3, 4 }));
        var ipv6 = BuildInterfaceOption(AddressFamily.InterNetworkV6, 0x01020304);
        byte[] hostOrder = BitConverter.IsLittleEndian
            ? new byte[] { 4, 3, 2, 1 } : new byte[] { 1, 2, 3, 4 };
        check("roaming socket: IPv6 interface index uses host byte order",
            ipv6.level == IpProtoIpv6 && ipv6.name == Ipv6UnicastIf
            && ipv6.value.SequenceEqual(hostOrder));

        byte[] sockaddr4 = BuildSockaddr(IPAddress.Parse("192.0.2.44"));
        check("roaming socket: IPv4 sockaddr binds the exact source with port zero",
            sockaddr4.Length == 16
            && BinaryPrimitives.ReadUInt16LittleEndian(sockaddr4) == AfInet
            && sockaddr4.AsSpan(2, 2).SequenceEqual(new byte[2])
            && sockaddr4.AsSpan(4, 4).SequenceEqual(new byte[] { 192, 0, 2, 44 }));
        byte[] sockaddr6 = BuildSockaddr(IPAddress.Parse("2001:db8::44"));
        check("roaming socket: IPv6 sockaddr binds the exact source with port zero",
            sockaddr6.Length == 28
            && BinaryPrimitives.ReadUInt16LittleEndian(sockaddr6) == AfInet6
            && sockaddr6.AsSpan(8, 16).SequenceEqual(IPAddress.Parse("2001:db8::44").GetAddressBytes()));

        bool rejected = false;
        try { _ = ToSocket(-1); }
        catch (ArgumentOutOfRangeException) { rejected = true; }
        check("roaming socket: negative native handle is rejected before Winsock", rejected);
        if (UIntPtr.Size == 8)
            check("roaming socket: 64-bit SOCKET is preserved without truncation",
                ToSocket(0x0000000100000001).ToUInt64() == 0x0000000100000001);
    }
}
