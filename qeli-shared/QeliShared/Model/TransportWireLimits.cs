namespace Qeli.Shared.Model;

/// <summary>
/// Wire-size limits needed by production config validation. The managed protocol codecs
/// live only in QeliConformance; keeping this small contract in QeliShared prevents the
/// production clients from depending on a second data-plane implementation.
/// </summary>
public static class TransportWireLimits
{
    public const int Ipv6MinimumMtu = 1280;
    private const int Ipv6Header = 40;
    private const int UdpHeader = 8;
    private const int ObfsSeal = 1 + 12;
    private const int QuicLongHeader = 1 + 4 + 1 + 4 + 1 + 1 + 2 + 4;
    private const int FragmentHeader = 6;
    private const int FutureLayerReserve = 32;

    public const int UdpFragmentMaxChunk =
        Ipv6MinimumMtu - Ipv6Header - UdpHeader - ObfsSeal - QuicLongHeader
        - FutureLayerReserve - FragmentHeader;

    // AUTH carries an X25519 public key plus fixed framing outside the credentials.
    private const int AuthFixedPayload = 32 + 17;
    public const int AuthCredentialBudget = UdpFragmentMaxChunk - AuthFixedPayload;
}
