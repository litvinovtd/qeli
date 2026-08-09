namespace Qeli.Shared.Vpn;

/// <summary>Connection state the data plane reports to the UI.</summary>
public enum VpnStatus { Disconnected, Connecting, Connected, Error }

/// <summary>
/// Platform TUN device the ABI 1.7+ packet bridge reads/writes IP packets on. Implemented
/// by the Windows Wintun adapter (<c>WintunAdapter</c>) and the macOS utun device
/// (<c>UtunDevice</c>); the platform <c>SetupTun</c> override opens one and hands it to
/// <see cref="VpnTunnelBase"/>, which shuttles bounded batches to the Rust data plane.
/// </summary>
public interface ITunDevice : IDisposable
{
    /// <summary>
    /// Block for the next outbound IP packet and copy it into caller-owned storage.
    /// Returns the packet length, or zero once the device closes or cancellation wins.
    /// </summary>
    int ReceivePacket(byte[] destination, CancellationToken ct);

    /// <summary>
    /// Inject the selected inbound IP-packet range into the OS. The source remains owned
    /// by the caller and is only required for the duration of the synchronous call.
    /// </summary>
    void SendPacket(byte[] source, int offset, int length);
}
