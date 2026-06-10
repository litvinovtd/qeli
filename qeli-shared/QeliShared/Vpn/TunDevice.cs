namespace Qeli.Shared.Vpn;

/// <summary>Connection state the data plane reports to the UI.</summary>
public enum VpnStatus { Disconnected, Connecting, Connected, Error }

/// <summary>
/// Platform TUN device the shared data plane reads/writes IP packets on. Implemented
/// by the Windows Wintun adapter (<c>WintunAdapter</c>) and the macOS utun device
/// (<c>UtunDevice</c>); the platform <c>SetupTun</c> override opens one and hands it to
/// the shared <see cref="VpnTunnelBase"/> tunnel loops. See docs/REFACTOR-PLAN.md (R5).
/// </summary>
public interface ITunDevice : IDisposable
{
    /// <summary>Block for the next outbound IP packet; returns null once the device closes.</summary>
    byte[]? ReceivePacket(CancellationToken ct);

    /// <summary>Inject an inbound IP packet (first <paramref name="length"/> bytes) into the OS.</summary>
    void SendPacket(byte[] packet, int length);
}
