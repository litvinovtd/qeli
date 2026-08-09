namespace Qeli.Shared.Vpn;

/// <summary>Connection state the data plane reports to the UI.</summary>
public enum VpnStatus { Disconnected, Connecting, Connected, Error }

/// <summary>
/// Lifecycle contract shared by platform TUN implementations. Windows exposes packet-oriented
/// Wintun access, while macOS exposes a descriptor which the Rust core duplicates and owns for
/// one connection generation.
/// </summary>
public interface ITunDevice : IDisposable { }

/// <summary>TUN whose platform API exchanges caller-owned packet buffers.</summary>
public interface IPacketTunDevice : ITunDevice
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

/// <summary>
/// Unix TUN whose descriptor can be duplicated into the Rust core. The platform object keeps
/// the original descriptor for interface lifetime/route cleanup; Rust owns its generation-scoped
/// duplicate and all packet IO.
/// </summary>
public interface IFdTunDevice : ITunDevice
{
    int FileDescriptor { get; }
}
