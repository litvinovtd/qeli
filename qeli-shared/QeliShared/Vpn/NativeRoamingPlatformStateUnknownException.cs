namespace Qeli.Shared.Vpn;

/// <summary>
/// A path command changed platform networking and its internal rollback did not restore a known
/// state. The native core must terminate the current generation; treating this as an ordinary
/// rejection and continuing the old carrier is unsafe.
/// </summary>
public sealed class NativeRoamingPlatformStateUnknownException : IOException
{
    public NativeRoamingPlatformStateUnknownException(string message, Exception innerException)
        : base(message, innerException) { }
}