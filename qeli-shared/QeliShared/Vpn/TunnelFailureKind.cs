namespace Qeli.Shared.Vpn;

/// <summary>Diagnostic category independent of localized terminal status text.
/// Unknown native errors remain Transport; this never changes retry/security policy.</summary>
public enum TunnelFailureKind { Transport, Authentication, ServerKeyMismatch }

internal static class TunnelFailurePolicy
{
    internal static TunnelFailureKind FromNativeError(string message) =>
        Model.ServerIdentityPolicy.IsKeyMismatch(message) ? TunnelFailureKind.ServerKeyMismatch :
        message.Contains("auth failed:", StringComparison.OrdinalIgnoreCase)
            || message.Contains("authentication failed", StringComparison.OrdinalIgnoreCase)
            ? TunnelFailureKind.Authentication : TunnelFailureKind.Transport;
}
