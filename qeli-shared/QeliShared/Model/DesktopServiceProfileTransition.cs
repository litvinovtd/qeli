using System.Text;
using System.Text.Json;

namespace Qeli.Shared.Model;

// Platform-independent stop/publish/restart contract shared by SCM and launchd clients.
public sealed class DesktopServiceProfileTransition(
    Func<bool> installed, Func<bool> desiredConnected, Func<VpnConfig?> readProfile,
    Action stop, Action<byte[]> publish, Action install, Action start, Action uninstall,
    Func<VpnConfig, byte[]> encode, Action? validateRegistration = null)
{
    private readonly object _gate = new();

    public void Apply(VpnConfig? profile, bool connectRequested)
    {
        lock (_gate)
        {
            bool exists = installed();
            if (profile is null)
            {
                if (exists) uninstall();
                return;
            }
            if (exists) validateRegistration?.Invoke();
            // Validate/encode before stopping any existing tunnel or publishing its replacement.
            byte[] encrypted = encode(profile);
            bool resume = !exists || connectRequested || desiredConnected();
            VpnConfig? previous = null;
            if (exists)
            {
                try { previous = readProfile(); }
                catch (Exception error) when (error is InvalidDataException or JsonException or DecoderFallbackException or System.Security.Cryptography.CryptographicException)
                {
                    // A trusted GUI may replace a malformed payload. ACL/I/O failures still refuse.
                }
            }
            bool changed = previous is null || JsonSerializer.Serialize(previous) != JsonSerializer.Serialize(profile);
            if (exists && changed) stop(); // must complete before the worker can load a new generation
            if (changed) publish(encrypted);
            if (!exists) install();
            if (resume) start();
            // An unchanged profile with intent=false stays disconnected on ordinary Settings Save.
        }
    }

    public bool UsesProfile(string id)
    {
        lock (_gate) return installed() && readProfile()?.Id == id;
    }

    public static VpnConfig Snapshot(VpnConfig profile, string logLevel)
    {
        var copy = JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(profile))!;
        copy.LoggingLevel = logLevel;
        return copy; // Keep stable Id; do not mutate the GUI's persisted profile instance.
    }
}
