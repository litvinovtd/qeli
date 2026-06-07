using System.IO;

namespace QeliMac.Model;

/// <summary>
/// macOS-idiomatic storage locations (the analogue of the Windows %APPDATA% /
/// %ProgramData% paths the qeli-win port used).
///
///   • per-user config  → ~/Library/Application Support/Qeli
///   • shared / daemon  → /Library/Application Support/Qeli   (root-writable,
///     user-readable; the launchd daemon and the GUI exchange status/log there)
/// </summary>
public static class Paths
{
    /// <summary>~/Library/Application Support/Qeli — profiles.json, settings.json.</summary>
    public static string UserDir
    {
        get
        {
            // When the GUI is launched with sudo, HOME may point at /var/root; prefer the
            // real invoking user's home so profiles live with the logged-in user.
            string home = Environment.GetEnvironmentVariable("SUDO_HOME")
                ?? (Environment.GetEnvironmentVariable("SUDO_USER") is { Length: > 0 } u
                        ? $"/Users/{u}"
                        : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (string.IsNullOrEmpty(home)) home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, "Library", "Application Support", "Qeli");
        }
    }

    /// <summary>/Library/Application Support/Qeli — daemon profile/status/log (shared).</summary>
    public static string ServiceDir => "/Library/Application Support/Qeli";
}
