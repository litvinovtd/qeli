using System.IO;
using System.Text.Json;

namespace QeliMac.Model;

/// <summary>App-wide settings persisted to ~/Library/Application Support/Qeli/settings.json.</summary>
public sealed class AppSettings
{
    public string Language { get; set; } = "en";       // "en" | "ru" (default English)
    public string Theme { get; set; } = "system";      // "system" | "light" | "dark"
    public bool ToastsEnabled { get; set; } = true;
    public bool CheckForUpdates { get; set; }           // opt-in: check GitHub for a newer version (default OFF)
    public bool ProbeReachability { get; set; } = true; // probe each profile's server for the reachability dot/latency (opt-out: sends a PQ ClientHello per profile)
    public bool AutoStart { get; set; }                 // run GUI at login (LaunchAgent)
    public bool AutoConnect { get; set; }               // connect on app start
    public string? AutoConnectProfile { get; set; }     // profile name to auto-connect
    public bool StartMinimized { get; set; }            // start hidden in the menu bar
    public bool ServiceEnabled { get; set; }            // desired: run as a launchd daemon
    public string? ServiceProfile { get; set; }         // profile the launchd daemon runs

    private static readonly string Dir = Paths.UserDir;
    private static readonly string FilePath = Path.Combine(Dir, "settings.json");
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private static AppSettings? _current;
    public static AppSettings Current => _current ??= Load();

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
        }
        catch { /* fall through to defaults */ }
        return new AppSettings();
    }

    public void Save()
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Options));
        _current = this;
    }
}
