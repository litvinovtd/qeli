using System.IO;
using System.Text.Json;

namespace QeliWin.Model;

/// <summary>App-wide settings persisted to %APPDATA%\QeliWin\settings.json.</summary>
public sealed class AppSettings
{
    public string Language { get; set; } = "en";       // "en" | "ru" (default English)
    public string Theme { get; set; } = "system";      // "system" | "light" | "dark"
    public bool ToastsEnabled { get; set; } = true;
    public bool CheckForUpdates { get; set; }           // opt-in: check GitHub for a newer version (default OFF)
    public bool ProbeReachability { get; set; } = true; // poll each profile's server for the reachability dot/latency AUTOMATICALLY (opt-out: sends a PQ ClientHello per profile). When off, only a manual "check reachability" probes.
    public int ProbeIntervalSecs { get; set; } = 30;    // auto-poll period (only when ProbeReachability is on); clamped 10..3600
    public bool AutoStart { get; set; }                 // run GUI at Windows logon (scheduled task)
    public bool AutoConnect { get; set; }               // connect on app start
    public string? AutoConnectProfile { get; set; }     // profile name to auto-connect
    public bool StartMinimized { get; set; }            // start hidden in the tray
    public bool ServiceEnabled { get; set; }            // desired: run as a Windows service
    public string? ServiceProfile { get; set; }         // profile the Windows service runs

    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "QeliWin");
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
