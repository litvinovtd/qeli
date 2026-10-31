using System.IO;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliWin.Model;

/// <summary>App-wide settings persisted to %APPDATA%\QeliWin\settings.json.</summary>
public sealed class AppSettings
{
    public string Language { get; set; } = "en";       // "en" | "ru" (default English)
    public WindowDimensions ConfigEditorSize { get; set; } = new(720, 680);
    public WindowDimensions IniEditorSize { get; set; } = new(560, 440);
    public WindowDimensions ImportEditorSize { get; set; } = new(560, 440);
    public string Theme { get; set; } = "system";      // "system" | "light" | "dark"
    // Timestamp shape in the log view. Same values as the server's
    // [logging] time_format; anything unknown renders as "datetime".
    public string LogTimeFormat { get; set; } = "datetime";  // "datetime" | "rfc3339" | "time" | "epoch" | "none"
    public string LogLevel { get; set; } = "info";           // "info" (compact) | "debug" (detailed)
    public bool ToastsEnabled { get; set; } = true;
    public bool CheckForUpdates { get; set; }           // opt-in: check GitHub for a newer version (default OFF)
    public bool ProbeReachability { get; set; } = false; // privacy-safe opt-in: automatic UDP probes emit a distinctive PQ first flight. Manual checks always remain available.
    public int ProbeIntervalSecs { get; set; } = 30;    // auto-poll period (only when ProbeReachability is on); clamped 10..3600
    public bool AutoStart { get; set; }                 // run GUI at Windows logon (scheduled task)
    public bool AutoConnect { get; set; }               // connect on app start
    public string? AutoConnectProfile { get; set; }     // profile name to auto-connect
    public bool StartMinimized { get; set; }            // start hidden in the tray
    public bool ServiceEnabled { get; set; }            // desired: run as a Windows service
    public string? ServiceProfile { get; set; }         // profile the Windows service runs
    public string PersistentAdapterMode { get; set; } = "off"; // off | profiles | global

    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "QeliWin");
    private static readonly string FilePath = Path.Combine(Dir, "settings.json");
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private static AppSettings? _current;
    public static AppSettings Current => _current ??= Load();

    public static AppSettings Load() => AppSettingsStore.Load<AppSettings>(FilePath, Options);

    internal AppSettings Snapshot() => (AppSettings)MemberwiseClone();

    public void Save()
    {
        AppSettingsStore.Save(this, FilePath, Options);
        _current = this;
    }
}
