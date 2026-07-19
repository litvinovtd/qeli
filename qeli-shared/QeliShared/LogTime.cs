namespace Qeli.Shared;

/// <summary>
/// Renders the timestamp that prefixes a log line, in the shape the user picked
/// in Settings. This is the C# twin of the Rust <c>util::log_timestamp</c> and
/// of the server's <c>[logging] time_format</c> key — the same value names and
/// the same output, so a desktop log and a server log can be read side by side
/// (and, with <c>rfc3339</c>, sorted together).
///
/// Kept in qeli-shared because qeli-win (WPF) and qeli-mac (Avalonia) duplicate
/// their whole UI layer; this is one of the few pieces both can actually share.
/// </summary>
public static class LogTime
{
    /// <summary>Documented values, in the order the Settings dropdown shows them.</summary>
    public const string Default = "datetime";

    /// <summary>
    /// Returns the stamp for <paramref name="fmt"/>, or an empty string for
    /// <c>none</c>/<c>off</c> — the caller must then omit the separator too.
    /// An unknown or null value degrades to <see cref="Default"/> rather than
    /// throwing: settings.json is hand-editable and a typo there must not break
    /// logging.
    /// </summary>
    public static string Stamp(string? fmt)
    {
        switch ((fmt ?? "").Trim().ToLowerInvariant())
        {
            case "none":
            case "off":
                return "";
            case "rfc3339":
            case "iso8601":
                // UTC, so lines from several hosts collate correctly.
                return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z";
            case "time":
                return DateTime.Now.ToString("HH:mm:ss.fff");
            case "epoch":
            case "unix":
            {
                long ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                return $"{ms / 1000}.{ms % 1000:000}";
            }
            default:
                return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        }
    }

    /// <summary>
    /// Convenience for the log views: the stamp plus the two-space separator,
    /// collapsing to nothing when the user chose <c>none</c>.
    /// </summary>
    public static string Prefix(string? fmt)
    {
        var ts = Stamp(fmt);
        return ts.Length == 0 ? "" : ts + "  ";
    }
}
