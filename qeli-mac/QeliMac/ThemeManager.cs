using System.Diagnostics;
using Avalonia;
using Avalonia.Media;
using Avalonia.Styling;

namespace QeliMac;

/// <summary>
/// Derives the app palette from the current macOS appearance (light/dark) and accent
/// color (read via <c>defaults</c>), then publishes them as application resources the
/// XAML consumes via DynamicResource. The macOS analogue of qeli-win's registry-based
/// ThemeManager. Call <see cref="Apply"/> at startup and on a live theme switch.
/// </summary>
public static class ThemeManager
{
    public static bool IsLight { get; private set; }
    public static Color Accent { get; private set; }

    public static void Apply()
    {
        var app = Application.Current;
        if (app == null) return;

        var mode = QeliMac.Model.AppSettings.Current.Theme;
        IsLight = mode == "light" || (mode != "dark" && !MacIsDark());
        Accent = ReadAccentColor() ?? H("#2B7DD9");

        // Keep Fluent base controls (scrollbars, menus, focus rings) in step.
        app.RequestedThemeVariant = IsLight ? ThemeVariant.Light : ThemeVariant.Dark;

        var r = app.Resources;
        void B(string key, Color c) => r[key] = new SolidColorBrush(c);

        if (IsLight)
        {
            B("Bg", H("#F4F7FC"));
            B("Panel", H("#FFFFFF"));
            B("PanelBorder", H("#E1E7F2"));
            B("Fg", H("#1A2233"));
            B("FgDim", H("#6B7A90"));
            B("InputBg", H("#FFFFFF"));
            B("InputBorder", H("#D8DFEA"));
            B("Hover", H("#EEF2FA"));
            B("Selected", WithAlpha(Accent, 28));
            B("ScrollThumb", Color.FromArgb(0x38, 0, 0, 0));
            B("ScrollThumbHover", Color.FromArgb(0x66, 0, 0, 0));
            B("Danger", H("#E5484D"));
            B("StatusConnected", H("#10B95C"));
            B("StatusConnecting", H("#F0A911"));
            B("StatusDisconnected", H("#A6B0C2"));
            B("StatusError", H("#E5484D"));
        }
        else
        {
            B("Bg", H("#0F1018"));
            B("Panel", H("#1A1B2A"));
            B("PanelBorder", H("#2B2E45"));
            B("Fg", H("#ECEDF6"));
            B("FgDim", H("#9AA3BD"));
            B("InputBg", H("#15182A"));
            B("InputBorder", H("#2B2E45"));
            B("Hover", H("#232539"));
            B("Selected", WithAlpha(Accent, 55));
            B("ScrollThumb", Color.FromArgb(0x40, 0xFF, 0xFF, 0xFF));
            B("ScrollThumbHover", Color.FromArgb(0x70, 0xFF, 0xFF, 0xFF));
            B("Danger", H("#FF6B6B"));
            B("StatusConnected", H("#19E07C"));
            B("StatusConnecting", H("#FFB300"));
            B("StatusDisconnected", H("#5B6481"));
            B("StatusError", H("#FF6B6B"));
        }

        B("Accent", Accent);
        B("AccentHover", Mix(Accent, IsLight ? Colors.Black : Colors.White, 0.12));
        B("AccentFg", Luminance(Accent) > 0.6 ? H("#10131A") : Colors.White);
    }

    // ── macOS appearance reads ────────────────────────────────────────────────────
    private static bool MacIsDark()
    {
        // `defaults read -g AppleInterfaceStyle` prints "Dark" in dark mode and errors
        // (no key) in light mode.
        var (outp, code) = ReadDefault("-g AppleInterfaceStyle");
        return code == 0 && outp.Trim().Equals("Dark", StringComparison.OrdinalIgnoreCase);
    }

    private static Color? ReadAccentColor()
    {
        // AppleAccentColor: 0 red,1 orange,2 yellow,3 green,4 blue,5 purple,6 pink,-1 graphite.
        // Absent key → the default multicolor blue.
        var (outp, code) = ReadDefault("-g AppleAccentColor");
        if (code != 0 || !int.TryParse(outp.Trim(), out int idx)) return null;
        return idx switch
        {
            0 => H("#FF5257"),  // red
            1 => H("#F7821B"),  // orange
            2 => H("#FFC600"),  // yellow
            3 => H("#62BA46"),  // green
            4 => H("#007AFF"),  // blue
            5 => H("#953D96"),  // purple
            6 => H("#F74F9E"),  // pink
            -1 => H("#8C8C8C"), // graphite
            _ => null,
        };
    }

    private static (string outp, int code) ReadDefault(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/defaults", $"read {args}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            string outp = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            return (outp, p.ExitCode);
        }
        catch { return ("", -1); }
    }

    // ── color helpers ─────────────────────────────────────────────────────────────
    private static Color H(string hex) => Color.Parse(hex);

    private static Color WithAlpha(Color c, byte a) => Color.FromArgb(a, c.R, c.G, c.B);

    private static double Luminance(Color c) => (0.299 * c.R + 0.587 * c.G + 0.114 * c.B) / 255.0;

    private static Color Mix(Color a, Color b, double t) => Color.FromRgb(
        (byte)(a.R + (b.R - a.R) * t),
        (byte)(a.G + (b.G - a.G) * t),
        (byte)(a.B + (b.B - a.B) * t));
}
