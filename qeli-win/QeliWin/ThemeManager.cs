using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace QeliWin;

/// <summary>
/// Derives the app palette from the current Windows theme (light/dark) and accent
/// color (read from the registry), then publishes them as application resources the
/// XAML consumes via DynamicResource. Call <see cref="Apply"/> at startup.
/// </summary>
public static class ThemeManager
{
    public static bool IsLight { get; private set; }
    public static Color Accent { get; private set; }

    public static void Apply()
    {
        // Theme mode: "light"/"dark" force it; "system" follows Windows. Palette mirrors
        // the Qeli mobile app (values/colors.xml + values-night/colors.xml).
        var mode = QeliWin.Model.AppSettings.Current.Theme;
        IsLight = mode == "light" || (mode != "dark" && ReadAppsUseLightTheme());
        Accent = ReadAccentColor() ?? H("#2B7DD9");

        var r = Application.Current.Resources;
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

    // ── registry reads ──────────────────────────────────────────────────────────
    private static bool ReadAppsUseLightTheme()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int i && i != 0;
        }
        catch { return false; }
    }

    private static Color? ReadAccentColor()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM");
            if (k?.GetValue("AccentColor") is int abgr)
            {
                byte rr = (byte)(abgr & 0xFF);
                byte gg = (byte)((abgr >> 8) & 0xFF);
                byte bb = (byte)((abgr >> 16) & 0xFF);
                return Color.FromRgb(rr, gg, bb);
            }
        }
        catch { /* fall through */ }
        return null;
    }

    // ── color helpers ─────────────────────────────────────────────────────────────
    private static Color H(string hex) => (Color)ColorConverter.ConvertFromString(hex);

    private static Color WithAlpha(Color c, byte a) => Color.FromArgb(a, c.R, c.G, c.B);

    private static double Luminance(Color c) => (0.299 * c.R + 0.587 * c.G + 0.114 * c.B) / 255.0;

    private static Color Mix(Color a, Color b, double t) => Color.FromRgb(
        (byte)(a.R + (b.R - a.R) * t),
        (byte)(a.G + (b.G - a.G) * t),
        (byte)(a.B + (b.B - a.B) * t));
}
