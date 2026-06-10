using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using QeliWin.Model;
using Qeli.Shared.Model;

namespace QeliWin;

/// <summary>Maps a profile's reachability to a status dot color for the profile card.</summary>
public sealed class ReachabilityToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Reachable = Frozen(0x35, 0xC7, 0x59); // green
    private static readonly SolidColorBrush Unreachable = Frozen(0xE5, 0x53, 0x4B); // red
    private static readonly SolidColorBrush Checking = Frozen(0xF2, 0xC0, 0x44); // amber
    private static readonly SolidColorBrush Unknown = Frozen(0x9A, 0xA4, 0xB0); // gray

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value switch
        {
            ProfileReachability.Reachable => Reachable,
            ProfileReachability.Unreachable => Unreachable,
            ProfileReachability.Checking => Checking,
            _ => Unknown,
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();

    private static SolidColorBrush Frozen(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        br.Freeze();
        return br;
    }
}
