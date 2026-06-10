using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using QeliMac.Model;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>Maps a profile's reachability to a status dot color for the profile card.</summary>
public sealed class ReachabilityToBrushConverter : IValueConverter
{
    private static readonly IBrush Reachable = Frozen(0x35, 0xC7, 0x59); // green
    private static readonly IBrush Unreachable = Frozen(0xE5, 0x53, 0x4B); // red
    private static readonly IBrush Checking = Frozen(0xF2, 0xC0, 0x44); // amber
    private static readonly IBrush Unknown = Frozen(0x9A, 0xA4, 0xB0); // gray

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

    private static IBrush Frozen(byte r, byte g, byte b) =>
        new ImmutableSolidColorBrush(Color.FromRgb(r, g, b));
}
