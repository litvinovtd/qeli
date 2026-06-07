using System.IO;
using Avalonia.Controls;
using Avalonia.Media.Imaging;

namespace QeliMac;

/// <summary>Small Avalonia UI helpers shared across windows.</summary>
public static class Ui
{
    /// <summary>Decode a PNG byte buffer into an Avalonia bitmap (for Image.Source).</summary>
    public static Bitmap Png(byte[] data) => new(new MemoryStream(data));

    /// <summary>Decode a PNG byte buffer into a WindowIcon (for Window.Icon / TrayIcon).</summary>
    public static WindowIcon Icon(byte[] data) => new(new MemoryStream(data));
}
