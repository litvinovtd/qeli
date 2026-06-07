using System.IO;
using System.Windows.Media.Imaging;

namespace QeliWin;

/// <summary>Small WPF UI helpers shared across windows.</summary>
public static class Ui
{
    /// <summary>Decode a PNG byte buffer into a frozen, ready-to-bind BitmapImage.</summary>
    public static BitmapImage Png(byte[] data)
    {
        var img = new BitmapImage();
        img.BeginInit();
        img.CacheOption = BitmapCacheOption.OnLoad;
        img.StreamSource = new MemoryStream(data);
        img.EndInit();
        img.Freeze();
        return img;
    }
}
