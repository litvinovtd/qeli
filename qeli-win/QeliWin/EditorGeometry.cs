using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using QeliWin.Model;
namespace QeliWin;
internal static class EditorGeometry
{
    internal static void Attach(Window window, string key)
    {
        window.Loaded += (_, _) =>
        {
            var settings = AppSettings.Current;
            var saved = key == "form" ? settings.ConfigEditorSize : key == "ini" ? settings.IniEditorSize : settings.ImportEditorSize;
            var screen = System.Windows.Forms.Screen.FromHandle(new WindowInteropHelper(window).Handle);
            var dpi = VisualTreeHelper.GetDpi(window);
            var area = screen.WorkingArea;
            double width = Math.Max(1, area.Width / dpi.DpiScaleX - 24);
            double height = Math.Max(1, area.Height / dpi.DpiScaleY - 24);
            window.MinWidth = Math.Min(window.MinWidth, width);
            window.MinHeight = Math.Min(window.MinHeight, height);
            window.MaxWidth = width; window.MaxHeight = height;
            window.Width = Math.Clamp(saved is not null && double.IsFinite(saved.Width) ? saved.Width : window.Width, window.MinWidth, width);
            window.Height = Math.Clamp(saved is not null && double.IsFinite(saved.Height) ? saved.Height : window.Height, window.MinHeight, height);
            // Center again after restoring dimensions and clamp to this monitor's work area.
            double left = double.IsFinite(window.Left) ? window.Left : area.Left / dpi.DpiScaleX;
            double top = double.IsFinite(window.Top) ? window.Top : area.Top / dpi.DpiScaleY;
            window.Left = Math.Clamp(left, area.Left / dpi.DpiScaleX, Math.Max(area.Left / dpi.DpiScaleX, area.Right / dpi.DpiScaleX - window.Width));
            window.Top = Math.Clamp(top, area.Top / dpi.DpiScaleY, Math.Max(area.Top / dpi.DpiScaleY, area.Bottom / dpi.DpiScaleY - window.Height));
        };
        window.Closed += (_, _) =>
        {
            var bounds = window.WindowState == WindowState.Normal ? new Size(window.ActualWidth, window.ActualHeight) : window.RestoreBounds.Size;
            if (!double.IsFinite(bounds.Width) || !double.IsFinite(bounds.Height) || bounds.Width <= 0 || bounds.Height <= 0) return;
            var settings = AppSettings.Current.Snapshot();
            var size = new WindowDimensions(bounds.Width, bounds.Height);
            if (key == "form") settings.ConfigEditorSize = size;
            else if (key == "ini") settings.IniEditorSize = size;
            else settings.ImportEditorSize = size;
            try { settings.Save(); } catch (Exception error) { System.Diagnostics.Debug.WriteLine(error.Message); }
        };
    }
}
