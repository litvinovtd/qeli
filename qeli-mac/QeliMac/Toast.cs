using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Qeli.Shared;

namespace QeliMac;


/// <summary>
/// Lightweight toaster-style notification: a borderless rounded window that fades in at
/// the bottom-right, shows the Qeli logo + a title/message, and auto-dismisses. Themed
/// via the application palette. One toast at a time. The Avalonia port of qeli-win's
/// WPF Toast.
/// </summary>
public static class Toast
{
    private static Window? _current;

    /// <summary>Global on/off switch (driven by app settings).</summary>
    public static bool Enabled { get; set; } = true;

    public static void Show(ToastKind kind, string title, string message)
    {
        if (!Enabled) return;
        if (Application.Current?.ApplicationLifetime == null) return;
        Dispatcher.UIThread.Post(() => ShowInternal(kind, title, message));
    }

    private static IBrush Res(string key) =>
        Application.Current!.Resources.TryGetResource(key, Application.Current.ActualThemeVariant, out var v)
            && v is IBrush b ? b : Brushes.Gray;

    private static void ShowInternal(ToastKind kind, string title, string message)
    {
        try { _current?.Close(); } catch { }

        var logo = new Image
        {
            Width = 34, Height = 34,
            Source = Ui.Png(Branding.LogoPng(48)),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0),
        };

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock
        {
            Text = title, FontSize = 14, FontWeight = FontWeight.SemiBold, Foreground = Res("Fg"),
        });
        if (!string.IsNullOrEmpty(message))
            texts.Children.Add(new TextBlock
            {
                Text = message, FontSize = 12, Foreground = Res("FgDim"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0),
            });

        var content = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(16, 13, 18, 13),
        };
        content.Children.Add(logo);
        content.Children.Add(texts);

        var card = new Border
        {
            Background = Res("Panel"),
            BorderBrush = Res("PanelBorder"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(11),
            MaxWidth = 360,
            Child = content,
            BoxShadow = BoxShadows.Parse("0 4 18 0 #59000000"),
        };

        var win = new Window
        {
            SystemDecorations = SystemDecorations.None,
            Background = Brushes.Transparent,
            TransparencyLevelHint = new[] { WindowTransparencyLevel.Transparent },
            ShowInTaskbar = false,
            Topmost = true,
            CanResize = false,
            SizeToContent = SizeToContent.WidthAndHeight,
            ShowActivated = false,
            Content = new Border { Margin = new Thickness(12), Child = card },
            Opacity = 0,
            Transitions = new Avalonia.Animation.Transitions
            {
                new Avalonia.Animation.DoubleTransition
                {
                    Property = Visual.OpacityProperty,
                    Duration = TimeSpan.FromMilliseconds(220),
                },
            },
        };

        win.PointerPressed += (_, _) => { try { win.Close(); } catch { } };

        win.Opened += (_, _) =>
        {
            var screen = win.Screens.Primary ?? win.Screens.All.FirstOrDefault();
            if (screen != null)
            {
                var wa = screen.WorkingArea;
                double scale = screen.Scaling;
                int w = (int)(win.Bounds.Width * scale);
                int h = (int)(win.Bounds.Height * scale);
                win.Position = new PixelPoint(
                    wa.X + wa.Width - w - (int)(8 * scale),
                    wa.Y + wa.Height - h - (int)(8 * scale));
            }
            win.Opacity = 1; // fade in via the transition
        };

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            win.Opacity = 0;
            var close = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(240) };
            close.Tick += (_, _) => { close.Stop(); try { win.Close(); } catch { } };
            close.Start();
        };

        win.Closed += (_, _) => { if (ReferenceEquals(_current, win)) _current = null; };

        _current = win;
        win.Show();
        timer.Start();
    }
}
