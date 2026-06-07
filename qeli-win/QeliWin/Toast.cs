using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;

namespace QeliWin;

public enum ToastKind { Success, Info, Error }

/// <summary>
/// Lightweight toaster-style notification: a borderless rounded window that slides in
/// at the bottom-right, shows the Qeli logo + a status-colored accent strip, and
/// auto-dismisses. Themed via the application palette. One toast at a time.
/// </summary>
public static class Toast
{
    private static Window? _current;

    /// <summary>Global on/off switch (driven by app settings).</summary>
    public static bool Enabled { get; set; } = true;

    public static void Show(ToastKind kind, string title, string message)
    {
        if (!Enabled) return;
        var app = Application.Current;
        if (app == null) return;
        app.Dispatcher.Invoke(() => ShowInternal(kind, title, message));
    }

    private static Brush Res(string key) =>
        (Brush)(Application.Current.Resources[key] ?? Brushes.Gray);

    private static void ShowInternal(ToastKind kind, string title, string message)
    {
        try { _current?.Close(); } catch { }

        var logo = new Image
        {
            Width = 34,
            Height = 34,
            Source = Ui.Png(Branding.LogoPng(48)),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0),
        };
        RenderOptions.SetBitmapScalingMode(logo, BitmapScalingMode.HighQuality);

        var texts = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock
        {
            Text = title,
            FontFamily = (FontFamily)Application.Current.Resources["DisplayFont"],
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Foreground = Res("Fg"),
        });
        if (!string.IsNullOrEmpty(message))
            texts.Children.Add(new TextBlock
            {
                Text = message,
                FontFamily = (FontFamily)Application.Current.Resources["UiFont"],
                FontSize = 12,
                Foreground = Res("FgDim"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 0),
            });

        var content = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(16, 13, 18, 13) };
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
            Effect = new DropShadowEffect { Color = Colors.Black, BlurRadius = 18, ShadowDepth = 4, Opacity = 0.35 },
        };

        var transform = new TranslateTransform(0, 24);
        var win = new Window
        {
            WindowStyle = WindowStyle.None,
            AllowsTransparency = true,
            Background = Brushes.Transparent,
            ShowInTaskbar = false,
            Topmost = true,
            ResizeMode = ResizeMode.NoResize,
            SizeToContent = SizeToContent.WidthAndHeight,
            ShowActivated = false,
            Content = new Border { Margin = new Thickness(12), Child = card, RenderTransform = transform },
        };

        win.MouseLeftButtonUp += (_, _) => { try { win.Close(); } catch { } };

        win.Loaded += (_, _) =>
        {
            var wa = SystemParameters.WorkArea;
            win.Left = wa.Right - win.ActualWidth - 8;
            win.Top = wa.Bottom - win.ActualHeight - 8;

            win.BeginAnimation(UIElement.OpacityProperty,
                new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
            transform.BeginAnimation(TranslateTransform.YProperty,
                new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(260))
                { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
        };

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(220));
            fade.Completed += (_, _) => { try { win.Close(); } catch { } };
            win.BeginAnimation(UIElement.OpacityProperty, fade);
        };

        win.Closed += (_, _) => { if (ReferenceEquals(_current, win)) _current = null; };

        _current = win;
        win.Opacity = 0;
        win.Show();
        timer.Start();
    }
}
